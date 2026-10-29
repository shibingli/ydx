// Package workflow owns the framework's BPMN 2.0 workflow engine: versioned process
// definitions, a token-based runtime, Chinese approval semantics and an abstract
// notification layer. | Package workflow 负责框架的 BPMN 2.0 流程引擎：多版本流程定义、
// 基于令牌的运行期、中国式审批语义与抽象通知层。
//
// The domain is deliberately free of HTTP, GORM and messaging imports: persistence
// arrives through Store, assignee resolution through Directory and outbound
// notifications through Channel, so the engine can be embedded in any application. |
// 本域刻意不依赖 HTTP、GORM 与消息中心：持久化经 Store 注入，审批人解析经 Directory 注入，
// 对外通知经 Channel 注入，因此引擎可以嵌入任何应用。
//
// Tenant is a hard boundary in every method: a cross-tenant read or write reports
// ErrNotFound and never reveals whether the row exists elsewhere. | 租户是每个方法的硬边界：
// 跨租户读写一律返回 ErrNotFound，绝不泄露别处是否存在该行。
package workflow

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/shibingli/ydx/errs"
)

// Lifecycle states of a definition, a version, an instance and a task. | 流程定义、版本、实例与任务的生命周期状态。
const (
	// DefinitionDraft is a definition that has never been published. | DefinitionDraft 表示从未发布过的定义。
	DefinitionDraft = "draft"
	// DefinitionPublished accepts new instances. | DefinitionPublished 表示可以发起新实例。
	DefinitionPublished = "published"
	// DefinitionDisabled stops new instances while running ones continue. | DefinitionDisabled 表示停止发起新实例，运行中的实例继续。
	DefinitionDisabled = "disabled"

	// VersionDraft is an editable design snapshot. | VersionDraft 是可编辑的设计快照。
	VersionDraft = "draft"
	// VersionPublished is an immutable snapshot instances can bind to. | VersionPublished 是不可变、可被实例绑定的快照。
	VersionPublished = "published"

	// InstanceRunning has at least one live token. | InstanceRunning 表示至少有一个活动令牌。
	InstanceRunning = "running"
	// InstanceCompleted reached an end event. | InstanceCompleted 表示到达结束事件。
	InstanceCompleted = "completed"
	// InstanceWithdrawn was withdrawn by its initiator or an administrator. | InstanceWithdrawn 表示被发起人或管理员撤回。
	InstanceWithdrawn = "withdrawn"
	// InstanceTerminated was ended by a rejection policy or an administrator. | InstanceTerminated 表示因驳回策略或管理员操作终止。
	InstanceTerminated = "terminated"

	// TaskPending is actionable but not acknowledged. | TaskPending 表示可处理但尚未签收。
	TaskPending = "pending"
	// TaskClaimed was acknowledged by its assignee. | TaskClaimed 表示已被指派人签收。
	TaskClaimed = "claimed"
	// TaskCompleted carries a decision. | TaskCompleted 表示已给出决策。
	TaskCompleted = "completed"
	// TaskCancelled was withdrawn, returned or removed. | TaskCancelled 表示因撤回、退回或减签而取消。
	TaskCancelled = "cancelled"
	// TaskQueued waits for its turn in sequential mode. | TaskQueued 在顺序审批中等待轮到自己。
	TaskQueued = "queued"

	// TokenActive is executing right now. | TokenActive 表示正在执行。
	TokenActive = "active"
	// TokenWaiting waits for tasks or a gateway join. | TokenWaiting 表示等待任务或网关汇聚。
	TokenWaiting = "waiting"
	// TokenCompleted finished its path. | TokenCompleted 表示已完成自己的路径。
	TokenCompleted = "completed"
	// TokenCancelled was cancelled by withdrawal, return or termination. | TokenCancelled 表示因撤回、退回或终止而取消。
	TokenCancelled = "cancelled"
)

// Node types of the supported BPMN subset. | 支持的 BPMN 子集节点类型。
const (
	// NodeStart is the single start event. | NodeStart 是唯一的开始事件。
	NodeStart = "start"
	// NodeEnd is an end event. | NodeEnd 是结束事件。
	NodeEnd = "end"
	// NodeUserTask needs a human decision. | NodeUserTask 需要人工决策。
	NodeUserTask = "user"
	// NodeServiceTask is automatic. | NodeServiceTask 是自动节点。
	NodeServiceTask = "service"
	// NodeExclusive is an XOR gateway. | NodeExclusive 是排他网关。
	NodeExclusive = "exclusive"
	// NodeParallel is an AND gateway. | NodeParallel 是并行网关。
	NodeParallel = "parallel"
	// NodeInclusive is an OR gateway. | NodeInclusive 是包容网关。
	NodeInclusive = "inclusive"
	// NodeCatch is an intermediate catch event. | NodeCatch 是中间捕获事件。
	NodeCatch = "catch"
	// NodeEventGateway is an event-based gateway that races its outgoing catch events. |
	// NodeEventGateway 是让出线捕获事件竞争的事件网关。
	NodeEventGateway = "event"
)

// Intermediate catch event kinds. | 中间捕获事件类型。
const (
	// WaitTimer waits until a deadline. | WaitTimer 等待到截止时间。
	WaitTimer = "timer"
	// WaitMessage waits for a named signal delivered through the API. | WaitMessage 等待经 API 投递的命名信号。
	WaitMessage = "message"
)

// Assignment kinds and claim modes. | 指派类型与认领模式。
const (
	// AssigneeUser names explicit user ids or login names. | AssigneeUser 指定用户 ID 或登录名。
	AssigneeUser = "user"
	// AssigneeRole names roles, which act as approval groups. | AssigneeRole 指定角色，角色即审批组。
	AssigneeRole = "role"
	// AssigneeInitiator assigns the node to the instance initiator. | AssigneeInitiator 把节点指派给实例发起人。
	AssigneeInitiator = "initiator"
	// AssigneeGroup names workflow-owned groups; a group may link to a yd role. | AssigneeGroup
	// 指定流程自有组；流程组可以关联 yd 角色。
	AssigneeGroup = "group"

	// ClaimAssigned gives every task a direct assignee. | ClaimAssigned 为每个任务直接指定处理人。
	ClaimAssigned = "assigned"
	// ClaimRequired asks the assignee to acknowledge before acting. | ClaimRequired 要求处理人先签收再处理。
	ClaimRequired = "claim"
	// ClaimGrab pools candidates and assigns the task to the first claimer. | ClaimGrab 把任务放进候选池，先抢到者获得。
	ClaimGrab = "grab"
)

// Completion modes and rejection policies. | 完成模式与驳回策略。
const (
	// CompletionAny is or-sign: one approval passes the node. | CompletionAny 是或签：一人通过即通过。
	CompletionAny = "any"
	// CompletionAll is countersign: everyone must approve. | CompletionAll 是会签：所有人都必须通过。
	CompletionAll = "all"
	// CompletionVote is vote-sign with a count or percentage threshold. | CompletionVote 是按票数或百分比判定通过的票签。
	CompletionVote = "vote"

	// ThresholdCount counts approvals. | ThresholdCount 按通过票数计数。
	ThresholdCount = "count"
	// ThresholdPercent measures approvals as a percentage of the live votes. | ThresholdPercent 按存活票数的百分比计算。
	ThresholdPercent = "percent"

	// OnRejectTerminate ends the instance as rejected. | OnRejectTerminate 以驳回终止实例。
	OnRejectTerminate = "terminate"
	// OnRejectEnd completes the instance as rejected. | OnRejectEnd 以驳回完成实例。
	OnRejectEnd = "end"
	// OnRejectReturnInitiator sends the work back to the initiator for revision. | OnRejectReturnInitiator 把流程退回发起人修改后重新提交。
	OnRejectReturnInitiator = "return_initiator"

	// RejectModeAny rejects the node on the first rejection. | RejectModeAny 表示首个驳回即驳回节点。
	RejectModeAny = "any"
	// RejectModeAll rejects the node only after every live vote rejected. | RejectModeAll 表示全部存活票都驳回才驳回节点。
	RejectModeAll = "all"
)

// Decisions, event names, notification states and auto-approval scopes. | 决策、事件名、通知状态与自动审批作用域。
const (
	// DecisionNone means no decision has been made. | DecisionNone 表示尚未决策。
	DecisionNone = "none"
	// DecisionApprove approves a task or node. | DecisionApprove 表示通过任务或节点。
	DecisionApprove = "approve"
	// DecisionReject rejects a task or node. | DecisionReject 表示驳回任务或节点。
	DecisionReject = "reject"

	// EventInstanceStarted fires when an instance starts. | EventInstanceStarted 在实例发起时触发。
	EventInstanceStarted = "instance.started"
	// EventInstanceCompleted fires when an instance completes. | EventInstanceCompleted 在实例完成时触发。
	EventInstanceCompleted = "instance.completed"
	// EventInstanceRejected fires when an instance ends rejected. | EventInstanceRejected 在实例被驳回结束时触发。
	EventInstanceRejected = "instance.rejected"
	// EventInstanceWithdrawn fires on withdrawal. | EventInstanceWithdrawn 在撤回时触发。
	EventInstanceWithdrawn = "instance.withdrawn"
	// EventInstanceTerminated fires on administrative termination. | EventInstanceTerminated 在管理员终止时触发。
	EventInstanceTerminated = "instance.terminated"
	// EventNodeEntered fires when a node becomes active. | EventNodeEntered 在节点激活时触发。
	EventNodeEntered = "node.entered"
	// EventTaskCreated fires when tasks are created. | EventTaskCreated 在任务创建时触发。
	EventTaskCreated = "task.created"
	// EventTaskClaimed fires on claim. | EventTaskClaimed 在签收时触发。
	EventTaskClaimed = "task.claimed"
	// EventTaskApproved fires on approval. | EventTaskApproved 在通过时触发。
	EventTaskApproved = "task.approved"
	// EventTaskRejected fires on rejection. | EventTaskRejected 在驳回时触发。
	EventTaskRejected = "task.rejected"
	// EventTaskTransferred fires on transfer. | EventTaskTransferred 在转办时触发。
	EventTaskTransferred = "task.transferred"
	// EventTaskDelegated fires on delegation. | EventTaskDelegated 在委派时触发。
	EventTaskDelegated = "task.delegated"
	// EventTaskDelegatedBack fires when a delegate hands the task back. | EventTaskDelegatedBack 在受托人交回任务时触发。
	EventTaskDelegatedBack = "task.delegated_back"
	// EventTaskAdded fires on add-sign. | EventTaskAdded 在加签时触发。
	EventTaskAdded = "task.added"
	// EventTaskRemoved fires on remove-sign. | EventTaskRemoved 在减签时触发。
	EventTaskRemoved = "task.removed"
	// EventTaskReturned fires on return. | EventTaskReturned 在退回时触发。
	EventTaskReturned = "task.returned"
	// EventTaskReminded fires on reminder. | EventTaskReminded 在催办时触发。
	EventTaskReminded = "task.reminded"
	// EventTaskAutoDecided fires on automatic approval. | EventTaskAutoDecided 在自动审批时触发。
	EventTaskAutoDecided = "task.auto_decided"
	// EventCommentAdded fires when a comment is appended. | EventCommentAdded 在追加评论时触发。
	EventCommentAdded = "comment.added"

	// NotificationPending awaits delivery. | NotificationPending 等待投递。
	NotificationPending = "pending"
	// NotificationSent was delivered to every configured channel. | NotificationSent 已投递到全部配置渠道。
	NotificationSent = "sent"
	// NotificationFailed exhausted its attempts. | NotificationFailed 已耗尽重试次数。
	NotificationFailed = "failed"

	// AutoScopeCategory matches the instance category. | AutoScopeCategory 匹配实例分类。
	AutoScopeCategory = "category"
	// AutoScopeRole matches any assignee or initiator role. | AutoScopeRole 匹配任一审批人或发起人的角色。
	AutoScopeRole = "role"
	// AutoScopeUser matches an assignee or initiator id. | AutoScopeUser 匹配审批人或发起人 ID。
	AutoScopeUser = "user"
	// AutoScopeEvent matches the triggering event name. | AutoScopeEvent 匹配触发事件名。
	AutoScopeEvent = "event"
	// AutoScopeGroup matches a workflow group of any assignee or the initiator. | AutoScopeGroup
	// 匹配任一审批人或发起人所属的流程组。
	AutoScopeGroup = "group"

	// AutoScopeVariable is the variable-scope rule. | AutoScopeVariable 是变量作用域规则。
	AutoScopeVariable = "variable"

	// GroupEnabled makes a workflow group selectable. | GroupEnabled 表示流程组可选。
	GroupEnabled = "enabled"
	// GroupDisabled hides a workflow group from new assignments. | GroupDisabled 表示流程组从新指派中隐藏。
	GroupDisabled = "disabled"

	// AutoEventStart evaluates a rule when the instance starts. | AutoEventStart 在实例发起时求值。
	AutoEventStart = "start"
	// AutoEventTask evaluates a rule when a user task is created. | AutoEventTask 在用户任务创建时求值。
	AutoEventTask = "task"
)

// Notification kinds. | 通知类型。
const (
	// NotifyAssigned tells an approver that a task is waiting. | NotifyAssigned 通知审批人任务待处理。
	NotifyAssigned = "assigned"
	// NotifyReminded reminds an overdue approver. | NotifyReminded 催办超期审批人。
	NotifyReminded = "reminded"
	// NotifyApproved tells the initiator that a task passed. | NotifyApproved 通知发起人任务已通过。
	NotifyApproved = "approved"
	// NotifyRejected tells the initiator that a task was rejected. | NotifyRejected 通知发起人任务被驳回。
	NotifyRejected = "rejected"
	// NotifyReturned tells the target that work returned. | NotifyReturned 通知目标节点工作被退回。
	NotifyReturned = "returned"
	// NotifyWithdrawn tells approvers that the instance was withdrawn. | NotifyWithdrawn 通知审批人实例已撤回。
	NotifyWithdrawn = "withdrawn"
	// NotifyCompleted tells the initiator that the instance finished. | NotifyCompleted 通知发起人实例已结束。
	NotifyCompleted = "completed"
	// NotifyDelegated tells a delegate that work arrived. | NotifyDelegated 通知受托人任务已委派。
	NotifyDelegated = "delegated"
)

// InitiatorNodeID is the synthetic node that returns work to the initiator. | InitiatorNodeID 是把工作退回发起人的合成节点。
const InitiatorNodeID = "__initiator__"

// Sentinel errors of the workflow domain. | 流程域的哨兵错误。
var (
	// ErrInvalidInput reports a malformed request or argument. | ErrInvalidInput 表示请求或参数非法。
	ErrInvalidInput = errs.New("invalid workflow input | 非法的流程输入")
	// ErrNotFound reports a definition, version, instance or task outside the tenant. | ErrNotFound
	// 表示定义、版本、实例或任务不在租户内或不存在。
	ErrNotFound = errs.New("workflow record not found | 流程记录不存在")
	// ErrConflict reports a unique-key collision or a concurrent change. | ErrConflict 表示唯一键冲突或并发修改。
	ErrConflict = errs.New("workflow record conflicts with an existing one | 流程记录与既有数据冲突")
	// ErrForbidden reports an action the caller may not perform. | ErrForbidden 表示调用方无权执行该动作。
	ErrForbidden = errs.New("workflow action is not allowed | 不允许执行该流程动作")
	// ErrInstanceClosed reports an action on a finished instance. | ErrInstanceClosed 表示对已结束实例执行动作。
	ErrInstanceClosed = errs.New("workflow instance is already closed | 流程实例已结束")
	// ErrTaskClosed reports an action on a finished task. | ErrTaskClosed 表示对已结束任务执行动作。
	ErrTaskClosed = errs.New("workflow task is already closed | 流程任务已结束")
	// ErrTaskNotMine reports an action by someone other than the assignee. | ErrTaskNotMine 表示非指派人执行任务动作。
	ErrTaskNotMine = errs.New("workflow task is not assigned to the caller | 流程任务未指派给调用方")
	// ErrNoAssignee reports a user task whose assignment resolved to nobody. | ErrNoAssignee 表示用户任务的指派解析后为空。
	ErrNoAssignee = errs.New("workflow task has no assignee | 流程任务没有可用的审批人")
	// ErrInvalidDesign reports a design document that cannot execute. | ErrInvalidDesign 表示无法执行的设计文档。
	ErrInvalidDesign = errs.New("invalid workflow design | 非法的流程设计")
	// ErrInvalidCondition reports a malformed gateway or rule condition. | ErrInvalidCondition 表示网关或规则条件非法。
	ErrInvalidCondition = errs.New("invalid workflow condition | 非法的流程条件")
	// ErrInvalidForm reports malformed form fields or submitted values. | ErrInvalidForm 表示表单字段或提交值非法。
	ErrInvalidForm = errs.New("invalid workflow form | 非法的流程表单")
	// ErrVersionPublished reports an edit to an immutable published version. | ErrVersionPublished 表示修改已发布的不可变版本。
	ErrVersionPublished = errs.New("workflow version is published and immutable | 流程版本已发布且不可修改")
	// ErrDefinitionPublished reports deleting a definition that has instances. | ErrDefinitionPublished
	// 表示删除仍有实例或已发布版本的定义。
	ErrDefinitionPublished = errs.New("workflow definition is in use | 流程定义正在使用中")
	// ErrImportInvalid reports a malformed import bundle. | ErrImportInvalid 表示导入包格式非法。
	ErrImportInvalid = errs.New("invalid workflow import bundle | 非法的流程导入包")
	// ErrBPMNInvalid reports malformed BPMN XML. | ErrBPMNInvalid 表示 BPMN XML 格式非法。
	ErrBPMNInvalid = errs.New("invalid BPMN document | 非法的 BPMN 文档")
	// ErrWithdrawExpired reports a withdrawal outside its window. | ErrWithdrawExpired 表示超出撤回窗口。
	ErrWithdrawExpired = errs.New("the withdrawal window has expired | 撤回窗口已过")
	// ErrRemindLimit reports a task that reached its reminder ceiling. | ErrRemindLimit 表示任务已达催办次数上限。
	ErrRemindLimit = errs.New("the reminder limit has been reached | 已达催办次数上限")
	// ErrUnavailable reports a missing store, directory or channel. | ErrUnavailable 表示存储、目录或渠道不可用。
	ErrUnavailable = errs.New("workflow service is unavailable | 流程服务不可用")
	// ErrAIUnavailable reports an AI decider that is not configured. | ErrAIUnavailable 表示未配置 AI 决策器。
	ErrAIUnavailable = errs.New("workflow AI decider is not configured | 未配置流程 AI 决策器")
	// ErrNotificationFailed reports every channel rejecting one notification. | ErrNotificationFailed
	// 表示全部通知渠道都拒绝了同一条通知。
	ErrNotificationFailed = errs.New("workflow notification failed | 流程通知发送失败")
	// ErrLimit reports a configured count or size ceiling. | ErrLimit 表示达到配置的数量或大小上限。
	ErrLimit = errs.New("workflow limit exceeded | 超出流程配置上限")
)

// Options configure the workflow service. Zero values keep the framework defaults. | Options 配置流程服务，零值保持框架默认。
type Options struct {
	// Now and NewID are injectable for deterministic tests. | Now 与 NewID 供确定性测试注入。
	Now   func() time.Time
	NewID func(prefix string) (string, error)
	// NotifyEvents lists the event kinds that produce notifications; empty means all. | NotifyEvents
	// 列出会发送通知的事件类型；空表示全部。
	NotifyEvents []string
	// WithdrawWindow is how long an initiator may withdraw an instance. | WithdrawWindow 是发起人可撤回实例的时长。
	WithdrawWindow time.Duration
	// DefaultDue is the default task deadline when a node names none. | DefaultDue 是节点未指定时的默认任务期限。
	DefaultDue time.Duration
	// DefaultRemindEvery is the default reminder interval. | DefaultRemindEvery 是默认催办间隔。
	DefaultRemindEvery time.Duration
	// DefaultMaxRemind is the default reminder ceiling. | DefaultMaxRemind 是默认催办次数上限。
	DefaultMaxRemind int
	// ScanInterval is the scheduler tick. | ScanInterval 是调度器扫描间隔。
	ScanInterval time.Duration
	// NotificationRetry is the maximum delivery attempts of one notification. | NotificationRetry 是单条通知的最大投递次数。
	NotificationRetry int
	// NotificationTimeout bounds one channel call. | NotificationTimeout 限制单次渠道调用。
	NotificationTimeout time.Duration
	// MaxNameLen, MaxTitleLen, MaxDescriptionLen and MaxCommentLen bound text fields. | MaxNameLen、MaxTitleLen、
	// MaxDescriptionLen 与 MaxCommentLen 限制文本字段。
	MaxNameLen        int
	MaxTitleLen       int
	MaxDescriptionLen int
	MaxCommentLen     int
	// MaxDesignBytes and MaxVariablesBytes bound JSON payloads. | MaxDesignBytes 与 MaxVariablesBytes 限制 JSON 载荷。
	MaxDesignBytes    int
	MaxVariablesBytes int
	// MaxImportBytes and MaxBundleDefinitions bound imports. | MaxImportBytes 与 MaxBundleDefinitions 限制导入。
	MaxImportBytes       int
	MaxBundleDefinitions int
	// MaxNodes, MaxEdges, MaxFormFields, MaxAssignees and MaxAutoRules bound a design. | MaxNodes、MaxEdges、
	// MaxFormFields、MaxAssignees 与 MaxAutoRules 限制单个设计。
	MaxNodes      int
	MaxEdges      int
	MaxFormFields int
	MaxAssignees  int
	MaxAutoRules  int
	// MaxConditionLen bounds one condition expression. | MaxConditionLen 限制单条条件表达式长度。
	MaxConditionLen int
	// PageSize and MaxPageSize bound list queries. | PageSize 与 MaxPageSize 限制列表分页。
	PageSize    int
	MaxPageSize int
	// DueScanLimit bounds one scheduler scan. | DueScanLimit 限制一次调度扫描的任务数。
	DueScanLimit int
	// MinAIConfidence is the minimum confidence of an AI decision. | MinAIConfidence 是 AI 决策的最低置信度。
	MinAIConfidence float64
}

// DefaultOptions returns the framework defaults. | DefaultOptions 返回框架默认值。
func DefaultOptions() Options {
	return Options{
		WithdrawWindow:       30 * time.Minute,
		DefaultDue:           72 * time.Hour,
		DefaultRemindEvery:   12 * time.Hour,
		DefaultMaxRemind:     5,
		ScanInterval:         30 * time.Second,
		NotificationRetry:    5,
		NotificationTimeout:  10 * time.Second,
		MaxNameLen:           120,
		MaxTitleLen:          200,
		MaxDescriptionLen:    1000,
		MaxCommentLen:        2000,
		MaxDesignBytes:       1 << 20,
		MaxVariablesBytes:    256 << 10,
		MaxImportBytes:       8 << 20,
		MaxBundleDefinitions: 200,
		MaxNodes:             200,
		MaxEdges:             400,
		MaxFormFields:        60,
		MaxAssignees:         100,
		MaxAutoRules:         50,
		MaxConditionLen:      2048,
		PageSize:             20,
		MaxPageSize:          100,
		DueScanLimit:         200,
		MinAIConfidence:      0.7,
	}
}

// normalize fills every zero value. | normalize 补齐全部零值。
func (o Options) normalize() Options {
	d := DefaultOptions()
	if o.WithdrawWindow <= 0 {
		o.WithdrawWindow = d.WithdrawWindow
	}
	if o.DefaultDue <= 0 {
		o.DefaultDue = d.DefaultDue
	}
	if o.DefaultRemindEvery <= 0 {
		o.DefaultRemindEvery = d.DefaultRemindEvery
	}
	if o.DefaultMaxRemind <= 0 {
		o.DefaultMaxRemind = d.DefaultMaxRemind
	}
	if o.ScanInterval <= 0 {
		o.ScanInterval = d.ScanInterval
	}
	if o.NotificationRetry <= 0 {
		o.NotificationRetry = d.NotificationRetry
	}
	if o.NotificationTimeout <= 0 {
		o.NotificationTimeout = d.NotificationTimeout
	}
	if o.MaxNameLen <= 0 {
		o.MaxNameLen = d.MaxNameLen
	}
	if o.MaxTitleLen <= 0 {
		o.MaxTitleLen = d.MaxTitleLen
	}
	if o.MaxDescriptionLen <= 0 {
		o.MaxDescriptionLen = d.MaxDescriptionLen
	}
	if o.MaxCommentLen <= 0 {
		o.MaxCommentLen = d.MaxCommentLen
	}
	if o.MaxDesignBytes <= 0 {
		o.MaxDesignBytes = d.MaxDesignBytes
	}
	if o.MaxVariablesBytes <= 0 {
		o.MaxVariablesBytes = d.MaxVariablesBytes
	}
	if o.MaxImportBytes <= 0 {
		o.MaxImportBytes = d.MaxImportBytes
	}
	if o.MaxBundleDefinitions <= 0 {
		o.MaxBundleDefinitions = d.MaxBundleDefinitions
	}
	if o.MaxNodes <= 0 {
		o.MaxNodes = d.MaxNodes
	}
	if o.MaxEdges <= 0 {
		o.MaxEdges = d.MaxEdges
	}
	if o.MaxFormFields <= 0 {
		o.MaxFormFields = d.MaxFormFields
	}
	if o.MaxAssignees <= 0 {
		o.MaxAssignees = d.MaxAssignees
	}
	if o.MaxAutoRules <= 0 {
		o.MaxAutoRules = d.MaxAutoRules
	}
	if o.MaxConditionLen <= 0 {
		o.MaxConditionLen = d.MaxConditionLen
	}
	if o.PageSize <= 0 {
		o.PageSize = d.PageSize
	}
	if o.MaxPageSize <= 0 {
		o.MaxPageSize = d.MaxPageSize
	}
	if o.MaxPageSize < o.PageSize {
		o.MaxPageSize = o.PageSize
	}
	if o.DueScanLimit <= 0 {
		o.DueScanLimit = d.DueScanLimit
	}
	if o.MinAIConfidence <= 0 || o.MinAIConfidence > 1 {
		o.MinAIConfidence = d.MinAIConfidence
	}
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	if o.NewID == nil {
		o.NewID = newID
	}
	return o
}

// newID returns a prefixed random identifier. | newID 返回带前缀的随机标识。
func newID(prefix string) (string, error) {
	var raw [16]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return "", errs.Wrap(err, ErrUnavailable)
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}

// trimLen trims surrounding whitespace and reports whether the rune length fits limit. utf8
// counts runes without allocating the []rune temporary the previous implementation built for
// every title, comment and note. | trimLen 去掉首尾空白并报告符文长度是否不超过 limit。utf8 直接
// 统计符文，不再为每个标题、评论与说明分配 []rune 临时切片。
func trimLen(value string, limit int) (string, bool) {
	value = strings.TrimSpace(value)
	if limit <= 0 {
		return value, true
	}
	return value, utf8.RuneCountInString(value) <= limit
}
