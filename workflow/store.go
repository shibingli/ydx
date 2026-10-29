package workflow

import (
	"context"
	"time"
)

// Store is the persistence boundary of the workflow domain. Every method carries the tenant
// explicitly, and a row outside that tenant reports ErrNotFound. | Store 是流程域的持久化边界。
// 每个方法都显式携带租户，租户外的行一律返回 ErrNotFound。
//
// WithTx runs fn inside one database transaction. Reads performed through the Store handed to
// fn must observe a row lock where the backend supports it, so two approvers cannot complete
// the same task or advance the same token twice. | WithTx 在一个数据库事务内执行 fn。通过交给
// fn 的 Store 执行的读取在支持的后端上必须获得行锁，因此两个审批人不可能同时完成同一任务，
// 也不可能把同一令牌推进两次。
type Store interface {
	// WithTx runs fn inside one transaction. | WithTx 在一个事务内执行 fn。
	WithTx(ctx context.Context, fn func(Store) error) error

	// CreateDefinition, UpdateDefinition and DeleteDefinition maintain the definition row. |
	// CreateDefinition、UpdateDefinition 与 DeleteDefinition 维护定义行。
	CreateDefinition(ctx context.Context, def Definition) error
	UpdateDefinition(ctx context.Context, def Definition) error
	DeleteDefinition(ctx context.Context, tenantID, id string) error
	GetDefinition(ctx context.Context, tenantID, id string) (Definition, error)
	GetDefinitionByKey(ctx context.Context, tenantID, key string) (Definition, error)
	ListDefinitions(ctx context.Context, tenantID string, filter DefinitionFilter) ([]Definition, int, error)

	// CreateVersion, UpdateVersion and DeleteVersion maintain version rows. | CreateVersion、
	// UpdateVersion 与 DeleteVersion 维护版本行。
	CreateVersion(ctx context.Context, version Version) error
	UpdateVersion(ctx context.Context, version Version) error
	DeleteVersion(ctx context.Context, tenantID, id string) error
	GetVersion(ctx context.Context, tenantID, id string) (Version, error)
	GetVersionByNumber(ctx context.Context, tenantID, definitionID string, version int) (Version, error)
	GetLatestPublishedVersion(ctx context.Context, tenantID, definitionID string) (Version, error)
	ListVersions(ctx context.Context, tenantID, definitionID string) ([]Version, error)
	NextVersionNumber(ctx context.Context, tenantID, definitionID string) (int, error)

	// CreateInstance, UpdateInstance and GetInstance maintain instance rows. GetInstance
	// locks the row when called inside WithTx on a backend that supports it. | CreateInstance、
	// UpdateInstance 与 GetInstance 维护实例行。在 WithTx 内调用 GetInstance 时，支持的后端会加行锁。
	CreateInstance(ctx context.Context, inst Instance) error
	UpdateInstance(ctx context.Context, inst Instance) error
	GetInstance(ctx context.Context, tenantID, id string) (Instance, error)
	ListInstances(ctx context.Context, tenantID string, filter InstanceFilter) ([]Instance, int, error)
	CountRunningInstances(ctx context.Context, tenantID, definitionID, businessKey string) (int, error)

	// CreateToken, UpdateToken and GetToken maintain execution tokens. | CreateToken、UpdateToken
	// 与 GetToken 维护执行令牌。
	CreateToken(ctx context.Context, token Token) error
	UpdateToken(ctx context.Context, token Token) error
	GetToken(ctx context.Context, tenantID, id string) (Token, error)
	ListTokens(ctx context.Context, tenantID, instanceID string) ([]Token, error)
	ListTokensAtNode(ctx context.Context, tenantID, instanceID, nodeID string) ([]Token, error)
	CountLiveTokens(ctx context.Context, tenantID, instanceID string) (int, error)
	CountLiveTokensByForkGroup(ctx context.Context, tenantID, instanceID, forkGroup string) (int, error)
	// ListDueTimerTokens returns waiting timer tokens whose deadline has passed. | ListDueTimerTokens
	// 返回截止时间已过的等待定时令牌。
	ListDueTimerTokens(ctx context.Context, now time.Time, limit int) ([]Token, error)
	// ListMessageTokens returns waiting message tokens matching one instance and signal. |
	// ListMessageTokens 返回匹配实例与信号的等待消息令牌。
	ListMessageTokens(ctx context.Context, tenantID, instanceID, messageName string) ([]Token, error)
	// CancelWaitGroup cancels the other competitors of one event gateway. | CancelWaitGroup
	// 取消一个事件网关的其它竞争令牌。
	CancelWaitGroup(ctx context.Context, tenantID, instanceID, waitGroup, exceptID string, now time.Time) error

	// CreateTask, UpdateTask and ClaimTask maintain tasks. ClaimTask is an atomic
	// compare-and-set so two claimers cannot both win the same task. | CreateTask、UpdateTask
	// 与 ClaimTask 维护任务。ClaimTask 是原子比较并写入，两个抢单者不可能都成功。
	CreateTask(ctx context.Context, task Task) error
	UpdateTask(ctx context.Context, task Task) error
	ClaimTask(ctx context.Context, tenantID, id, actorID, actorName string, now time.Time) (Task, error)
	// ClaimReminder atomically moves one due reminder forward. The boolean is false when
	// another node already claimed it or the task closed. | ClaimReminder 原子推进一次到期催办。
	// 布尔值为 false 表示另一个节点已领取或任务已结束。
	ClaimReminder(ctx context.Context, tenantID, id string, now, next time.Time) (Task, bool, error)
	GetTask(ctx context.Context, tenantID, id string) (Task, error)
	ListTasks(ctx context.Context, tenantID string, filter TaskFilter) ([]Task, int, error)
	ListTasksByToken(ctx context.Context, tenantID, tokenID string) ([]Task, error)
	ListDueTasks(ctx context.Context, now time.Time, limit int) ([]Task, error)

	// Events, comments and notifications form the append-only audit and outbox surface. | Events、
	// comments 与 notifications 构成追加式审计与发件箱面。
	CreateEvent(ctx context.Context, event Event) error
	ListEvents(ctx context.Context, tenantID, instanceID string, limit int) ([]Event, error)
	CreateComment(ctx context.Context, comment Comment) error
	ListComments(ctx context.Context, tenantID, instanceID string, limit int) ([]Comment, error)
	CreateNotification(ctx context.Context, note Notification) error
	UpdateNotification(ctx context.Context, note Notification) error
	ClaimNotification(ctx context.Context, tenantID, id string, now, leaseUntil time.Time) (Notification, bool, error)
	ListPendingNotifications(ctx context.Context, now time.Time, limit int) ([]Notification, error)

	// Workflow-owned approval groups; a group may link to a yd role. | 流程自有审批组；组可以关联 yd 角色。
	CreateGroup(ctx context.Context, group Group) error
	UpdateGroup(ctx context.Context, group Group) error
	DeleteGroup(ctx context.Context, tenantID, id string) error
	GetGroup(ctx context.Context, tenantID, id string) (Group, error)
	GetGroupByKey(ctx context.Context, tenantID, key string) (Group, error)
	ListGroups(ctx context.Context, tenantID string, filter GroupFilter) ([]Group, int, error)
	ListGroupsByUser(ctx context.Context, tenantID, userID string) ([]Group, error)
	ListGroupMembers(ctx context.Context, tenantID, groupID string) ([]GroupMember, error)
	AddGroupMember(ctx context.Context, member GroupMember) error
	RemoveGroupMember(ctx context.Context, tenantID, groupID, userID string) error

	// Stats returns the tenant summary. | Stats 返回租户汇总。
	Stats(ctx context.Context, tenantID string) (Stats, error)
}

// Directory resolves assignees and their roles. It is the only seam between the engine and
// the authentication store, which is why the engine never imports auth. | Directory 解析审批人
// 及其角色。它是引擎与鉴权存储之间唯一的接缝，因此引擎从不导入 auth。
type Directory interface {
	// User returns one active member of the tenant. | User 返回租户内一个启用成员。
	User(ctx context.Context, tenantID, userID string) (Assignee, error)
	// Users resolves a batch, preserving the requested order and skipping duplicates. | Users
	// 批量解析，保持请求顺序并跳过重复项。
	Users(ctx context.Context, tenantID string, userIDs []string) ([]Assignee, error)
	// UsersByRole returns every active member holding role. | UsersByRole 返回持有该角色的全部启用成员。
	UsersByRole(ctx context.Context, tenantID, role string) ([]Assignee, error)
}

// Assignee is one resolved approval candidate. | Assignee 是一个解析后的审批候选人。
type Assignee struct {
	// ID is the user id. | ID 是用户 ID。
	ID string
	// Name is the display name shown on tasks. | Name 是任务上展示的名称。
	Name string
	// Email is used by the SMTP notification channel. | Email 供 SMTP 通知渠道使用。
	Email string
	// Roles are the role names of the user inside the tenant. | Roles 是用户在租户内的角色名。
	Roles []string
	// Groups are the workflow group keys that supplied the candidate. | Groups 是提供该候选人的流程组键。
	Groups []string
}

// DecisionInput is everything a rule or AI decider may inspect. | DecisionInput 是规则或 AI 决策器可以查看的全部输入。
type DecisionInput struct {
	// Variables is the parsed instance variable object. | Variables 是解析后的实例变量对象。
	Variables map[string]any
	// TenantID, Instance, Task, Node, Definition and Version describe the context. | TenantID、
	// Instance、Task、Node、Definition 与 Version 描述上下文。
	TenantID string
	// ActorName is the display name of the actor for automatic actions. | ActorName 是自动动作操作人的展示名。
	ActorName  string
	Instance   Instance
	Version    Version
	Definition Definition
	// Rule is the rule being evaluated; zero for a direct decider call. | Rule 是正在求值的规则；
	// 直接调用决策器时为零值。
	Rule AutoRule
	Node Node
	Task Task
}

// DecisionResult is the output of a rule or AI decider. | DecisionResult 是规则或 AI 决策器的输出。
type DecisionResult struct {
	// Decision is approve, reject or none (abstain). | Decision 取 approve、reject 或 none（弃权）。
	Decision string
	// Reason is the explanation recorded on the automatic task. | Reason 是记录在自动任务上的说明。
	Reason string
	// Confidence is the decider's confidence in [0, 1]. | Confidence 是决策器在 [0, 1] 区间内的置信度。
	Confidence float64
}

// Decider is the optional automatic-approval decision maker, implemented by workflow/ai. |
// Decider 是可选的自动审批决策器，由 workflow/ai 实现。
type Decider interface {
	// Decide returns one decision for the given context. | Decide 针对给定上下文返回一个决策。
	Decide(ctx context.Context, in DecisionInput) (DecisionResult, error)
}

// Channel is one outbound notification transport. | Channel 是一种对外通知传输。
type Channel interface {
	// Name is the stable channel name used in configuration. | Name 是配置中使用的稳定渠道名。
	Name() string
	// Send delivers one notification. | Send 投递一条通知。
	Send(ctx context.Context, note Notification) error
}
