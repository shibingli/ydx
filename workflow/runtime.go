package workflow

import (
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// Instance is one execution of a published process version. | Instance 是一个已发布流程版本的一次执行。
type Instance struct {
	// CreatedAt is the UTC creation instant. | CreatedAt 是 UTC 创建时刻。
	CreatedAt time.Time `json:"created_at" gorm:"column:created_at;autoCreateTime;index:idx_wf_inst_tenant_status_updated,priority:3"`
	// UpdatedAt is the UTC last-write instant. | UpdatedAt 是 UTC 最后写入时刻。
	UpdatedAt time.Time `json:"updated_at" gorm:"column:updated_at;autoUpdateTime;index:idx_wf_inst_tenant_status_updated,priority:4;index:idx_wf_inst_tenant_category_updated,priority:3"`
	// StartedAt is the activation instant. | StartedAt 是激活时刻。
	StartedAt time.Time `json:"started_at" gorm:"column:started_at;index:idx_wf_inst_tenant_initiator_created,priority:3"`
	// EndedAt is the terminal instant; zero while running. | EndedAt 是结束时刻；运行中为零值。
	EndedAt time.Time `json:"ended_at,omitempty" gorm:"column:ended_at"`
	// DueAt is the instance deadline; zero means none. | DueAt 是实例期限；零值表示没有。
	DueAt time.Time `json:"due_at,omitempty" gorm:"column:due_at"`
	// ID is the primary key, prefixed "wfins_". | ID 是主键，前缀为 wfins_。
	ID string `json:"id" gorm:"column:id;type:varchar(64);primaryKey"`
	// TenantID is the owning tenant. | TenantID 是归属租户。
	TenantID string `json:"tenant_id" gorm:"column:tenant_id;type:varchar(64);not null;index:idx_wf_inst_tenant_status_updated,priority:1;index:idx_wf_inst_tenant_initiator_created,priority:1;index:idx_wf_inst_tenant_def_version,priority:1;index:idx_wf_inst_tenant_business,priority:1;index:idx_wf_inst_tenant_category_updated,priority:1"`
	// DefinitionID is the owning definition. | DefinitionID 是所属定义。
	DefinitionID string `json:"definition_id" gorm:"column:definition_id;type:varchar(64);not null;index:idx_wf_inst_tenant_def_version,priority:2"`
	// VersionID is the pinned immutable version. | VersionID 是绑定的不可变版本。
	VersionID string `json:"version_id" gorm:"column:version_id;type:varchar(64);not null;index:idx_wf_inst_tenant_def_version,priority:3"`
	// DefinitionKey is a denormalised copy for links that outlive a renamed definition. | DefinitionKey
	// 是为链接与历史保留的非规范化副本。
	DefinitionKey string `json:"definition_key" gorm:"column:definition_key;type:varchar(64);not null"`
	// DefinitionName is the Chinese name at start time. | DefinitionName 是发起时的中文名。
	DefinitionName string `json:"definition_name" gorm:"column:definition_name;type:varchar(120);not null"`
	// Title is the instance subject. | Title 是实例标题。
	Title string `json:"title" gorm:"column:title;type:varchar(200);not null"`
	// BusinessKey is the caller's external reference. | BusinessKey 是调用方的外部业务键。
	BusinessKey string `json:"business_key,omitempty" gorm:"column:business_key;type:varchar(128);index:idx_wf_inst_tenant_business,priority:2"`
	// Category is copied from the definition for filtering. | Category 从定义复制，便于筛选。
	Category string `json:"category,omitempty" gorm:"column:category;type:varchar(64);index:idx_wf_inst_tenant_category_updated,priority:2"`
	// InitiatorID is the user who started the instance. | InitiatorID 是发起实例的用户。
	InitiatorID string `json:"initiator_id" gorm:"column:initiator_id;type:varchar(64);not null;index:idx_wf_inst_tenant_initiator_created,priority:2"`
	// InitiatorName is the display name at start time. | InitiatorName 是发起时的展示名。
	InitiatorName string `json:"initiator_name,omitempty" gorm:"column:initiator_name;type:varchar(120)"`
	// Status is running, completed, withdrawn or terminated. | Status 取 running、completed、withdrawn 或 terminated。
	Status string `json:"status" gorm:"column:status;type:varchar(16);not null;index:idx_wf_inst_tenant_status_updated,priority:2"`
	// Outcome is approved, rejected, withdrawn or terminated; empty while running. | Outcome
	// 取 approved、rejected、withdrawn 或 terminated；运行中为空。
	Outcome string `json:"outcome,omitempty" gorm:"column:outcome;type:varchar(16)"`
	// EndedReason is the human-readable terminal reason. | EndedReason 是结束原因。
	EndedReason string `json:"ended_reason,omitempty" gorm:"column:ended_reason;type:varchar(500)"`
	// Variables is the canonical JSON object of instance variables. | Variables 是实例变量的规范化 JSON 对象。
	Variables string `json:"variables,omitempty" gorm:"column:variables;type:text"`
	// VisitedNodes is a JSON array of user-task node ids in visit order. | VisitedNodes 是用户任务节点 ID 的访问顺序 JSON 数组。
	VisitedNodes string `json:"visited_nodes,omitempty" gorm:"column:visited_nodes;type:text"`
	// CurrentNodes is a JSON array of node ids that hold live tasks. | CurrentNodes 是持有活动任务的节点 ID JSON 数组。
	CurrentNodes string `json:"current_nodes,omitempty" gorm:"column:current_nodes;type:text"`
	// Version is the pinned version number. | Version 是绑定的版本号。
	Version int `json:"version" gorm:"column:version_number;not null"`
}

// TableName pins the table name. | TableName 固定表名。
func (Instance) TableName() string { return "yd_workflow_instances" }

// Token is one live execution path through the graph. | Token 是穿过流程图的一条活动执行路径。
type Token struct {
	// CreatedAt is the UTC creation instant. | CreatedAt 是 UTC 创建时刻。
	CreatedAt time.Time `json:"created_at" gorm:"column:created_at;autoCreateTime"`
	// UpdatedAt is the UTC last-write instant. | UpdatedAt 是 UTC 最后写入时刻。
	UpdatedAt time.Time `json:"updated_at" gorm:"column:updated_at;autoUpdateTime"`
	// WaitUntil is the timer deadline. | WaitUntil 是定时器截止时间。
	WaitUntil time.Time `json:"wait_until,omitempty" gorm:"column:wait_until;index:idx_wf_tok_tenant_wait,priority:3"`
	// ID is the primary key, prefixed "wftok_". | ID 是主键，前缀为 wftok_。
	ID string `json:"id" gorm:"column:id;type:varchar(64);primaryKey"`
	// TenantID is the owning tenant. | TenantID 是归属租户。
	TenantID string `json:"tenant_id" gorm:"column:tenant_id;type:varchar(64);not null;index:idx_wf_tok_tenant_instance_status,priority:1;index:idx_wf_tok_tenant_instance_node,priority:1;index:idx_wf_tok_tenant_fork,priority:1;index:idx_wf_tok_tenant_wait,priority:1"`
	// InstanceID is the owning instance. | InstanceID 是所属实例。
	InstanceID string `json:"instance_id" gorm:"column:instance_id;type:varchar(64);not null;index:idx_wf_tok_tenant_instance_status,priority:2;index:idx_wf_tok_tenant_instance_node,priority:2"`
	// NodeID is the node the token currently sits at. | NodeID 是令牌当前所在节点。
	NodeID string `json:"node_id" gorm:"column:node_id;type:varchar(64);not null;index:idx_wf_tok_tenant_instance_node,priority:3"`
	// Status is active, waiting, completed or cancelled. | Status 取 active、waiting、completed 或 cancelled。
	Status string `json:"status" gorm:"column:status;type:varchar(16);not null;index:idx_wf_tok_tenant_instance_status,priority:3"`
	// ForkGroup links the branches of one inclusive split. | ForkGroup 关联一次包容网关分支的全部分支。
	ForkGroup string `json:"fork_group,omitempty" gorm:"column:fork_group;type:varchar(64);index:idx_wf_tok_tenant_fork,priority:2"`
	// ForkNode is the split node that created the group. | ForkNode 是创建该分支组的网关节点。
	ForkNode string `json:"fork_node,omitempty" gorm:"column:fork_node;type:varchar(64)"`
	// Remaining is the JSON plan of assignees still to be activated in sequential mode. |
	// Remaining 是顺序模式中尚未激活的审批人计划 JSON。
	Remaining string `json:"remaining,omitempty" gorm:"column:remaining;type:text"`
	// WaitType is timer or message while the token waits on a catch event. | WaitType 在令牌等待捕获事件时取 timer 或 message。
	WaitType string `json:"wait_type,omitempty" gorm:"column:wait_type;type:varchar(16)"`
	// MessageName is the signal name the token waits for. | MessageName 是令牌等待的信号名。
	MessageName string `json:"message_name,omitempty" gorm:"column:message_name;type:varchar(128)"`
	// WaitGroup links the competing tokens of one event-based gateway. | WaitGroup 关联一个事件网关的竞争令牌。
	WaitGroup string `json:"wait_group,omitempty" gorm:"column:wait_group;type:varchar(64);index:idx_wf_tok_tenant_wait,priority:2"`
	// Seq orders tokens created by the same split. | Seq 为同一分支创建的令牌排序。
	Seq int `json:"seq,omitempty" gorm:"column:seq_order;not null;default:0"`
}

// TableName pins the table name. | TableName 固定表名。
func (Token) TableName() string { return "yd_workflow_tokens" }

// Task is one human decision waiting for, or already given by, one assignee. | Task
// 是一个审批人对某项工作的待处理或已处理决策。
type Task struct {
	// CreatedAt is the UTC creation instant. | CreatedAt 是 UTC 创建时刻。
	CreatedAt time.Time `json:"created_at" gorm:"column:created_at;autoCreateTime;index:idx_wf_task_tenant_assignee_status_created,priority:4"`
	// UpdatedAt is the UTC last-write instant. | UpdatedAt 是 UTC 最后写入时刻。
	UpdatedAt time.Time `json:"updated_at" gorm:"column:updated_at;autoUpdateTime"`
	// DueAt is the task deadline; zero means none. | DueAt 是任务期限；零值表示没有。
	DueAt time.Time `json:"due_at,omitempty" gorm:"column:due_at;index:idx_wf_task_tenant_status_due,priority:3"`
	// ClaimedAt is when the task was claimed; zero before. | ClaimedAt 是签收时刻；之前为零值。
	ClaimedAt time.Time `json:"claimed_at,omitempty" gorm:"column:claimed_at"`
	// CompletedAt is when the decision was made; zero before. | CompletedAt 是决策时刻；之前为零值。
	CompletedAt time.Time `json:"completed_at,omitempty" gorm:"column:completed_at"`
	// LastRemindAt is the last reminder instant. | LastRemindAt 是最近一次催办时刻。
	LastRemindAt time.Time `json:"last_remind_at,omitempty" gorm:"column:last_remind_at"`
	// NextRemindAt is the earliest time the scheduler may remind again. | NextRemindAt 是调度器最早可再次催办的时间。
	NextRemindAt time.Time `json:"next_remind_at,omitempty" gorm:"column:next_remind_at;index:idx_wf_task_tenant_status_due,priority:4"`
	// ID is the primary key, prefixed "wftsk_". | ID 是主键，前缀为 wftsk_。
	ID string `json:"id" gorm:"column:id;type:varchar(64);primaryKey"`
	// TenantID is the owning tenant. | TenantID 是归属租户。
	TenantID string `json:"tenant_id" gorm:"column:tenant_id;type:varchar(64);not null;index:idx_wf_task_tenant_assignee_status_created,priority:1;index:idx_wf_task_tenant_instance,priority:1;index:idx_wf_task_tenant_token,priority:1;index:idx_wf_task_tenant_status_due,priority:1;index:idx_wf_task_tenant_category,priority:1"`
	// InstanceID is the owning instance. | InstanceID 是所属实例。
	InstanceID string `json:"instance_id" gorm:"column:instance_id;type:varchar(64);not null;index:idx_wf_task_tenant_instance,priority:2"`
	// TokenID is the node token this task belongs to. | TokenID 是任务所属的节点令牌。
	TokenID string `json:"token_id" gorm:"column:token_id;type:varchar(64);not null;index:idx_wf_task_tenant_token,priority:2"`
	// NodeID is the user-task node id. | NodeID 是用户任务节点 ID。
	NodeID string `json:"node_id" gorm:"column:node_id;type:varchar(64);not null"`
	// NodeName is the Chinese node name at creation. | NodeName 是创建时的中文节点名。
	NodeName string `json:"node_name" gorm:"column:node_name;type:varchar(120)"`
	// NodeNameEN is the English node name at creation. | NodeNameEN 是创建时的英文节点名。
	NodeNameEN string `json:"node_name_en,omitempty" gorm:"column:node_name_en;type:varchar(120)"`
	// AssigneeID is the current assignee; empty for an unclaimed pool task. | AssigneeID 是当前指派人；候选池任务为空。
	AssigneeID string `json:"assignee_id,omitempty" gorm:"column:assignee_id;type:varchar(64);index:idx_wf_task_tenant_assignee_status_created,priority:2"`
	// AssigneeName is the display name at assignment time. | AssigneeName 是指派时的展示名。
	AssigneeName string `json:"assignee_name,omitempty" gorm:"column:assignee_name;type:varchar(120)"`
	// AssigneeType is user, role or initiator as configured. | AssigneeType 是配置的 user、role 或 initiator。
	AssigneeType string `json:"assignee_type,omitempty" gorm:"column:assignee_type;type:varchar(16)"`
	// OriginalAssigneeID is the owner before delegation; empty when not delegated. | OriginalAssigneeID
	// 是委派前的任务所有者；未委派时为空。
	OriginalAssigneeID string `json:"original_assignee_id,omitempty" gorm:"column:original_assignee_id;type:varchar(64)"`
	// OriginalAssigneeName is the display name of the owner before delegation. | OriginalAssigneeName
	// 是委派前所有者的展示名。
	OriginalAssigneeName string `json:"original_assignee_name,omitempty" gorm:"column:original_assignee_name;type:varchar(120)"`
	// DelegatedTo is the current delegate; empty when not delegated. | DelegatedTo 是当前受托人；未委派时为空。
	DelegatedTo string `json:"delegated_to,omitempty" gorm:"column:delegated_to;type:varchar(64)"`
	// DelegatedFrom is the delegate who handed the task back. | DelegatedFrom 是交回任务的受托人。
	DelegatedFrom string `json:"delegated_from,omitempty" gorm:"column:delegated_from;type:varchar(64)"`
	// CandidateRefs is a pipe-delimited candidate index used by inbox queries. | CandidateRefs
	// 是用竖线分隔的候选人索引，供收件箱查询使用。
	CandidateRefs string `json:"-" gorm:"column:candidate_refs;type:text"`
	// Status is pending, claimed, completed or cancelled. | Status 取 pending、claimed、completed 或 cancelled。
	Status string `json:"status" gorm:"column:status;type:varchar(16);not null;index:idx_wf_task_tenant_assignee_status_created,priority:3;index:idx_wf_task_tenant_status_due,priority:2"`
	// Decision is none, approve or reject. | Decision 取 none、approve 或 reject。
	Decision string `json:"decision" gorm:"column:decision;type:varchar(16);not null;default:'none'"`
	// Comment is the approver's note. | Comment 是审批意见。
	Comment string `json:"comment,omitempty" gorm:"column:comment;type:varchar(2000)"`
	// FormData is the JSON object submitted with this task. | FormData 是随任务提交的 JSON 对象。
	FormData string `json:"form_data,omitempty" gorm:"column:form_data;type:text"`
	// InstanceTitle is a list projection, not a column. | InstanceTitle 是列表投影，不是表列。
	InstanceTitle string `json:"instance_title,omitempty" gorm:"-"`
	// InstanceInitiator is a list projection, not a column. | InstanceInitiator 是列表投影，不是表列。
	InstanceInitiator string `json:"instance_initiator,omitempty" gorm:"-"`
	// DefinitionKey is the definition key copied at creation. | DefinitionKey 是创建时复制的定义键。
	DefinitionKey string `json:"definition_key,omitempty" gorm:"column:definition_key;type:varchar(64);index:idx_wf_task_tenant_category,priority:2"`
	// Category is the process category copied at creation. | Category 是创建时复制的流程分类。
	Category string `json:"category,omitempty" gorm:"column:category;type:varchar(64);index:idx_wf_task_tenant_category,priority:3"`
	// Candidates is the JSON array of candidate ids for claim and grab tasks. | Candidates
	// 是签收与抢单任务的候选用户 ID JSON 数组。
	Candidates []string `json:"candidates,omitempty" gorm:"column:candidates;type:text;serializer:json"`
	// Seq orders tasks inside one node. | Seq 为同一节点内任务排序。
	Seq int `json:"seq" gorm:"column:seq_order;not null;default:0"`
	// Priority is the display priority. | Priority 是展示优先级。
	Priority int `json:"priority,omitempty" gorm:"column:priority;not null;default:0"`
	// RemindCount is the number of reminders already sent. | RemindCount 是已发送的催办次数。
	RemindCount int `json:"remind_count" gorm:"column:remind_count;not null;default:0"`
	// MaxRemind is the reminder ceiling copied from the node. | MaxRemind 是从节点复制的催办上限。
	MaxRemind int `json:"max_remind" gorm:"column:max_remind;not null;default:0"`
	// RemindEverySeconds is the reminder interval copied from the node. | RemindEverySeconds 是从节点复制的催办间隔秒数。
	RemindEverySeconds int `json:"remind_every_seconds" gorm:"column:remind_every_seconds;not null;default:0"`
}

// TableName pins the table name. | TableName 固定表名。
func (Task) TableName() string { return "yd_workflow_tasks" }

// TaskCandidate is one normalised candidate assignment. It exists so an inbox query can use an
// index instead of a leading-wildcard LIKE over a JSON column. | TaskCandidate 是一条规范化的
// 候选人指派；它的存在使收件箱查询可以使用索引，而不是对 JSON 列做前导通配符 LIKE。
type TaskCandidate struct {
	// CreatedAt is the UTC creation instant. | CreatedAt 是 UTC 创建时刻。
	CreatedAt time.Time `json:"created_at" gorm:"column:created_at;autoCreateTime"`
	// ID is the primary key, prefixed "wfcnd_". | ID 是主键，前缀为 wfcnd_。
	ID string `json:"id" gorm:"column:id;type:varchar(160);primaryKey"`
	// TenantID is the owning tenant. | TenantID 是归属租户。
	TenantID string `json:"tenant_id" gorm:"column:tenant_id;type:varchar(64);not null;uniqueIndex:uidx_wf_candidate,priority:1;index:idx_wf_candidate_tenant_user,priority:1"`
	// TaskID is the candidate task. | TaskID 是候选任务。
	TaskID string `json:"task_id" gorm:"column:task_id;type:varchar(64);not null;uniqueIndex:uidx_wf_candidate,priority:2"`
	// UserID is the candidate user. | UserID 是候选用户。
	UserID string `json:"user_id" gorm:"column:user_id;type:varchar(64);not null;uniqueIndex:uidx_wf_candidate,priority:3;index:idx_wf_candidate_tenant_user,priority:2"`
}

// TableName pins the table name. | TableName 固定表名。
func (TaskCandidate) TableName() string { return "yd_workflow_task_candidates" }

// Event is one append-only timeline entry. | Event 是一条追加式时间线记录。
type Event struct {
	// CreatedAt is the UTC creation instant. | CreatedAt 是 UTC 创建时刻。
	CreatedAt time.Time `json:"created_at" gorm:"column:created_at;autoCreateTime;index:idx_wf_event_tenant_instance_created,priority:3"`
	// ID is the primary key, prefixed "wfeve_". | ID 是主键，前缀为 wfeve_。
	ID string `json:"id" gorm:"column:id;type:varchar(64);primaryKey"`
	// TenantID is the owning tenant. | TenantID 是归属租户。
	TenantID string `json:"tenant_id" gorm:"column:tenant_id;type:varchar(64);not null;index:idx_wf_event_tenant_instance_created,priority:1"`
	// InstanceID is the owning instance. | InstanceID 是所属实例。
	InstanceID string `json:"instance_id" gorm:"column:instance_id;type:varchar(64);not null;index:idx_wf_event_tenant_instance_created,priority:2"`
	// TaskID is the related task, when any. | TaskID 是相关任务（如有）。
	TaskID string `json:"task_id,omitempty" gorm:"column:task_id;type:varchar(64)"`
	// NodeID is the related node, when any. | NodeID 是相关节点（如有）。
	NodeID string `json:"node_id,omitempty" gorm:"column:node_id;type:varchar(64)"`
	// ActorID is the user who caused the event; "system" for automatic actions. | ActorID
	// 是触发事件的用户；自动动作使用 system。
	ActorID string `json:"actor_id,omitempty" gorm:"column:actor_id;type:varchar(64)"`
	// ActorName is the actor display name. | ActorName 是操作人展示名。
	ActorName string `json:"actor_name,omitempty" gorm:"column:actor_name;type:varchar(120)"`
	// Type is one Event* constant. | Type 取一个 Event* 常量。
	Type string `json:"type" gorm:"column:event_type;type:varchar(48);not null"`
	// Message is the bilingual human-readable summary. | Message 是中英双语的人类可读摘要。
	Message string `json:"message,omitempty" gorm:"column:message;type:varchar(500)"`
	// Detail is optional JSON metadata. | Detail 是可选的 JSON 元数据。
	Detail string `json:"detail,omitempty" gorm:"column:detail;type:text"`
}

// TableName pins the table name. | TableName 固定表名。
func (Event) TableName() string { return "yd_workflow_events" }

// Comment is one approval note or system remark on an instance. | Comment 是实例上的一条审批意见或系统备注。
type Comment struct {
	// CreatedAt is the UTC creation instant. | CreatedAt 是 UTC 创建时刻。
	CreatedAt time.Time `json:"created_at" gorm:"column:created_at;autoCreateTime;index:idx_wf_comment_tenant_instance_created,priority:3"`
	// ID is the primary key, prefixed "wfcmt_". | ID 是主键，前缀为 wfcmt_。
	ID string `json:"id" gorm:"column:id;type:varchar(64);primaryKey"`
	// TenantID is the owning tenant. | TenantID 是归属租户。
	TenantID string `json:"tenant_id" gorm:"column:tenant_id;type:varchar(64);not null;index:idx_wf_comment_tenant_instance_created,priority:1"`
	// InstanceID is the owning instance. | InstanceID 是所属实例。
	InstanceID string `json:"instance_id" gorm:"column:instance_id;type:varchar(64);not null;index:idx_wf_comment_tenant_instance_created,priority:2"`
	// TaskID is the related task, when any. | TaskID 是相关任务（如有）。
	TaskID string `json:"task_id,omitempty" gorm:"column:task_id;type:varchar(64)"`
	// AuthorID is the author id; "system" for automatic remarks. | AuthorID 是作者 ID；系统备注使用 system。
	AuthorID string `json:"author_id" gorm:"column:author_id;type:varchar(64)"`
	// AuthorName is the author display name. | AuthorName 是作者展示名。
	AuthorName string `json:"author_name,omitempty" gorm:"column:author_name;type:varchar(120)"`
	// Kind is comment or system. | Kind 取 comment 或 system。
	Kind string `json:"kind" gorm:"column:kind;type:varchar(16);not null;default:'comment'"`
	// Body is the note text. | Body 是备注正文。
	Body string `json:"body" gorm:"column:body;type:varchar(2000);not null"`
}

// TableName pins the table name. | TableName 固定表名。
func (Comment) TableName() string { return "yd_workflow_comments" }

// Notification is one durable outbox row for one recipient. | Notification 是一条面向单个接收人的持久化发件箱记录。
type Notification struct {
	// CreatedAt is the UTC creation instant. | CreatedAt 是 UTC 创建时刻。
	CreatedAt time.Time `json:"created_at" gorm:"column:created_at;autoCreateTime;index:idx_wf_notify_tenant_status_created,priority:3"`
	// UpdatedAt is the UTC last-write instant. | UpdatedAt 是 UTC 最后写入时刻。
	UpdatedAt time.Time `json:"updated_at" gorm:"column:updated_at;autoUpdateTime"`
	// SentAt is the successful delivery instant. | SentAt 是成功投递时刻。
	SentAt time.Time `json:"sent_at,omitempty" gorm:"column:sent_at"`
	// NextAttemptAt is the earliest retry instant. | NextAttemptAt 是最早重试时刻。
	NextAttemptAt time.Time `json:"next_attempt_at,omitempty" gorm:"column:next_attempt_at"`
	// ID is the primary key, prefixed "wfntf_". | ID 是主键，前缀为 wfntf_。
	ID string `json:"id" gorm:"column:id;type:varchar(64);primaryKey"`
	// TenantID is the owning tenant. | TenantID 是归属租户。
	TenantID string `json:"tenant_id" gorm:"column:tenant_id;type:varchar(64);not null;index:idx_wf_notify_tenant_status_created,priority:1;index:idx_wf_notify_tenant_instance,priority:1"`
	// InstanceID is the related instance. | InstanceID 是相关实例。
	InstanceID string `json:"instance_id,omitempty" gorm:"column:instance_id;type:varchar(64);index:idx_wf_notify_tenant_instance,priority:2"`
	// TaskID is the related task, when any. | TaskID 是相关任务（如有）。
	TaskID string `json:"task_id,omitempty" gorm:"column:task_id;type:varchar(64)"`
	// RecipientID is the user who receives the notification. | RecipientID 是接收通知的用户。
	RecipientID string `json:"recipient_id" gorm:"column:recipient_id;type:varchar(64);not null"`
	// RecipientName is the display name at creation time. | RecipientName 是创建时的展示名。
	RecipientName string `json:"recipient_name,omitempty" gorm:"column:recipient_name;type:varchar(120)"`
	// RecipientAddress is the e-mail address used by the SMTP channel; it never enters an API payload. |
	// RecipientAddress 是 SMTP 渠道使用的邮箱地址；它不会进入 API 载荷。
	RecipientAddress string `json:"-" gorm:"column:recipient_address;type:varchar(320)"`
	// Kind is one Notify* constant. | Kind 取一个 Notify* 常量。
	Kind string `json:"kind" gorm:"column:kind;type:varchar(32);not null"`
	// Channels is a comma-separated list of channel names; empty means every configured channel. |
	// Channels 是逗号分隔的渠道名；空表示全部已配置渠道。
	Channels string `json:"channels,omitempty" gorm:"column:channels;type:varchar(200)"`
	// Status is pending, sent or failed. | Status 取 pending、sent 或 failed。
	Status string `json:"status" gorm:"column:status;type:varchar(16);not null;index:idx_wf_notify_tenant_status_created,priority:2"`
	// Title is the notification subject. | Title 是通知标题。
	Title string `json:"title" gorm:"column:title;type:varchar(200)"`
	// Body is the notification text. | Body 是通知正文。
	Body string `json:"body" gorm:"column:body;type:text"`
	// URL is the deep link the recipient should open. | URL 是接收人应打开的深链。
	URL string `json:"url,omitempty" gorm:"column:url;type:varchar(500)"`
	// LastError is the last failure summary. | LastError 是最近一次失败摘要。
	LastError string `json:"last_error,omitempty" gorm:"column:last_error;type:varchar(500)"`
	// Attempts is the number of delivery attempts. | Attempts 是投递尝试次数。
	Attempts int `json:"attempts" gorm:"column:attempts;not null;default:0"`
}

// TableName pins the table name. | TableName 固定表名。
func (Notification) TableName() string { return "yd_workflow_notifications" }

// InstanceFilter selects one page of instances. | InstanceFilter 选择一页实例。
type InstanceFilter struct {
	// Query matches title, business key and initiator name. | Query 匹配标题、业务键与发起人展示名。
	Query string
	// Status, Category, DefinitionID and InitiatorID narrow the page. | Status、Category、DefinitionID 与
	// InitiatorID 收窄分页结果。
	Status       string
	Category     string
	DefinitionID string
	InitiatorID  string
	// Lean omits the variable and node-snapshot payloads from list rows; detail reads keep them.
	// | Lean 让列表行省略变量与节点快照载荷；详情读取仍保留。
	Lean bool
	// Page and PageSize are 1-based. | Page 与 PageSize 从 1 开始。
	Page     int
	PageSize int
}

// InstancePage is one page of instances. | InstancePage 是一页实例。
type InstancePage struct {
	// Items are the rows in this page. | Items 是本页记录。
	Items []Instance `json:"items"`
	// Total is the number of matching instances. | Total 是匹配总数。
	Total int `json:"total"`
	// Page and PageSize echo the effective paging. | Page 与 PageSize 回显生效的分页。
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
}

// TaskFilter selects one page of tasks. | TaskFilter 选择一页任务。
type TaskFilter struct {
	// Query matches the instance title, initiator and node name. | Query 匹配实例标题、发起人与节点名。
	Query string
	// Status limits one task state; empty means every open state. | Status 限定一个任务状态；空表示全部未结束状态。
	Status string
	// ActorID selects tasks assigned to or claimable by that user. | ActorID 选择分配给该用户或该用户可抢的任务。
	ActorID string
	// AssigneeID selects tasks assigned to exactly that user. | AssigneeID 精确选择指派人。
	AssigneeID string
	// CandidateID selects pool tasks naming that candidate. | CandidateID 选择候选池中包含该用户的任务。
	CandidateID string
	// InstanceID, DefinitionID and Category narrow the page. | InstanceID、DefinitionID 与 Category 收窄分页结果。
	InstanceID   string
	DefinitionID string
	Category     string
	// Statuses lists several states, used by inbox tabs. | Statuses 列出多个状态，供收件箱页签使用。
	Statuses []string
	// Page and PageSize are 1-based. | Page 与 PageSize 从 1 开始。
	Page     int
	PageSize int
	// Overdue selects tasks whose deadline has passed. | Overdue 选择已过截止时间的任务。
	Overdue bool
}

// TaskPage is one page of tasks. | TaskPage 是一页任务。
type TaskPage struct {
	// Items are the rows in this page. | Items 是本页记录。
	Items []Task `json:"items"`
	// Total is the number of matching tasks. | Total 是匹配总数。
	Total int `json:"total"`
	// Page and PageSize echo the effective paging. | Page 与 PageSize 回显生效的分页。
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
}

// Stats summarises one tenant's workflow surface. | Stats 汇总一个租户的流程概况。
type Stats struct {
	// Definitions is the number of definitions. | Definitions 是定义数量。
	Definitions int `json:"definitions"`
	// Published is the number of published definitions. | Published 是已发布定义数量。
	Published int `json:"published"`
	// Instances is the number of instances. | Instances 是实例数量。
	Instances int `json:"instances"`
	// Running, Completed, Withdrawn and Rejected count instances by state. | Running、Completed、
	// Withdrawn 与 Rejected 按状态统计实例。
	Running   int `json:"running"`
	Completed int `json:"completed"`
	Withdrawn int `json:"withdrawn"`
	Rejected  int `json:"rejected"`
	// PendingTasks and OverdueTasks count actionable human work. | PendingTasks 与 OverdueTasks 统计待处理人工工作。
	PendingTasks int `json:"pending_tasks"`
	OverdueTasks int `json:"overdue_tasks"`
}

// InstanceDetail is the complete view of one instance. | InstanceDetail 是一个实例的完整视图。
type InstanceDetail struct {
	// Variables is the parsed instance variable object. | Variables 是解析后的实例变量对象。
	Variables map[string]any `json:"variables"`
	// Instance is the instance row. | Instance 是实例记录。
	Instance Instance `json:"instance"`
	// Version is the pinned version. | Version 是绑定的版本。
	Version Version `json:"version"`
	// Design is the parsed design of the pinned version. | Design 是绑定版本解析后的设计。
	Design Design `json:"design"`
	// Tasks, Events and Comments are the audit surface. | Tasks、Events 与 Comments 是审计面。
	Tasks    []Task    `json:"tasks"`
	Events   []Event   `json:"events"`
	Comments []Comment `json:"comments"`
	// Definition is the owning definition. | Definition 是所属定义。
	Definition Definition `json:"definition"`
}

// TaskDetail is the complete view of one task. | TaskDetail 是一个任务的完整视图。
type TaskDetail struct {
	// Variables is the parsed instance variable object. | Variables 是解析后的实例变量对象。
	Variables map[string]any `json:"variables"`
	// Instance is the owning instance. | Instance 是所属实例。
	Instance Instance `json:"instance"`
	// Version is the pinned version. | Version 是绑定的版本。
	Version Version `json:"version"`
	// Comments are the instance comments. | Comments 是实例评论。
	Comments []Comment `json:"comments"`
	// Design is the parsed design of the pinned version. | Design 是绑定版本解析后的设计。
	Design Design `json:"design"`
	// Definition is the owning definition. | Definition 是所属定义。
	Definition Definition `json:"definition"`
	// Node is the current node. | Node 是当前节点。
	Node Node `json:"node"`
	// Task is the task row. | Task 是任务记录。
	Task Task `json:"task"`
}

// applyInstanceProjection fills the denormalized instance display fields on a task that was read
// without the store's projection query. | applyInstanceProjection 为没有经过存储投影查询读取的
// 任务填充反规范化的实例展示字段。
func (t *Task) applyInstanceProjection(inst Instance) {
	t.InstanceTitle = inst.Title
	t.InstanceInitiator = inst.InitiatorName
	if t.DefinitionKey == "" {
		t.DefinitionKey = inst.DefinitionKey
	}
	if t.Category == "" {
		t.Category = inst.Category
	}
}

// CandidateList decodes the JSON candidate list. | CandidateList 解码 JSON 候选人列表。
func (t Task) CandidateList() []string {
	if len(t.Candidates) == 0 {
		return nil
	}
	out := make([]string, 0, len(t.Candidates))
	for _, id := range t.Candidates {
		if id = strings.TrimSpace(id); id != "" {
			out = append(out, id)
		}
	}
	return out
}

// CandidateIndex builds the pipe-delimited index used by inbox queries. | CandidateIndex
// 构建收件箱查询使用的竖线分隔索引。
func CandidateIndex(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	var b strings.Builder
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		b.WriteByte('|')
		b.WriteString(id)
	}
	if b.Len() == 0 {
		return ""
	}
	b.WriteByte('|')
	return b.String()
}

// ParseVariables decodes a JSON object, returning an empty map for empty input. | ParseVariables
// 解码 JSON 对象；空输入返回空映射。
func ParseVariables(raw string) (map[string]any, error) {
	if strings.TrimSpace(raw) == "" {
		return map[string]any{}, nil
	}
	out := map[string]any{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, errs.Wrap(err, ErrInvalidInput)
	}
	return out, nil
}

// DecodeStringList decodes a JSON string array, returning nil for empty input. | DecodeStringList
// 解码 JSON 字符串数组；空输入返回 nil。
func DecodeStringList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	out := []string{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

// EncodeStringList encodes a string array, returning an empty JSON array for nil. | EncodeStringList
// 编码字符串数组；nil 返回空 JSON 数组。
func EncodeStringList(values []string) string {
	if values == nil {
		values = []string{}
	}
	data, err := json.Marshal(values)
	if err != nil {
		return "[]"
	}
	return string(data)
}
