package workflow

import (
	"sort"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/regexpx"
)

// keyRe constrains a definition key: a stable lower-case slug that survives URLs and JSON. |
// keyRe 约束流程定义键：可安全用于 URL 与 JSON 的稳定小写短标识。
var keyRe = regexpx.MustCompile(`^[a-z][a-z0-9_-]{1,63}$`)

// nodeIDRe constrains a node or edge identifier inside one design. | nodeIDRe 约束单个设计内的节点或连线标识。
var nodeIDRe = regexpx.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)

// fieldKeyRe constrains a form field key. | fieldKeyRe 约束表单字段键。
var fieldKeyRe = regexpx.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

// Definition is a versioned process definition owned by one tenant. | Definition 是一个租户拥有的多版本流程定义。
type Definition struct {
	// CreatedAt is the UTC creation instant. | CreatedAt 是 UTC 创建时刻。
	CreatedAt time.Time `json:"created_at" gorm:"column:created_at;autoCreateTime;index:idx_wf_def_tenant_status_updated,priority:3"`
	// UpdatedAt is the UTC last-write instant. | UpdatedAt 是 UTC 最后写入时刻。
	UpdatedAt time.Time `json:"updated_at" gorm:"column:updated_at;autoUpdateTime;index:idx_wf_def_tenant_status_updated,priority:4"`
	// ID is the primary key, prefixed "wfdef_". | ID 是主键，前缀为 wfdef_。
	ID string `json:"id" gorm:"column:id;type:varchar(64);primaryKey"`
	// TenantID is the owning tenant and the first column of every index. | TenantID 是归属租户，也是每个索引的首列。
	TenantID string `json:"tenant_id" gorm:"column:tenant_id;type:varchar(64);not null;uniqueIndex:uidx_wf_def_key,priority:1;index:idx_wf_def_tenant_status_updated,priority:1;index:idx_wf_def_tenant_category,priority:1"`
	// Key is the immutable public identifier, unique inside the tenant. | Key 是不可变公共标识，租户内唯一。
	Key string `json:"key" gorm:"column:def_key;type:varchar(64);not null;uniqueIndex:uidx_wf_def_key,priority:2"`
	// Name is the Chinese display name. | Name 是中文展示名。
	Name string `json:"name" gorm:"column:name;type:varchar(120);not null"`
	// NameEN is the English display name. | NameEN 是英文展示名。
	NameEN string `json:"name_en,omitempty" gorm:"column:name_en;type:varchar(120)"`
	// Description explains the process. | Description 说明流程用途。
	Description string `json:"description,omitempty" gorm:"column:description;type:varchar(1000)"`
	// Category groups processes for filters and auto-approval rules. | Category 为筛选与自动审批规则分组流程。
	Category string `json:"category,omitempty" gorm:"column:category;type:varchar(64);index:idx_wf_def_tenant_category,priority:2"`
	// Icon is a lucide icon name rendered by the shared icon partial. | Icon 是共享图标片段渲染的 lucide 图标名。
	Icon string `json:"icon,omitempty" gorm:"column:icon;type:varchar(64)"`
	// Status is draft, published or disabled. | Status 取 draft、published 或 disabled。
	Status string `json:"status" gorm:"column:status;type:varchar(16);not null;index:idx_wf_def_tenant_status_updated,priority:2"`
	// CreatedBy and UpdatedBy record the acting administrator. | CreatedBy 与 UpdatedBy 记录操作的管理员。
	CreatedBy string `json:"created_by,omitempty" gorm:"column:created_by;type:varchar(64)"`
	// UpdatedBy is the last administrator who changed the definition. | UpdatedBy 是最后修改该定义的管理员。
	UpdatedBy string `json:"updated_by,omitempty" gorm:"column:updated_by;type:varchar(64)"`
	// CurrentVersion is the latest published version number, zero before the first publish. | CurrentVersion
	// 是最近发布的版本号，首次发布前为 0。
	CurrentVersion int `json:"current_version" gorm:"column:current_version;not null;default:0"`
	// VersionCount is a query projection, not a column. | VersionCount 是查询投影，不是表列。
	VersionCount int `json:"version_count" gorm:"-"`
	// InstanceCount is a query projection, not a column. | InstanceCount 是查询投影，不是表列。
	InstanceCount int `json:"instance_count" gorm:"-"`
}

// TableName pins the table name. | TableName 固定表名。
func (Definition) TableName() string { return "yd_workflow_definitions" }

// Version is one immutable published or editable draft snapshot of a definition. | Version
// 是流程定义的一个可编辑草稿或不可变已发布快照。
type Version struct {
	// CreatedAt is the UTC creation instant. | CreatedAt 是 UTC 创建时刻。
	CreatedAt time.Time `json:"created_at" gorm:"column:created_at;autoCreateTime"`
	// UpdatedAt is the UTC last-write instant. | UpdatedAt 是 UTC 最后写入时刻。
	UpdatedAt time.Time `json:"updated_at" gorm:"column:updated_at;autoUpdateTime"`
	// PublishedAt is the publication instant; zero while draft. | PublishedAt 是发布时刻；草稿时为零值。
	PublishedAt time.Time `json:"published_at,omitempty" gorm:"column:published_at"`
	// ID is the primary key, prefixed "wfver_". | ID 是主键，前缀为 wfver_。
	ID string `json:"id" gorm:"column:id;type:varchar(64);primaryKey"`
	// TenantID is the owning tenant. | TenantID 是归属租户。
	TenantID string `json:"tenant_id" gorm:"column:tenant_id;type:varchar(64);not null;uniqueIndex:uidx_wf_ver_number,priority:1;index:idx_wf_ver_tenant_def_status,priority:1"`
	// DefinitionID is the owning definition. | DefinitionID 是所属定义。
	DefinitionID string `json:"definition_id" gorm:"column:definition_id;type:varchar(64);not null;uniqueIndex:uidx_wf_ver_number,priority:2;index:idx_wf_ver_tenant_def_status,priority:2"`
	// Status is draft or published. | Status 取 draft 或 published。
	Status string `json:"status" gorm:"column:status;type:varchar(16);not null;index:idx_wf_ver_tenant_def_status,priority:3"`
	// Design is the canonical JSON design document. | Design 是规范化后的 JSON 设计文档。
	Design string `json:"design" gorm:"column:design;type:text;not null"`
	// BPMN is the derived BPMN 2.0 XML document. | BPMN 是派生的 BPMN 2.0 XML 文档。
	BPMN string `json:"bpmn,omitempty" gorm:"column:bpmn;type:text"`
	// Checksum is the SHA-256 of Design, used to detect drift. | Checksum 是 Design 的 SHA-256，用于检测漂移。
	Checksum string `json:"checksum,omitempty" gorm:"column:checksum;type:varchar(64)"`
	// Note is the publication note. | Note 是发布说明。
	Note string `json:"note,omitempty" gorm:"column:note;type:varchar(500)"`
	// PublishedBy is the administrator who published this version. | PublishedBy 是发布该版本的管理员。
	PublishedBy string `json:"published_by,omitempty" gorm:"column:published_by;type:varchar(64)"`
	// CreatedBy is the administrator who created this draft. | CreatedBy 是创建该草稿的管理员。
	CreatedBy string `json:"created_by,omitempty" gorm:"column:created_by;type:varchar(64)"`
	// Version is the monotonically increasing version number. | Version 是单调递增的版本号。
	Version int `json:"version" gorm:"column:version_number;not null;uniqueIndex:uidx_wf_ver_number,priority:3"`
}

// TableName pins the table name. | TableName 固定表名。
func (Version) TableName() string { return "yd_workflow_versions" }

// VersionSummary is the lightweight identity and lifecycle projection of one version. Lists and
// pickers need the version number and draft/published state, not the design or BPMN documents. |
// VersionSummary 是一个版本的轻量标识与生命周期投影。列表与选择器只需要版本号与草稿/已发布状态，
// 不需要设计或 BPMN 文档。
type VersionSummary struct {
	// ID is the version primary key. | ID 是版本主键。
	ID string `json:"id"`
	// DefinitionID is the owning definition. | DefinitionID 是所属定义。
	DefinitionID string `json:"definition_id"`
	// Status is draft or published. | Status 取 draft 或 published。
	Status string `json:"status"`
	// Note is the publication note shown in version drawers. | Note 是版本抽屉展示的说明。
	Note string `json:"note,omitempty"`
	// PublishedAt is the publication instant; zero while draft. | PublishedAt 是发布时刻；草稿时为零值。
	PublishedAt time.Time `json:"published_at,omitempty"`
	// Version is the monotonically increasing version number. | Version 是单调递增的版本号。
	Version int `json:"version"`
}

// Position is the designer coordinate of one node. | Position 是节点在设计器中的坐标。
type Position struct {
	// X is the horizontal coordinate in CSS pixels. | X 是水平坐标（CSS 像素）。
	X float64 `json:"x"`
	// Y is the vertical coordinate in CSS pixels. | Y 是垂直坐标（CSS 像素）。
	Y float64 `json:"y"`
}

// FormOption is one selectable option of a form field. | FormOption 是表单字段的一个可选项。
type FormOption struct {
	// Value is the machine value submitted. | Value 是提交的机器值。
	Value string `json:"value"`
	// Label is the Chinese label. | Label 是中文标签。
	Label string `json:"label"`
	// LabelEN is the English label. | LabelEN 是英文标签。
	LabelEN string `json:"label_en,omitempty"`
}

// FormField describes one value collected by the start form or a task form. | FormField
// 描述发起表单或任务表单收集的一个值。
type FormField struct {
	// Key is the machine key stored in the instance variables. | Key 是存入实例变量的机器键。
	Key string `json:"key"`
	// Label is the Chinese label. | Label 是中文标签。
	Label string `json:"label"`
	// LabelEN is the English label. | LabelEN 是英文标签。
	LabelEN string `json:"label_en,omitempty"`
	// Type is text, textarea, number, date, datetime, select or checkbox. | Type 取 text、textarea、
	// number、date、datetime、select 或 checkbox。
	Type string `json:"type"`
	// Placeholder is the Chinese hint. | Placeholder 是中文提示。
	Placeholder string `json:"placeholder,omitempty"`
	// PlaceholderEN is the English hint. | PlaceholderEN 是英文提示。
	PlaceholderEN string `json:"placeholder_en,omitempty"`
	// Default is the initial value. | Default 是初始值。
	Default string `json:"default,omitempty"`
	// Pattern is an optional regular expression the value must match. | Pattern 是取值必须匹配的可选正则。
	Pattern string `json:"pattern,omitempty"`
	// Options lists the selectable values of a select field. | Options 列出选择型字段的可选值。
	Options []FormOption `json:"options,omitempty"`
	// Min and Max bound a numeric field. | Min 与 Max 限制数值字段。
	Min float64 `json:"min,omitempty"`
	Max float64 `json:"max,omitempty"`
	// MaxLength bounds the rune length of a text field. | MaxLength 限制文本字段的符文长度。
	MaxLength int `json:"max_length,omitempty"`
	// Required marks the field mandatory. | Required 标记字段必填。
	Required bool `json:"required,omitempty"`
}

// Assignment selects the assignees of a user task. | Assignment 选择用户任务的处理人。
type Assignment struct {
	// Type is user, role or initiator. | Type 取 user、role 或 initiator。
	Type string `json:"type"`
	// Claim is assigned, claim or grab. | Claim 取 assigned、claim 或 grab。
	Claim string `json:"claim,omitempty"`
	// Values lists user ids or role names; empty for initiator. | Values 列出用户 ID 或角色名；发起人类型为空。
	Values []string `json:"values,omitempty"`
}

// Completion configures how a user task node finishes. | Completion 配置用户任务节点的完成方式。
type Completion struct {
	// Mode is any (or-sign), all (countersign) or vote (vote-sign). | Mode 取 any（或签）、all（会签）或 vote（票签）。
	Mode string `json:"mode,omitempty"`
	// ThresholdType is count or percent; used by vote mode. | ThresholdType 取 count 或 percent；供票签模式使用。
	ThresholdType string `json:"threshold_type,omitempty"`
	// RejectMode is any (reject on the first rejection, the default for all and vote) or all
	// (reject only after every live vote rejected). | RejectMode 取 any（首个驳回即驳回，会签与票签的默认值）
	// 或 all（全部存活票都驳回才驳回）。
	RejectMode string `json:"reject_mode,omitempty"`
	// Threshold is the approval threshold: a whole count or a percentage in (0, 100]. | Threshold
	// 是通过阈值：整数票数或 (0, 100] 区间内的百分比。
	Threshold float64 `json:"threshold,omitempty"`
	// Sequential activates one task at a time in sequence. | Sequential 按顺序一次只激活一个任务。
	Sequential bool `json:"sequential,omitempty"`
}

// AutoRule is one automatic-approval rule evaluated at instance start or task creation. | AutoRule
// 是在实例发起或任务创建时求值的一条自动审批规则。
type AutoRule struct {
	// ID is the stable identifier of the rule. | ID 是规则的稳定标识。
	ID string `json:"id"`
	// Name is the Chinese display name. | Name 是中文展示名。
	Name string `json:"name,omitempty"`
	// NameEN is the English display name. | NameEN 是英文展示名。
	NameEN string `json:"name_en,omitempty"`
	// Event is start or task. | Event 取 start 或 task。
	Event string `json:"event"`
	// Scope is category, role, user, event or variable. | Scope 取 category、role、user、event 或 variable。
	Scope string `json:"scope"`
	// Condition is a safe expression over instance variables for the variable scope. | Condition
	// 是变量作用域下对实例变量求值的安全表达式。
	Condition string `json:"condition,omitempty"`
	// Decision is approve or reject. | Decision 取 approve 或 reject。
	Decision string `json:"decision"`
	// Prompt is an optional extra instruction for the AI decider. | Prompt 是给 AI 决策器的可选补充指令。
	Prompt string `json:"prompt,omitempty"`
	// Match lists the accepted values for category, role, user and event scopes. | Match
	// 列出分类、角色、用户与事件作用域接受的值。
	Match []string `json:"match,omitempty"`
	// Priority orders rules; larger values win. | Priority 决定规则顺序；数值越大越优先。
	Priority int `json:"priority,omitempty"`
	// Enabled reports whether the rule participates. | Enabled 报告规则是否参与求值。
	Enabled bool `json:"enabled"`
	// UseAI asks the configured decider instead of the fixed decision. | UseAI 表示改由已配置的决策器给出结论。
	UseAI bool `json:"use_ai,omitempty"`
}

// DesignSettings carries process-level runtime settings. | DesignSettings 承载流程级运行设置。
type DesignSettings struct {
	// Due is the default task deadline as a Go duration string. | Due 是默认任务期限（Go 时长字符串）。
	Due string `json:"due,omitempty"`
	// WithdrawWindow overrides the service withdrawal window. | WithdrawWindow 覆盖服务的撤回窗口。
	WithdrawWindow string `json:"withdraw_window,omitempty"`
	// Description is shown on the start form. | Description 展示在发起表单上。
	Description string `json:"description,omitempty"`
	// DescriptionEN is the English description. | DescriptionEN 是英文说明。
	DescriptionEN string `json:"description_en,omitempty"`
	// UniqueBusinessKey rejects a second running instance with the same business key. | UniqueBusinessKey
	// 拒绝同一业务键的第二个运行中实例。
	UniqueBusinessKey bool `json:"unique_business_key,omitempty"`
	// ForbidReturn disables the return action; the zero value allows it. | ForbidReturn 关闭退回动作；零值允许。
	ForbidReturn bool `json:"forbid_return,omitempty"`
	// ForbidDelegate disables delegation; the zero value allows it. | ForbidDelegate 关闭委派；零值允许。
	ForbidDelegate bool `json:"forbid_delegate,omitempty"`
	// ForbidAddSign disables add-sign and remove-sign; the zero value allows them. | ForbidAddSign
	// 关闭加签与减签；零值允许。
	ForbidAddSign bool `json:"forbid_add_sign,omitempty"`
}

// Node is one BPMN node of the supported subset. | Node 是支持子集中的一个 BPMN 节点。
type Node struct {
	// ID is unique inside the design. | ID 在设计内唯一。
	ID string `json:"id"`
	// Type is start, end, user, service, exclusive, parallel or inclusive. | Type 取 start、end、user、
	// service、exclusive、parallel 或 inclusive。
	Type string `json:"type"`
	// Name is the Chinese display name. | Name 是中文展示名。
	Name string `json:"name"`
	// NameEN is the English display name. | NameEN 是英文展示名。
	NameEN string `json:"name_en,omitempty"`
	// Description is the Chinese node hint. | Description 是中文节点提示。
	Description string `json:"description,omitempty"`
	// DescriptionEN is the English node hint. | DescriptionEN 是英文节点提示。
	DescriptionEN string `json:"description_en,omitempty"`
	// OnReject is terminate, end or return_initiator. | OnReject 取 terminate、end 或 return_initiator。
	OnReject string `json:"on_reject,omitempty"`
	// Due overrides the task deadline as a Go duration string. | Due 以 Go 时长字符串覆盖任务期限。
	Due string `json:"due,omitempty"`
	// RemindEvery overrides the reminder interval. | RemindEvery 覆盖催办间隔。
	RemindEvery string `json:"remind_every,omitempty"`
	// AIPrompt is an optional instruction for the AI decider. | AIPrompt 是给 AI 决策器的可选指令。
	AIPrompt string `json:"ai_prompt,omitempty"`
	// WaitKind is timer or message for a catch event. | WaitKind 对捕获事件取 timer 或 message。
	WaitKind string `json:"wait_kind,omitempty"`
	// WaitFor is the timer duration as a Go or ISO-8601 duration string. | WaitFor 是定时器时长，
	// 取 Go 或 ISO-8601 时长字符串。
	WaitFor string `json:"wait_for,omitempty"`
	// MessageName is the signal name a message catch event waits for. | MessageName 是消息捕获事件等待的信号名。
	MessageName string `json:"message_name,omitempty"`
	// Assignee selects the approvers of a user task. | Assignee 选择用户任务审批人。
	Assignee Assignment `json:"assignee,omitempty"`
	// Form lists the fields a task approval collects. | Form 列出任务审批收集的字段。
	Form []FormField `json:"form,omitempty"`
	// Completion configures the approval mode of a user task. | Completion 配置用户任务的审批方式。
	Completion Completion `json:"completion,omitempty"`
	// Position is the designer coordinate. | Position 是设计器坐标。
	Position Position `json:"position"`
	// MaxRemind overrides the reminder ceiling. | MaxRemind 覆盖催办次数上限。
	MaxRemind int `json:"max_remind,omitempty"`
	// AllowAuto enables automatic-approval rules on this node. | AllowAuto 开启该节点的自动审批规则。
	AllowAuto bool `json:"allow_auto,omitempty"`
	// Terminate marks an end event that cancels every other token when reached. | Terminate
	// 标记到达时取消其它全部令牌的结束事件。
	Terminate bool `json:"terminate,omitempty"`
}

// Edge is one sequence flow. | Edge 是一条顺序流。
type Edge struct {
	// ID is unique inside the design. | ID 在设计内唯一。
	ID string `json:"id"`
	// Source is the source node id. | Source 是源节点 ID。
	Source string `json:"source"`
	// Target is the target node id. | Target 是目标节点 ID。
	Target string `json:"target"`
	// Name is the Chinese display name. | Name 是中文展示名。
	Name string `json:"name,omitempty"`
	// NameEN is the English display name. | NameEN 是英文展示名。
	NameEN string `json:"name_en,omitempty"`
	// Condition is a safe boolean expression; empty means always. | Condition 是安全布尔表达式；空表示总是成立。
	Condition string `json:"condition,omitempty"`
	// Default marks the fallback flow of an exclusive gateway. | Default 标记排他网关的默认流。
	Default bool `json:"default,omitempty"`
	// Sort orders outgoing flows for exclusive evaluation. | Sort 决定排他网关出线的求值顺序。
	Sort int `json:"sort,omitempty"`
}

// Design is the editable graph of one process version. | Design 是一个流程版本的可编辑图。
//
// A Design parsed from JSON carries a read-only index used by FindNode, Outgoing and Incoming. Callers
// that append nodes or edges keep working: the index is ignored as soon as the lengths differ. |
// 从 JSON 解析出的 Design 带有供 FindNode、Outgoing 与 Incoming 使用的只读索引。追加节点或连线的调用方
// 仍然可用：一旦长度不一致，索引即被忽略。
type Design struct {
	// Forms maps a scope ("start" or a node id) to its form fields. | Forms 把作用域（"start" 或节点 ID）映射到表单字段。
	Forms map[string][]FormField `json:"forms,omitempty"`
	// index is a read-only lookup built by parseDesign. | index 是 parseDesign 构建的只读索引。
	index *designIndex
	// Settings carries process-level runtime settings. | Settings 承载流程级运行设置。
	Settings DesignSettings `json:"settings,omitempty"`
	// Nodes are the graph nodes. | Nodes 是图节点。
	Nodes []Node `json:"nodes"`
	// Edges are the sequence flows. | Edges 是顺序流。
	Edges []Edge `json:"edges"`
	// Rules are the automatic-approval rules. | Rules 是自动审批规则。
	Rules []AutoRule `json:"rules,omitempty"`
	// SchemaVersion is the design document version. | SchemaVersion 是设计文档版本。
	SchemaVersion int `json:"schema_version"`
}

// DefaultDesign returns an empty design with the current schema version. | DefaultDesign 返回当前 schema 版本的空白设计。
func DefaultDesign() Design {
	return Design{SchemaVersion: 1, Forms: map[string][]FormField{}}
}

// StartForm returns the start form fields. | StartForm 返回发起表单字段。
func (d Design) StartForm() []FormField { return d.Forms["start"] }

// FormFor returns the form fields of one node, falling back to the start form. | FormFor
// 返回某个节点的表单字段，缺失时回退到发起表单。
func (d Design) FormFor(nodeID string) []FormField {
	if fields, ok := d.Forms[nodeID]; ok && len(fields) > 0 {
		return fields
	}
	if nodeID == InitiatorNodeID {
		return d.StartForm()
	}
	return nil
}

// FindNode returns the node carrying id. | FindNode 返回携带 id 的节点。
func (d Design) FindNode(id string) (Node, bool) {
	if index := d.usableIndex(); index != nil {
		if position, ok := index.nodes[id]; ok {
			return d.Nodes[position], true
		}
		return Node{}, false
	}
	for i := range d.Nodes {
		if d.Nodes[i].ID == id {
			return d.Nodes[i], true
		}
	}
	return Node{}, false
}

// Outgoing returns the outgoing flows of a node ordered by Sort, then ID. The returned slice is a
// copy: callers may sort or append without touching the shared index. | Outgoing 返回节点的出线，
// 按 Sort 与 ID 排序。返回的是副本：调用方可以排序或追加，不会影响共享索引。
func (d Design) Outgoing(nodeID string) []Edge {
	if index := d.usableIndex(); index != nil {
		edges := index.outgoing[nodeID]
		if len(edges) == 0 {
			return nil
		}
		return append([]Edge(nil), edges...)
	}
	out := make([]Edge, 0, 2)
	for _, e := range d.Edges {
		if e.Source == nodeID {
			out = append(out, e)
		}
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0; j-- {
			if out[j-1].Sort > out[j].Sort || (out[j-1].Sort == out[j].Sort && out[j-1].ID > out[j].ID) {
				out[j-1], out[j] = out[j], out[j-1]
				continue
			}
			break
		}
	}
	return out
}

// Incoming returns the incoming flows of a node. The returned slice is a copy. | Incoming 返回节点的入线。
// 返回的是副本。
func (d Design) Incoming(nodeID string) []Edge {
	if index := d.usableIndex(); index != nil {
		edges := index.incoming[nodeID]
		if len(edges) == 0 {
			return nil
		}
		return append([]Edge(nil), edges...)
	}
	in := make([]Edge, 0, 2)
	for _, e := range d.Edges {
		if e.Target == nodeID {
			in = append(in, e)
		}
	}
	return in
}

// usableIndex returns the precomputed index only while it still describes this design. |
// usableIndex 仅当索引仍然描述当前设计时返回它。
func (d Design) usableIndex() *designIndex {
	index := d.index
	if index == nil || index.nodesLen != len(d.Nodes) || index.edgesLen != len(d.Edges) {
		return nil
	}
	return index
}

// outgoingView returns the shared sorted adjacency for runtime iteration. Unlike Outgoing it does
// not copy, so callers must only read the edges. | outgoingView 返回供运行期迭代的共享已排序邻接。
// 与 Outgoing 不同，它不复制，调用方只能读取连线。
func (d Design) outgoingView(nodeID string) []Edge {
	if index := d.usableIndex(); index != nil {
		return index.outgoing[nodeID]
	}
	return d.Outgoing(nodeID)
}

// incomingView returns the shared adjacency for runtime iteration. Callers must only read it. |
// incomingView 返回供运行期迭代的共享邻接。调用方只能读取。
func (d Design) incomingView(nodeID string) []Edge {
	if index := d.usableIndex(); index != nil {
		return index.incoming[nodeID]
	}
	return d.Incoming(nodeID)
}

// sortedRules returns the automatic-approval rules in evaluation order. Parsed designs reuse the
// pre-sorted slice; a directly constructed design is copied and sorted on demand. |
// sortedRules 按求值顺序返回自动审批规则。解析后的设计复用预排序切片；直接构造的设计按需复制并排序。
func (d Design) sortedRules() []AutoRule {
	if index := d.usableIndex(); index != nil {
		return index.rules
	}
	rules := append([]AutoRule(nil), d.Rules...)
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority == rules[j].Priority {
			return rules[i].ID < rules[j].ID
		}
		return rules[i].Priority > rules[j].Priority
	})
	return rules
}

// DefinitionInput is the editable payload of a definition. | DefinitionInput 是流程定义的可编辑载荷。
type DefinitionInput struct {
	// Key is required on creation and ignored on update. | Key 在创建时必填，更新时忽略。
	Key string
	// Name is the Chinese display name. | Name 是中文展示名。
	Name string
	// NameEN is the English display name. | NameEN 是英文展示名。
	NameEN string
	// Description explains the process. | Description 说明流程用途。
	Description string
	// Category groups processes. | Category 为流程分组。
	Category string
	// Icon is a lucide icon name. | Icon 是 lucide 图标名。
	Icon string
	// Status is draft, published or disabled; empty keeps the current value on update. | Status
	// 取 draft、published 或 disabled；更新时空值保持当前值。
	Status string
}

// VersionInput is the editable payload of a draft version. | VersionInput 是草稿版本的可编辑载荷。
type VersionInput struct {
	// Note is the draft or publication note. | Note 是草稿或发布说明。
	Note string
	// Design is the design document. | Design 是设计文档。
	Design Design
}

// DefinitionFilter selects one page of definitions. | DefinitionFilter 选择一页流程定义。
type DefinitionFilter struct {
	// Query matches key, Chinese name and English name. | Query 匹配键、中文名与英文名。
	Query string
	// Category narrows to one category. | Category 限定一个分类。
	Category string
	// Status narrows to one lifecycle state. | Status 限定一个生命周期状态。
	Status string
	// Page and PageSize are 1-based; zero uses the service defaults. | Page 与 PageSize 从 1 开始；零值使用服务默认值。
	Page     int
	PageSize int
}

// DefinitionPage is one page of definitions. | DefinitionPage 是一页流程定义。
type DefinitionPage struct {
	// Items are the rows in this page. | Items 是本页记录。
	Items []Definition `json:"items"`
	// Total is the number of matching definitions. | Total 是匹配总数。
	Total int `json:"total"`
	// Page and PageSize echo the effective paging. | Page 与 PageSize 回显生效的分页。
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
}

// VersionPage lists every version of one definition. | VersionPage 列出一个定义的全部版本。
type VersionPage struct {
	// Items are the versions in descending version order. | Items 是按版本号降序排列的版本。
	Items []Version `json:"items"`
	// Total is the number of versions. | Total 是版本总数。
	Total int `json:"total"`
}

// VersionSummaryPage lists lightweight version projections; designs and BPMN documents are
// available through the single-version read. | VersionSummaryPage 列出轻量版本投影；设计与
// BPMN 文档经单版本读取获取。
type VersionSummaryPage struct {
	// Items are the summaries in descending version order. | Items 是按版本号降序排列的摘要。
	Items []VersionSummary `json:"items"`
	// Total is the number of versions. | Total 是版本总数。
	Total int `json:"total"`
}

// normalizeDefinitionInput validates and canonicalizes a definition payload. | normalizeDefinitionInput
// 校验并规范化流程定义载荷。
func (s *Service) normalizeDefinitionInput(in DefinitionInput, requireKey bool) (DefinitionInput, error) {
	in.Key = strings.ToLower(strings.TrimSpace(in.Key))
	if requireKey && !keyRe.MatchString(in.Key) {
		return DefinitionInput{}, errs.Detail(ErrInvalidInput, "key=%[1]q | 键=%[1]q", in.Key)
	}
	var ok bool
	if in.Name, ok = trimLen(in.Name, s.options.MaxNameLen); !ok || in.Name == "" {
		return DefinitionInput{}, ErrInvalidInput
	}
	if in.NameEN, ok = trimLen(in.NameEN, s.options.MaxNameLen); !ok {
		return DefinitionInput{}, ErrInvalidInput
	}
	if in.Description, ok = trimLen(in.Description, s.options.MaxDescriptionLen); !ok {
		return DefinitionInput{}, ErrInvalidInput
	}
	if in.Category, ok = trimLen(in.Category, 64); !ok {
		return DefinitionInput{}, ErrInvalidInput
	}
	if in.Icon, ok = trimLen(in.Icon, 64); !ok {
		return DefinitionInput{}, ErrInvalidInput
	}
	if in.Status == "" {
		in.Status = DefinitionDraft
	}
	switch in.Status {
	case DefinitionDraft, DefinitionPublished, DefinitionDisabled:
	default:
		return DefinitionInput{}, ErrInvalidInput
	}
	return in, nil
}
