package workflow

import (
	"context"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
	ydlog "github.com/shibingli/ydx/log"
)

// Actor identifies the caller of a workflow action. | Actor 标识流程动作的调用方。
type Actor struct {
	// ID is the user id. | ID 是用户 ID。
	ID string
	// Name is the display name recorded on events. | Name 是记录在事件上的展示名。
	Name string
	// Admin bypasses ownership checks on administrative actions. | Admin 使管理动作跳过归属校验。
	Admin bool
}

// StartInput carries one process start. | StartInput 承载一次流程发起。
type StartInput struct {
	// Variables are instance variables merged into condition evaluation. | Variables 是参与条件求值的实例变量。
	Variables map[string]any
	// FormData is the start form submission; it overrides same-key Variables. | FormData 是发起表单提交，
	// 覆盖同名 Variables。
	FormData map[string]any
	// DefinitionID or DefinitionKey selects the definition; DefinitionID wins. | DefinitionID 或
	// DefinitionKey 选择定义；DefinitionID 优先。
	DefinitionID  string
	DefinitionKey string
	// Title is the instance subject; empty falls back to the definition name. | Title 是实例标题；
	// 空值回退到定义名。
	Title string
	// BusinessKey is the caller's external reference. | BusinessKey 是调用方的外部业务键。
	BusinessKey string
	// Category overrides the definition category. | Category 覆盖定义分类。
	Category string
	// Version pins a published version; zero selects the latest published version. | Version
	// 绑定一个已发布版本；零值选择最新已发布版本。
	Version int
}

// runtimeTxn is the per-instance working set inside one transaction. | runtimeTxn 是一个事务内针对单个实例的工作集。
type runtimeTxn struct {
	// now is the transaction clock. | now 是事务时钟。
	now time.Time
	// st is the transaction-bound store. | st 是绑定事务的存储。
	st Store
	// s is the owning service. | s 是所属服务。
	s *Service
	// inst is the mutable instance row. | inst 是可变的实例行。
	inst *Instance
	// vars is the mutable variable object. | vars 是可变的变量对象。
	vars map[string]any
	// tenantID and definitionID make the lazy definition load possible. | tenantID 与 definitionID
	// 支撑定义的惰性加载。
	tenantID     string
	definitionID string
	ver          Version
	// notes are the notifications persisted in this transaction and dispatched after commit. |
	// notes 是本事务内持久化、提交后投递的通知。
	notes []Notification
	// design is the parsed pinned version. | design 是解析后的绑定版本。
	design Design
	// def and ver are the pinned definition and version. def is loaded lazily because only an AI
	// decision reads it; ordinary actions no longer pay a definition query. | def 与 ver 是绑定的
	// 定义与版本。def 惰性加载，因为只有 AI 决策会读取它；普通动作不再为定义查询付出成本。
	def Definition
	// depth bounds recursive gateway/token processing. | depth 限制网关与令牌的递归处理深度。
	depth int
	// defLoaded reports whether def is populated. | defLoaded 报告 def 是否已填充。
	defLoaded bool
	// varsDirty reports whether Variables must be written back. | varsDirty 报告是否需要写回 Variables。
	varsDirty bool
}

// Start creates a running instance and advances it until it waits or finishes. | Start 创建运行中实例，
// 并推进到等待或结束状态。
func (s *Service) Start(ctx context.Context, tenantID string, actor Actor, in StartInput) (Instance, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor.ID = strings.TrimSpace(actor.ID)
	if tenantID == "" || actor.ID == "" {
		return Instance{}, ErrInvalidInput
	}
	def, err := s.resolveStartDefinition(ctx, tenantID, in)
	if err != nil {
		return Instance{}, err
	}
	if def.Status != DefinitionPublished {
		return Instance{}, errs.Detail(ErrInvalidInput, "definition %[1]q is not published | 定义 %[1]q 尚未发布", def.Key)
	}
	version, err := s.resolveStartVersion(ctx, tenantID, def, in.Version)
	if err != nil {
		return Instance{}, err
	}
	design, err := s.designOf(version)
	if err != nil {
		return Instance{}, err
	}
	variables, err := mergeStartVariables(in.FormData, in.Variables)
	if err != nil {
		return Instance{}, err
	}
	if err := s.validateSubmittedForm(design.StartForm(), variables); err != nil {
		return Instance{}, err
	}
	rawVariables, err := json.Marshal(variables)
	if err != nil {
		return Instance{}, errs.Wrap(err, ErrInvalidForm)
	}
	if len(rawVariables) > s.options.MaxVariablesBytes {
		return Instance{}, errs.Detail(ErrLimit, "variables are %[1]d bytes, limit %[2]d | 变量大小 %[1]d 字节，上限 %[2]d", len(rawVariables), s.options.MaxVariablesBytes)
	}
	title, ok := trimLen(in.Title, s.options.MaxTitleLen)
	if !ok {
		return Instance{}, ErrInvalidInput
	}
	if title == "" {
		title = def.Name
	}
	businessKey, ok := trimLen(in.BusinessKey, 128)
	if !ok {
		return Instance{}, ErrInvalidInput
	}
	category, ok := trimLen(in.Category, 64)
	if !ok {
		return Instance{}, ErrInvalidInput
	}
	if category == "" {
		category = def.Category
	}
	now := s.now()
	// Generate identity once: an AI deferral replays the transaction, and a fresh instance id on
	// each replay would also change the decider's input fingerprint and defeat the cache. |
	// 身份只生成一次：AI 延后重放事务时，若每次生成新的实例 ID，决策输入指纹也会变化，缓存随即失效。
	instanceID, err := s.options.NewID("wfins_")
	if err != nil {
		return Instance{}, errs.Wrap(err, ErrUnavailable)
	}
	tokenID, err := s.options.NewID("wftok_")
	if err != nil {
		return Instance{}, errs.Wrap(err, ErrUnavailable)
	}

	var created Instance
	var notes []Notification
	err = s.store.WithTx(ctx, func(st Store) error {
		// Each attempt starts from pristine state: the AI deferral path replays this callback after
		// rolling the previous transaction back. | 每次尝试都从干净状态开始：AI 延后路径会在回滚上一次
		// 事务之后重新执行本回调。
		created = Instance{}
		attemptVars := make(map[string]any, len(variables))
		for key, value := range variables {
			attemptVars[key] = value
		}
		tx := &runtimeTxn{
			s: s, st: st, inst: &created, def: def, defLoaded: true, tenantID: tenantID, definitionID: def.ID,
			ver: version, design: design, vars: attemptVars, now: now,
		}
		if design.Settings.UniqueBusinessKey && businessKey != "" {
			count, err := st.CountRunningInstances(ctx, tenantID, def.ID, businessKey)
			if err != nil {
				return err
			}
			if count > 0 {
				return errs.Detail(ErrConflict, "business key %[1]q already has a running instance | 业务键 %[1]q 已有运行中实例", businessKey)
			}
		}
		id := instanceID
		created = Instance{
			CreatedAt:      now,
			UpdatedAt:      now,
			StartedAt:      now,
			DueAt:          instanceDue(now, design.Settings.Due),
			ID:             id,
			TenantID:       tenantID,
			DefinitionID:   def.ID,
			VersionID:      version.ID,
			DefinitionKey:  def.Key,
			DefinitionName: def.Name,
			Version:        version.Version,
			Title:          title,
			BusinessKey:    businessKey,
			Category:       category,
			InitiatorID:    actor.ID,
			InitiatorName:  actor.Name,
			Status:         InstanceRunning,
			Variables:      string(rawVariables),
			VisitedNodes:   "[]",
			CurrentNodes:   "[]",
		}
		if err := st.CreateInstance(ctx, created); err != nil {
			return err
		}
		start, ok := designStartNode(design)
		if !ok {
			return ErrInvalidDesign
		}
		token := Token{
			CreatedAt:  now,
			UpdatedAt:  now,
			ID:         tokenID,
			TenantID:   tenantID,
			InstanceID: created.ID,
			NodeID:     start.ID,
			Status:     TokenActive,
		}
		if err := st.CreateToken(ctx, token); err != nil {
			return err
		}
		tx.event(ctx, EventInstanceStarted, "", start.ID, actor.ID, actor.Name, "流程已发起 | instance started", "")
		if decision, rule, matched, err := s.evaluateAuto(ctx, tx, start, AutoEventStart, nil); err != nil {
			return err
		} else if matched {
			if err := s.applyStartDecision(ctx, tx, &token, start, decision, rule, actor); err != nil {
				return err
			}
		} else if err := s.advance(ctx, tx, &token); err != nil {
			return err
		}
		notes = tx.notes
		return nil
	})
	if err != nil {
		return Instance{}, err
	}
	s.flushNotifications(ctx, notes)
	return created, nil
}

// resolveStartDefinition selects the definition named by the start input. | resolveStartDefinition
// 选择发起输入指定的定义。
func (s *Service) resolveStartDefinition(ctx context.Context, tenantID string, in StartInput) (Definition, error) {
	if id := strings.TrimSpace(in.DefinitionID); id != "" {
		return s.store.GetDefinition(ctx, tenantID, id)
	}
	key := strings.ToLower(strings.TrimSpace(in.DefinitionKey))
	if !keyRe.MatchString(key) {
		return Definition{}, ErrInvalidInput
	}
	return s.store.GetDefinitionByKey(ctx, tenantID, key)
}

// resolveStartVersion selects the pinned or latest published version. When the store exposes the
// runtime meta reader, an already parsed version is served from the cache without reading the
// design and BPMN documents again; the latest-published pointer itself is still read live, so a
// publication on another node is picked up immediately. | resolveStartVersion 选择绑定版本或最新
// 已发布版本。存储提供运行期元数据读取时，已解析过的版本直接从缓存返回，不再读取设计串与 BPMN 串；
// 最新已发布指针仍然实时读取，因此其它节点上的发布会立即生效。
func (s *Service) resolveStartVersion(ctx context.Context, tenantID string, def Definition, number int) (Version, error) {
	if reader, ok := s.store.(runtimeVersionMetaReader); ok {
		return s.resolveStartVersionMeta(ctx, reader, tenantID, def, number)
	}
	if number > 0 {
		version, err := s.store.GetVersionByNumber(ctx, tenantID, def.ID, number)
		if err != nil {
			return Version{}, err
		}
		if version.Status != VersionPublished {
			return Version{}, errs.Detail(ErrInvalidInput, "version %[1]d is not published | 版本 %[1]d 尚未发布", number)
		}
		return version, nil
	}
	return s.store.GetLatestPublishedVersion(ctx, tenantID, def.ID)
}

// resolveStartVersionMeta implements the cached runtime read. | resolveStartVersionMeta 实现带缓存的
// 运行期读取。
func (s *Service) resolveStartVersionMeta(ctx context.Context, reader runtimeVersionMetaReader, tenantID string, def Definition, number int) (Version, error) {
	var meta Version
	var err error
	if number > 0 {
		meta, err = reader.GetVersionByNumberMeta(ctx, tenantID, def.ID, number)
	} else {
		meta, err = reader.GetLatestPublishedVersionMeta(ctx, tenantID, def.ID)
	}
	if err != nil {
		return Version{}, err
	}
	key := runtimeVersionKey{TenantID: tenantID, VersionID: meta.ID}
	if cached, _, ok := s.versions.get(key); ok {
		return cached, nil
	}
	if meta.Design != "" {
		// A store without the optional reader returns the full row through the wrapper. |
		// 未实现可选读取器的存储会经包装层返回完整行。
		if number > 0 && meta.Status != VersionPublished {
			return Version{}, errs.Detail(ErrInvalidInput, "version %[1]d is not published | 版本 %[1]d 尚未发布", number)
		}
		return meta, nil
	}
	version, _, err := s.loadVersion(ctx, s.store, tenantID, meta.ID)
	if err != nil {
		return Version{}, err
	}
	if number > 0 && version.Status != VersionPublished {
		return Version{}, errs.Detail(ErrInvalidInput, "version %[1]d is not published | 版本 %[1]d 尚未发布", number)
	}
	return version, nil
}

// mergeStartVariables combines the start form and the caller variables. | mergeStartVariables
// 合并发起表单与调用方变量。
func mergeStartVariables(form, extra map[string]any) (map[string]any, error) {
	out := make(map[string]any, len(form)+len(extra))
	for key, value := range extra {
		out[key] = value
	}
	for key, value := range form {
		out[key] = value
	}
	return out, nil
}

// instanceDue computes the instance deadline. | instanceDue 计算实例期限。
func instanceDue(now time.Time, raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return time.Time{}
	}
	return now.Add(d)
}

// designStartNode returns the single start node. | designStartNode 返回唯一的开始节点。
func designStartNode(design Design) (Node, bool) {
	for _, node := range design.Nodes {
		if node.Type == NodeStart {
			return node, true
		}
	}
	return Node{}, false
}

// applyStartDecision finishes or lets an instance continue after a start-scope automatic rule. |
// applyStartDecision 在发起级自动规则命中后结束实例或让其继续。
func (s *Service) applyStartDecision(ctx context.Context, tx *runtimeTxn, token *Token, node Node, decision DecisionResult, rule AutoRule, actor Actor) error {
	comment := "自动审批规则 " + rule.ID + " | automatic rule " + rule.ID
	if strings.TrimSpace(decision.Reason) != "" {
		comment += ": " + decision.Reason
	}
	tx.event(ctx, EventTaskAutoDecided, "", node.ID, "system", "system", comment, "")
	if decision.Decision == DecisionReject {
		return s.finishInstance(ctx, tx, InstanceTerminated, "rejected", comment, actor)
	}
	return s.finishInstance(ctx, tx, InstanceCompleted, "approved", comment, actor)
}

// advance drives one token until it waits for a task or finishes its path. | advance 推进一个令牌，
// 直到它等待任务或完成自己的路径。
func (s *Service) advance(ctx context.Context, tx *runtimeTxn, token *Token) error {
	for {
		if token.Status == TokenCompleted || token.Status == TokenCancelled {
			return nil
		}
		if tx.inst.Status != InstanceRunning {
			return nil
		}
		tx.depth++
		if tx.depth > 256 {
			return errs.Detail(ErrInvalidDesign, "token processing exceeded the depth limit | 令牌推进超过深度上限")
		}
		node, ok := tx.design.FindNode(token.NodeID)
		if !ok && token.NodeID != InitiatorNodeID {
			return errs.Detail(ErrInvalidDesign, "token names unknown node %[1]q | 令牌指向未知节点 %[1]q", token.NodeID)
		}
		if token.NodeID == InitiatorNodeID {
			return s.activateInitiatorTask(ctx, tx, token)
		}
		switch node.Type {
		case NodeStart:
			out := tx.design.outgoingView(node.ID)
			if len(out) == 0 {
				return ErrInvalidDesign
			}
			return s.followEdges(ctx, tx, token, out, "")
		case NodeEnd:
			if node.Terminate {
				return s.finishInstance(ctx, tx, InstanceCompleted, "approved", "terminate end event | 终止结束事件", Actor{ID: "system", Name: "system"})
			}
			token.Status = TokenCompleted
			token.UpdatedAt = tx.now
			if err := tx.st.UpdateToken(ctx, *token); err != nil {
				return err
			}
			return s.finishIfDone(ctx, tx)
		case NodeServiceTask:
			tx.event(ctx, EventNodeEntered, "", node.ID, "system", "system", "服务任务已执行 | service task executed", "")
			return s.completeNode(ctx, tx, token, node, DecisionApprove, "system", "system", "服务任务自动完成 | service task completed automatically")
		case NodeExclusive:
			return s.advanceExclusive(ctx, tx, token, node)
		case NodeParallel:
			return s.advanceParallel(ctx, tx, token, node)
		case NodeInclusive:
			return s.advanceInclusive(ctx, tx, token, node)
		case NodeCatch:
			return s.activateCatch(ctx, tx, token, node)
		case NodeEventGateway:
			return s.activateEventGateway(ctx, tx, token, node)
		case NodeUserTask:
			return s.activateUserTask(ctx, tx, token, node)
		default:
			return errs.Detail(ErrInvalidDesign, "unsupported node type %[1]q | 不支持的节点类型 %[1]q", node.Type)
		}
	}
}

// activateCatch parks a token on a timer or message catch event. | activateCatch 把令牌停在定时或消息捕获事件上。
func (s *Service) activateCatch(ctx context.Context, tx *runtimeTxn, token *Token, node Node) error {
	switch node.WaitKind {
	case WaitTimer:
		duration, err := parseDurationText(node.WaitFor)
		if err != nil || duration < 0 {
			return errs.Detail(ErrInvalidDesign, "catch event %[1]q has an invalid duration | 捕获事件 %[1]q 的时长非法", node.ID)
		}
		token.WaitType = WaitTimer
		token.WaitUntil = tx.now.Add(duration)
		token.MessageName = ""
	case WaitMessage:
		token.WaitType = WaitMessage
		token.MessageName = node.MessageName
		token.WaitUntil = time.Time{}
	default:
		return ErrInvalidDesign
	}
	token.Status = TokenWaiting
	token.UpdatedAt = tx.now
	if err := tx.st.UpdateToken(ctx, *token); err != nil {
		return err
	}
	tx.event(ctx, EventNodeEntered, "", node.ID, "system", "system", "等待事件 | waiting for event", node.WaitKind)
	return tx.persistRuntime(ctx)
}

// activateEventGateway races the outgoing catch events. | activateEventGateway 让出线捕获事件竞争。
func (s *Service) activateEventGateway(ctx context.Context, tx *runtimeTxn, token *Token, node Node) error {
	group := token.WaitGroup
	if group == "" {
		id, err := s.options.NewID("wfwai_")
		if err != nil {
			return errs.Wrap(err, ErrUnavailable)
		}
		group = id
	}
	token.Status = TokenCompleted
	token.UpdatedAt = tx.now
	if err := tx.st.UpdateToken(ctx, *token); err != nil {
		return err
	}
	for i, edge := range tx.design.outgoingView(node.ID) {
		childID, err := s.options.NewID("wftok_")
		if err != nil {
			return errs.Wrap(err, ErrUnavailable)
		}
		child := Token{
			CreatedAt:  tx.now,
			UpdatedAt:  tx.now,
			ID:         childID,
			TenantID:   tx.inst.TenantID,
			InstanceID: tx.inst.ID,
			NodeID:     edge.Target,
			Status:     TokenActive,
			WaitGroup:  group,
			ForkNode:   node.ID,
			Seq:        i,
		}
		if err := tx.st.CreateToken(ctx, child); err != nil {
			return err
		}
		if err := s.advance(ctx, tx, &child); err != nil {
			return err
		}
	}
	return tx.persistRuntime(ctx)
}

// fireWaitingToken wakes one timer or message token and cancels its race competitors. |
// fireWaitingToken 唤醒一个定时或消息令牌，并取消其竞争令牌。
func (s *Service) fireWaitingToken(ctx context.Context, tx *runtimeTxn, token *Token) error {
	token.Status = TokenActive
	token.WaitType = ""
	token.WaitUntil = time.Time{}
	token.MessageName = ""
	token.UpdatedAt = tx.now
	if err := tx.st.UpdateToken(ctx, *token); err != nil {
		return err
	}
	if token.WaitGroup != "" {
		if err := tx.st.CancelWaitGroup(ctx, tx.inst.TenantID, tx.inst.ID, token.WaitGroup, token.ID, tx.now); err != nil {
			return err
		}
	}
	if node, ok := tx.design.FindNode(token.NodeID); ok && node.Type == NodeCatch {
		return s.followEdges(ctx, tx, token, tx.design.outgoingView(node.ID), "")
	}
	return s.advance(ctx, tx, token)
}

// Signal delivers one named message to a waiting instance. It returns the number of tokens woken. |
// Signal 向等待中的实例投递一个命名消息，返回被唤醒的令牌数量。
func (s *Service) Signal(ctx context.Context, tenantID string, actor Actor, instanceID, messageName string, payload map[string]any) (int, error) {
	tenantID = strings.TrimSpace(tenantID)
	instanceID = strings.TrimSpace(instanceID)
	messageName = strings.TrimSpace(messageName)
	if tenantID == "" || instanceID == "" || messageName == "" || strings.TrimSpace(actor.ID) == "" {
		return 0, ErrInvalidInput
	}
	if len(messageName) > 128 {
		return 0, ErrInvalidInput
	}
	if len(payload) > 0 {
		data, err := json.Marshal(payload)
		if err != nil {
			return 0, ErrInvalidInput
		}
		if len(data) > s.options.MaxVariablesBytes {
			return 0, ErrLimit
		}
	}
	var woken int
	var notes []Notification
	err := s.store.WithTx(ctx, func(st Store) error {
		// Reset per attempt: an AI deferral replays this callback after a rollback. |
		// 每次尝试都重置：AI 延后会在回滚后重放本回调。
		woken = 0
		rt, err := s.loadRuntime(ctx, st, tenantID, instanceID)
		if err != nil {
			return err
		}
		if rt.inst.Status != InstanceRunning {
			return ErrInstanceClosed
		}
		tokens, err := st.ListMessageTokens(ctx, tenantID, instanceID, messageName)
		if err != nil {
			return err
		}
		rt.mergeFormData(payload)
		for i := range tokens {
			token := tokens[i]
			if token.Status != TokenWaiting || token.WaitType != WaitMessage {
				continue
			}
			if err := s.fireWaitingToken(ctx, rt, &token); err != nil {
				return err
			}
			woken++
		}
		if err := rt.refreshCurrentNodes(ctx); err != nil {
			return err
		}
		if err := rt.persistRuntime(ctx); err != nil {
			return err
		}
		notes = rt.notes
		return nil
	})
	if err != nil {
		return 0, err
	}
	s.flushNotifications(ctx, notes)
	return woken, nil
}

// followEdges continues a token along the given edges. One edge moves the token in place; several
// complete it and create one child token per edge. | followEdges 让令牌沿给定连线继续。单条连线原地移动令牌；
// 多条连线会完成当前令牌并为每条连线创建一个子令牌。
func (s *Service) followEdges(ctx context.Context, tx *runtimeTxn, token *Token, edges []Edge, forkGroup string) error {
	if len(edges) == 0 {
		return errs.Detail(ErrInvalidDesign, "node %[1]q has no viable outgoing flow | 节点 %[1]q 没有可走的出线", token.NodeID)
	}
	if len(edges) == 1 {
		token.NodeID = edges[0].Target
		// A token reaching here may have been completed by completeNode; moving it along a
		// single flow re-activates it so advance continues. | 到达这里的令牌可能已被 completeNode
		// 标记完成；沿单条连线移动时重新激活，使 advance 继续推进。
		token.Status = TokenActive
		token.UpdatedAt = tx.now
		if forkGroup != "" {
			token.ForkGroup = forkGroup
		}
		if err := tx.st.UpdateToken(ctx, *token); err != nil {
			return err
		}
		return s.advance(ctx, tx, token)
	}
	token.Status = TokenCompleted
	token.UpdatedAt = tx.now
	if err := tx.st.UpdateToken(ctx, *token); err != nil {
		return err
	}
	for i, edge := range edges {
		childID, err := s.options.NewID("wftok_")
		if err != nil {
			return errs.Wrap(err, ErrUnavailable)
		}
		child := Token{
			CreatedAt:  tx.now,
			UpdatedAt:  tx.now,
			ID:         childID,
			TenantID:   tx.inst.TenantID,
			InstanceID: tx.inst.ID,
			NodeID:     edge.Target,
			Status:     TokenActive,
			ForkGroup:  forkGroup,
			ForkNode:   token.NodeID,
			Seq:        i,
		}
		if err := tx.st.CreateToken(ctx, child); err != nil {
			return err
		}
		if err := s.advance(ctx, tx, &child); err != nil {
			return err
		}
	}
	return s.recheckJoins(ctx, tx)
}

// advanceExclusive evaluates the outgoing conditions in order and follows the first match. |
// advanceExclusive 按顺序求值出线条件并沿首个命中的连线继续。
func (s *Service) advanceExclusive(ctx context.Context, tx *runtimeTxn, token *Token, node Node) error {
	out := tx.design.outgoingView(node.ID)
	var fallback *Edge
	for i := range out {
		edge := out[i]
		if edge.Default {
			fallback = &out[i]
			continue
		}
		if edge.Condition == "" {
			return s.followEdges(ctx, tx, token, []Edge{edge}, "")
		}
		matched, err := EvaluateCondition(edge.Condition, tx.vars)
		if err != nil {
			return errs.Detail(ErrInvalidCondition, "gateway %[1]q edge %[2]q: %[3]s | 网关 %[1]q 连线 %[2]q：%[3]s", node.ID, edge.ID, err.Error())
		}
		if matched {
			return s.followEdges(ctx, tx, token, []Edge{edge}, "")
		}
	}
	if fallback != nil {
		return s.followEdges(ctx, tx, token, []Edge{*fallback}, "")
	}
	return errs.Detail(ErrInvalidCondition, "exclusive gateway %[1]q matched no outgoing flow | 排他网关 %[1]q 没有命中的出线", node.ID)
}

// advanceParallel implements the AND split and join. | advanceParallel 实现并行网关的分支与汇聚。
func (s *Service) advanceParallel(ctx context.Context, tx *runtimeTxn, token *Token, node Node) error {
	in := tx.design.incomingView(node.ID)
	out := tx.design.outgoingView(node.ID)
	if len(in) > 1 {
		token.Status = TokenWaiting
		token.UpdatedAt = tx.now
		if err := tx.st.UpdateToken(ctx, *token); err != nil {
			return err
		}
		tokens, err := tx.st.ListTokensAtNode(ctx, tx.inst.TenantID, tx.inst.ID, node.ID)
		if err != nil {
			return err
		}
		arrived := 0
		for _, at := range tokens {
			if at.Status == TokenActive || at.Status == TokenWaiting {
				arrived++
			}
		}
		if arrived < len(in) {
			return nil
		}
		for i := range tokens {
			at := &tokens[i]
			if at.Status != TokenActive && at.Status != TokenWaiting {
				continue
			}
			if at.ID == token.ID {
				at.Status = TokenActive
			} else {
				at.Status = TokenCompleted
			}
			at.UpdatedAt = tx.now
			if err := tx.st.UpdateToken(ctx, *at); err != nil {
				return err
			}
		}
		token.Status = TokenActive
	}
	if len(out) == 0 {
		return ErrInvalidDesign
	}
	if len(out) == 1 {
		return s.followEdges(ctx, tx, token, out, "")
	}
	return s.followEdges(ctx, tx, token, out, token.ForkGroup)
}

// advanceInclusive implements the OR split and join. | advanceInclusive 实现包容网关的分支与汇聚。
func (s *Service) advanceInclusive(ctx context.Context, tx *runtimeTxn, token *Token, node Node) error {
	in := tx.design.incomingView(node.ID)
	out := tx.design.outgoingView(node.ID)
	if len(in) > 1 {
		token.Status = TokenWaiting
		token.UpdatedAt = tx.now
		if err := tx.st.UpdateToken(ctx, *token); err != nil {
			return err
		}
		tokens, err := tx.st.ListTokensAtNode(ctx, tx.inst.TenantID, tx.inst.ID, node.ID)
		if err != nil {
			return err
		}
		arrived := 0
		for _, at := range tokens {
			if (at.Status == TokenActive || at.Status == TokenWaiting) && (token.ForkGroup == "" || at.ForkGroup == token.ForkGroup) {
				arrived++
			}
		}
		others := 0
		if token.ForkGroup != "" {
			live, err := tx.st.CountLiveTokensByForkGroup(ctx, tx.inst.TenantID, tx.inst.ID, token.ForkGroup)
			if err != nil {
				return err
			}
			others = live - arrived
			if others < 0 {
				others = 0
			}
		} else {
			others = len(in) - arrived
		}
		if arrived == 0 || others > 0 {
			return nil
		}
		for i := range tokens {
			at := &tokens[i]
			if at.Status != TokenActive && at.Status != TokenWaiting {
				continue
			}
			if token.ForkGroup != "" && at.ForkGroup != token.ForkGroup {
				continue
			}
			if at.ID == token.ID {
				at.Status = TokenActive
			} else {
				at.Status = TokenCompleted
			}
			at.UpdatedAt = tx.now
			if err := tx.st.UpdateToken(ctx, *at); err != nil {
				return err
			}
		}
		token.Status = TokenActive
	}
	if len(out) == 0 {
		return ErrInvalidDesign
	}
	if len(out) == 1 {
		return s.followEdges(ctx, tx, token, out, "")
	}
	group := token.ForkGroup
	if group == "" {
		id, err := s.options.NewID("wffork_")
		if err != nil {
			return errs.Wrap(err, ErrUnavailable)
		}
		group = id
	}
	selected := make([]Edge, 0, len(out))
	var fallback *Edge
	for i := range out {
		edge := out[i]
		if edge.Default {
			fallback = &out[i]
			continue
		}
		if edge.Condition == "" {
			selected = append(selected, edge)
			continue
		}
		matched, err := EvaluateCondition(edge.Condition, tx.vars)
		if err != nil {
			return errs.Detail(ErrInvalidCondition, "gateway %[1]q edge %[2]q: %[3]s | 网关 %[1]q 连线 %[2]q：%[3]s", node.ID, edge.ID, err.Error())
		}
		if matched {
			selected = append(selected, edge)
		}
	}
	if len(selected) == 0 && fallback != nil {
		selected = append(selected, *fallback)
	}
	if len(selected) == 0 {
		return errs.Detail(ErrInvalidCondition, "inclusive gateway %[1]q matched no outgoing flow | 包容网关 %[1]q 没有命中的出线", node.ID)
	}
	return s.followEdges(ctx, tx, token, selected, group)
}

// recheckJoins retries every waiting gateway token, so a branch that ends early cannot leave a
// join waiting forever. | recheckJoins 重试全部等待中的网关令牌，使提前结束的分支不会让汇聚永远等待。
func (s *Service) recheckJoins(ctx context.Context, tx *runtimeTxn) error {
	tokens, err := tx.st.ListTokens(ctx, tx.inst.TenantID, tx.inst.ID)
	if err != nil {
		return err
	}
	for i := range tokens {
		token := tokens[i]
		if token.Status != TokenWaiting {
			continue
		}
		node, ok := tx.design.FindNode(token.NodeID)
		if !ok || (node.Type != NodeParallel && node.Type != NodeInclusive) {
			continue
		}
		if err := s.advance(ctx, tx, &token); err != nil {
			return err
		}
	}
	return nil
}

// completeNode marks a user or service node decided and continues along its outgoing flows. |
// completeNode 标记用户或服务节点已决策，并沿出线继续。
func (s *Service) completeNode(ctx context.Context, tx *runtimeTxn, token *Token, node Node, decision, actorID, actorName, message string) error {
	token.Status = TokenCompleted
	token.UpdatedAt = tx.now
	if err := tx.st.UpdateToken(ctx, *token); err != nil {
		return err
	}
	if decision == DecisionReject {
		switch node.OnReject {
		case OnRejectEnd:
			return s.finishInstance(ctx, tx, InstanceCompleted, "rejected", message, Actor{ID: actorID, Name: actorName})
		case OnRejectReturnInitiator:
			return s.returnToInitiator(ctx, tx, node, actorID, actorName, message)
		default:
			return s.finishInstance(ctx, tx, InstanceTerminated, "rejected", message, Actor{ID: actorID, Name: actorName})
		}
	}
	out := tx.design.outgoingView(node.ID)
	if len(out) == 0 {
		return errs.Detail(ErrInvalidDesign, "node %[1]q has no outgoing flow | 节点 %[1]q 没有出线", node.ID)
	}
	return s.followEdges(ctx, tx, token, out, "")
}

// finishIfDone completes the instance when no live token remains. | finishIfDone 在没有活动令牌时完成实例。
func (s *Service) finishIfDone(ctx context.Context, tx *runtimeTxn) error {
	live, err := tx.st.CountLiveTokens(ctx, tx.inst.TenantID, tx.inst.ID)
	if err != nil {
		return err
	}
	if live > 0 {
		return nil
	}
	return s.finishInstance(ctx, tx, InstanceCompleted, "approved", "", Actor{ID: "system", Name: "system"})
}

// finishInstance closes an instance, cancels live work and records the terminal event. |
// finishInstance 结束实例、取消活动工作并记录终止事件。
func (s *Service) finishInstance(ctx context.Context, tx *runtimeTxn, status, outcome, reason string, actor Actor) error {
	if tx.inst.Status != InstanceRunning {
		return nil
	}
	if err := s.cancelLiveWork(ctx, tx, "instance finished | 实例已结束"); err != nil {
		return err
	}
	tx.inst.Status = status
	tx.inst.Outcome = outcome
	tx.inst.EndedAt = tx.now
	tx.inst.UpdatedAt = tx.now
	tx.inst.EndedReason = strings.TrimSpace(reason)
	tx.inst.CurrentNodes = "[]"
	if err := tx.st.UpdateInstance(ctx, *tx.inst); err != nil {
		return err
	}
	eventType := EventInstanceCompleted
	if outcome == "rejected" {
		eventType = EventInstanceRejected
	} else if status == InstanceWithdrawn {
		eventType = EventInstanceWithdrawn
	} else if status == InstanceTerminated {
		eventType = EventInstanceTerminated
	}
	tx.event(ctx, eventType, "", "", actor.ID, actor.Name, reason, "")
	tx.notify(ctx, NotifyCompleted, tx.inst.InitiatorID, "", "")
	if outcome == "rejected" {
		tx.notify(ctx, NotifyRejected, tx.inst.InitiatorID, "", "")
	}
	return nil
}

// cancelLiveWork cancels every live token and every open task of the instance. | cancelLiveWork
// 取消实例的全部活动令牌与未结束任务。
func (s *Service) cancelLiveWork(ctx context.Context, tx *runtimeTxn, reason string) error {
	tokens, err := tx.st.ListTokens(ctx, tx.inst.TenantID, tx.inst.ID)
	if err != nil {
		return err
	}
	for i := range tokens {
		token := &tokens[i]
		if token.Status != TokenActive && token.Status != TokenWaiting {
			continue
		}
		token.Status = TokenCancelled
		token.UpdatedAt = tx.now
		if err := tx.st.UpdateToken(ctx, *token); err != nil {
			return err
		}
	}
	tasks, _, err := tx.st.ListTasks(ctx, tx.inst.TenantID, TaskFilter{InstanceID: tx.inst.ID, Page: 1, PageSize: s.options.MaxPageSize})
	if err != nil {
		return err
	}
	for i := range tasks {
		task := &tasks[i]
		if task.Status != TaskPending && task.Status != TaskClaimed {
			continue
		}
		task.Status = TaskCancelled
		task.Comment = reason
		task.UpdatedAt = tx.now
		if err := tx.st.UpdateTask(ctx, *task); err != nil {
			return err
		}
	}
	return nil
}

// event appends one timeline entry inside the transaction. | event 在事务内追加一条时间线记录。
func (tx *runtimeTxn) event(ctx context.Context, eventType, taskID, nodeID, actorID, actorName, message, detail string) {
	id, err := tx.s.options.NewID("wfeve_")
	if err != nil {
		// A failed id generation is practically impossible (crypto/rand); the event is skipped
		// rather than aborting an already valid business transition. | ID 生成失败在实践中不可能（crypto/rand），
		// 因此跳过事件而不是中止已经合法的业务流转。
		return
	}
	_ = tx.st.CreateEvent(ctx, Event{
		CreatedAt:  tx.now,
		ID:         id,
		TenantID:   tx.inst.TenantID,
		InstanceID: tx.inst.ID,
		TaskID:     taskID,
		NodeID:     nodeID,
		ActorID:    actorID,
		ActorName:  actorName,
		Type:       eventType,
		Message:    message,
		Detail:     detail,
	})
}

// notify enqueues one notification for one recipient inside the transaction. | notify 在事务内为单个接收人排入一条通知。
func (tx *runtimeTxn) notify(ctx context.Context, kind, recipientID, taskID, nodeName string) {
	tx.notifyRecipient(ctx, kind, recipientID, "", "", taskID, nodeName)
}

// notifyRecipient enqueues one notification. Known recipient details skip the directory lookup;
// task activation already resolved every assignee, so a node with many candidates no longer costs
// one directory read per notification. | notifyRecipient 排入一条通知。已知接收人信息会跳过目录查询；
// 任务激活时已经解析了每个审批人，因此候选很多的节点不再为每条通知付一次目录读取。
func (tx *runtimeTxn) notifyRecipient(ctx context.Context, kind, recipientID, recipientName, recipientAddress, taskID, nodeName string) {
	s := tx.s
	if !s.notificationsActive() || !notificationEnabled(s.options.NotifyEvents, kind) {
		return
	}
	recipientID = strings.TrimSpace(recipientID)
	if recipientID == "" {
		return
	}
	title, body := NotificationText(kind, s.notificationLang(), tx.inst.Title, nodeName, "", tx.inst.InitiatorName)
	id, err := s.options.NewID("wfntf_")
	if err != nil {
		return
	}
	if recipientName == "" && recipientAddress == "" && s.directory != nil {
		if assignee, err := s.directory.User(ctx, tx.inst.TenantID, recipientID); err == nil {
			recipientName = assignee.Name
			recipientAddress = assignee.Email
		}
	}
	note := Notification{
		CreatedAt:        tx.now,
		UpdatedAt:        tx.now,
		NextAttemptAt:    tx.now,
		ID:               id,
		TenantID:         tx.inst.TenantID,
		InstanceID:       tx.inst.ID,
		TaskID:           taskID,
		RecipientID:      recipientID,
		RecipientName:    recipientName,
		RecipientAddress: recipientAddress,
		Kind:             kind,
		Status:           NotificationPending,
		Title:            title,
		Body:             body,
		URL:              notificationURL(s.notificationBaseURL(), "/workflow/tasks/"+taskID),
	}
	if taskID == "" {
		note.URL = notificationURL(s.notificationBaseURL(), "/workflow/tasks?instance="+tx.inst.ID)
	}
	if err := tx.st.CreateNotification(ctx, note); err != nil {
		return
	}
	tx.notes = append(tx.notes, note)
}

// notificationsActive reports whether notifications are wired. | notificationsActive 报告通知是否已装配。
func (s *Service) notificationsActive() bool {
	return s.dispatcher != nil && s.dispatcher.Len() > 0
}

// notificationLang is configured through the options' NotifyEvents companion fields; the zero
// value defaults to Chinese. | notificationLang 由选项中的通知伴随字段配置；零值默认中文。
func (s *Service) notificationLang() string { return s.notificationOptions.Lang }

// notificationBaseURL returns the configured deep-link prefix. | notificationBaseURL 返回配置的深链前缀。
func (s *Service) notificationBaseURL() string { return s.notificationOptions.BaseURL }

// flushNotifications dispatches committed notifications and records their outcome. | flushNotifications
// 投递已提交的通知并记录结果。
func (s *Service) flushNotifications(ctx context.Context, notes []Notification) {
	if len(notes) == 0 || !s.notificationsActive() {
		return
	}
	// The business transaction already committed; a delivery failure must never surface as a
	// request failure. | 业务事务已经提交；投递失败绝不能变成请求失败。
	deliverCtx, cancel := context.WithTimeout(ctx, s.options.NotificationTimeout*time.Duration(len(notes)+1))
	defer cancel()
	for i := range notes {
		note := &notes[i]
		err := s.dispatcher.Send(deliverCtx, *note)
		note.Attempts++
		note.UpdatedAt = s.now()
		if err == nil {
			note.Status = NotificationSent
			note.SentAt = note.UpdatedAt
			note.LastError = ""
		} else {
			note.LastError = truncate(err.Error(), 500)
			if note.Attempts >= s.options.NotificationRetry {
				note.Status = NotificationFailed
			} else {
				note.Status = NotificationPending
				note.NextAttemptAt = note.UpdatedAt.Add(retryBackoff(note.Attempts))
			}
			s.log.Warn("workflow notification delivery failed | 流程通知投递失败",
				ydlog.Err(err),
				ydlog.Str("notification", note.ID),
				ydlog.Int("attempts", note.Attempts),
			)
		}
		if updateErr := s.store.UpdateNotification(ctx, *note); updateErr != nil {
			s.log.Warn("workflow notification state could not be stored | 流程通知状态写入失败", ydlog.Err(updateErr))
		}
	}
}

// retryBackoff grows the retry delay without exceeding one hour. | retryBackoff 增大重试延迟，上限一小时。
func retryBackoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	delay := time.Minute * time.Duration(1<<minInt(attempts-1, 6))
	if delay > time.Hour {
		return time.Hour
	}
	return delay
}

// minInt returns the smaller of two ints. | minInt 返回两个整数中的较小者。
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// truncate cuts s to at most limit bytes without splitting a rune. | truncate 把 s 截到至多 limit 字节，且不切断符文。
func truncate(s string, limit int) string {
	if limit <= 0 || len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut]
}

// applyAutoDecision completes a node automatically with the decision and audit trail. |
// applyAutoDecision 依据决策自动完成节点并留下审计痕迹。
func (s *Service) applyAutoDecision(ctx context.Context, tx *runtimeTxn, token *Token, node Node, decision DecisionResult, rule AutoRule) error {
	comment := "自动审批规则 " + rule.ID + " | automatic rule " + rule.ID
	if strings.TrimSpace(decision.Reason) != "" {
		comment += ": " + decision.Reason
	}
	task, err := s.createAutoTask(ctx, tx, token, node, decision, comment)
	if err != nil {
		return err
	}
	tx.event(ctx, EventTaskAutoDecided, task.ID, node.ID, "system", "system", comment, "")
	return s.completeNode(ctx, tx, token, node, decision.Decision, "system", "system", comment)
}

// createAutoTask records one completed system task so an automatic decision is visible in the audit
// table like any human decision. | createAutoTask 记录一个已完成的系统任务，使自动决策与人工决策一样
// 出现在审计表中。
func (s *Service) createAutoTask(ctx context.Context, tx *runtimeTxn, token *Token, node Node, decision DecisionResult, comment string) (Task, error) {
	id, err := s.options.NewID("wftsk_")
	if err != nil {
		return Task{}, errs.Wrap(err, ErrUnavailable)
	}
	task := Task{
		CreatedAt:    tx.now,
		UpdatedAt:    tx.now,
		ClaimedAt:    tx.now,
		CompletedAt:  tx.now,
		ID:           id,
		TenantID:     tx.inst.TenantID,
		InstanceID:   tx.inst.ID,
		TokenID:      token.ID,
		NodeID:       node.ID,
		NodeName:     node.Name,
		NodeNameEN:   node.NameEN,
		AssigneeType: "system",
		AssigneeName: "system",
		Status:       TaskCompleted,
		Decision:     decision.Decision,
		Comment:      truncate(comment, s.options.MaxCommentLen),
		RemindCount:  0,
	}
	if err := tx.st.CreateTask(ctx, task); err != nil {
		return Task{}, err
	}
	return task, nil
}

// finishRejectedByPolicy applies the node's rejection policy. | finishRejectedByPolicy 应用节点的驳回策略。
func (s *Service) finishRejectedByPolicy(ctx context.Context, tx *runtimeTxn, token *Token, node Node, actorID, actorName, message string) error {
	switch node.OnReject {
	case OnRejectEnd:
		return s.finishInstance(ctx, tx, InstanceCompleted, "rejected", message, Actor{ID: actorID, Name: actorName})
	case OnRejectReturnInitiator:
		return s.returnToInitiator(ctx, tx, node, actorID, actorName, message)
	default:
		return s.finishInstance(ctx, tx, InstanceTerminated, "rejected", message, Actor{ID: actorID, Name: actorName})
	}
}

// returnToInitiator cancels live work and creates the synthetic initiator task. | returnToInitiator
// 取消活动工作并创建合成的发起人任务。
func (s *Service) returnToInitiator(ctx context.Context, tx *runtimeTxn, node Node, actorID, actorName, message string) error {
	if err := s.cancelLiveWork(ctx, tx, message); err != nil {
		return err
	}
	tokenID, err := s.options.NewID("wftok_")
	if err != nil {
		return errs.Wrap(err, ErrUnavailable)
	}
	token := Token{
		CreatedAt:  tx.now,
		UpdatedAt:  tx.now,
		ID:         tokenID,
		TenantID:   tx.inst.TenantID,
		InstanceID: tx.inst.ID,
		NodeID:     InitiatorNodeID,
		Status:     TokenActive,
	}
	if err := tx.st.CreateToken(ctx, token); err != nil {
		return err
	}
	tx.inst.CurrentNodes = EncodeStringList([]string{InitiatorNodeID})
	tx.inst.UpdatedAt = tx.now
	if err := tx.st.UpdateInstance(ctx, *tx.inst); err != nil {
		return err
	}
	tx.event(ctx, EventTaskReturned, "", node.ID, actorID, actorName, message, "")
	tx.notify(ctx, NotifyReturned, tx.inst.InitiatorID, "", node.Name)
	return s.activateInitiatorTask(ctx, tx, &token)
}

// activateInitiatorTask creates the revision task assigned to the instance initiator. | activateInitiatorTask
// 创建指派给实例发起人的重新提交任务。
func (s *Service) activateInitiatorTask(ctx context.Context, tx *runtimeTxn, token *Token) error {
	node := Node{
		ID:   InitiatorNodeID,
		Type: NodeUserTask,
		Name: "重新提交 | Revise",
		Assignee: Assignment{
			Type:  AssigneeInitiator,
			Claim: ClaimAssigned,
		},
		Completion: Completion{Mode: CompletionAny},
	}
	return s.activateUserTask(ctx, tx, token, node)
}

// loadRuntime loads the instance, definition, version and design inside a transaction. | loadRuntime
// 在事务内加载实例、定义、版本与设计。
func (s *Service) loadRuntime(ctx context.Context, st Store, tenantID, instanceID string) (*runtimeTxn, error) {
	inst, err := st.GetInstance(ctx, tenantID, instanceID)
	if err != nil {
		return nil, err
	}
	return s.loadRuntimeFor(ctx, st, tenantID, inst)
}

// loadRuntimeFor builds the working set from an instance the caller already read. Task actions
// first load the instance through loadTaskRuntime, so re-reading it here would duplicate a locked
// query on every decision. | loadRuntimeFor 用调用方已经读取的实例构建工作集。任务动作先经
// loadTaskRuntime 读取实例，这里再读一次会让每次决策重复一条加锁查询。
func (s *Service) loadRuntimeFor(ctx context.Context, st Store, tenantID string, inst Instance) (*runtimeTxn, error) {
	version, design, err := s.loadVersion(ctx, st, tenantID, inst.VersionID)
	if err != nil {
		return nil, err
	}
	variables, err := ParseVariables(inst.Variables)
	if err != nil {
		return nil, err
	}
	return &runtimeTxn{
		s:            s,
		st:           st,
		inst:         &inst,
		ver:          version,
		design:       design,
		vars:         variables,
		now:          s.now(),
		tenantID:     tenantID,
		definitionID: inst.DefinitionID,
	}, nil
}

// runtimeDefinition returns the pinned definition, loading it on first use. Only AI decisions
// need it; task completion, parsing and notifications work from the version and instance
// snapshots. | runtimeDefinition 返回绑定定义，首次使用时加载。只有 AI 决策需要它；任务完成、
// 解析与通知都基于版本与实例快照运行。
func (s *Service) runtimeDefinition(ctx context.Context, tx *runtimeTxn) (Definition, error) {
	if tx.defLoaded {
		return tx.def, nil
	}
	def, err := tx.st.GetDefinition(ctx, tx.tenantID, tx.definitionID)
	if err != nil {
		return Definition{}, err
	}
	tx.def = def
	tx.defLoaded = true
	return def, nil
}

// persistRuntime writes the mutable instance and variable state. | persistRuntime 写回可变实例与变量状态。
func (tx *runtimeTxn) persistRuntime(ctx context.Context) error {
	if tx.varsDirty {
		data, err := json.Marshal(tx.vars)
		if err != nil {
			return errs.Wrap(err, ErrInvalidForm)
		}
		if len(data) > tx.s.options.MaxVariablesBytes {
			return errs.Detail(ErrLimit, "variables are %[1]d bytes, limit %[2]d | 变量大小 %[1]d 字节，上限 %[2]d", len(data), tx.s.options.MaxVariablesBytes)
		}
		tx.inst.Variables = string(data)
	}
	tx.inst.UpdatedAt = tx.now
	return tx.st.UpdateInstance(ctx, *tx.inst)
}

// addVisited records one user-task node in the instance trace. | addVisited 在实例轨迹中记录一个用户任务节点。
func (tx *runtimeTxn) addVisited(nodeID string) {
	visited := DecodeStringList(tx.inst.VisitedNodes)
	for _, id := range visited {
		if id == nodeID {
			return
		}
	}
	visited = append(visited, nodeID)
	tx.inst.VisitedNodes = EncodeStringList(visited)
}

// setCurrentNodes records the node ids holding live tasks. | setCurrentNodes 记录持有活动任务的节点 ID。
func (tx *runtimeTxn) setCurrentNodes(nodes []string) {
	tx.inst.CurrentNodes = EncodeStringList(nodes)
}

// instanceVariables returns a copy of the working variables. | instanceVariables 返回工作变量的副本。
func (tx *runtimeTxn) instanceVariables() map[string]any {
	out := make(map[string]any, len(tx.vars))
	for key, value := range tx.vars {
		out[key] = value
	}
	return out
}
