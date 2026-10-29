package workflow

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/regexpx"
)

// activateUserTask resolves assignees, applies automatic rules and creates the node's tasks. |
// activateUserTask 解析审批人、应用自动规则并创建节点任务。
func (s *Service) activateUserTask(ctx context.Context, tx *runtimeTxn, token *Token, node Node) error {
	tx.addVisited(node.ID)
	tx.event(ctx, EventNodeEntered, "", node.ID, "system", "system", "进入节点 | node entered", "")
	assignees, err := s.resolveAssignees(ctx, tx, node)
	if err != nil {
		return err
	}
	if node.AllowAuto {
		decision, rule, matched, err := s.evaluateAuto(ctx, tx, node, AutoEventTask, assignees)
		if err != nil {
			return err
		}
		if matched {
			return s.applyAutoDecision(ctx, tx, token, node, decision, rule)
		}
	}
	token.Status = TokenWaiting
	token.NodeID = node.ID
	token.UpdatedAt = tx.now
	if err := tx.st.UpdateToken(ctx, *token); err != nil {
		return err
	}
	if err := s.createNodeTasks(ctx, tx, token, node, assignees); err != nil {
		return err
	}
	if err := tx.refreshCurrentNodes(ctx); err != nil {
		return err
	}
	return tx.persistRuntime(ctx)
}

// resolveAssignees expands the node assignment into concrete users. | resolveAssignees 把节点指派展开为具体用户。
func (s *Service) resolveAssignees(ctx context.Context, tx *runtimeTxn, node Node) ([]Assignee, error) {
	switch node.Assignee.Type {
	case AssigneeInitiator:
		return []Assignee{{ID: tx.inst.InitiatorID, Name: tx.inst.InitiatorName}}, nil
	case AssigneeUser, AssigneeRole, AssigneeGroup:
	default:
		return nil, ErrInvalidDesign
	}
	if s.directory == nil {
		return nil, errs.Detail(ErrUnavailable, "assignee directory is not configured | 未配置审批人目录")
	}
	var resolved []Assignee
	switch node.Assignee.Type {
	case AssigneeUser:
		users, err := s.directory.Users(ctx, tx.inst.TenantID, node.Assignee.Values)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, users...)
	case AssigneeRole:
		for _, role := range node.Assignee.Values {
			users, err := s.directory.UsersByRole(ctx, tx.inst.TenantID, role)
			if err != nil {
				return nil, err
			}
			resolved = append(resolved, users...)
		}
	case AssigneeGroup:
		for _, ref := range node.Assignee.Values {
			_, users, err := s.resolveGroup(ctx, tx.inst.TenantID, ref)
			if err != nil {
				return nil, err
			}
			resolved = append(resolved, users...)
		}
	}
	seen := make(map[string]int, len(resolved))
	out := make([]Assignee, 0, len(resolved))
	for _, user := range resolved {
		user.ID = strings.TrimSpace(user.ID)
		if user.ID == "" {
			continue
		}
		if index, ok := seen[user.ID]; ok {
			out[index].Roles = mergeStrings(out[index].Roles, user.Roles)
			out[index].Groups = mergeStrings(out[index].Groups, user.Groups)
			continue
		}
		seen[user.ID] = len(out)
		out = append(out, user)
		if len(out) > s.options.MaxAssignees {
			return nil, errs.Detail(ErrLimit, "node %[1]q resolved more than %[2]d assignees | 节点 %[1]q 解析出的审批人超过 %[2]d 个", node.ID, s.options.MaxAssignees)
		}
	}
	if len(out) == 0 {
		return nil, errs.Detail(ErrNoAssignee, "node %[1]q resolved no active users | 节点 %[1]q 没有解析到启用用户", node.ID)
	}
	return out, nil
}

// ruleMatchContext caches the initiator's roles and groups across every rule of one evaluation.
// Before this, a role-scoped rule performed a directory lookup and a group-scoped rule performed
// a database query, once per rule, on every node activation. | ruleMatchContext 在一次求值内缓存
// 发起人的角色与流程组。在此之前，每个角色作用域规则都会查一次目录，每个组作用域规则都会查一次库，
// 每次节点激活都按规则数重复。
type ruleMatchContext struct {
	// assignees are the resolved candidates of the node. | assignees 是节点解析出的候选人。
	assignees []Assignee
	// roles is the initiator's role list. | roles 是发起人的角色列表。
	roles []string
	// groups is the initiator's workflow group keys. | groups 是发起人的流程组键。
	groups []string
	// rolesLoaded and groupsLoaded make the lazy loads run once. | rolesLoaded 与 groupsLoaded 让惰性加载只执行一次。
	rolesLoaded  bool
	groupsLoaded bool
}

// initiatorRoles returns the initiator's roles. | initiatorRoles 返回发起人的角色。
func (c *ruleMatchContext) initiatorRoles(ctx context.Context, s *Service, tx *runtimeTxn) []string {
	if c.rolesLoaded {
		return c.roles
	}
	c.rolesLoaded = true
	if s.directory == nil {
		return nil
	}
	if initiator, err := s.directory.User(ctx, tx.inst.TenantID, tx.inst.InitiatorID); err == nil {
		c.roles = initiator.Roles
	}
	return c.roles
}

// initiatorGroups returns the initiator's workflow group keys. | initiatorGroups 返回发起人的流程组键。
func (c *ruleMatchContext) initiatorGroups(ctx context.Context, s *Service, tx *runtimeTxn) ([]string, error) {
	if c.groupsLoaded {
		return c.groups, nil
	}
	groups, err := tx.st.ListGroupsByUser(ctx, tx.inst.TenantID, tx.inst.InitiatorID)
	if err != nil {
		return nil, err
	}
	c.groups = make([]string, 0, len(groups))
	for _, group := range groups {
		c.groups = append(c.groups, group.Key)
	}
	c.groupsLoaded = true
	return c.groups, nil
}

// evaluateAuto evaluates the definition rules against one event. | evaluateAuto 针对一次事件求值定义规则。
func (s *Service) evaluateAuto(ctx context.Context, tx *runtimeTxn, node Node, event string, assignees []Assignee) (DecisionResult, AutoRule, bool, error) {
	if event == AutoEventTask && !node.AllowAuto {
		return DecisionResult{}, AutoRule{}, false, nil
	}
	match := &ruleMatchContext{assignees: assignees}
	for _, rule := range tx.design.sortedRules() {
		if !rule.Enabled || rule.Event != event {
			continue
		}
		ok, err := s.ruleMatches(ctx, tx, rule, event, match)
		if err != nil {
			return DecisionResult{}, AutoRule{}, false, err
		}
		if !ok {
			continue
		}
		if rule.UseAI {
			if s.decider == nil {
				continue
			}
			def, err := s.runtimeDefinition(ctx, tx)
			if err != nil {
				return DecisionResult{}, AutoRule{}, false, err
			}
			input := DecisionInput{
				TenantID:   tx.inst.TenantID,
				Instance:   *tx.inst,
				Node:       node,
				Definition: def,
				Version:    tx.ver,
				Variables:  tx.instanceVariables(),
				Rule:       rule,
				ActorName:  "system",
			}
			key := aiDecisionKey{
				TenantID:   tx.inst.TenantID,
				InstanceID: tx.inst.ID,
				NodeID:     node.ID,
				RuleID:     rule.ID,
			}
			hash, err := aiInputHash(input)
			if err != nil {
				return DecisionResult{}, AutoRule{}, false, err
			}
			entry, cached := deferredAIDecision(tx.st, key, hash)
			if !cached {
				// Abort this transaction so the decider runs without holding its locks. |
				// 中止当前事务，使决策器不再持有事务锁。
				return DecisionResult{}, AutoRule{}, false, &aiDeferral{key: key, input: input, hash: hash}
			}
			if entry.skip {
				continue
			}
			result := entry.result
			if result.Decision != DecisionApprove && result.Decision != DecisionReject {
				continue
			}
			if result.Confidence > 0 && result.Confidence < s.options.MinAIConfidence {
				continue
			}
			if strings.TrimSpace(result.Reason) == "" {
				result.Reason = "AI 自动审批 | automated by AI"
			}
			return result, rule, true, nil
		}
		return DecisionResult{Decision: rule.Decision, Reason: rule.Name, Confidence: 1}, rule, true, nil
	}
	return DecisionResult{}, AutoRule{}, false, nil
}

// ruleMatches reports whether the rule's scope matches the current instance and node. |
// ruleMatches 报告规则作用域是否匹配当前实例与节点。
func (s *Service) ruleMatches(ctx context.Context, tx *runtimeTxn, rule AutoRule, event string, match *ruleMatchContext) (bool, error) {
	switch rule.Scope {
	case AutoScopeCategory:
		return containsFold(rule.Match, tx.inst.Category), nil
	case AutoScopeUser:
		if containsFold(rule.Match, tx.inst.InitiatorID) {
			return true, nil
		}
		for _, assignee := range match.assignees {
			if containsFold(rule.Match, assignee.ID) {
				return true, nil
			}
		}
		return false, nil
	case AutoScopeRole:
		for _, assignee := range match.assignees {
			for _, role := range assignee.Roles {
				if containsFold(rule.Match, role) {
					return true, nil
				}
			}
		}
		for _, role := range match.initiatorRoles(ctx, s, tx) {
			if containsFold(rule.Match, role) {
				return true, nil
			}
		}
		return false, nil
	case AutoScopeEvent:
		return containsFold(rule.Match, event), nil
	case AutoScopeGroup:
		for _, assignee := range match.assignees {
			for _, group := range assignee.Groups {
				if containsFold(rule.Match, group) {
					return true, nil
				}
			}
		}
		groups, err := match.initiatorGroups(ctx, s, tx)
		if err != nil {
			return false, err
		}
		for _, group := range groups {
			if containsFold(rule.Match, group) {
				return true, nil
			}
		}
		return false, nil
	case AutoScopeVariable:
		return EvaluateCondition(rule.Condition, tx.vars)
	default:
		return false, nil
	}
}

// mergeStrings appends values that are not already present. | mergeStrings 追加尚不存在的值。
func mergeStrings(target []string, values []string) []string {
	for _, value := range values {
		found := false
		for _, existing := range target {
			if existing == value {
				found = true
				break
			}
		}
		if !found {
			target = append(target, value)
		}
	}
	return target
}

// containsFold reports whether list contains value, ignoring case. | containsFold 报告列表是否包含值（忽略大小写）。
func containsFold(list []string, value string) bool {
	value = strings.TrimSpace(value)
	for _, item := range list {
		if strings.EqualFold(strings.TrimSpace(item), value) {
			return true
		}
	}
	return false
}

// createNodeTasks creates one task per assignee, honouring sequential mode and claim mode. |
// createNodeTasks 为每个审批人创建任务，遵循顺序模式与认领模式。
func (s *Service) createNodeTasks(ctx context.Context, tx *runtimeTxn, token *Token, node Node, assignees []Assignee) error {
	for i, assignee := range assignees {
		status := TaskPending
		if node.Completion.Sequential && i > 0 {
			status = TaskQueued
		}
		task, err := s.createTask(ctx, tx, token, node, assignee, i, status)
		if err != nil {
			return err
		}
		if status == TaskPending {
			if task.AssigneeID != "" {
				tx.notifyRecipient(ctx, NotifyAssigned, task.AssigneeID, assignee.Name, assignee.Email, task.ID, node.Name)
			}
			for _, candidate := range task.Candidates {
				candidate = strings.TrimSpace(candidate)
				if candidate == "" || candidate == task.AssigneeID {
					continue
				}
				tx.notifyRecipient(ctx, NotifyAssigned, candidate, assignee.Name, assignee.Email, task.ID, node.Name)
			}
		}
	}
	return nil
}

// createTask inserts one task for one assignee. | createTask 为一个审批人插入一条任务。
func (s *Service) createTask(ctx context.Context, tx *runtimeTxn, token *Token, node Node, assignee Assignee, seq int, status string) (Task, error) {
	id, err := s.options.NewID("wftsk_")
	if err != nil {
		return Task{}, errs.Wrap(err, ErrUnavailable)
	}
	due := tx.now.Add(s.options.DefaultDue)
	if raw := strings.TrimSpace(tx.design.Settings.Due); raw != "" {
		if parsed, parseErr := time.ParseDuration(raw); parseErr == nil {
			due = tx.now.Add(parsed)
		}
	}
	if raw := strings.TrimSpace(node.Due); raw != "" {
		if parsed, parseErr := time.ParseDuration(raw); parseErr == nil {
			due = tx.now.Add(parsed)
		}
	}
	remindEvery := s.options.DefaultRemindEvery
	if raw := strings.TrimSpace(node.RemindEvery); raw != "" {
		if parsed, parseErr := time.ParseDuration(raw); parseErr == nil {
			remindEvery = parsed
		}
	}
	maxRemind := s.options.DefaultMaxRemind
	if node.MaxRemind > 0 {
		maxRemind = node.MaxRemind
	}
	task := Task{
		CreatedAt:          tx.now,
		UpdatedAt:          tx.now,
		DueAt:              due,
		NextRemindAt:       due,
		ID:                 id,
		TenantID:           tx.inst.TenantID,
		InstanceID:         tx.inst.ID,
		TokenID:            token.ID,
		NodeID:             node.ID,
		NodeName:           node.Name,
		NodeNameEN:         node.NameEN,
		AssigneeType:       node.Assignee.Type,
		Status:             status,
		Decision:           DecisionNone,
		Seq:                seq,
		RemindCount:        0,
		MaxRemind:          maxRemind,
		RemindEverySeconds: int(remindEvery / time.Second),
		InstanceTitle:      tx.inst.Title,
		InstanceInitiator:  tx.inst.InitiatorName,
		DefinitionKey:      tx.inst.DefinitionKey,
		Category:           tx.inst.Category,
	}
	if node.Assignee.Claim == ClaimAssigned {
		task.AssigneeID = assignee.ID
		task.AssigneeName = assignee.Name
	} else {
		task.Candidates = []string{assignee.ID}
		task.CandidateRefs = CandidateIndex(task.Candidates)
	}
	if err := tx.st.CreateTask(ctx, task); err != nil {
		return Task{}, err
	}
	return task, nil
}

// refreshCurrentNodes recomputes the node ids that hold waiting tokens. | refreshCurrentNodes
// 重新计算持有等待令牌的节点 ID。
func (tx *runtimeTxn) refreshCurrentNodes(ctx context.Context) error {
	var tokens []Token
	var err error
	if lister, ok := tx.st.(waitingTokenLister); ok {
		// Only waiting tokens matter; completed rows would make this scan grow with history. |
		// 只有等待令牌有意义；已完成的行会让扫描随历史增长。
		tokens, err = lister.ListWaitingTokens(ctx, tx.inst.TenantID, tx.inst.ID)
	} else {
		tokens, err = tx.st.ListTokens(ctx, tx.inst.TenantID, tx.inst.ID)
	}
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	nodes := make([]string, 0, len(tokens))
	for _, token := range tokens {
		if token.Status != TokenWaiting {
			continue
		}
		node, ok := tx.design.FindNode(token.NodeID)
		if !ok {
			if token.NodeID == InitiatorNodeID {
				if !seen[token.NodeID] {
					seen[token.NodeID] = true
					nodes = append(nodes, token.NodeID)
				}
			}
			continue
		}
		if node.Type != NodeUserTask {
			continue
		}
		if !seen[node.ID] {
			seen[node.ID] = true
			nodes = append(nodes, node.ID)
		}
	}
	sort.Strings(nodes)
	tx.setCurrentNodes(nodes)
	return nil
}

// validateSubmittedForm validates a map of values against form fields. | validateSubmittedForm
// 依据表单字段校验一份提交值。
func (s *Service) validateSubmittedForm(fields []FormField, values map[string]any) error {
	for _, field := range fields {
		raw, present := values[field.Key]
		if !present || raw == nil {
			if field.Required {
				return errs.Detail(ErrInvalidForm, "field %[1]q is required | 字段 %[1]q 必填", field.Key)
			}
			continue
		}
		switch field.Type {
		case "checkbox":
			checked, ok := boolValue(raw)
			if !ok {
				return errs.Detail(ErrInvalidForm, "field %[1]q needs a boolean | 字段 %[1]q 需要布尔值", field.Key)
			}
			if field.Required && !checked {
				return errs.Detail(ErrInvalidForm, "field %[1]q must be checked | 字段 %[1]q 必须勾选", field.Key)
			}
		case "number":
			number, ok := numericValue(raw)
			if !ok {
				return errs.Detail(ErrInvalidForm, "field %[1]q needs a number | 字段 %[1]q 需要数字", field.Key)
			}
			if field.Max != 0 && number > field.Max {
				return errs.Detail(ErrInvalidForm, "field %[1]q exceeds its maximum | 字段 %[1]q 超过最大值", field.Key)
			}
			if field.Min != 0 && number < field.Min {
				return errs.Detail(ErrInvalidForm, "field %[1]q is below its minimum | 字段 %[1]q 低于最小值", field.Key)
			}
		case "select":
			text := stringValue(raw)
			if text == "" {
				if field.Required {
					return errs.Detail(ErrInvalidForm, "field %[1]q is required | 字段 %[1]q 必填", field.Key)
				}
				continue
			}
			matched := false
			for _, option := range field.Options {
				if option.Value == text {
					matched = true
					break
				}
			}
			if !matched {
				return errs.Detail(ErrInvalidForm, "field %[1]q has an unknown option | 字段 %[1]q 的取值不在选项中", field.Key)
			}
		case "date", "datetime":
			text := strings.TrimSpace(stringValue(raw))
			if text == "" {
				if field.Required {
					return errs.Detail(ErrInvalidForm, "field %[1]q is required | 字段 %[1]q 必填", field.Key)
				}
				continue
			}
			layout := "2006-01-02"
			if field.Type == "datetime" {
				layout = time.RFC3339
			}
			if _, err := time.Parse(layout, text); err != nil {
				return errs.Detail(ErrInvalidForm, "field %[1]q has an invalid date | 字段 %[1]q 的日期非法", field.Key)
			}
		default:
			text := stringValue(raw)
			if text == "" {
				if field.Required {
					return errs.Detail(ErrInvalidForm, "field %[1]q is required | 字段 %[1]q 必填", field.Key)
				}
				continue
			}
			if field.MaxLength > 0 && len([]rune(text)) > field.MaxLength {
				return errs.Detail(ErrInvalidForm, "field %[1]q is longer than %[2]d characters | 字段 %[1]q 超过 %[2]d 个字符", field.Key, field.MaxLength)
			}
			if field.Pattern != "" {
				pattern, err := regexpx.Compile(field.Pattern)
				if err != nil || !pattern.MatchString(text) {
					return errs.Detail(ErrInvalidForm, "field %[1]q does not match its pattern | 字段 %[1]q 不匹配正则", field.Key)
				}
			}
		}
	}
	return nil
}

// boolValue interprets the boolean carriers a form may submit. | boolValue 解读表单可能提交的布尔载体。
func boolValue(value any) (bool, bool) {
	switch v := value.(type) {
	case bool:
		return v, true
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "1", "on", "yes":
			return true, true
		case "false", "0", "off", "no", "":
			return false, true
		}
		return false, false
	case float64:
		return v != 0, true
	case int:
		return v != 0, true
	default:
		return false, false
	}
}

// mergeFormData merges submitted form values into the instance variables. | mergeFormData
// 把提交的表单值合并到实例变量。
func (tx *runtimeTxn) mergeFormData(values map[string]any) {
	if len(values) == 0 {
		return
	}
	if tx.vars == nil {
		tx.vars = map[string]any{}
	}
	for key, value := range values {
		tx.vars[key] = value
	}
	tx.varsDirty = true
}

// evaluateCompletion computes the node result from its tasks. | evaluateCompletion 依据任务计算节点结果。
func (s *Service) evaluateCompletion(ctx context.Context, tx *runtimeTxn, token *Token, node Node) (string, error) {
	tasks, err := tx.st.ListTasksByToken(ctx, tx.inst.TenantID, token.ID)
	if err != nil {
		return "", err
	}
	total, approved, rejected, open := 0, 0, 0, 0
	for _, task := range tasks {
		if task.Status == TaskCancelled {
			continue
		}
		total++
		switch task.Status {
		case TaskCompleted:
			if task.Decision == DecisionApprove {
				approved++
			} else if task.Decision == DecisionReject {
				rejected++
			}
		case TaskPending, TaskClaimed, TaskQueued:
			open++
		}
	}
	mode := node.Completion.Mode
	if mode == "" {
		mode = CompletionAny
	}
	rejectImmediate := node.Completion.RejectMode != RejectModeAll
	switch mode {
	case CompletionAny:
		if approved > 0 {
			return DecisionApprove, nil
		}
		if open == 0 && rejected > 0 {
			return DecisionReject, nil
		}
		return DecisionNone, nil
	case CompletionAll:
		if rejected > 0 && (rejectImmediate || open == 0) {
			return DecisionReject, nil
		}
		if total > 0 && approved == total {
			return DecisionApprove, nil
		}
		return DecisionNone, nil
	case CompletionVote:
		if rejected > 0 && rejectImmediate {
			return DecisionReject, nil
		}
		need := voteThreshold(node.Completion, total)
		if approved >= need {
			return DecisionApprove, nil
		}
		if approved+open < need {
			return DecisionReject, nil
		}
		if open == 0 {
			return DecisionReject, nil
		}
		return DecisionNone, nil
	default:
		return "", ErrInvalidDesign
	}
}

// voteThreshold converts a count or percentage threshold into a whole vote count. | voteThreshold
// 把票数或百分比阈值转换为整数票数。
func voteThreshold(completion Completion, total int) int {
	if completion.ThresholdType == ThresholdPercent {
		need := int(completion.Threshold*float64(total)/100 + 0.999999)
		if need < 1 {
			need = 1
		}
		return need
	}
	need := int(completion.Threshold)
	if need < 1 {
		need = 1
	}
	return need
}

// cancelOpenTasks cancels every actionable or queued task of one token. | cancelOpenTasks
// 取消一个令牌下全部可处理或排队任务。
func (s *Service) cancelOpenTasks(ctx context.Context, tx *runtimeTxn, tokenID, reason string) error {
	tasks, err := tx.st.ListTasksByToken(ctx, tx.inst.TenantID, tokenID)
	if err != nil {
		return err
	}
	for i := range tasks {
		task := &tasks[i]
		if task.Status != TaskPending && task.Status != TaskClaimed && task.Status != TaskQueued {
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

// promoteQueuedTask activates the next queued task of a token in sequential mode. |
// promoteQueuedTask 在顺序模式下激活令牌的下一条排队任务。
func (s *Service) promoteQueuedTask(ctx context.Context, tx *runtimeTxn, tokenID string) (Task, bool, error) {
	tasks, err := tx.st.ListTasksByToken(ctx, tx.inst.TenantID, tokenID)
	if err != nil {
		return Task{}, false, err
	}
	var next *Task
	for i := range tasks {
		task := &tasks[i]
		if task.Status != TaskQueued {
			continue
		}
		if next == nil || task.Seq < next.Seq || (task.Seq == next.Seq && task.ID < next.ID) {
			next = task
		}
	}
	if next == nil {
		return Task{}, false, nil
	}
	next.Status = TaskPending
	next.UpdatedAt = tx.now
	if err := tx.st.UpdateTask(ctx, *next); err != nil {
		return Task{}, false, err
	}
	tx.notify(ctx, NotifyAssigned, next.AssigneeID, next.ID, next.NodeName)
	for _, candidate := range next.CandidateList() {
		tx.notify(ctx, NotifyAssigned, candidate, next.ID, next.NodeName)
	}
	return *next, true, nil
}

// taskJSON encodes one task's form payload. | taskJSON 编码任务的表单载荷。
func taskJSON(values map[string]any) string {
	if len(values) == 0 {
		return ""
	}
	data, err := json.Marshal(values)
	if err != nil {
		return ""
	}
	return string(data)
}

// parseFormData decodes a task form payload. | parseFormData 解码任务表单载荷。
func parseFormData(raw string) map[string]any {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	out := map[string]any{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

// intString renders an integer for diagnostics. | intString 为诊断渲染整数。
func intString(value int) string { return strconv.Itoa(value) }
