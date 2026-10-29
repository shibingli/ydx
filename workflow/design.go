package workflow

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/regexpx"
)

// formTypes is the closed set of supported form field types. | formTypes 是受支持的表单字段类型闭集。
var formTypes = map[string]bool{
	"text":     true,
	"textarea": true,
	"number":   true,
	"date":     true,
	"datetime": true,
	"select":   true,
	"checkbox": true,
}

// nodeTypes is the closed set of supported BPMN node types. | nodeTypes 是受支持的 BPMN 节点类型闭集。
var nodeTypes = map[string]bool{
	NodeStart:        true,
	NodeEnd:          true,
	NodeUserTask:     true,
	NodeServiceTask:  true,
	NodeExclusive:    true,
	NodeParallel:     true,
	NodeInclusive:    true,
	NodeCatch:        true,
	NodeEventGateway: true,
}

// normalizeDesign parses, validates and canonicalises one design document. The returned string
// is the exact JSON persisted in the version row. | normalizeDesign 解析、校验并规范化一个设计文档。
// 返回的字符串就是写入版本行的精确 JSON。
func (s *Service) normalizeDesign(in Design) (Design, string, error) {
	if in.SchemaVersion <= 0 {
		in.SchemaVersion = 1
	}
	if in.SchemaVersion > 1 {
		return Design{}, "", errs.Detail(ErrInvalidDesign, "unsupported schema version %[1]d | 不支持的 schema 版本 %[1]d", in.SchemaVersion)
	}
	if in.Forms == nil {
		in.Forms = map[string][]FormField{}
	}
	if len(in.Nodes) == 0 {
		return Design{}, "", errs.Detail(ErrInvalidDesign, "a design needs at least one node | 设计至少需要一个节点")
	}
	if len(in.Nodes) > s.options.MaxNodes {
		return Design{}, "", errs.Detail(ErrLimit, "node count %[1]d exceeds %[2]d | 节点数 %[1]d 超过 %[2]d", len(in.Nodes), s.options.MaxNodes)
	}
	if len(in.Edges) > s.options.MaxEdges {
		return Design{}, "", errs.Detail(ErrLimit, "edge count %[1]d exceeds %[2]d | 连线数 %[1]d 超过 %[2]d", len(in.Edges), s.options.MaxEdges)
	}

	nodes := make(map[string]Node, len(in.Nodes))
	startCount, endCount := 0, 0
	for i := range in.Nodes {
		node := &in.Nodes[i]
		node.ID = strings.TrimSpace(node.ID)
		node.Type = strings.TrimSpace(node.Type)
		if !nodeIDRe.MatchString(node.ID) {
			return Design{}, "", errs.Detail(ErrInvalidDesign, "node id=%[1]q | 节点 ID=%[1]q", node.ID)
		}
		if _, dup := nodes[node.ID]; dup {
			return Design{}, "", errs.Detail(ErrInvalidDesign, "duplicate node id %[1]q | 节点 ID %[1]q 重复", node.ID)
		}
		if !nodeTypes[node.Type] {
			return Design{}, "", errs.Detail(ErrInvalidDesign, "node %[1]q has unknown type %[2]q | 节点 %[1]q 的类型 %[2]q 未知", node.ID, node.Type)
		}
		var ok bool
		if node.Name, ok = trimLen(node.Name, s.options.MaxNameLen); !ok || node.Name == "" {
			return Design{}, "", errs.Detail(ErrInvalidDesign, "node %[1]q needs a name | 节点 %[1]q 需要名称", node.ID)
		}
		if node.NameEN, ok = trimLen(node.NameEN, s.options.MaxNameLen); !ok {
			return Design{}, "", errs.Detail(ErrInvalidDesign, "node %[1]q has an over-long English name | 节点 %[1]q 的英文名过长", node.ID)
		}
		if node.Description, ok = trimLen(node.Description, s.options.MaxDescriptionLen); !ok {
			return Design{}, "", ErrInvalidDesign
		}
		if node.DescriptionEN, ok = trimLen(node.DescriptionEN, s.options.MaxDescriptionLen); !ok {
			return Design{}, "", ErrInvalidDesign
		}
		switch node.Type {
		case NodeStart:
			startCount++
		case NodeEnd:
			endCount++
		case NodeUserTask:
			if err := s.normalizeAssignment(node); err != nil {
				return Design{}, "", err
			}
		case NodeServiceTask:
			node.Assignee = Assignment{}
		case NodeCatch:
			node.WaitKind = strings.TrimSpace(node.WaitKind)
			switch node.WaitKind {
			case WaitTimer:
				node.WaitFor = strings.TrimSpace(node.WaitFor)
				if _, err := parseDurationText(node.WaitFor); err != nil {
					return Design{}, "", errs.Detail(ErrInvalidDesign, "catch event %[1]q needs a valid timer duration | 捕获事件 %[1]q 需要合法的定时时长", node.ID)
				}
			case WaitMessage:
				node.MessageName = strings.TrimSpace(node.MessageName)
				if node.MessageName == "" || len(node.MessageName) > 128 {
					return Design{}, "", errs.Detail(ErrInvalidDesign, "catch event %[1]q needs a signal name | 捕获事件 %[1]q 需要信号名", node.ID)
				}
			default:
				return Design{}, "", errs.Detail(ErrInvalidDesign, "catch event %[1]q needs a wait kind | 捕获事件 %[1]q 需要等待类型", node.ID)
			}
		}
		if err := s.normalizeNodeTiming(node); err != nil {
			return Design{}, "", err
		}
		nodes[node.ID] = *node
	}
	if startCount != 1 {
		return Design{}, "", errs.Detail(ErrInvalidDesign, "a design needs exactly one start event, found %[1]d | 设计必须恰好有一个开始事件，实际为 %[1]d", startCount)
	}
	if endCount == 0 {
		return Design{}, "", errs.Detail(ErrInvalidDesign, "a design needs at least one end event | 设计至少需要一个结束事件")
	}

	edges := make(map[string]Edge, len(in.Edges))
	outgoing := make(map[string][]Edge, len(in.Nodes))
	incoming := make(map[string][]Edge, len(in.Nodes))
	for i := range in.Edges {
		edge := &in.Edges[i]
		edge.ID = strings.TrimSpace(edge.ID)
		if !nodeIDRe.MatchString(edge.ID) {
			return Design{}, "", errs.Detail(ErrInvalidDesign, "edge id=%[1]q | 连线 ID=%[1]q", edge.ID)
		}
		if _, dup := edges[edge.ID]; dup {
			return Design{}, "", errs.Detail(ErrInvalidDesign, "duplicate edge id %[1]q | 连线 ID %[1]q 重复", edge.ID)
		}
		if _, ok := nodes[edge.Source]; !ok {
			return Design{}, "", errs.Detail(ErrInvalidDesign, "edge %[1]q names unknown source %[2]q | 连线 %[1]q 的源节点 %[2]q 不存在", edge.ID, edge.Source)
		}
		if _, ok := nodes[edge.Target]; !ok {
			return Design{}, "", errs.Detail(ErrInvalidDesign, "edge %[1]q names unknown target %[2]q | 连线 %[1]q 的目标节点 %[2]q 不存在", edge.ID, edge.Target)
		}
		if edge.Source == edge.Target {
			return Design{}, "", errs.Detail(ErrInvalidDesign, "edge %[1]q is a self loop | 连线 %[1]q 是自环", edge.ID)
		}
		edge.Condition = strings.TrimSpace(edge.Condition)
		if edge.Condition != "" {
			source := nodes[edge.Source]
			if source.Type != NodeExclusive && source.Type != NodeInclusive {
				return Design{}, "", errs.Detail(ErrInvalidDesign, "edge %[1]q from %[2]s cannot carry a condition | 来自 %[2]s 的连线 %[1]q 不能携带条件", edge.ID, source.Type)
			}
			if len(edge.Condition) > s.options.MaxConditionLen {
				return Design{}, "", errs.Detail(ErrLimit, "condition on edge %[1]q is too long | 连线 %[1]q 的条件过长", edge.ID)
			}
			if err := ValidateCondition(edge.Condition); err != nil {
				return Design{}, "", errs.Detail(ErrInvalidCondition, "edge %[1]q: %[2]s | 连线 %[1]q：%[2]s", edge.ID, err.Error())
			}
		}
		if edge.Default {
			if nodes[edge.Source].Type != NodeExclusive {
				return Design{}, "", errs.Detail(ErrInvalidDesign, "edge %[1]q is default but its source is not an exclusive gateway | 连线 %[1]q 是默认流，但源节点不是排他网关", edge.ID)
			}
			if edge.Condition != "" {
				return Design{}, "", errs.Detail(ErrInvalidDesign, "the default edge %[1]q cannot carry a condition | 默认连线 %[1]q 不能携带条件", edge.ID)
			}
		}
		edges[edge.ID] = *edge
		outgoing[edge.Source] = append(outgoing[edge.Source], *edge)
		incoming[edge.Target] = append(incoming[edge.Target], *edge)
	}

	for i := range in.Nodes {
		node := in.Nodes[i]
		out := outgoing[node.ID]
		in := incoming[node.ID]
		switch node.Type {
		case NodeStart:
			if len(in) != 0 {
				return Design{}, "", errs.Detail(ErrInvalidDesign, "start event %[1]q has incoming flows | 开始事件 %[1]q 存在入线", node.ID)
			}
			if len(out) == 0 {
				return Design{}, "", errs.Detail(ErrInvalidDesign, "start event %[1]q has no outgoing flow | 开始事件 %[1]q 没有出线", node.ID)
			}
		case NodeEnd:
			if len(out) != 0 {
				return Design{}, "", errs.Detail(ErrInvalidDesign, "end event %[1]q has outgoing flows | 结束事件 %[1]q 存在出线", node.ID)
			}
			if len(in) == 0 {
				return Design{}, "", errs.Detail(ErrInvalidDesign, "end event %[1]q has no incoming flow | 结束事件 %[1]q 没有入线", node.ID)
			}
		default:
			if len(out) == 0 {
				return Design{}, "", errs.Detail(ErrInvalidDesign, "node %[1]q has no outgoing flow | 节点 %[1]q 没有出线", node.ID)
			}
			if len(in) == 0 {
				return Design{}, "", errs.Detail(ErrInvalidDesign, "node %[1]q has no incoming flow | 节点 %[1]q 没有入线", node.ID)
			}
		}
		if node.Type == NodeExclusive {
			defaults, unconditional := 0, 0
			for _, edge := range out {
				if edge.Default {
					defaults++
				}
				if edge.Condition == "" && !edge.Default {
					unconditional++
				}
			}
			if defaults > 1 {
				return Design{}, "", errs.Detail(ErrInvalidDesign, "exclusive gateway %[1]q has %[2]d default flows | 排他网关 %[1]q 有 %[2]d 条默认流", node.ID, defaults)
			}
			if unconditional > 1 {
				return Design{}, "", errs.Detail(ErrInvalidDesign, "exclusive gateway %[1]q has %[2]d unconditional flows | 排他网关 %[1]q 有 %[2]d 条无条件流", node.ID, unconditional)
			}
		}
		if node.Type == NodeParallel {
			for _, edge := range out {
				if edge.Condition != "" {
					return Design{}, "", errs.Detail(ErrInvalidDesign, "parallel gateway %[1]q cannot branch on a condition | 并行网关 %[1]q 不能按条件分支", node.ID)
				}
			}
		}
		if node.Type == NodeCatch && len(out) != 1 {
			return Design{}, "", errs.Detail(ErrInvalidDesign, "catch event %[1]q must have exactly one outgoing flow | 捕获事件 %[1]q 必须恰好有一条出线", node.ID)
		}
		if node.Type == NodeEventGateway {
			if len(out) < 2 {
				return Design{}, "", errs.Detail(ErrInvalidDesign, "event gateway %[1]q needs at least two outgoing flows | 事件网关 %[1]q 至少需要两条出线", node.ID)
			}
			for _, edge := range out {
				target, ok := nodes[edge.Target]
				if !ok || target.Type != NodeCatch {
					return Design{}, "", errs.Detail(ErrInvalidDesign, "event gateway %[1]q may only lead to catch events | 事件网关 %[1]q 只能指向捕获事件", node.ID)
				}
			}
		}
	}

	if err := reachable(in.Nodes, nodes, outgoing); err != nil {
		return Design{}, "", err
	}

	if err := s.validateForms(in.Forms); err != nil {
		return Design{}, "", err
	}
	if err := s.validateRules(in.Rules); err != nil {
		return Design{}, "", err
	}
	if err := s.validateSettings(in.Settings); err != nil {
		return Design{}, "", err
	}

	data, err := json.Marshal(in)
	if err != nil {
		return Design{}, "", errs.Wrap(err, ErrInvalidDesign)
	}
	if len(data) > s.options.MaxDesignBytes {
		return Design{}, "", errs.Detail(ErrLimit, "design is %[1]d bytes, limit %[2]d | 设计大小 %[1]d 字节，上限 %[2]d", len(data), s.options.MaxDesignBytes)
	}
	return in, string(data), nil
}

// reachable verifies that every node can be reached from the start event. | reachable 校验每个节点都能从开始事件到达。
func reachable(list []Node, nodes map[string]Node, outgoing map[string][]Edge) error {
	startID := ""
	for _, node := range list {
		if node.Type == NodeStart {
			startID = node.ID
			break
		}
	}
	seen := map[string]bool{startID: true}
	queue := []string{startID}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, edge := range outgoing[current] {
			if seen[edge.Target] {
				continue
			}
			seen[edge.Target] = true
			queue = append(queue, edge.Target)
		}
	}
	for _, node := range list {
		if !seen[node.ID] {
			return errs.Detail(ErrInvalidDesign, "node %[1]q is not reachable from the start event | 节点 %[1]q 无法从开始事件到达", node.ID)
		}
	}
	return nil
}

// normalizeAssignment validates the assignee and completion settings of a user task. | normalizeAssignment
// 校验用户任务的指派与完成配置。
func (s *Service) normalizeAssignment(node *Node) error {
	node.Assignee.Type = strings.TrimSpace(node.Assignee.Type)
	if node.Assignee.Type == "" {
		node.Assignee.Type = AssigneeInitiator
	}
	switch node.Assignee.Type {
	case AssigneeUser, AssigneeRole, AssigneeGroup, AssigneeInitiator:
	default:
		return errs.Detail(ErrInvalidDesign, "node %[1]q has an unknown assignee type %[2]q | 节点 %[1]q 的指派类型 %[2]q 未知", node.ID, node.Assignee.Type)
	}
	if node.Assignee.Type != AssigneeInitiator && len(node.Assignee.Values) == 0 {
		return errs.Detail(ErrInvalidDesign, "node %[1]q has no assignee values | 节点 %[1]q 没有指派值", node.ID)
	}
	if len(node.Assignee.Values) > s.options.MaxAssignees {
		return errs.Detail(ErrLimit, "node %[1]q has %[2]d assignees, limit %[3]d | 节点 %[1]q 有 %[2]d 个指派值，上限 %[3]d", node.ID, len(node.Assignee.Values), s.options.MaxAssignees)
	}
	seen := map[string]bool{}
	values := make([]string, 0, len(node.Assignee.Values))
	for _, value := range node.Assignee.Values {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > 128 {
			return errs.Detail(ErrInvalidDesign, "node %[1]q has an invalid assignee value | 节点 %[1]q 含非法指派值", node.ID)
		}
		if seen[value] {
			continue
		}
		seen[value] = true
		values = append(values, value)
	}
	node.Assignee.Values = values
	if node.Assignee.Type == AssigneeInitiator {
		node.Assignee.Values = nil
	}
	node.Assignee.Claim = strings.TrimSpace(node.Assignee.Claim)
	if node.Assignee.Claim == "" {
		node.Assignee.Claim = ClaimAssigned
	}
	switch node.Assignee.Claim {
	case ClaimAssigned, ClaimRequired, ClaimGrab:
	default:
		return errs.Detail(ErrInvalidDesign, "node %[1]q has an unknown claim mode %[2]q | 节点 %[1]q 的认领模式 %[2]q 未知", node.ID, node.Assignee.Claim)
	}

	node.Completion.Mode = strings.TrimSpace(node.Completion.Mode)
	if node.Completion.Mode == "" {
		node.Completion.Mode = CompletionAny
	}
	switch node.Completion.Mode {
	case CompletionAny, CompletionAll, CompletionVote:
	default:
		return errs.Detail(ErrInvalidDesign, "node %[1]q has an unknown completion mode %[2]q | 节点 %[1]q 的完成模式 %[2]q 未知", node.ID, node.Completion.Mode)
	}
	if node.Completion.Mode == CompletionVote {
		node.Completion.ThresholdType = strings.TrimSpace(node.Completion.ThresholdType)
		if node.Completion.ThresholdType == "" {
			node.Completion.ThresholdType = ThresholdCount
		}
		switch node.Completion.ThresholdType {
		case ThresholdCount:
			if node.Completion.Threshold < 1 || node.Completion.Threshold != float64(int(node.Completion.Threshold)) {
				return errs.Detail(ErrInvalidDesign, "node %[1]q needs a whole count threshold | 节点 %[1]q 需要整数票数阈值", node.ID)
			}
		case ThresholdPercent:
			if node.Completion.Threshold <= 0 || node.Completion.Threshold > 100 {
				return errs.Detail(ErrInvalidDesign, "node %[1]q needs a percentage threshold in (0,100] | 节点 %[1]q 需要 (0,100] 区间内的百分比阈值", node.ID)
			}
		default:
			return errs.Detail(ErrInvalidDesign, "node %[1]q has an unknown threshold type | 节点 %[1]q 的阈值类型未知", node.ID)
		}
	} else {
		node.Completion.ThresholdType = ""
		node.Completion.Threshold = 0
	}
	if node.Completion.Mode == CompletionAll || node.Completion.Mode == CompletionVote {
		node.Completion.RejectMode = strings.TrimSpace(node.Completion.RejectMode)
		if node.Completion.RejectMode == "" {
			node.Completion.RejectMode = RejectModeAny
		}
		switch node.Completion.RejectMode {
		case RejectModeAny, RejectModeAll:
		default:
			return errs.Detail(ErrInvalidDesign, "node %[1]q has an unknown reject mode | 节点 %[1]q 的驳回模式未知", node.ID)
		}
	} else {
		node.Completion.RejectMode = ""
	}
	node.OnReject = strings.TrimSpace(node.OnReject)
	if node.OnReject == "" {
		node.OnReject = OnRejectTerminate
	}
	switch node.OnReject {
	case OnRejectTerminate, OnRejectEnd, OnRejectReturnInitiator:
	default:
		return errs.Detail(ErrInvalidDesign, "node %[1]q has an unknown rejection policy | 节点 %[1]q 的驳回策略未知", node.ID)
	}
	if node.MaxRemind < 0 || node.MaxRemind > 100 {
		return errs.Detail(ErrInvalidDesign, "node %[1]q has an invalid reminder limit | 节点 %[1]q 的催办上限非法", node.ID)
	}
	return nil
}

// normalizeNodeTiming validates the due and reminder durations of a node. | normalizeNodeTiming
// 校验节点的期限与催办时长。
func (s *Service) normalizeNodeTiming(node *Node) error {
	node.Due = strings.TrimSpace(node.Due)
	if node.Due != "" {
		d, err := time.ParseDuration(node.Due)
		if err != nil || d < 0 {
			return errs.Detail(ErrInvalidDesign, "node %[1]q has an invalid due duration | 节点 %[1]q 的期限非法", node.ID)
		}
	}
	node.RemindEvery = strings.TrimSpace(node.RemindEvery)
	if node.RemindEvery != "" {
		d, err := time.ParseDuration(node.RemindEvery)
		if err != nil || d < 0 {
			return errs.Detail(ErrInvalidDesign, "node %[1]q has an invalid reminder interval | 节点 %[1]q 的催办间隔非法", node.ID)
		}
	}
	node.AIPrompt = strings.TrimSpace(node.AIPrompt)
	if len(node.AIPrompt) > s.options.MaxDescriptionLen {
		return ErrInvalidDesign
	}
	return nil
}

// validateForms checks every form scope. | validateForms 校验全部表单作用域。
func (s *Service) validateForms(forms map[string][]FormField) error {
	for scope, fields := range forms {
		if scope != "start" && !nodeIDRe.MatchString(scope) {
			return errs.Detail(ErrInvalidDesign, "form scope %[1]q is invalid | 表单作用域 %[1]q 非法", scope)
		}
		if len(fields) > s.options.MaxFormFields {
			return errs.Detail(ErrLimit, "form %[1]q has %[2]d fields, limit %[3]d | 表单 %[1]q 有 %[2]d 个字段，上限 %[3]d", scope, len(fields), s.options.MaxFormFields)
		}
		seen := map[string]bool{}
		for i := range fields {
			field := &fields[i]
			field.Key = strings.TrimSpace(field.Key)
			if !fieldKeyRe.MatchString(field.Key) {
				return errs.Detail(ErrInvalidForm, "field key=%[1]q | 字段键=%[1]q", field.Key)
			}
			if seen[field.Key] {
				return errs.Detail(ErrInvalidForm, "duplicate field key %[1]q | 字段键 %[1]q 重复", field.Key)
			}
			seen[field.Key] = true
			var ok bool
			if field.Label, ok = trimLen(field.Label, s.options.MaxNameLen); !ok || field.Label == "" {
				return errs.Detail(ErrInvalidForm, "field %[1]q needs a label | 字段 %[1]q 需要标签", field.Key)
			}
			if field.LabelEN, ok = trimLen(field.LabelEN, s.options.MaxNameLen); !ok {
				return ErrInvalidForm
			}
			field.Type = strings.TrimSpace(field.Type)
			if field.Type == "" {
				field.Type = "text"
			}
			if !formTypes[field.Type] {
				return errs.Detail(ErrInvalidForm, "field %[1]q has unknown type %[2]q | 字段 %[1]q 的类型 %[2]q 未知", field.Key, field.Type)
			}
			if field.Type == "select" && len(field.Options) == 0 {
				return errs.Detail(ErrInvalidForm, "select field %[1]q has no options | 选择字段 %[1]q 没有选项", field.Key)
			}
			for j := range field.Options {
				option := &field.Options[j]
				option.Value = strings.TrimSpace(option.Value)
				if option.Value == "" || len(option.Value) > 128 {
					return errs.Detail(ErrInvalidForm, "field %[1]q has an invalid option | 字段 %[1]q 含非法选项", field.Key)
				}
				if option.Label, ok = trimLen(option.Label, s.options.MaxNameLen); !ok || option.Label == "" {
					return errs.Detail(ErrInvalidForm, "field %[1]q has an option without a label | 字段 %[1]q 的选项缺少标签", field.Key)
				}
			}
			if field.MaxLength < 0 || field.MaxLength > 10000 {
				return ErrInvalidForm
			}
			if field.Min > field.Max && field.Max != 0 {
				return errs.Detail(ErrInvalidForm, "field %[1]q has min greater than max | 字段 %[1]q 的最小值大于最大值", field.Key)
			}
			field.Pattern = strings.TrimSpace(field.Pattern)
			if field.Pattern != "" {
				if len(field.Pattern) > s.options.MaxConditionLen {
					return ErrInvalidForm
				}
				if _, err := regexpx.Compile(field.Pattern); err != nil {
					return errs.Detail(ErrInvalidForm, "field %[1]q has an invalid pattern | 字段 %[1]q 的正则非法", field.Key)
				}
			}
		}
		forms[scope] = fields
	}
	return nil
}

// validateRules checks the automatic-approval rules. | validateRules 校验自动审批规则。
func (s *Service) validateRules(rules []AutoRule) error {
	if len(rules) > s.options.MaxAutoRules {
		return errs.Detail(ErrLimit, "rule count %[1]d exceeds %[2]d | 规则数 %[1]d 超过 %[2]d", len(rules), s.options.MaxAutoRules)
	}
	seen := map[string]bool{}
	for i := range rules {
		rule := &rules[i]
		rule.ID = strings.TrimSpace(rule.ID)
		if rule.ID == "" {
			rule.ID = fmt.Sprintf("rule-%d", i+1)
		}
		if !nodeIDRe.MatchString(rule.ID) {
			return errs.Detail(ErrInvalidDesign, "rule id=%[1]q | 规则 ID=%[1]q", rule.ID)
		}
		if seen[rule.ID] {
			return errs.Detail(ErrInvalidDesign, "duplicate rule id %[1]q | 规则 ID %[1]q 重复", rule.ID)
		}
		seen[rule.ID] = true
		if rule.Event == "" {
			rule.Event = AutoEventTask
		}
		switch rule.Event {
		case AutoEventStart, AutoEventTask:
		default:
			return errs.Detail(ErrInvalidDesign, "rule %[1]q has an unknown event | 规则 %[1]q 的事件未知", rule.ID)
		}
		switch rule.Scope {
		case AutoScopeCategory, AutoScopeRole, AutoScopeUser, AutoScopeEvent, AutoScopeGroup, AutoScopeVariable:
		default:
			return errs.Detail(ErrInvalidDesign, "rule %[1]q has an unknown scope | 规则 %[1]q 的作用域未知", rule.ID)
		}
		if rule.Scope != AutoScopeVariable && len(rule.Match) == 0 {
			return errs.Detail(ErrInvalidDesign, "rule %[1]q needs match values | 规则 %[1]q 需要匹配值", rule.ID)
		}
		if rule.Scope == AutoScopeVariable {
			if strings.TrimSpace(rule.Condition) == "" {
				return errs.Detail(ErrInvalidDesign, "rule %[1]q needs a condition | 规则 %[1]q 需要条件", rule.ID)
			}
			if len(rule.Condition) > s.options.MaxConditionLen {
				return errs.Detail(ErrLimit, "rule %[1]q condition is too long | 规则 %[1]q 的条件过长", rule.ID)
			}
			if err := ValidateCondition(rule.Condition); err != nil {
				return errs.Detail(ErrInvalidCondition, "rule %[1]q: %[2]s | 规则 %[1]q：%[2]s", rule.ID, err.Error())
			}
		}
		if rule.Decision != DecisionApprove && rule.Decision != DecisionReject {
			return errs.Detail(ErrInvalidDesign, "rule %[1]q has an unknown decision | 规则 %[1]q 的决策未知", rule.ID)
		}
		if rule.UseAI && rule.Decision == "" {
			return errs.Detail(ErrInvalidDesign, "an AI rule still needs a fallback decision | AI 规则仍需要回落决策")
		}
		rule.Prompt = strings.TrimSpace(rule.Prompt)
		if len(rule.Prompt) > s.options.MaxDescriptionLen {
			return ErrInvalidDesign
		}
	}
	return nil
}

// validateSettings checks process-level runtime settings. | validateSettings 校验流程级运行设置。
func (s *Service) validateSettings(settings DesignSettings) error {
	if settings.WithdrawWindow != "" {
		d, err := time.ParseDuration(strings.TrimSpace(settings.WithdrawWindow))
		if err != nil || d < 0 {
			return errs.Detail(ErrInvalidDesign, "invalid withdraw window | 撤回窗口非法")
		}
	}
	if settings.Due != "" {
		d, err := time.ParseDuration(strings.TrimSpace(settings.Due))
		if err != nil || d < 0 {
			return errs.Detail(ErrInvalidDesign, "invalid default due | 默认期限非法")
		}
	}
	var ok bool
	if settings.Description, ok = trimLen(settings.Description, s.options.MaxDescriptionLen); !ok {
		return ErrInvalidDesign
	}
	if settings.DescriptionEN, ok = trimLen(settings.DescriptionEN, s.options.MaxDescriptionLen); !ok {
		return ErrInvalidDesign
	}
	return nil
}

// parseDurationText accepts a Go duration or a compact ISO-8601 duration such as PT30M. |
// parseDurationText 接受 Go 时长或紧凑的 ISO-8601 时长（如 PT30M）。
func parseDurationText(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, ErrInvalidDesign
	}
	if parsed, err := time.ParseDuration(raw); err == nil {
		return parsed, nil
	}
	upper := strings.ToUpper(raw)
	if !strings.HasPrefix(upper, "P") {
		return 0, ErrInvalidDesign
	}
	var total time.Duration
	number := strings.Builder{}
	datePart := !strings.Contains(upper, "T")
	for i := 1; i < len(upper); i++ {
		ch := upper[i]
		switch {
		case ch >= '0' && ch <= '9' || ch == '.':
			number.WriteByte(ch)
			continue
		case ch == 'T':
			datePart = false
			continue
		}
		value, err := strconv.ParseFloat(number.String(), 64)
		if err != nil {
			return 0, ErrInvalidDesign
		}
		number.Reset()
		switch ch {
		case 'D':
			total += time.Duration(value * float64(24*time.Hour))
		case 'H':
			total += time.Duration(value * float64(time.Hour))
		case 'M':
			if datePart {
				return 0, ErrInvalidDesign
			}
			total += time.Duration(value * float64(time.Minute))
		case 'S':
			total += time.Duration(value * float64(time.Second))
		default:
			return 0, ErrInvalidDesign
		}
	}
	if number.Len() != 0 || total < 0 {
		return 0, ErrInvalidDesign
	}
	return total, nil
}

// checksum returns the SHA-256 of the canonical design. | checksum 返回规范化设计的 SHA-256。
func checksum(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}
