package workflow

import (
	"encoding/xml"
	"io"
	"strconv"
	"strings"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/regexpx"
)

// BPMNProcess is one imported BPMN process. | BPMNProcess 是一个导入的 BPMN 流程。
type BPMNProcess struct {
	// Key is the process id. | Key 是流程 ID。
	Key string
	// Name is the process name. | Name 是流程名称。
	Name string
	// Description is the process documentation. | Description 是流程说明。
	Description string
	// Design is the validated graph. | Design 是校验后的图。
	Design Design
}

// bpmnElement is a namespace-tolerant XML element tree. | bpmnElement 是与命名空间无关的 XML 元素树。
type bpmnElement struct {
	// Name is the qualified element name. | Name 是限定元素名。
	Name xml.Name
	// Text is the concatenated character data. | Text 是拼接后的字符数据。
	Text string
	// Attrs are the element attributes. | Attrs 是元素属性。
	Attrs []xml.Attr
	// Children are the nested elements. | Children 是嵌套元素。
	Children []bpmnElement
}

// UnmarshalXML decodes one element and its whole subtree. | UnmarshalXML 解码一个元素及其整棵子树。
func (e *bpmnElement) UnmarshalXML(dec *xml.Decoder, start xml.StartElement) error {
	e.Name = start.Name
	e.Attrs = start.Attr
	for {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		switch t := token.(type) {
		case xml.StartElement:
			child := bpmnElement{}
			if err := dec.DecodeElement(&child, &t); err != nil {
				return err
			}
			e.Children = append(e.Children, child)
		case xml.CharData:
			e.Text += string(t)
		case xml.EndElement:
			return nil
		}
	}
}

// local returns the element local name. | local 返回元素本地名。
func (e bpmnElement) local() string { return normalizeLocal(e.Name.Local) }

// normalizeLocal strips any colon prefix left on an unresolved name. | normalizeLocal 去掉未解析名称上残留的冒号前缀。
func normalizeLocal(name string) string {
	if i := strings.LastIndexByte(name, ':'); i >= 0 {
		return name[i+1:]
	}
	return name
}

// attr returns the first attribute with the given local name. | attr 返回指定本地名的首个属性。
func (e bpmnElement) attr(name string) string {
	for _, attr := range e.Attrs {
		if normalizeLocal(attr.Name.Local) == name {
			return attr.Value
		}
	}
	return ""
}

// child returns the first child with the given local name. | child 返回指定本地名的首个子元素。
func (e bpmnElement) child(name string) (bpmnElement, bool) {
	for _, child := range e.Children {
		if child.local() == name {
			return child, true
		}
	}
	return bpmnElement{}, false
}

// children returns every child with the given local name. | children 返回指定本地名的全部子元素。
func (e bpmnElement) children(name string) []bpmnElement {
	out := make([]bpmnElement, 0, 2)
	for _, child := range e.Children {
		if child.local() == name {
			out = append(out, child)
		}
	}
	return out
}

// ParseBPMN parses and validates a BPMN 2.0 XML document. | ParseBPMN 解析并校验 BPMN 2.0 XML 文档。
func ParseBPMN(raw string) (BPMNProcess, error) {
	if strings.TrimSpace(raw) == "" {
		return BPMNProcess{}, ErrBPMNInvalid
	}
	decoder := xml.NewDecoder(strings.NewReader(raw))
	root := bpmnElement{}
	if err := decoder.Decode(&root); err != nil {
		return BPMNProcess{}, errs.Detail(ErrBPMNInvalid, "xml: %[1]s | XML：%[1]s", err.Error())
	}
	if root.local() != "definitions" {
		return BPMNProcess{}, errs.Detail(ErrBPMNInvalid, "root element is %[1]q | 根元素是 %[1]q", root.local())
	}
	process, ok := root.child("process")
	if !ok {
		return BPMNProcess{}, errs.Detail(ErrBPMNInvalid, "the document has no process | 文档没有 process")
	}
	result := BPMNProcess{
		Key:  strings.TrimSpace(process.attr("id")),
		Name: strings.TrimSpace(process.attr("name")),
	}
	if result.Name == "" {
		result.Name = result.Key
	}
	if documentation, ok := process.child("documentation"); ok {
		result.Description = strings.TrimSpace(documentation.Text)
	}
	design := DefaultDesign()
	if ext, ok := process.child("extensionElements"); ok {
		if cfg, ok := ext.child("config"); ok && strings.TrimSpace(cfg.Text) != "" {
			parsed := processExtension{}
			if err := json.Unmarshal([]byte(strings.TrimSpace(cfg.Text)), &parsed); err != nil {
				return BPMNProcess{}, errs.Detail(ErrBPMNInvalid, "process extension is not JSON | 流程扩展不是 JSON")
			}
			if parsed.Forms != nil {
				design.Forms = parsed.Forms
			}
			design.Rules = parsed.Rules
			design.Settings = parsed.Settings
			if parsed.SchemaVersion > 0 {
				design.SchemaVersion = parsed.SchemaVersion
			}
		}
	}

	positions := parseBPMNPositions(root)
	defaults := map[string]string{}
	edgeIndex := 0
	for _, element := range process.Children {
		switch element.local() {
		case "sequenceFlow":
			edge := Edge{
				ID:     strings.TrimSpace(element.attr("id")),
				Source: strings.TrimSpace(element.attr("sourceRef")),
				Target: strings.TrimSpace(element.attr("targetRef")),
				Name:   strings.TrimSpace(element.attr("name")),
				Sort:   edgeIndex,
			}
			edgeIndex++
			if condition, ok := element.child("conditionExpression"); ok {
				edge.Condition = stripBPMNExpression(condition.Text)
			}
			design.Edges = append(design.Edges, edge)
		case "startEvent", "endEvent", "userTask", "serviceTask", "exclusiveGateway", "parallelGateway", "inclusiveGateway",
			"intermediateCatchEvent", "eventBasedGateway",
			"task", "manualTask", "receiveTask", "sendTask", "scriptTask", "businessRuleTask":
			node, sourceID, err := parseBPMNNode(element)
			if err != nil {
				return BPMNProcess{}, err
			}
			if sourceID != "" {
				defaults[sourceID] = element.attr("default")
			}
			design.Nodes = append(design.Nodes, node)
		case "extensionElements", "documentation", "laneSet", "dataObject", "dataObjectReference", "textAnnotation", "association":
			// Non-executable metadata is preserved by the extension payload or ignored. |
			// 非可执行元数据由扩展载荷保留或忽略。
			continue
		default:
			return BPMNProcess{}, errs.Detail(ErrBPMNInvalid, "unsupported process element %[1]q | 不支持的流程元素 %[1]q", element.local())
		}
	}
	for i := range design.Edges {
		if sourceID := design.Edges[i].Source; sourceID != "" {
			if flow := defaults[sourceID]; flow != "" && flow == design.Edges[i].ID {
				design.Edges[i].Default = true
			}
		}
	}
	assignMissingPositions(design.Nodes, positions)
	for i := range design.Nodes {
		if pos, ok := positions[design.Nodes[i].ID]; ok {
			design.Nodes[i].Position = pos
		}
	}
	service := &Service{options: DefaultOptions().normalize()}
	normalized, _, err := service.normalizeDesign(design)
	if err != nil {
		return BPMNProcess{}, errs.Wrap(err, ErrBPMNInvalid)
	}
	result.Design = normalized
	return result, nil
}

// parseBPMNNode converts one standard element into a domain node. | parseBPMNNode 把一个标准元素转换为领域节点。
func parseBPMNNode(element bpmnElement) (Node, string, error) {
	local := element.local()
	nodeType := ""
	switch local {
	case "startEvent":
		nodeType = NodeStart
	case "endEvent":
		nodeType = NodeEnd
	case "userTask", "task", "manualTask", "receiveTask":
		nodeType = NodeUserTask
	case "serviceTask", "sendTask", "scriptTask", "businessRuleTask":
		nodeType = NodeServiceTask
	case "exclusiveGateway":
		nodeType = NodeExclusive
	case "parallelGateway":
		nodeType = NodeParallel
	case "inclusiveGateway":
		nodeType = NodeInclusive
	case "intermediateCatchEvent":
		nodeType = NodeCatch
	case "eventBasedGateway":
		nodeType = NodeEventGateway
	}
	node := Node{
		ID:         strings.TrimSpace(element.attr("id")),
		Type:       nodeType,
		Name:       strings.TrimSpace(element.attr("name")),
		Position:   Position{X: 0, Y: 0},
		Assignee:   Assignment{Type: AssigneeInitiator, Claim: ClaimAssigned},
		Completion: Completion{Mode: CompletionAny},
	}
	if node.Name == "" {
		node.Name = node.ID
	}
	if node.Type == NodeEnd {
		if _, ok := element.child("terminateEventDefinition"); ok {
			node.Terminate = true
		}
	}
	if node.Type == NodeCatch {
		if timer, ok := element.child("timerEventDefinition"); ok {
			node.WaitKind = WaitTimer
			if duration, ok := timer.child("timeDuration"); ok {
				node.WaitFor = strings.TrimSpace(duration.Text)
			}
		} else if message, ok := element.child("messageEventDefinition"); ok {
			node.WaitKind = WaitMessage
			node.MessageName = strings.TrimSpace(message.attr("messageRef"))
			if node.MessageName == "" {
				node.MessageName = strings.TrimSpace(message.attr("name"))
			}
		}
	}
	preservedExtension := false
	if ext, ok := element.child("extensionElements"); ok {
		if cfg, ok := ext.child("config"); ok && strings.TrimSpace(cfg.Text) != "" {
			parsed := nodeExtension{}
			if err := json.Unmarshal([]byte(strings.TrimSpace(cfg.Text)), &parsed); err == nil && parsed.Node.ID != "" {
				preserved := parsed.Node
				preserved.ID = node.ID
				preserved.Type = node.Type
				if node.Name != node.ID {
					preserved.Name = node.Name
				}
				if node.Terminate {
					preserved.Terminate = true
				}
				node = preserved
				preservedExtension = true
			}
		}
	}
	if node.Type == NodeUserTask && !preservedExtension {
		if assignee := strings.TrimSpace(element.attr("assignee")); assignee != "" {
			if strings.Contains(assignee, "initiator") {
				node.Assignee = Assignment{Type: AssigneeInitiator, Claim: ClaimAssigned}
			} else {
				node.Assignee = Assignment{Type: AssigneeUser, Values: []string{assignee}, Claim: ClaimAssigned}
			}
		}
		if users := strings.TrimSpace(element.attr("candidateUsers")); users != "" {
			node.Assignee = Assignment{Type: AssigneeUser, Values: splitList(users), Claim: ClaimAssigned}
		}
		if groups := strings.TrimSpace(element.attr("candidateGroups")); groups != "" {
			node.Assignee = Assignment{Type: AssigneeRole, Values: splitList(groups), Claim: ClaimAssigned}
		}
		if potential, ok := element.child("potentialOwner"); ok {
			if expression, ok := potential.child("resourceAssignmentExpression"); ok {
				if formal, ok := expression.child("formalExpression"); ok {
					values := splitList(formal.Text)
					if len(values) > 0 && node.Assignee.Type == AssigneeInitiator {
						node.Assignee = Assignment{Type: AssigneeUser, Values: values, Claim: ClaimAssigned}
					}
				}
			}
		}
	}
	if node.Type == NodeUserTask {
		if mi, ok := element.child("multiInstanceLoopCharacteristics"); ok && !preservedExtension {
			node.Completion.Sequential = strings.EqualFold(mi.attr("isSequential"), "true")
			node.Completion.Mode = CompletionAll
			if condition, ok := mi.child("completionCondition"); ok {
				if completion, matched := parseVoteCondition(condition.Text); matched {
					node.Completion = completion
					node.Completion.Sequential = strings.EqualFold(mi.attr("isSequential"), "true")
				}
			}
		}
	}
	return node, node.ID, nil
}

// parseVoteCondition recognises the standard completion conditions BPMN tools emit. |
// parseVoteCondition 识别 BPMN 工具输出的标准完成条件。
func parseVoteCondition(raw string) (Completion, bool) {
	text := stripBPMNExpression(raw)
	text = strings.ReplaceAll(text, " ", "")
	countRe := regexpx.MustCompile(`^nrOfCompletedInstances(?:>=|==|>)([0-9]+)$`)
	if match := countRe.FindStringSubmatch(text); match != nil {
		count, err := strconv.ParseFloat(match[1], 64)
		if err != nil {
			return Completion{}, false
		}
		return Completion{Mode: CompletionVote, ThresholdType: ThresholdCount, Threshold: count, RejectMode: RejectModeAny}, true
	}
	percentRe := regexpx.MustCompile(`^nrOfCompletedInstances/nrOfInstances(?:>=|==|>)([0-9.]+)$`)
	if match := percentRe.FindStringSubmatch(text); match != nil {
		ratio, err := strconv.ParseFloat(match[1], 64)
		if err != nil {
			return Completion{}, false
		}
		percent := ratio * 100
		if percent <= 1 {
			percent = ratio
		}
		return Completion{Mode: CompletionVote, ThresholdType: ThresholdPercent, Threshold: percent, RejectMode: RejectModeAny}, true
	}
	return Completion{}, false
}

// stripBPMNExpression removes the ${...} or #{...} wrapper of a formal expression. |
// stripBPMNExpression 去掉形式表达式的 ${...} 或 #{...} 包装。
func stripBPMNExpression(raw string) string {
	raw = strings.TrimSpace(raw)
	for _, prefix := range []string{"${", "#{"} {
		if strings.HasPrefix(raw, prefix) && strings.HasSuffix(raw, "}") {
			return strings.TrimSpace(raw[len(prefix) : len(raw)-1])
		}
	}
	return raw
}

// splitList splits a comma-separated BPMN list. | splitList 切分逗号分隔的 BPMN 列表。
func splitList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			out = append(out, value)
		}
	}
	return out
}

// parseBPMNPositions extracts BPMNShape bounds. | parseBPMNPositions 提取 BPMNShape 的边界。
func parseBPMNPositions(root bpmnElement) map[string]Position {
	out := map[string]Position{}
	for _, diagram := range root.children("BPMNDiagram") {
		for _, plane := range diagram.children("BPMNPlane") {
			for _, shape := range plane.children("BPMNShape") {
				id := strings.TrimSpace(shape.attr("bpmnElement"))
				if id == "" {
					continue
				}
				bounds, ok := shape.child("Bounds")
				if !ok {
					continue
				}
				x, errX := strconv.ParseFloat(bounds.attr("x"), 64)
				y, errY := strconv.ParseFloat(bounds.attr("y"), 64)
				if errX == nil && errY == nil {
					out[id] = Position{X: x, Y: y}
				}
			}
		}
	}
	return out
}

// assignMissingPositions lays out nodes without a diagram position on a grid. |
// assignMissingPositions 为没有图形坐标的节点按网格排布。
func assignMissingPositions(nodes []Node, positions map[string]Position) {
	missing := make([]int, 0, len(nodes))
	for i := range nodes {
		if _, ok := positions[nodes[i].ID]; !ok {
			missing = append(missing, i)
		}
	}
	for order, index := range missing {
		nodes[index].Position = Position{
			X: 80 + float64(order%4)*220,
			Y: 80 + float64(order/4)*140,
		}
	}
}

// readAllBPMN reads a bounded BPMN document from r. | readAllBPMN 从 r 读取有上限的 BPMN 文档。
func readAllBPMN(r io.Reader, limit int) ([]byte, error) {
	if limit <= 0 {
		limit = DefaultOptions().MaxImportBytes
	}
	data, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, errs.Wrap(err, ErrBPMNInvalid)
	}
	if len(data) > limit {
		return nil, errs.Detail(ErrLimit, "BPMN document exceeds %[1]d bytes | BPMN 文档超过 %[1]d 字节", limit)
	}
	return data, nil
}
