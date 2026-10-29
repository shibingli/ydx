package workflow

import (
	"bytes"
	"encoding/xml"
	"strconv"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// BPMN namespace constants. | BPMN 命名空间常量。
const (
	// bpmnNamespace is the BPMN 2.0 model namespace. | bpmnNamespace 是 BPMN 2.0 模型命名空间。
	bpmnNamespace = "http://www.omg.org/spec/BPMN/20100524/MODEL"
	// bpmnDINamespace is the BPMN diagram-interchange namespace. | bpmnDINamespace 是 BPMN 图形交换命名空间。
	bpmnDINamespace = "http://www.omg.org/spec/BPMN/20100524/DI"
	// dcNamespace is the diagram-common namespace. | dcNamespace 是图形通用命名空间。
	dcNamespace = "http://www.omg.org/spec/DD/20100524/DC"
	// diNamespace is the diagram-interchange namespace. | diNamespace 是图形交换命名空间。
	diNamespace = "http://www.omg.org/spec/DD/20100524/DI"
	// camundaNamespace is the Camunda extension namespace accepted on import. | camundaNamespace
	// 是导入时接受的 Camunda 扩展命名空间。
	camundaNamespace = "http://camunda.org/schema/1.0/bpmn"
	// ydNamespace is the YD extension namespace carrying the lossless JSON config. | ydNamespace
	// 是携带无损 JSON 配置的 YD 扩展命名空间。
	ydNamespace = "https://yun-dev.cn/bpmn"
	// bpmnTargetNamespace is the target namespace every exported document declares. | bpmnTargetNamespace
	// 是每个导出文档声明的目标命名空间。
	bpmnTargetNamespace = "https://yun-dev.cn/bpmn/definitions"
)

// nodeExtension is the lossless YD payload stored under extensionElements. | nodeExtension
// 是存储在 extensionElements 下的无损 YD 载荷。
type nodeExtension struct {
	// Node is the complete domain node, including every YD-specific setting. | Node 是完整领域节点，
	// 含全部 YD 专有配置。
	Node Node `json:"node"`
}

// processExtension carries process-level forms, rules and settings. | processExtension 承载流程级表单、规则与设置。
type processExtension struct {
	// Forms maps a scope to its fields. | Forms 把作用域映射到字段。
	Forms map[string][]FormField `json:"forms,omitempty"`
	// Settings are the runtime settings. | Settings 是运行期设置。
	Settings DesignSettings `json:"settings,omitempty"`
	// Rules are the automatic-approval rules. | Rules 是自动审批规则。
	Rules []AutoRule `json:"rules,omitempty"`
	// SchemaVersion is the design schema version. | SchemaVersion 是设计 schema 版本。
	SchemaVersion int `json:"schema_version,omitempty"`
}

// BuildBPMN renders one design as a BPMN 2.0 XML document with BPMN DI. | BuildBPMN 把设计渲染为
// 带 BPMN DI 的 BPMN 2.0 XML 文档。
func BuildBPMN(def Definition, version int, design Design) (string, error) {
	var out bytes.Buffer
	out.WriteString(xml.Header)
	out.WriteString(`<definitions xmlns="` + bpmnNamespace + `"`)
	out.WriteString(` xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"`)
	out.WriteString(` xmlns:bpmndi="` + bpmnDINamespace + `"`)
	out.WriteString(` xmlns:dc="` + dcNamespace + `"`)
	out.WriteString(` xmlns:di="` + diNamespace + `"`)
	out.WriteString(` xmlns:camunda="` + camundaNamespace + `"`)
	out.WriteString(` xmlns:yd="` + ydNamespace + `"`)
	out.WriteString(` targetNamespace="` + bpmnTargetNamespace + `"`)
	out.WriteString(` id="definitions_` + xmlAttr(def.Key) + `">`)
	out.WriteString(`<process id="` + xmlAttr(def.Key) + `" name="` + xmlAttr(def.Name) + `" isExecutable="true">`)
	if def.Description != "" {
		out.WriteString(`<documentation>` + xmlText(def.Description) + `</documentation>`)
	}
	out.WriteString(`<extensionElements><yd:config>` + xmlText(mustJSON(processExtension{
		Forms:         design.Forms,
		Rules:         design.Rules,
		Settings:      design.Settings,
		SchemaVersion: design.SchemaVersion,
	})) + `</yd:config></extensionElements>`)

	for _, node := range design.Nodes {
		if err := writeBPMNNode(&out, node, design); err != nil {
			return "", err
		}
	}
	for _, edge := range design.Edges {
		out.WriteString(`<sequenceFlow id="` + xmlAttr(edge.ID) + `" sourceRef="` + xmlAttr(edge.Source) +
			`" targetRef="` + xmlAttr(edge.Target) + `"`)
		if edge.Name != "" {
			out.WriteString(` name="` + xmlAttr(edge.Name) + `"`)
		}
		out.WriteString(`>`)
		if edge.Condition != "" {
			out.WriteString(`<conditionExpression xsi:type="tFormalExpression">` + xmlText("${"+edge.Condition+"}") + `</conditionExpression>`)
		}
		out.WriteString(`</sequenceFlow>`)
	}

	out.WriteString(`</process>`)
	writeBPMNDiagram(&out, def, design)
	out.WriteString(`</definitions>`)
	if !utf8Valid(out.String()) {
		return "", errs.Detail(ErrBPMNInvalid, "generated BPMN is not valid UTF-8 | 生成的 BPMN 不是合法 UTF-8")
	}
	return out.String(), nil
}

// writeBPMNNode renders one node in its standard BPMN element. | writeBPMNNode 用标准 BPMN 元素渲染一个节点。
func writeBPMNNode(out *bytes.Buffer, node Node, design Design) error {
	tag := ""
	switch node.Type {
	case NodeStart:
		tag = "startEvent"
	case NodeEnd:
		tag = "endEvent"
	case NodeUserTask:
		tag = "userTask"
	case NodeServiceTask:
		tag = "serviceTask"
	case NodeExclusive:
		tag = "exclusiveGateway"
	case NodeParallel:
		tag = "parallelGateway"
	case NodeInclusive:
		tag = "inclusiveGateway"
	case NodeCatch:
		tag = "intermediateCatchEvent"
	case NodeEventGateway:
		tag = "eventBasedGateway"
	default:
		return errs.Detail(ErrBPMNInvalid, "unsupported node type %[1]q | 不支持的节点类型 %[1]q", node.Type)
	}
	out.WriteString(`<` + tag + ` id="` + xmlAttr(node.ID) + `" name="` + xmlAttr(node.Name) + `"`)
	if node.Type == NodeUserTask {
		writeCamundaAssignment(out, node.Assignee)
	}
	if node.Type == NodeExclusive {
		for _, edge := range design.Outgoing(node.ID) {
			if edge.Default {
				out.WriteString(` default="` + xmlAttr(edge.ID) + `"`)
				break
			}
		}
	}
	out.WriteString(`>`)
	out.WriteString(`<extensionElements><yd:config>` + xmlText(mustJSON(nodeExtension{Node: node})) + `</yd:config></extensionElements>`)
	if node.Type == NodeEnd && node.Terminate {
		out.WriteString(`<terminateEventDefinition/>`)
	}
	if node.Type == NodeCatch {
		switch node.WaitKind {
		case WaitTimer:
			out.WriteString(`<timerEventDefinition><timeDuration>` + xmlText(toISODuration(node.WaitFor)) + `</timeDuration></timerEventDefinition>`)
		case WaitMessage:
			out.WriteString(`<messageEventDefinition messageRef="` + xmlAttr(node.MessageName) + `"/>`)
		}
	}
	if node.Type == NodeUserTask {
		if node.Completion.Mode == CompletionAll || node.Completion.Mode == CompletionVote || node.Completion.Sequential {
			out.WriteString(`<multiInstanceLoopCharacteristics isSequential="` + boolText(node.Completion.Sequential) + `">`)
			if node.Completion.Mode == CompletionVote {
				out.WriteString(`<completionCondition xsi:type="tFormalExpression">` + xmlText(bpmnVoteCondition(node.Completion)) + `</completionCondition>`)
			}
			out.WriteString(`</multiInstanceLoopCharacteristics>`)
		}
		// Camunda-compatible multi-instance assignment hints. | 与 Camunda 兼容的多实例指派提示。
		if len(node.Assignee.Values) > 0 && node.Assignee.Type == AssigneeUser {
			out.WriteString(`<potentialOwner><resourceAssignmentExpression><formalExpression>` +
				xmlText(strings.Join(node.Assignee.Values, ",")) +
				`</formalExpression></resourceAssignmentExpression></potentialOwner>`)
		}
	}
	out.WriteString(`</` + tag + `>`)
	return nil
}

// writeCamundaAssignment writes the compatibility attributes tools such as Camunda Modeler read. |
// writeCamundaAssignment 写出 Camunda Modeler 等工具读取的兼容属性。
func writeCamundaAssignment(out *bytes.Buffer, assignment Assignment) {
	switch assignment.Type {
	case AssigneeInitiator:
		out.WriteString(` camunda:assignee="${initiator}"`)
	case AssigneeUser:
		if len(assignment.Values) == 1 {
			out.WriteString(` camunda:assignee="` + xmlAttr(assignment.Values[0]) + `"`)
		} else if len(assignment.Values) > 1 {
			out.WriteString(` camunda:candidateUsers="` + xmlAttr(strings.Join(assignment.Values, ",")) + `"`)
		}
	case AssigneeRole:
		out.WriteString(` camunda:candidateGroups="` + xmlAttr(strings.Join(assignment.Values, ",")) + `"`)
	}
}

// toISODuration renders a Go duration as ISO-8601, which is what BPMN timeDuration expects. |
// toISODuration 把 Go 时长渲染为 BPMN timeDuration 期望的 ISO-8601 形式。
func toISODuration(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(strings.ToUpper(raw), "P") {
		return raw
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return raw
	}
	remaining := d
	days := remaining / (24 * time.Hour)
	remaining -= days * 24 * time.Hour
	hours := remaining / time.Hour
	remaining -= hours * time.Hour
	minutes := remaining / time.Minute
	remaining -= minutes * time.Minute
	seconds := remaining / time.Second
	var b strings.Builder
	b.WriteString("P")
	if days > 0 {
		b.WriteString(strconv.FormatInt(int64(days), 10))
		b.WriteString("D")
	}
	if hours > 0 || minutes > 0 || seconds > 0 || days == 0 {
		b.WriteString("T")
		if hours > 0 {
			b.WriteString(strconv.FormatInt(int64(hours), 10))
			b.WriteString("H")
		}
		if minutes > 0 {
			b.WriteString(strconv.FormatInt(int64(minutes), 10))
			b.WriteString("M")
		}
		if seconds > 0 || (hours == 0 && minutes == 0) {
			b.WriteString(strconv.FormatInt(int64(seconds), 10))
			b.WriteString("S")
		}
	}
	return b.String()
}

// bpmnVoteCondition renders the standard completion condition for a vote node. | bpmnVoteCondition
// 渲染票签节点的标准完成条件。
func bpmnVoteCondition(completion Completion) string {
	if completion.ThresholdType == ThresholdPercent {
		ratio := completion.Threshold / 100
		return "${nrOfCompletedInstances/nrOfInstances >= " + strconv.FormatFloat(ratio, 'f', -1, 64) + "}"
	}
	if completion.Threshold < 1 {
		return "${nrOfCompletedInstances >= 1}"
	}
	return "${nrOfCompletedInstances >= " + strconv.Itoa(int(completion.Threshold)) + "}"
}

// writeBPMNDiagram renders the diagram interchange section. | writeBPMNDiagram 渲染图形交换部分。
func writeBPMNDiagram(out *bytes.Buffer, def Definition, design Design) {
	out.WriteString(`<bpmndi:BPMNDiagram id="diagram_` + xmlAttr(def.Key) + `">`)
	out.WriteString(`<bpmndi:BPMNPlane id="plane_` + xmlAttr(def.Key) + `" bpmnElement="` + xmlAttr(def.Key) + `">`)
	for _, node := range design.Nodes {
		w, h := bpmnShapeSize(node.Type)
		out.WriteString(`<bpmndi:BPMNShape id="shape_` + xmlAttr(node.ID) + `" bpmnElement="` + xmlAttr(node.ID) + `">`)
		out.WriteString(`<dc:Bounds x="` + formatFloat(node.Position.X) + `" y="` + formatFloat(node.Position.Y) +
			`" width="` + formatFloat(w) + `" height="` + formatFloat(h) + `"/>`)
		out.WriteString(`</bpmndi:BPMNShape>`)
	}
	positions := make(map[string]Position, len(design.Nodes))
	for _, node := range design.Nodes {
		positions[node.ID] = node.Position
	}
	for _, edge := range design.Edges {
		source, sok := positions[edge.Source]
		target, tok := positions[edge.Target]
		if !sok || !tok {
			continue
		}
		sw, sh := bpmnShapeSize(nodeTypeOf(design, edge.Source))
		tw, th := bpmnShapeSize(nodeTypeOf(design, edge.Target))
		out.WriteString(`<bpmndi:BPMNEdge id="edge_` + xmlAttr(edge.ID) + `" bpmnElement="` + xmlAttr(edge.ID) + `">`)
		out.WriteString(`<di:waypoint x="` + formatFloat(source.X+sw/2) + `" y="` + formatFloat(source.Y+sh/2) + `"/>`)
		out.WriteString(`<di:waypoint x="` + formatFloat(target.X+tw/2) + `" y="` + formatFloat(target.Y+th/2) + `"/>`)
		out.WriteString(`</bpmndi:BPMNEdge>`)
	}
	out.WriteString(`</bpmndi:BPMNPlane></bpmndi:BPMNDiagram>`)
}

// nodeTypeOf returns the type of one node or an empty string when absent. | nodeTypeOf 返回节点类型，缺失时返回空串。
func nodeTypeOf(design Design, id string) string {
	if node, ok := design.FindNode(id); ok {
		return node.Type
	}
	return ""
}

// bpmnShapeSize returns the default shape size of one node type. | bpmnShapeSize 返回节点类型的默认图形尺寸。
func bpmnShapeSize(nodeType string) (float64, float64) {
	switch nodeType {
	case NodeStart, NodeEnd:
		return 36, 36
	case NodeExclusive, NodeParallel, NodeInclusive:
		return 50, 50
	default:
		return 140, 72
	}
}

// mustJSON marshals a value and returns "{}" on the impossible failure path. | mustJSON 编组值，失败时返回 "{}"。
func mustJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(data)
}

// xmlText escapes text for an XML text node. | xmlText 为 XML 文本节点转义。
func xmlText(value string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(value))
	return b.String()
}

// xmlAttr escapes a value for an XML attribute. | xmlAttr 为 XML 属性转义。
func xmlAttr(value string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(value))
	return b.String()
}

// boolText renders a bool as an XML boolean. | boolText 把布尔值渲染为 XML 布尔值。
func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

// formatFloat renders a coordinate without a trailing zero. | formatFloat 渲染坐标，去掉多余的零。
func formatFloat(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}

// utf8Valid reports whether s is valid UTF-8. | utf8Valid 报告 s 是否为合法 UTF-8。
func utf8Valid(s string) bool {
	for _, r := range s {
		if r == '�' {
			return false
		}
	}
	return true
}
