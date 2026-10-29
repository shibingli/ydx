package workflow_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/shibingli/ydx/workflow"
)

// TestBPMNRoundTrip preserves the executable graph through XML. | TestBPMNRoundTrip 通过 XML
// 往返保持可执行图。
func TestBPMNRoundTrip(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	design := workflow.DefaultDesign()
	design.Nodes = []workflow.Node{
		startNode(),
		userNode("approve", "审批", workflow.Assignment{Type: workflow.AssigneeRole, Values: []string{"staff"}}, workflow.Completion{
			Mode: workflow.CompletionVote, ThresholdType: workflow.ThresholdPercent, Threshold: 60, Sequential: true, RejectMode: workflow.RejectModeAny,
		}),
		{ID: "xor", Type: workflow.NodeExclusive, Name: "判断", Position: workflow.Position{X: 420, Y: 200}},
		endNode("end"),
		endNode("reject"),
	}
	design.Edges = []workflow.Edge{
		edge("e1", "start", "approve", ""),
		edge("e2", "approve", "xor", ""),
		edge("e3", "xor", "end", "amount > 100"),
		{ID: "e4", Source: "xor", Target: "reject", Default: true},
	}
	design.Forms["start"] = []workflow.FormField{{Key: "amount", Label: "金额", Type: "number", Required: true}}
	design.Rules = []workflow.AutoRule{{ID: "r1", Enabled: true, Event: workflow.AutoEventTask, Scope: workflow.AutoScopeCategory, Match: []string{"leave"}, Decision: workflow.DecisionReject}}
	design.Settings = workflow.DesignSettings{Due: "24h", ForbidReturn: true}
	_, version := f.publishDefinition(t, "bpmn-roundtrip", design)

	for _, want := range []string{
		`xmlns:bpmndi="http://www.omg.org/spec/BPMN/20100524/DI"`,
		`xmlns:camunda="http://camunda.org/schema/1.0/bpmn"`,
		`<userTask id="approve"`,
		`camunda:candidateGroups="staff"`,
		`<multiInstanceLoopCharacteristics isSequential="true">`,
		`<conditionExpression xsi:type="tFormalExpression">${amount &gt; 100}</conditionExpression>`,
		`<bpmndi:BPMNShape id="shape_approve"`,
		`<dc:Bounds x="240" y="200"`,
	} {
		if !strings.Contains(version.BPMN, want) {
			t.Errorf("BPMN 缺少 %q:\n%s", want, version.BPMN)
		}
	}

	parsed, err := workflow.ParseBPMN(version.BPMN)
	if err != nil {
		t.Fatalf("解析 BPMN 失败: %v", err)
	}
	if parsed.Key != "bpmn-roundtrip" || len(parsed.Design.Nodes) != 5 || len(parsed.Design.Edges) != 4 {
		t.Fatalf("往返结果 = key=%s nodes=%d edges=%d", parsed.Key, len(parsed.Design.Nodes), len(parsed.Design.Edges))
	}
	node, ok := parsed.Design.FindNode("approve")
	if !ok || node.Assignee.Type != workflow.AssigneeRole || node.Assignee.Values[0] != "staff" {
		t.Fatalf("指派未往返: %+v", node)
	}
	if node.Completion.Mode != workflow.CompletionVote || node.Completion.Threshold != 60 || !node.Completion.Sequential {
		t.Fatalf("票签配置未往返: %+v", node.Completion)
	}
	if !parsed.Design.Settings.ForbidReturn || parsed.Design.Settings.Due != "24h" {
		t.Fatalf("设置未往返: %+v", parsed.Design.Settings)
	}
	var defaultEdge bool
	for _, item := range parsed.Design.Edges {
		if item.ID == "e4" && item.Default {
			defaultEdge = true
		}
		if item.ID == "e3" && item.Condition != "amount > 100" {
			t.Fatalf("条件未往返: %+v", item)
		}
	}
	if !defaultEdge {
		t.Fatalf("默认流未往返: %+v", parsed.Design.Edges)
	}
}

// TestParseCamundaStyleBPMN covers the interoperability attributes of third-party modelers. |
// TestParseCamundaStyleBPMN 覆盖第三方建模器的互操作属性。
func TestParseCamundaStyleBPMN(t *testing.T) {
	raw := `<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="http://www.omg.org/spec/BPMN/20100524/MODEL" xmlns:camunda="http://camunda.org/schema/1.0/bpmn" targetNamespace="test">
  <process id="camunda_proc" name="Camunda process">
    <startEvent id="start" name="Start"/>
    <userTask id="approve" name="Approve" camunda:candidateGroups="staff">
      <multiInstanceLoopCharacteristics isSequential="true">
        <completionCondition>${nrOfCompletedInstances/nrOfInstances >= 0.5}</completionCondition>
      </multiInstanceLoopCharacteristics>
    </userTask>
    <exclusiveGateway id="xor" name="Decide" default="toEnd"/>
    <endEvent id="end" name="End"><terminateEventDefinition/></endEvent>
    <sequenceFlow id="e1" sourceRef="start" targetRef="approve"/>
    <sequenceFlow id="e2" sourceRef="approve" targetRef="xor"/>
    <sequenceFlow id="e3" sourceRef="xor" targetRef="end" name="Big">
      <conditionExpression>${amount > 100}</conditionExpression>
    </sequenceFlow>
    <sequenceFlow id="toEnd" sourceRef="xor" targetRef="end"/>
  </process>
</definitions>`
	parsed, err := workflow.ParseBPMN(raw)
	if err != nil {
		t.Fatalf("解析 Camunda 风格 BPMN 失败: %v", err)
	}
	if parsed.Key != "camunda_proc" || parsed.Name != "Camunda process" {
		t.Fatalf("流程元信息 = %+v", parsed)
	}
	node, ok := parsed.Design.FindNode("approve")
	if !ok || node.Assignee.Type != workflow.AssigneeRole || len(node.Assignee.Values) != 1 || node.Assignee.Values[0] != "staff" {
		t.Fatalf("候选组未解析: %+v", node)
	}
	if node.Completion.Mode != workflow.CompletionVote || node.Completion.Threshold != 50 || !node.Completion.Sequential {
		t.Fatalf("多实例完成条件未解析: %+v", node.Completion)
	}
	end, _ := parsed.Design.FindNode("end")
	if !end.Terminate {
		t.Fatal("终止结束事件未解析")
	}
	var conditional, defaultFlow bool
	for _, item := range parsed.Design.Edges {
		if item.ID == "e3" && item.Condition == "amount > 100" {
			conditional = true
		}
		if item.ID == "toEnd" && item.Default {
			defaultFlow = true
		}
	}
	if !conditional || !defaultFlow {
		t.Fatalf("条件或默认流未解析: %+v", parsed.Design.Edges)
	}
}

// TestParseBPMNEvents covers timer, message and event-based gateway elements. |
// TestParseBPMNEvents 覆盖定时、消息与事件网关元素。
func TestParseBPMNEvents(t *testing.T) {
	raw := `<?xml version="1.0"?>
<definitions xmlns="http://www.omg.org/spec/BPMN/20100524/MODEL" targetNamespace="test">
  <process id="events" name="Events">
    <startEvent id="start"/>
    <eventBasedGateway id="race"/>
    <intermediateCatchEvent id="timer"><timerEventDefinition><timeDuration>PT2H</timeDuration></timerEventDefinition></intermediateCatchEvent>
    <intermediateCatchEvent id="message"><messageEventDefinition messageRef="approve-signal"/></intermediateCatchEvent>
    <endEvent id="end"/>
    <sequenceFlow id="e1" sourceRef="start" targetRef="race"/>
    <sequenceFlow id="e2" sourceRef="race" targetRef="timer"/>
    <sequenceFlow id="e3" sourceRef="race" targetRef="message"/>
    <sequenceFlow id="e4" sourceRef="timer" targetRef="end"/>
    <sequenceFlow id="e5" sourceRef="message" targetRef="end"/>
  </process>
</definitions>`
	parsed, err := workflow.ParseBPMN(raw)
	if err != nil {
		t.Fatalf("解析事件 BPMN 失败: %v", err)
	}
	timer, _ := parsed.Design.FindNode("timer")
	if timer.Type != workflow.NodeCatch || timer.WaitKind != workflow.WaitTimer || timer.WaitFor != "PT2H" {
		t.Fatalf("定时事件 = %+v", timer)
	}
	message, _ := parsed.Design.FindNode("message")
	if message.WaitKind != workflow.WaitMessage || message.MessageName != "approve-signal" {
		t.Fatalf("消息事件 = %+v", message)
	}
	race, _ := parsed.Design.FindNode("race")
	if race.Type != workflow.NodeEventGateway {
		t.Fatalf("事件网关 = %+v", race)
	}
	if _, err := workflow.ParseBPMN(parsed.Design.Nodes[0].Name); err == nil {
		t.Fatal("非 BPMN 文本应被拒绝")
	}
}

// TestParseBPMNRejectsUnsupported covers malformed and unsupported documents. |
// TestParseBPMNRejectsUnsupported 覆盖非法与不支持文档。
func TestParseBPMNRejectsUnsupported(t *testing.T) {
	cases := []string{
		"",
		"<not-bpmn/>",
		`<definitions xmlns="http://www.omg.org/spec/BPMN/20100524/MODEL"><process id="p"><subProcess id="s"/></process></definitions>`,
		`<definitions xmlns="http://www.omg.org/spec/BPMN/20100524/MODEL"><process id="p"><startEvent id="start"/></process></definitions>`,
	}
	for _, raw := range cases {
		if _, err := workflow.ParseBPMN(raw); !errors.Is(err, workflow.ErrBPMNInvalid) {
			t.Errorf("文档 %q 的错误 = %v, 期望 ErrBPMNInvalid", raw, err)
		}
	}
}

// TestBundleExportImport covers the JSON bundle lifecycle. | TestBundleExportImport 覆盖 JSON 流程包生命周期。
func TestBundleExportImport(t *testing.T) {
	source := newFixture(t)
	defer source.close()
	design := linearDesign(workflow.Assignment{Type: workflow.AssigneeInitiator}, workflow.Completion{Mode: workflow.CompletionAny})
	source.publishDefinition(t, "bundle", design)
	bundle, err := source.svc.ExportBundle(context.Background(), source.tenant, []string{"bundle"})
	if err != nil {
		t.Fatalf("导出流程包失败: %v", err)
	}
	if len(bundle.Definitions) != 1 || len(bundle.Definitions[0].Versions) != 1 {
		t.Fatalf("流程包内容 = %+v", bundle)
	}

	target := newFixture(t)
	defer target.close()
	report, err := target.svc.ImportBundle(context.Background(), target.tenant, "boss", bundle)
	if err != nil {
		t.Fatalf("导入流程包失败: %v", err)
	}
	if report.Created != 1 || report.Definitions != 1 {
		t.Fatalf("导入报告 = %+v", report)
	}
	def, err := target.svc.GetDefinitionByKey(context.Background(), target.tenant, "bundle")
	if err != nil {
		t.Fatalf("导入后读取定义失败: %v", err)
	}
	if def.CurrentVersion != 1 || def.Status != workflow.DefinitionPublished {
		t.Fatalf("导入后定义 = %+v", def)
	}
	inst := target.start(t, "bundle", nil)
	if inst.Status != workflow.InstanceRunning {
		t.Fatalf("导入定义发起状态 = %s", inst.Status)
	}
	second, err := target.svc.ImportBundle(context.Background(), target.tenant, "boss", bundle)
	if err != nil {
		t.Fatalf("重复导入失败: %v", err)
	}
	if second.Skipped != 1 || second.Created != 0 {
		t.Fatalf("重复导入报告 = %+v", second)
	}

	changed := bundle
	changed.Definitions[0].Versions[0].Design.Nodes[1].Name = "被篡改的已发布节点"
	if _, err := target.svc.ImportBundle(context.Background(), target.tenant, "boss", changed); !errors.Is(err, workflow.ErrConflict) {
		t.Fatalf("篡改已发布版本的错误 = %v, 期望 ErrConflict", err)
	}
}

// TestImportBPMNCreatesDraft covers direct BPMN import. | TestImportBPMNCreatesDraft 覆盖直接导入 BPMN。
func TestImportBPMNCreatesDraft(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	process, err := workflow.ParseBPMN(`<definitions xmlns="http://www.omg.org/spec/BPMN/20100524/MODEL" xmlns:camunda="http://camunda.org/schema/1.0/bpmn"><process id="imported" name="Imported"><startEvent id="start"/><userTask id="task" name="Task" camunda:assignee="u1"/><endEvent id="end"/><sequenceFlow id="e1" sourceRef="start" targetRef="task"/><sequenceFlow id="e2" sourceRef="task" targetRef="end"/></process></definitions>`)
	if err != nil {
		t.Fatalf("解析内置 BPMN 失败: %v", err)
	}
	def, version, err := f.svc.ImportBPMN(context.Background(), f.tenant, "boss", process)
	if err != nil {
		t.Fatalf("导入 BPMN 失败: %v", err)
	}
	if def.Key != "imported" || version.Status != workflow.VersionDraft || version.BPMN == "" {
		t.Fatalf("导入结果 = def=%+v version=%+v", def, version)
	}
	if _, err := f.svc.PublishVersion(context.Background(), f.tenant, version.ID, "boss", "导入发布"); err != nil {
		t.Fatalf("发布导入版本失败: %v", err)
	}
	inst := f.start(t, "imported", nil)
	if len(f.openTasks(t, inst.ID)) != 1 {
		t.Fatalf("导入流程发起后任务 = %d", len(f.openTasks(t, inst.ID)))
	}
}
