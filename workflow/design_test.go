package workflow_test

import (
	"context"
	"errors"
	"testing"

	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/workflow"
)

// createDefinition creates one draft definition for design validation. | createDefinition 为设计校验创建一个草稿定义。
func createDefinition(t *testing.T, f *fixture, key string) workflow.Definition {
	t.Helper()
	def, err := f.svc.CreateDefinition(context.Background(), f.tenant, "boss", workflow.DefinitionInput{Key: key, Name: key})
	if err != nil {
		t.Fatalf("创建定义失败: %v", err)
	}
	return def
}

// TestDesignValidationRejectsBrokenGraphs covers graph and configuration validation. |
// TestDesignValidationRejectsBrokenGraphs 覆盖图与配置校验。
func TestDesignValidationRejectsBrokenGraphs(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	def := createDefinition(t, f, "validate")

	base := func() workflow.Design {
		return linearDesign(workflow.Assignment{Type: workflow.AssigneeInitiator}, workflow.Completion{Mode: workflow.CompletionAny})
	}
	cases := []struct {
		name   string
		mutate func(*workflow.Design)
	}{
		{"no-nodes", func(d *workflow.Design) { d.Nodes = nil; d.Edges = nil }},
		{"no-start", func(d *workflow.Design) {
			d.Nodes = []workflow.Node{d.Nodes[1], d.Nodes[2]}
			d.Edges = []workflow.Edge{edge("e2", "approve", "end", "")}
		}},
		{"two-starts", func(d *workflow.Design) {
			d.Nodes = append(d.Nodes, workflow.Node{ID: "start2", Type: workflow.NodeStart, Name: "另一个开始"})
		}},
		{"no-end", func(d *workflow.Design) {
			d.Nodes = []workflow.Node{d.Nodes[0], d.Nodes[1]}
			d.Edges = []workflow.Edge{edge("e1", "start", "approve", "")}
		}},
		{"unreachable", func(d *workflow.Design) {
			d.Nodes = append(d.Nodes, workflow.Node{ID: "island", Type: workflow.NodeServiceTask, Name: "孤岛"})
			d.Edges = append(d.Edges, edge("e3", "island", "end", ""))
		}},
		{"dangling-edge", func(d *workflow.Design) {
			d.Edges = append(d.Edges, edge("e3", "approve", "missing", ""))
		}},
		{"self-loop", func(d *workflow.Design) {
			d.Edges = append(d.Edges, edge("e3", "approve", "approve", ""))
		}},
		{"duplicate-node", func(d *workflow.Design) {
			d.Nodes = append(d.Nodes, d.Nodes[1])
		}},
		{"unknown-type", func(d *workflow.Design) {
			d.Nodes[1].Type = "magic"
		}},
		{"user-without-assignee", func(d *workflow.Design) {
			d.Nodes[1].Assignee = workflow.Assignment{Type: workflow.AssigneeUser}
		}},
		{"bad-vote-threshold", func(d *workflow.Design) {
			d.Nodes[1].Completion = workflow.Completion{Mode: workflow.CompletionVote, ThresholdType: workflow.ThresholdPercent, Threshold: 0}
		}},
		{"two-defaults", func(d *workflow.Design) {
			gateway := workflow.Node{ID: "xor", Type: workflow.NodeExclusive, Name: "判断"}
			d.Nodes = []workflow.Node{d.Nodes[0], d.Nodes[1], d.Nodes[2], gateway}
			d.Edges = []workflow.Edge{
				edge("e1", "start", "xor", ""),
				edge("e2", "xor", "approve", ""),
				{ID: "e3", Source: "xor", Target: "end", Default: true},
				{ID: "e4", Source: "xor", Target: "end", Default: true},
			}
		}},
		{"bad-condition", func(d *workflow.Design) {
			gateway := workflow.Node{ID: "xor", Type: workflow.NodeExclusive, Name: "判断"}
			d.Nodes = []workflow.Node{d.Nodes[0], d.Nodes[1], d.Nodes[2], gateway}
			d.Edges = []workflow.Edge{
				edge("e1", "start", "xor", ""),
				edge("e2", "xor", "approve", "amount >"),
				{ID: "e3", Source: "xor", Target: "end", Default: true},
			}
		}},
		{"duplicate-form-key", func(d *workflow.Design) {
			d.Forms["start"] = []workflow.FormField{
				{Key: "amount", Label: "金额", Type: "number"},
				{Key: "amount", Label: "重复", Type: "text"},
			}
		}},
		{"select-without-options", func(d *workflow.Design) {
			d.Forms["start"] = []workflow.FormField{{Key: "kind", Label: "类型", Type: "select"}}
		}},
		{"unknown-rule-scope", func(d *workflow.Design) {
			d.Rules = []workflow.AutoRule{{ID: "r1", Enabled: true, Event: workflow.AutoEventTask, Scope: "magic", Decision: workflow.DecisionApprove}}
		}},
		{"catch-without-duration", func(d *workflow.Design) {
			d.Nodes = []workflow.Node{
				d.Nodes[0],
				{ID: "wait", Type: workflow.NodeCatch, Name: "等待", WaitKind: workflow.WaitTimer},
				d.Nodes[2],
			}
			d.Edges = []workflow.Edge{edge("e1", "start", "wait", ""), edge("e2", "wait", "end", "")}
		}},
		{"event-gateway-to-user", func(d *workflow.Design) {
			gateway := workflow.Node{ID: "event", Type: workflow.NodeEventGateway, Name: "事件"}
			d.Nodes = []workflow.Node{d.Nodes[0], gateway, d.Nodes[1], d.Nodes[2]}
			d.Edges = []workflow.Edge{
				edge("e1", "start", "event", ""),
				edge("e2", "event", "approve", ""),
				edge("e3", "approve", "end", ""),
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			design := base()
			tc.mutate(&design)
			if _, err := f.svc.CreateVersion(context.Background(), f.tenant, def.ID, "boss", workflow.VersionInput{Design: design}); err == nil {
				t.Fatalf("%s: 期望设计校验失败", tc.name)
			} else if !errors.Is(err, workflow.ErrInvalidDesign) && !errors.Is(err, workflow.ErrInvalidForm) &&
				!errors.Is(err, workflow.ErrInvalidCondition) && !errors.Is(err, workflow.ErrLimit) {
				t.Fatalf("%s: 错误 = %v, 期望设计类哨兵", tc.name, err)
			}
		})
	}
}

// TestDesignValidationAcceptsRichGraph covers a valid graph with every executable node. |
// TestDesignValidationAcceptsRichGraph 覆盖包含全部可执行节点的合法图。
func TestDesignValidationAcceptsRichGraph(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	def := createDefinition(t, f, "rich")
	design := workflow.DefaultDesign()
	design.Nodes = []workflow.Node{
		startNode(),
		{ID: "service", Type: workflow.NodeServiceTask, Name: "服务"},
		{ID: "xor", Type: workflow.NodeExclusive, Name: "判断"},
		userNode("approve", "审批", workflow.Assignment{Type: workflow.AssigneeRole, Values: []string{"staff"}}, workflow.Completion{Mode: workflow.CompletionVote, ThresholdType: workflow.ThresholdCount, Threshold: 1}),
		{ID: "event", Type: workflow.NodeEventGateway, Name: "事件"},
		{ID: "timer", Type: workflow.NodeCatch, Name: "定时", WaitKind: workflow.WaitTimer, WaitFor: "PT5M"},
		{ID: "message", Type: workflow.NodeCatch, Name: "消息", WaitKind: workflow.WaitMessage, MessageName: "go"},
		endNode("end"),
	}
	design.Edges = []workflow.Edge{
		edge("e1", "start", "service", ""),
		edge("e2", "service", "xor", ""),
		edge("e3", "xor", "approve", "amount > 10"),
		{ID: "e4", Source: "xor", Target: "event", Default: true},
		edge("e5", "approve", "end", ""),
		edge("e6", "event", "timer", ""),
		edge("e7", "event", "message", ""),
		edge("e8", "timer", "end", ""),
		edge("e9", "message", "end", ""),
	}
	design.Forms["start"] = []workflow.FormField{
		{Key: "amount", Label: "金额", Type: "number", Required: true},
		{Key: "kind", Label: "类型", Type: "select", Options: []workflow.FormOption{{Value: "a", Label: "甲"}}},
	}
	design.Rules = []workflow.AutoRule{{ID: "r1", Enabled: true, Event: workflow.AutoEventTask, Scope: workflow.AutoScopeGroup, Match: []string{"approvers"}, Decision: workflow.DecisionReject}}
	design.Settings = workflow.DesignSettings{Due: "48h", ForbidDelegate: true}
	version, err := f.svc.CreateVersion(context.Background(), f.tenant, def.ID, "boss", workflow.VersionInput{Design: design})
	if err != nil {
		t.Fatalf("合法设计被拒绝: %v", err)
	}
	if version.Checksum == "" || version.BPMN == "" {
		t.Fatalf("版本缺少校验和或 BPMN: %+v", version)
	}
	if _, err := f.svc.PublishVersion(context.Background(), f.tenant, version.ID, "boss", "ok"); err != nil {
		t.Fatalf("发布合法设计失败: %v", err)
	}
}

// TestDefinitionAndVersionLifecycle covers CRUD, conflicts and immutability. |
// TestDefinitionAndVersionLifecycle 覆盖定义与版本生命周期。
func TestDefinitionAndVersionLifecycle(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	def := createDefinition(t, f, "lifecycle")
	if _, err := f.svc.CreateDefinition(context.Background(), f.tenant, "boss", workflow.DefinitionInput{Key: "lifecycle", Name: "重复"}); !errors.Is(err, workflow.ErrConflict) {
		t.Fatalf("重复定义键错误 = %v", err)
	}
	if _, err := f.svc.SetDefinitionStatus(context.Background(), f.tenant, def.ID, "boss", workflow.DefinitionPublished); err == nil {
		t.Fatal("没有发布版本时不应允许发布定义")
	}
	design := linearDesign(workflow.Assignment{Type: workflow.AssigneeInitiator}, workflow.Completion{Mode: workflow.CompletionAny})
	version, err := f.svc.CreateVersion(context.Background(), f.tenant, def.ID, "boss", workflow.VersionInput{Design: design})
	if err != nil {
		t.Fatalf("创建版本失败: %v", err)
	}
	updated, err := f.svc.UpdateVersion(context.Background(), f.tenant, version.ID, "boss", workflow.VersionInput{Design: design, Note: "草稿"})
	if err != nil || updated.Note != "草稿" {
		t.Fatalf("更新草稿失败: %v %+v", err, updated)
	}
	published, err := f.svc.PublishVersion(context.Background(), f.tenant, version.ID, "boss", "发布")
	if err != nil {
		t.Fatalf("发布失败: %v", err)
	}
	if published.Status != workflow.VersionPublished || published.PublishedAt.IsZero() {
		t.Fatalf("发布结果 = %+v", published)
	}
	if _, err := f.svc.UpdateVersion(context.Background(), f.tenant, version.ID, "boss", workflow.VersionInput{Design: design}); !errors.Is(err, workflow.ErrVersionPublished) {
		t.Fatalf("修改已发布版本错误 = %v", err)
	}
	if err := f.svc.DeleteVersion(context.Background(), f.tenant, version.ID); !errors.Is(err, workflow.ErrVersionPublished) {
		t.Fatalf("删除已发布版本错误 = %v", err)
	}
	if err := f.svc.DeleteDefinition(context.Background(), f.tenant, def.ID); err != nil {
		t.Fatalf("删除无实例定义失败: %v", err)
	}
	if _, err := f.svc.GetDefinition(context.Background(), f.tenant, def.ID); !errors.Is(err, workflow.ErrNotFound) {
		t.Fatalf("删除后读取错误 = %v", err)
	}
}

// TestDesignIndexMatchesLinearLookup proves the parsed design's index returns the same nodes and
// edge order as the linear fallback, and that appending a node invalidates it cleanly. |
// TestDesignIndexMatchesLinearLookup 证明解析后设计的索引与线性回退返回相同节点与连线顺序，
// 并且追加节点会让索引干净失效。
func TestDesignIndexMatchesLinearLookup(t *testing.T) {
	design := workflow.Design{
		SchemaVersion: 1,
		Nodes:         []workflow.Node{{ID: "n0"}, {ID: "n1"}, {ID: "n2"}},
		Edges: []workflow.Edge{
			{ID: "e-b", Source: "n0", Target: "n1", Sort: 2},
			{ID: "e-a", Source: "n0", Target: "n2", Sort: 1},
			{ID: "e-c", Source: "n2", Target: "n1"},
		},
	}
	raw, err := json.Marshal(design)
	if err != nil {
		t.Fatalf("编码设计失败: %v", err)
	}
	parsed, err := workflow.DesignOf(workflow.Version{Design: string(raw)})
	if err != nil {
		t.Fatalf("解析设计失败: %v", err)
	}
	outgoing := func(d workflow.Design) []string {
		ids := make([]string, 0, 2)
		for _, edge := range d.Outgoing("n0") {
			ids = append(ids, edge.ID)
		}
		return ids
	}
	incoming := func(d workflow.Design) []string {
		ids := make([]string, 0, 2)
		for _, edge := range d.Incoming("n1") {
			ids = append(ids, edge.ID)
		}
		return ids
	}
	if got := outgoing(parsed); len(got) != 2 || got[0] != "e-a" || got[1] != "e-b" {
		t.Fatalf("索引出线 = %v, 期望 [e-a e-b]", got)
	}
	if got := outgoing(design); len(got) != 2 || got[0] != "e-a" || got[1] != "e-b" {
		t.Fatalf("线性出线 = %v, 期望 [e-a e-b]", got)
	}
	if got := incoming(parsed); len(got) != 2 || got[0] != "e-b" || got[1] != "e-c" {
		t.Fatalf("索引入线 = %v, 期望 [e-b e-c]", got)
	}
	if got := incoming(design); len(got) != 2 || got[0] != "e-b" || got[1] != "e-c" {
		t.Fatalf("线性入线 = %v, 期望 [e-b e-c]", got)
	}
	if _, ok := parsed.FindNode("n2"); !ok {
		t.Fatal("索引未找到 n2")
	}
	if _, ok := parsed.FindNode("missing"); ok {
		t.Fatal("索引错误命中 missing")
	}
	parsed.Nodes = append(parsed.Nodes, workflow.Node{ID: "n3"})
	if got := outgoing(parsed); len(got) != 2 || got[0] != "e-a" {
		t.Fatalf("追加节点后出线 = %v", got)
	}
}
