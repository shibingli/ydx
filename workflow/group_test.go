package workflow_test

import (
	"context"
	"errors"
	"testing"

	"github.com/shibingli/ydx/workflow"
)

// TestWorkflowGroupResolutionAndRoleLink covers explicit members, linked roles and auto rules. |
// TestWorkflowGroupResolutionAndRoleLink 覆盖显式成员、关联角色与自动规则。
func TestWorkflowGroupResolutionAndRoleLink(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	group, err := f.svc.CreateGroup(context.Background(), f.tenant, workflow.GroupInput{
		Key: "approvers", Name: "审批组", Role: "manager",
	})
	if err != nil {
		t.Fatalf("创建流程组失败: %v", err)
	}
	if _, err := f.svc.CreateGroup(context.Background(), f.tenant, workflow.GroupInput{Key: "approvers", Name: "重复"}); !errors.Is(err, workflow.ErrConflict) {
		t.Fatalf("重复组键错误 = %v", err)
	}
	members, err := f.svc.SetGroupMembers(context.Background(), f.tenant, group.ID, []string{"u1"})
	if err != nil || len(members) != 1 {
		t.Fatalf("设置组成员失败: %v %+v", err, members)
	}
	page, err := f.svc.ListGroups(context.Background(), f.tenant, workflow.GroupFilter{Page: 1, PageSize: 10})
	if err != nil || page.Total != 1 || page.Items[0].MemberCount != 1 {
		t.Fatalf("组列表 = %+v %v", page, err)
	}
	groups, err := f.svc.GetGroupByKey(context.Background(), f.tenant, "approvers")
	if err != nil || groups.Role != "manager" {
		t.Fatalf("按键读取组 = %+v %v", groups, err)
	}

	design := linearDesign(workflow.Assignment{Type: workflow.AssigneeGroup, Values: []string{"approvers"}}, workflow.Completion{Mode: workflow.CompletionAny})
	f.publishDefinition(t, "group-flow", design)
	inst := f.start(t, "group-flow", nil)
	tasks := f.openTasks(t, inst.ID)
	assignees := map[string]bool{}
	for _, task := range tasks {
		assignees[task.AssigneeID] = true
	}
	if !assignees["u1"] || !assignees["u3"] {
		t.Fatalf("流程组解析结果 = %+v, 期望包含 u1（显式）与 u3（manager 角色）", assignees)
	}
	if assignees["u2"] {
		t.Fatalf("流程组错误包含了 u2: %+v", assignees)
	}

	autoDesign := linearDesign(workflow.Assignment{Type: workflow.AssigneeGroup, Values: []string{"approvers"}}, workflow.Completion{Mode: workflow.CompletionAny})
	autoDesign.Rules = []workflow.AutoRule{{
		ID: "group-auto", Enabled: true, Event: workflow.AutoEventTask, Scope: workflow.AutoScopeGroup,
		Match: []string{"approvers"}, Decision: workflow.DecisionApprove, Priority: 1,
	}}
	f.publishDefinition(t, "group-auto", autoDesign)
	autoInst := f.start(t, "group-auto", nil)
	if got := f.instance(t, autoInst.ID); got.Status != workflow.InstanceCompleted {
		t.Fatalf("流程组自动审批状态 = %s", got.Status)
	}
}

// TestWorkflowGroupLifecycle covers update, disable and delete. | TestWorkflowGroupLifecycle
// 覆盖组的修改、停用与删除。
func TestWorkflowGroupLifecycle(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	group, err := f.svc.CreateGroup(context.Background(), f.tenant, workflow.GroupInput{Key: "ops", Name: "运营组"})
	if err != nil {
		t.Fatalf("创建组失败: %v", err)
	}
	if _, err := f.svc.SetGroupMembers(context.Background(), f.tenant, group.ID, []string{"u1", "u2"}); err != nil {
		t.Fatalf("设置成员失败: %v", err)
	}
	updated, err := f.svc.UpdateGroup(context.Background(), f.tenant, group.ID, workflow.GroupInput{
		Name: "运营组（停用）", Status: workflow.GroupDisabled,
	})
	if err != nil || updated.Status != workflow.GroupDisabled {
		t.Fatalf("停用组失败: %v %+v", err, updated)
	}
	f.publishDefinition(t, "disabled-group", linearDesign(
		workflow.Assignment{Type: workflow.AssigneeGroup, Values: []string{"ops"}},
		workflow.Completion{Mode: workflow.CompletionAny},
	))
	if _, err := f.svc.Start(context.Background(), f.tenant, actor("u1"), workflow.StartInput{DefinitionKey: "disabled-group", Title: "停用组"}); !errors.Is(err, workflow.ErrNoAssignee) {
		t.Fatalf("停用组发起错误 = %v, 期望 ErrNoAssignee", err)
	}
	if err := f.svc.DeleteGroup(context.Background(), f.tenant, group.ID); err != nil {
		t.Fatalf("删除组失败: %v", err)
	}
	if _, err := f.svc.GetGroup(context.Background(), f.tenant, group.ID); !errors.Is(err, workflow.ErrNotFound) {
		t.Fatalf("删除后读取错误 = %v", err)
	}
	if _, err := f.svc.Start(context.Background(), f.tenant, actor("u1"), workflow.StartInput{DefinitionKey: "disabled-group", Title: "已删组"}); !errors.Is(err, workflow.ErrNotFound) {
		t.Fatalf("删除组后发起错误 = %v, 期望 ErrNotFound", err)
	}
}
