package workflow_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shibingli/ydx/workflow"
)

// TestLinearApprovalCompletesInstance covers the simplest approvable process. |
// TestLinearApprovalCompletesInstance 覆盖最简可审批流程。
func TestLinearApprovalCompletesInstance(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	f.publishDefinition(t, "linear", linearDesign(
		workflow.Assignment{Type: workflow.AssigneeInitiator},
		workflow.Completion{Mode: workflow.CompletionAny},
	))
	inst := f.start(t, "linear", nil)
	if inst.Status != workflow.InstanceRunning {
		t.Fatalf("发起后状态 = %s, 期望 running", inst.Status)
	}
	task := f.taskFor(t, inst.ID, "u1")
	if task.NodeID != "approve" || task.Status != workflow.TaskPending {
		t.Fatalf("任务 = %+v", task)
	}
	f.approve(t, "u1", task.ID, workflow.DecisionApprove)
	final := f.instance(t, inst.ID)
	if final.Status != workflow.InstanceCompleted || final.Outcome != "approved" {
		t.Fatalf("完成后实例 = %+v", final)
	}
	if final.EndedAt.IsZero() {
		t.Fatal("完成实例没有结束时间")
	}
	if f.channel.count() < 2 {
		t.Fatalf("通知数量 = %d, 期望至少 2（待办 + 完成）", f.channel.count())
	}
}

// TestTaskReadsKeepInstanceProjection guards the bare task read: GetTask, TaskDetail and the task
// returned by Approve must still carry the denormalized instance display fields. |
// TestTaskReadsKeepInstanceProjection 守护单行任务读取：GetTask、TaskDetail 与 Approve 返回的任务
// 仍必须携带反规范化的实例展示字段。
func TestTaskReadsKeepInstanceProjection(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	f.publishDefinition(t, "projection", linearDesign(
		workflow.Assignment{Type: workflow.AssigneeInitiator},
		workflow.Completion{Mode: workflow.CompletionAny},
	))
	inst := f.start(t, "projection", nil)
	task := f.taskFor(t, inst.ID, "u1")
	ctx := context.Background()
	read, err := f.svc.GetTask(ctx, f.tenant, task.ID)
	if err != nil {
		t.Fatalf("GetTask 失败: %v", err)
	}
	if read.InstanceTitle != inst.Title || read.InstanceInitiator != inst.InitiatorName || read.Category != inst.Category {
		t.Fatalf("GetTask 投影 = %+v", read)
	}
	detail, err := f.svc.TaskDetail(ctx, f.tenant, task.ID)
	if err != nil {
		t.Fatalf("TaskDetail 失败: %v", err)
	}
	if detail.Task.InstanceTitle != inst.Title || detail.Task.InstanceInitiator != inst.InitiatorName {
		t.Fatalf("TaskDetail 投影 = %+v", detail.Task)
	}
	decided, err := f.svc.Approve(ctx, f.tenant, actor("u1"), task.ID, workflow.ActionInput{Decision: workflow.DecisionApprove})
	if err != nil {
		t.Fatalf("审批失败: %v", err)
	}
	if decided.InstanceTitle != inst.Title || decided.InstanceInitiator != inst.InitiatorName {
		t.Fatalf("Approve 投影 = %+v", decided)
	}
}

// TestOrSignCompletesOnFirstApproval covers any-mode approval. | TestOrSignCompletesOnFirstApproval
// 覆盖或签：首人通过即完成。
func TestOrSignCompletesOnFirstApproval(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	f.publishDefinition(t, "or-sign", linearDesign(
		workflow.Assignment{Type: workflow.AssigneeUser, Values: []string{"u1", "u2"}},
		workflow.Completion{Mode: workflow.CompletionAny},
	))
	inst := f.start(t, "or-sign", nil)
	tasks := f.openTasks(t, inst.ID)
	if len(tasks) != 2 {
		t.Fatalf("或签任务数 = %d, 期望 2", len(tasks))
	}
	first := f.taskFor(t, inst.ID, "u1")
	f.approve(t, "u1", first.ID, workflow.DecisionApprove)
	final := f.instance(t, inst.ID)
	if final.Status != workflow.InstanceCompleted {
		t.Fatalf("或签后状态 = %s", final.Status)
	}
	for _, task := range f.listTasks(t, inst.ID) {
		if task.AssigneeID == "u2" && task.Status != workflow.TaskCancelled {
			t.Fatalf("或签未取消另一人的任务: %+v", task)
		}
	}
}

// TestCountersignRequiresEveryApproval covers all-mode approval and rejection. |
// TestCountersignRequiresEveryApproval 覆盖会签的全员通过与驳回。
func TestCountersignRequiresEveryApproval(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	f.publishDefinition(t, "countersign", linearDesign(
		workflow.Assignment{Type: workflow.AssigneeUser, Values: []string{"u1", "u2"}},
		workflow.Completion{Mode: workflow.CompletionAll, RejectMode: workflow.RejectModeAny},
	))
	inst := f.start(t, "countersign", nil)
	first := f.taskFor(t, inst.ID, "u1")
	f.approve(t, "u1", first.ID, workflow.DecisionApprove)
	if got := f.instance(t, inst.ID); got.Status != workflow.InstanceRunning {
		t.Fatalf("一人通过后会签状态 = %s", got.Status)
	}
	second := f.taskFor(t, inst.ID, "u2")
	f.approve(t, "u2", second.ID, workflow.DecisionApprove)
	if got := f.instance(t, inst.ID); got.Status != workflow.InstanceCompleted {
		t.Fatalf("全员通过后会签状态 = %s", got.Status)
	}

	other := f.start(t, "countersign", nil)
	rejectTask := f.taskFor(t, other.ID, "u1")
	f.approve(t, "u1", rejectTask.ID, workflow.DecisionReject)
	final := f.instance(t, other.ID)
	if final.Status != workflow.InstanceTerminated || final.Outcome != "rejected" {
		t.Fatalf("会签驳回后实例 = %+v", final)
	}
}

// TestVoteThresholds covers count and percentage vote-sign. | TestVoteThresholds 覆盖票数与百分比票签。
func TestVoteThresholds(t *testing.T) {
	cases := []struct {
		name       string
		completion workflow.Completion
		approvals  int
	}{
		{"count", workflow.Completion{Mode: workflow.CompletionVote, ThresholdType: workflow.ThresholdCount, Threshold: 2}, 2},
		{"percent", workflow.Completion{Mode: workflow.CompletionVote, ThresholdType: workflow.ThresholdPercent, Threshold: 50}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			defer f.close()
			f.publishDefinition(t, "vote-"+tc.name, linearDesign(
				workflow.Assignment{Type: workflow.AssigneeUser, Values: []string{"u1", "u2", "u3"}},
				tc.completion,
			))
			inst := f.start(t, "vote-"+tc.name, nil)
			for i := 0; i < tc.approvals; i++ {
				user := []string{"u1", "u2", "u3"}[i]
				task := f.taskFor(t, inst.ID, user)
				f.approve(t, user, task.ID, workflow.DecisionApprove)
			}
			if got := f.instance(t, inst.ID); got.Status != workflow.InstanceCompleted {
				t.Fatalf("票签达标后状态 = %s", got.Status)
			}
		})
	}
}

// TestSequentialApprovalQueuesTasks covers sequential mode. | TestSequentialApprovalQueuesTasks 覆盖顺序审批。
func TestSequentialApprovalQueuesTasks(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	f.publishDefinition(t, "sequential", linearDesign(
		workflow.Assignment{Type: workflow.AssigneeUser, Values: []string{"u1", "u2", "u3"}},
		workflow.Completion{Mode: workflow.CompletionAll, Sequential: true},
	))
	inst := f.start(t, "sequential", nil)
	tasks := f.listTasks(t, inst.ID)
	pending, queued := 0, 0
	for _, task := range tasks {
		switch task.Status {
		case workflow.TaskPending:
			pending++
		case workflow.TaskQueued:
			queued++
		}
	}
	if pending != 1 || queued != 2 {
		t.Fatalf("顺序审批 pending=%d queued=%d, 期望 1/2: %+v", pending, queued, tasks)
	}
	for _, user := range []string{"u1", "u2", "u3"} {
		task := f.openTasks(t, inst.ID)
		var current workflow.Task
		for _, candidate := range task {
			if candidate.AssigneeID == user {
				current = candidate
			}
		}
		if current.ID == "" {
			t.Fatalf("未找到 %s 的当前任务: %+v", user, task)
		}
		f.approve(t, user, current.ID, workflow.DecisionApprove)
	}
	if got := f.instance(t, inst.ID); got.Status != workflow.InstanceCompleted {
		t.Fatalf("顺序审批完成后状态 = %s", got.Status)
	}
}

// TestGrabAndClaimRequiresAtomicClaim covers claim and grab modes. | TestGrabAndClaimRequiresAtomicClaim
// 覆盖签收与抢单模式。
func TestGrabAndClaimRequiresAtomicClaim(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	f.publishDefinition(t, "grab", linearDesign(
		workflow.Assignment{Type: workflow.AssigneeUser, Values: []string{"u1", "u2"}, Claim: workflow.ClaimGrab},
		workflow.Completion{Mode: workflow.CompletionAny},
	))
	inst := f.start(t, "grab", nil)
	var target workflow.Task
	for _, task := range f.listTasks(t, inst.ID) {
		if task.Status == workflow.TaskPending && len(task.Candidates) > 0 {
			target = task
			break
		}
	}
	if target.ID == "" {
		t.Fatalf("抢单任务没有候选池: %+v", f.listTasks(t, inst.ID))
	}
	if _, err := f.svc.Approve(context.Background(), f.tenant, actor("u1"), target.ID, workflow.ActionInput{Decision: workflow.DecisionApprove}); !errors.Is(err, workflow.ErrTaskNotMine) {
		t.Fatalf("未签收直接审批错误 = %v, 期望 ErrTaskNotMine", err)
	}
	claimed, err := f.svc.Claim(context.Background(), f.tenant, actor("u1"), target.ID)
	if err != nil {
		t.Fatalf("签收失败: %v", err)
	}
	if claimed.AssigneeID != "u1" || claimed.Status != workflow.TaskClaimed {
		t.Fatalf("签收结果 = %+v", claimed)
	}
	if _, err := f.svc.Claim(context.Background(), f.tenant, actor("u2"), target.ID); err == nil {
		t.Fatal("第二个人不应抢到同一任务")
	}
	f.approve(t, "u1", target.ID, workflow.DecisionApprove)
	if got := f.instance(t, inst.ID); got.Status != workflow.InstanceCompleted {
		t.Fatalf("抢单审批后状态 = %s", got.Status)
	}
}

// TestTransferAndDelegation covers reassignment semantics. | TestTransferAndDelegation 覆盖转办与委派。
func TestTransferAndDelegation(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	f.publishDefinition(t, "transfer", linearDesign(
		workflow.Assignment{Type: workflow.AssigneeUser, Values: []string{"u1"}},
		workflow.Completion{Mode: workflow.CompletionAny},
	))
	inst := f.start(t, "transfer", nil)
	task := f.taskFor(t, inst.ID, "u1")
	transferred, err := f.svc.Transfer(context.Background(), f.tenant, actor("u1"), task.ID, workflow.TransferInput{TargetID: "u3", Comment: "转办"})
	if err != nil {
		t.Fatalf("转办失败: %v", err)
	}
	if transferred.AssigneeID != "u3" {
		t.Fatalf("转办后处理人 = %s", transferred.AssigneeID)
	}
	delegated, err := f.svc.Delegate(context.Background(), f.tenant, actor("u3"), task.ID, workflow.DelegateInput{TargetID: "u2", Comment: "委派"})
	if err != nil {
		t.Fatalf("委派失败: %v", err)
	}
	if delegated.AssigneeID != "u2" || delegated.OriginalAssigneeID != "u3" {
		t.Fatalf("委派结果 = %+v", delegated)
	}
	handed, err := f.svc.Approve(context.Background(), f.tenant, actor("u2"), task.ID, workflow.ActionInput{Decision: workflow.DecisionApprove, Comment: "受托处理"})
	if err != nil {
		t.Fatalf("受托审批失败: %v", err)
	}
	if handed.AssigneeID != "u3" || handed.Status != workflow.TaskPending || handed.DelegatedFrom != "u2" {
		t.Fatalf("委派交回结果 = %+v", handed)
	}
	f.approve(t, "u3", task.ID, workflow.DecisionApprove)
	if got := f.instance(t, inst.ID); got.Status != workflow.InstanceCompleted {
		t.Fatalf("委派最终审批后状态 = %s", got.Status)
	}
}

// TestAddAndRemoveSign covers dynamic approver changes. | TestAddAndRemoveSign 覆盖动态加签与减签。
func TestAddAndRemoveSign(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	f.publishDefinition(t, "add-sign", linearDesign(
		workflow.Assignment{Type: workflow.AssigneeUser, Values: []string{"u1"}},
		workflow.Completion{Mode: workflow.CompletionAll},
	))
	inst := f.start(t, "add-sign", nil)
	original := f.taskFor(t, inst.ID, "u1")
	added, err := f.svc.AddSign(context.Background(), f.tenant, actor("u1"), original.ID, workflow.AddSignInput{UserIDs: []string{"u2", "u3"}})
	if err != nil {
		t.Fatalf("加签失败: %v", err)
	}
	if len(added) != 2 {
		t.Fatalf("加签返回 = %d 条, 期望 2", len(added))
	}
	if len(f.openTasks(t, inst.ID)) != 3 {
		t.Fatalf("加签后未结束任务 = %d, 期望 3", len(f.openTasks(t, inst.ID)))
	}
	if err := f.svc.RemoveSign(context.Background(), f.tenant, actor("u1"), original.ID, added[1].ID, "减签"); err != nil {
		t.Fatalf("减签失败: %v", err)
	}
	if len(f.openTasks(t, inst.ID)) != 2 {
		t.Fatalf("减签后未结束任务 = %d, 期望 2", len(f.openTasks(t, inst.ID)))
	}
	for _, user := range []string{"u1", "u2"} {
		task := f.taskFor(t, inst.ID, user)
		f.approve(t, user, task.ID, workflow.DecisionApprove)
	}
	if got := f.instance(t, inst.ID); got.Status != workflow.InstanceCompleted {
		t.Fatalf("加减签后状态 = %s", got.Status)
	}
}

// TestSequentialAddSignBefore covers front insertion. | TestSequentialAddSignBefore 覆盖前加签。
func TestSequentialAddSignBefore(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	f.publishDefinition(t, "add-before", linearDesign(
		workflow.Assignment{Type: workflow.AssigneeUser, Values: []string{"u1", "u2"}},
		workflow.Completion{Mode: workflow.CompletionAll, Sequential: true},
	))
	inst := f.start(t, "add-before", nil)
	task := f.taskFor(t, inst.ID, "u1")
	if _, err := f.svc.AddSign(context.Background(), f.tenant, actor("u1"), task.ID, workflow.AddSignInput{
		UserIDs: []string{"u3"}, Position: "before",
	}); err != nil {
		t.Fatalf("前加签失败: %v", err)
	}
	next := f.taskFor(t, inst.ID, "u3")
	if next.ID == "" {
		t.Fatal("前加签后 u3 不是当前审批人")
	}
	for _, user := range []string{"u3", "u1", "u2"} {
		current := f.taskFor(t, inst.ID, user)
		f.approve(t, user, current.ID, workflow.DecisionApprove)
	}
	if got := f.instance(t, inst.ID); got.Status != workflow.InstanceCompleted {
		t.Fatalf("前加签流程状态 = %s", got.Status)
	}
}

// TestReturnToPreviousNode covers the return action. | TestReturnToPreviousNode 覆盖退回。
func TestReturnToPreviousNode(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	design := workflow.DefaultDesign()
	design.Nodes = []workflow.Node{
		startNode(),
		userNode("first", "初审 | First", workflow.Assignment{Type: workflow.AssigneeUser, Values: []string{"u1"}}, workflow.Completion{Mode: workflow.CompletionAny}),
		userNode("second", "复审 | Second", workflow.Assignment{Type: workflow.AssigneeUser, Values: []string{"u2"}}, workflow.Completion{Mode: workflow.CompletionAny}),
		endNode("end"),
	}
	design.Edges = []workflow.Edge{
		edge("e1", "start", "first", ""),
		edge("e2", "first", "second", ""),
		edge("e3", "second", "end", ""),
	}
	f.publishDefinition(t, "return", design)
	inst := f.start(t, "return", nil)
	f.approve(t, "u1", f.taskFor(t, inst.ID, "u1").ID, workflow.DecisionApprove)
	second := f.taskFor(t, inst.ID, "u2")
	if err := f.svc.Return(context.Background(), f.tenant, actor("u2"), second.ID, workflow.ReturnInput{TargetNodeID: "first", Comment: "退回"}); err != nil {
		t.Fatalf("退回失败: %v", err)
	}
	firstAgain := f.taskFor(t, inst.ID, "u1")
	if firstAgain.ID == "" {
		t.Fatal("退回后没有重新生成初审任务")
	}
	f.approve(t, "u1", firstAgain.ID, workflow.DecisionApprove)
	f.approve(t, "u2", f.taskFor(t, inst.ID, "u2").ID, workflow.DecisionApprove)
	if got := f.instance(t, inst.ID); got.Status != workflow.InstanceCompleted {
		t.Fatalf("退回重走后状态 = %s", got.Status)
	}
}

// TestTerminateAndRemind covers an administrative termination and a reminder. |
// TestTerminateAndRemind 覆盖管理员终止与催办。
func TestTerminateAndRemind(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	f.publishDefinition(t, "terminate", linearDesign(
		workflow.Assignment{Type: workflow.AssigneeInitiator},
		workflow.Completion{Mode: workflow.CompletionAny},
	))
	inst := f.start(t, "terminate", nil)
	task := f.taskFor(t, inst.ID, "u1")
	if _, err := f.svc.Remind(context.Background(), f.tenant, actor("u1"), task.ID, "请尽快处理"); err != nil {
		t.Fatalf("催办失败: %v", err)
	}
	if err := f.svc.TerminateInstance(context.Background(), f.tenant, adminActor(), inst.ID, workflow.ReasonInput{
		Reason: "管理员终止",
	}); err != nil {
		t.Fatalf("终止失败: %v", err)
	}
	final := f.instance(t, inst.ID)
	if final.Status != workflow.InstanceTerminated || final.Outcome != "terminated" {
		t.Fatalf("终止后的实例 = %+v", final)
	}
	closed, err := f.svc.GetTask(context.Background(), f.tenant, task.ID)
	if err != nil {
		t.Fatalf("读取已终止任务失败: %v", err)
	}
	if closed.Status != workflow.TaskCancelled {
		t.Fatalf("终止后的任务状态 = %s, 期望 cancelled", closed.Status)
	}
}

// TestWithdrawWindow covers initiator withdrawal. | TestWithdrawWindow 覆盖发起人撤回窗口。
func TestWithdrawWindow(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	f.publishDefinition(t, "withdraw", linearDesign(
		workflow.Assignment{Type: workflow.AssigneeInitiator},
		workflow.Completion{Mode: workflow.CompletionAny},
	))
	inst := f.start(t, "withdraw", nil)
	if err := f.svc.WithdrawInstance(context.Background(), f.tenant, actor("u1"), inst.ID, workflow.ReasonInput{Reason: "不办了"}); err != nil {
		t.Fatalf("撤回失败: %v", err)
	}
	final := f.instance(t, inst.ID)
	if final.Status != workflow.InstanceWithdrawn || final.Outcome != "withdrawn" {
		t.Fatalf("撤回后实例 = %+v", final)
	}

	second := f.start(t, "withdraw", nil)
	f.clock.Advance(31 * time.Minute)
	if err := f.svc.WithdrawInstance(context.Background(), f.tenant, actor("u1"), second.ID, workflow.ReasonInput{Reason: "超时"}); !errors.Is(err, workflow.ErrWithdrawExpired) {
		t.Fatalf("超窗撤回错误 = %v, 期望 ErrWithdrawExpired", err)
	}
	if err := f.svc.WithdrawInstance(context.Background(), f.tenant, adminActor(), second.ID, workflow.ReasonInput{Reason: "管理员"}); err != nil {
		t.Fatalf("管理员撤回失败: %v", err)
	}
}

// TestRejectReturnInitiator covers the revision loop. | TestRejectReturnInitiator 覆盖驳回退回发起人。
func TestRejectReturnInitiator(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	node := userNode("approve", "审批 | Approve", workflow.Assignment{Type: workflow.AssigneeInitiator}, workflow.Completion{Mode: workflow.CompletionAny})
	node.OnReject = workflow.OnRejectReturnInitiator
	design := linearDesign(workflow.Assignment{Type: workflow.AssigneeInitiator}, workflow.Completion{Mode: workflow.CompletionAny})
	design.Nodes[1] = node
	f.publishDefinition(t, "reject-return", design)
	inst := f.start(t, "reject-return", nil)
	f.approve(t, "u1", f.taskFor(t, inst.ID, "u1").ID, workflow.DecisionReject)
	tasks := f.openTasks(t, inst.ID)
	if len(tasks) != 1 || tasks[0].NodeID != workflow.InitiatorNodeID || tasks[0].AssigneeID != "u1" {
		t.Fatalf("驳回退回发起人任务 = %+v", tasks)
	}
	f.approve(t, "u1", tasks[0].ID, workflow.DecisionApprove)
	if got := f.instance(t, inst.ID); got.Status != workflow.InstanceRunning {
		t.Fatalf("重新提交后状态 = %s", got.Status)
	}
	f.approve(t, "u1", f.taskFor(t, inst.ID, "u1").ID, workflow.DecisionApprove)
	if got := f.instance(t, inst.ID); got.Status != workflow.InstanceCompleted {
		t.Fatalf("二次审批后状态 = %s", got.Status)
	}
}

// TestParallelForkAndJoin covers the AND gateway. | TestParallelForkAndJoin 覆盖并行网关。
func TestParallelForkAndJoin(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	fork := workflow.Node{ID: "fork", Type: workflow.NodeParallel, Name: "并行 | Fork", Position: workflow.Position{X: 150, Y: 200}}
	join := workflow.Node{ID: "join", Type: workflow.NodeParallel, Name: "汇聚 | Join", Position: workflow.Position{X: 620, Y: 200}}
	design := workflow.DefaultDesign()
	design.Nodes = []workflow.Node{
		startNode(), fork,
		userNode("a", "A | A", workflow.Assignment{Type: workflow.AssigneeUser, Values: []string{"u1"}}, workflow.Completion{Mode: workflow.CompletionAny}),
		userNode("b", "B | B", workflow.Assignment{Type: workflow.AssigneeUser, Values: []string{"u2"}}, workflow.Completion{Mode: workflow.CompletionAny}),
		join, endNode("end"),
	}
	design.Edges = []workflow.Edge{
		edge("e1", "start", "fork", ""),
		edge("e2", "fork", "a", ""),
		edge("e3", "fork", "b", ""),
		edge("e4", "a", "join", ""),
		edge("e5", "b", "join", ""),
		edge("e6", "join", "end", ""),
	}
	f.publishDefinition(t, "parallel", design)
	inst := f.start(t, "parallel", nil)
	if len(f.openTasks(t, inst.ID)) != 2 {
		t.Fatalf("并行分支任务数 = %d, 期望 2", len(f.openTasks(t, inst.ID)))
	}
	f.approve(t, "u1", f.taskFor(t, inst.ID, "u1").ID, workflow.DecisionApprove)
	if got := f.instance(t, inst.ID); got.Status != workflow.InstanceRunning {
		t.Fatalf("一个分支完成后状态 = %s", got.Status)
	}
	f.approve(t, "u2", f.taskFor(t, inst.ID, "u2").ID, workflow.DecisionApprove)
	if got := f.instance(t, inst.ID); got.Status != workflow.InstanceCompleted {
		t.Fatalf("并行汇聚后状态 = %s", got.Status)
	}
}

// TestExclusiveGatewayCondition covers XOR branching. | TestExclusiveGatewayCondition 覆盖排他网关条件分支。
func TestExclusiveGatewayCondition(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	gateway := workflow.Node{ID: "xor", Type: workflow.NodeExclusive, Name: "判断 | Decide", Position: workflow.Position{X: 160, Y: 200}}
	design := workflow.DefaultDesign()
	design.Nodes = []workflow.Node{
		startNode(), gateway,
		userNode("high", "大额 | High", workflow.Assignment{Type: workflow.AssigneeUser, Values: []string{"u3"}}, workflow.Completion{Mode: workflow.CompletionAny}),
		userNode("low", "小额 | Low", workflow.Assignment{Type: workflow.AssigneeUser, Values: []string{"u2"}}, workflow.Completion{Mode: workflow.CompletionAny}),
		endNode("end"),
	}
	design.Edges = []workflow.Edge{
		edge("e1", "start", "xor", ""),
		edge("e2", "xor", "high", "amount > 100"),
		edge("e3", "xor", "low", ""),
		edge("e4", "high", "end", ""),
		edge("e5", "low", "end", ""),
	}
	f.publishDefinition(t, "exclusive", design)
	high := f.start(t, "exclusive", map[string]any{"amount": 200})
	if len(f.openTasks(t, high.ID)) != 1 || f.openTasks(t, high.ID)[0].NodeID != "high" {
		t.Fatalf("大额分支任务 = %+v", f.openTasks(t, high.ID))
	}
	low := f.start(t, "exclusive", map[string]any{"amount": 50})
	if len(f.openTasks(t, low.ID)) != 1 || f.openTasks(t, low.ID)[0].NodeID != "low" {
		t.Fatalf("小额分支任务 = %+v", f.openTasks(t, low.ID))
	}
}

// TestInclusiveGateway covers OR branching and joining. | TestInclusiveGateway 覆盖包容网关分支与汇聚。
func TestInclusiveGateway(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	split := workflow.Node{ID: "split", Type: workflow.NodeInclusive, Name: "分支 | Split", Position: workflow.Position{X: 150, Y: 200}}
	join := workflow.Node{ID: "join", Type: workflow.NodeInclusive, Name: "汇聚 | Join", Position: workflow.Position{X: 650, Y: 200}}
	design := workflow.DefaultDesign()
	design.Nodes = []workflow.Node{
		startNode(), split,
		userNode("a", "A | A", workflow.Assignment{Type: workflow.AssigneeUser, Values: []string{"u1"}}, workflow.Completion{Mode: workflow.CompletionAny}),
		userNode("b", "B | B", workflow.Assignment{Type: workflow.AssigneeUser, Values: []string{"u2"}}, workflow.Completion{Mode: workflow.CompletionAny}),
		join, endNode("end"),
	}
	design.Edges = []workflow.Edge{
		edge("e1", "start", "split", ""),
		edge("e2", "split", "a", "amount > 50"),
		edge("e3", "split", "b", "amount > 100"),
		edge("e4", "a", "join", ""),
		edge("e5", "b", "join", ""),
		edge("e6", "join", "end", ""),
	}
	f.publishDefinition(t, "inclusive", design)
	inst := f.start(t, "inclusive", map[string]any{"amount": 200})
	if len(f.openTasks(t, inst.ID)) != 2 {
		t.Fatalf("包容分支任务数 = %d, 期望 2", len(f.openTasks(t, inst.ID)))
	}
	f.approve(t, "u1", f.taskFor(t, inst.ID, "u1").ID, workflow.DecisionApprove)
	f.approve(t, "u2", f.taskFor(t, inst.ID, "u2").ID, workflow.DecisionApprove)
	if got := f.instance(t, inst.ID); got.Status != workflow.InstanceCompleted {
		t.Fatalf("包容汇聚后状态 = %s", got.Status)
	}
}

// TestTimerCatchEvent covers timer events through the scheduler. | TestTimerCatchEvent 覆盖定时捕获事件。
func TestTimerCatchEvent(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	catch := workflow.Node{ID: "wait", Type: workflow.NodeCatch, Name: "等待 | Wait", WaitKind: workflow.WaitTimer, WaitFor: "1m", Position: workflow.Position{X: 300, Y: 200}}
	design := workflow.DefaultDesign()
	design.Nodes = []workflow.Node{startNode(), catch, endNode("end")}
	design.Edges = []workflow.Edge{edge("e1", "start", "wait", ""), edge("e2", "wait", "end", "")}
	f.publishDefinition(t, "timer", design)
	inst := f.start(t, "timer", nil)
	if got := f.instance(t, inst.ID); got.Status != workflow.InstanceRunning {
		t.Fatalf("定时等待状态 = %s", got.Status)
	}
	report, err := f.svc.RunDue(context.Background(), 10)
	if err != nil {
		t.Fatalf("首次扫描失败: %v", err)
	}
	if report.Timers != 0 {
		t.Fatalf("未到期定时器触发 = %d", report.Timers)
	}
	f.clock.Advance(2 * time.Minute)
	report, err = f.svc.RunDue(context.Background(), 10)
	if err != nil {
		t.Fatalf("定时扫描失败: %v", err)
	}
	if report.Timers != 1 {
		t.Fatalf("定时器触发 = %d, 期望 1", report.Timers)
	}
	if got := f.instance(t, inst.ID); got.Status != workflow.InstanceCompleted {
		t.Fatalf("定时器触发后状态 = %s", got.Status)
	}
}

// TestMessageAndEventGateway covers message catch and the event-based gateway race. |
// TestMessageAndEventGateway 覆盖消息捕获与事件网关竞争。
func TestMessageAndEventGateway(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	gateway := workflow.Node{ID: "event", Type: workflow.NodeEventGateway, Name: "事件 | Event", Position: workflow.Position{X: 150, Y: 200}}
	timer := workflow.Node{ID: "timer", Type: workflow.NodeCatch, Name: "超时 | Timeout", WaitKind: workflow.WaitTimer, WaitFor: "1h", Position: workflow.Position{X: 320, Y: 120}}
	message := workflow.Node{ID: "message", Type: workflow.NodeCatch, Name: "消息 | Message", WaitKind: workflow.WaitMessage, MessageName: "approve-signal", Position: workflow.Position{X: 320, Y: 280}}
	design := workflow.DefaultDesign()
	design.Nodes = []workflow.Node{startNode(), gateway, timer, message, endNode("end")}
	design.Edges = []workflow.Edge{
		edge("e1", "start", "event", ""),
		edge("e2", "event", "timer", ""),
		edge("e3", "event", "message", ""),
		edge("e4", "timer", "end", ""),
		edge("e5", "message", "end", ""),
	}
	f.publishDefinition(t, "message", design)
	inst := f.start(t, "message", nil)
	woken, err := f.svc.Signal(context.Background(), f.tenant, adminActor(), inst.ID, "approve-signal", map[string]any{"approved": true})
	if err != nil {
		t.Fatalf("投递消息失败: %v", err)
	}
	if woken != 1 {
		t.Fatalf("唤醒令牌 = %d, 期望 1", woken)
	}
	if got := f.instance(t, inst.ID); got.Status != workflow.InstanceCompleted {
		t.Fatalf("消息唤醒后状态 = %s", got.Status)
	}
}

// TestAutomaticApproval covers start-scope and task-scope rules. | TestAutomaticApproval 覆盖发起级与任务级自动审批。
func TestAutomaticApproval(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	design := linearDesign(workflow.Assignment{Type: workflow.AssigneeInitiator}, workflow.Completion{Mode: workflow.CompletionAny})
	design.Rules = []workflow.AutoRule{{
		ID: "auto-start", Enabled: true, Event: workflow.AutoEventStart, Scope: workflow.AutoScopeCategory,
		Match: []string{"leave"}, Decision: workflow.DecisionApprove, Priority: 10,
	}}
	f.publishDefinition(t, "auto-start", design)
	inst := f.start(t, "auto-start", nil)
	final := f.instance(t, inst.ID)
	if final.Status != workflow.InstanceCompleted || final.Outcome != "approved" {
		t.Fatalf("发起级自动审批实例 = %+v", final)
	}

	taskDesign := linearDesign(workflow.Assignment{Type: workflow.AssigneeInitiator}, workflow.Completion{Mode: workflow.CompletionAny})
	taskDesign.Rules = []workflow.AutoRule{{
		ID: "auto-task", Enabled: true, Event: workflow.AutoEventTask, Scope: workflow.AutoScopeRole,
		Match: []string{"staff"}, Decision: workflow.DecisionApprove, Priority: 10,
	}}
	f.publishDefinition(t, "auto-task", taskDesign)
	second := f.start(t, "auto-task", nil)
	if got := f.instance(t, second.ID); got.Status != workflow.InstanceCompleted {
		t.Fatalf("任务级自动审批状态 = %s", got.Status)
	}
	found := false
	for _, task := range f.listTasks(t, second.ID) {
		if task.AssigneeType == "system" && task.Decision == workflow.DecisionApprove {
			found = true
		}
	}
	if !found {
		t.Fatalf("自动审批没有留下系统任务: %+v", f.listTasks(t, second.ID))
	}
}

// fakeDecider returns a fixed AI decision. | fakeDecider 返回固定的 AI 决策。
type fakeDecider struct {
	// result is the returned decision. | result 是返回的决策。
	result workflow.DecisionResult
	// err is the returned error. | err 是返回的错误。
	err error
}

// Decide implements workflow.Decider. | Decide 实现 workflow.Decider。
func (d fakeDecider) Decide(context.Context, workflow.DecisionInput) (workflow.DecisionResult, error) {
	return d.result, d.err
}

// TestAIDeciderIntegration covers the configured and failing AI paths. | TestAIDeciderIntegration
// 覆盖 AI 决策器可用与失败两条路径。
func TestAIDeciderIntegration(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	design := linearDesign(workflow.Assignment{Type: workflow.AssigneeInitiator}, workflow.Completion{Mode: workflow.CompletionAny})
	design.Rules = []workflow.AutoRule{{
		ID: "ai", Enabled: true, Event: workflow.AutoEventTask, Scope: workflow.AutoScopeCategory,
		Match: []string{"leave"}, Decision: workflow.DecisionApprove, UseAI: true, Priority: 10,
	}}
	f.publishDefinition(t, "ai", design)
	f.svc.SetDecider(fakeDecider{result: workflow.DecisionResult{Decision: workflow.DecisionApprove, Reason: "符合政策", Confidence: 0.95}})
	inst := f.start(t, "ai", nil)
	if got := f.instance(t, inst.ID); got.Status != workflow.InstanceCompleted {
		t.Fatalf("AI 自动审批状态 = %s", got.Status)
	}

	f.svc.SetDecider(fakeDecider{err: workflow.ErrAIUnavailable})
	second := f.start(t, "ai", nil)
	if got := f.instance(t, second.ID); got.Status != workflow.InstanceRunning {
		t.Fatalf("AI 失败后退化为人工状态 = %s", got.Status)
	}
	if len(f.openTasks(t, second.ID)) != 1 {
		t.Fatalf("AI 失败后待办 = %d, 期望 1", len(f.openTasks(t, second.ID)))
	}
}

// probeDecider records whether it was invoked while a transaction callback was active. |
// probeDecider 记录自己是否在事务回调活动期间被调用。
type probeDecider struct {
	// probe observes transaction scopes. | probe 观察事务作用域。
	probe *txProbeStore
	// inside reports that at least one call saw an active transaction. | inside 表示至少一次调用发生在活动事务内。
	inside bool
	// calls counts invocations. | calls 统计调用次数。
	calls int
}

// Decide implements workflow.Decider. | Decide 实现 workflow.Decider。
func (d *probeDecider) Decide(context.Context, workflow.DecisionInput) (workflow.DecisionResult, error) {
	d.calls++
	if d.probe.inTx() {
		d.inside = true
	}
	return workflow.DecisionResult{Decision: workflow.DecisionApprove, Reason: "outside", Confidence: 0.99}, nil
}

// TestAIDeciderRunsOutsideTransaction proves the HTTP-style decider never executes while the
// engine holds a transaction (and therefore its row locks). | TestAIDeciderRunsOutsideTransaction
// 证明外部风格的决策器从不在引擎持有事务（以及行锁）期间执行。
func TestAIDeciderRunsOutsideTransaction(t *testing.T) {
	var probe *txProbeStore
	f := newFixtureWithStore(t, func(store workflow.Store) workflow.Store {
		probe = &txProbeStore{Store: store}
		return probe
	})
	defer f.close()
	design := linearDesign(workflow.Assignment{Type: workflow.AssigneeInitiator}, workflow.Completion{Mode: workflow.CompletionAny})
	design.Rules = []workflow.AutoRule{{
		ID: "ai-outside", Enabled: true, Event: workflow.AutoEventTask, Scope: workflow.AutoScopeCategory,
		Match: []string{"leave"}, Decision: workflow.DecisionApprove, UseAI: true, Priority: 10,
	}}
	f.publishDefinition(t, "ai-outside", design)
	decider := &probeDecider{probe: probe}
	f.svc.SetDecider(decider)
	inst := f.start(t, "ai-outside", map[string]any{
		"amount": 500, "level": "senior", "reason": "travel", "days": 3,
	})
	if got := f.instance(t, inst.ID); got.Status != workflow.InstanceCompleted {
		t.Fatalf("AI 自动审批状态 = %s", got.Status)
	}
	if decider.calls == 0 {
		t.Fatal("AI 决策器没有被调用")
	}
	if decider.inside {
		t.Fatal("AI 决策器在事务内执行，会长期持有行锁")
	}
	if probe.count() < 2 {
		t.Fatalf("事务次数 = %d, 期望至少 2（回滚后重放）", probe.count())
	}
}

// TestVersionIsolation covers running instances staying on their pinned version. |
// TestVersionIsolation 覆盖运行中实例绑定旧版本。
func TestVersionIsolation(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	designV1 := linearDesign(workflow.Assignment{Type: workflow.AssigneeInitiator}, workflow.Completion{Mode: workflow.CompletionAny})
	def, version := f.publishDefinition(t, "versioned", designV1)
	instV1 := f.start(t, "versioned", nil)
	designV2 := linearDesign(workflow.Assignment{Type: workflow.AssigneeUser, Values: []string{"u2"}}, workflow.Completion{Mode: workflow.CompletionAny})
	next, err := f.svc.CreateVersion(context.Background(), f.tenant, def.ID, "boss", workflow.VersionInput{Design: designV2})
	if err != nil {
		t.Fatalf("创建 v2 失败: %v", err)
	}
	versionV2, err := f.svc.PublishVersion(context.Background(), f.tenant, next.ID, "boss", "")
	if err != nil {
		t.Fatalf("发布 v2 失败: %v", err)
	}
	if version.Version != 1 || versionV2.Version != 2 {
		t.Fatalf("版本号 = %d, %d", version.Version, versionV2.Version)
	}
	instV2 := f.start(t, "versioned", nil)
	if instV1.Version != 1 || instV2.Version != 2 {
		t.Fatalf("实例版本 = %d, %d, 期望 1, 2", instV1.Version, instV2.Version)
	}
	if task := f.taskFor(t, instV1.ID, "u1"); task.NodeID != "approve" {
		t.Fatalf("v1 实例任务 = %+v", task)
	}
	if task := f.taskFor(t, instV2.ID, "u2"); task.NodeID != "approve" {
		t.Fatalf("v2 实例任务 = %+v", task)
	}
	if _, err := f.svc.UpdateVersion(context.Background(), f.tenant, version.ID, "boss", workflow.VersionInput{Design: designV2}); !errors.Is(err, workflow.ErrVersionPublished) {
		t.Fatalf("修改已发布版本错误 = %v", err)
	}
}

// TestStartPinnedVersionUsesRuntimeMeta covers the meta-read start path for both a published
// pinned version and a draft, and proves the cache does not hide a newer publication. |
// TestStartPinnedVersionUsesRuntimeMeta 覆盖已发布绑定版本与草稿的元数据读取发起路径，并证明缓存
// 不会遮蔽更新的发布。
func TestStartPinnedVersionUsesRuntimeMeta(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	designV1 := linearDesign(workflow.Assignment{Type: workflow.AssigneeInitiator}, workflow.Completion{Mode: workflow.CompletionAny})
	def, version := f.publishDefinition(t, "pinned", designV1)
	ctx := context.Background()
	first, err := f.svc.Start(ctx, f.tenant, actor("u1"), workflow.StartInput{
		DefinitionKey: "pinned", Title: "绑定 v1", Version: version.Version,
	})
	if err != nil {
		t.Fatalf("绑定已发布版本发起失败: %v", err)
	}
	if first.Version != version.Version {
		t.Fatalf("实例版本 = %d, 期望 %d", first.Version, version.Version)
	}
	// The first start caches v1; a second latest start must still resolve v1 from that cache. |
	// 第一次发起缓存了 v1；第二次按最新发起仍应从该缓存解析到 v1。
	second, err := f.svc.Start(ctx, f.tenant, actor("u1"), workflow.StartInput{DefinitionKey: "pinned", Title: "最新 v1"})
	if err != nil {
		t.Fatalf("缓存命中后发起失败: %v", err)
	}
	if second.Version != version.Version {
		t.Fatalf("缓存命中实例版本 = %d, 期望 %d", second.Version, version.Version)
	}
	draft, err := f.svc.CreateVersion(ctx, f.tenant, def.ID, "boss", workflow.VersionInput{Design: designV1})
	if err != nil {
		t.Fatalf("创建草稿失败: %v", err)
	}
	if _, err := f.svc.Start(ctx, f.tenant, actor("u1"), workflow.StartInput{
		DefinitionKey: "pinned", Title: "草稿", Version: draft.Version,
	}); !errors.Is(err, workflow.ErrInvalidInput) {
		t.Fatalf("绑定草稿发起错误 = %v, 期望 ErrInvalidInput", err)
	}
}

// TestTenantIsolation covers the hard tenant boundary. | TestTenantIsolation 覆盖租户硬边界。
func TestTenantIsolation(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	def, _ := f.publishDefinition(t, "tenant", linearDesign(workflow.Assignment{Type: workflow.AssigneeInitiator}, workflow.Completion{Mode: workflow.CompletionAny}))
	inst := f.start(t, "tenant", nil)
	if _, err := f.svc.GetDefinition(context.Background(), "tn_other", def.ID); !errors.Is(err, workflow.ErrNotFound) {
		t.Fatalf("跨租户读定义错误 = %v", err)
	}
	if _, err := f.svc.GetInstance(context.Background(), "tn_other", inst.ID); !errors.Is(err, workflow.ErrNotFound) {
		t.Fatalf("跨租户读实例错误 = %v", err)
	}
	task := f.taskFor(t, inst.ID, "u1")
	if _, err := f.svc.Approve(context.Background(), "tn_other", actor("u1"), task.ID, workflow.ActionInput{Decision: workflow.DecisionApprove}); !errors.Is(err, workflow.ErrNotFound) {
		t.Fatalf("跨租户处理任务错误 = %v", err)
	}
}

// TestFormValidation covers start and task form validation. | TestFormValidation 覆盖发起与任务表单校验。
func TestFormValidation(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	design := linearDesign(workflow.Assignment{Type: workflow.AssigneeInitiator}, workflow.Completion{Mode: workflow.CompletionAny})
	design.Forms["start"] = []workflow.FormField{
		{Key: "amount", Label: "金额", Type: "number", Required: true, Min: 1, Max: 1000},
		{Key: "reason", Label: "事由", Type: "text", Required: true, MaxLength: 20},
	}
	design.Nodes[1].Form = []workflow.FormField{{Key: "note", Label: "意见", Type: "text", Required: true}}
	f.publishDefinition(t, "form", design)
	if _, err := f.svc.Start(context.Background(), f.tenant, actor("u1"), workflow.StartInput{
		DefinitionKey: "form", Title: "缺字段", FormData: map[string]any{"amount": 10},
	}); !errors.Is(err, workflow.ErrInvalidForm) {
		t.Fatalf("缺必填字段错误 = %v", err)
	}
	if _, err := f.svc.Start(context.Background(), f.tenant, actor("u1"), workflow.StartInput{
		DefinitionKey: "form", Title: "超范围", FormData: map[string]any{"amount": 2000, "reason": "测试"},
	}); !errors.Is(err, workflow.ErrInvalidForm) {
		t.Fatalf("数值超范围错误 = %v", err)
	}
	inst := f.start(t, "form", map[string]any{"amount": 10, "reason": "测试"})
	task := f.taskFor(t, inst.ID, "u1")
	if _, err := f.svc.Approve(context.Background(), f.tenant, actor("u1"), task.ID, workflow.ActionInput{Decision: workflow.DecisionApprove}); !errors.Is(err, workflow.ErrInvalidForm) {
		t.Fatalf("任务表单缺字段错误 = %v", err)
	}
	if _, err := f.svc.Approve(context.Background(), f.tenant, actor("u1"), task.ID, workflow.ActionInput{
		Decision: workflow.DecisionApprove, FormData: map[string]any{"note": "同意"},
	}); err != nil {
		t.Fatalf("任务表单通过失败: %v", err)
	}
}

// TestConcurrentGrabIsAtomic covers two claimers racing for one task. | TestConcurrentGrabIsAtomic
// 覆盖两人并发抢同一任务。
func TestConcurrentGrabIsAtomic(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	f.publishDefinition(t, "atomic", linearDesign(
		workflow.Assignment{Type: workflow.AssigneeUser, Values: []string{"u1", "u2"}, Claim: workflow.ClaimGrab},
		workflow.Completion{Mode: workflow.CompletionAny},
	))
	inst := f.start(t, "atomic", nil)
	var target workflow.Task
	for _, task := range f.listTasks(t, inst.ID) {
		if task.Status == workflow.TaskPending && len(task.Candidates) > 0 {
			target = task
			break
		}
	}
	if target.ID == "" {
		t.Fatal("没有候选任务")
	}
	results := make(chan error, 2)
	for _, user := range []string{"u1", "u2"} {
		go func(userID string) {
			_, err := f.svc.Claim(context.Background(), f.tenant, actor(userID), target.ID)
			results <- err
		}(user)
	}
	success := 0
	var failures []string
	for i := 0; i < 2; i++ {
		if err := <-results; err == nil {
			success++
		} else {
			failures = append(failures, err.Error())
		}
	}
	if success != 1 {
		t.Fatalf("并发签收成功数 = %d, 期望 1, 错误 = %v", success, failures)
	}
}

// TestSchedulerReminderIsClaimedOnce covers multi-node reminder de-duplication. |
// TestSchedulerReminderIsClaimedOnce 覆盖多节点催办只触发一次。
func TestSchedulerReminderIsClaimedOnce(t *testing.T) {
	f := newFixture(t)
	defer f.close()
	f.publishDefinition(t, "remind", linearDesign(
		workflow.Assignment{Type: workflow.AssigneeInitiator},
		workflow.Completion{Mode: workflow.CompletionAny},
	))
	inst := f.start(t, "remind", nil)
	f.clock.Advance(73 * time.Hour)
	second, err := workflow.New(f.store, workflow.Deps{Directory: f.dir, Options: workflow.Options{Now: f.clock.Now}})
	if err != nil {
		t.Fatalf("构建第二节点失败: %v", err)
	}
	firstReport, err := f.svc.RunDue(context.Background(), 10)
	if err != nil {
		t.Fatalf("节点一扫描失败: %v", err)
	}
	secondReport, err := second.RunDue(context.Background(), 10)
	if err != nil {
		t.Fatalf("节点二扫描失败: %v", err)
	}
	if firstReport.Reminded+secondReport.Reminded != 1 {
		t.Fatalf("催办次数 = %d + %d, 期望合计 1", firstReport.Reminded, secondReport.Reminded)
	}
	task := f.taskFor(t, inst.ID, "u1")
	if task.RemindCount != 1 {
		t.Fatalf("任务催办计数 = %d, 期望 1", task.RemindCount)
	}
}
