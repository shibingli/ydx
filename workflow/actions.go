package workflow

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
	ydlog "github.com/shibingli/ydx/log"
)

// ActionInput is one approve or reject decision. | ActionInput 是一次通过或驳回决策。
type ActionInput struct {
	// FormData is the node form submission. | FormData 是节点表单提交。
	FormData map[string]any
	// Decision is approve or reject. | Decision 取 approve 或 reject。
	Decision string
	// Comment is the approver's note. | Comment 是审批意见。
	Comment string
}

// TransferInput is one transfer request. | TransferInput 是一次转办请求。
type TransferInput struct {
	// TargetID is the new assignee. | TargetID 是新的处理人。
	TargetID string
	// Comment explains the transfer. | Comment 说明转办原因。
	Comment string
}

// DelegateInput is one delegation request. | DelegateInput 是一次委派请求。
type DelegateInput struct {
	// TargetID is the delegate. | TargetID 是受托人。
	TargetID string
	// Comment explains the delegation. | Comment 说明委派原因。
	Comment string
}

// AddSignInput is one add-sign request. | AddSignInput 是一次加签请求。
type AddSignInput struct {
	// Position is before or after; empty means after. | Position 取 before 或 after；空表示后加签。
	Position string
	// Comment explains the addition. | Comment 说明加签原因。
	Comment string
	// UserIDs are the added approvers. | UserIDs 是新增审批人。
	UserIDs []string
}

// ReturnInput is one return request. | ReturnInput 是一次退回请求。
type ReturnInput struct {
	// TargetNodeID is a visited user task or InitiatorNodeID. | TargetNodeID 是访问过的用户任务或 InitiatorNodeID。
	TargetNodeID string
	// Comment explains the return. | Comment 说明退回原因。
	Comment string
}

// ReasonInput is one withdrawal or termination request. | ReasonInput 是一次撤回或终止请求。
type ReasonInput struct {
	// Reason explains the terminal action. | Reason 说明终止动作的原因。
	Reason string
}

// CommentInput is one free-form comment. | CommentInput 是一条自由评论。
type CommentInput struct {
	// Body is the comment text. | Body 是评论正文。
	Body string
}

// ListInstances returns one page of instances with the lean list projection: variable and node
// snapshot payloads are omitted and remain available through InstanceDetail. | ListInstances
// 返回一页实例，使用精简列表投影：变量与节点快照载荷被省略，仍可经 InstanceDetail 读取。
func (s *Service) ListInstances(ctx context.Context, tenantID string, filter InstanceFilter) (InstancePage, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return InstancePage{}, ErrInvalidInput
	}
	filter.Query = strings.TrimSpace(filter.Query)
	if filter.Status != "" {
		switch filter.Status {
		case InstanceRunning, InstanceCompleted, InstanceWithdrawn, InstanceTerminated:
		default:
			return InstancePage{}, ErrInvalidInput
		}
	}
	filter.Page, filter.PageSize = s.page(filter.Page, filter.PageSize)
	// A list never renders variables or node snapshots; omitting them bounds the response by the
	// page rather than by the largest payload any instance ever carried. | 列表从不渲染变量或节点快照；
	// 省略它们使响应大小由页长决定，而不是由某个实例曾携带的最大载荷决定。
	filter.Lean = true
	items, total, err := s.store.ListInstances(ctx, tenantID, filter)
	if err != nil {
		return InstancePage{}, err
	}
	return InstancePage{Items: items, Total: total, Page: filter.Page, PageSize: filter.PageSize}, nil
}

// GetInstance reads one instance inside the tenant. | GetInstance 读取租户内的一个实例。
func (s *Service) GetInstance(ctx context.Context, tenantID, instanceID string) (Instance, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(instanceID) == "" {
		return Instance{}, ErrInvalidInput
	}
	return s.store.GetInstance(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(instanceID))
}

// InstanceDetail assembles the full audit view of one instance. | InstanceDetail 组装一个实例的完整审计视图。
func (s *Service) InstanceDetail(ctx context.Context, tenantID, instanceID string) (InstanceDetail, error) {
	tenantID = strings.TrimSpace(tenantID)
	inst, err := s.store.GetInstance(ctx, tenantID, instanceID)
	if err != nil {
		return InstanceDetail{}, err
	}
	def, err := s.store.GetDefinition(ctx, tenantID, inst.DefinitionID)
	if err != nil {
		return InstanceDetail{}, err
	}
	version, design, err := s.loadVersion(ctx, s.store, tenantID, inst.VersionID)
	if err != nil {
		return InstanceDetail{}, err
	}
	tasks, err := s.instanceTasks(ctx, tenantID, inst.ID)
	if err != nil {
		return InstanceDetail{}, err
	}
	events, err := s.store.ListEvents(ctx, tenantID, inst.ID, 500)
	if err != nil {
		return InstanceDetail{}, err
	}
	comments, err := s.store.ListComments(ctx, tenantID, inst.ID, 500)
	if err != nil {
		return InstanceDetail{}, err
	}
	variables, err := ParseVariables(inst.Variables)
	if err != nil {
		return InstanceDetail{}, err
	}
	return InstanceDetail{
		Instance:   inst,
		Definition: def,
		Version:    version,
		Design:     design,
		Tasks:      tasks,
		Events:     events,
		Comments:   comments,
		Variables:  variables,
	}, nil
}

// instanceTasks lists every task of one instance. | instanceTasks 列出一个实例的全部任务。
func (s *Service) instanceTasks(ctx context.Context, tenantID, instanceID string) ([]Task, error) {
	items, _, err := s.store.ListTasks(ctx, tenantID, TaskFilter{InstanceID: instanceID, Page: 1, PageSize: s.options.MaxPageSize})
	if err != nil {
		return nil, err
	}
	if len(items) < s.options.MaxPageSize {
		return items, nil
	}
	all := items
	for page := 2; ; page++ {
		next, _, err := s.store.ListTasks(ctx, tenantID, TaskFilter{InstanceID: instanceID, Page: page, PageSize: s.options.MaxPageSize})
		if err != nil {
			return nil, err
		}
		if len(next) == 0 {
			break
		}
		all = append(all, next...)
		if len(next) < s.options.MaxPageSize {
			break
		}
	}
	return all, nil
}

// ListTasks returns one page of tasks. | ListTasks 返回一页任务。
func (s *Service) ListTasks(ctx context.Context, tenantID string, filter TaskFilter) (TaskPage, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return TaskPage{}, ErrInvalidInput
	}
	filter.Query = strings.TrimSpace(filter.Query)
	filter.Page, filter.PageSize = s.page(filter.Page, filter.PageSize)
	items, total, err := s.store.ListTasks(ctx, tenantID, filter)
	if err != nil {
		return TaskPage{}, err
	}
	return TaskPage{Items: items, Total: total, Page: filter.Page, PageSize: filter.PageSize}, nil
}

// GetTask reads one task inside the tenant. | GetTask 读取租户内的一个任务。
func (s *Service) GetTask(ctx context.Context, tenantID, taskID string) (Task, error) {
	tenantID = strings.TrimSpace(tenantID)
	taskID = strings.TrimSpace(taskID)
	if tenantID == "" || taskID == "" {
		return Task{}, ErrInvalidInput
	}
	return s.store.GetTask(ctx, tenantID, taskID)
}

// TaskDetail assembles the full view of one task. | TaskDetail 组装一个任务的完整视图。
func (s *Service) TaskDetail(ctx context.Context, tenantID, taskID string) (TaskDetail, error) {
	tenantID = strings.TrimSpace(tenantID)
	task, err := s.loadTaskRow(ctx, s.store, tenantID, taskID)
	if err != nil {
		return TaskDetail{}, err
	}
	inst, err := s.store.GetInstance(ctx, tenantID, task.InstanceID)
	if err != nil {
		return TaskDetail{}, err
	}
	task.applyInstanceProjection(inst)
	def, err := s.store.GetDefinition(ctx, tenantID, inst.DefinitionID)
	if err != nil {
		return TaskDetail{}, err
	}
	version, design, err := s.loadVersion(ctx, s.store, tenantID, inst.VersionID)
	if err != nil {
		return TaskDetail{}, err
	}
	node, ok := design.FindNode(task.NodeID)
	if !ok && task.NodeID == InitiatorNodeID {
		node = Node{ID: InitiatorNodeID, Type: NodeUserTask, Name: "重新提交 | Revise"}
	}
	comments, err := s.store.ListComments(ctx, tenantID, inst.ID, 500)
	if err != nil {
		return TaskDetail{}, err
	}
	variables, err := ParseVariables(inst.Variables)
	if err != nil {
		return TaskDetail{}, err
	}
	return TaskDetail{
		Task:       task,
		Instance:   inst,
		Definition: def,
		Version:    version,
		Design:     design,
		Node:       node,
		Variables:  variables,
		Comments:   comments,
	}, nil
}

// Claim acknowledges a task. It is an atomic compare-and-set, so two claimers cannot both win. |
// Claim 签收任务。它是原子比较并写入，两个抢单者不可能都成功。
func (s *Service) Claim(ctx context.Context, tenantID string, actor Actor, taskID string) (Task, error) {
	tenantID = strings.TrimSpace(tenantID)
	taskID = strings.TrimSpace(taskID)
	if tenantID == "" || taskID == "" || strings.TrimSpace(actor.ID) == "" {
		return Task{}, ErrInvalidInput
	}
	var claimed Task
	err := s.store.WithTx(ctx, func(st Store) error {
		inst, task, err := s.loadTaskRuntime(ctx, st, tenantID, taskID)
		if err != nil {
			return err
		}
		if inst.Status != InstanceRunning {
			return ErrInstanceClosed
		}
		if task.Status != TaskPending {
			if task.Status == TaskClaimed && task.AssigneeID == actor.ID {
				claimed = task
				return nil
			}
			return ErrTaskClosed
		}
		if task.AssigneeID != "" && task.AssigneeID != actor.ID {
			return ErrTaskNotMine
		}
		if len(task.Candidates) > 0 && !containsFold(task.Candidates, actor.ID) {
			return ErrTaskNotMine
		}
		updated, err := st.ClaimTask(ctx, tenantID, task.ID, actor.ID, actor.Name, s.now())
		if err != nil {
			return err
		}
		rt, err := s.loadRuntimeFor(ctx, st, tenantID, inst)
		if err != nil {
			return err
		}
		rt.event(ctx, EventTaskClaimed, updated.ID, updated.NodeID, actor.ID, actor.Name, "任务已签收 | task claimed", "")
		updated.applyInstanceProjection(inst)
		claimed = updated
		return nil
	})
	if err != nil {
		return Task{}, err
	}
	return claimed, nil
}

// Approve records one approve or reject decision and advances the node when it is decided. |
// Approve 记录一次通过或驳回决策，并在节点完成时推进流程。
func (s *Service) Approve(ctx context.Context, tenantID string, actor Actor, taskID string, in ActionInput) (Task, error) {
	tenantID = strings.TrimSpace(tenantID)
	taskID = strings.TrimSpace(taskID)
	in.Decision = strings.ToLower(strings.TrimSpace(in.Decision))
	if tenantID == "" || taskID == "" || strings.TrimSpace(actor.ID) == "" {
		return Task{}, ErrInvalidInput
	}
	if in.Decision != DecisionApprove && in.Decision != DecisionReject {
		return Task{}, ErrInvalidInput
	}
	comment, ok := trimLen(in.Comment, s.options.MaxCommentLen)
	if !ok {
		return Task{}, ErrInvalidInput
	}
	var result Task
	var notes []Notification
	err := s.store.WithTx(ctx, func(st Store) error {
		inst, task, err := s.loadTaskRuntime(ctx, st, tenantID, taskID)
		if err != nil {
			return err
		}
		if inst.Status != InstanceRunning {
			return ErrInstanceClosed
		}
		if task.Status == TaskQueued {
			return errs.Detail(ErrTaskClosed, "the task is queued | 任务仍在排队")
		}
		if task.Status != TaskPending && task.Status != TaskClaimed {
			return ErrTaskClosed
		}
		rt, err := s.loadRuntimeFor(ctx, st, tenantID, inst)
		if err != nil {
			return err
		}
		node, synthetic := s.taskNode(rt.design, task.NodeID)
		if !synthetic {
			if node.Assignee.Claim != ClaimAssigned && task.AssigneeID == "" {
				return errs.Detail(ErrTaskNotMine, "claim the task before acting | 请先签收任务再处理")
			}
			if node.Assignee.Claim == ClaimGrab && task.AssigneeID == "" {
				return errs.Detail(ErrTaskNotMine, "claim the task before acting | 请先签收任务再处理")
			}
		}
		if !actor.Admin && task.AssigneeID != actor.ID {
			return ErrTaskNotMine
		}
		if task.DelegatedTo != "" {
			if err := s.handBackDelegation(ctx, rt, &task, actor, in.Decision, comment); err != nil {
				return err
			}
			result = task
			notes = rt.notes
			return nil
		}
		if in.Decision == DecisionApprove {
			if err := s.validateSubmittedForm(node.Form, in.FormData); err != nil {
				return err
			}
			rt.mergeFormData(in.FormData)
		}
		task.Status = TaskCompleted
		task.Decision = in.Decision
		task.Comment = comment
		task.FormData = taskJSON(in.FormData)
		task.CompletedAt = rt.now
		task.UpdatedAt = rt.now
		if err := st.UpdateTask(ctx, task); err != nil {
			return err
		}
		if comment != "" {
			s.appendComment(ctx, rt, task.ID, actor, comment, "comment")
		}
		eventType := EventTaskApproved
		if in.Decision == DecisionReject {
			eventType = EventTaskRejected
		}
		rt.event(ctx, eventType, task.ID, task.NodeID, actor.ID, actor.Name, comment, "")
		token, err := st.GetToken(ctx, tenantID, task.TokenID)
		if err != nil {
			return err
		}
		if synthetic {
			token.Status = TokenCompleted
			token.UpdatedAt = rt.now
			if err := st.UpdateToken(ctx, token); err != nil {
				return err
			}
			if in.Decision == DecisionReject {
				if err := s.finishInstance(ctx, rt, InstanceTerminated, "rejected", comment, actor); err != nil {
					return err
				}
			} else {
				start, ok := designStartNode(rt.design)
				if !ok {
					return ErrInvalidDesign
				}
				token.NodeID = start.ID
				token.Status = TokenActive
				token.UpdatedAt = rt.now
				if err := st.UpdateToken(ctx, token); err != nil {
					return err
				}
				tx := rt
				if err := s.advance(ctx, tx, &token); err != nil {
					return err
				}
			}
			if err := rt.persistRuntime(ctx); err != nil {
				return err
			}
			result = task
			notes = rt.notes
			return nil
		}
		decision, err := s.evaluateCompletion(ctx, rt, &token, node)
		if err != nil {
			return err
		}
		if decision == DecisionNone {
			if node.Completion.Sequential {
				if _, _, err := s.promoteQueuedTask(ctx, rt, token.ID); err != nil {
					return err
				}
			}
			if err := rt.refreshCurrentNodes(ctx); err != nil {
				return err
			}
			if err := rt.persistRuntime(ctx); err != nil {
				return err
			}
			result = task
			notes = rt.notes
			return nil
		}
		if err := s.cancelOpenTasks(ctx, rt, token.ID, "node decided | 节点已决策"); err != nil {
			return err
		}
		tx := rt
		if err := s.completeNode(ctx, tx, &token, node, decision, actor.ID, actor.Name, comment); err != nil {
			return err
		}
		if err := rt.refreshCurrentNodes(ctx); err != nil {
			return err
		}
		if err := rt.persistRuntime(ctx); err != nil {
			return err
		}
		result = task
		notes = rt.notes
		return nil
	})
	if err != nil {
		return Task{}, err
	}
	s.flushNotifications(ctx, notes)
	return result, nil
}

// handBackDelegation completes the delegate step and returns the task to its owner. |
// handBackDelegation 完成受托步骤并把任务交还原指派人。
func (s *Service) handBackDelegation(ctx context.Context, tx *runtimeTxn, task *Task, actor Actor, decision, comment string) error {
	if !actor.Admin && task.AssigneeID != actor.ID {
		return ErrTaskNotMine
	}
	if comment != "" {
		s.appendComment(ctx, tx, task.ID, actor, "委派处理（"+decision+"）："+comment+" | delegated ("+decision+"): "+comment, "comment")
	}
	task.AssigneeID = task.OriginalAssigneeID
	task.AssigneeName = task.OriginalAssigneeName
	task.OriginalAssigneeID = ""
	task.OriginalAssigneeName = ""
	task.DelegatedTo = ""
	task.DelegatedFrom = actor.ID
	task.Status = TaskPending
	task.UpdatedAt = tx.now
	if err := tx.st.UpdateTask(ctx, *task); err != nil {
		return err
	}
	tx.event(ctx, EventTaskDelegatedBack, task.ID, task.NodeID, actor.ID, actor.Name, comment, "")
	tx.notify(ctx, NotifyDelegated, task.AssigneeID, task.ID, task.NodeName)
	return tx.persistRuntime(ctx)
}

// Transfer changes the assignee of one open task. | Transfer 变更一个未结束任务的处理人。
func (s *Service) Transfer(ctx context.Context, tenantID string, actor Actor, taskID string, in TransferInput) (Task, error) {
	return s.reassign(ctx, tenantID, actor, taskID, in.TargetID, in.Comment, false)
}

// Delegate hands one open task to a delegate and keeps the owner for final confirmation. |
// Delegate 把未结束任务交给受托人，并保留原指派人做最终确认。
func (s *Service) Delegate(ctx context.Context, tenantID string, actor Actor, taskID string, in DelegateInput) (Task, error) {
	return s.reassign(ctx, tenantID, actor, taskID, in.TargetID, in.Comment, true)
}

// reassign implements transfer and delegation. | reassign 实现转办与委派。
func (s *Service) reassign(ctx context.Context, tenantID string, actor Actor, taskID, targetID, comment string, delegate bool) (Task, error) {
	tenantID = strings.TrimSpace(tenantID)
	taskID = strings.TrimSpace(taskID)
	targetID = strings.TrimSpace(targetID)
	if tenantID == "" || taskID == "" || targetID == "" || strings.TrimSpace(actor.ID) == "" {
		return Task{}, ErrInvalidInput
	}
	comment, ok := trimLen(comment, s.options.MaxCommentLen)
	if !ok {
		return Task{}, ErrInvalidInput
	}
	if s.directory == nil {
		return Task{}, ErrUnavailable
	}
	target, err := s.directory.User(ctx, tenantID, targetID)
	if err != nil {
		return Task{}, err
	}
	var updated Task
	var notes []Notification
	err = s.store.WithTx(ctx, func(st Store) error {
		inst, task, err := s.loadTaskRuntime(ctx, st, tenantID, taskID)
		if err != nil {
			return err
		}
		if inst.Status != InstanceRunning {
			return ErrInstanceClosed
		}
		rt, err := s.loadRuntimeFor(ctx, st, tenantID, inst)
		if err != nil {
			return err
		}
		if delegate && rt.design.Settings.ForbidDelegate {
			return errs.Detail(ErrForbidden, "delegation is disabled by the process | 流程已关闭委派")
		}
		if !actor.Admin && task.AssigneeID != actor.ID {
			return ErrTaskNotMine
		}
		if task.Status != TaskPending && task.Status != TaskClaimed {
			return ErrTaskClosed
		}
		if delegate {
			if task.OriginalAssigneeID == "" {
				task.OriginalAssigneeID = task.AssigneeID
				task.OriginalAssigneeName = task.AssigneeName
			}
			task.DelegatedTo = target.ID
		} else {
			task.AssigneeID = target.ID
			task.AssigneeName = target.Name
			task.DelegatedTo = ""
			task.DelegatedFrom = ""
			task.OriginalAssigneeID = ""
			task.OriginalAssigneeName = ""
		}
		task.AssigneeID = target.ID
		task.AssigneeName = target.Name
		task.Status = TaskPending
		task.UpdatedAt = rt.now
		if err := st.UpdateTask(ctx, task); err != nil {
			return err
		}
		eventType := EventTaskTransferred
		if delegate {
			eventType = EventTaskDelegated
		}
		rt.event(ctx, eventType, task.ID, task.NodeID, actor.ID, actor.Name, comment, "")
		if comment != "" {
			s.appendComment(ctx, rt, task.ID, actor, comment, "comment")
		}
		kind := NotifyDelegated
		if !delegate {
			kind = NotifyAssigned
		}
		rt.notify(ctx, kind, target.ID, task.ID, task.NodeName)
		if err := txPersist(rt, ctx); err != nil {
			return err
		}
		updated = task
		notes = rt.notes
		return nil
	})
	if err != nil {
		return Task{}, err
	}
	s.flushNotifications(ctx, notes)
	return updated, nil
}

// txPersist is a tiny indirection kept for readability. | txPersist 是一个保持可读性的小间接调用。
func txPersist(tx *runtimeTxn, ctx context.Context) error { return tx.persistRuntime(ctx) }

// AddSign adds approvers to a running node. | AddSign 为运行中的节点增加审批人。
func (s *Service) AddSign(ctx context.Context, tenantID string, actor Actor, taskID string, in AddSignInput) ([]Task, error) {
	tenantID = strings.TrimSpace(tenantID)
	taskID = strings.TrimSpace(taskID)
	if tenantID == "" || taskID == "" || len(in.UserIDs) == 0 || strings.TrimSpace(actor.ID) == "" {
		return nil, ErrInvalidInput
	}
	if s.directory == nil {
		return nil, ErrUnavailable
	}
	users, err := s.directory.Users(ctx, tenantID, in.UserIDs)
	if err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return nil, ErrNoAssignee
	}
	comment, ok := trimLen(in.Comment, s.options.MaxCommentLen)
	if !ok {
		return nil, ErrInvalidInput
	}
	position := strings.ToLower(strings.TrimSpace(in.Position))
	if position == "" {
		position = "after"
	}
	if position != "before" && position != "after" {
		return nil, ErrInvalidInput
	}
	var created []Task
	var notes []Notification
	err = s.store.WithTx(ctx, func(st Store) error {
		inst, task, err := s.loadTaskRuntime(ctx, st, tenantID, taskID)
		if err != nil {
			return err
		}
		if inst.Status != InstanceRunning {
			return ErrInstanceClosed
		}
		rt, err := s.loadRuntimeFor(ctx, st, tenantID, inst)
		if err != nil {
			return err
		}
		if rt.design.Settings.ForbidAddSign {
			return errs.Detail(ErrForbidden, "add-sign is disabled by the process | 流程已关闭加签")
		}
		if !actor.Admin && task.AssigneeID != actor.ID {
			return ErrTaskNotMine
		}
		node, ok := rt.design.FindNode(task.NodeID)
		if !ok {
			return ErrInvalidDesign
		}
		if task.Status != TaskPending && task.Status != TaskClaimed && task.Status != TaskQueued {
			return ErrTaskClosed
		}
		existing, err := st.ListTasksByToken(ctx, tenantID, task.TokenID)
		if err != nil {
			return err
		}
		maxSeq := 0
		for _, item := range existing {
			if item.Seq > maxSeq {
				maxSeq = item.Seq
			}
		}
		baseSeq := maxSeq + 1
		if node.Completion.Sequential && position == "before" {
			for i := range existing {
				if existing[i].Status == TaskPending || existing[i].Status == TaskClaimed {
					existing[i].Status = TaskQueued
					existing[i].UpdatedAt = rt.now
					if err := st.UpdateTask(ctx, existing[i]); err != nil {
						return err
					}
				}
			}
			// Negative sequence numbers sort ahead of every existing task, so the newly added
			// approvers become the next queued tasks without renumbering the rest. |
			// 负序号排在任何既有任务之前，因此新增审批人成为下一批排队任务，而无需重排其余任务。
			baseSeq = -len(users)
		}
		for i, user := range users {
			status := TaskPending
			if node.Completion.Sequential {
				status = TaskQueued
			}
			seq := baseSeq + i
			newTask, err := s.createTask(ctx, rt, &Token{ID: task.TokenID, TenantID: tenantID, InstanceID: inst.ID}, node, user, seq, status)
			if err != nil {
				return err
			}
			created = append(created, newTask)
		}
		if node.Completion.Sequential {
			if _, _, err := s.promoteQueuedTask(ctx, rt, task.TokenID); err != nil {
				return err
			}
		}
		rt.event(ctx, EventTaskAdded, task.ID, task.NodeID, actor.ID, actor.Name, comment, "")
		if comment != "" {
			s.appendComment(ctx, rt, task.ID, actor, comment, "comment")
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
		return nil, err
	}
	s.flushNotifications(ctx, notes)
	return created, nil
}

// RemoveSign cancels one queued or pending task of a running node. | RemoveSign 取消运行中节点的一条排队或待处理任务。
func (s *Service) RemoveSign(ctx context.Context, tenantID string, actor Actor, taskID, targetTaskID, comment string) error {
	tenantID = strings.TrimSpace(tenantID)
	taskID = strings.TrimSpace(taskID)
	targetTaskID = strings.TrimSpace(targetTaskID)
	if tenantID == "" || taskID == "" || targetTaskID == "" || strings.TrimSpace(actor.ID) == "" {
		return ErrInvalidInput
	}
	comment, ok := trimLen(comment, s.options.MaxCommentLen)
	if !ok {
		return ErrInvalidInput
	}
	var notes []Notification
	err := s.store.WithTx(ctx, func(st Store) error {
		inst, task, err := s.loadTaskRuntime(ctx, st, tenantID, taskID)
		if err != nil {
			return err
		}
		if inst.Status != InstanceRunning {
			return ErrInstanceClosed
		}
		rt, err := s.loadRuntimeFor(ctx, st, tenantID, inst)
		if err != nil {
			return err
		}
		if rt.design.Settings.ForbidAddSign {
			return errs.Detail(ErrForbidden, "remove-sign is disabled by the process | 流程已关闭减签")
		}
		if !actor.Admin && task.AssigneeID != actor.ID {
			return ErrTaskNotMine
		}
		target, err := s.loadTaskRow(ctx, st, tenantID, targetTaskID)
		if err != nil {
			return err
		}
		if target.TokenID != task.TokenID || target.Status == TaskCompleted || target.Status == TaskCancelled {
			return ErrTaskClosed
		}
		open, err := st.ListTasksByToken(ctx, tenantID, target.TokenID)
		if err != nil {
			return err
		}
		live := 0
		for _, item := range open {
			if item.Status != TaskCancelled && item.Status != TaskCompleted {
				live++
			}
		}
		if live <= 1 {
			return errs.Detail(ErrConflict, "the last open task cannot be removed | 最后一条未结束任务不可减签")
		}
		target.Status = TaskCancelled
		target.Comment = comment
		target.UpdatedAt = rt.now
		if err := st.UpdateTask(ctx, target); err != nil {
			return err
		}
		node, _ := rt.design.FindNode(target.NodeID)
		if node.Completion.Sequential {
			if _, _, err := s.promoteQueuedTask(ctx, rt, target.TokenID); err != nil {
				return err
			}
		}
		rt.event(ctx, EventTaskRemoved, target.ID, target.NodeID, actor.ID, actor.Name, comment, "")
		if comment != "" {
			s.appendComment(ctx, rt, target.ID, actor, comment, "comment")
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
		return err
	}
	s.flushNotifications(ctx, notes)
	return nil
}

// Return sends the instance back to a visited user task or to the initiator. The target must
// appear in the instance trace, so a return cannot invent a shortcut. | Return 把实例退回访问过的
// 用户任务或发起人。目标必须出现在实例轨迹中，因此退回不能凭空制造捷径。
func (s *Service) Return(ctx context.Context, tenantID string, actor Actor, taskID string, in ReturnInput) error {
	tenantID = strings.TrimSpace(tenantID)
	taskID = strings.TrimSpace(taskID)
	target := strings.TrimSpace(in.TargetNodeID)
	if tenantID == "" || taskID == "" || target == "" || strings.TrimSpace(actor.ID) == "" {
		return ErrInvalidInput
	}
	comment, ok := trimLen(in.Comment, s.options.MaxCommentLen)
	if !ok {
		return ErrInvalidInput
	}
	var notes []Notification
	err := s.store.WithTx(ctx, func(st Store) error {
		inst, task, err := s.loadTaskRuntime(ctx, st, tenantID, taskID)
		if err != nil {
			return err
		}
		if inst.Status != InstanceRunning {
			return ErrInstanceClosed
		}
		rt, err := s.loadRuntimeFor(ctx, st, tenantID, inst)
		if err != nil {
			return err
		}
		if rt.design.Settings.ForbidReturn {
			return errs.Detail(ErrForbidden, "return is disabled by the process | 流程已关闭退回")
		}
		if !actor.Admin && task.AssigneeID != actor.ID {
			return ErrTaskNotMine
		}
		if task.Status != TaskPending && task.Status != TaskClaimed {
			return ErrTaskClosed
		}
		visited := DecodeStringList(inst.VisitedNodes)
		if target != InitiatorNodeID && !containsFold(visited, target) {
			return errs.Detail(ErrInvalidInput, "target %[1]q is not in the instance trace | 目标 %[1]q 不在实例轨迹中", target)
		}
		if target != InitiatorNodeID {
			node, ok := rt.design.FindNode(target)
			if !ok || node.Type != NodeUserTask {
				return ErrInvalidInput
			}
		}
		if err := s.cancelLiveWork(ctx, rt, "returned | 已退回"); err != nil {
			return err
		}
		trimmed := make([]string, 0, len(visited))
		for _, id := range visited {
			trimmed = append(trimmed, id)
			if id == target {
				break
			}
		}
		if target == InitiatorNodeID {
			trimmed = nil
		}
		rt.inst.VisitedNodes = EncodeStringList(trimmed)
		inst = *rt.inst
		tokenID, err := s.options.NewID("wftok_")
		if err != nil {
			return errs.Wrap(err, ErrUnavailable)
		}
		token := Token{
			CreatedAt:  rt.now,
			UpdatedAt:  rt.now,
			ID:         tokenID,
			TenantID:   tenantID,
			InstanceID: inst.ID,
			NodeID:     target,
			Status:     TokenActive,
		}
		if err := st.CreateToken(ctx, token); err != nil {
			return err
		}
		rt.event(ctx, EventTaskReturned, task.ID, task.NodeID, actor.ID, actor.Name, comment, "")
		if comment != "" {
			s.appendComment(ctx, rt, task.ID, actor, comment, "comment")
		}
		if err := s.advance(ctx, rt, &token); err != nil {
			return err
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
		return err
	}
	s.flushNotifications(ctx, notes)
	return nil
}

// WithdrawInstance withdraws a running instance inside the configured window; an administrator
// is not bounded by the window. | WithdrawInstance 在配置窗口内撤回运行中实例；管理员不受窗口限制。
func (s *Service) WithdrawInstance(ctx context.Context, tenantID string, actor Actor, instanceID string, in ReasonInput) error {
	tenantID = strings.TrimSpace(tenantID)
	instanceID = strings.TrimSpace(instanceID)
	if tenantID == "" || instanceID == "" || strings.TrimSpace(actor.ID) == "" {
		return ErrInvalidInput
	}
	reason, ok := trimLen(in.Reason, 500)
	if !ok {
		return ErrInvalidInput
	}
	var notes []Notification
	err := s.store.WithTx(ctx, func(st Store) error {
		inst, err := st.GetInstance(ctx, tenantID, instanceID)
		if err != nil {
			return err
		}
		if inst.Status != InstanceRunning {
			return ErrInstanceClosed
		}
		if !actor.Admin && inst.InitiatorID != actor.ID {
			return ErrForbidden
		}
		rt, err := s.loadRuntimeFor(ctx, st, tenantID, inst)
		if err != nil {
			return err
		}
		if !actor.Admin {
			window := s.options.WithdrawWindow
			if raw := strings.TrimSpace(rt.design.Settings.WithdrawWindow); raw != "" {
				if parsed, parseErr := time.ParseDuration(raw); parseErr == nil {
					window = parsed
				}
			}
			if window > 0 && s.now().Sub(inst.StartedAt) > window {
				return ErrWithdrawExpired
			}
		}
		if err := s.cancelLiveWork(ctx, rt, "withdrawn | 已撤回"); err != nil {
			return err
		}
		inst.Status = InstanceWithdrawn
		inst.Outcome = "withdrawn"
		inst.EndedAt = rt.now
		inst.UpdatedAt = rt.now
		inst.EndedReason = reason
		inst.CurrentNodes = "[]"
		if err := st.UpdateInstance(ctx, inst); err != nil {
			return err
		}
		rt.inst = &inst
		rt.event(ctx, EventInstanceWithdrawn, "", "", actor.ID, actor.Name, reason, "")
		rt.notify(ctx, NotifyWithdrawn, inst.InitiatorID, "", "")
		notes = rt.notes
		return nil
	})
	if err != nil {
		return err
	}
	s.flushNotifications(ctx, notes)
	return nil
}

// TerminateInstance ends a running instance administratively. | TerminateInstance 由管理员终止运行中实例。
func (s *Service) TerminateInstance(ctx context.Context, tenantID string, actor Actor, instanceID string, in ReasonInput) error {
	if !actor.Admin {
		return ErrForbidden
	}
	tenantID = strings.TrimSpace(tenantID)
	instanceID = strings.TrimSpace(instanceID)
	if tenantID == "" || instanceID == "" || strings.TrimSpace(actor.ID) == "" {
		return ErrInvalidInput
	}
	reason, ok := trimLen(in.Reason, 500)
	if !ok {
		return ErrInvalidInput
	}
	var notes []Notification
	err := s.store.WithTx(ctx, func(st Store) error {
		rt, err := s.loadRuntime(ctx, st, tenantID, instanceID)
		if err != nil {
			return err
		}
		if rt.inst.Status != InstanceRunning {
			return ErrInstanceClosed
		}
		if err := s.finishInstance(ctx, rt, InstanceTerminated, "terminated", reason, actor); err != nil {
			return err
		}
		notes = rt.notes
		return nil
	})
	if err != nil {
		return err
	}
	s.flushNotifications(ctx, notes)
	return nil
}

// Remind sends one reminder to the task's assignees. | Remind 向任务的处理人发送一次催办。
func (s *Service) Remind(ctx context.Context, tenantID string, actor Actor, taskID, comment string) (Task, error) {
	tenantID = strings.TrimSpace(tenantID)
	taskID = strings.TrimSpace(taskID)
	if tenantID == "" || taskID == "" || strings.TrimSpace(actor.ID) == "" {
		return Task{}, ErrInvalidInput
	}
	comment, ok := trimLen(comment, s.options.MaxCommentLen)
	if !ok {
		return Task{}, ErrInvalidInput
	}
	var updated Task
	var notes []Notification
	err := s.store.WithTx(ctx, func(st Store) error {
		inst, task, err := s.loadTaskRuntime(ctx, st, tenantID, taskID)
		if err != nil {
			return err
		}
		if inst.Status != InstanceRunning {
			return ErrInstanceClosed
		}
		if task.Status != TaskPending && task.Status != TaskClaimed {
			return ErrTaskClosed
		}
		if !actor.Admin && inst.InitiatorID != actor.ID {
			return ErrForbidden
		}
		if task.MaxRemind > 0 && task.RemindCount >= task.MaxRemind {
			return ErrRemindLimit
		}
		rt, err := s.loadRuntimeFor(ctx, st, tenantID, inst)
		if err != nil {
			return err
		}
		task.RemindCount++
		task.LastRemindAt = rt.now
		task.UpdatedAt = rt.now
		if err := st.UpdateTask(ctx, task); err != nil {
			return err
		}
		rt.event(ctx, EventTaskReminded, task.ID, task.NodeID, actor.ID, actor.Name, comment, "")
		if task.AssigneeID != "" {
			rt.notify(ctx, NotifyReminded, task.AssigneeID, task.ID, task.NodeName)
		}
		for _, candidate := range task.CandidateList() {
			rt.notify(ctx, NotifyReminded, candidate, task.ID, task.NodeName)
		}
		updated = task
		notes = rt.notes
		return rt.persistRuntime(ctx)
	})
	if err != nil {
		return Task{}, err
	}
	s.flushNotifications(ctx, notes)
	return updated, nil
}

// AddComment appends one free-form note to an instance. | AddComment 向实例追加一条自由备注。
func (s *Service) AddComment(ctx context.Context, tenantID string, actor Actor, instanceID string, in CommentInput) (Comment, error) {
	tenantID = strings.TrimSpace(tenantID)
	instanceID = strings.TrimSpace(instanceID)
	body, ok := trimLen(in.Body, s.options.MaxCommentLen)
	if tenantID == "" || instanceID == "" || !ok || body == "" || strings.TrimSpace(actor.ID) == "" {
		return Comment{}, ErrInvalidInput
	}
	var created Comment
	err := s.store.WithTx(ctx, func(st Store) error {
		rt, err := s.loadRuntime(ctx, st, tenantID, instanceID)
		if err != nil {
			return err
		}
		id, err := s.options.NewID("wfcmt_")
		if err != nil {
			return errs.Wrap(err, ErrUnavailable)
		}
		created = Comment{
			CreatedAt:  rt.now,
			ID:         id,
			TenantID:   tenantID,
			InstanceID: instanceID,
			AuthorID:   actor.ID,
			AuthorName: actor.Name,
			Kind:       "comment",
			Body:       body,
		}
		if err := st.CreateComment(ctx, created); err != nil {
			return err
		}
		rt.event(ctx, EventCommentAdded, "", "", actor.ID, actor.Name, body, "")
		return nil
	})
	if err != nil {
		return Comment{}, err
	}
	return created, nil
}

// appendComment creates a comment row inside an existing transaction. | appendComment 在既有事务内创建评论行。
func (s *Service) appendComment(ctx context.Context, tx *runtimeTxn, taskID string, actor Actor, body, kind string) {
	id, err := s.options.NewID("wfcmt_")
	if err != nil {
		return
	}
	_ = tx.st.CreateComment(ctx, Comment{
		CreatedAt:  tx.now,
		ID:         id,
		TenantID:   tx.inst.TenantID,
		InstanceID: tx.inst.ID,
		TaskID:     taskID,
		AuthorID:   actor.ID,
		AuthorName: actor.Name,
		Kind:       kind,
		Body:       truncate(body, s.options.MaxCommentLen),
	})
}

// loadTaskRow reads one task without duplicating the instance projection when the store supports
// it. | loadTaskRow 在存储支持时读取单条任务而不重复实例投影。
func (s *Service) loadTaskRow(ctx context.Context, st Store, tenantID, taskID string) (Task, error) {
	if reader, ok := st.(taskRowReader); ok {
		return reader.GetTaskBare(ctx, tenantID, taskID)
	}
	return st.GetTask(ctx, tenantID, taskID)
}

// loadTaskRuntime loads the instance and task inside a transaction. | loadTaskRuntime 在事务内加载实例与任务。
func (s *Service) loadTaskRuntime(ctx context.Context, st Store, tenantID, taskID string) (Instance, Task, error) {
	task, err := s.loadTaskRow(ctx, st, tenantID, taskID)
	if err != nil {
		return Instance{}, Task{}, err
	}
	inst, err := st.GetInstance(ctx, tenantID, task.InstanceID)
	if err != nil {
		return Instance{}, Task{}, err
	}
	task.applyInstanceProjection(inst)
	return inst, task, nil
}

// taskNode returns the node of a task, synthesising the initiator revision node. | taskNode
// 返回任务节点，并为发起人重新提交节点合成定义。
func (s *Service) taskNode(design Design, nodeID string) (Node, bool) {
	if node, ok := design.FindNode(nodeID); ok {
		return node, false
	}
	if nodeID == InitiatorNodeID {
		return Node{
			ID:         InitiatorNodeID,
			Type:       NodeUserTask,
			Name:       "重新提交 | Revise",
			Assignee:   Assignment{Type: AssigneeInitiator, Claim: ClaimAssigned},
			Completion: Completion{Mode: CompletionAny},
		}, true
	}
	return Node{}, false
}

// Stats returns the tenant summary. | Stats 返回租户汇总。
func (s *Service) Stats(ctx context.Context, tenantID string) (Stats, error) {
	if strings.TrimSpace(tenantID) == "" {
		return Stats{}, ErrInvalidInput
	}
	return s.store.Stats(ctx, strings.TrimSpace(tenantID))
}

// visibleTo reports whether the actor may read one task's instance. | visibleTo 报告调用方能否读取任务所属实例。
func (s *Service) visibleTo(ctx context.Context, tenantID string, inst Instance, actor Actor) (bool, error) {
	if actor.Admin || inst.InitiatorID == actor.ID {
		return true, nil
	}
	tasks, _, err := s.store.ListTasks(ctx, tenantID, TaskFilter{InstanceID: inst.ID, Page: 1, PageSize: s.options.MaxPageSize})
	if err != nil {
		return false, err
	}
	for _, task := range tasks {
		if task.AssigneeID == actor.ID {
			return true, nil
		}
		for _, candidate := range task.CandidateList() {
			if candidate == actor.ID {
				return true, nil
			}
		}
	}
	return false, nil
}

// InstanceVisible reports whether the actor may read the instance. | InstanceVisible 报告调用方能否读取实例。
func (s *Service) InstanceVisible(ctx context.Context, tenantID string, inst Instance, actor Actor) (bool, error) {
	return s.visibleTo(ctx, tenantID, inst, actor)
}

// TaskVisible reports whether the actor may read the task. | TaskVisible 报告调用方能否读取任务。
func (s *Service) TaskVisible(ctx context.Context, tenantID string, task Task, actor Actor) (bool, error) {
	if actor.Admin || task.AssigneeID == actor.ID || task.OriginalAssigneeID == actor.ID {
		return true, nil
	}
	for _, candidate := range task.CandidateList() {
		if candidate == actor.ID {
			return true, nil
		}
	}
	inst, err := s.store.GetInstance(ctx, tenantID, task.InstanceID)
	if err != nil {
		return false, err
	}
	if inst.InitiatorID == actor.ID {
		return true, nil
	}
	return false, nil
}

// SchedulerReport summarises one due scan. | SchedulerReport 汇总一次到期扫描。
type SchedulerReport struct {
	// Reminded is the number of reminders sent. | Reminded 是发送的催办数量。
	Reminded int
	// Notifications is the number of retried notifications. | Notifications 是重试的通知数量。
	Notifications int
	// Timers is the number of timer events advanced. | Timers 是推进的定时器事件数量。
	Timers int
}

// RunDue sends due reminders and retries pending notifications. It is safe to call from several
// nodes at once: each reminder and notification is claimed by a conditional update. |
// RunDue 发送到期催办并重试待投递通知。它可以由多个节点同时调用：每条催办与通知都经条件更新领取。
func (s *Service) RunDue(ctx context.Context, limit int) (SchedulerReport, error) {
	if limit <= 0 {
		limit = s.options.DueScanLimit
	}
	report := SchedulerReport{}
	timers, err := s.store.ListDueTimerTokens(ctx, s.now(), limit)
	if err != nil {
		return report, err
	}
	for _, token := range timers {
		if err := s.fireDueTimer(ctx, token); err != nil {
			if !isClosedOrGone(err) {
				s.log.Warn("workflow timer event failed | 流程定时事件失败", ydlog.Err(err))
			}
			continue
		}
		report.Timers++
	}
	tasks, err := s.store.ListDueTasks(ctx, s.now(), limit)
	if err != nil {
		return report, err
	}
	for _, task := range tasks {
		if err := s.remindDue(ctx, task); err != nil {
			if !isClosedOrGone(err) {
				s.log.Warn("workflow due reminder failed | 流程到期催办失败", ydlog.Err(err))
			}
			continue
		}
		report.Reminded++
	}
	notes, err := s.store.ListPendingNotifications(ctx, s.now(), limit)
	if err != nil {
		return report, err
	}
	if len(notes) > 0 && s.notificationsActive() {
		claimed := make([]Notification, 0, len(notes))
		lease := s.options.NotificationTimeout * 2
		if lease < time.Minute {
			lease = time.Minute
		}
		for _, note := range notes {
			// The lease makes a second node skip a row this one is already delivering; a crash
			// simply lets the lease expire. | 租约让另一个节点跳过本节点正在投递的行；进程崩溃则租约
			// 自然过期后重试。
			claimedNote, ok, claimErr := s.store.ClaimNotification(ctx, note.TenantID, note.ID, s.now(), s.now().Add(lease))
			if claimErr != nil {
				return report, claimErr
			}
			if ok {
				claimed = append(claimed, claimedNote)
			}
		}
		s.flushNotifications(ctx, claimed)
		report.Notifications = len(claimed)
	}
	return report, nil
}

// fireDueTimer wakes one timer token under a row lock, so two nodes cannot fire it twice. |
// fireDueTimer 在行锁下唤醒一个定时令牌，两个节点不可能重复触发。
func (s *Service) fireDueTimer(ctx context.Context, token Token) error {
	var notes []Notification
	err := s.store.WithTx(ctx, func(st Store) error {
		current, err := st.GetToken(ctx, token.TenantID, token.ID)
		if err != nil {
			return err
		}
		if current.Status != TokenWaiting || current.WaitType != WaitTimer || current.WaitUntil.After(s.now()) {
			return ErrTaskClosed
		}
		rt, err := s.loadRuntime(ctx, st, token.TenantID, token.InstanceID)
		if err != nil {
			return err
		}
		if rt.inst.Status != InstanceRunning {
			return ErrInstanceClosed
		}
		tx2 := rt
		if err := s.fireWaitingToken(ctx, tx2, &current); err != nil {
			return err
		}
		if err := tx2.refreshCurrentNodes(ctx); err != nil {
			return err
		}
		if err := tx2.persistRuntime(ctx); err != nil {
			return err
		}
		notes = tx2.notes
		return nil
	})
	if err != nil {
		return err
	}
	s.flushNotifications(ctx, notes)
	return nil
}

// remindDue sends one scheduler reminder through a conditional claim. | remindDue 经条件领取发送一次调度催办。
func (s *Service) remindDue(ctx context.Context, task Task) error {
	var notes []Notification
	err := s.store.WithTx(ctx, func(st Store) error {
		updated, ok, err := st.ClaimReminder(ctx, task.TenantID, task.ID, s.now(), s.now().Add(time.Duration(task.RemindEverySeconds)*time.Second))
		if err != nil || !ok {
			return err
		}
		inst, err := st.GetInstance(ctx, task.TenantID, updated.InstanceID)
		if err != nil {
			return err
		}
		rt, err := s.loadRuntime(ctx, st, task.TenantID, inst.ID)
		if err != nil {
			return err
		}
		rt.event(ctx, EventTaskReminded, updated.ID, updated.NodeID, "system", "system", "系统催办 | automatic reminder", "")
		if updated.AssigneeID != "" {
			rt.notify(ctx, NotifyReminded, updated.AssigneeID, updated.ID, updated.NodeName)
		}
		for _, candidate := range updated.CandidateList() {
			rt.notify(ctx, NotifyReminded, candidate, updated.ID, updated.NodeName)
		}
		notes = rt.notes
		return nil
	})
	if err != nil {
		return err
	}
	s.flushNotifications(ctx, notes)
	return nil
}

// isClosedOrGone reports errors that a scheduler should silently skip. | isClosedOrGone 报告调度器应静默跳过的错误。
func isClosedOrGone(err error) bool {
	return errors.Is(err, ErrTaskClosed) || errors.Is(err, ErrInstanceClosed) || errors.Is(err, ErrNotFound)
}
