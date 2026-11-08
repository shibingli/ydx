package scim

import (
	"context"
	"errors"
	"net/http"

	"github.com/shibingli/ydx/errs"
	ydxjson "github.com/shibingli/ydx/json"
)

// bulkUndoKind identifies the compensating action of one undo log entry. | bulkUndoKind 标识一个
// 撤销日志条目的补偿动作。
type bulkUndoKind uint8

const (
	// bulkUndoDeleteUser removes a User created by the transaction. | bulkUndoDeleteUser 删除事务
	// 创建的 User。
	bulkUndoDeleteUser bulkUndoKind = iota
	// bulkUndoDeleteGroup removes a Group created by the transaction. | bulkUndoDeleteGroup 删除
	// 事务创建的 Group。
	bulkUndoDeleteGroup
	// bulkUndoRestoreUser restores a User replaced by the transaction. | bulkUndoRestoreUser 恢复
	// 被事务替换的 User。
	bulkUndoRestoreUser
	// bulkUndoRestoreGroup restores a Group replaced by the transaction. | bulkUndoRestoreGroup
	// 恢复被事务替换的 Group。
	bulkUndoRestoreGroup
	// bulkUndoRecreateUser recreates a User deleted by the transaction. | bulkUndoRecreateUser
	// 重建被事务删除的 User。
	bulkUndoRecreateUser
	// bulkUndoRecreateGroup recreates a Group deleted by the transaction. | bulkUndoRecreateGroup
	// 重建被事务删除的 Group。
	bulkUndoRecreateGroup
)

// bulkUndoEntryOverhead is the fixed memory accounting overhead of one undo entry. |
// bulkUndoEntryOverhead 是一个撤销条目的固定内存计费开销。
const bulkUndoEntryOverhead int64 = 128

// bulkUndoEntry records how to compensate one applied bulk mutation. | bulkUndoEntry 记录如何补偿
// 一个已应用的批量变更。
type bulkUndoEntry struct {
	// priorUser and priorGroup hold the state before an update or delete. | priorUser 与 priorGroup
	// 保存更新或删除前的状态。
	priorUser  *User
	priorGroup *Group
	// id is the affected resource identifier. | id 是受影响资源的标识。
	id string
	// bulkID is the request-scoped identifier defined by the operation, if any. | bulkID 是操作定义
	// 的请求内标识（若有）。
	bulkID string
	// appliedVersion is the entity tag produced by the mutation, empty when unavailable. |
	// appliedVersion 是变更产生的实体标签，不可用时为空。
	appliedVersion string
	// bytes is the estimated undo log footprint. | bytes 是估算的撤销日志占用。
	bytes int64
	// kind selects the compensating action. | kind 选择补偿动作。
	kind bulkUndoKind
	// applied reports whether the store mutation committed. | applied 表示存储变更是否已提交。
	applied bool
}

// bulkUndoHandle marks a recorded undo entry as applied once the store mutation commits. |
// bulkUndoHandle 在存储变更提交后把已记录的撤销条目标记为已应用。
type bulkUndoHandle struct {
	// log owns the entry. | log 持有该条目。
	log *bulkUndoLog
	// index is the entry position and stays valid across appends. | index 是条目位置，在追加后仍然
	// 有效。
	index int
}

// markApplied marks the entry applied with the entity tag produced by the mutation. A nil handle
// is a no-op, so non-atomic call paths share the same helpers. | markApplied 用变更产生的实体标签把
// 条目标记为已应用。nil 句柄为空操作，因此非事务调用路径可复用同一组辅助函数。
func (h *bulkUndoHandle) markApplied(version string) {
	if h == nil || h.log == nil {
		return
	}
	if h.index < 0 || h.index >= len(h.log.entries) {
		return
	}
	entry := &h.log.entries[h.index]
	entry.applied = true
	entry.appliedVersion = version
}

// bulkUndoLog is the bounded, request-scoped compensating log of an atomic bulk request. |
// bulkUndoLog 是原子批量请求的、有界且请求内的补偿日志。
type bulkUndoLog struct {
	// entries are kept in operation order and rolled back in reverse. | entries 按操作顺序保存，
	// 回滚时逆序遍历。
	entries []bulkUndoEntry
	// bytes is the estimated footprint of entries. | bytes 是 entries 的估算占用。
	bytes int64
	// maxBytes bounds bytes. | maxBytes 限制 bytes。
	maxBytes int64
}

// newBulkUndoLog returns an undo log bounded by maxBytes, falling back to the default when the
// value is not positive. | newBulkUndoLog 返回由 maxBytes 限制的撤销日志；取值非正时回退到默认值。
func newBulkUndoLog(maxBytes int64) *bulkUndoLog {
	if maxBytes <= 0 {
		maxBytes = DefaultBulkMaxUndoBytes
	}
	return &bulkUndoLog{maxBytes: maxBytes}
}

// record appends entry and returns a handle for marking it applied later. A nil log is a no-op,
// which keeps the non-atomic bulk path free of undo bookkeeping. | record 追加 entry 并返回稍后标记
// 为已应用的句柄。nil 日志为空操作，使非事务批量路径不承担撤销记账。
func (l *bulkUndoLog) record(entry bulkUndoEntry) (*bulkUndoHandle, error) {
	if l == nil {
		return nil, nil
	}
	if entry.bytes < 0 {
		entry.bytes = 0
	}
	if l.maxBytes > 0 && entry.bytes > l.maxBytes-l.bytes {
		return nil, errs.Detail(ErrBulkUndoLimit, "bulk undo log exceeds %d bytes | 批量撤销日志超过 %d 字节",
			l.maxBytes, l.maxBytes)
	}
	l.entries = append(l.entries, entry)
	l.bytes += entry.bytes
	return &bulkUndoHandle{log: l, index: len(l.entries) - 1}, nil
}

// prepareUserRestore records how to restore existing before an update or patch. | prepareUserRestore
// 在更新或补丁前记录如何恢复 existing。
func (l *bulkUndoLog) prepareUserRestore(existing *User, bulkID string) (*bulkUndoHandle, error) {
	if l == nil {
		return nil, nil
	}
	if existing == nil || existing.ID == "" {
		return nil, errs.Detail(ErrInvalidValue, "cannot record undo entry without User id | 缺少 User 标识，无法记录撤销条目")
	}
	size, err := bulkUserSnapshotBytes(existing)
	if err != nil {
		return nil, err
	}
	return l.record(bulkUndoEntry{
		kind:      bulkUndoRestoreUser,
		id:        existing.ID,
		bulkID:    bulkID,
		priorUser: existing.Clone(),
		bytes:     size,
	})
}

// prepareUserRecreate records how to recreate existing before a delete. | prepareUserRecreate 在删除
// 前记录如何重建 existing。
func (l *bulkUndoLog) prepareUserRecreate(existing *User, bulkID string) (*bulkUndoHandle, error) {
	if l == nil {
		return nil, nil
	}
	if existing == nil || existing.ID == "" {
		return nil, errs.Detail(ErrInvalidValue, "cannot record undo entry without User id | 缺少 User 标识，无法记录撤销条目")
	}
	size, err := bulkUserSnapshotBytes(existing)
	if err != nil {
		return nil, err
	}
	return l.record(bulkUndoEntry{
		kind:      bulkUndoRecreateUser,
		id:        existing.ID,
		bulkID:    bulkID,
		priorUser: existing.Clone(),
		bytes:     size,
	})
}

// recordCreatedUser records an immediately applied delete compensation for a created User. |
// recordCreatedUser 为已创建的 User 记录立即生效的删除补偿。
func (l *bulkUndoLog) recordCreatedUser(created *User, bulkID string) error {
	if l == nil {
		return nil
	}
	if created == nil || created.ID == "" {
		return errs.Detail(ErrInternal, "created User has no id | 已创建 User 缺少标识")
	}
	size, err := bulkUserSnapshotBytes(created)
	if err != nil {
		return err
	}
	_, err = l.record(bulkUndoEntry{
		kind:           bulkUndoDeleteUser,
		id:             created.ID,
		bulkID:         bulkID,
		appliedVersion: userVersion(created),
		applied:        true,
		bytes:          size,
	})
	return err
}

// prepareGroupRestore records how to restore existing before an update or patch. |
// prepareGroupRestore 在更新或补丁前记录如何恢复 existing。
func (l *bulkUndoLog) prepareGroupRestore(existing *Group, bulkID string) (*bulkUndoHandle, error) {
	if l == nil {
		return nil, nil
	}
	if existing == nil || existing.ID == "" {
		return nil, errs.Detail(ErrInvalidValue, "cannot record undo entry without Group id | 缺少 Group 标识，无法记录撤销条目")
	}
	size, err := bulkGroupSnapshotBytes(existing)
	if err != nil {
		return nil, err
	}
	return l.record(bulkUndoEntry{
		kind:       bulkUndoRestoreGroup,
		id:         existing.ID,
		bulkID:     bulkID,
		priorGroup: existing.Clone(),
		bytes:      size,
	})
}

// prepareGroupRecreate records how to recreate existing before a delete. | prepareGroupRecreate 在
// 删除前记录如何重建 existing。
func (l *bulkUndoLog) prepareGroupRecreate(existing *Group, bulkID string) (*bulkUndoHandle, error) {
	if l == nil {
		return nil, nil
	}
	if existing == nil || existing.ID == "" {
		return nil, errs.Detail(ErrInvalidValue, "cannot record undo entry without Group id | 缺少 Group 标识，无法记录撤销条目")
	}
	size, err := bulkGroupSnapshotBytes(existing)
	if err != nil {
		return nil, err
	}
	return l.record(bulkUndoEntry{
		kind:       bulkUndoRecreateGroup,
		id:         existing.ID,
		bulkID:     bulkID,
		priorGroup: existing.Clone(),
		bytes:      size,
	})
}

// recordCreatedGroup records an immediately applied delete compensation for a created Group. |
// recordCreatedGroup 为已创建的 Group 记录立即生效的删除补偿。
func (l *bulkUndoLog) recordCreatedGroup(created *Group, bulkID string) error {
	if l == nil {
		return nil
	}
	if created == nil || created.ID == "" {
		return errs.Detail(ErrInternal, "created Group has no id | 已创建 Group 缺少标识")
	}
	size, err := bulkGroupSnapshotBytes(created)
	if err != nil {
		return err
	}
	_, err = l.record(bulkUndoEntry{
		kind:           bulkUndoDeleteGroup,
		id:             created.ID,
		bulkID:         bulkID,
		appliedVersion: groupVersion(created),
		applied:        true,
		bytes:          size,
	})
	return err
}

// bulkUserSnapshotBytes estimates the undo footprint of a User snapshot. | bulkUserSnapshotBytes
// 估算一个 User 快照的撤销占用。
func bulkUserSnapshotBytes(user *User) (int64, error) {
	data, err := ydxjson.Marshal(user)
	if err != nil {
		return 0, errs.WrapDetail(err, ErrInternal, "cannot size User undo snapshot | 无法计算 User 撤销快照大小")
	}
	return int64(len(data)) + bulkUndoEntryOverhead, nil
}

// bulkGroupSnapshotBytes estimates the undo footprint of a Group snapshot. | bulkGroupSnapshotBytes
// 估算一个 Group 快照的撤销占用。
func bulkGroupSnapshotBytes(group *Group) (int64, error) {
	data, err := ydxjson.Marshal(group)
	if err != nil {
		return 0, errs.WrapDetail(err, ErrInternal, "cannot size Group undo snapshot | 无法计算 Group 撤销快照大小")
	}
	return int64(len(data)) + bulkUndoEntryOverhead, nil
}

// bulkRollbackResult summarizes a rollback attempt. | bulkRollbackResult 汇总一次回滚尝试。
type bulkRollbackResult struct {
	// err joins every rollback failure. | err 连接所有回滚失败。
	err error
	// conflicts counts resources changed concurrently. | conflicts 统计被并发修改的资源数。
	conflicts int
	// failures counts store or validation failures. | failures 统计存储或校验失败数。
	failures int
}

// rollback undoes applied entries in reverse operation order and removes the request-scoped bulkId
// mappings of every rolled-back operation. It keeps going after an individual failure so one broken
// entry cannot prevent the remaining compensation. | rollback 按操作逆序撤销已应用条目，并移除所有
// 已回滚操作的请求内 bulkId 映射。单个条目失败后仍继续执行，避免一个损坏条目阻止其余补偿。
func (l *bulkUndoLog) rollback(ctx context.Context, store Store, ids map[string]string) bulkRollbackResult {
	var result bulkRollbackResult
	if l == nil || store == nil {
		return result
	}
	var failures []error
	for i := len(l.entries) - 1; i >= 0; i-- {
		entry := &l.entries[i]
		if entry.bulkID != "" && ids != nil {
			delete(ids, entry.bulkID)
		}
		if !entry.applied {
			continue
		}
		err := entry.rollback(ctx, store)
		if err == nil {
			continue
		}
		failures = append(failures, err)
		if errors.Is(err, ErrBulkRollbackConflict) {
			result.conflicts++
		} else {
			result.failures++
		}
	}
	result.err = errors.Join(failures...)
	return result
}

// rollback executes the compensating action of one entry. | rollback 执行一个条目的补偿动作。
func (e *bulkUndoEntry) rollback(ctx context.Context, store Store) error {
	switch e.kind {
	case bulkUndoDeleteUser:
		return e.rollbackDeleteUser(ctx, store)
	case bulkUndoDeleteGroup:
		return e.rollbackDeleteGroup(ctx, store)
	case bulkUndoRestoreUser:
		return e.rollbackRestoreUser(ctx, store)
	case bulkUndoRestoreGroup:
		return e.rollbackRestoreGroup(ctx, store)
	case bulkUndoRecreateUser:
		return e.rollbackRecreateUser(ctx, store)
	case bulkUndoRecreateGroup:
		return e.rollbackRecreateGroup(ctx, store)
	default:
		return errs.Detail(ErrInternal, "unknown bulk undo kind %d | 未知批量撤销类型 %d", e.kind, e.kind)
	}
}

// rollbackDeleteUser removes a User created by the transaction unless it changed concurrently. |
// rollbackDeleteUser 删除事务创建的 User，除非它已被并发修改。
func (e *bulkUndoEntry) rollbackDeleteUser(ctx context.Context, store Store) error {
	current, err := store.GetUser(ctx, e.id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return rollbackStoreFailure(err, ResourceTypeNameUser, e.id)
	}
	if rollbackVersionMismatch(e.appliedVersion, userVersion(current)) {
		return rollbackConflict(ResourceTypeNameUser, e.id)
	}
	if err := store.DeleteUser(ctx, e.id); err != nil {
		return rollbackStoreFailure(err, ResourceTypeNameUser, e.id)
	}
	return nil
}

// rollbackDeleteGroup removes a Group created by the transaction unless it changed concurrently. |
// rollbackDeleteGroup 删除事务创建的 Group，除非它已被并发修改。
func (e *bulkUndoEntry) rollbackDeleteGroup(ctx context.Context, store Store) error {
	current, err := store.GetGroup(ctx, e.id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return rollbackStoreFailure(err, ResourceTypeNameGroup, e.id)
	}
	if rollbackVersionMismatch(e.appliedVersion, groupVersion(current)) {
		return rollbackConflict(ResourceTypeNameGroup, e.id)
	}
	if err := store.DeleteGroup(ctx, e.id); err != nil {
		return rollbackStoreFailure(err, ResourceTypeNameGroup, e.id)
	}
	return nil
}

// rollbackRestoreUser restores the pre-update snapshot of a User unless it changed concurrently. |
// rollbackRestoreUser 恢复 User 的更新前快照，除非它已被并发修改。
func (e *bulkUndoEntry) rollbackRestoreUser(ctx context.Context, store Store) error {
	// Prefer the conditional write when the store supports it: the version check and the restore
	// then form one atomic step instead of a read-check-write window. | 存储支持条件写时优先使用：
	// 版本检查与恢复成为一个原子步骤，而不是读取-检查-写入的窗口。
	if e.appliedVersion != "" && e.priorUser != nil {
		if replacer, ok := store.(UserVersionReplacer); ok {
			restored := e.priorUser.Clone()
			restored.Password = ""
			if _, err := replacer.ReplaceUserIfVersion(ctx, restored, e.appliedVersion); err != nil {
				if errors.Is(err, ErrPreconditionFailed) || errors.Is(err, ErrNotFound) {
					return rollbackConflict(ResourceTypeNameUser, e.id)
				}
				return rollbackStoreFailure(err, ResourceTypeNameUser, e.id)
			}
			return nil
		}
	}
	current, err := store.GetUser(ctx, e.id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return rollbackConflict(ResourceTypeNameUser, e.id)
		}
		return rollbackStoreFailure(err, ResourceTypeNameUser, e.id)
	}
	if rollbackVersionMismatch(e.appliedVersion, userVersion(current)) {
		return rollbackConflict(ResourceTypeNameUser, e.id)
	}
	restored := e.priorUser.Clone()
	if restored == nil {
		return errs.Detail(ErrInternal, "missing User undo snapshot | 缺少 User 撤销快照")
	}
	restored.Password = ""
	if _, err := store.ReplaceUser(ctx, restored); err != nil {
		return rollbackStoreFailure(err, ResourceTypeNameUser, e.id)
	}
	return nil
}

// rollbackRestoreGroup restores the pre-update snapshot of a Group unless it changed concurrently. |
// rollbackRestoreGroup 恢复 Group 的更新前快照，除非它已被并发修改。
func (e *bulkUndoEntry) rollbackRestoreGroup(ctx context.Context, store Store) error {
	// Prefer the conditional write when the store supports it, matching the User path. | 存储支持
	// 条件写时优先使用，与 User 路径一致。
	if e.appliedVersion != "" && e.priorGroup != nil {
		if replacer, ok := store.(GroupVersionReplacer); ok {
			restored := e.priorGroup.Clone()
			if _, err := replacer.ReplaceGroupIfVersion(ctx, restored, e.appliedVersion); err != nil {
				if errors.Is(err, ErrPreconditionFailed) || errors.Is(err, ErrNotFound) {
					return rollbackConflict(ResourceTypeNameGroup, e.id)
				}
				return rollbackStoreFailure(err, ResourceTypeNameGroup, e.id)
			}
			return nil
		}
	}
	current, err := store.GetGroup(ctx, e.id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return rollbackConflict(ResourceTypeNameGroup, e.id)
		}
		return rollbackStoreFailure(err, ResourceTypeNameGroup, e.id)
	}
	if rollbackVersionMismatch(e.appliedVersion, groupVersion(current)) {
		return rollbackConflict(ResourceTypeNameGroup, e.id)
	}
	restored := e.priorGroup.Clone()
	if restored == nil {
		return errs.Detail(ErrInternal, "missing Group undo snapshot | 缺少 Group 撤销快照")
	}
	if _, err := store.ReplaceGroup(ctx, restored); err != nil {
		return rollbackStoreFailure(err, ResourceTypeNameGroup, e.id)
	}
	return nil
}

// rollbackRecreateUser recreates a User deleted by the transaction when the identifier is still
// free. A resource that reappeared concurrently is reported as a conflict instead of overwritten. |
// rollbackRecreateUser 在标识仍空闲时重建事务删除的 User。并发重现的资源会报告冲突而不会被覆盖。
func (e *bulkUndoEntry) rollbackRecreateUser(ctx context.Context, store Store) error {
	_, err := store.GetUser(ctx, e.id)
	switch {
	case err == nil:
		return rollbackConflict(ResourceTypeNameUser, e.id)
	case !errors.Is(err, ErrNotFound):
		return rollbackStoreFailure(err, ResourceTypeNameUser, e.id)
	}
	restored := e.priorUser.Clone()
	if restored == nil {
		return errs.Detail(ErrInternal, "missing User undo snapshot | 缺少 User 撤销快照")
	}
	restored.Password = ""
	if _, err := store.CreateUser(ctx, restored); err != nil {
		return rollbackStoreFailure(err, ResourceTypeNameUser, e.id)
	}
	return nil
}

// rollbackRecreateGroup recreates a Group deleted by the transaction when the identifier is still
// free. A resource that reappeared concurrently is reported as a conflict instead of overwritten. |
// rollbackRecreateGroup 在标识仍空闲时重建事务删除的 Group。并发重现的资源会报告冲突而不会被覆盖。
func (e *bulkUndoEntry) rollbackRecreateGroup(ctx context.Context, store Store) error {
	_, err := store.GetGroup(ctx, e.id)
	switch {
	case err == nil:
		return rollbackConflict(ResourceTypeNameGroup, e.id)
	case !errors.Is(err, ErrNotFound):
		return rollbackStoreFailure(err, ResourceTypeNameGroup, e.id)
	}
	restored := e.priorGroup.Clone()
	if restored == nil {
		return errs.Detail(ErrInternal, "missing Group undo snapshot | 缺少 Group 撤销快照")
	}
	if _, err := store.CreateGroup(ctx, restored); err != nil {
		return rollbackStoreFailure(err, ResourceTypeNameGroup, e.id)
	}
	return nil
}

// rollbackVersionMismatch reports whether current differs from the entity tag produced by the
// mutation. An empty applied tag means the store does not expose versions, so no conflict can be
// detected. | rollbackVersionMismatch 报告 current 是否不同于变更产生的实体标签。已应用标签为空表示
// 存储不暴露版本，因此无法检测冲突。
func rollbackVersionMismatch(applied, current string) bool {
	if applied == "" {
		return false
	}
	return normalizeETag(applied) != normalizeETag(current)
}

// rollbackConflict reports a concurrent change that blocks compensation. The detail carries only
// the resource type and identifier, never stored content. | rollbackConflict 报告阻止补偿的并发
// 变更。明细只包含资源类型与标识，绝不包含存储内容。
func rollbackConflict(resourceType, id string) error {
	return errs.Detail(ErrBulkRollbackConflict, "%s %q changed during bulk rollback | %s %q 在批量回滚期间发生变化",
		resourceType, id, resourceType, id)
}

// rollbackStoreFailure wraps a store failure raised while compensating. | rollbackStoreFailure 包装
// 补偿期间发生的存储故障。
func rollbackStoreFailure(err error, resourceType, id string) error {
	return errs.WrapDetail(err, ErrStoreUnavailable, "cannot roll back %s %q | 无法回滚 %s %q",
		resourceType, id, resourceType, id)
}

// handleBulkAtomic executes a bulk request with compensating rollback. Every operation runs in
// request order; the first failure rolls back all applied operations in reverse order and the
// response becomes a single Error object instead of a partially successful BulkResponse. |
// handleBulkAtomic 以补偿回滚执行批量请求。每个操作按请求顺序运行；首次失败会按逆序回滚所有已应用
// 操作，响应变为单个 Error 对象，而不是部分成功的 BulkResponse。
func (s *Server) handleBulkAtomic(w http.ResponseWriter, r *http.Request, request *BulkRequest) {
	ids := make(map[string]string, len(request.Operations))
	undo := newBulkUndoLog(s.bulkMaxUndoBytes)
	results := make([]BulkResponseOperation, 0, len(request.Operations))
	for index, operation := range request.Operations {
		result, err := s.runBulkOperation(r, operation, ids, undo)
		if err != nil {
			// Rollback must still run when the peer disconnected, so the request context is
			// detached from cancellation while keeping its values. | 对端断开时仍须执行回滚，因此
			// 回滚上下文脱离取消，但保留其值。
			rollbackCtx := context.Background()
			if r != nil {
				rollbackCtx = context.WithoutCancel(r.Context())
			}
			rolled := undo.rollback(rollbackCtx, s.store, ids)
			operationErr := errs.Detail(err, "atomic bulk operation %d failed | 原子批量第 %d 个操作失败",
				index+1, index+1)
			writeError(w, combineBulkAtomicFailure(operationErr, rolled))
			return
		}
		results = append(results, result)
	}
	writeSCIM(w, http.StatusOK, BulkResponse{
		Schemas:    []string{BulkResponseSchema},
		Operations: results,
	})
}

// combineBulkAtomicFailure merges the operation failure with rollback failures. When compensation
// is incomplete the result classifies as a server-side rollback failure, whose client detail is
// generic, so backend error text and credentials are never exposed. A pure concurrent-change
// conflict classifies as HTTP 409. | combineBulkAtomicFailure 合并操作失败与回滚失败。补偿不完整时
// 结果归类为服务端回滚失败，其客户端明细是通用文案，因此绝不暴露后端错误文本与凭据。纯并发变更冲突
// 归类为 HTTP 409。
func combineBulkAtomicFailure(original error, rollback bulkRollbackResult) error {
	if rollback.err == nil {
		return original
	}
	combined := errors.Join(original, rollback.err)
	if rollback.failures > 0 || classifyError(original).status >= http.StatusInternalServerError {
		return errs.WrapDetail(combined, ErrBulkRollbackFailed,
			"atomic bulk failed and rollback was incomplete | 原子批量失败且回滚不完整")
	}
	return errs.WrapDetail(combined, ErrBulkRollbackConflict,
		"atomic bulk failed and rollback could not restore prior state | 原子批量失败且回滚无法恢复原状态")
}
