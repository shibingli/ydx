package kmip

import (
	"context"
	"errors"

	"github.com/shibingli/ydx/errs"
)

// DefaultMaxUndoLogBytes is the default memory budget of the per-batch undo journal (64 MiB). |
// DefaultMaxUndoLogBytes 是每批撤销日志的默认内存预算（64 MiB）。
const DefaultMaxUndoLogBytes = 64 << 20

// ErrUndoLogLimit reports that a Batch Undo journal entry would exceed the configured memory budget. The failed
// operation is not applied and the journal remains consistent. | ErrUndoLogLimit 表示 Batch Undo 撤销日志条目会
// 超出配置的内存预算；失败的操作不会被应用，日志保持一致。
var ErrUndoLogLimit = errs.New("kmip: batch undo journal limit exceeded | kmip：批处理撤销日志超出限制")

// Memory-accounting overheads keep the journal budget conservative. | 内存核算开销使撤销日志预算保持保守。
const (
	undoEntryOverhead     = 64
	undoItemOverhead      = 32
	undoObjectOverhead    = 16
	undoAttributeOverhead = 32
)

// undoMutation is the inverse action of one journaled store mutation. | undoMutation 是一次已记录存储变更的逆动作。
type undoMutation uint8

const (
	// undoMutationCreate means the batch created the object, so rollback deletes it. | undoMutationCreate 表示
	// 批处理创建了对象，回滚时删除它。
	undoMutationCreate undoMutation = iota + 1
	// undoMutationUpdate means the batch replaced the object, so rollback restores the previous record. |
	// undoMutationUpdate 表示批处理替换了对象，回滚时恢复先前记录。
	undoMutationUpdate
	// undoMutationDelete means the batch deleted the object, so rollback recreates the previous record. |
	// undoMutationDelete 表示批处理删除了对象，回滚时重建先前记录。
	undoMutationDelete
)

// english returns the English name of the mutation. | english 返回变更的英文名称。
func (m undoMutation) english() string {
	switch m {
	case undoMutationCreate:
		return "create"
	case undoMutationUpdate:
		return "update"
	case undoMutationDelete:
		return "delete"
	default:
		return "unknown"
	}
}

// chinese returns the Chinese name of the mutation. | chinese 返回变更的中文名称。
func (m undoMutation) chinese() string {
	switch m {
	case undoMutationCreate:
		return "创建"
	case undoMutationUpdate:
		return "更新"
	case undoMutationDelete:
		return "删除"
	default:
		return "未知变更"
	}
}

// undoEntry records one store mutation together with the object state that existed before it. The record holds a deep
// copy, including key material, attributes, lifecycle state, dates and any destroyed tombstone, because Destroy,
// Revoke and Activate overwrite or erase those fields. Create entries only retain the new identifier. |
// undoEntry 记录一次存储变更及其发生前的对象状态。记录保存深拷贝，包含密钥材料、属性、生命周期状态、日期与
// 销毁墓碑，因为 Destroy、Revoke 与 Activate 会覆盖或擦除这些字段。Create 条目仅保留新标识符。
type undoEntry struct {
	// operation is the KMIP operation that produced the mutation. | operation 是产生该变更的 KMIP 操作。
	operation Operation
	// mutation is the inverse action applied during rollback. | mutation 是回滚时应用的逆动作。
	mutation undoMutation
	// record is the pre-mutation state, or the new identifier for a create. | record 是变更前状态；创建时为新标识符。
	record ObjectRecord
	// sequence is the one-based journal position, used in diagnostics. | sequence 是基于一的日志位置，用于诊断。
	sequence uint64
	// size is the accounted memory in bytes. | size 是核算的内存字节数。
	size int
}

// batchUndoLog is the per-batch inverse-operation journal used by Batch Undo. It is isolated to one request message,
// cleared after a successful commit and replayed in reverse order after a failure. A nil journal disables recording,
// which keeps the Stop and Continue policies free of journaling cost. | batchUndoLog 是 Batch Undo 使用的每批逆操作
// 日志。它隔离在单个请求消息内，成功提交后清空，失败后按逆序重放。nil 日志禁用记录，使 Stop 与 Continue 策略
// 不承担日志开销。
type batchUndoLog struct {
	// entries holds mutations in application order. | entries 按应用顺序保存变更。
	entries []undoEntry
	// used is the accounted memory of all entries. | used 是所有条目核算后的内存。
	used int
	// limit is the maximum accounted memory. | limit 是最大核算内存。
	limit int
	// sequence is the last assigned entry sequence. | sequence 是最后分配的条目序号。
	sequence uint64
	// operation is the current KMIP operation being dispatched. | operation 是当前分派的 KMIP 操作。
	operation Operation
}

// newBatchUndoLog returns a journal bounded by limit bytes; a non-positive limit selects DefaultMaxUndoLogBytes. |
// newBatchUndoLog 返回以 limit 字节为上限的日志；非正上限使用 DefaultMaxUndoLogBytes。
func newBatchUndoLog(limit int) *batchUndoLog {
	if limit <= 0 {
		limit = DefaultMaxUndoLogBytes
	}
	return &batchUndoLog{limit: limit}
}

// beginItem records the KMIP operation that subsequent mutations belong to. | beginItem 记录后续变更所属的 KMIP 操作。
func (j *batchUndoLog) beginItem(operation Operation) {
	if j == nil {
		return
	}
	j.operation = operation
}

// recordCreate journals the identifier of an object the batch is about to create. | recordCreate 记录批处理即将创建
// 的对象的标识符。
func (j *batchUndoLog) recordCreate(uniqueIdentifier string) error {
	if j == nil {
		return nil
	}
	entry := undoEntry{
		operation: j.operation,
		mutation:  undoMutationCreate,
		record:    ObjectRecord{UniqueIdentifier: uniqueIdentifier},
		size:      undoEntryOverhead + len(uniqueIdentifier),
	}
	return j.append(entry)
}

// recordUpdate journals the complete pre-mutation record of an object the batch is about to replace. The journal
// takes ownership of the record's key material and zeroizes it when the batch ends. | recordUpdate 记录批处理即将
// 替换的对象的完整变更前记录。日志接管记录密钥材料的所有权，并在批处理结束时清零。
func (j *batchUndoLog) recordUpdate(previous ObjectRecord) error {
	if j == nil {
		return nil
	}
	entry := undoEntry{
		operation: j.operation,
		mutation:  undoMutationUpdate,
		record:    previous,
		size:      undoRecordBytes(&previous),
	}
	return j.append(entry)
}

// recordDelete journals the complete record of an object the batch is about to delete. | recordDelete 记录批处理
// 即将删除的对象的完整记录。
func (j *batchUndoLog) recordDelete(previous ObjectRecord) error {
	if j == nil {
		return nil
	}
	entry := undoEntry{
		operation: j.operation,
		mutation:  undoMutationDelete,
		record:    previous,
		size:      undoRecordBytes(&previous),
	}
	return j.append(entry)
}

// append adds an entry when it fits within the memory budget. | append 在内存预算内添加条目。
func (j *batchUndoLog) append(entry undoEntry) error {
	if entry.size > j.limit-j.used {
		return errs.Detail(ErrUndoLogLimit,
			"batch undo journal entry of %d bytes exceeds the %d byte limit with %d bytes already used | "+
				"批处理撤销日志条目 %d 字节超过 %d 字节上限（已用 %d 字节）",
			entry.size, j.limit, j.used, entry.size, j.limit, j.used)
	}
	j.sequence++
	entry.sequence = j.sequence
	j.entries = append(j.entries, entry)
	j.used += entry.size
	return nil
}

// dropLast removes the newest entry when it matches the mutation and identifier, zeroizing its record. It is used
// when the corresponding store call fails and the batch therefore has nothing to undo. | dropLast 在最新条目匹配
// 变更类型与标识符时移除它并清零其记录；用于对应存储调用失败、因而无需撤销的场景。
func (j *batchUndoLog) dropLast(mutation undoMutation, uniqueIdentifier string) {
	if j == nil || len(j.entries) == 0 {
		return
	}
	last := &j.entries[len(j.entries)-1]
	if last.mutation != mutation || last.record.UniqueIdentifier != uniqueIdentifier {
		return
	}
	zeroizeRecord(&last.record)
	j.used -= last.size
	j.entries = j.entries[:len(j.entries)-1]
}

// rollback replays the journal in reverse order, restoring every recorded object. It continues after individual
// failures and returns their joined diagnostic; errors.Is matches ErrOperationFailed and each underlying store
// error. | rollback 按逆序重放日志，恢复每个已记录对象。单个恢复失败后继续处理其余条目并返回合并诊断；
// errors.Is 可匹配 ErrOperationFailed 与每个底层存储错误。
func (j *batchUndoLog) rollback(ctx context.Context, store Store) error {
	if j == nil || len(j.entries) == 0 {
		return nil
	}
	failures := make([]error, 0, 1)
	for i := len(j.entries) - 1; i >= 0; i-- {
		entry := j.entries[i]
		var err error
		switch entry.mutation {
		case undoMutationCreate:
			err = store.Delete(ctx, entry.record.UniqueIdentifier)
			if errors.Is(err, ErrItemNotFound) {
				// The object was already removed, for example by a failed Create Key Pair before the
				// batch rollback. | 对象已被移除，例如 Create Key Pair 失败时已自行清理。
				err = nil
			}
		case undoMutationUpdate:
			err = store.Update(ctx, cloneRecord(entry.record))
			if errors.Is(err, ErrItemNotFound) {
				err = store.Create(ctx, cloneRecord(entry.record))
			}
		case undoMutationDelete:
			err = store.Create(ctx, cloneRecord(entry.record))
			if errors.Is(err, ErrObjectExists) {
				err = store.Update(ctx, cloneRecord(entry.record))
			}
		default:
			err = errs.Detail(ErrOperationFailed, "unknown undo mutation %d | 未知撤销变更 %d", entry.mutation, entry.mutation)
		}
		if err == nil {
			continue
		}
		failures = append(failures, errs.WrapDetail(err, ErrOperationFailed,
			"restore %s of object %q for operation %s (entry %d) | 恢复对象 %q 的%s失败（操作 %s，条目 %d）",
			entry.mutation.english(), entry.record.UniqueIdentifier, entry.operation.String(), entry.sequence,
			entry.record.UniqueIdentifier, entry.mutation.chinese(), entry.operation.String(), entry.sequence))
	}
	if len(failures) == 0 {
		return nil
	}
	return errors.Join(failures...)
}

// clear zeroizes all retained key material and empties the journal. | clear 清零所有保留的密钥材料并清空日志。
func (j *batchUndoLog) clear() {
	if j == nil {
		return
	}
	for i := range j.entries {
		zeroizeRecord(&j.entries[i].record)
	}
	j.entries = nil
	j.used = 0
	j.sequence = 0
	j.operation = 0
}

// undoRecordBytes returns a conservative memory estimate of a record, including key material and attributes. |
// undoRecordBytes 返回记录的保守内存估算，包含密钥材料与属性。
func undoRecordBytes(record *ObjectRecord) int {
	size := undoEntryOverhead
	if record == nil {
		return size
	}
	size += len(record.UniqueIdentifier) + len(record.Owner)
	size += len(record.RevocationReason.Message)
	for i := range record.Names {
		size += len(record.Names[i].Value) + 8
	}
	for _, group := range record.ObjectGroups {
		size += len(group) + 8
	}
	size += undoAttributeListBytes(record.Attributes)
	if record.Object != nil {
		size += undoObjectBytes(record.Object)
	}
	return size
}

// undoAttributeListBytes returns a conservative memory estimate of an attribute list. | undoAttributeListBytes 返回
// 属性列表的保守内存估算。
func undoAttributeListBytes(list AttributeList) int {
	size := 0
	for i := range list {
		size += undoAttributeOverhead + len(list[i].Name) + len(list[i].VendorIdentification)
		size += undoItemBytes(list[i].Value)
	}
	return size
}

// undoObjectBytes returns a conservative memory estimate of a managed object. | undoObjectBytes 返回受管对象的保守
// 内存估算。
func undoObjectBytes(object *Object) int {
	if object == nil {
		return 0
	}
	size := undoObjectOverhead
	if object.SymmetricKey != nil {
		size += undoKeyBlockBytes(object.SymmetricKey.KeyBlock)
	}
	if object.PublicKey != nil {
		size += undoKeyBlockBytes(object.PublicKey.KeyBlock)
	}
	if object.PrivateKey != nil {
		size += undoKeyBlockBytes(object.PrivateKey.KeyBlock)
	}
	if object.SecretData != nil {
		size += undoKeyBlockBytes(object.SecretData.KeyBlock)
	}
	if object.Certificate != nil {
		size += len(object.Certificate.CertificateValue)
	}
	if object.Template != nil {
		size += undoAttributeListBytes(object.Template.Attributes)
	}
	if object.Opaque != nil {
		size += len(object.Opaque.OpaqueDataValue)
	}
	return size
}

// undoKeyBlockBytes returns a conservative memory estimate of a key block. | undoKeyBlockBytes 返回密钥块的保守
// 内存估算。
func undoKeyBlockBytes(kb KeyBlock) int {
	size := undoEntryOverhead
	size += undoItemBytes(kb.Value.Material)
	size += undoAttributeListBytes(kb.Value.Attributes)
	if kb.Wrapping != nil {
		size += undoEntryOverhead + len(kb.Wrapping.MACSignature) + len(kb.Wrapping.IVCounterNonce)
	}
	return size
}

// undoItemBytes returns a conservative memory estimate of a TTLV item tree. | undoItemBytes 返回 TTLV 项树的保守
// 内存估算。
func undoItemBytes(item Item) int {
	size := undoItemOverhead + len(item.Value)
	for i := range item.Children {
		size += undoItemBytes(item.Children[i])
	}
	return size
}

// zeroizeRecord clears the key material held by a record. | zeroizeRecord 清除记录持有的密钥材料。
func zeroizeRecord(record *ObjectRecord) {
	if record == nil || record.Object == nil {
		return
	}
	record.Object.Zeroize()
}
