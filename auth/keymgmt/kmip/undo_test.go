package kmip

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// undoStoreCall records one store mutation attempted during an undo test. | undoStoreCall 记录撤销测试中尝试的一次
// 存储变更。
type undoStoreCall struct {
	// Method is "create", "update" or "delete". | Method 是 "create"、"update" 或 "delete"。
	Method string
	// UniqueIdentifier is the affected object. | UniqueIdentifier 是受影响的对象。
	UniqueIdentifier string
	// State is the lifecycle state in the supplied record. | State 是所提供记录的生命周期状态。
	State State
	// HasObject reports whether the supplied record carries an object. | HasObject 报告所提供记录是否携带对象。
	HasObject bool
}

// recordingStore records store mutations and can fail selected deletes. | recordingStore 记录存储变更并可让指定
// 删除失败。
type recordingStore struct {
	*MemoryStore
	mu             sync.Mutex
	calls          []undoStoreCall
	failDeletes    map[string]error
	failAllDeletes bool
}

// newRecordingStore returns an empty recording store. | newRecordingStore 返回空的记录存储。
func newRecordingStore() *recordingStore {
	return &recordingStore{MemoryStore: NewMemoryStore(), failDeletes: make(map[string]error)}
}

// Create implements Store. | Create 实现 Store。
func (s *recordingStore) Create(ctx context.Context, record ObjectRecord) error {
	s.recordCall("create", record)
	return s.MemoryStore.Create(ctx, record)
}

// Update implements Store. | Update 实现 Store。
func (s *recordingStore) Update(ctx context.Context, record ObjectRecord) error {
	s.recordCall("update", record)
	return s.MemoryStore.Update(ctx, record)
}

// Delete implements Store. | Delete 实现 Store。
func (s *recordingStore) Delete(ctx context.Context, uniqueIdentifier string) error {
	s.mu.Lock()
	s.calls = append(s.calls, undoStoreCall{Method: "delete", UniqueIdentifier: uniqueIdentifier})
	failure := s.failDeletes[uniqueIdentifier]
	if s.failAllDeletes && failure == nil {
		failure = errors.New("all deletes blocked")
	}
	s.mu.Unlock()
	if failure != nil {
		return failure
	}
	return s.MemoryStore.Delete(ctx, uniqueIdentifier)
}

// recordCall appends one recorded mutation. | recordCall 追加一次记录的变更。
func (s *recordingStore) recordCall(method string, record ObjectRecord) {
	s.mu.Lock()
	s.calls = append(s.calls, undoStoreCall{
		Method:           method,
		UniqueIdentifier: record.UniqueIdentifier,
		State:            record.State,
		HasObject:        record.Object != nil,
	})
	s.mu.Unlock()
}

// takeCalls returns and clears the recorded calls. | takeCalls 返回并清空记录的调用。
func (s *recordingStore) takeCalls() []undoStoreCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]undoStoreCall(nil), s.calls...)
	s.calls = nil
	return out
}

// undoRequest builds a Batch Undo request. | undoRequest 构造 Batch Undo 请求。
func undoRequest(items ...RequestBatchItem) RequestMessage {
	return RequestMessage{
		Header: RequestHeader{
			ProtocolVersion:              DefaultProtocolVersion,
			BatchErrorContinuationOption: BatchUndo,
		},
		BatchItems: items,
	}
}

// missingGetItem builds a Get item that always fails. | missingGetItem 构造总是失败的 Get 项。
func missingGetItem(t *testing.T) RequestBatchItem {
	t.Helper()
	return RequestBatchItem{Operation: OpGet, Payload: mustItem(t, GetRequest{UniqueIdentifier: "batch-undo-missing"})}
}

// createSymmetricItem builds a Create item for an AES-256 key. | createSymmetricItem 构造 AES-256 密钥的 Create 项。
func createSymmetricItem(t *testing.T) RequestBatchItem {
	t.Helper()
	return RequestBatchItem{
		Operation: OpCreate,
		Payload:   mustItem(t, CreateRequest{ObjectType: ObjectTypeSymmetricKey, TemplateAttribute: symmetricTemplate()}),
	}
}

// storeRecords returns all records currently persisted by server. | storeRecords 返回服务器当前持久化的全部记录。
func storeRecords(t *testing.T, server *Server) []ObjectRecord {
	t.Helper()
	records, err := server.store.List(context.Background())
	if err != nil {
		t.Fatalf("store.List: %v", err)
	}
	return records
}

// mustRecord loads one record from the server store. | mustRecord 从服务器存储加载一条记录。
func mustRecord(t *testing.T, server *Server, uniqueIdentifier string) ObjectRecord {
	t.Helper()
	record, err := server.store.Get(context.Background(), uniqueIdentifier)
	if err != nil {
		t.Fatalf("store.Get(%q): %v", uniqueIdentifier, err)
	}
	return record
}

// rawMaterial returns the raw key material of a record. | rawMaterial 返回记录的原始密钥材料。
func rawMaterial(t *testing.T, record ObjectRecord) []byte {
	t.Helper()
	kb, err := recordKeyBlock(&record)
	if err != nil {
		t.Fatalf("recordKeyBlock: %v", err)
	}
	material, err := kb.Value.Raw()
	if err != nil {
		t.Fatalf("key material is not raw: %v", err)
	}
	return append([]byte(nil), material...)
}

// TestBatchUndoJournalReverseOrder covers inverse-operation ordering and operation tagging. |
// TestBatchUndoJournalReverseOrder 覆盖逆操作顺序与操作标记。
func TestBatchUndoJournalReverseOrder(t *testing.T) {
	ctx := context.Background()
	store := newRecordingStore()
	for _, record := range []ObjectRecord{
		{UniqueIdentifier: "pre-active", State: StatePreActive},
		{UniqueIdentifier: "active", State: StateActive},
	} {
		if err := store.MemoryStore.Create(ctx, record); err != nil {
			t.Fatalf("seed %q: %v", record.UniqueIdentifier, err)
		}
	}
	journal := newBatchUndoLog(DefaultMaxUndoLogBytes)
	journal.beginItem(OpCreate)
	if err := journal.recordCreate("created"); err != nil {
		t.Fatalf("recordCreate: %v", err)
	}
	journal.beginItem(OpActivate)
	if err := journal.recordUpdate(ObjectRecord{UniqueIdentifier: "pre-active", State: StatePreActive}); err != nil {
		t.Fatalf("recordUpdate: %v", err)
	}
	journal.beginItem(OpDeleteAttribute)
	if err := journal.recordDelete(ObjectRecord{UniqueIdentifier: "active", State: StateActive}); err != nil {
		t.Fatalf("recordDelete: %v", err)
	}
	if len(journal.entries) != 3 {
		t.Fatalf("journal entries = %d, want 3 | 日志条目 = %d，期望 3", len(journal.entries), len(journal.entries))
	}
	if journal.entries[0].operation != OpCreate || journal.entries[1].operation != OpActivate ||
		journal.entries[2].operation != OpDeleteAttribute {
		t.Fatalf("journal operations = %v, %v, %v | 日志操作错误",
			journal.entries[0].operation, journal.entries[1].operation, journal.entries[2].operation)
	}
	if journal.entries[0].sequence != 1 || journal.entries[1].sequence != 2 || journal.entries[2].sequence != 3 {
		t.Fatalf("journal sequences = %d, %d, %d | 日志序号错误",
			journal.entries[0].sequence, journal.entries[1].sequence, journal.entries[2].sequence)
	}

	// Apply the forward mutations that the batch performed. | 应用批处理执行的正向变更。
	if err := store.MemoryStore.Create(ctx, ObjectRecord{UniqueIdentifier: "created", State: StatePreActive}); err != nil {
		t.Fatalf("forward create: %v", err)
	}
	if err := store.MemoryStore.Update(ctx, ObjectRecord{UniqueIdentifier: "pre-active", State: StateActive}); err != nil {
		t.Fatalf("forward update: %v", err)
	}
	if err := store.MemoryStore.Delete(ctx, "active"); err != nil {
		t.Fatalf("forward delete: %v", err)
	}
	store.takeCalls()

	if err := journal.rollback(ctx, store); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	calls := store.takeCalls()
	want := []undoStoreCall{
		{Method: "create", UniqueIdentifier: "active", State: StateActive, HasObject: false},
		{Method: "update", UniqueIdentifier: "pre-active", State: StatePreActive, HasObject: false},
		{Method: "delete", UniqueIdentifier: "created"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("rollback order = %+v, want %+v | 回滚顺序 = %+v，期望 %+v", calls, want, calls, want)
	}
	restored, err := store.MemoryStore.Get(ctx, "pre-active")
	if err != nil {
		t.Fatalf("restored object: %v | 恢复对象：%v", err, err)
	}
	if restored.State != StatePreActive {
		t.Fatalf("restored state = %s, want %s | 恢复状态 = %s，期望 %s", restored.State, StatePreActive, restored.State, StatePreActive)
	}
	if _, err := store.MemoryStore.Get(ctx, "created"); !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("created object still exists: %v | 新建对象仍然存在：%v", err, err)
	}
	if _, err := store.MemoryStore.Get(ctx, "active"); err != nil {
		t.Fatalf("deleted object was not recreated: %v | 已删除对象未被重建：%v", err, err)
	}
}

// TestBatchUndoJournalLimit covers memory accounting and the explicit over-limit error. |
// TestBatchUndoJournalLimit 覆盖内存核算与明确的超限错误。
func TestBatchUndoJournalLimit(t *testing.T) {
	identifier := "0123456789abcdef0123456789abcdef"
	journal := newBatchUndoLog(undoEntryOverhead + len(identifier))
	if err := journal.recordCreate(identifier); err != nil {
		t.Fatalf("create entry should fit: %v | 创建条目应当可容纳：%v", err, err)
	}
	if journal.used != undoEntryOverhead+len(identifier) {
		t.Fatalf("used = %d, want %d | 已用 = %d，期望 %d",
			journal.used, undoEntryOverhead+len(identifier), journal.used, undoEntryOverhead+len(identifier))
	}
	object := NewSymmetricKeyObject(rawKeyBlock(AlgorithmAES, testKeyMaterial()))
	update := ObjectRecord{UniqueIdentifier: identifier, State: StateActive, Object: &object}
	if err := journal.recordUpdate(update); !errors.Is(err, ErrUndoLogLimit) {
		t.Fatalf("over-limit update error = %v, want ErrUndoLogLimit | 超限更新错误 = %v，期望 ErrUndoLogLimit", err, err)
	}
	if len(journal.entries) != 1 || journal.used != undoEntryOverhead+len(identifier) {
		t.Fatalf("failed entry changed the journal: entries=%d used=%d | 失败条目改变了日志：条目=%d 已用=%d",
			len(journal.entries), journal.used, len(journal.entries), journal.used)
	}
	if err := journal.recordDelete(update); !errors.Is(err, ErrUndoLogLimit) {
		t.Fatalf("over-limit delete error = %v, want ErrUndoLogLimit | 超限删除错误 = %v，期望 ErrUndoLogLimit", err, err)
	}
	withoutMaterial := undoRecordBytes(&ObjectRecord{UniqueIdentifier: identifier})
	if withMaterial := undoRecordBytes(&update); withMaterial <= withoutMaterial {
		t.Fatalf("record accounting ignores key material: %d <= %d | 记录核算未计入密钥材料：%d <= %d",
			withMaterial, withoutMaterial, withMaterial, withoutMaterial)
	}
	journal.clear()
	if len(journal.entries) != 0 || journal.used != 0 {
		t.Fatalf("clear left entries=%d used=%d | 清空后条目=%d 已用=%d", len(journal.entries), journal.used, len(journal.entries), journal.used)
	}
}

// TestBatchUndoRollbackFailureCombinesErrors covers best-effort rollback and joined diagnostics. |
// TestBatchUndoRollbackFailureCombinesErrors 覆盖尽力回滚与合并诊断。
func TestBatchUndoRollbackFailureCombinesErrors(t *testing.T) {
	ctx := context.Background()
	store := newRecordingStore()
	store.failDeletes["first"] = errors.New("first delete failed")
	store.failDeletes["second"] = errors.New("second delete failed")
	journal := newBatchUndoLog(DefaultMaxUndoLogBytes)
	if err := journal.recordCreate("first"); err != nil {
		t.Fatalf("recordCreate first: %v", err)
	}
	if err := journal.recordCreate("second"); err != nil {
		t.Fatalf("recordCreate second: %v", err)
	}
	err := journal.rollback(ctx, store)
	if err == nil {
		t.Fatal("rollback unexpectedly succeeded | 回滚意外成功")
	}
	if !errors.Is(err, ErrOperationFailed) {
		t.Fatalf("rollback error does not match ErrOperationFailed: %v | 回滚错误不匹配 ErrOperationFailed：%v", err, err)
	}
	message := err.Error()
	if !strings.Contains(message, `"first"`) || !strings.Contains(message, `"second"`) {
		t.Fatalf("rollback error is not diagnostic: %v | 回滚错误不可诊断：%v", err, err)
	}
	calls := store.takeCalls()
	if len(calls) != 2 || calls[0].UniqueIdentifier != "second" || calls[1].UniqueIdentifier != "first" {
		t.Fatalf("failed rollback did not continue in reverse order: %+v | 失败回滚未按逆序继续：%+v", calls, calls)
	}
}

// TestBatchUndoCreateAndRegisterRollback covers Create and Register compensation. |
// TestBatchUndoCreateAndRegisterRollback 覆盖 Create 与 Register 的补偿。
func TestBatchUndoCreateAndRegisterRollback(t *testing.T) {
	server := newTestServer(t)
	response := roundTrip(t, server, undoRequest(
		createSymmetricItem(t),
		RequestBatchItem{
			Operation: OpRegister,
			Payload: mustItem(t, RegisterRequest{
				ObjectType: ObjectTypeSymmetricKey,
				Object:     NewSymmetricKeyObject(rawKeyBlock(AlgorithmAES, testKeyMaterial())),
			}),
		},
		missingGetItem(t),
	))
	if len(response.BatchItems) != 3 {
		t.Fatalf("batch items = %d, want 3 | 批处理项 = %d，期望 3", len(response.BatchItems), len(response.BatchItems))
	}
	for i := 0; i < 2; i++ {
		if response.BatchItems[i].ResultStatus != ResultStatusOperationUndone {
			t.Fatalf("item %d status = %v, want OperationUndone | 项 %d 状态 = %v，期望 OperationUndone",
				i, response.BatchItems[i].ResultStatus, i, response.BatchItems[i].ResultStatus)
		}
		if response.BatchItems[i].Payload.Type != 0 {
			t.Fatalf("undone item %d retained its payload | 已撤销项 %d 保留了负载", i, i)
		}
	}
	if response.BatchItems[2].ResultStatus != ResultStatusOperationFailed {
		t.Fatalf("failing item status = %v | 失败项状态 = %v", response.BatchItems[2].ResultStatus, response.BatchItems[2].ResultStatus)
	}
	if records := storeRecords(t, server); len(records) != 0 {
		t.Fatalf("rollback left %d records | 回滚留下 %d 条记录", len(records), len(records))
	}
	if server.undo != nil {
		t.Fatal("journal was not cleared after the batch | 批处理结束后日志未清空")
	}
}

// TestBatchUndoCreateKeyPairRollback covers compensation for both halves of a key pair. |
// TestBatchUndoCreateKeyPairRollback 覆盖密钥对两部分的补偿。
func TestBatchUndoCreateKeyPairRollback(t *testing.T) {
	server := newTestServer(t)
	response := roundTrip(t, server, undoRequest(
		RequestBatchItem{
			Operation: OpCreateKeyPair,
			Payload: mustItem(t, CreateKeyPairRequest{
				CommonTemplateAttribute: &TemplateAttribute{Attributes: AttributeList{
					NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmEd25519)),
					NewIntegerAttribute(AttributeCryptographicLength, 256),
				}},
			}),
		},
		missingGetItem(t),
	))
	if len(response.BatchItems) != 2 || response.BatchItems[0].ResultStatus != ResultStatusOperationUndone {
		t.Fatalf("key pair rollback batch = %+v | 密钥对回滚批处理 = %+v", response.BatchItems, response.BatchItems)
	}
	if records := storeRecords(t, server); len(records) != 0 {
		t.Fatalf("key pair rollback left %d records | 密钥对回滚留下 %d 条记录", len(records), len(records))
	}
}

// TestBatchUndoLifecycleRestore covers Activate, Revoke and Destroy rollback, including material restoration and
// untouched neighbours. | TestBatchUndoLifecycleRestore 覆盖 Activate、Revoke 与 Destroy 回滚，包括材料恢复与
// 未受影响对象。
func TestBatchUndoLifecycleRestore(t *testing.T) {
	t.Run("activate", func(t *testing.T) {
		server := newTestServer(t)
		uid := createSymmetric(t, server)
		neighbour := createSymmetric(t, server)
		neighbourBefore := mustRecord(t, server, neighbour)
		before := mustRecord(t, server, uid)
		response := roundTrip(t, server, undoRequest(
			RequestBatchItem{Operation: OpActivate, Payload: mustItem(t, ActivateRequest{UniqueIdentifier: uid})},
			missingGetItem(t),
		))
		if response.BatchItems[0].ResultStatus != ResultStatusOperationUndone {
			t.Fatalf("activate status = %v | 激活状态 = %v", response.BatchItems[0].ResultStatus, response.BatchItems[0].ResultStatus)
		}
		after := mustRecord(t, server, uid)
		if after.State != StatePreActive || !after.ActivationDate.IsZero() || !after.LastChangeDate.Equal(before.LastChangeDate) {
			t.Fatalf("activate rollback = state %s, activation %v, change %v | 激活回滚 = 状态 %s，激活 %v，变更 %v",
				after.State, after.ActivationDate, after.LastChangeDate, after.State, after.ActivationDate, after.LastChangeDate)
		}
		if neighbourAfter := mustRecord(t, server, neighbour); !reflect.DeepEqual(neighbourBefore, neighbourAfter) {
			t.Fatalf("untouched neighbour changed: %+v -> %+v | 未受影响的相邻对象发生变化：%+v -> %+v",
				neighbourBefore, neighbourAfter, neighbourBefore, neighbourAfter)
		}
	})

	t.Run("revoke", func(t *testing.T) {
		server := newTestServer(t)
		uid := createSymmetric(t, server)
		activateKey(t, server, uid)
		before := mustRecord(t, server, uid)
		response := roundTrip(t, server, undoRequest(
			RequestBatchItem{
				Operation: OpRevoke,
				Payload: mustItem(t, RevokeRequest{
					UniqueIdentifier: uid,
					Reason:           RevocationReason{Code: RevocationCessationOfOperation},
				}),
			},
			missingGetItem(t),
		))
		if response.BatchItems[0].ResultStatus != ResultStatusOperationUndone {
			t.Fatalf("revoke status = %v | 撤销状态 = %v", response.BatchItems[0].ResultStatus, response.BatchItems[0].ResultStatus)
		}
		after := mustRecord(t, server, uid)
		if after.State != StateActive || !after.DeactivationDate.IsZero() || after.RevocationReason.Code != 0 ||
			!after.LastChangeDate.Equal(before.LastChangeDate) {
			t.Fatalf("revoke rollback = state %s, deactivation %v, reason %v, change %v | 撤销回滚 = 状态 %s，停用 %v，原因 %v，变更 %v",
				after.State, after.DeactivationDate, after.RevocationReason,
				after.LastChangeDate, after.State, after.DeactivationDate, after.RevocationReason, after.LastChangeDate)
		}
	})

	t.Run("destroy", func(t *testing.T) {
		server := newTestServer(t)
		uid := createSymmetric(t, server)
		activateKey(t, server, uid)
		before := mustRecord(t, server, uid)
		material := rawMaterial(t, before)
		response := roundTrip(t, server, undoRequest(
			RequestBatchItem{Operation: OpDestroy, Payload: mustItem(t, DestroyRequest{UniqueIdentifier: uid})},
			missingGetItem(t),
		))
		if response.BatchItems[0].ResultStatus != ResultStatusOperationUndone {
			t.Fatalf("destroy status = %v | 销毁状态 = %v", response.BatchItems[0].ResultStatus, response.BatchItems[0].ResultStatus)
		}
		after := mustRecord(t, server, uid)
		if after.State != StateActive || after.Object == nil {
			t.Fatalf("destroy rollback = state %s, object %v | 销毁回滚 = 状态 %s，对象 %v",
				after.State, after.Object != nil, after.State, after.Object != nil)
		}
		if restored := rawMaterial(t, after); !bytes.Equal(restored, material) {
			t.Fatal("destroy rollback did not restore the key material | 销毁回滚未恢复密钥材料")
		}
		if !after.DestroyDate.IsZero() || !after.LastChangeDate.Equal(before.LastChangeDate) {
			t.Fatalf("destroy rollback dates = destroy %v, change %v | 销毁回滚日期 = 销毁 %v，变更 %v",
				after.DestroyDate, after.LastChangeDate, after.DestroyDate, after.LastChangeDate)
		}
		// The restored object must be usable again. | 恢复的对象必须可以再次使用。
		if _, err := server.loadActive(uid, UsageMaskEncrypt); err != nil {
			t.Fatalf("restored object is not usable: %v | 恢复对象不可用：%v", err, err)
		}
	})
}

// TestBatchUndoDeriveAndUnwrapRollback covers generated-object compensation for Derive Key and Unwrap Key. |
// TestBatchUndoDeriveAndUnwrapRollback 覆盖 Derive Key 与 Unwrap Key 的生成对象补偿。
func TestBatchUndoDeriveAndUnwrapRollback(t *testing.T) {
	server := newTestServer(t)
	source := createSymmetric(t, server)
	activateKey(t, server, source)
	deriveResponse := roundTrip(t, server, undoRequest(
		RequestBatchItem{
			Operation: OpDeriveKey,
			Payload: mustItem(t, DeriveKeyRequest{
				ObjectType:        ObjectTypeSymmetricKey,
				UniqueIdentifiers: []string{source},
				DerivationMethod:  DerivationMethodHKDF,
				DerivationParameters: DerivationParameters{
					DerivationData: []byte("context"),
					Salt:           []byte("salt"),
				},
				TemplateAttribute: TemplateAttribute{Attributes: AttributeList{
					NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmAES)),
					NewIntegerAttribute(AttributeCryptographicLength, 128),
				}},
			}),
		},
		missingGetItem(t),
	))
	if deriveResponse.BatchItems[0].ResultStatus != ResultStatusOperationUndone {
		t.Fatalf("derive status = %v | 派生状态 = %v", deriveResponse.BatchItems[0].ResultStatus, deriveResponse.BatchItems[0].ResultStatus)
	}
	if records := storeRecords(t, server); len(records) != 1 || records[0].UniqueIdentifier != source {
		t.Fatalf("derive rollback left %+v | 派生回滚留下 %+v", records, records)
	}

	wrapping := createSymmetric(t, server)
	activateKey(t, server, wrapping)
	target := createSymmetric(t, server)
	activateKey(t, server, target)
	spec := KeyWrappingSpecification{
		WrappingMethod:           WrappingMethodEncrypt,
		EncryptionKeyInformation: &EncryptionKeyInformation{UniqueIdentifier: wrapping},
	}
	wrappedResponse, err := DecodeWrapKeyResponse(runOp(t, server, OpWrapKey, WrapKeyRequest{UniqueIdentifier: target, KeyWrappingSpecification: spec}))
	if err != nil {
		t.Fatalf("DecodeWrapKeyResponse: %v", err)
	}
	unwrapResponse := roundTrip(t, server, undoRequest(
		RequestBatchItem{
			Operation: OpUnwrapKey,
			Payload: mustItem(t, UnwrapKeyRequest{
				Object: wrappedResponse.Object,
				TemplateAttribute: TemplateAttribute{Attributes: AttributeList{
					NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmAES)),
					NewIntegerAttribute(AttributeCryptographicLength, 256),
				}},
			}),
		},
		missingGetItem(t),
	))
	if unwrapResponse.BatchItems[0].ResultStatus != ResultStatusOperationUndone {
		t.Fatalf("unwrap status = %v | 解封状态 = %v", unwrapResponse.BatchItems[0].ResultStatus, unwrapResponse.BatchItems[0].ResultStatus)
	}
	if records := storeRecords(t, server); len(records) != 3 {
		t.Fatalf("unwrap rollback left %d records, want 3 | 解封回滚留下 %d 条记录，期望 3", len(records), len(records))
	}
}

// TestBatchUndoReadOnlyOperationsDoNotJournal proves that Get, Encrypt, Decrypt and Sign consume no journal budget. |
// TestBatchUndoReadOnlyOperationsDoNotJournal 证明 Get、Encrypt、Decrypt 与 Sign 不消耗日志预算。
func TestBatchUndoReadOnlyOperationsDoNotJournal(t *testing.T) {
	server, err := NewServer(ServerConfig{AllowPlaintext: true, Store: NewMemoryStore(), MaxUndoLogBytes: 1})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	symmetric := createSymmetric(t, server)
	activateKey(t, server, symmetric)
	privateID, _ := createKeyPair(t, server, AlgorithmEd25519, 256)
	activateKey(t, server, privateID)
	plaintext := []byte("batch undo read only")
	gcm := CryptographicParameters{BlockCipherMode: BlockCipherModeGCM, RandomIV: true}
	encrypted, err := DecodeEncryptResponse(runOp(t, server, OpEncrypt, EncryptRequest{
		UniqueIdentifier: symmetric, CryptographicParameters: &gcm, Data: plaintext,
	}))
	if err != nil {
		t.Fatalf("DecodeEncryptResponse: %v", err)
	}
	signatureParams := CryptographicParameters{DigitalSignatureAlgorithm: DigitalSignatureEd25519}
	response := roundTrip(t, server, undoRequest(
		RequestBatchItem{Operation: OpEncrypt, Payload: mustItem(t, EncryptRequest{
			UniqueIdentifier: symmetric, CryptographicParameters: &gcm, Data: plaintext,
		})},
		RequestBatchItem{Operation: OpDecrypt, Payload: mustItem(t, DecryptRequest{
			UniqueIdentifier:           symmetric,
			CryptographicParameters:    &gcm,
			Data:                       encrypted.Data,
			IVCounterNonce:             encrypted.IVCounterNonce,
			AuthenticatedEncryptionTag: encrypted.AuthenticatedEncryptionTag,
		})},
		RequestBatchItem{Operation: OpSign, Payload: mustItem(t, SignRequest{
			UniqueIdentifier:        privateID,
			CryptographicParameters: &signatureParams,
			Data:                    plaintext,
		})},
		missingGetItem(t),
	))
	if len(response.BatchItems) != 4 {
		t.Fatalf("batch items = %d, want 4 | 批处理项 = %d，期望 4", len(response.BatchItems), len(response.BatchItems))
	}
	for i := 0; i < 3; i++ {
		if response.BatchItems[i].ResultStatus != ResultStatusOperationUndone {
			t.Fatalf("read-only item %d status = %v, want OperationUndone (no journal entry) | 只读项 %d 状态 = %v，期望 OperationUndone（无日志条目）",
				i, response.BatchItems[i].ResultStatus, i, response.BatchItems[i].ResultStatus)
		}
	}
	if records := storeRecords(t, server); len(records) != 3 {
		t.Fatalf("read-only batch changed the store: %d records | 只读批处理改变了存储：%d 条记录", len(records), len(records))
	}
}

// TestBatchUndoJournalLimitRejectsOperation covers the server memory budget before mutation. |
// TestBatchUndoJournalLimitRejectsOperation 覆盖变更前的服务器内存预算。
func TestBatchUndoJournalLimitRejectsOperation(t *testing.T) {
	t.Run("update", func(t *testing.T) {
		server, err := NewServer(ServerConfig{AllowPlaintext: true, Store: NewMemoryStore(), MaxUndoLogBytes: 128})
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		t.Cleanup(func() { _ = server.Close() })
		uid := createSymmetric(t, server)
		response := roundTrip(t, server, undoRequest(
			RequestBatchItem{Operation: OpActivate, Payload: mustItem(t, ActivateRequest{UniqueIdentifier: uid})},
			missingGetItem(t),
		))
		if len(response.BatchItems) != 1 {
			t.Fatalf("batch items = %d, want 1 because Stop follows the limit error | 批处理项 = %d，期望 1（超限错误后停止）",
				len(response.BatchItems), len(response.BatchItems))
		}
		if response.BatchItems[0].ResultStatus != ResultStatusOperationFailed ||
			!strings.Contains(response.BatchItems[0].ResultMessage, "undo journal") {
			t.Fatalf("limit failure = %+v | 超限失败 = %+v", response.BatchItems[0], response.BatchItems[0])
		}
		records := storeRecords(t, server)
		if len(records) != 1 || records[0].State != StatePreActive {
			t.Fatalf("over-limit activation changed the store: %+v | 超限激活改变了存储：%+v", records, records)
		}
	})

	t.Run("create", func(t *testing.T) {
		server, err := NewServer(ServerConfig{AllowPlaintext: true, Store: NewMemoryStore(), MaxUndoLogBytes: 1})
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		t.Cleanup(func() { _ = server.Close() })
		response := roundTrip(t, server, undoRequest(createSymmetricItem(t)))
		if len(response.BatchItems) != 1 || response.BatchItems[0].ResultStatus != ResultStatusOperationFailed ||
			!strings.Contains(response.BatchItems[0].ResultMessage, "undo journal") {
			t.Fatalf("create limit failure = %+v | 创建超限失败 = %+v", response.BatchItems, response.BatchItems)
		}
		if records := storeRecords(t, server); len(records) != 0 {
			t.Fatalf("over-limit create changed the store: %d records | 超限创建改变了存储：%d 条记录", len(records), len(records))
		}
	})
}

// TestBatchUndoConcurrentBatchesAreIsolated covers per-batch journal isolation under concurrency. |
// TestBatchUndoConcurrentBatchesAreIsolated 覆盖并发下每批日志的隔离。
func TestBatchUndoConcurrentBatchesAreIsolated(t *testing.T) {
	server := newTestServer(t)
	const (
		failingBatches    = 8
		successfulBatches = 8
	)
	requests := make([]RequestMessage, 0, failingBatches+successfulBatches)
	for i := 0; i < failingBatches; i++ {
		requests = append(requests, undoRequest(createSymmetricItem(t), missingGetItem(t)))
	}
	for i := 0; i < successfulBatches; i++ {
		requests = append(requests, undoRequest(createSymmetricItem(t)))
	}
	responses := make([]ResponseMessage, len(requests))
	var wg sync.WaitGroup
	for i := range requests {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			responses[index] = server.handleMessage(nil, requests[index])
		}(i)
	}
	wg.Wait()
	for i := 0; i < failingBatches; i++ {
		if len(responses[i].BatchItems) != 2 ||
			responses[i].BatchItems[0].ResultStatus != ResultStatusOperationUndone ||
			responses[i].BatchItems[1].ResultStatus != ResultStatusOperationFailed {
			t.Fatalf("failing batch %d response = %+v | 失败批处理 %d 响应 = %+v", i, responses[i].BatchItems, i, responses[i].BatchItems)
		}
	}
	for i := failingBatches; i < len(responses); i++ {
		if len(responses[i].BatchItems) != 1 || responses[i].BatchItems[0].ResultStatus != ResultStatusSuccess {
			t.Fatalf("successful batch %d response = %+v | 成功批处理 %d 响应 = %+v", i, responses[i].BatchItems, i, responses[i].BatchItems)
		}
	}
	if records := storeRecords(t, server); len(records) != successfulBatches {
		t.Fatalf("store holds %d records, want %d | 存储有 %d 条记录，期望 %d",
			len(records), successfulBatches, len(records), successfulBatches)
	}
	if server.undo != nil {
		t.Fatal("journal was not cleared after concurrent batches | 并发批处理后日志未清空")
	}
}

// TestBatchUndoRestoreFailureIsReported covers the response and store outcome when rollback cannot complete. |
// TestBatchUndoRestoreFailureIsReported 覆盖回滚无法完成时的响应与存储结果。
func TestBatchUndoRestoreFailureIsReported(t *testing.T) {
	store := newRecordingStore()
	store.failAllDeletes = true
	server, err := NewServer(ServerConfig{AllowPlaintext: true, Store: store})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	response := roundTrip(t, server, undoRequest(createSymmetricItem(t), missingGetItem(t)))
	if len(response.BatchItems) != 2 ||
		response.BatchItems[0].ResultStatus != ResultStatusOperationFailed ||
		response.BatchItems[0].ResultReason != ResultReasonGeneralFailure ||
		!strings.Contains(response.BatchItems[0].ResultMessage, "batch undo failed") {
		t.Fatalf("restore failure response = %+v | 恢复失败响应 = %+v", response.BatchItems, response.BatchItems)
	}
	if records := storeRecords(t, server); len(records) != 1 {
		t.Fatalf("failed rollback left %d records, want the unremovable one | 失败回滚留下 %d 条记录，期望保留无法删除的记录",
			len(records), len(records))
	}
	if server.undo != nil {
		t.Fatal("journal was not cleared after a failed rollback | 回滚失败后日志未清空")
	}
}
