package kmip

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// newTestServer returns a plaintext server suitable for in-process tests. | newTestServer 返回适合进程内测试的明文服务器。
func newTestServer(t *testing.T) *Server {
	t.Helper()
	server, err := NewServer(ServerConfig{AllowPlaintext: true, Store: NewMemoryStore()})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

// testHeader returns a default request header. | testHeader 返回默认请求头。
func testHeader() RequestHeader {
	return RequestHeader{ProtocolVersion: DefaultProtocolVersion}
}

// payloadEncoder is any payload type with an Item method. | payloadEncoder 是任何带 Item 方法的负载类型。
type payloadEncoder interface {
	Item() (Item, error)
}

// mustItem returns the encoded payload or fails the test. | mustItem 返回编码后的负载，失败时终止测试。
func mustItem(t *testing.T, encoder payloadEncoder) Item {
	t.Helper()
	item, err := encoder.Item()
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}
	return item
}

// roundTrip encodes, handles and decodes one request message. | roundTrip 编码、处理并解码一条请求消息。
func roundTrip(t *testing.T, server *Server, request RequestMessage) ResponseMessage {
	t.Helper()
	encoded, err := EncodeRequest(request)
	if err != nil {
		t.Fatalf("EncodeRequest: %v", err)
	}
	decoded, err := DecodeRequest(encoded)
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}
	response := server.handleMessage(nil, decoded)
	data, err := EncodeResponse(response)
	if err != nil {
		t.Fatalf("EncodeResponse: %v", err)
	}
	out, err := DecodeResponse(data)
	if err != nil {
		t.Fatalf("DecodeResponse: %v", err)
	}
	return out
}

// symmetricTemplate returns a template requesting an AES-256 key. | symmetricTemplate 返回请求 AES-256 密钥的模板。
func symmetricTemplate() TemplateAttribute {
	return TemplateAttribute{Attributes: AttributeList{
		NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmAES)),
		NewIntegerAttribute(AttributeCryptographicLength, 256),
	}}
}

// createSymmetric creates a symmetric key and returns its unique identifier. | createSymmetric 创建对称密钥并返回其唯一标识符。
func createSymmetric(t *testing.T, server *Server) string {
	t.Helper()
	response := roundTrip(t, server, RequestMessage{
		Header: testHeader(),
		BatchItems: []RequestBatchItem{{
			Operation: OpCreate,
			Payload:   mustItem(t, CreateRequest{ObjectType: ObjectTypeSymmetricKey, TemplateAttribute: symmetricTemplate()}),
		}},
	})
	if len(response.BatchItems) != 1 {
		t.Fatalf("Create returned %d batch items | Create 返回 %d 个批处理项", len(response.BatchItems), len(response.BatchItems))
	}
	item := response.BatchItems[0]
	if err := item.Err(); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	created, err := DecodeCreateResponse(item.Payload)
	if err != nil {
		t.Fatalf("DecodeCreateResponse: %v", err)
	}
	if created.UniqueIdentifier == "" {
		t.Fatal("Create returned an empty unique identifier | Create 返回空唯一标识符")
	}
	return created.UniqueIdentifier
}

// stateOf returns the State attribute of an object. | stateOf 返回对象的 State 属性。
func stateOf(t *testing.T, server *Server, uid string) State {
	t.Helper()
	response := roundTrip(t, server, RequestMessage{
		Header: testHeader(),
		BatchItems: []RequestBatchItem{{
			Operation: OpGetAttributes,
			Payload: mustItem(t, GetAttributesRequest{
				UniqueIdentifier: uid,
				AttributeNames:   []string{AttributeState},
			}),
		}},
	})
	item := response.BatchItems[0]
	if err := item.Err(); err != nil {
		t.Fatalf("GetAttributes failed: %v", err)
	}
	decoded, err := DecodeGetAttributesResponse(item.Payload)
	if err != nil {
		t.Fatalf("DecodeGetAttributesResponse: %v", err)
	}
	value, ok, err := decoded.LookupEnumeration(AttributeState)
	if err != nil || !ok {
		t.Fatalf("State attribute: ok=%v err=%v", ok, err)
	}
	return State(value)
}

// TestServerCreateGetLifecycle covers Create, Get, Activate, Revoke and Destroy. | TestServerCreateGetLifecycle
// 覆盖 Create、Get、Activate、Revoke 与 Destroy。
func TestServerCreateGetLifecycle(t *testing.T) {
	server := newTestServer(t)
	uid := createSymmetric(t, server)

	if state := stateOf(t, server, uid); state != StatePreActive {
		t.Fatalf("new object state = %s, want PreActive | 新对象状态为 %s，期望 PreActive", state, state)
	}

	response := roundTrip(t, server, RequestMessage{
		Header: testHeader(),
		BatchItems: []RequestBatchItem{{
			Operation: OpGet,
			Payload:   mustItem(t, GetRequest{UniqueIdentifier: uid}),
		}},
	})
	if err := response.BatchItems[0].Err(); err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	got, err := DecodeGetResponse(response.BatchItems[0].Payload)
	if err != nil {
		t.Fatalf("DecodeGetResponse: %v", err)
	}
	if got.UniqueIdentifier != uid || got.ObjectType != ObjectTypeSymmetricKey {
		t.Fatalf("Get returned uid=%q type=%s | Get 返回 uid=%q 类型=%s", got.UniqueIdentifier, got.ObjectType, got.UniqueIdentifier, got.ObjectType)
	}
	kb, err := got.Object.KeyBlock()
	if err != nil {
		t.Fatalf("Get object key block: %v", err)
	}
	if kb.Algorithm != AlgorithmAES || kb.Length != 256 {
		t.Fatalf("Get key block algorithm=%s length=%d | Get 密钥块算法=%s 长度=%d", kb.Algorithm, kb.Length, kb.Algorithm, kb.Length)
	}

	response = roundTrip(t, server, RequestMessage{
		Header: testHeader(),
		BatchItems: []RequestBatchItem{{
			Operation: OpActivate,
			Payload:   mustItem(t, ActivateRequest{UniqueIdentifier: uid}),
		}},
	})
	if err := response.BatchItems[0].Err(); err != nil {
		t.Fatalf("Activate failed: %v", err)
	}
	if state := stateOf(t, server, uid); state != StateActive {
		t.Fatalf("activated state = %s, want Active | 激活后状态为 %s，期望 Active", state, state)
	}

	// A second activation is an illegal state transition. | 第二次激活是非法状态迁移。
	response = roundTrip(t, server, RequestMessage{
		Header: testHeader(),
		BatchItems: []RequestBatchItem{{
			Operation: OpActivate,
			Payload:   mustItem(t, ActivateRequest{UniqueIdentifier: uid}),
		}},
	})
	if response.BatchItems[0].ResultReason != ResultReasonIllegalOperation {
		t.Fatalf("second Activate reason = %s, want Illegal Operation | 第二次 Activate 原因为 %s，期望非法操作", response.BatchItems[0].ResultReason, response.BatchItems[0].ResultReason)
	}

	response = roundTrip(t, server, RequestMessage{
		Header: testHeader(),
		BatchItems: []RequestBatchItem{{
			Operation: OpRevoke,
			Payload: mustItem(t, RevokeRequest{
				UniqueIdentifier: uid,
				Reason:           RevocationReason{Code: RevocationUnspecified},
			}),
		}},
	})
	if err := response.BatchItems[0].Err(); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}
	if state := stateOf(t, server, uid); state != StateDeactivated {
		t.Fatalf("revoked state = %s, want Deactivated | 撤销后状态为 %s，期望 Deactivated", state, state)
	}

	response = roundTrip(t, server, RequestMessage{
		Header: testHeader(),
		BatchItems: []RequestBatchItem{{
			Operation: OpDestroy,
			Payload:   mustItem(t, DestroyRequest{UniqueIdentifier: uid}),
		}},
	})
	if err := response.BatchItems[0].Err(); err != nil {
		t.Fatalf("Destroy failed: %v", err)
	}
	if state := stateOf(t, server, uid); state != StateDestroyed {
		t.Fatalf("destroyed state = %s, want Destroyed | 销毁后状态为 %s，期望 Destroyed", state, state)
	}

	response = roundTrip(t, server, RequestMessage{
		Header: testHeader(),
		BatchItems: []RequestBatchItem{{
			Operation: OpGet,
			Payload:   mustItem(t, GetRequest{UniqueIdentifier: uid}),
		}},
	})
	if reason := response.BatchItems[0].ResultReason; reason != ResultReasonIllegalOperation {
		t.Fatalf("Get after destroy reason = %s, want Illegal Operation | 销毁后 Get 原因为 %s，期望非法操作", reason, reason)
	}
}

// TestServerBatchErrorPolicy covers Stop and Continue batch continuation options. | TestServerBatchErrorPolicy
// 覆盖 Stop 与 Continue 两种批处理失败继续策略。
func TestServerBatchErrorPolicy(t *testing.T) {
	server := newTestServer(t)
	missing := mustItem(t, GetRequest{UniqueIdentifier: "does-not-exist"})
	create := mustItem(t, CreateRequest{ObjectType: ObjectTypeSymmetricKey, TemplateAttribute: symmetricTemplate()})

	batch := []RequestBatchItem{
		{Operation: OpGet, UniqueBatchItemID: []byte{1}, Payload: missing},
		{Operation: OpCreate, UniqueBatchItemID: []byte{2}, Payload: create},
	}

	// Stop: the failing first item ends the batch. | Stop：首个失败项终止批处理。
	header := testHeader()
	header.BatchErrorContinuationOption = BatchStop
	response := roundTrip(t, server, RequestMessage{Header: header, BatchItems: batch})
	if len(response.BatchItems) != 1 {
		t.Fatalf("BatchStop returned %d items, want 1 | BatchStop 返回 %d 项，期望 1 项", len(response.BatchItems), len(response.BatchItems))
	}
	if response.BatchItems[0].ResultReason != ResultReasonItemNotFound {
		t.Fatalf("BatchStop reason = %s, want Item Not Found | BatchStop 原因为 %s，期望对象不存在", response.BatchItems[0].ResultReason, response.BatchItems[0].ResultReason)
	}

	// Continue: later items still execute. | Continue：后续项仍然执行。
	header = testHeader()
	header.BatchErrorContinuationOption = BatchContinue
	response = roundTrip(t, server, RequestMessage{Header: header, BatchItems: batch})
	if len(response.BatchItems) != 2 {
		t.Fatalf("BatchContinue returned %d items, want 2 | BatchContinue 返回 %d 项，期望 2 项", len(response.BatchItems), len(response.BatchItems))
	}
	if response.BatchItems[0].ResultReason != ResultReasonItemNotFound {
		t.Fatalf("first item reason = %s, want Item Not Found | 首项原因为 %s，期望对象不存在", response.BatchItems[0].ResultReason, response.BatchItems[0].ResultReason)
	}
	if err := response.BatchItems[1].Err(); err != nil {
		t.Fatalf("second item failed after Continue: %v", err)
	}
	created, err := DecodeCreateResponse(response.BatchItems[1].Payload)
	if err != nil || created.UniqueIdentifier == "" {
		t.Fatalf("Create after Continue: uid=%q err=%v", created.UniqueIdentifier, err)
	}
	if string(response.BatchItems[0].UniqueBatchItemID) != string([]byte{1}) ||
		string(response.BatchItems[1].UniqueBatchItemID) != string([]byte{2}) {
		t.Fatal("batch item identifiers were not correlated | 批处理项标识未关联")
	}
}

// TestServerUnsupportedOperation reports an unsupported operation reason. | TestServerUnsupportedOperation 报告不支持操作的原因。
func TestServerUnsupportedOperation(t *testing.T) {
	server := newTestServer(t)
	response := roundTrip(t, server, RequestMessage{
		Header: testHeader(),
		BatchItems: []RequestBatchItem{{
			Operation: OpArchive,
			Payload:   mustItem(t, GetRequest{UniqueIdentifier: "any"}),
		}},
	})
	if response.BatchItems[0].ResultReason != ResultReasonOperationNotSupported {
		t.Fatalf("reason = %s, want Operation Not Supported | 原因为 %s，期望操作不支持", response.BatchItems[0].ResultReason, response.BatchItems[0].ResultReason)
	}
	var result *ResultError
	if !errors.As(response.BatchItems[0].Err(), &result) {
		t.Fatal("batch error is not a *ResultError | 批处理错误不是 *ResultError")
	}
	if !errors.Is(result, ErrUnsupported) {
		t.Fatalf("errors.Is(ErrUnsupported) = false | errors.Is(ErrUnsupported) 为 false")
	}
}

// TestServerServeFraming exercises the length-prefixed transport over net.Pipe. | TestServerServeFraming
// 通过 net.Pipe 验证长度前缀传输。
func TestServerServeFraming(t *testing.T) {
	server := newTestServer(t)
	client, peer := net.Pipe()
	defer func() { _ = client.Close() }()
	done := make(chan error, 1)
	go func() { done <- server.Serve(peer) }()

	request := RequestMessage{
		Header: testHeader(),
		BatchItems: []RequestBatchItem{{
			Operation: OpCreate,
			Payload:   mustItem(t, CreateRequest{ObjectType: ObjectTypeSymmetricKey, TemplateAttribute: symmetricTemplate()}),
		}},
	}
	encoded, err := EncodeRequest(request)
	if err != nil {
		t.Fatalf("EncodeRequest: %v", err)
	}
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Write(encoded); err != nil {
		t.Fatalf("write request: %v", err)
	}
	var header [ttlvHeaderSize]byte
	if _, err := io.ReadFull(client, header[:]); err != nil {
		t.Fatalf("read response header: %v", err)
	}
	length := binary.BigEndian.Uint32(header[4:8])
	body := make([]byte, int(length)+ttlvHeaderSize)
	copy(body, header[:])
	if _, err := io.ReadFull(client, body[ttlvHeaderSize:]); err != nil {
		t.Fatalf("read response body: %v", err)
	}
	response, err := DecodeResponse(body)
	if err != nil {
		t.Fatalf("DecodeResponse: %v", err)
	}
	if err := response.BatchItems[0].Err(); err != nil {
		t.Fatalf("Create over transport failed: %v", err)
	}
	_ = client.Close()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop after the client closed | 客户端关闭后 Serve 未停止")
	}
}
