package kmip

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// startTestServer starts server on an ephemeral loopback listener. | startTestServer 在回环临时端口上启动服务器。
func startTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	server := newTestServer(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.ServeListener(listener)
	}()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not stop | 服务器未停止")
		}
	})
	return server, listener.Addr().String()
}

// dialTestClient dials a plaintext test client. | dialTestClient 拨号明文测试客户端。
func dialTestClient(t *testing.T, address string) *Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := DialContext(ctx, ClientConfig{Address: address, AllowPlaintext: true})
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// TestClientLifecycle runs the full create/get/activate/destroy lifecycle over TCP. |
// TestClientLifecycle 通过 TCP 执行完整的创建/获取/激活/销毁生命周期。
func TestClientLifecycle(t *testing.T) {
	_, address := startTestServer(t)
	client := dialTestClient(t, address)
	ctx := context.Background()

	created, err := client.Create(ctx, CreateRequest{
		ObjectType:        ObjectTypeSymmetricKey,
		TemplateAttribute: symmetricTemplate(),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.UniqueIdentifier == "" {
		t.Fatal("Create returned no identifier | Create 未返回标识符")
	}
	got, err := client.Get(ctx, GetRequest{UniqueIdentifier: created.UniqueIdentifier})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ObjectType != ObjectTypeSymmetricKey {
		t.Errorf("Get object type = %v, want symmetric key | 对象类型错误", got.ObjectType)
	}
	got.Object.Zeroize()
	activated, err := client.Activate(ctx, ActivateRequest{UniqueIdentifier: created.UniqueIdentifier})
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if activated.UniqueIdentifier != created.UniqueIdentifier {
		t.Errorf("Activate identifier = %q, want %q | 激活标识符不一致", activated.UniqueIdentifier, created.UniqueIdentifier)
	}
	destroyed, err := client.Destroy(ctx, DestroyRequest{UniqueIdentifier: created.UniqueIdentifier})
	if err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if destroyed.UniqueIdentifier != created.UniqueIdentifier {
		t.Errorf("Destroy identifier = %q, want %q | 销毁标识符不一致", destroyed.UniqueIdentifier, created.UniqueIdentifier)
	}
	// KMIP permits servers to retain a destroyed tombstone or to remove the object. This server keeps
	// the tombstone and reports an illegal operation; a removing store reports Item Not Found. |
	// KMIP 允许服务器保留销毁墓碑或直接删除对象。本服务器保留墓碑并报告非法操作；删除型存储报告对象不存在。
	if _, err := client.Get(ctx, GetRequest{UniqueIdentifier: created.UniqueIdentifier}); !errors.Is(err, ErrIllegalOperation) && !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("Get after Destroy = %v, want ErrIllegalOperation or ErrItemNotFound | 销毁后 Get 应返回非法操作或对象不存在", err)
	}
}

// TestClientRejectsPlaintextByDefault requires TLS unless AllowPlaintext is set. |
// TestClientRejectsPlaintextByDefault 要求 TLS，除非显式设置 AllowPlaintext。
func TestClientRejectsPlaintextByDefault(t *testing.T) {
	_, err := DialContext(context.Background(), ClientConfig{Address: "127.0.0.1:1"})
	if !errors.Is(err, ErrTLSRequired) {
		t.Fatalf("DialContext error = %v, want ErrTLSRequired | 应返回 ErrTLSRequired", err)
	}
}

// TestClientClosed reports ErrClosed after Close. | TestClientClosed 在 Close 之后返回 ErrClosed。
func TestClientClosed(t *testing.T) {
	_, address := startTestServer(t)
	client := dialTestClient(t, address)
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	_, err := client.Query(context.Background(), QueryRequest{})
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("Query after Close = %v, want ErrClosed | 关闭后 Query 应返回 ErrClosed", err)
	}
}

// TestClientResponseLimit reports ErrResponseTooLarge for a tiny configured limit. |
// TestClientResponseLimit 在配置的响应上限过小时返回 ErrResponseTooLarge。
func TestClientResponseLimit(t *testing.T) {
	_, address := startTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := DialContext(ctx, ClientConfig{
		Address:         address,
		AllowPlaintext:  true,
		MaxResponseSize: ttlvHeaderSize + 16,
	})
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer func() { _ = client.Close() }()
	if _, err := client.Create(ctx, CreateRequest{ObjectType: ObjectTypeSymmetricKey, TemplateAttribute: symmetricTemplate()}); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("Create with small response limit = %v, want ErrResponseTooLarge | 小响应上限应返回 ErrResponseTooLarge", err)
	}
}

// TestClientCloseInterruptsBlockedRequest covers Close while a request waits for an unresponsive
// server. | TestClientCloseInterruptsBlockedRequest 覆盖请求等待无响应服务器时的 Close。
func TestClientCloseInterruptsBlockedRequest(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	received := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		buffer := make([]byte, 4096)
		if _, readErr := conn.Read(buffer); readErr != nil {
			return
		}
		close(received)
		<-release
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := DialContext(ctx, ClientConfig{Address: listener.Addr().String(), AllowPlaintext: true})
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	payload := mustItem(t, GetRequest{UniqueIdentifier: "blocked"})
	doErr := make(chan error, 1)
	go func() {
		_, err := client.Do(context.Background(), RequestBatchItem{Operation: OpGet, Payload: payload})
		doErr <- err
	}()
	select {
	case <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not receive the request | 服务器未收到请求")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- client.Close() }()
	select {
	case closeErr := <-closeDone:
		if closeErr != nil {
			t.Fatalf("Close: %v", closeErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked behind an in-flight request | Close 被进行中的请求阻塞")
	}
	select {
	case err := <-doErr:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("Do err = %v, want ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Do did not return after Close | Close 后 Do 未返回")
	}
}
