package kmip

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// testTCPProxy forwards TCP connections to target and can drop the live connections while keeping
// the listener open. | testTCPProxy 把 TCP 连接转发到 target，并能在保持监听器打开的同时断开活动连接。
type testTCPProxy struct {
	listener net.Listener
	target   string
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
}

// startTestProxy starts a proxy in front of target. | startTestProxy 在 target 前启动代理。
func startTestProxy(t *testing.T, target string) (*testTCPProxy, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	proxy := &testTCPProxy{listener: listener, target: target, conns: make(map[net.Conn]struct{})}
	go proxy.acceptLoop()
	t.Cleanup(proxy.close)
	return proxy, listener.Addr().String()
}

// acceptLoop accepts client connections and pairs each with a fresh upstream connection. |
// acceptLoop 接受客户端连接，并为每个连接建立新的上游连接。
func (p *testTCPProxy) acceptLoop() {
	for {
		client, err := p.listener.Accept()
		if err != nil {
			return
		}
		upstream, err := net.Dial("tcp", p.target)
		if err != nil {
			_ = client.Close()
			continue
		}
		p.track(client)
		p.track(upstream)
		go p.relay(client, upstream)
	}
}

// relay copies bytes in both directions until either side closes. | relay 双向复制字节直到任一侧关闭。
func (p *testTCPProxy) relay(client, upstream net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, client)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		done <- struct{}{}
	}()
	<-done
	_ = client.Close()
	_ = upstream.Close()
	<-done
	p.untrack(client)
	p.untrack(upstream)
}

// track records a live connection. | track 记录活动连接。
func (p *testTCPProxy) track(conn net.Conn) {
	p.mu.Lock()
	p.conns[conn] = struct{}{}
	p.mu.Unlock()
}

// untrack forgets a closed connection. | untrack 遗忘已关闭的连接。
func (p *testTCPProxy) untrack(conn net.Conn) {
	p.mu.Lock()
	delete(p.conns, conn)
	p.mu.Unlock()
}

// drop closes every live connection but keeps accepting new ones. | drop 关闭所有活动连接，但继续接受新连接。
func (p *testTCPProxy) drop() {
	p.mu.Lock()
	conns := make([]net.Conn, 0, len(p.conns))
	for conn := range p.conns {
		conns = append(conns, conn)
	}
	p.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

// close stops the proxy and closes its connections. | close 停止代理并关闭其连接。
func (p *testTCPProxy) close() {
	_ = p.listener.Close()
	p.drop()
}

// TestClientReconnectsAfterTransportFailure verifies lazy reconnect and that the failed request is
// returned to the caller. | TestClientReconnectsAfterTransportFailure 校验惰性重连，且失败请求返回给调用方。
func TestClientReconnectsAfterTransportFailure(t *testing.T) {
	_, address := startTestServer(t)
	proxy, proxyAddress := startTestProxy(t, address)
	client := dialTestClient(t, proxyAddress)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	query := QueryRequest{QueryFunctions: []QueryFunction{QueryFunctionOperations}}
	if _, err := client.Query(ctx, query); err != nil {
		t.Fatalf("initial Query: %v | 初始 Query：%v", err, err)
	}
	proxy.drop()
	if _, err := client.Query(ctx, query); err == nil {
		t.Fatal("Query after proxy drop succeeded; a failed request must not be replayed | 代理断开后 Query 成功；失败请求不得重放")
	}
	if _, err := client.Query(ctx, query); err != nil {
		t.Fatalf("Query after reconnect: %v | 重连后 Query：%v", err, err)
	}
	if _, err := client.Query(ctx, query); err != nil {
		t.Fatalf("Query on reconnected connection: %v | 重连连接上的 Query：%v", err, err)
	}
}

// TestClientDoesNotReplayFailedRequest verifies that a request already written is never retried on a
// new connection. | TestClientDoesNotReplayFailedRequest 校验已写入的请求绝不会在新连接上重试。
func TestClientDoesNotReplayFailedRequest(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var mu sync.Mutex
	accepts := 0
	requests := 0
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			accepts++
			mu.Unlock()
			go func() {
				defer conn.Close()
				var header [8]byte
				if _, err := io.ReadFull(conn, header[:]); err != nil {
					return
				}
				body := make([]byte, binary.BigEndian.Uint32(header[4:]))
				if _, err := io.ReadFull(conn, body); err != nil {
					return
				}
				mu.Lock()
				requests++
				mu.Unlock()
			}()
		}
	}()
	client := dialTestClient(t, listener.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.Query(ctx, QueryRequest{QueryFunctions: []QueryFunction{QueryFunctionOperations}}); !errors.Is(err, ErrTransport) {
		t.Fatalf("Query err = %v, want ErrTransport | Query 错误 = %v，期望 ErrTransport", err, err)
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	gotAccepts, gotRequests := accepts, requests
	mu.Unlock()
	if gotAccepts != 1 || gotRequests != 1 {
		t.Fatalf("accepts = %d, requests = %d, want 1 and 1; the failed request was replayed | accepts = %d，requests = %d，期望 1 与 1；失败请求被重放",
			gotAccepts, gotRequests, gotAccepts, gotRequests)
	}
}

// TestClientConcurrentReconnect verifies that concurrent callers share one lazy reconnect safely. |
// TestClientConcurrentReconnect 校验并发调用方安全共享一次惰性重连。
func TestClientConcurrentReconnect(t *testing.T) {
	_, address := startTestServer(t)
	proxy, proxyAddress := startTestProxy(t, address)
	client := dialTestClient(t, proxyAddress)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	query := QueryRequest{QueryFunctions: []QueryFunction{QueryFunctionOperations}}
	if _, err := client.Query(ctx, query); err != nil {
		t.Fatalf("initial Query: %v | 初始 Query：%v", err, err)
	}
	proxy.drop()

	const workers = 8
	const attempts = 10
	results := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range attempts {
				if _, err := client.Query(ctx, query); err == nil {
					results <- nil
					return
				} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					results <- err
					return
				}
			}
			results <- ErrTransport
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent Query did not recover: %v | 并发 Query 未恢复：%v", err, err)
		}
	}
}

// TestClientCloseDoesNotReconnect verifies that Close permanently disables dialing. |
// TestClientCloseDoesNotReconnect 校验 Close 永久禁用拨号。
func TestClientCloseDoesNotReconnect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	accepts := 0
	accepted := make(chan struct{}, 4)
	var conns []net.Conn
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			accepts++
			conns = append(conns, conn)
			mu.Unlock()
			accepted <- struct{}{}
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		for _, conn := range conns {
			_ = conn.Close()
		}
		mu.Unlock()
	})
	client := dialTestClient(t, listener.Addr().String())
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("client did not connect | 客户端未连接")
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := client.Query(context.Background(), QueryRequest{QueryFunctions: []QueryFunction{QueryFunctionOperations}}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Query after Close err = %v, want ErrClosed | Close 后 Query 错误 = %v，期望 ErrClosed", err, err)
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	got := accepts
	mu.Unlock()
	if got != 1 {
		t.Fatalf("accepts after Close = %d, want 1; the client reconnected after Close | Close 后 accepts = %d，期望 1；客户端在 Close 后重连",
			got, got)
	}
}
