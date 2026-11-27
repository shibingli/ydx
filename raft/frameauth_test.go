package raft

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestFrameAuthRoundTrip checks the optional freshness fields survive encode and
// decode and remain covered by HMAC. | TestFrameAuthRoundTrip 检查可选新鲜度字段
// 的编解码往返，并保持 HMAC 覆盖。
func TestFrameAuthRoundTrip(t *testing.T) {
	secret := []byte("0123456789abcdef")
	msgs := []Message{{Type: MsgHeartbeat, From: 1, To: 2, Term: 3}}
	auth := &frameAuth{timestamp: time.Now().UnixNano(), counter: 7}
	frame, err := encodeHTTPFrameInto(nil, msgs, auth)
	if err != nil {
		t.Fatal(err)
	}
	if frame[5]&flagFrameAuth == 0 {
		t.Fatal("auth flag missing")
	}
	got, gotAuth, err := decodeHTTPFrameAuth(frame)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].From != 1 || gotAuth == nil ||
		gotAuth.timestamp != auth.timestamp || gotAuth.counter != auth.counter {
		t.Fatalf("messages=%+v auth=%+v", got, gotAuth)
	}
	signed, err := encodeStreamFrame(msgs, secret, 1<<20, auth)
	if err != nil {
		t.Fatal(err)
	}
	if _, signedAuth, err := decodeStreamFrame(signed, secret, 1<<20); err != nil ||
		signedAuth == nil || signedAuth.counter != auth.counter {
		t.Fatalf("signed frame auth=%+v err=%v", signedAuth, err)
	}
	tampered := append([]byte(nil), signed...)
	tampered[len(tampered)-1] ^= 0xff
	if _, _, err := decodeStreamFrame(tampered, secret, 1<<20); err == nil {
		t.Fatal("tampered auth frame accepted")
	}
	plain, err := encodeHTTPFrame(msgs)
	if err != nil {
		t.Fatal(err)
	}
	if _, gotAuth, err := decodeHTTPFrameAuth(plain); err != nil || gotAuth != nil {
		t.Fatalf("plain auth=%+v err=%v", gotAuth, err)
	}
}

// TestReplayGuard checks freshness, ordering and replay rejection. |
// TestReplayGuard 检查新鲜度、顺序与重放拒绝。
func TestReplayGuard(t *testing.T) {
	now := time.Unix(1000, 0)
	g := newReplayGuard(time.Minute)
	g.now = func() time.Time { return now }
	fresh := func(counter uint64) *frameAuth {
		return &frameAuth{timestamp: now.UnixNano(), counter: counter}
	}
	if !g.accept(1, fresh(1)) {
		t.Fatal("first frame rejected")
	}
	if g.accept(1, fresh(1)) {
		t.Fatal("replayed frame accepted")
	}
	if !g.accept(1, fresh(2)) {
		t.Fatal("newer counter rejected")
	}
	if g.accept(1, &frameAuth{timestamp: now.Add(-2 * time.Minute).UnixNano(), counter: 3}) {
		t.Fatal("stale frame accepted")
	}
	if g.accept(1, &frameAuth{timestamp: now.Add(2 * time.Minute).UnixNano(), counter: 4}) {
		t.Fatal("future frame accepted")
	}
	if g.accept(2, fresh(1)) != true {
		t.Fatal("independent sender rejected")
	}
	if g.accept(1, nil) {
		t.Fatal("missing auth accepted")
	}
}

// TestHTTPFrameAuthReplay verifies the HTTP handler rejects a replayed signed
// frame and accepts the first delivery. | TestHTTPFrameAuthReplay 验证 HTTP 处理器
// 拒绝重放的签名帧并接受首次投递。
func TestHTTPFrameAuthReplay(t *testing.T) {
	secret := []byte("0123456789abcdef")
	tr, err := NewHTTPTransport(HTTPTransportOptions{
		ID: 2, SharedSecret: secret, FrameMaxAge: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	got := make(chan Message, 1)
	if err := tr.Start(func(m Message) { got <- m }); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(tr.Handler())
	defer srv.Close()
	auth := &frameAuth{timestamp: time.Now().UnixNano(), counter: 1000}
	frame, err := encodeHTTPFrameInto(nil, []Message{{Type: MsgHeartbeat, From: 1, To: 2, Term: 3}}, auth)
	if err != nil {
		t.Fatal(err)
	}
	post := func() int {
		req, err := http.NewRequest(http.MethodPost, srv.URL+defaultHTTPPath, bytes.NewReader(frame))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(httpSignatureHead, signFrame(secret, frame))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if code := post(); code != http.StatusNoContent {
		t.Fatalf("first status = %d", code)
	}
	select {
	case <-got:
	case <-time.After(time.Second):
		t.Fatal("first frame not delivered")
	}
	if code := post(); code != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401", code)
	}
}

// TestStreamFrameMaxAge verifies a receiver with freshness enabled rejects a
// sender that does not add auth fields. | TestStreamFrameMaxAge 验证启用新鲜度的
// 接收方拒绝不添加 auth 字段的发送方。
func TestStreamFrameMaxAge(t *testing.T) {
	secret := []byte("0123456789abcdef")
	receiver, err := NewTCPTransport(TCPTransportOptions{
		ListenAddr: "127.0.0.1:0", SharedSecret: secret, FrameMaxAge: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	plain, err := NewTCPTransport(TCPTransportOptions{
		ListenAddr: "127.0.0.1:0", SharedSecret: secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	in := make(chan Message, 1)
	if err := receiver.Start(func(m Message) { in <- m }); err != nil {
		t.Fatal(err)
	}
	if err := plain.Start(func(Message) {}); err != nil {
		t.Fatal(err)
	}
	plain.UpdatePeer(2, receiver.Addr())
	if err := plain.Send(context.Background(), []Message{{Type: MsgHeartbeat, From: 1, To: 2, Term: 3}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-in:
		t.Fatal("unauthenticated frame accepted")
	case <-time.After(300 * time.Millisecond):
	}
	secure, err := NewTCPTransport(TCPTransportOptions{
		ListenAddr: "127.0.0.1:0", SharedSecret: secret, FrameMaxAge: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer secure.Close()
	if err := secure.Start(func(Message) {}); err != nil {
		t.Fatal(err)
	}
	secure.UpdatePeer(2, receiver.Addr())
	if err := secure.Send(context.Background(), []Message{{Type: MsgHeartbeat, From: 3, To: 2, Term: 4}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-in:
	case <-time.After(3 * time.Second):
		t.Fatal("authenticated frame not delivered")
	}
}
