package raft

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

// TestTransportRemovePeer drops a peer and allows a later re-add. |
// TestTransportRemovePeer 移除对端并允许之后重新加入。
func TestTransportRemovePeer(t *testing.T) {
	t1, err := NewTCPTransport(TCPTransportOptions{ListenAddr: "127.0.0.1:0", AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	defer t1.Close()
	t2, err := NewTCPTransport(TCPTransportOptions{ListenAddr: "127.0.0.1:0", AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	defer t2.Close()
	in := make(chan Message, 4)
	if err := t2.Start(func(m Message) { in <- m }); err != nil {
		t.Fatal(err)
	}
	if err := t1.Start(func(Message) {}); err != nil {
		t.Fatal(err)
	}
	if !t1.RequiresPeerAddresses() {
		t.Fatal("TCP transport does not require peer addresses")
	}
	t1.UpdatePeer(2, t2.Addr())
	if got, ok := t1.PeerAddress(2); !ok || got != t2.Addr() {
		t.Fatalf("peer address = %q, %v", got, ok)
	}
	if err := t1.Send(context.Background(), []Message{{Type: MsgHeartbeat, From: 1, To: 2, Term: 3}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-in:
	case <-time.After(3 * time.Second):
		t.Fatal("message not delivered before removal")
	}

	t1.RemovePeer(2)
	if _, ok := t1.PeerAddress(2); ok {
		t.Fatal("peer address survived removal")
	}
	if err := t1.Send(context.Background(), []Message{{Type: MsgHeartbeat, From: 1, To: 2, Term: 4}}); !errors.Is(err, ErrUnknownNode) {
		t.Fatalf("send after removal error = %v, want ErrUnknownNode", err)
	}
	// A later UpdatePeer recreates the peer and its goroutine. | 之后的 UpdatePeer
	// 会重建对端及其协程。
	t1.UpdatePeer(2, t2.Addr())
	if err := t1.Send(context.Background(), []Message{{Type: MsgHeartbeat, From: 1, To: 2, Term: 5}}); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-in:
		if m.Term != 5 {
			t.Fatalf("term = %d, want 5", m.Term)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("message not delivered after re-add")
	}
}

// TestTransportAddressChangeReconnects verifies an address update reconnects
// before the next write instead of waiting for the old connection to fail. |
// TestTransportAddressChangeReconnects 验证地址更新在下一次写入前重连，而不是等待
// 旧连接失败。
func TestTransportAddressChangeReconnects(t *testing.T) {
	sender, err := NewTCPTransport(TCPTransportOptions{ListenAddr: "127.0.0.1:0", AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	oldPeer, err := NewTCPTransport(TCPTransportOptions{ListenAddr: "127.0.0.1:0", AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	defer oldPeer.Close()
	newPeer, err := NewTCPTransport(TCPTransportOptions{ListenAddr: "127.0.0.1:0", AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	defer newPeer.Close()
	oldIn := make(chan Message, 4)
	newIn := make(chan Message, 4)
	if err := oldPeer.Start(func(m Message) { oldIn <- m }); err != nil {
		t.Fatal(err)
	}
	if err := newPeer.Start(func(m Message) { newIn <- m }); err != nil {
		t.Fatal(err)
	}
	if err := sender.Start(func(Message) {}); err != nil {
		t.Fatal(err)
	}
	sender.UpdatePeer(2, oldPeer.Addr())
	if err := sender.Send(context.Background(), []Message{{Type: MsgHeartbeat, From: 1, To: 2, Term: 1}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-oldIn:
	case <-time.After(3 * time.Second):
		t.Fatal("first message not delivered to the old address")
	}

	sender.UpdatePeer(2, newPeer.Addr())
	if err := sender.Send(context.Background(), []Message{{Type: MsgHeartbeat, From: 1, To: 2, Term: 2}}); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-newIn:
		if m.Term != 2 {
			t.Fatalf("term = %d, want 2", m.Term)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("address update did not reconnect to the new address")
	}
	select {
	case m := <-oldIn:
		t.Fatalf("old address received a message after the update: %+v", m)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestHTTPTransportRemovePeer verifies the HTTP transport implements the peer
// directory and removal extensions. | TestHTTPTransportRemovePeer 验证 HTTP 传输
// 实现对端目录与移除扩展。
func TestHTTPTransportRemovePeer(t *testing.T) {
	tr, err := NewHTTPTransport(HTTPTransportOptions{ID: 1, AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	if err := tr.Start(func(Message) {}); err != nil {
		t.Fatal(err)
	}
	tr.UpdatePeer(2, "http://127.0.0.1:1")
	if got, ok := tr.PeerAddress(2); !ok || got != "http://127.0.0.1:1" {
		t.Fatalf("peer address = %q, %v", got, ok)
	}
	tr.RemovePeer(2)
	if _, ok := tr.PeerAddress(2); ok {
		t.Fatal("HTTP peer address survived removal")
	}
	if err := tr.Send(context.Background(), []Message{{Type: MsgHeartbeat, From: 1, To: 2}}); !errors.Is(err, ErrUnknownNode) {
		t.Fatalf("send after removal error = %v, want ErrUnknownNode", err)
	}
}

// TestSeedDoesNotOverwriteKnownPeer verifies Config.Peers is a fallback for
// transports that expose a peer directory. | TestSeedDoesNotOverwriteKnownPeer
// 验证 Config.Peers 对暴露对端目录的传输只是回填，不覆盖已有地址。
func TestSeedDoesNotOverwriteKnownPeer(t *testing.T) {
	tr := &directoryRecordingTransport{recordingTransport: recordingTransport{peers: make(map[NodeID]string)}}
	tr.peers[2] = "explicit:2"
	node, err := New(Config{
		ID: 4, Join: true, Storage: NewMemStorage(), FSM: newKVFSM(),
		Transport: tr, TickInterval: 5 * time.Millisecond, HeartbeatTicks: 1, ElectionTicks: 8,
		Peers: []Peer{
			{ID: 2, Addr: "seed:2"},
			{ID: 3, Addr: "seed:3"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	if got := tr.addr(2); got != "explicit:2" {
		t.Fatalf("existing peer 2 overwritten with %q", got)
	}
	if got := tr.addr(3); got != "seed:3" {
		t.Fatalf("missing peer 3 not seeded: %q", got)
	}
}

// directoryRecordingTransport exposes the recorded map as a peer directory. |
// directoryRecordingTransport 把记录表暴露为对端目录。
type directoryRecordingTransport struct {
	recordingTransport
}

// PeerAddress implements PeerDirectory. | PeerAddress 实现 PeerDirectory。
func (t *directoryRecordingTransport) PeerAddress(id NodeID) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	addr, ok := t.peers[id]
	return addr, ok
}

// nopConn is a tracked connection used by the max-conns test. | nopConn 是连接上限
// 测试使用的空连接。
type nopConn struct{ id int }

// Read implements io.Reader. | Read 实现 io.Reader。
func (nopConn) Read([]byte) (int, error) { return 0, io.EOF }

// Write implements io.Writer. | Write 实现 io.Writer。
func (nopConn) Write(p []byte) (int, error) { return len(p), nil }

// Close implements io.Closer. | Close 实现 io.Closer。
func (nopConn) Close() error { return nil }

// TestStreamTransportMaxConns verifies the configurable connection cap. |
// TestStreamTransportMaxConns 验证可配置的连接上限。
func TestStreamTransportMaxConns(t *testing.T) {
	t1 := &streamTransport{maxConns: 2, conns: make(map[io.ReadWriteCloser]struct{})}
	if !t1.track(&nopConn{id: 1}) || !t1.track(&nopConn{id: 2}) {
		t.Fatal("track rejected a connection before the cap")
	}
	if t1.track(&nopConn{id: 3}) {
		t.Fatal("track accepted a connection past the cap")
	}
	unlimited := &streamTransport{maxConns: 0, conns: make(map[io.ReadWriteCloser]struct{})}
	for i := 0; i < 64; i++ {
		if !unlimited.track(&nopConn{id: i}) {
			t.Fatalf("unlimited transport rejected connection %d", i)
		}
	}
}
