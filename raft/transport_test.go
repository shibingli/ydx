package raft

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"
)

// TestStreamFrameAuthentication checks framing and HMAC failure. | TestStreamFrameAuthentication
// 检查帧结构与 HMAC 失败。
func TestStreamFrameAuthentication(t *testing.T) {
	secret := []byte("0123456789abcdef")
	msgs := []Message{{Type: MsgHeartbeat, From: 1, To: 2, Term: 4, Commit: 3}}
	frame, err := encodeStreamFrame(msgs, secret, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	got, err := readStreamFrame(bytes.NewReader(frame), secret, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].From != 1 || got[0].To != 2 {
		t.Fatalf("messages = %+v", got)
	}
	if _, err := readStreamFrame(bytes.NewReader(frame), []byte("abcdefghijklmnop"), 1<<20); err == nil {
		t.Fatal("accepted a frame with the wrong secret")
	}
	corrupt := append([]byte(nil), frame...)
	corrupt[len(corrupt)-1] ^= 0xff
	if _, err := readStreamFrame(bytes.NewReader(corrupt), secret, 1<<20); err == nil {
		t.Fatal("accepted a corrupt frame")
	}
}

// TestTCPTransportDelivery sends a message between two TCP transports. | TestTCPTransportDelivery
// 在两个 TCP 传输之间发送消息。
func TestTCPTransportDelivery(t *testing.T) {
	t1, err := NewTCPTransport(TCPTransportOptions{ListenAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	defer t1.Close()
	t2, err := NewTCPTransport(TCPTransportOptions{ListenAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	defer t2.Close()
	in := make(chan Message, 1)
	if err := t2.Start(func(m Message) { in <- m }); err != nil {
		t.Fatal(err)
	}
	if err := t1.Start(func(Message) {}); err != nil {
		t.Fatal(err)
	}
	t1.UpdatePeer(2, t2.Addr())
	if err := t1.Send(context.Background(), []Message{{Type: MsgHeartbeat, From: 1, To: 2, Term: 3, Commit: 2}}); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-in:
		if m.From != 1 || m.To != 2 || m.Term != 3 || m.Commit != 2 {
			t.Fatalf("message = %+v", m)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("message not delivered")
	}
}

// TestHTTPTransportDelivery sends a message through an httptest server. | TestHTTPTransportDelivery
// 通过 httptest 服务器发送消息。
func TestHTTPTransportDelivery(t *testing.T) {
	secret := []byte("0123456789abcdef")
	t1, err := NewHTTPTransport(HTTPTransportOptions{ID: 1, SharedSecret: secret})
	if err != nil {
		t.Fatal(err)
	}
	defer t1.Close()
	t2, err := NewHTTPTransport(HTTPTransportOptions{ID: 2, SharedSecret: secret})
	if err != nil {
		t.Fatal(err)
	}
	defer t2.Close()
	in := make(chan Message, 1)
	if err := t2.Start(func(m Message) { in <- m }); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(t2.Handler())
	defer server.Close()
	if err := t1.Start(func(Message) {}); err != nil {
		t.Fatal(err)
	}
	t1.UpdatePeer(2, server.URL)
	if err := t1.Send(context.Background(), []Message{{Type: MsgApp, From: 1, To: 2, Term: 5,
		Entries: []Entry{{Index: 1, Term: 5, Type: EntryNormal, Data: []byte("x")}}}}); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-in:
		if m.From != 1 || len(m.Entries) != 1 || string(m.Entries[0].Data) != "x" {
			t.Fatalf("message = %+v", m)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("message not delivered")
	}
}

// TestRDMATransportUnsupported checks the default build's explicit failure.
// | TestRDMATransportUnsupported 检查默认构建的显式失败。
func TestRDMATransportUnsupported(t *testing.T) {
	if RDMAAvailable() {
		t.Skip("RDMA is available in this build")
	}
	_, err := NewRDMATransport(RDMATransportOptions{ListenAddr: "127.0.0.1:1"})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("error = %v, want ErrUnsupported", err)
	}
}

// TestClusterOverTCP runs consensus over real loopback TCP sockets. | TestClusterOverTCP
// 在真实回环 TCP 套接字上运行共识。
func TestClusterOverTCP(t *testing.T) {
	const size = 3
	transports := make([]*TCPTransport, size)
	peers := make([]Peer, size)
	for i := 0; i < size; i++ {
		tr, err := NewTCPTransport(TCPTransportOptions{ListenAddr: "127.0.0.1:0", Queue: 256})
		if err != nil {
			t.Fatal(err)
		}
		transports[i] = tr
		peers[i] = Peer{ID: NodeID(i + 1), Addr: tr.Addr()}
	}
	nodes := make([]*Node, size)
	fsms := make([]*kvFSM, size)
	for i := 0; i < size; i++ {
		fsm := newKVFSM()
		node, err := New(Config{
			ID: NodeID(i + 1), Peers: peers, Storage: NewMemStorage(), FSM: fsm,
			Transport: transports[i], TickInterval: 5 * time.Millisecond,
			HeartbeatTicks: 1, ElectionTicks: 8, MaxBatchEntries: 64,
		})
		if err != nil {
			t.Fatalf("node %d: %v", i+1, err)
		}
		nodes[i] = node
		fsms[i] = fsm
	}
	defer func() {
		for _, node := range nodes {
			_ = node.Close()
		}
	}()
	var leader *Node
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		leaders := 0
		for _, node := range nodes {
			if node.State() == StateLeader {
				leader = node
				leaders++
			}
		}
		if leaders == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if leader == nil {
		t.Fatal("no leader over TCP")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	res, err := leader.Propose(ctx, []byte("tcp=ok"))
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	for i, node := range nodes {
		if err := node.WaitApplied(ctx, res.Index); err != nil {
			t.Fatalf("node %d applied: %v", i+1, err)
		}
		if got := fsms[i].value("tcp"); got != "ok" {
			t.Fatalf("node %d value = %q", i+1, got)
		}
	}
}
