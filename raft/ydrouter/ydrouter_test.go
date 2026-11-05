package ydrouter

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shibingli/ydx/raft"
	"github.com/shibingli/ydx/router"
)

// TestMountDeliversMessage verifies the YD router route end to end. | TestMountDeliversMessage
// 端到端验证 YD 路由。
func TestMountDeliversMessage(t *testing.T) {
	receiver, err := raft.NewHTTPTransport(raft.HTTPTransportOptions{ID: 2, Path: "/raft/message"})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	sender, err := raft.NewHTTPTransport(raft.HTTPTransportOptions{ID: 1, Path: "/raft/message"})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	in := make(chan raft.Message, 1)
	if err := receiver.Start(func(m raft.Message) { in <- m }); err != nil {
		t.Fatal(err)
	}
	if err := sender.Start(func(raft.Message) {}); err != nil {
		t.Fatal(err)
	}
	r := router.New()
	if err := Mount(r, "/raft/message", receiver); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(r)
	defer server.Close()
	sender.UpdatePeer(2, server.URL)
	if err := sender.Send(context.Background(), []raft.Message{{
		Type: raft.MsgHeartbeat, From: 1, To: 2, Term: 7, Commit: 3,
	}}); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-in:
		if m.From != 1 || m.To != 2 || m.Term != 7 {
			t.Fatalf("message = %+v", m)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("message not delivered through YD router")
	}
}

// TestMountRejectsNil checks argument validation. | TestMountRejectsNil 检查参数校验。
func TestMountRejectsNil(t *testing.T) {
	if err := Mount(nil, "/x", nil); err == nil {
		t.Fatal("expected an error")
	}
	if err := Mount(router.New(), "", nil); err == nil {
		t.Fatal("expected an error")
	}
}
