//go:build linux && rdma && (amd64 || arm64)

package rdma

import (
	"bytes"
	"testing"
	"time"
)

// testConnConfig returns a small loopback connection configuration. |
// testConnConfig 返回小型环回连接配置。
func testConnConfig(t *testing.T) ConnConfig {
	t.Helper()
	cfg := DefaultConnConfig()
	cfg.Config = testConfig(t)
	cfg.Slots = 64
	cfg.SlotSize = 4096
	cfg.SendTimeout = 3 * time.Second
	cfg.RecvTimeout = 3 * time.Second
	return cfg
}

// dialPair creates a listener and a dialed connection in one process. |
// dialPair 在同一进程内创建监听与拨号连接。
func dialPair(t *testing.T, cfg ConnConfig) (client, server *Conn) {
	t.Helper()
	ln, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen = %v | 监听失败", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	type accepted struct {
		c   *Conn
		err error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		ch <- accepted{c, err}
	}()
	client, err = Dial(ln.Addr().String(), cfg)
	if err != nil {
		t.Fatalf("Dial = %v | 拨号失败", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	res := <-ch
	if res.err != nil {
		t.Fatalf("Accept = %v | 接受连接失败", res.err)
	}
	server = res.c
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}

// TestConnLoopback proves a message round trip over the zero-copy connection.
// | TestConnLoopback 证明零拷贝连接上的消息往返。
func TestConnLoopback(t *testing.T) {
	client, server := dialPair(t, testConnConfig(t))
	msg := []byte("hello rdma conn")
	if err := client.Send(msg); err != nil {
		t.Fatalf("Send = %v | 发送失败", err)
	}
	got, err := server.Recv()
	if err != nil {
		t.Fatalf("Recv = %v | 接收失败", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("payload = %q, want %q | 负载不符", got, msg)
	}
	reply := []byte("reply")
	if err := server.Send(reply); err != nil {
		t.Fatalf("Send reply = %v | 回复失败", err)
	}
	got, err = client.Recv()
	if err != nil {
		t.Fatalf("Recv reply = %v | 接收回复失败", err)
	}
	if !bytes.Equal(got, reply) {
		t.Fatalf("reply = %q | 回复不符", got)
	}
}

// TestConnZeroCopy proves Alloc/SendBuffer and RecvBuffer/Release avoid the
// copying convenience path. | TestConnZeroCopy 证明 Alloc/SendBuffer 与
// RecvBuffer/Release 走零拷贝路径。
func TestConnZeroCopy(t *testing.T) {
	client, server := dialPair(t, testConnConfig(t))
	msg := []byte("zero copy payload")
	b, err := client.Alloc(len(msg))
	if err != nil {
		t.Fatalf("Alloc = %v | 获取发送槽位失败", err)
	}
	copy(b.Bytes(), msg)
	if err := client.SendBuffer(b, len(msg)); err != nil {
		t.Fatalf("SendBuffer = %v | 零拷贝发送失败", err)
	}
	rb, n, err := server.RecvBuffer()
	if err != nil {
		t.Fatalf("RecvBuffer = %v | 零拷贝接收失败", err)
	}
	if !bytes.Equal(rb.Bytes()[:n], msg) {
		t.Fatalf("payload = %q | 负载不符", rb.Bytes()[:n])
	}
	if err := server.Release(rb); err != nil {
		t.Fatalf("Release = %v | 释放失败", err)
	}
}

// TestConnBatch proves a batched send is delivered in order. | TestConnBatch
// 证明批量发送按序送达。
func TestConnBatch(t *testing.T) {
	client, server := dialPair(t, testConnConfig(t))
	msgs := make([][]byte, 8)
	for i := range msgs {
		msgs[i] = []byte{byte(i), byte(i + 1), byte(i + 2)}
	}
	posted, err := client.SendBatch(msgs)
	if err != nil || posted != len(msgs) {
		t.Fatalf("SendBatch = %d/%v | 批量发送失败", posted, err)
	}
	for i := range msgs {
		got, err := server.Recv()
		if err != nil {
			t.Fatalf("Recv #%d = %v | 接收失败", i, err)
		}
		if !bytes.Equal(got, msgs[i]) {
			t.Fatalf("message %d = %v, want %v | 消息不符", i, got, msgs[i])
		}
	}
}

// TestConnInlineReuse stresses the inline send path: the transmit buffer is
// recycled by SendBuffer as soon as ibv_post_send returns. | TestConnInlineReuse
// 压测内联发送路径：SendBuffer 在 ibv_post_send 返回后立即回收发送缓冲区。
func TestConnInlineReuse(t *testing.T) {
	client, server := dialPair(t, testConnConfig(t))
	const messages = 2000
	errCh := make(chan error, 1)
	go func() {
		for i := 0; i < messages; i++ {
			b, n, err := server.RecvBuffer()
			if err != nil {
				errCh <- err
				return
			}
			tb, err := server.Alloc(n)
			if err != nil {
				errCh <- err
				return
			}
			copy(tb.Bytes(), b.Bytes()[:n])
			if err := server.SendBuffer(tb, n); err != nil {
				errCh <- err
				return
			}
			if err := server.Release(b); err != nil {
				errCh <- err
				return
			}
		}
		errCh <- nil
	}()
	for i := 0; i < messages; i++ {
		msg := []byte{byte(i), byte(i >> 8), 0xaa, 0x55}
		if err := client.Send(msg); err != nil {
			t.Fatalf("Send #%d = %v | 发送失败", i, err)
		}
		got, err := client.Recv()
		if err != nil {
			t.Fatalf("Recv #%d = %v | 接收失败", i, err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("message #%d = %v, want %v | 消息不符", i, got, msg)
		}
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server echo = %v | 服务端回显失败", err)
	}
}

// TestConnLargeMessage proves non-inline sends are signaled and their buffers
// are recycled by completions. | TestConnLargeMessage 证明非内联发送会请求
// 完成事件，并由完成事件回收缓冲区。
func TestConnLargeMessage(t *testing.T) {
	client, server := dialPair(t, testConnConfig(t))
	msg := bytes.Repeat([]byte("payload-"), 256)
	if len(msg) <= client.QP().MaxInline() {
		t.Fatalf("message %d is inline, want non-inline | 消息应走非内联路径", len(msg))
	}
	if err := client.Send(msg); err != nil {
		t.Fatalf("Send = %v | 发送失败", err)
	}
	got, err := server.Recv()
	if err != nil {
		t.Fatalf("Recv = %v | 接收失败", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("payload length = %d, want %d | 负载不符", len(got), len(msg))
	}
	if err := server.Send(msg); err != nil {
		t.Fatalf("echo = %v | 回显失败", err)
	}
	got, err = client.Recv()
	if err != nil {
		t.Fatalf("Recv echo = %v | 接收回显失败", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo length = %d, want %d | 回显不符", len(got), len(msg))
	}
}
