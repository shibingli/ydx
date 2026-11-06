//go:build linux && rdma && (amd64 || arm64)

package rdma

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// TestDeviceCloseBusy verifies a device refuses to close while children exist.
// | TestDeviceCloseBusy 验证设备在仍有子资源时拒绝关闭。
func TestDeviceCloseBusy(t *testing.T) {
	d := openTestDevice(t)
	cq, err := d.NewCQ(32)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); !errors.Is(err, ErrBusy) {
		t.Fatalf("Close with live CQ = %v, want ErrBusy", err)
	}
	if err := cq.Close(); err != nil {
		t.Fatalf("CQ.Close = %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close after children = %v", err)
	}
}

// TestConnBatchExceedsPool verifies SendBatch posts every message even when the
// batch exceeds the send pool depth. | TestConnBatchExceedsPool 验证批次超过发送池
// 深度时 SendBatch 仍提交全部消息。
func TestConnBatchExceedsPool(t *testing.T) {
	cfg := testConnConfig(t)
	cfg.Slots = 8
	cfg.MaxBatch = 64
	client, server := dialPair(t, cfg)
	const count = 40
	msgs := make([][]byte, count)
	for i := range msgs {
		msgs[i] = bytes.Repeat([]byte{byte(i)}, 32)
	}
	type result struct {
		err error
	}
	recvDone := make(chan result, 1)
	go func() {
		for i := 0; i < count; i++ {
			b, n, err := server.RecvBuffer()
			if err != nil {
				recvDone <- result{err}
				return
			}
			if !bytes.Equal(b.Bytes()[:n], msgs[i]) {
				_ = server.Release(b)
				recvDone <- result{errors.New("payload mismatch")}
				return
			}
			if err := server.Release(b); err != nil {
				recvDone <- result{err}
				return
			}
		}
		recvDone <- result{}
	}()
	posted, err := client.SendBatch(msgs)
	if err != nil || posted != count {
		t.Fatalf("SendBatch = %d/%v, want %d", posted, err, count)
	}
	select {
	case res := <-recvDone:
		if res.err != nil {
			t.Fatalf("receive: %v", res.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("receiver did not complete")
	}
}

// TestConnRejectsDuplicateSend verifies the same send buffer cannot be posted
// twice before completion. | TestConnRejectsDuplicateSend 验证完成前不能重复提交
// 同一发送缓冲区。
func TestConnRejectsDuplicateSend(t *testing.T) {
	cfg := testConnConfig(t)
	client, _ := dialPair(t, cfg)
	b, err := client.Alloc(cfg.SlotSize)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SendBuffer(b, cfg.SlotSize); err != nil {
		t.Fatal(err)
	}
	if err := client.SendBuffer(b, cfg.SlotSize); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("duplicate SendBuffer = %v, want ErrInvalidConfig", err)
	}
}

// TestConnRejectsDuplicateRelease verifies a received buffer cannot be
// reposted twice. | TestConnRejectsDuplicateRelease 验证接收缓冲区不能重复重新提交。
func TestConnRejectsDuplicateRelease(t *testing.T) {
	client, server := dialPair(t, testConnConfig(t))
	if err := client.Send([]byte("x")); err != nil {
		t.Fatal(err)
	}
	b, _, err := server.RecvBuffer()
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Release(b); err != nil {
		t.Fatal(err)
	}
	if err := server.Release(b); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("duplicate Release = %v, want ErrInvalidConfig", err)
	}
}

// TestConnCloseWhileRecv verifies Close unblocks a receive operation without a
// use-after-free. | TestConnCloseWhileRecv 验证 Close 能唤醒接收操作且不会造成
// 释放后使用。
func TestConnCloseWhileRecv(t *testing.T) {
	cfg := testConnConfig(t)
	cfg.RecvTimeout = -1
	_, server := dialPair(t, cfg)
	done := make(chan error, 1)
	go func() {
		_, _, err := server.RecvBuffer()
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	if err := server.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("RecvBuffer after Close = %v, want ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RecvBuffer did not unblock on Close")
	}
}

// TestListenerCloseWhileAccept verifies Close unblocks Accept. |
// TestListenerCloseWhileAccept 验证 Close 能唤醒 Accept。
func TestListenerCloseWhileAccept(t *testing.T) {
	cfg := testConnConfig(t)
	ln, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := ln.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("Accept after Close = %v, want ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Accept did not unblock on Close")
	}
}

// TestConnRejectsSlotMismatch verifies asymmetric slot geometry fails in the
// handshake instead of on the first large message. | TestConnRejectsSlotMismatch
// 验证不对称槽位参数在握手时失败，而不是在第一条大消息时失败。
func TestConnRejectsSlotMismatch(t *testing.T) {
	serverCfg := testConnConfig(t)
	serverCfg.SlotSize = 4096
	ln, err := Listen("127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	acceptCh := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		acceptCh <- err
	}()
	clientCfg := testConnConfig(t)
	clientCfg.SlotSize = 8192
	if _, err := Dial(ln.Addr().String(), clientCfg); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Dial with mismatched slots = %v, want ErrInvalidConfig", err)
	}
	select {
	case <-acceptCh:
	case <-time.After(5 * time.Second):
		t.Fatal("Accept did not finish")
	}
}
