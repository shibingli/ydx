package rdma

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

// TestGIDAPIPAIsLinkLocal verifies IPv4-mapped 169.254/16 addresses are not
// preferred over routable GIDs. | TestGIDAPIPAIsLinkLocal 验证 IPv4 映射的
// 169.254/16 地址不会被优先于可路由 GID。
func TestGIDAPIPAIsLinkLocal(t *testing.T) {
	gid, err := ParseGID(3, "::ffff:169.254.10.20")
	if err != nil {
		t.Fatal(err)
	}
	if !gid.IsLinkLocal() {
		t.Fatal("APIPA GID not classified as link-local")
	}
	if _, ok := gid.IPv4(); ok {
		t.Fatal("APIPA GID reported as a routable IPv4 address")
	}
	good, err := ParseGID(4, "::ffff:192.168.8.2")
	if err != nil {
		t.Fatal(err)
	}
	if good.IsLinkLocal() {
		t.Fatal("routable IPv4 GID classified as link-local")
	}
}

// TestConfigRejectsLargeGIDIndex verifies the AH uint8 index limit. |
// TestConfigRejectsLargeGIDIndex 验证 AH 的 uint8 索引上限。
func TestConfigRejectsLargeGIDIndex(t *testing.T) {
	cfg := DefaultConfig()
	cfg.GIDIndex = 256
	if err := cfg.normalize(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("normalize = %v, want ErrInvalidConfig", err)
	}
}

// TestPoolMaxSlots verifies a huge-page rounded arena does not expose more
// slots than requested. | TestPoolMaxSlots 验证大页取整后的内存区不会暴露超过
// 请求数量的槽位。
func TestPoolMaxSlots(t *testing.T) {
	pool, err := newPoolMax(newTestMR(4096), 256, 64, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if got := pool.Slots(); got != 8 {
		t.Fatalf("slots = %d, want 8", got)
	}
}

// TestAccessString verifies permission letters are distinct. | TestAccessString
// 验证权限字母互不混淆。
func TestAccessString(t *testing.T) {
	if got := (AccessLocalWrite | AccessRemoteWrite | AccessRemoteRead | AccessRemoteAtomic).String(); got != "LWRA" {
		t.Fatalf("Access.String = %q, want LWRA", got)
	}
}

// TestExchangeQPInfoValidation rejects impossible peer parameters. |
// TestExchangeQPInfoValidation 拒绝不可能的远端参数。
func TestExchangeQPInfoValidation(t *testing.T) {
	cases := []qpInfo{
		func() qpInfo { i := testQPInfo(t); i.Slots = 0; return i }(),
		func() qpInfo { i := testQPInfo(t); i.SlotSize = 0; return i }(),
		func() qpInfo { i := testQPInfo(t); i.MTU = 1500; return i }(),
		func() qpInfo { i := testQPInfo(t); i.PSN = 0x1000000; return i }(),
	}
	for _, remote := range cases {
		client, server := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			var buf bytes.Buffer
			if err := writeQPInfo(&buf, remote); err == nil {
				_, _ = server.Write(buf.Bytes())
			}
			_ = server.Close()
		}()
		_, err := exchangeQPInfo(client, testQPInfo(t), time.Second)
		_ = client.Close()
		<-done
		if !errors.Is(err, ErrHandshake) {
			t.Fatalf("exchange %+v = %v, want ErrHandshake", remote, err)
		}
	}
}
