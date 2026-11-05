package rdma

import (
	"net"
	"testing"
)

// TestDefaultConfigAutoSelectsGID proves the default configuration leaves the
// GID type and index to automatic selection so RoCE and InfiniBand hardware
// both work. | TestDefaultConfigAutoSelectsGID 证明默认配置把 GID 类型与索引
// 都交给自动选择，从而同时支持 RoCE 与 InfiniBand 硬件。
func TestDefaultConfigAutoSelectsGID(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.GIDType != GIDTypeUnknown {
		t.Fatalf("GIDType = %v, want automatic | GIDType 应为自动", cfg.GIDType)
	}
	if cfg.GIDIndex != AutoGIDIndex {
		t.Fatalf("GIDIndex = %d, want %d | GIDIndex 应为自动", cfg.GIDIndex, AutoGIDIndex)
	}
	if cfg.Port != 1 {
		t.Fatalf("Port = %d, want 1 | Port 应为 1", cfg.Port)
	}
	if cfg.HopLimit != 64 {
		t.Fatalf("HopLimit = %d, want 64 | HopLimit 应为 64", cfg.HopLimit)
	}
	if cfg.RetryCount != 7 || cfg.RNRRetry != 7 {
		t.Fatalf("retries = %d/%d, want 7/7 | 重试次数应为 7/7", cfg.RetryCount, cfg.RNRRetry)
	}
	if err := cfg.normalize(); err != nil {
		t.Fatalf("normalize(default) = %v | 默认配置不应报错", err)
	}
}

// TestConfigNormalizeFillsQueueDepth proves zero queue depths become usable
// defaults. | TestConfigNormalizeFillsQueueDepth 证明零值队列深度会被填充为可用默认值。
func TestConfigNormalizeFillsQueueDepth(t *testing.T) {
	cfg := Config{}
	if err := cfg.normalize(); err != nil {
		t.Fatalf("normalize = %v | normalize 不应报错", err)
	}
	if cfg.Port != 1 {
		t.Fatalf("Port = %d, want 1 | Port 应归一化为 1", cfg.Port)
	}
	if cfg.QueueDepth < 64 {
		t.Fatalf("QueueDepth = %d, want >= 64 | 队列深度至少 64", cfg.QueueDepth)
	}
	if cfg.CQDepth < cfg.QueueDepth {
		t.Fatalf("CQDepth = %d, want >= QueueDepth %d | CQ 深度不得小于队列深度", cfg.CQDepth, cfg.QueueDepth)
	}
}

// TestConfigNormalizeRejectsInvalidMTU proves unsupported path MTUs are
// rejected rather than silently rounded. | TestConfigNormalizeRejectsInvalidMTU
// 证明不支持的路径 MTU 会被拒绝而不是静默取整。
func TestConfigNormalizeRejectsInvalidMTU(t *testing.T) {
	cfg := Config{MTU: 1500}
	if err := cfg.normalize(); err == nil {
		t.Fatal("normalize(MTU=1500) = nil, want error | 非标准 MTU 应报错")
	}
	for _, mtu := range []int{256, 512, 1024, 2048, 4096} {
		cfg := Config{MTU: mtu}
		if err := cfg.normalize(); err != nil {
			t.Fatalf("normalize(MTU=%d) = %v | 标准 MTU 应通过", mtu, err)
		}
	}
}

// TestConfigNormalizeRejectsInvalidRetries proves out-of-range retry fields are
// rejected. | TestConfigNormalizeRejectsInvalidRetries 证明越界的重试字段会被拒绝。
func TestConfigNormalizeRejectsInvalidRetries(t *testing.T) {
	if err := (&Config{RetryCount: 8}).normalize(); err == nil {
		t.Fatal("normalize(RetryCount=8) = nil, want error | RetryCount 越界应报错")
	}
	if err := (&Config{RNRRetry: 8}).normalize(); err == nil {
		t.Fatal("normalize(RNRRetry=8) = nil, want error | RNRRetry 越界应报错")
	}
	if err := (&Config{Timeout: 32}).normalize(); err == nil {
		t.Fatal("normalize(Timeout=32) = nil, want error | Timeout 越界应报错")
	}
	if err := (&Config{GIDIndex: -2}).normalize(); err == nil {
		t.Fatal("normalize(GIDIndex=-2) = nil, want error | GIDIndex 越界应报错")
	}
}

// TestSelectGIDPrefersRoCEv2IPv4 proves automatic selection skips link-local
// GIDs and picks the RoCE v2 IPv4-mapped entry. | TestSelectGIDPrefersRoCEv2IPv4
// 证明自动选择会跳过链路本地 GID，选择 RoCE v2 的 IPv4 映射表项。
func TestSelectGIDPrefersRoCEv2IPv4(t *testing.T) {
	gids := []GID{
		{Index: 0, Addr: parseGIDForTest(t, "fe80::ba59:9fff:fe01:1150"), Type: GIDTypeRoCEv1, NetDev: "eth0"},
		{Index: 1, Addr: parseGIDForTest(t, "fe80::ba59:9fff:fe01:1150"), Type: GIDTypeRoCEv2, NetDev: "eth0"},
		{Index: 2, Addr: parseGIDForTest(t, "::ffff:192.168.2.2"), Type: GIDTypeRoCEv1, NetDev: "eth0"},
		{Index: 3, Addr: parseGIDForTest(t, "::ffff:192.168.2.2"), Type: GIDTypeRoCEv2, NetDev: "eth0"},
	}
	cfg := DefaultConfig()
	idx, err := cfg.selectGID(gids)
	if err != nil {
		t.Fatalf("selectGID = %v | 自动选择失败", err)
	}
	if idx != 3 {
		t.Fatalf("selectGID = %d, want 3 | 应选择 RoCE v2 IPv4 表项", idx)
	}
}

// TestSelectGIDAutodetectsInfiniBand proves automatic selection prefers RoCE
// v2 when present but still selects a native InfiniBand GID on IB-only
// hardware. | TestSelectGIDAutodetectsInfiniBand 证明自动选择在存在 RoCE v2 时
// 优先选择它，在仅支持 InfiniBand 的硬件上仍能选中原生 IB GID。
func TestSelectGIDAutodetectsInfiniBand(t *testing.T) {
	mixed := []GID{
		{Index: 0, Addr: parseGIDForTest(t, "fe80::1"), Type: GIDTypeInfiniBand},
		{Index: 1, Addr: parseGIDForTest(t, "::ffff:192.168.2.2"), Type: GIDTypeRoCEv2},
	}
	cfg := DefaultConfig()
	idx, err := cfg.selectGID(mixed)
	if err != nil {
		t.Fatalf("selectGID(mixed) = %v | 混合 GID 自动选择失败", err)
	}
	if idx != 1 {
		t.Fatalf("selectGID(mixed) = %d, want 1 | 应优先选择 RoCE v2", idx)
	}
	ibOnly := mixed[:1]
	idx, err = cfg.selectGID(ibOnly)
	if err != nil {
		t.Fatalf("selectGID(ib) = %v | 仅 IB GID 时应能自动选择", err)
	}
	if idx != 0 {
		t.Fatalf("selectGID(ib) = %d, want 0 | 应回退到原生 InfiniBand GID", idx)
	}
}

// TestSelectGIDHonoursExplicitIndex proves an explicit GID index wins over
// automatic preference. | TestSelectGIDHonoursExplicitIndex 证明显式 GID 索引
// 优先于自动偏好。
func TestSelectGIDHonoursExplicitIndex(t *testing.T) {
	gids := []GID{
		{Index: 0, Addr: parseGIDForTest(t, "fe80::1"), Type: GIDTypeRoCEv1},
		{Index: 1, Addr: parseGIDForTest(t, "fe80::2"), Type: GIDTypeRoCEv2},
	}
	cfg := DefaultConfig()
	cfg.GIDIndex = 0
	idx, err := cfg.selectGID(gids)
	if err != nil {
		t.Fatalf("selectGID = %v | 显式索引失败", err)
	}
	if idx != 0 {
		t.Fatalf("selectGID = %d, want 0 | 显式索引应被采用", idx)
	}
	cfg.GIDIndex = 9
	if _, err := cfg.selectGID(gids); err == nil {
		t.Fatal("selectGID(index=9) = nil, want error | 不存在的索引应报错")
	}
}

// TestSelectGIDFiltersByNetDev proves the netdev filter is applied. |
// TestSelectGIDFiltersByNetDev 证明 netdev 过滤生效。
func TestSelectGIDFiltersByNetDev(t *testing.T) {
	gids := []GID{
		{Index: 0, Addr: parseGIDForTest(t, "::ffff:10.0.0.1"), Type: GIDTypeRoCEv2, NetDev: "eth0"},
		{Index: 1, Addr: parseGIDForTest(t, "::ffff:192.168.2.2"), Type: GIDTypeRoCEv2, NetDev: "eth1"},
	}
	cfg := DefaultConfig()
	cfg.NetDev = "eth1"
	idx, err := cfg.selectGID(gids)
	if err != nil {
		t.Fatalf("selectGID = %v | netdev 过滤失败", err)
	}
	if idx != 1 {
		t.Fatalf("selectGID = %d, want 1 | 应匹配指定 netdev", idx)
	}
}

// TestGIDIP proves IPv4-mapped and native IPv6 GIDs decode to their address
// while link-local and zero GIDs are rejected. | TestGIDIP 证明 IPv4 映射与
// 原生 IPv6 GID 可解码出地址，链路本地与全零 GID 被拒绝。
func TestGIDIP(t *testing.T) {
	cases := []struct {
		name string
		gid  string
		want string
		ok   bool
	}{
		{"mapped", "::ffff:192.168.2.2", "192.168.2.2", true},
		{"native", "2001:db8::1", "2001:db8::1", true},
		{"linklocal", "fe80::1", "", false},
		{"zero", "::", "", false},
	}
	for _, tc := range cases {
		g := GID{Addr: parseGIDForTest(t, tc.gid)}
		ip, ok := g.IP()
		if ok != tc.ok {
			t.Fatalf("%s: IP ok = %v, want %v | IP 判定不符", tc.name, ok, tc.ok)
		}
		if tc.ok && !ip.Equal(net.ParseIP(tc.want)) {
			t.Fatalf("%s: IP = %s, want %s | IP 地址不符", tc.name, ip, tc.want)
		}
	}
}

// TestGIDIPv4Only proves IPv4() returns an address only for IPv4-encoded GIDs.
// | TestGIDIPv4Only 证明 IPv4() 只对 IPv4 编码的 GID 返回地址。
func TestGIDIPv4Only(t *testing.T) {
	if _, ok := (GID{Addr: parseGIDForTest(t, "::ffff:192.168.2.2")}).IPv4(); !ok {
		t.Fatal("IPv4(mapped) ok = false, want true | IPv4 映射 GID 应成功")
	}
	if _, ok := (GID{Addr: parseGIDForTest(t, "2001:db8::1")}).IPv4(); ok {
		t.Fatal("IPv4(native IPv6) ok = true, want false | 纯 IPv6 GID 不应成功")
	}
}

// parseGIDForTest parses one textual IPv6 address into a GID. | parseGIDForTest
// 将文本 IPv6 地址解析为 GID。
func parseGIDForTest(t *testing.T, s string) (g [16]byte) {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil || ip.To16() == nil {
		t.Fatalf("parse IP %q failed | IP 解析失败", s)
	}
	copy(g[:], ip.To16())
	return g
}
