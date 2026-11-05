//go:build linux && rdma && (amd64 || arm64)

package rdma

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// testConfig returns DefaultConfig with optional environment overrides so the
// integration tests can run on RDMA hardware from any vendor. Recognised
// variables are YDX_RDMA_DEVICE, YDX_RDMA_PORT, YDX_RDMA_NETDEV,
// YDX_RDMA_GID_INDEX, YDX_RDMA_GID_TYPE (auto, ib, rocev1, rocev2) and
// YDX_RDMA_VERBS. With none set, device and GID selection stay automatic. |
// testConfig 返回带可选环境变量覆盖的 DefaultConfig，使集成测试可运行于任意
// 厂商的 RDMA 硬件。识别的变量为 YDX_RDMA_DEVICE、YDX_RDMA_PORT、
// YDX_RDMA_NETDEV、YDX_RDMA_GID_INDEX、YDX_RDMA_GID_TYPE（auto、ib、rocev1、
// rocev2）与 YDX_RDMA_VERBS。均未设置时设备与 GID 保持自动选择。
func testConfig(t *testing.T) Config {
	t.Helper()
	cfg := DefaultConfig()
	if v := strings.TrimSpace(os.Getenv("YDX_RDMA_DEVICE")); v != "" {
		cfg.Device = v
	}
	if v := strings.TrimSpace(os.Getenv("YDX_RDMA_NETDEV")); v != "" {
		cfg.NetDev = v
	}
	if v := strings.TrimSpace(os.Getenv("YDX_RDMA_VERBS")); v != "" {
		cfg.VerbsLibrary = v
	}
	if v := strings.TrimSpace(os.Getenv("YDX_RDMA_PORT")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			t.Fatalf("YDX_RDMA_PORT=%q is invalid | 端口环境变量非法", v)
		}
		cfg.Port = n
	}
	if v := strings.TrimSpace(os.Getenv("YDX_RDMA_GID_INDEX")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			t.Fatalf("YDX_RDMA_GID_INDEX=%q is invalid | GID 索引环境变量非法", v)
		}
		cfg.GIDIndex = n
	}
	switch v := strings.ToLower(strings.TrimSpace(os.Getenv("YDX_RDMA_GID_TYPE"))); v {
	case "", "auto", "unknown":
		cfg.GIDType = GIDTypeUnknown
	case "ib", "infiniband":
		cfg.GIDType = GIDTypeInfiniBand
	case "rocev1", "v1":
		cfg.GIDType = GIDTypeRoCEv1
	case "rocev2", "v2":
		cfg.GIDType = GIDTypeRoCEv2
	default:
		t.Fatalf("YDX_RDMA_GID_TYPE=%q is invalid | GID 类型环境变量非法", v)
	}
	return cfg
}
