//go:build linux && rdma && (amd64 || arm64)

package rdma

import (
	"os"
	"strconv"
	"strings"
	"testing"

	ydx "github.com/shibingli/ydx/rdma"
)

// benchConfig returns the benchmark configuration with optional environment
// overrides, so the same benchmarks run on RDMA hardware from any vendor. The
// recognised variables are YDX_RDMA_DEVICE, YDX_RDMA_PORT, YDX_RDMA_NETDEV,
// YDX_RDMA_GID_INDEX and YDX_RDMA_GID_TYPE. | benchConfig 返回带可选环境变量
// 覆盖的基准配置，使同一基准可运行于任意厂商的 RDMA 硬件。识别的变量为
// YDX_RDMA_DEVICE、YDX_RDMA_PORT、YDX_RDMA_NETDEV、YDX_RDMA_GID_INDEX 与
// YDX_RDMA_GID_TYPE。
func benchConfig(t *testing.T) ydx.Config {
	t.Helper()
	cfg := ydx.DefaultConfig()
	if v := strings.TrimSpace(os.Getenv("YDX_RDMA_DEVICE")); v != "" {
		cfg.Device = v
	}
	if v := strings.TrimSpace(os.Getenv("YDX_RDMA_NETDEV")); v != "" {
		cfg.NetDev = v
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
		cfg.GIDType = ydx.GIDTypeUnknown
	case "ib", "infiniband":
		cfg.GIDType = ydx.GIDTypeInfiniBand
	case "rocev1", "v1":
		cfg.GIDType = ydx.GIDTypeRoCEv1
	case "rocev2", "v2":
		cfg.GIDType = ydx.GIDTypeRoCEv2
	default:
		t.Fatalf("YDX_RDMA_GID_TYPE=%q is invalid | GID 类型环境变量非法", v)
	}
	return cfg
}
