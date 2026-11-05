package rdma

import "github.com/shibingli/ydx/errs"

// Default queue and path parameters. | 默认队列与路径参数。
const (
	// DefaultPort is the usual first port of an RDMA device. | DefaultPort 是
	// RDMA 设备通常使用的 1 号端口。
	DefaultPort = 1
	// DefaultQueueDepth is the default send and receive queue depth. |
	// DefaultQueueDepth 是默认发送与接收队列深度。
	DefaultQueueDepth = 512
	// DefaultHopLimit is the default RoCE v2 IPv6 hop limit. | DefaultHopLimit
	// 是默认 RoCE v2 IPv6 跳数限制。
	DefaultHopLimit = 64
	// DefaultTimeout is the default local ACK timeout exponent. | DefaultTimeout
	// 是默认本地 ACK 超时指数。
	DefaultTimeout = 14
	// DefaultRetryCount is the default transport retry count. | DefaultRetryCount
	// 是默认传输重试次数。
	DefaultRetryCount = 7
	// DefaultRNRRetry is the default receiver-not-ready retry count; 7 retries
	// forever. | DefaultRNRRetry 是默认接收端未就绪重试次数；7 表示无限重试。
	DefaultRNRRetry = 7
	// DefaultMinRNRTimer is the default minimum RNR NAK timer. |
	// DefaultMinRNRTimer 是默认最小 RNR NAK 定时器。
	DefaultMinRNRTimer = 12
	// DefaultMaxRDMAtomic is the default outstanding RDMA read and atomic
	// count. | DefaultMaxRDMAtomic 是默认在途 RDMA 读与原子操作数。
	DefaultMaxRDMAtomic = 16
)

// Config configures one opened RDMA device and its queue pair defaults. The
// zero value is valid; DefaultConfig supplies tuned defaults for RoCE v2. |
// Config 配置一个已打开的 RDMA 设备及其队列对默认值。零值可用；
// DefaultConfig 提供面向 RoCE v2 的调优默认值。
type Config struct {
	// VerbsLibrary overrides the libibverbs shared object path. Empty tries the
	// portable soname, then the common Debian, Ubuntu, RHEL, Fedora, SUSE and
	// OFED paths. | VerbsLibrary 覆盖 libibverbs 共享库路径。为空时先尝试可移植
	// soname，再尝试 Debian、Ubuntu、RHEL、Fedora、SUSE 与 OFED 的常见路径。
	VerbsLibrary string
	// Device selects a device such as "mlx5_0". Empty picks the first device
	// with an active port. | Device 选择设备，例如 "mlx5_0"；为空时选择第一个
	// 存在活动端口的设备。
	Device string
	// Port selects the device port. Zero means DefaultPort. | Port 选择设备
	// 端口；零表示 DefaultPort。
	Port int
	// GIDIndex selects a GID table entry. AutoGIDIndex picks automatically. |
	// GIDIndex 选择 GID 表项；AutoGIDIndex 表示自动选择。
	GIDIndex int
	// GIDType restricts automatic GID selection to one type. | GIDType 将自动
	// GID 选择限制为一种类型。
	GIDType GIDType
	// NetDev restricts automatic GID selection to one Ethernet netdev. |
	// NetDev 将自动 GID 选择限制为一个以太网设备。
	NetDev string
	// MTU is the path MTU: 256, 512, 1024, 2048 or 4096. Zero uses the port's
	// active MTU. | MTU 是路径 MTU：256、512、1024、2048 或 4096；零使用端口
	// 当前活动 MTU。
	MTU int
	// TrafficClass is the RoCE v2 IPv6 traffic class. | TrafficClass 是 RoCE v2
	// IPv6 流量类别。
	TrafficClass uint8
	// ServiceLevel is the InfiniBand service level. | ServiceLevel 是
	// InfiniBand 服务等级。
	ServiceLevel uint8
	// HopLimit is the RoCE v2 IPv6 hop limit. Zero means DefaultHopLimit. |
	// HopLimit 是 RoCE v2 IPv6 跳数限制；零表示 DefaultHopLimit。
	HopLimit uint8
	// PSN is the initial send packet sequence number. Zero picks a random
	// value. | PSN 是初始发送报文序列号；零表示随机值。
	PSN uint32
	// Timeout is the local ACK timeout exponent (0-31). | Timeout 是本地 ACK
	// 超时指数（0-31）。
	Timeout uint8
	// RetryCount is the transport retry count (0-7). | RetryCount 是传输重试
	// 次数（0-7）。
	RetryCount uint8
	// RNRRetry is the receiver-not-ready retry count (0-7); 7 means forever. |
	// RNRRetry 是接收端未就绪重试次数（0-7）；7 表示无限。
	RNRRetry uint8
	// MinRNRTimer is the minimum RNR NAK timer (0-31). | MinRNRTimer 是最小
	// RNR NAK 定时器（0-31）。
	MinRNRTimer uint8
	// MaxRDMAtomic is the outstanding RDMA read and atomic count (0-31). |
	// MaxRDMAtomic 是在途 RDMA 读与原子操作数（0-31）。
	MaxRDMAtomic uint8
	// MaxDestRDMAtomic is the remote outstanding RDMA read and atomic count
	// (0-31). | MaxDestRDMAtomic 是远端在途 RDMA 读与原子操作数（0-31）。
	MaxDestRDMAtomic uint8
	// MaxInline is the maximum inline payload in bytes. Zero uses the device
	// maximum. | MaxInline 是最大内联负载字节数；零使用设备上限。
	MaxInline int
	// QueueDepth is the send and receive queue depth. Zero means
	// DefaultQueueDepth. | QueueDepth 是发送与接收队列深度；零表示
	// DefaultQueueDepth。
	QueueDepth int
	// CQDepth is the completion queue depth. Zero means twice QueueDepth. |
	// CQDepth 是完成队列深度；零表示 QueueDepth 的两倍。
	CQDepth int
}

// DefaultConfig returns a configuration tuned for RoCE v2 with automatic GID
// selection. | DefaultConfig 返回面向 RoCE v2 自动选择 GID 的调优配置。
func DefaultConfig() Config {
	return Config{
		Port:             DefaultPort,
		GIDIndex:         AutoGIDIndex,
		GIDType:          GIDTypeRoCEv2,
		HopLimit:         DefaultHopLimit,
		Timeout:          DefaultTimeout,
		RetryCount:       DefaultRetryCount,
		RNRRetry:         DefaultRNRRetry,
		MinRNRTimer:      DefaultMinRNRTimer,
		MaxRDMAtomic:     DefaultMaxRDMAtomic,
		MaxDestRDMAtomic: DefaultMaxRDMAtomic,
		QueueDepth:       DefaultQueueDepth,
	}
}

// normalize validates the configuration and fills zero-value defaults. It is
// idempotent. | normalize 校验配置并填充零值默认项，可重复调用。
func (c *Config) normalize() error {
	if c.Port == 0 {
		c.Port = DefaultPort
	}
	if c.Port < 0 || c.Port > 255 {
		return errs.Detail(ErrInvalidConfig, "port %d | 端口 %d", c.Port, c.Port)
	}
	if c.GIDIndex < AutoGIDIndex {
		return errs.Detail(ErrInvalidConfig, "gid index %d | GID 索引 %d", c.GIDIndex, c.GIDIndex)
	}
	if c.GIDType > GIDTypeRoCEv2 {
		return errs.Detail(ErrInvalidConfig, "gid type %d | GID 类型 %d", c.GIDType, c.GIDType)
	}
	switch c.MTU {
	case 0, 256, 512, 1024, 2048, 4096:
	default:
		return errs.Detail(ErrInvalidConfig, "mtu %d is not 256/512/1024/2048/4096 | MTU %d 非法", c.MTU, c.MTU)
	}
	if c.HopLimit == 0 {
		c.HopLimit = DefaultHopLimit
	}
	if c.QueueDepth == 0 {
		c.QueueDepth = DefaultQueueDepth
	}
	if c.QueueDepth < 2 {
		return errs.Detail(ErrInvalidConfig, "queue depth %d | 队列深度 %d", c.QueueDepth, c.QueueDepth)
	}
	if c.CQDepth == 0 {
		c.CQDepth = c.QueueDepth * 2
	}
	if c.CQDepth < c.QueueDepth {
		return errs.Detail(ErrInvalidConfig, "cq depth %d < queue depth %d | CQ 深度小于队列深度", c.CQDepth, c.QueueDepth)
	}
	if c.Timeout > 31 {
		return errs.Detail(ErrInvalidConfig, "timeout %d | 超时指数 %d", c.Timeout, c.Timeout)
	}
	if c.RetryCount > 7 {
		return errs.Detail(ErrInvalidConfig, "retry count %d | 重试次数 %d", c.RetryCount, c.RetryCount)
	}
	if c.RNRRetry > 7 {
		return errs.Detail(ErrInvalidConfig, "rnr retry %d | RNR 重试次数 %d", c.RNRRetry, c.RNRRetry)
	}
	if c.MinRNRTimer > 31 {
		return errs.Detail(ErrInvalidConfig, "min rnr timer %d | 最小 RNR 定时器 %d", c.MinRNRTimer, c.MinRNRTimer)
	}
	if c.MaxRDMAtomic == 0 {
		c.MaxRDMAtomic = DefaultMaxRDMAtomic
	}
	if c.MaxRDMAtomic > 31 {
		return errs.Detail(ErrInvalidConfig, "max rd atomic %d | 最大 RD 原子数 %d", c.MaxRDMAtomic, c.MaxRDMAtomic)
	}
	if c.MaxDestRDMAtomic == 0 {
		c.MaxDestRDMAtomic = DefaultMaxRDMAtomic
	}
	if c.MaxDestRDMAtomic > 31 {
		return errs.Detail(ErrInvalidConfig, "max dest rd atomic %d | 远端最大 RD 原子数 %d", c.MaxDestRDMAtomic, c.MaxDestRDMAtomic)
	}
	if c.MaxInline < 0 {
		return errs.Detail(ErrInvalidConfig, "max inline %d | 最大内联 %d", c.MaxInline, c.MaxInline)
	}
	return nil
}

// selectGID returns the GID table index to use. An explicit index wins;
// otherwise the best entry matching GIDType and NetDev is chosen, preferring
// RoCE v2, routable IPv4 addresses and non-link-local entries in that order. |
// selectGID 返回使用的 GID 表索引。显式索引优先；否则选择最匹配 GIDType 与
// NetDev 的表项，依次偏好 RoCE v2、可路由 IPv4 地址、非链路本地表项。
func (c *Config) selectGID(gids []GID) (int, error) {
	if c.GIDIndex >= 0 {
		for _, g := range gids {
			if g.Index == c.GIDIndex {
				return g.Index, nil
			}
		}
		return 0, errs.Detail(ErrNoGID, "index %d not found | 索引 %d 不存在", c.GIDIndex, c.GIDIndex)
	}
	best := -1
	bestScore := -1
	for _, g := range gids {
		if g.IsZero() {
			continue
		}
		if c.GIDType != GIDTypeUnknown && g.Type != c.GIDType {
			continue
		}
		if c.NetDev != "" && g.NetDev != c.NetDev {
			continue
		}
		score := 0
		switch g.Type {
		case GIDTypeRoCEv2:
			score += 30
		case GIDTypeRoCEv1:
			score += 20
		case GIDTypeInfiniBand:
			score += 10
		}
		if _, ok := g.IPv4(); ok {
			score += 6
		}
		if !g.IsLinkLocal() {
			score += 3
		}
		if score > bestScore {
			bestScore = score
			best = g.Index
		}
	}
	if best < 0 {
		return 0, errs.Detail(ErrNoGID, "type %s netdev %q | 类型 %s 网卡 %q", c.GIDType, c.NetDev, c.GIDType, c.NetDev)
	}
	return best, nil
}
