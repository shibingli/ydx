package rdma

import (
	"net"
	"strconv"

	"github.com/shibingli/ydx/errs"
)

// AutoGIDIndex asks the library to pick a GID from its type and netdev
// preferences. | AutoGIDIndex 让库按类型与网卡偏好自动选择 GID。
const AutoGIDIndex = -1

// GIDType classifies one GID table entry. | GIDType 标识一个 GID 表项的类型。
type GIDType uint8

const (
	// GIDTypeUnknown leaves the type unspecified. | GIDTypeUnknown 表示类型未指定。
	GIDTypeUnknown GIDType = iota
	// GIDTypeInfiniBand is a native InfiniBand GID. | GIDTypeInfiniBand 是原生
	// InfiniBand GID。
	GIDTypeInfiniBand
	// GIDTypeRoCEv1 is a RoCE v1 GID (Ethernet link layer). | GIDTypeRoCEv1 是
	// RoCE v1 GID（以太网链路层）。
	GIDTypeRoCEv1
	// GIDTypeRoCEv2 is a RoCE v2 GID (UDP/IP encapsulation). | GIDTypeRoCEv2 是
	// RoCE v2 GID（UDP/IP 封装）。
	GIDTypeRoCEv2
)

// String returns the English name of the GID type. | String 返回 GID 类型的英文名。
func (t GIDType) String() string {
	switch t {
	case GIDTypeInfiniBand:
		return "InfiniBand"
	case GIDTypeRoCEv1:
		return "RoCE v1"
	case GIDTypeRoCEv2:
		return "RoCE v2"
	default:
		return "unknown"
	}
}

// GID is one entry of a port GID table. | GID 是端口 GID 表中的一个表项。
type GID struct {
	// Index is the GID table index used by ibv_modify_qp. | Index 是
	// ibv_modify_qp 使用的 GID 表索引。
	Index int
	// Addr is the raw 16-byte GID. | Addr 是 16 字节原始 GID。
	Addr [16]byte
	// Type classifies the entry. | Type 标识表项类型。
	Type GIDType
	// NetDev is the backing Ethernet netdev for RoCE entries. | NetDev 是 RoCE
	// 表项对应的以太网设备。
	NetDev string
}

// ParseGID parses a textual IPv6 or IPv4-mapped address into a GID with the
// given index. | ParseGID 将 IPv6 或 IPv4 映射文本地址解析为指定索引的 GID。
func ParseGID(index int, s string) (GID, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return GID{}, errs.Detail(ErrInvalidGID, "%q", s)
	}
	v6 := ip.To16()
	if v6 == nil {
		return GID{}, errs.Detail(ErrInvalidGID, "%q", s)
	}
	g := GID{Index: index}
	copy(g.Addr[:], v6)
	return g, nil
}

// String renders the GID address in canonical form. | String 以规范形式输出 GID 地址。
func (g GID) String() string { return net.IP(g.Addr[:]).String() }

// IsZero reports whether every GID byte is zero. | IsZero 报告 GID 是否全零。
func (g GID) IsZero() bool {
	for _, b := range g.Addr {
		if b != 0 {
			return false
		}
	}
	return true
}

// IsLinkLocal reports whether the GID is in fe80::/10. | IsLinkLocal 报告 GID
// 是否位于 fe80::/10。
func (g GID) IsLinkLocal() bool {
	return g.Addr[0] == 0xfe && g.Addr[1]&0xc0 == 0x80
}

// IPv4 returns the IPv4 address carried by an IPv4-mapped or IPv4-compatible
// GID. | IPv4 返回 IPv4 映射或 IPv4 兼容 GID 中携带的 IPv4 地址。
func (g GID) IPv4() (net.IP, bool) {
	if g.IsZero() || g.IsLinkLocal() {
		return nil, false
	}
	for i := 0; i < 10; i++ {
		if g.Addr[i] != 0 {
			return nil, false
		}
	}
	mapped := g.Addr[10] == 0xff && g.Addr[11] == 0xff
	compatible := g.Addr[10] == 0 && g.Addr[11] == 0
	if !mapped && !compatible {
		return nil, false
	}
	ip := make(net.IP, 4)
	copy(ip, g.Addr[12:16])
	if ip.Equal(net.IPv4zero) {
		return nil, false
	}
	return ip, true
}

// IP returns the address carried by the GID. Link-local and zero GIDs report
// false because they cannot address a RoCE v2 peer. | IP 返回 GID 携带的地址；
// 链路本地与全零 GID 返回 false，因为它们不能寻址 RoCE v2 对端。
func (g GID) IP() (net.IP, bool) {
	if g.IsZero() || g.IsLinkLocal() {
		return nil, false
	}
	if ip, ok := g.IPv4(); ok {
		return ip, true
	}
	ip := make(net.IP, 16)
	copy(ip, g.Addr[:])
	return ip, true
}

// gidTypeFromSysfs converts a sysfs type string to a GIDType. The sysfs text
// "IB/RoCE v1" is shared by native InfiniBand and RoCE v1, so the link layer
// disambiguates it. | gidTypeFromSysfs 将 sysfs 类型字符串转换为 GIDType。
// "IB/RoCE v1" 同时用于原生 InfiniBand 与 RoCE v1，用链路层区分。
func gidTypeFromSysfs(s string, link LinkLayer) GIDType {
	switch s {
	case "RoCE v2":
		return GIDTypeRoCEv2
	case "IB/RoCE v1":
		if link == LinkLayerInfiniBand {
			return GIDTypeInfiniBand
		}
		return GIDTypeRoCEv1
	default:
		return GIDTypeUnknown
	}
}

// inferGIDType classifies a GID when sysfs omits gid_attrs/types. Native
// InfiniBand links yield InfiniBand GIDs; Ethernet links yield RoCE v1 for
// link-local addresses and RoCE v2 otherwise. | inferGIDType 在 sysfs 未提供
// gid_attrs/types 时判定 GID 类型。原生 InfiniBand 链路为 InfiniBand GID；
// 以太网链路本地地址为 RoCE v1，其余为 RoCE v2。
func inferGIDType(g GID, link LinkLayer) GIDType {
	switch link {
	case LinkLayerInfiniBand:
		return GIDTypeInfiniBand
	case LinkLayerEthernet:
		if g.IsLinkLocal() {
			return GIDTypeRoCEv1
		}
		return GIDTypeRoCEv2
	default:
		return GIDTypeUnknown
	}
}

// parseDecimal parses a base-10 sysfs integer. | parseDecimal 解析十进制 sysfs 整数。
func parseDecimal(s string) (uint64, bool) {
	v, err := strconv.ParseUint(s, 10, 64)
	return v, err == nil
}
