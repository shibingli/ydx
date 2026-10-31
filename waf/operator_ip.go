package waf

import (
	"net"
	"net/netip"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// ipMatcher matches addresses against a fixed prefix and address set. | ipMatcher 用固定前缀与
// 地址集合匹配地址。
type ipMatcher struct {
	prefixes []netip.Prefix
	addrs    []netip.Addr
}

// parseIPMatcher parses CIDR prefixes and single addresses. | parseIPMatcher 解析 CIDR 前缀与单个地址。
func parseIPMatcher(items []string) (*ipMatcher, error) {
	m := &ipMatcher{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(item); err == nil {
			m.prefixes = append(m.prefixes, prefix.Masked())
			continue
		}
		addr, err := parseAddress(item)
		if err != nil {
			return nil, errs.Detail(ErrParse, "invalid IP or CIDR %q | 非法的 IP 或 CIDR %q", item, item)
		}
		m.addrs = append(m.addrs, addr)
	}
	if len(m.prefixes) == 0 && len(m.addrs) == 0 {
		return nil, errs.Detail(ErrParse, "empty IP match set | 空的 IP 匹配集合")
	}
	return m, nil
}

// parseAddress parses a host, optionally with a port, and unmaps IPv4-mapped IPv6 addresses.
// | parseAddress 解析主机（可带端口）并解映射 IPv4 映射的 IPv6 地址。
func parseAddress(value string) (netip.Addr, error) {
	value = strings.TrimSpace(value)
	if addr, err := netip.ParseAddr(value); err == nil {
		return addr.Unmap(), nil
	}
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		return netip.Addr{}, err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, err
	}
	return addr.Unmap(), nil
}

// match reports whether value matches a prefix or address. | match 报告 value 是否匹配某个前缀或地址。
func (m *ipMatcher) match(value string) bool {
	if m == nil {
		return false
	}
	addr, err := parseAddress(value)
	if err != nil {
		return false
	}
	for _, prefix := range m.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	for _, candidate := range m.addrs {
		if candidate == addr {
			return true
		}
	}
	return false
}
