package waf

import (
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// parseTrustedProxy parses a trusted proxy address or CIDR. | parseTrustedProxy 解析可信代理地址或 CIDR。
func parseTrustedProxy(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Prefix{}, errs.Detail(ErrInvalidOption, "empty trusted proxy | 空的可信代理")
	}
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, errs.Detail(ErrInvalidOption, "invalid trusted proxy %q | 非法的可信代理 %q", value, value)
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// resolveClientIP returns the client host, honoring proxy headers only from trusted proxies.
// | resolveClientIP 返回客户端主机，仅信任来自可信代理的代理头。
func resolveClientIP(opts Options, r *http.Request) string {
	if r == nil {
		return ""
	}
	if opts.ClientIP != nil {
		return opts.ClientIP(r)
	}
	remote := remoteHost(r.RemoteAddr)
	if len(opts.trusted) == 0 {
		return remote
	}
	addr, err := netip.ParseAddr(remote)
	if err != nil || !trustedAddr(opts.trusted, addr.Unmap()) {
		return remote
	}
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			candidate := strings.TrimSpace(parts[i])
			parsed, err := netip.ParseAddr(candidate)
			if err != nil {
				continue
			}
			parsed = parsed.Unmap()
			if trustedAddr(opts.trusted, parsed) {
				continue
			}
			return parsed.String()
		}
		if len(parts) > 0 {
			if parsed, err := netip.ParseAddr(strings.TrimSpace(parts[0])); err == nil {
				return parsed.Unmap().String()
			}
		}
	}
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-Ip")); realIP != "" {
		if parsed, err := netip.ParseAddr(realIP); err == nil {
			return parsed.Unmap().String()
		}
	}
	return remote
}

// trustedAddr reports whether addr matches one trusted prefix. | trustedAddr 报告 addr 是否匹配某个
// 可信前缀。
func trustedAddr(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// remoteHost extracts the host from RemoteAddr. | remoteHost 从 RemoteAddr 提取主机。
func remoteHost(remoteAddr string) string {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}
