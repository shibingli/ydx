package kerberos

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// defaultKDCPort is the assigned Kerberos KDC port. | defaultKDCPort 是分配的 Kerberos
// KDC 端口。
const defaultKDCPort = "88"

// maxKDCResponseSize bounds a framed TCP response. | maxKDCResponseSize 限制带帧的 TCP 响应。
const maxKDCResponseSize = 4 << 20

// defaultKDCExchangeTimeout bounds one KDC exchange. | defaultKDCExchangeTimeout 限制一次
// KDC 交换。
const defaultKDCExchangeTimeout = 10 * time.Second

// dnsResolver is the subset of net.Resolver used for KDC discovery. | dnsResolver 是
// KDC 发现使用的 net.Resolver 子集。
type dnsResolver interface {
	// LookupSRV resolves SRV records for a service and protocol. | LookupSRV 解析服务与协议的
	// SRV 记录。
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
	// LookupTXT resolves TXT records for a name. | LookupTXT 解析名称的 TXT 记录。
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// kdcTransport sends KDC requests and resolves KDC locations. | kdcTransport 发送 KDC
// 请求并解析 KDC 位置。
type kdcTransport struct {
	servers      []string
	realm        string
	timeout      time.Duration
	retries      int
	preferTCP    bool
	resolver     dnsResolver
	mu           sync.Mutex
	discovered   []string
	discoveredAt time.Time
}

// newKDCRansport builds a transport from explicit servers and discovery settings. | newKDCTransport
// 用显式服务器与发现设置构建传输。
func newKDCTransport(servers []string, realm string, timeout time.Duration, retries int, preferTCP bool, resolver dnsResolver) *kdcTransport {
	normalized := make([]string, 0, len(servers))
	for _, server := range servers {
		if value, ok := normalizeKDCServer(server); ok {
			normalized = append(normalized, value)
		}
	}
	if timeout <= 0 {
		timeout = defaultKDCExchangeTimeout
	}
	if retries < 0 {
		retries = 0
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &kdcTransport{
		servers:   normalized,
		realm:     realm,
		timeout:   timeout,
		retries:   retries,
		preferTCP: preferTCP,
		resolver:  resolver,
	}
}

// normalizeKDCServer accepts host, host:port, and bracketed IPv6 literals. | normalizeKDCServer
// 接受主机、host:port 与带方括号的 IPv6 字面量。
func normalizeKDCServer(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	if host, port, err := net.SplitHostPort(value); err == nil {
		if host == "" || port == "" {
			return "", false
		}
		return net.JoinHostPort(host, port), true
	}
	trimmed := strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
	if ip := net.ParseIP(trimmed); ip != nil {
		return net.JoinHostPort(trimmed, defaultKDCPort), true
	}
	return net.JoinHostPort(value, defaultKDCPort), true
}

// candidates returns explicit servers or a cached DNS discovery result. | candidates
// 返回显式服务器或缓存的 DNS 发现结果。
func (t *kdcTransport) candidates(ctx context.Context) ([]string, error) {
	if len(t.servers) > 0 {
		return t.servers, nil
	}
	if t.realm == "" {
		return nil, errs.Detail(ErrKDCNotFound, "no KDC servers and no realm | 没有 KDC 服务器且没有 realm")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.discovered) > 0 && time.Since(t.discoveredAt) < 5*time.Minute {
		return append([]string(nil), t.discovered...), nil
	}
	servers, err := discoverKDCs(ctx, t.realm, t.resolver, t.preferTCP)
	if err != nil {
		return nil, err
	}
	t.discovered = append([]string(nil), servers...)
	t.discoveredAt = time.Now()
	return servers, nil
}

// exchange sends one KDC request and returns the raw response message. KRB-ERROR
// responses are returned to the caller for semantic decoding. | exchange 发送一个 KDC
// 请求并返回原始响应消息。KRB-ERROR 响应返回给调用方做语义解码。
func (t *kdcTransport) exchange(ctx context.Context, request []byte) ([]byte, error) {
	servers, err := t.candidates(ctx)
	if err != nil {
		return nil, err
	}
	attempts := t.retries + 1
	var lastErr error
	for round := 0; round < attempts; round++ {
		for _, server := range servers {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			response, err := t.exchangeOne(ctx, server, request)
			if err != nil {
				lastErr = err
				continue
			}
			return response, nil
		}
	}
	if lastErr == nil {
		lastErr = errs.Detail(ErrKDCUnavailable, "no KDC candidates | 没有 KDC 候选")
	}
	return nil, lastErr
}

// exchangeOne tries one KDC, falling back to TCP when UDP reports an oversized
// response. | exchangeOne 尝试一个 KDC，UDP 报告响应过大时回退到 TCP。
func (t *kdcTransport) exchangeOne(ctx context.Context, server string, request []byte) ([]byte, error) {
	if t.preferTCP {
		return t.exchangeTCP(ctx, server, request)
	}
	response, err := t.exchangeUDP(ctx, server, request)
	if err != nil {
		return nil, err
	}
	if krbErr, parseErr := ParseKRBError(response); parseErr == nil && krbErr.ErrorCode == 52 {
		return t.exchangeTCP(ctx, server, request)
	}
	return response, nil
}

// exchangeUDP performs one UDP request and response. | exchangeUDP 执行一次 UDP 请求与响应。
func (t *kdcTransport) exchangeUDP(ctx context.Context, server string, request []byte) ([]byte, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(attemptCtx, "udp", server)
	if err != nil {
		return nil, wrapKDCError(err, attemptCtx, server, "UDP dial")
	}
	defer conn.Close()
	if deadline, ok := attemptCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(request); err != nil {
		return nil, wrapKDCError(err, attemptCtx, server, "UDP write")
	}
	buffer := make([]byte, 64<<10)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, wrapKDCError(err, attemptCtx, server, "UDP read")
	}
	if n == 0 {
		return nil, errs.Detail(ErrKDCUnavailable, "empty UDP response from %s | 来自 %s 的空 UDP 响应", server, server)
	}
	return append([]byte(nil), buffer[:n]...), nil
}

// exchangeTCP performs one length-framed TCP request and response. | exchangeTCP 执行一次
// 带长度帧的 TCP 请求与响应。
func (t *kdcTransport) exchangeTCP(ctx context.Context, server string, request []byte) ([]byte, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(attemptCtx, "tcp", server)
	if err != nil {
		return nil, wrapKDCError(err, attemptCtx, server, "TCP dial")
	}
	defer conn.Close()
	if deadline, ok := attemptCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	frame := make([]byte, 4+len(request))
	binary.BigEndian.PutUint32(frame, uint32(len(request)))
	copy(frame[4:], request)
	if _, err := conn.Write(frame); err != nil {
		return nil, wrapKDCError(err, attemptCtx, server, "TCP write")
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, wrapKDCError(err, attemptCtx, server, "TCP read header")
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 {
		return nil, errs.Detail(ErrKDCUnavailable, "empty TCP response from %s | 来自 %s 的空 TCP 响应", server, server)
	}
	if size > maxKDCResponseSize {
		return nil, errs.Detail(ErrResponseTooBig, "TCP response from %s is %d bytes | 来自 %s 的 TCP 响应为 %d 字节",
			server, size, server, size)
	}
	response := make([]byte, int(size))
	if _, err := io.ReadFull(conn, response); err != nil {
		return nil, wrapKDCError(err, attemptCtx, server, "TCP read body")
	}
	return response, nil
}

// wrapKDCError classifies a transport failure as timeout or unavailability. | wrapKDCError
// 把传输失败分类为超时或不可用。
func wrapKDCError(err error, ctx context.Context, server, operation string) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		if errors.Is(ctxErr, context.DeadlineExceeded) {
			return errs.WrapDetail(ctxErr, ErrKDCTimeout, "%s with %s timed out | 与 %s 的 %s 超时", operation, server, server, operation)
		}
		return ctxErr
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return errs.WrapDetail(err, ErrKDCTimeout, "%s with %s timed out | 与 %s 的 %s 超时", operation, server, server, operation)
	}
	return errs.WrapDetail(err, ErrKDCUnavailable, "%s with %s failed | 与 %s 的 %s 失败", operation, server, server, operation)
}

// discoverKDCs resolves KDC servers through RFC 4120 DNS SRV records. | discoverKDCs
// 通过 RFC 4120 DNS SRV 记录解析 KDC 服务器。
func discoverKDCs(ctx context.Context, realm string, resolver dnsResolver, preferTCP bool) ([]string, error) {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	protocols := []string{"udp", "tcp"}
	if preferTCP {
		protocols = []string{"tcp", "udp"}
	}
	var servers []string
	var lastErr error
	for _, protocol := range protocols {
		_, records, err := resolver.LookupSRV(ctx, "kerberos", protocol, realm)
		if err != nil {
			lastErr = err
			continue
		}
		for _, record := range records {
			target := strings.TrimSuffix(record.Target, ".")
			if target == "" || target == "." {
				continue
			}
			port := int(record.Port)
			if port == 0 {
				port = 88
			}
			servers = append(servers, net.JoinHostPort(target, itoa(port)))
		}
		if len(servers) > 0 {
			return servers, nil
		}
	}
	if lastErr != nil {
		return nil, errs.WrapDetail(lastErr, ErrKDCNotFound, "no KDC SRV record for realm %s | realm %s 没有 KDC SRV 记录", realm, realm)
	}
	return nil, errs.Detail(ErrKDCNotFound, "no KDC SRV record for realm %s | realm %s 没有 KDC SRV 记录", realm, realm)
}

// DiscoverKDCs resolves KDC servers for realm with DNS SRV. A nil resolver uses
// net.DefaultResolver. | DiscoverKDCs 用 DNS SRV 为 realm 解析 KDC 服务器。resolver
// 为空时使用 net.DefaultResolver。
func DiscoverKDCs(ctx context.Context, realm string, resolver *net.Resolver, preferTCP bool) ([]string, error) {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return discoverKDCs(ctx, realm, resolver, preferTCP)
}

// DiscoverRealm resolves a realm from the RFC 4120 TXT record _kerberos.host. | DiscoverRealm
// 从 RFC 4120 TXT 记录 _kerberos.host 解析 realm。
func DiscoverRealm(ctx context.Context, host string, resolver *net.Resolver) (string, error) {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return discoverRealm(ctx, host, resolver)
}

// discoverRealm implements realm discovery through a TXT lookup. | discoverRealm 通过 TXT
// 查询实现 realm 发现。
func discoverRealm(ctx context.Context, host string, resolver dnsResolver) (string, error) {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" {
		return "", errs.Detail(ErrRealmNotFound, "empty host name | 主机名为空")
	}
	records, err := resolver.LookupTXT(ctx, "_kerberos."+host)
	if err != nil {
		return "", errs.WrapDetail(err, ErrRealmNotFound, "realm TXT lookup for %s failed | %s 的 realm TXT 查询失败", host, host)
	}
	for _, record := range records {
		value := strings.Trim(strings.TrimSpace(record), "\"")
		value = strings.TrimSpace(value)
		if value != "" {
			return strings.ToUpper(value), nil
		}
	}
	return "", errs.Detail(ErrRealmNotFound, "no realm TXT record for %s | %s 没有 realm TXT 记录", host, host)
}

// itoa renders a non-negative int without pulling formatting elsewhere. | itoa 渲染非负
// int，避免在别处引入格式化。
func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for value > 0 {
		pos--
		buf[pos] = byte('0' + value%10)
		value /= 10
	}
	return string(buf[pos:])
}
