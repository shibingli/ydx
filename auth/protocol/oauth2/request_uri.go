package oauth2

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/shibingli/ydx/errs"
)

// requestObjectCacheCapacity bounds the number of cached by-reference request objects. |
// requestObjectCacheCapacity 限定按引用请求对象的缓存条目数。
const requestObjectCacheCapacity = 1024

// requestURISingleUseCapacity bounds the number of remembered single-use request_uri values so a
// stream of unique URIs cannot grow the map without limit. | requestURISingleUseCapacity 限定记住的
// 一次性 request_uri 值数量，避免唯一 URI 流无限增长该映射。
const requestURISingleUseCapacity = 4096

// cachedRequestObject is one fetched request object with its cache deadline. | cachedRequestObject
// 是带缓存期限的已抓取请求对象。
type cachedRequestObject struct {
	body    string
	expires time.Time
}

// requestURICache fetches, validates and caches RFC 9101 by-reference request objects. |
// requestURICache 抓取、校验并缓存 RFC 9101 按引用传递的请求对象。
type requestURICache struct {
	mu      sync.Mutex
	entries map[string]cachedRequestObject
	used    map[string]time.Time
	client  *http.Client
	config  RequestURIConfig
	now     func() time.Time
}

// newRequestURICache normalizes the configuration and returns a cache. | newRequestURICache 规范化
// 配置并返回缓存。
func newRequestURICache(config RequestURIConfig, now func() time.Time) *requestURICache {
	if config.Timeout <= 0 {
		config.Timeout = 5 * time.Second
	}
	if config.MaxSize <= 0 {
		config.MaxSize = 1 << 20
	}
	if config.MaxURILength <= 0 {
		config.MaxURILength = 2048
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = 5 * time.Minute
	}
	if now == nil {
		now = time.Now
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout:   config.Timeout,
			Transport: requestObjectTransport(config.AllowLoopback),
		}
	} else {
		// Copy before changing redirect policy so the caller's client is never mutated. | 修改
		// 重定向策略前先复制，避免改动调用方客户端。
		copied := *client
		client = &copied
	}
	// A redirect can point at an internal service after the initial URL passed every check, so
	// request-object fetches never follow one. | 重定向可能在初始 URL 通过检查后指向内部服务，
	// 因此请求对象抓取从不跟随重定向。
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &requestURICache{
		entries: make(map[string]cachedRequestObject),
		used:    make(map[string]time.Time),
		client:  client,
		config:  config,
		now:     now,
	}
}

// requestObjectTransport returns an egress transport that refuses non-public addresses. |
// requestObjectTransport 返回拒绝非公网地址的出站传输。
func requestObjectTransport(allowLoopback bool) *http.Transport {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				host = address
			}
			ip := net.ParseIP(strings.Trim(host, "[]"))
			if ip == nil {
				return nil
			}
			if ip.IsLoopback() {
				if allowLoopback {
					return nil
				}
				return errs.Detail(ErrInvalidRequestURI, "loopback request_uri is not allowed | 不允许回环 request_uri")
			}
			if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
				ip.IsUnspecified() || ip.IsMulticast() {
				return errs.Detail(ErrInvalidRequestURI, "non-public request_uri address is not allowed | 不允许非公网 request_uri 地址")
			}
			return nil
		},
	}
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}
}

// Fetch returns the request object referenced by requestURI. | Fetch 返回 requestURI 引用的请求对象。
func (c *requestURICache) Fetch(ctx context.Context, client *Client, requestURI string) (string, error) {
	parsed, err := c.validateURI(client, requestURI)
	if err != nil {
		return "", err
	}
	if c.config.SingleUse && !c.beginUse(requestURI) {
		return "", NewError(ErrorInvalidRequestURI, "request_uri was already used | request_uri 已被使用")
	}
	if body, ok := c.lookup(requestURI); ok {
		return body, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return "", NewError(ErrorInvalidRequestURI, "request_uri cannot be requested | 无法请求 request_uri")
	}
	req.Header.Set("Accept", "application/oauth-authz-req+jwt, application/jwt, application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return "", NewError(ErrorInvalidRequestURI, "request_uri fetch failed | request_uri 抓取失败")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", NewError(ErrorInvalidRequestURI, "request_uri returned a non-200 status | request_uri 返回非 200 状态")
	}
	if !requestObjectContentType(resp.Header.Get("Content-Type")) {
		return "", NewError(ErrorInvalidRequestURI, "request_uri content type is not a request object | request_uri 内容类型不是请求对象")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.config.MaxSize+1))
	if err != nil {
		return "", NewError(ErrorInvalidRequestURI, "request_uri body cannot be read | 无法读取 request_uri 正文")
	}
	if int64(len(body)) > c.config.MaxSize {
		return "", NewError(ErrorInvalidRequestURI, "request_uri body is too large | request_uri 正文过大")
	}
	if len(body) == 0 {
		return "", NewError(ErrorInvalidRequestURI, "request_uri body is empty | request_uri 正文为空")
	}
	c.store(requestURI, string(body))
	return string(body), nil
}

// validateURI applies scheme, host and registration policy. | validateURI 应用方案、主机与注册策略。
func (c *requestURICache) validateURI(client *Client, requestURI string) (*url.URL, error) {
	if strings.TrimSpace(requestURI) == "" || len(requestURI) > c.config.MaxURILength {
		return nil, NewError(ErrorInvalidRequestURI, "request_uri length is invalid | request_uri 长度非法")
	}
	parsed, err := url.Parse(requestURI)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, NewError(ErrorInvalidRequestURI, "request_uri must be an absolute URI | request_uri 必须是绝对 URI")
	}
	loopback := isLoopbackHost(parsed.Hostname())
	switch parsed.Scheme {
	case "https":
	case "http":
		if !loopback || !c.config.AllowLoopback {
			return nil, NewError(ErrorInvalidRequestURI, "request_uri must use https | request_uri 必须使用 https")
		}
	default:
		return nil, NewError(ErrorInvalidRequestURI, "request_uri scheme is not allowed | 不允许 request_uri 方案")
	}
	if ip := net.ParseIP(strings.Trim(parsed.Hostname(), "[]")); ip != nil {
		if loopback && !c.config.AllowLoopback {
			return nil, NewError(ErrorInvalidRequestURI, "loopback request_uri is not allowed | 不允许回环 request_uri")
		}
		if !loopback && (ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
			ip.IsUnspecified() || ip.IsMulticast()) {
			return nil, NewError(ErrorInvalidRequestURI, "non-public request_uri address is not allowed | 不允许非公网 request_uri 地址")
		}
	}
	if client == nil {
		return nil, NewError(ErrorInvalidRequestURI, "request_uri client is unknown | request_uri 客户端未知")
	}
	if c.config.RequireRegistration {
		if !clientAllowsRequestURI(client, requestURI) {
			return nil, NewError(ErrorInvalidRequestURI, "request_uri is not registered | request_uri 未注册")
		}
		return parsed, nil
	}
	if !requestURIHostAllowed(parsed, c.config.AllowedHosts) {
		return nil, NewError(ErrorInvalidRequestURI, "request_uri host is not allowed | 不允许 request_uri 主机")
	}
	return parsed, nil
}

// lookup returns a cached body and evicts expired entries. | lookup 返回缓存正文并清除过期条目。
func (c *requestURICache) lookup(requestURI string) (string, bool) {
	if c.config.CacheTTL <= 0 {
		return "", false
	}
	now := c.now().UTC()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prune(now)
	entry, ok := c.entries[requestURI]
	if !ok || !now.Before(entry.expires) {
		return "", false
	}
	return entry.body, true
}

// store caches a fetched body. | store 缓存已抓取的正文。
func (c *requestURICache) store(requestURI, body string) {
	if c.config.CacheTTL <= 0 {
		return
	}
	now := c.now().UTC()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prune(now)
	if len(c.entries) >= requestObjectCacheCapacity {
		c.evictSoonest()
	}
	c.entries[requestURI] = cachedRequestObject{body: body, expires: now.Add(c.config.CacheTTL)}
}

// prune removes expired entries; the caller holds the mutex. | prune 清除过期条目；调用方持有互斥锁。
func (c *requestURICache) prune(now time.Time) {
	for key, entry := range c.entries {
		if !now.Before(entry.expires) {
			delete(c.entries, key)
		}
	}
	for key, expiry := range c.used {
		if !now.Before(expiry) {
			delete(c.used, key)
		}
	}
}

// evictSoonest removes the entry with the earliest expiry; the caller holds the mutex. | evictSoonest
// 移除最早到期的条目；调用方持有互斥锁。
func (c *requestURICache) evictSoonest() {
	var oldestKey string
	var oldest time.Time
	for key, entry := range c.entries {
		if oldestKey == "" || entry.expires.Before(oldest) {
			oldestKey = key
			oldest = entry.expires
		}
	}
	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

// beginUse records a single-use request URI and reports whether it was fresh. | beginUse 记录一次性
// request URI 并报告是否为首次使用。
func (c *requestURICache) beginUse(requestURI string) bool {
	now := c.now().UTC()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prune(now)
	if _, exists := c.used[requestURI]; exists {
		return false
	}
	if len(c.used) >= requestURISingleUseCapacity {
		c.evictEarliestUse()
	}
	ttl := c.config.CacheTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	c.used[requestURI] = now.Add(ttl)
	return true
}

// evictEarliestUse removes the single-use record with the earliest expiry; the caller holds the
// mutex. | evictEarliestUse 移除最早到期的一次性记录；调用方持有互斥锁。
func (c *requestURICache) evictEarliestUse() {
	var oldestKey string
	var oldest time.Time
	for key, expiry := range c.used {
		if oldestKey == "" || expiry.Before(oldest) {
			oldestKey = key
			oldest = expiry
		}
	}
	if oldestKey != "" {
		delete(c.used, oldestKey)
	}
}

// clientAllowsRequestURI reports whether requestURI is registered for client. | clientAllowsRequestURI
// 报告 requestURI 是否为客户端注册值。
func clientAllowsRequestURI(client *Client, requestURI string) bool {
	if client == nil {
		return false
	}
	for _, registered := range client.RequestURIs {
		if registered == requestURI {
			return true
		}
	}
	return false
}

// requestURIHostAllowed reports whether parsed matches one allowed host. | requestURIHostAllowed
// 报告 parsed 是否匹配一个允许主机。
func requestURIHostAllowed(parsed *url.URL, allowed []string) bool {
	if parsed == nil {
		return false
	}
	for _, entry := range allowed {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "://") {
			candidate, err := url.Parse(entry)
			if err != nil {
				continue
			}
			entry = candidate.Host
		}
		if strings.Contains(entry, ":") {
			if strings.EqualFold(entry, parsed.Host) {
				return true
			}
			continue
		}
		if strings.EqualFold(entry, parsed.Hostname()) {
			return true
		}
	}
	return false
}

// requestObjectContentType accepts the RFC 9101 media type and common generic encodings. |
// requestObjectContentType 接受 RFC 9101 媒体类型与常见通用编码。
func requestObjectContentType(value string) bool {
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(value, ";")[0]))
	switch mediaType {
	case "", "application/oauth-authz-req+jwt", "application/jwt", "application/octet-stream", "text/plain":
		return true
	default:
		return false
	}
}
