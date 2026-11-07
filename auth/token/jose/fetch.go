package jose

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// The default HTTP key set policy. | 默认 HTTP 密钥集策略。
const (
	// DefaultJWKSFetchTTL is how long a fetched key set is served without revalidation. | DefaultJWKSFetchTTL 是获取的密钥集在无需重新校验情况下的服务时长。
	DefaultJWKSFetchTTL = 5 * time.Minute
	// DefaultJWKSMinRefreshInterval bounds how often an unknown kid may force a refresh. | DefaultJWKSMinRefreshInterval 限制未知 kid 触发刷新的最低间隔。
	DefaultJWKSMinRefreshInterval = 30 * time.Second
	// DefaultJWKSMaxBodySize is the largest accepted JWKS response body. | DefaultJWKSMaxBodySize 是接受的最大 JWKS 响应体。
	DefaultJWKSMaxBodySize = 1 << 20
	// DefaultJWKSHTTPTimeout is the timeout of the default HTTP client. | DefaultJWKSHTTPTimeout 是默认 HTTP 客户端的超时。
	DefaultJWKSHTTPTimeout = 15 * time.Second
)

// KeySetSource produces a key set, typically from HTTP. | KeySetSource 生成密钥集，通常来自 HTTP。
type KeySetSource interface {
	// Fetch returns the current key set. | Fetch 返回当前密钥集。
	Fetch(ctx context.Context) (*KeySet, error)
}

// KeySetSourceFunc adapts a function to KeySetSource. | KeySetSourceFunc 把函数适配为
// KeySetSource。
type KeySetSourceFunc func(ctx context.Context) (*KeySet, error)

// Fetch calls f(ctx). | Fetch 调用 f(ctx)。
func (f KeySetSourceFunc) Fetch(ctx context.Context) (*KeySet, error) {
	if f == nil {
		return nil, errs.Detail(ErrInvalidConfig, "nil key set source | 密钥集来源为 nil")
	}
	return f(ctx)
}

// FetcherOptions configures a Fetcher. | FetcherOptions 配置 Fetcher。
type FetcherOptions struct {
	// Client is the HTTP client; nil uses a client with DefaultJWKSHTTPTimeout. | Client 是 HTTP 客户端；为空时使用带 DefaultJWKSHTTPTimeout 的客户端。
	Client *http.Client
	// Cache is the key cache to publish into; nil creates a fresh cache. | Cache 是用于发布的密钥缓存；为空时创建新缓存。
	Cache *Cache
	// CacheTTL is the freshness lifetime; zero uses DefaultJWKSFetchTTL. | CacheTTL 是新鲜度时长；零值使用 DefaultJWKSFetchTTL。
	CacheTTL time.Duration
	// MinRefreshInterval bounds unknown-kid refreshes; zero uses DefaultJWKSMinRefreshInterval. | MinRefreshInterval 限制未知 kid 刷新频率；零值使用 DefaultJWKSMinRefreshInterval。
	MinRefreshInterval time.Duration
	// MaxBodySize caps the response body; zero uses DefaultJWKSMaxBodySize. | MaxBodySize 限制响应体；零值使用 DefaultJWKSMaxBodySize。
	MaxBodySize int64
	// Now overrides the clock; nil uses time.Now. | Now 用于替换时钟；为空时使用 time.Now。
	Now func() time.Time
}

// Fetcher downloads and caches a JWKS document over HTTP. | Fetcher 通过 HTTP 下载并缓存 JWKS 文档。
//
// It supports TTL caching, conditional requests through ETag and Last-Modified, a hard body-size
// limit, and a forced refresh when a token names an unknown kid. A Fetcher is safe for concurrent
// use. | 它支持 TTL 缓存、通过 ETag 与 Last-Modified 的条件请求、硬性正文大小限制，以及在令牌
// 引用未知 kid 时强制刷新。Fetcher 可安全并发使用。
type Fetcher struct {
	client     *http.Client
	cache      *Cache
	url        string
	now        func() time.Time
	ttl        time.Duration
	minRefresh time.Duration
	maxBody    int64

	mu           sync.Mutex
	etag         string
	lastModified string
	fetchedAt    time.Time
	lastAttempt  time.Time
	haveCache    bool
}

// NewFetcher returns a Fetcher for the absolute HTTP or HTTPS JWKS URL. | NewFetcher 返回用于绝对
// HTTP 或 HTTPS JWKS URL 的 Fetcher。
func NewFetcher(rawURL string, opts FetcherOptions) (*Fetcher, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errs.Detail(ErrInvalidConfig, "invalid JWKS URL %[1]q | 非法 JWKS URL %[1]q", rawURL)
	}
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: DefaultJWKSHTTPTimeout}
	}
	cache := opts.Cache
	if cache == nil {
		cache = NewCache()
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	f := &Fetcher{
		client:     client,
		cache:      cache,
		url:        rawURL,
		now:        now,
		ttl:        opts.CacheTTL,
		minRefresh: opts.MinRefreshInterval,
		maxBody:    opts.MaxBodySize,
	}
	if f.ttl <= 0 {
		f.ttl = DefaultJWKSFetchTTL
	}
	if f.minRefresh <= 0 {
		f.minRefresh = DefaultJWKSMinRefreshInterval
	}
	if f.maxBody <= 0 {
		f.maxBody = DefaultJWKSMaxBodySize
	}
	return f, nil
}

// URL returns the configured JWKS endpoint. | URL 返回配置的 JWKS 端点。
func (f *Fetcher) URL() string { return f.url }

// Cache returns the cache the fetcher publishes into. | Cache 返回 Fetcher 发布到的缓存。
func (f *Fetcher) Cache() *Cache { return f.cache }

// Fetch returns the cached set while it is fresh, otherwise revalidates it over HTTP. | Fetch 在
// 缓存新鲜时返回缓存集合，否则通过 HTTP 重新校验。
//
// A 304 response keeps the cached set and refreshes its freshness deadline. | 304 响应保留缓存
// 集合并刷新其新鲜度期限。
func (f *Fetcher) Fetch(ctx context.Context) (*KeySet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetchLocked(ctx, false)
}

// ForceRefresh revalidates the key set over HTTP regardless of the cache TTL. | ForceRefresh 无视
// 缓存 TTL，通过 HTTP 重新校验密钥集。
func (f *Fetcher) ForceRefresh(ctx context.Context) (*KeySet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetchLocked(ctx, true)
}

// Key returns the key named by kid, refreshing once when the kid is unknown. | Key 返回 kid 指定的
// 密钥，在 kid 未知时刷新一次。
//
// A failed refresh still returns a cached key that matches a known kid, so a temporary JWKS
// outage does not invalidate every token. Unknown kids are rate-limited by
// MinRefreshInterval to keep hostile tokens from driving unbounded fetches. | 刷新失败时，若缓存中
// 存在该 kid 指定的密钥，仍返回该密钥，因此短暂的 JWKS 故障不会使所有令牌失效。未知 kid 受
// MinRefreshInterval 限速，避免恶意令牌驱动无界获取。
func (f *Fetcher) Key(ctx context.Context, kid string) (*Key, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	now := f.now()
	if f.haveCache {
		if k, err := f.cache.Get(kid); err == nil {
			if now.Sub(f.fetchedAt) < f.ttl {
				return k, nil
			}
			if _, refreshErr := f.fetchLocked(ctx, true); refreshErr == nil {
				if fresh, err := f.cache.Get(kid); err == nil {
					return fresh, nil
				}
			}
			return k, nil
		}
	}
	if !f.lastAttempt.IsZero() && now.Sub(f.lastAttempt) < f.minRefresh {
		return nil, errs.Detail(ErrKeyNotFound, "kid=%[1]q | kid=%[1]q", kid)
	}
	if _, err := f.fetchLocked(ctx, true); err != nil {
		return nil, err
	}
	return f.cache.Get(kid)
}

// Resolver returns a KeyResolver backed by the fetcher and its unknown-kid refresh. | Resolver
// 返回由 Fetcher 及其未知 kid 刷新支持的 KeyResolver。
func (f *Fetcher) Resolver() KeyResolver {
	return KeyResolverFunc(func(ctx context.Context, header Header) (*Key, error) {
		return f.Key(ctx, header.String("kid"))
	})
}

// fetchLocked performs one conditional GET. The caller must hold f.mu. | fetchLocked 执行一次条件
// GET。调用方必须持有 f.mu。
func (f *Fetcher) fetchLocked(ctx context.Context, force bool) (*KeySet, error) {
	now := f.now()
	if !force && f.haveCache && now.Sub(f.fetchedAt) < f.ttl {
		return f.cache.Snapshot(), nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrFetchFailed, "build JWKS request | 构造 JWKS 请求")
	}
	req.Header.Set("Accept", "application/jwk-set+json, application/json")
	if f.haveCache {
		if f.etag != "" {
			req.Header.Set("If-None-Match", f.etag)
		}
		if f.lastModified != "" {
			req.Header.Set("If-Modified-Since", f.lastModified)
		}
	}
	f.lastAttempt = now
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrFetchFailed, "fetch JWKS | 获取 JWKS")
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusNotModified:
		if !f.haveCache {
			return nil, errs.Detail(ErrFetchFailed, "304 without cached key set | 304 但无缓存密钥集")
		}
		f.fetchedAt = now
		return f.cache.Snapshot(), nil
	case resp.StatusCode != http.StatusOK:
		return nil, errs.Detail(ErrFetchFailed, "status %[1]d | 状态码 %[1]d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, f.maxBody+1))
	if err != nil {
		return nil, errs.WrapDetail(err, ErrFetchFailed, "read JWKS | 读取 JWKS")
	}
	if int64(len(body)) > f.maxBody {
		return nil, errs.Detail(ErrResponseTooLarge, "body exceeds %[1]d bytes | 正文超过 %[1]d 字节", f.maxBody)
	}
	set, err := ParseKeySet(body)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrFetchFailed, "decode JWKS | 解码 JWKS")
	}
	f.cache.Set(set)
	f.etag = resp.Header.Get("ETag")
	f.lastModified = resp.Header.Get("Last-Modified")
	f.fetchedAt = now
	f.haveCache = true
	return set, nil
}
