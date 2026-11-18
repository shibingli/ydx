package client

import (
	"bytes"
	"context"
	"hash/fnv"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/errs"
)

// CacheEntry is one immutable cached response variant. | CacheEntry 是一个不可变的缓存响应变体。
type CacheEntry struct {
	// Expires is the absolute expiry time; zero means never. | Expires 是绝对过期时间；零值表示不过期。
	Expires time.Time
	// Header is the stored response header. | Header 是存储的响应头。
	Header http.Header
	// VaryValues records the request header values named by Vary. | VaryValues 记录 Vary 指定的请求头值。
	VaryValues map[string]string
	// Status is the response status line. | Status 是响应状态行。
	Status string
	// Proto is the response protocol line. | Proto 是响应协议行。
	Proto string
	// Body is the stored response body. | Body 是存储的响应正文。
	Body []byte
	// StatusCode is the response status code. | StatusCode 是响应状态码。
	StatusCode int
	// ProtoMajor is the major protocol version. | ProtoMajor 是协议主版本。
	ProtoMajor int
	// ProtoMinor is the minor protocol version. | ProtoMinor 是协议次版本。
	ProtoMinor int
	// Uncompressed reports whether the response body was transparently decompressed. | Uncompressed 报告响应正文是否被透明解压。
	Uncompressed bool
}

// matches reports whether the request agrees with the stored Vary values. | matches 报告请求是否与存储的 Vary 值一致。
func (e *CacheEntry) matches(req *http.Request) bool {
	if e == nil || req == nil {
		return false
	}
	for name, want := range e.VaryValues {
		if headerValue(req.Header, name) != want {
			return false
		}
	}
	return true
}

// CacheStats is a snapshot of store counters. | CacheStats 是存储计数器快照。
type CacheStats struct {
	// Hits is the number of served cache entries. | Hits 是命中缓存的次数。
	Hits uint64
	// Misses is the number of lookup misses and expired entries. | Misses 是未命中与过期次数。
	Misses uint64
	// Stores is the number of accepted store writes. | Stores 是接受的写入次数。
	Stores uint64
	// Evictions is the number of capacity evictions. | Evictions 是容量驱逐次数。
	Evictions uint64
}

// Store is the response cache backend contract. | Store 是响应缓存后端契约。
type Store interface {
	// Get returns an entry when present and unexpired. | Get 在存在且未过期时返回条目。
	Get(key string) (*CacheEntry, bool)
	// Set stores an entry, taking ownership of its body. | Set 存储条目并接管其正文所有权。
	Set(key string, entry *CacheEntry)
	// Delete removes one entry. | Delete 删除单个条目。
	Delete(key string)
	// Stats returns point-in-time counters. | Stats 返回时间点计数器。
	Stats() CacheStats
	// Close stops background work. | Close 停止后台工作。
	Close() error
}

// MemoryOptions configures the built-in memory store. | MemoryOptions 配置内置内存存储。
type MemoryOptions struct {
	// MaxBytes is the total byte budget; <=0 means 64 MiB. | MaxBytes 是总字节预算；<=0 表示 64 MiB。
	MaxBytes int64
	// MaxEntryBytes is the per-entry cap; <=0 means 4 MiB. | MaxEntryBytes 是单条上限；<=0 表示 4 MiB。
	MaxEntryBytes int64
	// Shards is the shard count; <=0 means 16. | Shards 是分片数；<=0 表示 16。
	Shards int
	// CleanupInterval is the sweep period; <=0 means 1s. | CleanupInterval 是清扫周期；<=0 表示 1s。
	CleanupInterval time.Duration
}

// cacheItem is one intrusive LRU node. | cacheItem 是一个侵入式 LRU 节点。
type cacheItem struct {
	entry      *CacheEntry
	prev, next *cacheItem
	key        string
	size       int64
}

// cacheShard is one independently locked LRU shard. | cacheShard 是独立加锁的 LRU 分片。
type cacheShard struct {
	items    map[string]*cacheItem
	head     *cacheItem
	tail     *cacheItem
	used     int64
	capacity int64
	mu       sync.Mutex
}

// MemoryStore is the built-in sharded LRU + TTL store. | MemoryStore 是内置分片 LRU + TTL 存储。
type MemoryStore struct {
	stop      chan struct{}
	shards    []*cacheShard
	wg        sync.WaitGroup
	maxEntry  int64
	hits      atomic.Uint64
	misses    atomic.Uint64
	stores    atomic.Uint64
	evictions atomic.Uint64
	closeOnce sync.Once
}

// NewMemoryStore builds a memory store with defaults for zero fields. | NewMemoryStore 为零字段填充默认值后构建内存存储。
func NewMemoryStore(o MemoryOptions) (*MemoryStore, error) {
	if o.MaxBytes <= 0 {
		o.MaxBytes = 64 << 20
	}
	if o.Shards <= 0 {
		o.Shards = 16
	}
	if o.MaxEntryBytes <= 0 {
		o.MaxEntryBytes = 4 << 20
	}
	if o.MaxEntryBytes > o.MaxBytes {
		o.MaxEntryBytes = o.MaxBytes
	}
	if o.CleanupInterval <= 0 {
		o.CleanupInterval = time.Second
	}
	if o.MaxBytes < 64 || o.MaxEntryBytes < 64 {
		return nil, errs.Detail(ErrInvalidConfig, "cache limits too small | 缓存上限过小")
	}
	shardCapacity := o.MaxBytes / int64(o.Shards)
	if shardCapacity < o.MaxEntryBytes {
		o.MaxEntryBytes = shardCapacity
	}
	store := &MemoryStore{
		shards:   make([]*cacheShard, o.Shards),
		maxEntry: o.MaxEntryBytes,
		stop:     make(chan struct{}),
	}
	for i := range store.shards {
		store.shards[i] = &cacheShard{
			items:    make(map[string]*cacheItem),
			capacity: shardCapacity,
		}
	}
	store.wg.Add(1)
	go store.janitor(o.CleanupInterval)
	return store, nil
}

// Get returns a live entry and marks it most recently used. | Get 返回存活条目并标记为最近使用。
func (s *MemoryStore) Get(key string) (*CacheEntry, bool) {
	if s == nil {
		return nil, false
	}
	shard := s.shardFor(key)
	shard.mu.Lock()
	item := shard.items[key]
	if item == nil {
		shard.mu.Unlock()
		s.misses.Add(1)
		return nil, false
	}
	if !item.entry.Expires.IsZero() && time.Now().After(item.entry.Expires) {
		shard.remove(item)
		shard.mu.Unlock()
		s.misses.Add(1)
		return nil, false
	}
	shard.touch(item)
	shard.mu.Unlock()
	s.hits.Add(1)
	return item.entry, true
}

// Set stores an entry and evicts LRU entries until it fits. | Set 存储条目并按需驱逐 LRU 条目。
func (s *MemoryStore) Set(key string, entry *CacheEntry) {
	if s == nil || entry == nil {
		return
	}
	size := cacheEntrySize(key, entry)
	if size > s.maxEntry {
		return
	}
	shard := s.shardFor(key)
	if size > shard.capacity {
		return
	}
	shard.mu.Lock()
	if old := shard.items[key]; old != nil {
		shard.remove(old)
	}
	item := &cacheItem{key: key, entry: entry, size: size}
	shard.items[key] = item
	shard.pushFront(item)
	shard.used += size
	for shard.used > shard.capacity && shard.tail != nil {
		shard.remove(shard.tail)
		s.evictions.Add(1)
	}
	shard.mu.Unlock()
	s.stores.Add(1)
}

// Delete removes one entry. | Delete 删除单个条目。
func (s *MemoryStore) Delete(key string) {
	if s == nil {
		return
	}
	shard := s.shardFor(key)
	shard.mu.Lock()
	if item := shard.items[key]; item != nil {
		shard.remove(item)
	}
	shard.mu.Unlock()
}

// Stats returns the store counters. | Stats 返回存储计数器。
func (s *MemoryStore) Stats() CacheStats {
	if s == nil {
		return CacheStats{}
	}
	return CacheStats{
		Hits:      s.hits.Load(),
		Misses:    s.misses.Load(),
		Stores:    s.stores.Load(),
		Evictions: s.evictions.Load(),
	}
}

// Close stops the janitor and releases entries. | Close 停止清扫器并释放条目。
func (s *MemoryStore) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		close(s.stop)
		s.wg.Wait()
		for _, shard := range s.shards {
			shard.mu.Lock()
			shard.items = make(map[string]*cacheItem)
			shard.head = nil
			shard.tail = nil
			shard.used = 0
			shard.mu.Unlock()
		}
	})
	return nil
}

// janitor periodically removes expired entries. | janitor 周期性删除过期条目。
func (s *MemoryStore) janitor(interval time.Duration) {
	defer s.wg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			now := time.Now()
			for _, shard := range s.shards {
				shard.mu.Lock()
				for _, item := range shard.items {
					if !item.entry.Expires.IsZero() && now.After(item.entry.Expires) {
						shard.remove(item)
					}
				}
				shard.mu.Unlock()
			}
		}
	}
}

// shardFor returns the shard for key. | shardFor 返回 key 对应的分片。
func (s *MemoryStore) shardFor(key string) *cacheShard {
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(key))
	return s.shards[hash.Sum64()%uint64(len(s.shards))]
}

// cacheEntrySize estimates the accounted bytes of one entry. | cacheEntrySize 估算单条目的计费字节。
func cacheEntrySize(key string, entry *CacheEntry) int64 {
	size := int64(len(key) + len(entry.Body) + 32)
	for name, values := range entry.Header {
		size += int64(len(name))
		for _, value := range values {
			size += int64(len(value))
		}
	}
	for name, value := range entry.VaryValues {
		size += int64(len(name) + len(value))
	}
	return size
}

// pushFront links item at the MRU position. | pushFront 把条目链接到 MRU 位置。
func (s *cacheShard) pushFront(item *cacheItem) {
	item.prev = nil
	item.next = s.head
	if s.head != nil {
		s.head.prev = item
	}
	s.head = item
	if s.tail == nil {
		s.tail = item
	}
}

// touch moves item to the MRU position. | touch 把条目移到 MRU 位置。
func (s *cacheShard) touch(item *cacheItem) {
	if item == s.head {
		return
	}
	s.unlink(item)
	s.pushFront(item)
}

// remove unlinks and deletes item. | remove 解除链接并删除条目。
func (s *cacheShard) remove(item *cacheItem) {
	s.unlink(item)
	delete(s.items, item.key)
	s.used -= item.size
}

// unlink removes item from the list without deleting it from the map. | unlink 从链表移除条目但不删除 map 键。
func (s *cacheShard) unlink(item *cacheItem) {
	if item.prev != nil {
		item.prev.next = item.next
	} else {
		s.head = item.next
	}
	if item.next != nil {
		item.next.prev = item.prev
	} else {
		s.tail = item.prev
	}
	item.prev = nil
	item.next = nil
}

// CachePolicy configures response caching for one rule or the client. | CachePolicy 为单条规则或客户端配置响应缓存。
type CachePolicy struct {
	// Store overrides the engine store. | Store 覆盖引擎存储。
	Store Store
	// KeyFunc overrides the cache key. | KeyFunc 覆盖缓存键。
	KeyFunc func(*http.Request) string
	// Methods lists cacheable methods; nil means GET/HEAD. | Methods 列出可缓存方法；nil 表示 GET/HEAD。
	Methods []string
	// StatusCodes lists cacheable statuses; nil means 200/203/204. | StatusCodes 列出可缓存状态码；nil 表示 200/203/204。
	StatusCodes []int
	// Vary lists extra request headers that distinguish variants. | Vary 列出区分变体的额外请求头。
	Vary []string
	// TTL is the explicit entry lifetime; >0 wins, 0 uses headers, <0 disables. | TTL 是显式条目寿命；>0 优先，0 使用响应头，<0 禁用。
	TTL time.Duration
	// MaxBodyBytes caps the buffered response body; <=0 means 4 MiB. | MaxBodyBytes 限制缓冲的响应正文；<=0 表示 4 MiB。
	MaxBodyBytes int64
	// IgnoreHeaders disables Cache-Control/Expires handling. | IgnoreHeaders 禁用 Cache-Control/Expires 处理。
	IgnoreHeaders bool
	// AllowSensitive permits caching requests/responses with credentials or cookies. | AllowSensitive 允许缓存带凭据或 Cookie 的请求/响应。
	AllowSensitive bool
}

// withDefaults fills zero-value cache policy fields. | withDefaults 填充零值缓存策略字段。
func (p CachePolicy) withDefaults() CachePolicy {
	if p.Methods == nil {
		p.Methods = []string{http.MethodGet, http.MethodHead}
	}
	if p.StatusCodes == nil {
		p.StatusCodes = []int{http.StatusOK, http.StatusNonAuthoritativeInfo, http.StatusNoContent}
	}
	if p.MaxBodyBytes <= 0 {
		p.MaxBodyBytes = 4 << 20
	}
	return p
}

// WithCache sets the client-wide cache policy. | WithCache 设置客户端级缓存策略。
func WithCache(policy CachePolicy) Option {
	return func(o *options) error {
		o.Cache = &policy
		return nil
	}
}

// WithCacheStore sets the client-wide cache backend. | WithCacheStore 设置客户端级缓存后端。
func WithCacheStore(store Store) Option {
	return func(o *options) error {
		if store == nil {
			return errs.Detail(ErrInvalidConfig, "nil cache store | 空缓存存储")
		}
		o.CacheStore = store
		return nil
	}
}

// multiReadCloser restores a partially read body as a stream. | multiReadCloser 把部分读取的正文还原为流。
type multiReadCloser struct {
	io.Reader
	closer io.Closer
}

// Close closes the underlying body. | Close 关闭底层正文。
func (m *multiReadCloser) Close() error {
	if m.closer == nil {
		return nil
	}
	return m.closer.Close()
}

// cacheTTL resolves the entry lifetime from policy and response headers. | cacheTTL 从策略与响应头解析条目寿命。
func cacheTTL(header http.Header, policy CachePolicy) (time.Duration, bool) {
	if !policy.IgnoreHeaders {
		control := strings.ToLower(header.Get("Cache-Control"))
		if strings.Contains(control, "no-store") || strings.Contains(control, "private") {
			return 0, false
		}
	}
	if policy.TTL > 0 {
		return policy.TTL, true
	}
	if policy.TTL < 0 || policy.IgnoreHeaders {
		return 0, false
	}
	control := strings.ToLower(header.Get("Cache-Control"))
	for _, part := range strings.Split(control, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "max-age=") {
			if seconds, err := strconv.Atoi(strings.TrimPrefix(part, "max-age=")); err == nil && seconds > 0 {
				return time.Duration(seconds) * time.Second, true
			}
		}
	}
	if expires := header.Get("Expires"); expires != "" {
		if when, err := http.ParseTime(expires); err == nil {
			if delay := time.Until(when); delay > 0 {
				return delay, true
			}
		}
	}
	return 0, false
}

// varyValues records the request values named by Vary and policy extras. | varyValues 记录 Vary 与策略额外项指定的请求值。
func varyValues(respHeader http.Header, req *http.Request, extra []string) (map[string]string, bool) {
	names := append([]string(nil), extra...)
	for _, value := range respHeader.Values("Vary") {
		for _, name := range strings.Split(value, ",") {
			name = strings.TrimSpace(name)
			if name == "*" {
				return nil, false
			}
			if name != "" {
				names = append(names, name)
			}
		}
	}
	if len(names) == 0 {
		return nil, true
	}
	values := make(map[string]string, len(names))
	for _, name := range names {
		canonical := http.CanonicalHeaderKey(name)
		values[canonical] = headerValue(req.Header, canonical)
	}
	return values, true
}

// cacheBypassKey marks a context that must bypass reads and writes. | cacheBypassKey 标记必须绕过读写的 context。
type cacheBypassKey struct{}

// WithoutCache returns a context that bypasses response caching. | WithoutCache 返回绕过响应缓存的 context。
func WithoutCache(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, cacheBypassKey{}, true)
}

// cacheBypassed reports whether ctx disables caching. | cacheBypassed 报告 ctx 是否禁用缓存。
func cacheBypassed(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	value, _ := ctx.Value(cacheBypassKey{}).(bool)
	return value
}

// ensureCacheStore returns the configured store or lazily creates the memory store. | ensureCacheStore 返回配置的存储或惰性创建内存存储。
func (e *engine) ensureCacheStore() Store {
	if e.opts.CacheStore != nil {
		return e.opts.CacheStore
	}
	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()
	if e.closed.Load() {
		return nil
	}
	if e.cacheStore != nil {
		return e.cacheStore
	}
	store, err := NewMemoryStore(MemoryOptions{})
	if err != nil {
		return nil
	}
	e.cacheStore = store
	e.ownsCache = true
	return store
}

// cacheFor resolves the rule or client cache policy and its backend. | cacheFor 解析规则或客户端缓存策略及其后端。
func (e *engine) cacheFor(rule *Rule) (CachePolicy, Store, bool) {
	var policy *CachePolicy
	if rule != nil && rule.Cache != nil {
		policy = rule.Cache
	} else if e.opts.Cache != nil {
		policy = e.opts.Cache
	}
	if policy == nil {
		return CachePolicy{}, nil, false
	}
	resolved := policy.withDefaults()
	store := resolved.Store
	if store == nil {
		store = e.ensureCacheStore()
	}
	if store == nil {
		return CachePolicy{}, nil, false
	}
	return resolved, store, true
}

// cacheReadable reports whether a request may read the cache. | cacheReadable 报告请求是否可读缓存。
func cacheReadable(req *http.Request, policy CachePolicy) bool {
	if req == nil || req.URL == nil || cacheBypassed(req.Context()) {
		return false
	}
	allowed := false
	for _, method := range policy.Methods {
		if method == req.Method {
			allowed = true
			break
		}
	}
	if !allowed {
		return false
	}
	control := strings.ToLower(req.Header.Get("Cache-Control"))
	if strings.Contains(control, "no-store") || strings.Contains(control, "no-cache") {
		return false
	}
	if strings.Contains(strings.ToLower(req.Header.Get("Accept")), "text/event-stream") {
		return false
	}
	if conditionalRequest(req) {
		return false
	}
	if !policy.AllowSensitive {
		if req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" {
			return false
		}
	}
	return true
}

// cacheWritable reports whether a response may be stored for this request. | cacheWritable 报告该请求的响应是否可写入缓存。
func cacheWritable(req *http.Request, policy CachePolicy) bool {
	if req == nil || req.URL == nil || cacheBypassed(req.Context()) {
		return false
	}
	allowed := false
	for _, method := range policy.Methods {
		if method == req.Method {
			allowed = true
			break
		}
	}
	if !allowed || strings.Contains(strings.ToLower(req.Header.Get("Cache-Control")), "no-store") ||
		strings.Contains(strings.ToLower(req.Header.Get("Accept")), "text/event-stream") ||
		conditionalRequest(req) {
		return false
	}
	if !policy.AllowSensitive {
		if req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" {
			return false
		}
	}
	return true
}

// cacheableStatus reports whether status is listed by the policy. | cacheableStatus 报告状态码是否在策略列表中。
func cacheableStatus(policy CachePolicy, status int) bool {
	for _, candidate := range policy.StatusCodes {
		if candidate == status {
			return true
		}
	}
	return false
}

// storeCacheResponse buffers and stores a cacheable response; oversized or
// errored bodies are restored as a stream. | storeCacheResponse 缓冲并存储可缓存响应；超限或
// 出错的正文会还原为流。
func (e *engine) storeCacheResponse(resp *http.Response, req *http.Request, key string, policy CachePolicy, store Store) {
	if resp == nil || resp.Body == nil || isEventStream(resp.Header) || !cacheWritable(req, policy) {
		return
	}
	if !policy.AllowSensitive && resp.Header.Get("Set-Cookie") != "" {
		return
	}
	vary, ok := varyValues(resp.Header, req, policy.Vary)
	if !ok {
		return
	}
	ttl, ok := cacheTTL(resp.Header, policy)
	if !ok || ttl <= 0 {
		return
	}
	max := policy.MaxBodyBytes
	data, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		resp.Body = &multiReadCloser{Reader: io.MultiReader(bytes.NewReader(data), resp.Body), closer: resp.Body}
		return
	}
	if int64(len(data)) > max {
		resp.Body = &multiReadCloser{Reader: io.MultiReader(bytes.NewReader(data), resp.Body), closer: resp.Body}
		return
	}
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(data))
	resp.TransferEncoding = nil
	resp.Header.Del("Transfer-Encoding")
	header := resp.Header.Clone()
	if req.Method == http.MethodHead {
		if n, parseErr := strconv.ParseInt(header.Get("Content-Length"), 10, 64); parseErr == nil {
			resp.ContentLength = n
		}
	} else {
		resp.ContentLength = int64(len(data))
		header.Set("Content-Length", strconv.Itoa(len(data)))
	}
	store.Set(key, &CacheEntry{
		Status:       resp.Status,
		StatusCode:   resp.StatusCode,
		Proto:        resp.Proto,
		ProtoMajor:   resp.ProtoMajor,
		ProtoMinor:   resp.ProtoMinor,
		Header:       header,
		Body:         data,
		Expires:      time.Now().Add(ttl),
		VaryValues:   vary,
		Uncompressed: resp.Uncompressed,
	})
	e.counters.cacheStores.Add(1)
	if e.hooks.OnCacheStore != nil {
		_ = callHook(func() error {
			e.hooks.OnCacheStore(req.Context(), req, int64(len(data)))
			return nil
		})
	}
}

// cachedResponse materializes a cached entry as a fresh response. | cachedResponse 把缓存条目物化为全新响应。
func cachedResponse(req *http.Request, entry *CacheEntry) *http.Response {
	header := entry.Header.Clone()
	contentLength := int64(len(entry.Body))
	if req.Method == http.MethodHead || header.Get("Content-Length") != "" {
		if n, err := strconv.ParseInt(header.Get("Content-Length"), 10, 64); err == nil {
			contentLength = n
		}
	}
	return &http.Response{
		Status:        entry.Status,
		StatusCode:    entry.StatusCode,
		Proto:         entry.Proto,
		ProtoMajor:    entry.ProtoMajor,
		ProtoMinor:    entry.ProtoMinor,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(entry.Body)),
		ContentLength: contentLength,
		Request:       req,
		Uncompressed:  entry.Uncompressed,
	}
}
