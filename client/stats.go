package client

import "sync/atomic"

// counters is the engine's atomic counter set. | counters 是引擎的原子计数器集合。
type counters struct {
	requests      atomic.Uint64
	responses     atomic.Uint64
	errors        atomic.Uint64
	retries       atomic.Uint64
	cacheHits     atomic.Uint64
	cacheMisses   atomic.Uint64
	cacheStores   atomic.Uint64
	coalesced     atomic.Uint64
	mirrors       atomic.Uint64
	mirrorErrors  atomic.Uint64
	blocked       atomic.Uint64
	sseSessions   atomic.Uint64
	sseEvents     atomic.Uint64
	bytesSent     atomic.Uint64
	bytesReceived atomic.Uint64
	tlsInsecure   atomic.Uint64
	inflight      atomic.Int64
}

// Stats returns a point-in-time snapshot of client counters. | Stats 返回客户端计数器的时间点快照。
func (c *Client) Stats() Stats {
	if c == nil || c.engine == nil {
		return Stats{}
	}
	e := c.engine
	out := Stats{
		Requests:      e.counters.requests.Load(),
		Responses:     e.counters.responses.Load(),
		Errors:        e.counters.errors.Load(),
		Retries:       e.counters.retries.Load(),
		CacheHits:     e.counters.cacheHits.Load(),
		CacheMisses:   e.counters.cacheMisses.Load(),
		CacheStores:   e.counters.cacheStores.Load(),
		Coalesced:     e.counters.coalesced.Load(),
		Mirrors:       e.counters.mirrors.Load(),
		MirrorErrors:  e.counters.mirrorErrors.Load(),
		MirrorDrops:   e.mirrorDrops.Load(),
		Blocked:       e.counters.blocked.Load(),
		SSESessions:   e.counters.sseSessions.Load(),
		SSEEvents:     e.counters.sseEvents.Load(),
		BytesSent:     e.counters.bytesSent.Load(),
		BytesReceived: e.counters.bytesReceived.Load(),
		Inflight:      uint64(e.counters.inflight.Load()),
		TLSInsecure:   e.counters.tlsInsecure.Load(),
	}
	e.cacheMu.RLock()
	store := e.cacheStore
	e.cacheMu.RUnlock()
	if store != nil {
		out.CacheEvictions = store.Stats().Evictions
	}
	if hosts := e.hosts.Load(); hosts != nil {
		out.FailOpen = hosts.FailOpen()
	}
	return out
}

// HostStats returns a point-in-time snapshot of the default host pool. | HostStats 返回默认 Host 池的时间点快照。
func (c *Client) HostStats() []HostStats {
	if c == nil || c.engine == nil {
		return nil
	}
	hosts := c.engine.hosts.Load()
	if hosts == nil {
		return nil
	}
	return hosts.Stats()
}

// Stats is a point-in-time view of client counters. | Stats 是客户端计数器的时间点视图。
type Stats struct {
	// Requests is the number of accepted requests. | Requests 是已接受的请求数。
	Requests uint64
	// Responses is the number of completed responses. | Responses 是已完成的响应数。
	Responses uint64
	// Errors is the number of failed requests. | Errors 是失败请求数。
	Errors uint64
	// Retries is the number of retry attempts. | Retries 是重试尝试数。
	Retries uint64
	// CacheHits is the number of cache hits. | CacheHits 是缓存命中数。
	CacheHits uint64
	// CacheMisses is the number of cache misses. | CacheMisses 是缓存未命中数。
	CacheMisses uint64
	// CacheStores is the number of responses offered to the cache store; a custom
	// or size-limited store may still reject an entry. | CacheStores 是提交给缓存
	// 存储的响应数；自定义或受限存储仍可能拒绝条目。
	CacheStores uint64
	// CacheEvictions is the number of evicted cache entries. | CacheEvictions 是被驱逐的缓存条目数。
	CacheEvictions uint64
	// Coalesced is the number of requests served by request coalescing. | Coalesced 是由请求合并服务的请求数。
	Coalesced uint64
	// Mirrors is the number of mirrored requests scheduled. | Mirrors 是已调度的镜像请求数。
	Mirrors uint64
	// MirrorErrors is the number of failed mirror requests. | MirrorErrors 是失败的镜像请求数。
	MirrorErrors uint64
	// MirrorDrops is the number of dropped mirror/tee payloads. | MirrorDrops 是被丢弃的镜像/tee 载荷数。
	MirrorDrops uint64
	// Blocked is the number of requests rejected by guards. | Blocked 是被守卫拒绝的请求数。
	Blocked uint64
	// SSESessions is the number of SSE streams opened. | SSESessions 是打开的 SSE 流数。
	SSESessions uint64
	// SSEEvents is the number of parsed SSE events. | SSEEvents 是解析的 SSE 事件数。
	SSEEvents uint64
	// BytesSent is the number of request body bytes written. | BytesSent 是写出的请求正文字节数。
	BytesSent uint64
	// BytesReceived is the number of response body bytes read. | BytesReceived 是读取的响应正文字节数。
	BytesReceived uint64
	// Inflight is the number of requests currently in flight. | Inflight 是当前在途请求数。
	Inflight uint64
	// FailOpen is the number of host selections that fell back to unhealthy hosts. | FailOpen 是回退到不健康 Host 的次数。
	FailOpen uint64
	// TLSInsecure is the number of TLS states built with InsecureSkipVerify. | TLSInsecure 是以 InsecureSkipVerify 构建的 TLS 状态数。
	TLSInsecure uint64
}
