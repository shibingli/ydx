package client

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
	// CacheStores is the number of responses stored in cache. | CacheStores 是写入缓存的响应数。
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
}
