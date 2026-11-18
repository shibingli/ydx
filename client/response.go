package client

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"

	"github.com/shibingli/ydx/buffpool"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/xml"
)

// defaultResponseLimit is the default in-memory response body cap (4 MiB). | defaultResponseLimit 是默认内存响应正文上限（4 MiB）。
const defaultResponseLimit = 4 << 20

// HopMeta describes one redirect hop. | HopMeta 描述一次重定向跳转。
type HopMeta struct {
	// URL is the logical URL of the hop. | URL 是该跳的逻辑 URL。
	URL string
	// Host is the target host selected for the hop. | Host 是该跳选择的目标 Host。
	Host string
	// Status is the response status code. | Status 是响应状态码。
	Status int
	// CacheHit reports whether the hop was served from cache. | CacheHit 报告该跳是否由缓存服务。
	CacheHit bool
	// Duration is the hop duration. | Duration 是该跳耗时。
	Duration time.Duration
}

// Timings carries optional httptrace phase durations. | Timings 携带可选的 httptrace 阶段耗时。
type Timings struct {
	// DNS is name resolution time. | DNS 是域名解析耗时。
	DNS time.Duration
	// Connect is TCP connect time. | Connect 是 TCP 连接耗时。
	Connect time.Duration
	// TLSHandshake is TLS handshake time. | TLSHandshake 是 TLS 握手耗时。
	TLSHandshake time.Duration
	// TTFB is time to first response byte. | TTFB 是首字节响应耗时。
	TTFB time.Duration
	// Total is the total RoundTrip time. | Total 是 RoundTrip 总耗时。
	Total time.Duration
}

// Meta carries client-side request metadata alongside a response. | Meta 随响应携带客户端侧请求元数据。
type Meta struct {
	// Rule is the matched rule, when any. | Rule 是命中的规则（如有）。
	Rule *Rule
	// Host is the selected host, when any. | Host 是选中的 Host（如有）。
	Host *Host
	// Guard is the guard decision, when a guard ran. | Guard 是守卫决策（如执行过）。
	Guard *GuardDecision
	// Timings carries optional phase timings. | Timings 携带可选的阶段耗时。
	Timings Timings
	// Mirrors records the synchronous shadow snapshot. | Mirrors 记录同步影子结果快照。
	Mirrors []MirrorResult
	// MirrorResults safely observes asynchronous shadows; nil without mirroring. | MirrorResults 安全观察异步镜像；无镜像时为 nil。
	MirrorResults *MirrorResults
	// Hops records the redirect chain in order. | Hops 按顺序记录重定向链。
	Hops []HopMeta
	// Params are the captured path parameters. | Params 是路径参数捕获。
	Params Params

	// hopInline backs the first redirect hop without an allocation. | hopInline 为首次重定向提供无分配存储。
	hopInline [1]HopMeta
	// urlHint avoids rebuilding the first logical hop URL. | urlHint 避免重建首次逻辑跳 URL。
	urlHint string
	// Attempts is the number of upstream attempts for the final hop. | Attempts 是最终一跳的上游尝试次数。
	Attempts int
	// BytesSent is the request body bytes written. | BytesSent 是写出的请求正文字节数。
	BytesSent int64
	// BytesRead is the response body bytes read. | BytesRead 是读取的响应正文字节数。
	BytesRead int64

	// CacheHit reports whether the response came from cache. | CacheHit 报告响应是否来自缓存。
	CacheHit bool
	// Coalesced reports whether the response was shared by request coalescing. | Coalesced 报告响应是否由请求合并共享。
	Coalesced bool
}

// metaKey is the context key carrying the per-call Meta pointer. | metaKey 是携带每次调用 Meta 指针的 context 键。
type metaKey struct{}

// metaFromContext returns the Meta pointer stored by Send or DoWithMeta. | metaFromContext 返回 Send 或 DoWithMeta 存入的 Meta 指针。
func metaFromContext(ctx context.Context) *Meta {
	if ctx == nil {
		return nil
	}
	meta, _ := ctx.Value(metaKey{}).(*Meta)
	return meta
}

// Response wraps http.Response with client metadata and body helpers. | Response 用客户端元数据与正文辅助方法包装 http.Response。
type Response struct {
	*http.Response
	Meta Meta
}

// BytesLimit reads and closes the body, failing when it exceeds n bytes. | BytesLimit 读取并关闭正文，超过 n 字节时失败。
func (r *Response) BytesLimit(n int64) ([]byte, error) {
	if r == nil || r.Response == nil || r.Body == nil {
		return nil, ErrBodyConsumed
	}
	if n <= 0 {
		n = defaultResponseLimit
	}
	body := r.Body
	limit := n + 1
	if limit <= 0 {
		limit = n
	}
	var data []byte
	var err error
	maxInt := int64(^uint(0) >> 1)
	if r.ContentLength > 0 && r.ContentLength <= n && r.ContentLength <= maxInt {
		var buffer bytes.Buffer
		buffer.Grow(int(r.ContentLength))
		_, err = io.Copy(&buffer, io.LimitReader(body, limit))
		data = buffer.Bytes()
	} else {
		data, err = io.ReadAll(io.LimitReader(body, limit))
	}
	r.Body = nil
	_ = body.Close()
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > n {
		return nil, errs.Detail(ErrResponseTooLarge, "limit %d bytes | 上限 %d 字节", n, n)
	}
	return data, nil
}

// Bytes reads and closes the body with the default limit. | Bytes 以默认上限读取并关闭正文。
func (r *Response) Bytes() ([]byte, error) {
	return r.BytesLimit(defaultResponseLimit)
}

// JSON decodes the body as JSON. | JSON 把正文按 JSON 解码。
func (r *Response) JSON(v any) error {
	data, err := r.Bytes()
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// XML decodes the body as XML. | XML 把正文按 XML 解码。
func (r *Response) XML(v any) error {
	data, err := r.Bytes()
	if err != nil {
		return err
	}
	return xml.Unmarshal(data, v)
}

// String reads the body as a string. | String 把正文读取为字符串。
func (r *Response) String() (string, error) {
	data, err := r.Bytes()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// SaveTo streams the body into w and closes it. | SaveTo 把正文流式写入 w 并关闭。
func (r *Response) SaveTo(w io.Writer) (int64, error) {
	if r == nil || r.Response == nil || r.Body == nil {
		return 0, ErrBodyConsumed
	}
	buf := buffpool.Get(32 << 10)
	buf = buf[:cap(buf)]
	defer buffpool.Put(buf)
	n, err := io.CopyBuffer(w, r.Body, buf)
	_ = r.Body.Close()
	r.Body = nil
	return n, err
}

// Discard drains and closes the body. | Discard 排空并关闭正文。
func (r *Response) Discard() error {
	if r == nil || r.Response == nil || r.Body == nil {
		return nil
	}
	_, err := io.Copy(io.Discard, r.Body)
	_ = r.Body.Close()
	r.Body = nil
	return err
}
