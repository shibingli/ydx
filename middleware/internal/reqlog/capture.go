package reqlog

import (
	"io"
	"net/http"
	"sync"

	"github.com/shibingli/ydx/buffpool"
	"github.com/shibingli/ydx/router"
)

// capturePool recycles the capture wrapper, removing one allocation per request. |
// capturePool 复用捕获包装器，消除每请求一次分配。
//
// The wrapper is returned only after its fields have been read for the log record and the
// context has been detached from it; no reference survives the request, so reuse cannot leak
// status or byte counts across requests. | 只有日志记录读完其字段、且上下文已与其解绑之后，
// 包装器才会被归还；请求结束后不再存在引用，因此复用不会让状态码或字节数跨请求泄漏。
var capturePool = sync.Pool{New: func() any { return new(Capture) }}

// Capture counts the response bytes and remembers the status code. | Capture 统计响应字节数并
// 记录状态码。
//
// It is installed by Begin and returned by End; a Capture must not be used after End. |
// 它由 Begin 安装、由 End 归还；End 之后不得再使用该 Capture。
type Capture struct {
	http.ResponseWriter
	status int
	bytes  int64
}

// Begin installs a pooled capture around c.Writer and returns it. | Begin 在 c.Writer 上安装
// 池化捕获器并返回。
//
// The caller must always call End(c, capture), including on the panic path, so the context
// and the pool never retain request state. | 调用方必须始终调用 End(c, capture)，panic 路径也
// 不例外，使上下文与池都不会保留请求状态。
func Begin(c *router.Ctx) *Capture {
	cap := capturePool.Get().(*Capture)
	cap.ResponseWriter = c.Writer
	cap.status = 0
	cap.bytes = 0
	c.Writer = cap
	return cap
}

// End restores c.Writer and returns the capture to the pool. | End 恢复 c.Writer 并把捕获器
// 归还池。
func End(c *router.Ctx, cap *Capture) {
	if cap == nil {
		return
	}
	c.Writer = cap.ResponseWriter
	cap.ResponseWriter = nil
	cap.status = 0
	cap.bytes = 0
	capturePool.Put(cap)
}

// Status returns the recorded status code, or 0 when nothing has been written. |
// Status 返回已记录的状态码；尚未写出时返回 0。
func (c *Capture) Status() int { return c.status }

// Bytes returns the recorded response body length. | Bytes 返回已记录的响应正文字节数。
func (c *Capture) Bytes() int64 { return c.bytes }

// WriteHeader records the status code before delegating. | WriteHeader 记录状态码后转发。
func (c *Capture) WriteHeader(code int) {
	if c.status == 0 {
		c.status = code
	}
	c.ResponseWriter.WriteHeader(code)
}

// Write counts the written bytes. | Write 累加已写出的字节数。
func (c *Capture) Write(p []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	n, err := c.ResponseWriter.Write(p)
	c.bytes += int64(n)
	return n, err
}

// ReadFrom counts bytes copied through io.ReaderFrom, so sendfile-backed paths keep working
// through the wrapper: io.Copy of an *os.File, http.ServeContent ranges and Ctx.Download all
// check for ReaderFrom before falling back to a buffer. | ReadFrom 统计经 io.ReaderFrom 拷贝的
// 字节数，使 sendfile 路径穿过包装器后仍然有效：io.Copy 文件、http.ServeContent 的区间响应与
// Ctx.Download 都会先检查 ReaderFrom，再退回缓冲拷贝。
func (c *Capture) ReadFrom(r io.Reader) (int64, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	if rf, ok := c.ResponseWriter.(io.ReaderFrom); ok {
		n, err := rf.ReadFrom(r)
		c.bytes += n
		return n, err
	}
	buf := bufpool.Get(32 << 10)
	buf = buf[:cap(buf)] // buffpool returns length 0; CopyBuffer panics on an empty buffer | buffpool 返回长度为 0；空缓冲会让 CopyBuffer panic
	defer bufpool.Put(buf)
	n, err := io.CopyBuffer(c.ResponseWriter, r, buf)
	c.bytes += n
	return n, err
}

// Flush implements http.Flusher so streaming responses keep working. | Flush 实现 http.Flusher，
// 保证流式响应不受影响。
func (c *Capture) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the wrapped writer to http.ResponseController. | Unwrap 向
// http.ResponseController 暴露被包装的写入器。
func (c *Capture) Unwrap() http.ResponseWriter { return c.ResponseWriter }
