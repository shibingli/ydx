package waf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// readerOnly hides every optional method of the wrapped reader so io.Copy uses the destination's
// ReaderFrom. | readerOnly 隐藏包装读取器的可选方法，使 io.Copy 使用目标端的 ReaderFrom。
type readerOnly struct {
	io.Reader
}

// recordingReaderFrom records whether the underlying ReaderFrom fast path was taken.
// | recordingReaderFrom 记录是否走了底层 ReaderFrom 快路径。
type recordingReaderFrom struct {
	*httptest.ResponseRecorder
	called bool
}

// ReadFrom records the call and copies without recursing into itself. | ReadFrom 记录调用并在不递归
// 到自身的情况下复制。
func (r *recordingReaderFrom) ReadFrom(src io.Reader) (int64, error) {
	r.called = true
	return io.Copy(plainWriter{Writer: r.ResponseRecorder}, src)
}

// TestReadFromRunsPhase3BeforeBody verifies the non-buffered ReaderFrom path evaluates phase 3
// before delegating body bytes to the underlying writer. | TestReadFromRunsPhase3BeforeBody 验证
// 非缓冲 ReaderFrom 路径在把正文委托给底层写入器之前执行 phase 3。
func TestReadFromRunsPhase3BeforeBody(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule RESPONSE_STATUS "@streq 200" "id:9600,phase:3,deny,status:403"`,
	}, nil)
	recorder := &recordingReaderFrom{ResponseRecorder: httptest.NewRecorder()}
	handler := instance.HTTPMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(rw, readerOnly{Reader: strings.NewReader("secret-body")})
	}))
	handler.ServeHTTP(recorder, httptestNewRequest("/"))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
	if recorder.called {
		t.Fatal("underlying ReaderFrom was used after phase 3 interrupted the response")
	}
	if body := recorder.Body.String(); strings.Contains(body, "secret-body") {
		t.Fatalf("body leaks handler payload: %q", body)
	}
}

// TestFlushDoesNotSendRejectedPrefix verifies Flush in reject mode discards the buffered prefix
// and refuses to forward subsequent body bytes. | TestFlushDoesNotSendRejectedPrefix 验证 Reject 模式
// 下 Flush 丢弃已缓冲前缀并拒绝继续发送正文。
func TestFlushDoesNotSendRejectedPrefix(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule RESPONSE_BODY "@contains secret" "id:9601,phase:4,deny,status:403"`,
	}, func(options *Options) {
		options.ResponseBodyAccess = true
		options.ResponseBodyLimit = 16
		options.ResponseBodyLimitAction = LimitReject
	})
	recorder := httptest.NewRecorder()
	handler := instance.HTTPMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		_, _ = rw.Write([]byte("prefix-not-secret-0123456789"))
		rw.(http.Flusher).Flush()
		_, _ = rw.Write([]byte("secret"))
	}))
	handler.ServeHTTP(recorder, httptestNewRequest("/"))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", recorder.Code)
	}
	body := recorder.Body.String()
	if strings.Contains(body, "secret") {
		t.Fatalf("body leaks secret: %q", body)
	}
	if strings.Contains(body, "prefix-not") {
		t.Fatalf("body leaks rejected prefix: %q", body)
	}
}
