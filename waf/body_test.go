package waf

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestJSONBodyArguments(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule ARGS_POST:user.name "@contains admin" "id:9500,phase:2,deny,status:403"`,
	}, nil)
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"user":{"name":"admin","roles":["a","b"]}}`))
	request.Header.Set("Content-Type", "application/json")
	response := serveTest(t, instance, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

func TestMultipartArguments(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("payload", "attack"); err != nil {
		t.Fatalf("WriteField: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	instance := newTestWAF(t, []string{
		`SecRule ARGS_POST:payload "@contains attack" "id:9501,phase:2,deny,status:403"`,
	}, nil)
	request := httptest.NewRequest(http.MethodPost, "/", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response := serveTest(t, instance, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

// TestMultipartLargeFieldIsFullyInspected verifies a field tail beyond 1 MiB is still inspected.
// | TestMultipartLargeFieldIsFullyInspected 验证超过 1 MiB 的字段尾部仍会被检测。
func TestMultipartLargeFieldIsFullyInspected(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("payload", strings.Repeat("a", 2<<20)+"attack"); err != nil {
		t.Fatalf("WriteField: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	instance := newTestWAF(t, []string{
		`SecRule ARGS_POST:payload "@contains attack" "id:9511,phase:2,deny,status:403"`,
	}, nil)
	request := httptest.NewRequest(http.MethodPost, "/", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response := serveTest(t, instance, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

// TestChunkedRequestBodyInspection verifies phase 2 inspects a request body of unknown length,
// as chunked transfer encoding produces. | TestChunkedRequestBodyInspection 验证 phase 2 检测
// 未知长度的请求正文，分块传输编码即产生这种正文。
func TestChunkedRequestBodyInspection(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule ARGS_POST:payload "@contains attack" "id:9514,phase:2,deny,status:403"`,
	}, nil)
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("payload=attack"))
	request.ContentLength = -1
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := serveTest(t, instance, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

// TestJSONArrayRootIsFlattened verifies a non-object JSON root is flattened without error. |
// TestJSONArrayRootIsFlattened 验证非对象 JSON 根会被扁平化且不报错。
func TestJSONArrayRootIsFlattened(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule JSON:0 "@contains attack" "id:9515,phase:2,deny,status:403"`,
	}, nil)
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`["attack"]`))
	request.Header.Set("Content-Type", "application/json")
	response := serveTest(t, instance, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

func TestRequestBodyLimitReject(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule ARGS_POST:payload "@contains attack" "id:9502,phase:2,deny,status:403"`,
	}, func(options *Options) {
		options.RequestBodyLimit = 10
		options.RequestBodyLimitAction = LimitReject
	})
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("payload=attack&more=data"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := serveTest(t, instance, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%q", response.Code, response.Body.String())
	}
}

func TestRequestBodyProcessPartialReplaysHandlerBody(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains nothing" "id:9503,phase:1,deny,status:403"`,
	}, func(options *Options) {
		options.RequestBodyLimit = 10
		options.RequestBodyLimitAction = LimitProcessPartial
	})
	payload := "payload=attack&more=data"
	recorder := httptest.NewRecorder()
	handler := instance.HTTPMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("ReadAll: %v", err)
		}
		if string(body) != payload {
			t.Errorf("body = %q, want %q", body, payload)
		}
		rw.WriteHeader(http.StatusOK)
	}))
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(payload))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
}

// statusRecordingWriter records every WriteHeader call, including informational responses.
// | statusRecordingWriter 记录每次 WriteHeader 调用，包括信息性响应。
type statusRecordingWriter struct {
	header   http.Header
	body     bytes.Buffer
	statuses []int
}

// Header returns the header map. | Header 返回头部映射。
func (w *statusRecordingWriter) Header() http.Header { return w.header }

// WriteHeader records one status. | WriteHeader 记录一个状态码。
func (w *statusRecordingWriter) WriteHeader(code int) { w.statuses = append(w.statuses, code) }

// Write appends response bytes. | Write 追加响应字节。
func (w *statusRecordingWriter) Write(p []byte) (int, error) {
	if len(w.statuses) == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(p)
}

// TestResponseWriterForwardsInformationalHeaders verifies 103 Early Hints does not become the final
// transaction status and phase 3 still inspects the final status. |
// TestResponseWriterForwardsInformationalHeaders 验证 103 Early Hints 不会成为最终事务状态，且
// phase 3 仍检测最终状态。
func TestResponseWriterForwardsInformationalHeaders(t *testing.T) {
	var eventStatus int
	instance := newTestWAF(t, []string{
		`SecRule RESPONSE_STATUS "@eq 202" "id:9510,phase:3,deny,status:403"`,
	}, func(options *Options) {
		options.Observer = func(event Event) { eventStatus = event.Status }
	})
	writer := &statusRecordingWriter{header: make(http.Header)}
	handler := instance.HTTPMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Link", "</style.css>; rel=preload")
		rw.WriteHeader(http.StatusEarlyHints)
		rw.WriteHeader(http.StatusAccepted)
	}))
	handler.ServeHTTP(writer, httptest.NewRequest(http.MethodGet, "/", nil))
	if len(writer.statuses) < 2 || writer.statuses[0] != http.StatusEarlyHints {
		t.Fatalf("statuses = %v, want 103 followed by the final status", writer.statuses)
	}
	if writer.statuses[len(writer.statuses)-1] != http.StatusForbidden {
		t.Fatalf("statuses = %v, want final 403 from phase 3", writer.statuses)
	}
	if eventStatus != http.StatusForbidden {
		t.Fatalf("event status = %d, want 403", eventStatus)
	}
}

func TestResponseBodyLimitProcessPartial(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule RESPONSE_BODY "@contains secret" "id:9504,phase:4,deny,status:403"`,
	}, func(options *Options) {
		options.ResponseBodyAccess = true
		options.ResponseBodyLimit = 5
		options.ResponseBodyLimitAction = LimitProcessPartial
	})
	recorder := httptest.NewRecorder()
	handler := instance.HTTPMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(rw, "abc secret def")
	}))
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "secret") {
		t.Fatalf("body = %q", recorder.Body.String())
	}
}

func TestResponseBodyLimitReject(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule RESPONSE_BODY "@contains secret" "id:9505,phase:4,deny,status:403"`,
	}, func(options *Options) {
		options.ResponseBodyAccess = true
		options.ResponseBodyLimit = 5
		options.ResponseBodyLimitAction = LimitReject
	})
	recorder := httptest.NewRecorder()
	handler := instance.HTTPMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(rw, "abc secret def")
	}))
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", recorder.Code)
	}
	if stats := instance.Stats(); stats.Errors == 0 {
		t.Fatal("oversized response not counted as error")
	}
}

func TestResponseFlushInspectsPrefix(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule RESPONSE_BODY "@contains first" "id:9506,phase:4,deny,status:403"`,
	}, func(options *Options) { options.ResponseBodyAccess = true })
	recorder := httptest.NewRecorder()
	handler := instance.HTTPMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(rw, "first")
		if flusher, ok := rw.(http.Flusher); ok {
			flusher.Flush()
		}
		_, _ = io.WriteString(rw, " secret")
	}))
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
}

func TestResponseFlushStreamsAfterPrefix(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule RESPONSE_BODY "@contains secret" "id:9507,phase:4,deny,status:403"`,
	}, func(options *Options) { options.ResponseBodyAccess = true })
	recorder := httptest.NewRecorder()
	handler := instance.HTTPMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(rw, "first")
		if flusher, ok := rw.(http.Flusher); ok {
			flusher.Flush()
		}
		_, _ = io.WriteString(rw, " secret")
	}))
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if recorder.Body.String() != "first secret" {
		t.Fatalf("body = %q", recorder.Body.String())
	}
}

// TestResponseBodyInspectionSniffsMissingContentType verifies phase 4 inspects a textual response
// even when the handler never sets Content-Type. | TestResponseBodyInspectionSniffsMissingContentType
// 验证处理器未设置 Content-Type 时，phase 4 仍检测文本响应。
func TestResponseBodyInspectionSniffsMissingContentType(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule RESPONSE_BODY "@contains secret" "id:9512,phase:4,deny,status:403"`,
	}, func(options *Options) { options.ResponseBodyAccess = true })
	recorder := httptest.NewRecorder()
	handler := instance.HTTPMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(rw, "<html><body>secret</body></html>")
	}))
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", recorder.Code, recorder.Body.String())
	}
}

// TestResponseBodyInspectionSkipsSniffedBinary verifies a body sniffed as binary is not exposed to
// RESPONSE_BODY rules and is forwarded unchanged. | TestResponseBodyInspectionSkipsSniffedBinary
// 验证嗅探为二进制的正文不会暴露给 RESPONSE_BODY 规则，并原样转发。
func TestResponseBodyInspectionSkipsSniffedBinary(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule RESPONSE_BODY "@contains secret" "id:9513,phase:4,deny,status:403"`,
	}, func(options *Options) { options.ResponseBodyAccess = true })
	payload := []byte{0x00, 0x01, 0x02, 0x03, 0x00, 's', 'e', 'c', 'r', 'e', 't'}
	recorder := httptest.NewRecorder()
	handler := instance.HTTPMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		_, _ = rw.Write(payload)
	}))
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if !bytes.Equal(recorder.Body.Bytes(), payload) {
		t.Fatalf("body = %v, want %v", recorder.Body.Bytes(), payload)
	}
}

func TestAuditWriterReceivesBlockedEvent(t *testing.T) {
	var audit bytes.Buffer
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains audit" "id:9508,phase:1,deny,status:403"`,
	}, func(options *Options) { options.AuditWriter = &audit })
	serveTest(t, instance, httptestNewRequest("/audit"))
	if audit.Len() == 0 {
		t.Fatal("audit writer received nothing")
	}
	if !strings.Contains(audit.String(), "9508") {
		t.Fatalf("audit = %q", audit.String())
	}
}

func TestConcurrentRequests(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains blocked" "id:9509,phase:1,deny,status:403"`,
	}, nil)
	var wait sync.WaitGroup
	for index := 0; index < 64; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			target := "/allowed"
			if index%2 == 0 {
				target = "/blocked"
			}
			recorder := httptest.NewRecorder()
			instance.HTTPMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				rw.WriteHeader(http.StatusOK)
			})).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
			if index%2 == 0 && recorder.Code != http.StatusForbidden {
				t.Errorf("blocked status = %d", recorder.Code)
			}
			if index%2 == 1 && recorder.Code != http.StatusOK {
				t.Errorf("allowed status = %d", recorder.Code)
			}
		}(index)
	}
	wait.Wait()
}
