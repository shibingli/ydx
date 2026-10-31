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
