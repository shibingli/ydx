package scim

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ydxjson "github.com/shibingli/ydx/json"
)

// errorReadCloser always fails reads. | errorReadCloser 读取总是失败。
type errorReadCloser struct{}

// Read implements io.Reader. | Read 实现 io.Reader。
func (errorReadCloser) Read([]byte) (int, error) { return 0, errors.New("read failed") }

// Close implements io.Closer. | Close 实现 io.Closer。
func (errorReadCloser) Close() error { return nil }

// TestDecodeBodyLimits verifies non-bulk body limits and error mapping. | TestDecodeBodyLimits 校验
// 非批量请求体限制与错误映射。
func TestDecodeBodyLimits(t *testing.T) {
	var target map[string]any
	if err := decodeBody(&http.Request{Body: nil}, &target); err == nil || !errors.Is(err, ErrInvalidSyntax) {
		t.Fatalf("nil body error = %v", err)
	}
	request := &http.Request{Body: io.NopCloser(errorReadCloser{})}
	if err := decodeBody(request, &target); err == nil || !errors.Is(err, ErrInvalidSyntax) {
		t.Fatalf("read error = %v", err)
	}
	request = &http.Request{Body: io.NopCloser(strings.NewReader("{not-json"))}
	if err := decodeBody(request, &target); err == nil || !errors.Is(err, ErrInvalidSyntax) {
		t.Fatalf("invalid JSON error = %v", err)
	}
	large := strings.Repeat(" ", maxSCIMRequestBody+1)
	request = &http.Request{Body: io.NopCloser(strings.NewReader(large))}
	if err := decodeBody(request, &target); err == nil || !errors.Is(err, ErrTooMany) {
		t.Fatalf("oversize error = %v", err)
	}
	exact := `{"a":"b"}` + strings.Repeat(" ", maxSCIMRequestBody-len(`{"a":"b"}`))
	request = &http.Request{Body: io.NopCloser(strings.NewReader(exact))}
	if err := decodeBody(request, &target); err != nil || target["a"] != "b" {
		t.Fatalf("exact limit decode = %#v, %v", target, err)
	}
}

// TestOversizedRequestBodyRejected verifies the HTTP handler rejects an oversized body. |
// TestOversizedRequestBodyRejected 校验 HTTP 处理器拒绝超大请求体。
func TestOversizedRequestBodyRejected(t *testing.T) {
	env := newTestEnv(t, Options{}, "/scim")
	recorder := env.do(http.MethodPost, "/Users", []byte(strings.Repeat(" ", maxSCIMRequestBody+1)), nil)
	requireError(t, recorder, http.StatusBadRequest, "tooMany")
}

// TestOversizedBulkRawBodyRejected verifies the bulk decoder bounds attacker-controlled bodies. |
// TestOversizedBulkRawBodyRejected 校验批量解码器限制攻击者控制的请求体。
func TestOversizedBulkRawBodyRejected(t *testing.T) {
	env := newTestEnv(t, Options{BulkMaxPayloadSize: 64}, "/scim")
	recorder := env.do(http.MethodPost, "/Bulk", []byte(strings.Repeat("x", 128)), nil)
	requireError(t, recorder, http.StatusBadRequest, "tooMany")
	if _, err := env.server.decodeBulkRequest(&http.Request{Body: nil}); err == nil || !errors.Is(err, ErrInvalidSyntax) {
		t.Fatalf("nil bulk body error = %v", err)
	}
	request := &http.Request{Body: io.NopCloser(errorReadCloser{})}
	if _, err := env.server.decodeBulkRequest(request); err == nil || !errors.Is(err, ErrInvalidSyntax) {
		t.Fatalf("bulk read error = %v", err)
	}
}

// TestBulkHonorsCallerContext verifies canceled caller contexts stop bulk mutations. |
// TestBulkHonorsCallerContext 校验取消的调用方上下文会阻止批量变更。
func TestBulkHonorsCallerContext(t *testing.T) {
	env := newTestEnv(t, Options{}, "/scim")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	recorder := env.doContext(ctx, http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "ctx"}}},
	}, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("bulk status = %d", recorder.Code)
	}
	var response BulkResponse
	decodeResponseBody(t, recorder, &response)
	if len(response.Operations) != 1 || response.Operations[0].Status != "500" {
		t.Fatalf("bulk operations = %+v", response.Operations)
	}
	if _, err := env.store.GetUser(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("store lookup error = %v", err)
	}
	if _, total, err := env.store.ListUsers(context.Background(), ListQuery{}); err != nil || total != 0 {
		t.Fatalf("canceled bulk mutated store: total = %d, %v", total, err)
	}
}

// TestSubstituteBulkIDsDeterministic verifies longest-first, stable replacement. |
// TestSubstituteBulkIDsDeterministic 校验最长优先且稳定的替换。
func TestSubstituteBulkIDsDeterministic(t *testing.T) {
	ids := map[string]string{"a": "1", "ab": "2"}
	for i := 0; i < 20; i++ {
		if got := substituteBulkIDs("/Users/bulkId:ab", ids); got != "/Users/2" {
			t.Fatalf("prefix collision = %q", got)
		}
		if got := substituteBulkIDs("/Users/bulkId:a", ids); got != "/Users/1" {
			t.Fatalf("short key = %q", got)
		}
	}
	if got := substituteBulkIDs("/Users/bulkId:missing", ids); got != "/Users/bulkId:missing" {
		t.Fatalf("unknown key = %q", got)
	}
	if got := substituteBulkIDs("", ids); got != "" {
		t.Fatalf("empty value = %q", got)
	}
	if got := substituteBulkIDs("/Users/bulkId:a", nil); got != "/Users/bulkId:a" {
		t.Fatalf("nil ids = %q", got)
	}
}

// TestDiscoveryAttributeMutability verifies RFC 7643 mutability and display flags. |
// TestDiscoveryAttributeMutability 校验 RFC 7643 可变性与 display 标记。
func TestDiscoveryAttributeMutability(t *testing.T) {
	attributes := map[string]Attribute{}
	for _, attribute := range userSchemaAttributes() {
		attributes[strings.ToLower(attribute.Name)] = attribute
	}
	for _, name := range []string{"entitlements", "roles"} {
		attribute, ok := attributes[name]
		if !ok {
			t.Fatalf("%s attribute missing", name)
		}
		if !attribute.MultiValued || attribute.Mutability != MutabilityReadWrite {
			t.Fatalf("%s attribute = %+v", name, attribute)
		}
	}
	emails, ok := attributes["emails"]
	if !ok {
		t.Fatalf("emails attribute missing")
	}
	var display *Attribute
	for i := range emails.SubAttributes {
		if strings.EqualFold(emails.SubAttributes[i].Name, "display") {
			display = &emails.SubAttributes[i]
		}
	}
	if display == nil || display.Mutability != MutabilityReadOnly {
		t.Fatalf("emails display = %+v", display)
	}
}

// TestDiscoveryHandlers verifies discovery endpoints through the router. |
// TestDiscoveryHandlers 校验通过路由器访问发现端点。
func TestDiscoveryHandlers(t *testing.T) {
	env := newTestEnv(t, Options{}, "/scim")
	for _, path := range []string{"/ServiceProviderConfig", "/ResourceTypes", "/Schemas"} {
		recorder := env.do(http.MethodGet, path, nil, nil)
		if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != ContentType {
			t.Fatalf("%s status = %d, content type = %q", path, recorder.Code, recorder.Header().Get("Content-Type"))
		}
	}
	for _, path := range []string{"/ResourceTypes/User", "/ResourceTypes/Group", "/Schemas/" + UserSchema, "/Schemas/" + GroupSchema} {
		recorder := env.do(http.MethodGet, path, nil, nil)
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s status = %d body = %s", path, recorder.Code, recorder.Body.String())
		}
	}
	for _, path := range []string{"/ResourceTypes/Unknown", "/Schemas/urn:example:unknown"} {
		recorder := env.do(http.MethodGet, path, nil, nil)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d", path, recorder.Code)
		}
	}
}

// TestClientOversizedResponse verifies the client rejects oversized responses. |
// TestClientOversizedResponse 校验客户端拒绝超大响应。
func TestClientOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ContentType)
		_, _ = io.CopyN(w, zeroReader{}, int64(maxClientResponseSize)+1)
	}))
	defer server.Close()
	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.GetUser(context.Background(), "u1"); err == nil || !errors.Is(err, ErrInvalidSyntax) {
		t.Fatalf("oversized response error = %v", err)
	}
}

// zeroReader yields zero bytes forever. | zeroReader 持续产生零字节。
type zeroReader struct{}

// Read implements io.Reader. | Read 实现 io.Reader。
func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}

// TestClientOptionsAndErrors verifies custom HTTP clients and error decoding. |
// TestClientOptionsAndErrors 校验自定义 HTTP 客户端与错误解码。
func TestClientOptionsAndErrors(t *testing.T) {
	var used bool
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		used = true
		if request.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
		}
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Header:     http.Header{"Content-Type": []string{ContentType}},
			Body: io.NopCloser(strings.NewReader(
				`{"schemas":["` + ErrorSchema + `"],"status":"400","scimType":"invalidFilter","detail":"bad filter"}`)),
			Request: request,
		}, nil
	})
	client, err := NewClient("https://example.test/scim", WithHTTPClient(&http.Client{Transport: transport}),
		WithBearerToken("token"), WithUserAgent("agent"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.ListUsers(context.Background(), ListOptions{})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !used {
		t.Fatalf("custom HTTP client not used")
	}
	var failure *ErrorResponse
	if !errors.As(err, &failure) || failure.StatusCode != http.StatusBadRequest ||
		failure.ScimType != "invalidFilter" || failure.Detail != "bad filter" {
		t.Fatalf("error response = %+v", failure)
	}
	if !errors.Is(err, ErrInvalidFilter) {
		t.Fatalf("error does not unwrap to ErrInvalidFilter: %v", err)
	}
}

// roundTripFunc adapts a function to http.RoundTripper. | roundTripFunc 把函数适配为
// http.RoundTripper。
type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip implements http.RoundTripper. | RoundTrip 实现 http.RoundTripper。
func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

// TestErrorResponseText verifies safe error text and sentinel mapping. |
// TestErrorResponseText 校验安全错误文本与哨兵映射。
func TestErrorResponseText(t *testing.T) {
	var nilError *ErrorResponse
	if nilError.Error() != "scim: request failed | scim：请求失败" || nilError.Unwrap() != nil {
		t.Fatalf("nil error text = %q, unwrap = %v", nilError.Error(), nilError.Unwrap())
	}
	if got := (&ErrorResponse{Detail: "detail"}).Error(); got != "detail" {
		t.Fatalf("detail text = %q", got)
	}
	if got := (&ErrorResponse{StatusCode: http.StatusNotFound}).Error(); got != ErrNotFound.Error() {
		t.Fatalf("sentinel text = %q", got)
	}
	if got := (&ErrorResponse{StatusCode: 299}).Error(); got != ErrInvalidRequest.Error() {
		t.Fatalf("fallback text = %q", got)
	}
	cases := []struct {
		scimType string
		want     error
	}{
		{"invalidFilter", ErrInvalidFilter},
		{"invalidPath", ErrInvalidPath},
		{"noTarget", ErrNoTarget},
		{"mutability", ErrMutability},
		{"uniqueness", ErrUniqueness},
		{"tooMany", ErrTooMany},
		{"invalidVers", ErrInvalidVersion},
		{"invalidSyntax", ErrInvalidSyntax},
		{"invalidValue", ErrInvalidValue},
	}
	for _, testCase := range cases {
		if got := sentinelForStatus(0, testCase.scimType); got != testCase.want {
			t.Fatalf("scimType %q = %v", testCase.scimType, got)
		}
	}
	statuses := []struct {
		status int
		want   error
	}{
		{http.StatusBadRequest, ErrInvalidRequest},
		{http.StatusUnauthorized, ErrUnauthorized},
		{http.StatusForbidden, ErrForbidden},
		{http.StatusNotFound, ErrNotFound},
		{http.StatusConflict, ErrConflict},
		{http.StatusPreconditionFailed, ErrPreconditionFailed},
		{http.StatusNotModified, ErrNotModified},
		{http.StatusNotImplemented, ErrUnsupported},
		{http.StatusInternalServerError, ErrInternal},
		{http.StatusTeapot, ErrInvalidRequest},
	}
	for _, testCase := range statuses {
		if got := sentinelForStatus(testCase.status, ""); got != testCase.want {
			t.Fatalf("status %d = %v", testCase.status, got)
		}
	}
}

// decodeResponseBody decodes a recorder body into target. | decodeResponseBody 把 recorder 响应体
// 解码到 target。
func decodeResponseBody(t *testing.T, recorder *httptest.ResponseRecorder, target any) {
	t.Helper()
	if err := ydxjson.Unmarshal(bytes.TrimSpace(recorder.Body.Bytes()), target); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}
