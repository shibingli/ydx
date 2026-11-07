package cas

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/base64"
)

// logoutReceiver is a test service that accepts back-channel logout requests. | logoutReceiver 是
// 接受后端登出请求的测试服务。
type logoutReceiver struct {
	mu       sync.Mutex
	requests []*LogoutRequest
	values   []string
	status   int
	delay    time.Duration
}

// newLogoutReceiver starts a test service that parses logoutRequest and answers status. | newLogoutReceiver
// 启动解析 logoutRequest 并以 status 应答的测试服务。
func newLogoutReceiver(t *testing.T, status int, delay time.Duration) (*httptest.Server, *logoutReceiver) {
	t.Helper()
	receiver := &logoutReceiver{status: status, delay: delay}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "form", http.StatusBadRequest)
			return
		}
		value := r.PostForm.Get(logoutRequestParameter)
		parsed, err := ParseLogoutRequest(value)
		if err != nil {
			http.Error(w, "request", http.StatusBadRequest)
			return
		}
		receiver.mu.Lock()
		receiver.requests = append(receiver.requests, parsed)
		receiver.values = append(receiver.values, value)
		status := receiver.status
		receiver.mu.Unlock()
		if receiver.delay > 0 {
			select {
			case <-time.After(receiver.delay):
			case <-r.Context().Done():
				return
			}
		}
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(server.Close)
	return server, receiver
}

// snapshot returns a copy of the parsed requests. | snapshot 返回已解析请求的副本。
func (r *logoutReceiver) snapshot() []*LogoutRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*LogoutRequest(nil), r.requests...)
}

// count returns the number of received requests. | count 返回已接收请求数量。
func (r *logoutReceiver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.requests)
}

// newSLOServer builds a server with a session registry and the given registered services. |
// newSLOServer 构建带会话注册表与指定已注册服务的服务端。
func newSLOServer(t *testing.T, services []string, options ...func(*ServerConfig)) (*Server, *MemoryServiceSessionRegistry, *MemoryTicketStore, *testClock) {
	t.Helper()
	registry := NewMemoryServiceSessionRegistry()
	configs := []func(*ServerConfig){
		func(config *ServerConfig) {
			config.SessionRegistry = registry
			if len(services) > 0 {
				config.ServiceRegistry = NewStaticServiceRegistry(services...)
			}
		},
	}
	configs = append(configs, options...)
	server, store, clock := newTestServer(t, configs...)
	t.Cleanup(func() { _ = registry.Close() })
	return server, registry, store, clock
}

// TestSLOLogoutRequestRevokesFamilyAndNotifiesOthers covers inbound back-channel logout. |
// TestSLOLogoutRequestRevokesFamilyAndNotifiesOthers 覆盖入站后端登出。
func TestSLOLogoutRequestRevokesFamilyAndNotifiesOthers(t *testing.T) {
	firstService, firstReceiver := newLogoutReceiver(t, http.StatusOK, 0)
	secondService, secondReceiver := newLogoutReceiver(t, http.StatusOK, 0)
	server, registry, store, _ := newSLOServer(t, []string{firstService.URL, secondService.URL})
	handler := newTestRouter(t, server)
	cookie, stFirst := loginAndTicket(t, handler, firstService.URL)
	tgt, err := store.Get(t.Context(), cookie.Value)
	if err != nil {
		t.Fatalf("load TGT: %v", err)
	}
	stSecond, err := server.issueTicket(t.Context(), TicketST, testPrincipal(), "user-1", secondService.URL, tgt, server.config.ServiceTicketTimeout, false, false)
	if err != nil {
		t.Fatalf("issue second ST: %v", err)
	}
	if registry.Len() != 2 {
		t.Fatalf("registered sessions = %d, want 2", registry.Len())
	}
	document, err := BuildLogoutRequest("", stFirst, server.nowTime())
	if err != nil {
		t.Fatalf("BuildLogoutRequest: %v", err)
	}
	form := url.Values{logoutRequestParameter: {string(document)}}
	recorder := serve(t, handler, http.MethodPost, "/cas/logout", form)
	if recorder.Code != http.StatusOK {
		t.Fatalf("logout request status = %d, want 200; body: %s", recorder.Code, recorder.Body.String())
	}
	for _, id := range []string{cookie.Value, stFirst, stSecond.ID} {
		if _, err := store.Get(t.Context(), id); !errors.Is(err, ErrTicketNotFound) {
			t.Fatalf("ticket %q survived logout: %v", id, err)
		}
	}
	if registry.Len() != 0 {
		t.Fatalf("sessions survived logout: %d", registry.Len())
	}
	if firstReceiver.count() != 0 {
		t.Fatalf("origin service received %d requests, want 0", firstReceiver.count())
	}
	received := secondReceiver.snapshot()
	if len(received) != 1 {
		t.Fatalf("other service received %d requests, want 1", len(received))
	}
	if received[0].SessionIndex != stSecond.ID {
		t.Fatalf("SessionIndex = %q, want %q", received[0].SessionIndex, stSecond.ID)
	}
	if received[0].NameIdentifier != "alice" {
		t.Fatalf("NameIdentifier = %q, want alice", received[0].NameIdentifier)
	}
	replay := serve(t, handler, http.MethodPost, "/cas/logout", form)
	if replay.Code != http.StatusOK {
		t.Fatalf("replay status = %d, want 200; body: %s", replay.Code, replay.Body.String())
	}
	if secondReceiver.count() != 1 {
		t.Fatalf("replay delivered again: %d", secondReceiver.count())
	}
}

// TestSLOLogoutRequestNameIdentifierFallback covers a request without SessionIndex. |
// TestSLOLogoutRequestNameIdentifierFallback 覆盖不带 SessionIndex 的请求。
func TestSLOLogoutRequestNameIdentifierFallback(t *testing.T) {
	firstService, firstReceiver := newLogoutReceiver(t, http.StatusOK, 0)
	secondService, secondReceiver := newLogoutReceiver(t, http.StatusOK, 0)
	server, registry, store, _ := newSLOServer(t, []string{firstService.URL, secondService.URL})
	handler := newTestRouter(t, server)
	firstCookie, stFirst := loginAndTicket(t, handler, firstService.URL)
	secondCookie, stSecond := loginAndTicket(t, handler, secondService.URL)
	if registry.Len() != 2 {
		t.Fatalf("registered sessions = %d, want 2", registry.Len())
	}
	document, err := BuildLogoutRequest("alice", "", server.nowTime())
	if err != nil {
		t.Fatalf("BuildLogoutRequest: %v", err)
	}
	form := url.Values{logoutRequestParameter: {string(document)}}
	recorder := serve(t, handler, http.MethodPost, "/cas/logout", form)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", recorder.Code, recorder.Body.String())
	}
	if registry.Len() != 0 {
		t.Fatalf("sessions survived: %d", registry.Len())
	}
	for _, id := range []string{firstCookie.Value, secondCookie.Value, stFirst, stSecond} {
		if _, err := store.Get(t.Context(), id); !errors.Is(err, ErrTicketNotFound) {
			t.Fatalf("ticket %q survived: %v", id, err)
		}
	}
	if firstReceiver.count() != 1 || secondReceiver.count() != 1 {
		t.Fatalf("deliveries = %d/%d, want 1/1", firstReceiver.count(), secondReceiver.count())
	}
}

// TestSLOLogoutRequestUnknownSessionIsNoOp covers replay-safe unknown session indices. |
// TestSLOLogoutRequestUnknownSessionIsNoOp 覆盖可安全重放的未知会话索引。
func TestSLOLogoutRequestUnknownSessionIsNoOp(t *testing.T) {
	service, receiver := newLogoutReceiver(t, http.StatusOK, 0)
	server, registry, store, _ := newSLOServer(t, []string{service.URL})
	handler := newTestRouter(t, server)
	_, st := loginAndTicket(t, handler, service.URL)
	document, err := BuildLogoutRequest("alice", "ST-unknown", server.nowTime())
	if err != nil {
		t.Fatalf("BuildLogoutRequest: %v", err)
	}
	form := url.Values{logoutRequestParameter: {string(document)}}
	recorder := serve(t, handler, http.MethodPost, "/cas/logout", form)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if _, err := store.Get(t.Context(), st); err != nil {
		t.Fatalf("known ticket was revoked by an unknown session index: %v", err)
	}
	if registry.Len() != 1 {
		t.Fatalf("sessions = %d, want 1", registry.Len())
	}
	if receiver.count() != 0 {
		t.Fatalf("receiver got %d requests, want 0", receiver.count())
	}
}

// TestSLOLogoutRequestMalformedAndOversized covers rejection before any state change. |
// TestSLOLogoutRequestMalformedAndOversized 覆盖任何状态变更前的拒绝。
func TestSLOLogoutRequestMalformedAndOversized(t *testing.T) {
	server, registry, _, _ := newSLOServer(t, nil)
	handler := newTestRouter(t, server)
	cases := []struct {
		name   string
		method string
		target string
		form   url.Values
		status int
	}{
		{"empty query", http.MethodGet, "/cas/logout?logoutRequest=", nil, http.StatusBadRequest},
		{"plain garbage", http.MethodGet, "/cas/logout?logoutRequest=not-xml", nil, http.StatusBadRequest},
		{"invalid base64", http.MethodGet, "/cas/logout?logoutRequest=!!!!", nil, http.StatusBadRequest},
		{"other xml", http.MethodGet, "/cas/logout?logoutRequest=" + url.QueryEscape("<foo/>"), nil, http.StatusBadRequest},
		{"missing identifiers", http.MethodGet, "/cas/logout?logoutRequest=" + url.QueryEscape(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol"></samlp:LogoutRequest>`), nil, http.StatusBadRequest},
		{"truncated xml", http.MethodGet, "/cas/logout?logoutRequest=" + url.QueryEscape(`<samlp:LogoutRequest>`), nil, http.StatusBadRequest},
		{"oversized query", http.MethodGet, "/cas/logout?logoutRequest=" + strings.Repeat("a", maxProtocolBody+1), nil, http.StatusRequestEntityTooLarge},
		{"oversized form", http.MethodPost, "/cas/logout", url.Values{logoutRequestParameter: {strings.Repeat("a", maxProtocolBody)}}, http.StatusRequestEntityTooLarge},
		{"empty form field", http.MethodPost, "/cas/logout", url.Values{logoutRequestParameter: {""}}, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := serve(t, handler, tc.method, tc.target, tc.form)
			if recorder.Code != tc.status {
				t.Fatalf("status = %d, want %d; body: %s", recorder.Code, tc.status, recorder.Body.String())
			}
		})
	}
	if registry.Len() != 0 {
		t.Fatalf("malformed requests created sessions: %d", registry.Len())
	}
}

// TestSLODeliveryResults covers success, HTTP errors, timeouts and observers. |
// TestSLODeliveryResults 覆盖成功、HTTP 错误、超时与观察者。
func TestSLODeliveryResults(t *testing.T) {
	goodService, _ := newLogoutReceiver(t, http.StatusOK, 0)
	failingService, _ := newLogoutReceiver(t, http.StatusServiceUnavailable, 0)
	slowService, _ := newLogoutReceiver(t, http.StatusOK, 200*time.Millisecond)
	var mu sync.Mutex
	var observed []LogoutDeliveryResult
	server, _, _, _ := newSLOServer(t, nil,
		func(config *ServerConfig) {
			config.LogoutCallbackTimeout = 40 * time.Millisecond
			config.LogoutObserver = func(_ context.Context, result LogoutDeliveryResult) {
				mu.Lock()
				observed = append(observed, result)
				mu.Unlock()
			}
		})
	principal := testPrincipal()
	tgt, err := server.issueTicket(t.Context(), TicketTGT, principal, "user-1", "", nil, server.config.TGTTimeout, false, false)
	if err != nil {
		t.Fatalf("issue TGT: %v", err)
	}
	for _, service := range []string{goodService.URL, failingService.URL, slowService.URL} {
		if _, err := server.issueTicket(t.Context(), TicketST, principal, "user-1", service, tgt, server.config.ServiceTicketTimeout, false, false); err != nil {
			t.Fatalf("issue ST for %s: %v", service, err)
		}
	}
	sessions, err := server.Sessions().ListByTGT(t.Context(), tgt.ID)
	if err != nil {
		t.Fatalf("ListByTGT: %v", err)
	}
	results := server.DeliverLogoutRequests(t.Context(), sessions, "")
	if len(results) != 3 {
		t.Fatalf("results = %d, want 3", len(results))
	}
	byService := make(map[string]LogoutDeliveryResult, len(results))
	for _, result := range results {
		byService[result.Service] = result
	}
	good := byService[goodService.URL]
	if good.Err != nil || good.StatusCode != http.StatusOK || good.Duration <= 0 {
		t.Fatalf("successful result = %#v", good)
	}
	failing := byService[failingService.URL]
	if !errors.Is(failing.Err, ErrLogoutDelivery) || failing.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("failing result = %#v", failing)
	}
	slow := byService[slowService.URL]
	if slow.Err == nil || slow.StatusCode != 0 {
		t.Fatalf("timeout result = %#v", slow)
	}
	mu.Lock()
	observedCount := len(observed)
	mu.Unlock()
	if observedCount != 3 {
		t.Fatalf("observed = %d, want 3", observedCount)
	}
	invalid := server.DeliverLogoutRequests(t.Context(), []*ServiceSession{{Service: "not a url", SessionIndex: "ST-x"}}, "")
	if len(invalid) != 1 || !errors.Is(invalid[0].Err, ErrLogoutDelivery) {
		t.Fatalf("invalid service result = %#v", invalid)
	}
	missing := server.DeliverLogoutRequests(t.Context(), []*ServiceSession{{Service: goodService.URL}}, "")
	if len(missing) != 1 || !errors.Is(missing[0].Err, ErrInvalidLogoutRequest) {
		t.Fatalf("missing identifiers result = %#v", missing)
	}
}

// TestSLODeliveryCancellationAndFilters covers cancellation and request filtering. |
// TestSLODeliveryCancellationAndFilters 覆盖取消与请求过滤。
func TestSLODeliveryCancellationAndFilters(t *testing.T) {
	service, receiver := newLogoutReceiver(t, http.StatusOK, 0)
	server, _, _, _ := newSLOServer(t, []string{service.URL})
	principal := testPrincipal()
	tgt, err := server.issueTicket(t.Context(), TicketTGT, principal, "user-1", "", nil, server.config.TGTTimeout, false, false)
	if err != nil {
		t.Fatalf("issue TGT: %v", err)
	}
	first, err := server.issueTicket(t.Context(), TicketST, principal, "user-1", service.URL, tgt, server.config.ServiceTicketTimeout, false, false)
	if err != nil {
		t.Fatalf("issue ST: %v", err)
	}
	second, err := server.issueTicket(t.Context(), TicketST, principal, "user-1", service.URL, tgt, server.config.ServiceTicketTimeout, false, false)
	if err != nil {
		t.Fatalf("issue second ST: %v", err)
	}
	firstSession, err := server.Sessions().Get(t.Context(), first.ID)
	if err != nil {
		t.Fatalf("Get first session: %v", err)
	}
	secondSession, err := server.Sessions().Get(t.Context(), second.ID)
	if err != nil {
		t.Fatalf("Get second session: %v", err)
	}
	var nilServer *Server
	if got := nilServer.DeliverLogoutRequests(t.Context(), []*ServiceSession{firstSession.Clone()}, ""); got != nil {
		t.Fatalf("nil server results = %#v", got)
	}
	if got := server.DeliverLogoutRequests(t.Context(), nil, ""); got != nil {
		t.Fatalf("nil sessions results = %#v", got)
	}
	if got := server.DeliverLogoutRequests(t.Context(), []*ServiceSession{nil, {Service: service.URL}}, ""); len(got) != 1 {
		t.Fatalf("filtered results = %#v", got)
	}
	skipped := server.DeliverLogoutRequests(t.Context(), []*ServiceSession{firstSession.Clone(), secondSession.Clone()}, first.ID)
	if len(skipped) != 1 || skipped[0].SessionIndex != second.ID {
		t.Fatalf("skipped results = %#v", skipped)
	}
	if receiver.count() != 1 {
		t.Fatalf("receiver got %d requests, want 1", receiver.count())
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	canceledResults := server.DeliverLogoutRequests(canceled, []*ServiceSession{firstSession.Clone()}, "")
	if len(canceledResults) != 1 || canceledResults[0].Err == nil {
		t.Fatalf("canceled results = %#v", canceledResults)
	}
}

// TestSLOLogoutRequestValue covers presence detection for GET and POST. | TestSLOLogoutRequestValue
// 覆盖 GET 与 POST 的存在性检测。
func TestSLOLogoutRequestValue(t *testing.T) {
	if _, ok := logoutRequestValue(nil); ok {
		t.Fatal("nil request reported a logout request")
	}
	request := httptest.NewRequest(http.MethodGet, "/cas/logout?logoutRequest=value", nil)
	if value, ok := logoutRequestValue(request); !ok || value != "value" {
		t.Fatalf("GET value = %q, %v", value, ok)
	}
	request = httptest.NewRequest(http.MethodGet, "/cas/logout", nil)
	if _, ok := logoutRequestValue(request); ok {
		t.Fatal("GET without parameter reported a logout request")
	}
	request = httptest.NewRequest(http.MethodPost, "/cas/logout", nil)
	request.PostForm = url.Values{logoutRequestParameter: {"form-value"}}
	if value, ok := logoutRequestValue(request); !ok || value != "form-value" {
		t.Fatalf("POST value = %q, %v", value, ok)
	}
	request.PostForm = url.Values{logoutRequestParameter: {}}
	if value, ok := logoutRequestValue(request); !ok || value != "" {
		t.Fatalf("POST empty value = %q, %v", value, ok)
	}
	request = httptest.NewRequest(http.MethodPost, "/cas/logout", nil)
	if _, ok := logoutRequestValue(request); ok {
		t.Fatal("POST without parameter reported a logout request")
	}
}

// TestBuildAndParseLogoutRequest covers SAML construction, escaping and parsing variants. |
// TestBuildAndParseLogoutRequest 覆盖 SAML 构造、转义与解析变体。
func TestBuildAndParseLogoutRequest(t *testing.T) {
	now := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)
	document, err := BuildLogoutRequest(`a<b&"c"`, "ST-1&2", now)
	if err != nil {
		t.Fatalf("BuildLogoutRequest: %v", err)
	}
	text := string(document)
	for _, want := range []string{samlProtocolNamespace, samlAssertionNamespace, `Version="2.0"`, `IssueInstant="2026-01-01T12:00:00Z"`, "&lt;", "&amp;"} {
		if !strings.Contains(text, want) {
			t.Fatalf("document %s has no %q", text, want)
		}
	}
	parsed, err := ParseLogoutRequest(text)
	if err != nil {
		t.Fatalf("ParseLogoutRequest: %v", err)
	}
	if parsed.NameIdentifier != `a<b&"c"` || parsed.SessionIndex != "ST-1&2" {
		t.Fatalf("parsed = %#v", parsed)
	}
	if parsed.ID == "" || !strings.HasPrefix(parsed.ID, "_") {
		t.Fatalf("request ID = %q", parsed.ID)
	}
	if _, err := BuildLogoutRequest("", "", now); !errors.Is(err, ErrInvalidLogoutRequest) {
		t.Fatalf("empty build err = %v", err)
	}
	zeroTimeDocument, err := BuildLogoutRequest("alice", "", time.Time{})
	if err != nil {
		t.Fatalf("zero-time build: %v", err)
	}
	if !strings.Contains(string(zeroTimeDocument), "IssueInstant=") {
		t.Fatalf("zero-time document = %s", zeroTimeDocument)
	}

	variants := []string{
		`<LogoutRequest ID="_id" Version="2.0" IssueInstant="2026-01-01T12:00:00Z"><NameIdentifier>alice</NameIdentifier><SessionIndex>ST-1</SessionIndex></LogoutRequest>`,
		`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" ID="_id" Version="2.0" IssueInstant="2026-01-01T12:00:00Z" NotOnOrAfter="2030-01-01T00:00:00Z"><saml:Issuer>https://cas.example.com</saml:Issuer><saml:NameID>alice</saml:NameID><samlp:SessionIndex>ST-1</samlp:SessionIndex></samlp:LogoutRequest>`,
		`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol"><saml:NameIdentifier xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion">alice</saml:NameIdentifier></samlp:LogoutRequest></soap:Body></soap:Envelope>`,
	}
	for _, variant := range variants {
		parsed, err := ParseLogoutRequest(variant)
		if err != nil {
			t.Fatalf("variant %s: %v", variant, err)
		}
		if parsed.NameIdentifier != "alice" && parsed.SessionIndex != "ST-1" {
			t.Fatalf("variant parsed = %#v", parsed)
		}
	}
	saml2, err := ParseLogoutRequest(variants[1])
	if err != nil {
		t.Fatalf("SAML 2 variant: %v", err)
	}
	if saml2.NameIdentifier != "alice" || saml2.SessionIndex != "ST-1" || saml2.Issuer != "https://cas.example.com" {
		t.Fatalf("SAML 2 parsed = %#v", saml2)
	}
	if !saml2.NotOnOrAfter.Equal(time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("NotOnOrAfter = %v", saml2.NotOnOrAfter)
	}
	badTime, err := ParseLogoutRequest(`<LogoutRequest NotOnOrAfter="not-a-time"><SessionIndex>ST-1</SessionIndex></LogoutRequest>`)
	if err != nil {
		t.Fatalf("bad time parse: %v", err)
	}
	if !badTime.NotOnOrAfter.IsZero() {
		t.Fatalf("bad time = %v", badTime.NotOnOrAfter)
	}

	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		encoded := encoding.EncodeToString(document)
		parsed, err := ParseLogoutRequest(encoded)
		if err != nil {
			t.Fatalf("base64 %q: %v", encoded, err)
		}
		if parsed.SessionIndex != "ST-1&2" {
			t.Fatalf("base64 parsed = %#v", parsed)
		}
	}
	withSpaces := strings.ReplaceAll(base64.StdEncoding.EncodeToString(document), "+", " ")
	if _, err := ParseLogoutRequest(withSpaces); err != nil {
		t.Fatalf("space-for-plus base64: %v", err)
	}
}

// TestParseLogoutRequestErrors covers malformed logout requests. | TestParseLogoutRequestErrors
// 覆盖格式错误的登出请求。
func TestParseLogoutRequestErrors(t *testing.T) {
	cases := []string{
		"",
		"not xml",
		"!!!!",
		"<foo/>",
		`<LogoutRequest></LogoutRequest>`,
		`<LogoutRequest><NameIdentifier> </NameIdentifier></LogoutRequest>`,
		`<LogoutRequest><NameIdentifier>alice</NameIdentifier>`,
		strings.Repeat("a", maxProtocolBody+1),
	}
	for _, value := range cases {
		if _, err := ParseLogoutRequest(value); !errors.Is(err, ErrInvalidLogoutRequest) {
			t.Fatalf("ParseLogoutRequest(%q) err = %v, want ErrInvalidLogoutRequest", value, err)
		}
	}
}

// TestBrowserLogoutNotifiesServices covers browser logout with back-channel delivery. |
// TestBrowserLogoutNotifiesServices 覆盖带后端投递的浏览器登出。
func TestBrowserLogoutNotifiesServices(t *testing.T) {
	service, receiver := newLogoutReceiver(t, http.StatusOK, 0)
	server, registry, store, _ := newSLOServer(t, []string{service.URL})
	handler := newTestRouter(t, server)
	cookie, st := loginAndTicket(t, handler, service.URL)
	recorder := serve(t, handler, http.MethodGet, "/cas/logout", nil, cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "Signed out") {
		t.Fatalf("body = %q", recorder.Body.String())
	}
	if _, err := store.Get(t.Context(), st); !errors.Is(err, ErrTicketNotFound) {
		t.Fatalf("ST survived logout: %v", err)
	}
	if registry.Len() != 0 {
		t.Fatalf("sessions survived logout: %d", registry.Len())
	}
	requests := receiver.snapshot()
	if len(requests) != 1 || requests[0].SessionIndex != st {
		t.Fatalf("deliveries = %#v", requests)
	}
}

// TestServiceSessionOutlivesTicket covers the session lifetime following the TGT. |
// TestServiceSessionOutlivesTicket 覆盖会话跟随 TGT 的生命周期。
func TestServiceSessionOutlivesTicket(t *testing.T) {
	service, _ := newLogoutReceiver(t, http.StatusOK, 0)
	server, registry, _, clock := newSLOServer(t, []string{service.URL})
	tgt, st := issueTestTickets(t, server, service.URL)
	session, err := registry.Get(t.Context(), st.ID)
	if err != nil {
		t.Fatalf("Get session: %v", err)
	}
	if !session.ExpiresAt.Equal(tgt.ExpiresAt) {
		t.Fatalf("session expiry = %v, want TGT expiry %v", session.ExpiresAt, tgt.ExpiresAt)
	}
	clock.Advance(2 * server.config.ServiceTicketTimeout)
	if !session.Active(clock.Now()) {
		t.Fatal("session expired with the single-use ticket")
	}
}

// TestServerOwnedSessionRegistry covers registry ownership defaults. | TestServerOwnedSessionRegistry
// 覆盖注册表所有权默认值。
func TestServerOwnedSessionRegistry(t *testing.T) {
	server, err := NewServer(ServerConfig{
		Issuer:        testIssuer,
		Authenticator: AuthenticatorFunc(testAuthenticator),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if server.Sessions() == nil {
		t.Fatal("owned mode has no session registry")
	}
	if _, ok := server.Sessions().(*MemoryServiceSessionRegistry); !ok {
		t.Fatalf("owned registry type = %T", server.Sessions())
	}
	if err := server.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	store := NewMemoryTicketStore()
	t.Cleanup(store.Stop)
	server, err = NewServer(ServerConfig{
		Issuer:        testIssuer,
		Authenticator: AuthenticatorFunc(testAuthenticator),
		TicketStore:   store,
	})
	if err != nil {
		t.Fatalf("NewServer with store: %v", err)
	}
	if server.Sessions() != nil {
		t.Fatalf("caller-supplied store created a session registry: %#v", server.Sessions())
	}
	_ = server.Close()

	registry := NewMemoryServiceSessionRegistry()
	t.Cleanup(func() { _ = registry.Close() })
	server, err = NewServer(ServerConfig{
		Issuer:          testIssuer,
		Authenticator:   AuthenticatorFunc(testAuthenticator),
		SessionRegistry: registry,
	})
	if err != nil {
		t.Fatalf("NewServer with registry: %v", err)
	}
	if server.Sessions() != registry {
		t.Fatal("configured registry was not used")
	}
	_ = server.Close()
}

// TestSLOLogoutWithoutSessionRegistry covers local revocation when back-channel tracking is off. |
// TestSLOLogoutWithoutSessionRegistry 覆盖未启用后端跟踪时的本地撤销。
func TestSLOLogoutWithoutSessionRegistry(t *testing.T) {
	server, store, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	cookie, st := loginAndTicket(t, handler, testAppService)
	document, err := BuildLogoutRequest("", st, server.nowTime())
	if err != nil {
		t.Fatalf("BuildLogoutRequest: %v", err)
	}
	form := url.Values{logoutRequestParameter: {string(document)}}
	recorder := serve(t, handler, http.MethodPost, "/cas/logout", form)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", recorder.Code, recorder.Body.String())
	}
	for _, id := range []string{cookie.Value, st} {
		if _, err := store.Get(t.Context(), id); !errors.Is(err, ErrTicketNotFound) {
			t.Fatalf("ticket %q survived: %v", id, err)
		}
	}
}

// TestSLOLogoutSessionRegistryFallback covers resolving the TGT after the ticket record is gone. |
// TestSLOLogoutSessionRegistryFallback 覆盖票据记录已消失后解析 TGT。
func TestSLOLogoutSessionRegistryFallback(t *testing.T) {
	service, receiver := newLogoutReceiver(t, http.StatusOK, 0)
	server, registry, store, _ := newSLOServer(t, []string{service.URL})
	handler := newTestRouter(t, server)
	cookie, st := loginAndTicket(t, handler, service.URL)
	tgt, err := store.Get(t.Context(), cookie.Value)
	if err != nil {
		t.Fatalf("load TGT: %v", err)
	}
	second, err := server.issueTicket(t.Context(), TicketST, testPrincipal(), "user-1", service.URL, tgt, server.config.ServiceTicketTimeout, false, false)
	if err != nil {
		t.Fatalf("issue second ST: %v", err)
	}
	if err := store.Delete(t.Context(), st); err != nil {
		t.Fatalf("Delete ST: %v", err)
	}
	document, err := BuildLogoutRequest("", st, server.nowTime())
	if err != nil {
		t.Fatalf("BuildLogoutRequest: %v", err)
	}
	form := url.Values{logoutRequestParameter: {string(document)}}
	recorder := serve(t, handler, http.MethodPost, "/cas/logout", form)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", recorder.Code, recorder.Body.String())
	}
	if _, err := store.Get(t.Context(), cookie.Value); !errors.Is(err, ErrTicketNotFound) {
		t.Fatalf("TGT survived: %v", err)
	}
	if _, err := store.Get(t.Context(), second.ID); !errors.Is(err, ErrTicketNotFound) {
		t.Fatalf("second ST survived: %v", err)
	}
	if registry.Len() != 0 {
		t.Fatalf("sessions survived: %d", registry.Len())
	}
	if requests := receiver.snapshot(); len(requests) != 1 || requests[0].SessionIndex != second.ID {
		t.Fatalf("deliveries = %#v", requests)
	}
}

// TestMemoryServiceSessionRegistryLifecycle covers the memory registry contract. |
// TestMemoryServiceSessionRegistryLifecycle 覆盖内存注册表契约。
func TestMemoryServiceSessionRegistryLifecycle(t *testing.T) {
	registry := NewMemoryServiceSessionRegistry()
	if registry.sessions == nil || registry.byTGT == nil || registry.byUser == nil {
		t.Fatal("constructor left an index nil")
	}
	registry.SetClock(nil)
	if registry.clock == nil {
		t.Fatal("SetClock(nil) cleared the clock")
	}
	base := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: base}
	registry.SetClock(clock.Now)
	if got := registry.clock(); !got.Equal(base) {
		t.Fatalf("clock = %v", got)
	}
	if err := registry.Register(t.Context(), nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil register err = %v", err)
	}
	if err := registry.Register(t.Context(), &ServiceSession{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty index register err = %v", err)
	}
	first := &ServiceSession{SessionIndex: "ST-1", User: "alice", UserID: "user-1", Service: "https://a", TGTID: "TGT-1", IssuedAt: base, ExpiresAt: base.Add(time.Hour)}
	second := &ServiceSession{SessionIndex: "ST-2", User: "bob", UserID: "user-2", Service: "https://b", TGTID: "TGT-1", IssuedAt: base.Add(time.Minute), ExpiresAt: base.Add(time.Hour)}
	third := &ServiceSession{SessionIndex: "ST-3", User: "alice", UserID: "user-1", Service: "https://c", TGTID: "TGT-2", IssuedAt: base, ExpiresAt: base.Add(time.Hour)}
	for _, session := range []*ServiceSession{first, second, third} {
		if err := registry.Register(t.Context(), session); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
	if registry.Len() != 3 {
		t.Fatalf("Len = %d, want 3", registry.Len())
	}
	got, err := registry.Get(t.Context(), "ST-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.TicketID != "ST-1" || got.User != "alice" || got.UserID != "user-1" {
		t.Fatalf("Get = %#v", got)
	}
	got.User = "mutated"
	again, _ := registry.Get(t.Context(), "ST-1")
	if again.User != "alice" {
		t.Fatal("Get returned an aliased record")
	}
	if _, err := registry.Get(t.Context(), ""); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("empty Get err = %v", err)
	}
	if _, err := registry.Get(t.Context(), "ST-missing"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("missing Get err = %v", err)
	}
	byTGT, _ := registry.ListByTGT(t.Context(), "TGT-1")
	if len(byTGT) != 2 || byTGT[0].SessionIndex != "ST-1" || byTGT[1].SessionIndex != "ST-2" {
		t.Fatalf("ListByTGT = %#v", byTGT)
	}
	byUser, _ := registry.ListByUser(t.Context(), "alice")
	if len(byUser) != 2 {
		t.Fatalf("ListByUser(alice) = %#v", byUser)
	}
	byID, _ := registry.ListByUser(t.Context(), "user-1")
	if len(byID) != 2 {
		t.Fatalf("ListByUser(user-1) = %#v", byID)
	}
	if missing, _ := registry.ListByUser(t.Context(), "nobody"); missing != nil {
		t.Fatalf("ListByUser(nobody) = %#v", missing)
	}
	if missing, _ := registry.ListByTGT(t.Context(), "TGT-missing"); missing != nil {
		t.Fatalf("ListByTGT(missing) = %#v", missing)
	}

	replacement := &ServiceSession{SessionIndex: "ST-1", User: "bob", UserID: "user-2", Service: "https://a", TGTID: "TGT-9", IssuedAt: base, ExpiresAt: base.Add(time.Hour)}
	if err := registry.Register(t.Context(), replacement); err != nil {
		t.Fatalf("replacement Register: %v", err)
	}
	oldTGT, _ := registry.ListByTGT(t.Context(), "TGT-1")
	if len(oldTGT) != 1 || oldTGT[0].SessionIndex != "ST-2" {
		t.Fatalf("old TGT index = %#v", oldTGT)
	}
	aliceSessions, _ := registry.ListByUser(t.Context(), "alice")
	if len(aliceSessions) != 1 || aliceSessions[0].SessionIndex != "ST-3" {
		t.Fatalf("old user index = %#v", aliceSessions)
	}
	if err := registry.Delete(t.Context(), "ST-unknown"); err != nil {
		t.Fatalf("Delete unknown: %v", err)
	}
	if err := registry.Delete(t.Context(), "ST-2"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := registry.Get(t.Context(), "ST-2"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("deleted session err = %v", err)
	}
	removed, err := registry.DeleteByUser(t.Context(), "bob")
	if err != nil || len(removed) != 1 || removed[0].SessionIndex != "ST-1" {
		t.Fatalf("DeleteByUser = %#v, %v", removed, err)
	}
	if registry.Len() != 1 {
		t.Fatalf("Len after DeleteByUser = %d", registry.Len())
	}
	removed, err = registry.DeleteByTGT(t.Context(), "TGT-2")
	if err != nil || len(removed) != 1 || removed[0].SessionIndex != "ST-3" {
		t.Fatalf("DeleteByTGT = %#v, %v", removed, err)
	}
	if registry.Len() != 0 {
		t.Fatalf("Len = %d, want 0", registry.Len())
	}
	if removed, err := registry.DeleteByTGT(t.Context(), "TGT-2"); err != nil || len(removed) != 0 {
		t.Fatalf("second DeleteByTGT = %#v, %v", removed, err)
	}
	if removed, err := registry.DeleteByUser(t.Context(), "nobody"); err != nil || len(removed) != 0 {
		t.Fatalf("DeleteByUser(nobody) = %#v, %v", removed, err)
	}
}

// TestServiceSessionHelpers covers Clone, Active and expiry cleanup. | TestServiceSessionHelpers
// 覆盖 Clone、Active 与过期清理。
func TestServiceSessionHelpers(t *testing.T) {
	var session *ServiceSession
	if session.Clone() != nil {
		t.Fatal("nil Clone returned a value")
	}
	if session.Active(time.Now()) {
		t.Fatal("nil session is active")
	}
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		session *ServiceSession
		active  bool
	}{
		{nil, false},
		{&ServiceSession{}, true},
		{&ServiceSession{ExpiresAt: now.Add(time.Hour)}, true},
		{&ServiceSession{ExpiresAt: now}, false},
		{&ServiceSession{ExpiresAt: now.Add(-time.Hour)}, false},
	}
	for _, tc := range cases {
		if got := tc.session.Active(now); got != tc.active {
			t.Fatalf("Active(%#v) = %v, want %v", tc.session, got, tc.active)
		}
	}

	registry := NewMemoryServiceSessionRegistry()
	if err := registry.Register(t.Context(), &ServiceSession{SessionIndex: "ST-past", ExpiresAt: now.Add(-time.Minute)}); err != nil {
		t.Fatalf("Register past: %v", err)
	}
	if err := registry.Register(t.Context(), &ServiceSession{SessionIndex: "ST-future", ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatalf("Register future: %v", err)
	}
	if err := registry.Register(t.Context(), &ServiceSession{SessionIndex: "ST-never"}); err != nil {
		t.Fatalf("Register zero: %v", err)
	}
	removed, err := registry.DeleteExpired(t.Context(), now)
	if err != nil || removed != 1 {
		t.Fatalf("DeleteExpired = %d, %v", removed, err)
	}
	if registry.Len() != 2 {
		t.Fatalf("Len = %d, want 2", registry.Len())
	}
	if _, err := registry.Get(t.Context(), "ST-past"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("past session survived: %v", err)
	}
}

// TestMemoryServiceSessionRegistryGC covers the janitor. | TestMemoryServiceSessionRegistryGC 覆盖清理器。
func TestMemoryServiceSessionRegistryGC(t *testing.T) {
	registry := NewMemoryServiceSessionRegistry()
	registry.StartGC(5 * time.Millisecond)
	registry.StartGC(5 * time.Millisecond)
	if err := registry.Register(t.Context(), &ServiceSession{SessionIndex: "ST-expired", ExpiresAt: time.Now().Add(-time.Second)}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for registry.Len() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if registry.Len() != 0 {
		t.Fatalf("janitor did not remove the expired session")
	}
	registry.Stop()
	registry.Stop()
	if err := registry.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	registry.StartGC(time.Millisecond)
	if err := registry.Register(t.Context(), &ServiceSession{SessionIndex: "ST-after-stop", ExpiresAt: time.Now().Add(-time.Second)}); err != nil {
		t.Fatalf("Register after stop: %v", err)
	}
	if registry.Len() != 1 {
		t.Fatalf("stopped janitor removed a session")
	}
}
