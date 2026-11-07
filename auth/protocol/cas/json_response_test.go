package cas

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// decodeJSONEnvelope decodes a JSON protocol body. | decodeJSONEnvelope 解码 JSON 协议正文。
func decodeJSONEnvelope(t *testing.T, body string) jsonValidationEnvelope {
	t.Helper()
	var envelope jsonValidationEnvelope
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		t.Fatalf("JSON body %q: %v", body, err)
	}
	return envelope
}

// TestValidationJSONEndpoints covers JSON success on every validation endpoint. |
// TestValidationJSONEndpoints 覆盖每个校验端点的 JSON 成功响应。
func TestValidationJSONEndpoints(t *testing.T) {
	server, _, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	endpoints := []string{"serviceValidate", "p3/serviceValidate", "proxyValidate", "p3/proxyValidate"}
	for _, endpoint := range endpoints {
		t.Run(endpoint, func(t *testing.T) {
			_, st := issueTestTickets(t, server, testAppService)
			extra := url.Values{"format": {"json"}}
			recorder := serve(t, handler, http.MethodGet, validateURL(endpoint, st.ID, testAppService, extra), nil)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body: %s", recorder.Code, recorder.Body.String())
			}
			if contentType := recorder.Header().Get("Content-Type"); contentType != casJSONContentType {
				t.Fatalf("Content-Type = %q, want %q", contentType, casJSONContentType)
			}
			if cache := recorder.Header().Get("Cache-Control"); cache != "no-store" {
				t.Fatalf("Cache-Control = %q, want no-store", cache)
			}
			envelope := decodeJSONEnvelope(t, recorder.Body.String())
			if envelope.AuthenticationSuccess == nil || envelope.AuthenticationFailure != nil {
				t.Fatalf("envelope = %#v", envelope)
			}
			success := envelope.AuthenticationSuccess
			if success.User != "alice" {
				t.Fatalf("user = %q, want alice", success.User)
			}
			if got := success.Attributes["email"]; len(got) != 1 || got[0] != "alice@example.com" {
				t.Fatalf("email attribute = %#v", got)
			}
			if got := success.Attributes["role"]; len(got) != 1 || got[0] != "admin" {
				t.Fatalf("role attribute = %#v", got)
			}
			if success.ProxyGrantingTicket != "" || len(success.Proxies) != 0 {
				t.Fatalf("unexpected proxy fields: %#v", success)
			}
		})
	}
}

// TestValidationJSONFailure covers JSON failures, including replay and missing parameters. |
// TestValidationJSONFailure 覆盖 JSON 失败，包括重放与缺少参数。
func TestValidationJSONFailure(t *testing.T) {
	server, _, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	_, st := issueTestTickets(t, server, testAppService)
	extra := url.Values{"format": {"json"}}
	first := serve(t, handler, http.MethodGet, validateURL("serviceValidate", st.ID, testAppService, extra), nil)
	if code := decodeJSONEnvelope(t, first.Body.String()).AuthenticationSuccess.User; code != "alice" {
		t.Fatalf("first validation user = %q", code)
	}
	replay := serve(t, handler, http.MethodGet, validateURL("serviceValidate", st.ID, testAppService, extra), nil)
	if replay.Code != http.StatusOK {
		t.Fatalf("replay status = %d, want 200", replay.Code)
	}
	envelope := decodeJSONEnvelope(t, replay.Body.String())
	if envelope.AuthenticationFailure == nil || envelope.AuthenticationSuccess != nil {
		t.Fatalf("replay envelope = %#v", envelope)
	}
	if envelope.AuthenticationFailure.Code != ErrorCodeInvalidTicket {
		t.Fatalf("replay code = %q", envelope.AuthenticationFailure.Code)
	}
	if envelope.AuthenticationFailure.Description == "" {
		t.Fatal("replay description is empty")
	}

	missing := serve(t, handler, http.MethodGet, "/cas/serviceValidate?format=json&service="+url.QueryEscape(testAppService), nil)
	if missing.Code != http.StatusOK {
		t.Fatalf("missing ticket status = %d, want 200", missing.Code)
	}
	envelope = decodeJSONEnvelope(t, missing.Body.String())
	if envelope.AuthenticationFailure == nil || envelope.AuthenticationFailure.Code != ErrorCodeInvalidRequest {
		t.Fatalf("missing ticket envelope = %#v", envelope)
	}
}

// TestValidationJSONProxyFields covers proxyGrantingTicket and proxies in the JSON schema. |
// TestValidationJSONProxyFields 覆盖 JSON 模式中的 proxyGrantingTicket 与 proxies。
func TestValidationJSONProxyFields(t *testing.T) {
	callback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("pgtId") == "" || r.URL.Query().Get("pgtIou") == "" {
			t.Errorf("callback query = %v", r.URL.Query())
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(callback.Close)
	server, store, _ := newTestServer(t, func(config *ServerConfig) {
		config.AllowInsecurePGTCallback = true
		config.ServiceRegistry = NewAllowAllServiceRegistry()
	})
	handler := newTestRouter(t, server)
	_, st := issueTestTickets(t, server, testAppService)
	extra := url.Values{"format": {"json"}, "pgtUrl": {callback.URL + "/pgt"}}
	recorder := serve(t, handler, http.MethodGet, validateURL("p3/serviceValidate", st.ID, testAppService, extra), nil)
	envelope := decodeJSONEnvelope(t, recorder.Body.String())
	if envelope.AuthenticationSuccess == nil {
		t.Fatalf("body = %s", recorder.Body.String())
	}
	pgt := envelope.AuthenticationSuccess.ProxyGrantingTicket
	if !strings.HasPrefix(pgt, TicketPrefixPGT) {
		t.Fatalf("proxyGrantingTicket = %q, want PGT- prefix", pgt)
	}
	if _, err := store.Get(context.Background(), pgt); err != nil {
		t.Fatalf("issued PGT missing from store: %v", err)
	}

	cases := []struct {
		endpoint string
		parent   TicketType
	}{
		{"proxyValidate", TicketST},
		{"p3/proxyValidate", TicketST},
		{"p3/proxyValidate", TicketPT},
	}
	for _, tc := range cases {
		_, st := issueTestTickets(t, server, testAppService)
		parent := st
		if tc.parent == TicketPT {
			pt, err := server.issueTicket(context.Background(), TicketPT, testPrincipal(), "user-1", testAPIEndpoint, st, server.config.ProxyTicketTimeout, false, false)
			if err != nil {
				t.Fatalf("issue PT: %v", err)
			}
			parent = pt
			pt.ProxyChain = []string{"https://proxy.example.com/cb"}
			if err := store.Save(context.Background(), pt); err != nil {
				t.Fatalf("save PT: %v", err)
			}
		}
		proxyExtra := url.Values{"format": {"json"}}
		recorder := serve(t, handler, http.MethodGet, validateURL(tc.endpoint, parent.ID, parent.Service, proxyExtra), nil)
		envelope := decodeJSONEnvelope(t, recorder.Body.String())
		if envelope.AuthenticationSuccess == nil {
			t.Fatalf("%s body = %s", tc.endpoint, recorder.Body.String())
		}
		if tc.parent == TicketPT {
			if len(envelope.AuthenticationSuccess.Proxies) != 1 ||
				envelope.AuthenticationSuccess.Proxies[0] != "https://proxy.example.com/cb" {
				t.Fatalf("proxies = %#v", envelope.AuthenticationSuccess.Proxies)
			}
		}
	}
}

// TestValidationJSONNegotiation covers format precedence and Accept quality selection. |
// TestValidationJSONNegotiation 覆盖 format 优先级与 Accept 质量选择。
func TestValidationJSONNegotiation(t *testing.T) {
	server, _, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	cases := []struct {
		name   string
		accept string
		format string
		json   bool
	}{
		{"no accept", "", "", false},
		{"json accept", "application/json", "", true},
		{"json suffix", "application/problem+json", "", true},
		{"json preferred", "application/json;q=0.9, application/xml;q=0.5", "", true},
		{"xml preferred", "application/xml;q=0.9, application/json;q=0.1", "", false},
		{"wildcard", "*/*", "", false},
		{"html only", "text/html", "", false},
		{"zero quality", "application/json;q=0", "", false},
		{"invalid quality", "application/json;q=abc", "", false},
		{"equal quality json first", "application/json, application/xml", "", true},
		{"equal quality xml first", "application/xml, application/json", "", false},
		{"uppercase parameter", "application/json;Q=0.5, application/xml;q=0.4", "", true},
		{"format json wins", "application/xml", "json", true},
		{"format uppercase json", "", "JSON", true},
		{"format xml wins", "application/json", "xml", false},
		{"unknown format keeps xml", "application/json", "yaml", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, st := issueTestTickets(t, server, testAppService)
			target := validateURL("p3/serviceValidate", st.ID, testAppService, nil)
			if tc.format != "" {
				target += "&format=" + url.QueryEscape(tc.format)
			}
			request := httptest.NewRequest(http.MethodGet, target, nil)
			if tc.accept != "" {
				request.Header.Set("Accept", tc.accept)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			isJSON := strings.HasPrefix(recorder.Header().Get("Content-Type"), "application/json")
			if isJSON != tc.json {
				t.Fatalf("Accept %q format %q: Content-Type = %q, want json=%v",
					tc.accept, tc.format, recorder.Header().Get("Content-Type"), tc.json)
			}
		})
	}
}

// TestValidateCAS10JSON covers the explicit JSON extension of /validate and the unchanged text
// default. | TestValidateCAS10JSON 覆盖 /validate 的显式 JSON 扩展与不变的文本默认值。
func TestValidateCAS10JSON(t *testing.T) {
	server, _, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	ticketURL := func(ticket string, extra url.Values) string {
		return validateURL("validate", ticket, testAppService, extra)
	}
	_, st := issueTestTickets(t, server, testAppService)
	accept := httptest.NewRequest(http.MethodGet, ticketURL(st.ID, nil), nil)
	accept.Header.Set("Accept", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, accept)
	if got := recorder.Body.String(); got != "yes\nalice\n" {
		t.Fatalf("default /validate body = %q", got)
	}

	_, st = issueTestTickets(t, server, testAppService)
	jsonRecorder := serve(t, handler, http.MethodGet, ticketURL(st.ID, url.Values{"format": {"json"}}), nil)
	envelope := decodeJSONEnvelope(t, jsonRecorder.Body.String())
	if envelope.AuthenticationSuccess == nil || envelope.AuthenticationSuccess.User != "alice" {
		t.Fatalf("JSON /validate body = %s", jsonRecorder.Body.String())
	}

	jsonReplay := serve(t, handler, http.MethodGet, ticketURL(st.ID, url.Values{"format": {"json"}}), nil)
	envelope = decodeJSONEnvelope(t, jsonReplay.Body.String())
	if envelope.AuthenticationFailure == nil || envelope.AuthenticationFailure.Code != ErrorCodeInvalidTicket {
		t.Fatalf("JSON /validate failure = %s", jsonReplay.Body.String())
	}

	_, st = issueTestTickets(t, server, testAppService)
	xmlRecorder := serve(t, handler, http.MethodGet, ticketURL(st.ID, url.Values{"format": {"xml"}}), nil)
	if got := xmlRecorder.Body.String(); got != "yes\nalice\n" {
		t.Fatalf("format=xml /validate body = %q", got)
	}
}

// TestJSONAttributesUnmarshal covers the tolerant attribute decoder. | TestJSONAttributesUnmarshal
// 覆盖宽容的属性解码器。
func TestJSONAttributesUnmarshal(t *testing.T) {
	var attributes jsonAttributes
	if err := json.Unmarshal([]byte(`{"role":["admin","user"],"email":"a@example.com"}`), &attributes); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got := attributes["role"]; len(got) != 2 || got[0] != "admin" || got[1] != "user" {
		t.Fatalf("role = %#v", got)
	}
	if got := attributes["email"]; len(got) != 1 || got[0] != "a@example.com" {
		t.Fatalf("email = %#v", got)
	}
	attributes = jsonAttributes{"stale": {"value"}}
	if err := json.Unmarshal([]byte("null"), &attributes); err != nil {
		t.Fatalf("null Unmarshal: %v", err)
	}
	if attributes != nil {
		t.Fatalf("null attributes = %#v", attributes)
	}
	if err := json.Unmarshal([]byte(`{"role":123}`), &attributes); err == nil {
		t.Fatal("numeric attribute was accepted")
	}
	if err := json.Unmarshal([]byte(`["role"]`), &attributes); err == nil {
		t.Fatal("array attribute object was accepted")
	}
}

// TestWriteCASJSONMarshalFailure covers the encoder failure path. | TestWriteCASJSONMarshalFailure
// 覆盖编码失败路径。
func TestWriteCASJSONMarshalFailure(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeCASJSON(recorder, make(chan int))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", recorder.Code)
	}
	if contentType := recorder.Header().Get("Content-Type"); contentType != casJSONContentType {
		t.Fatalf("Content-Type = %q", contentType)
	}
	envelope := decodeJSONEnvelope(t, recorder.Body.String())
	if envelope.AuthenticationFailure == nil || envelope.AuthenticationFailure.Code != ErrorCodeInternalError {
		t.Fatalf("envelope = %#v", envelope)
	}
}

// TestWriteValidationSuccessJSONDefaults covers the nil result guard. | TestWriteValidationSuccessJSONDefaults
// 覆盖空结果保护。
func TestWriteValidationSuccessJSONDefaults(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeValidationSuccessJSON(recorder, nil)
	envelope := decodeJSONEnvelope(t, recorder.Body.String())
	if envelope.AuthenticationSuccess == nil || envelope.AuthenticationSuccess.User != "" {
		t.Fatalf("envelope = %#v", envelope)
	}
}

// TestValidationResponseFormatNil covers the nil request guard. | TestValidationResponseFormatNil
// 覆盖空请求保护。
func TestValidationResponseFormatNil(t *testing.T) {
	if got := validationResponseFormat(nil, false); got != validationFormatXML {
		t.Fatalf("nil request format = %v", got)
	}
}

// TestParseAcceptPart covers every quality parsing branch. | TestParseAcceptPart 覆盖每个质量解析分支。
func TestParseAcceptPart(t *testing.T) {
	cases := []struct {
		part    string
		media   string
		quality float64
	}{
		{"application/json", "application/json", 1},
		{" Application/JSON ; charset=utf-8 ", "application/json", 1},
		{"application/xml;q=0.5", "application/xml", 0.5},
		{"application/xml;q=abc", "application/xml", 0},
		{"application/xml;q=2", "application/xml", 1},
		{"application/xml;q=-1", "application/xml", 0},
		{"application/xml;q=", "application/xml", 0},
		{"application/xml;level=1;q=0.25", "application/xml", 0.25},
	}
	for _, tc := range cases {
		media, quality := parseAcceptPart(tc.part)
		if media != tc.media || quality != tc.quality {
			t.Fatalf("parseAcceptPart(%q) = %q, %v; want %q, %v", tc.part, media, quality, tc.media, tc.quality)
		}
	}
}

// TestPrefersJSON covers wildcard and empty Accept handling. | TestPrefersJSON 覆盖通配符与空 Accept 处理。
func TestPrefersJSON(t *testing.T) {
	cases := []struct {
		accept string
		want   bool
	}{
		{"", false},
		{"   ", false},
		{"application/json", true},
		{"application/ld+json", true},
		{"application/json, */*", true},
		{"application/json;q=0.2, application/xml;q=0.8", false},
		{"application/*, text/html", false},
		{"text/xml", false},
	}
	for _, tc := range cases {
		if got := prefersJSON(tc.accept); got != tc.want {
			t.Fatalf("prefersJSON(%q) = %v, want %v", tc.accept, got, tc.want)
		}
	}
}

// TestJSONValidationKeepsXMLDefault guards the existing XML contract. | TestJSONValidationKeepsXMLDefault
// 守护既有 XML 契约。
func TestJSONValidationKeepsXMLDefault(t *testing.T) {
	server, _, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	_, st := issueTestTickets(t, server, testAppService)
	recorder := serve(t, handler, http.MethodGet, validateURL("p3/serviceValidate", st.ID, testAppService, nil), nil)
	if contentType := recorder.Header().Get("Content-Type"); contentType != casContentType {
		t.Fatalf("Content-Type = %q, want %q", contentType, casContentType)
	}
	if !strings.Contains(recorder.Body.String(), "<cas:serviceResponse") {
		t.Fatalf("body = %s", recorder.Body.String())
	}
}
