package cas

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// newClientFixture starts a CAS server and a client pointed at it. | newClientFixture 启动 CAS
// 服务端以及指向它的客户端。
func newClientFixture(t *testing.T) (*Server, *Client, *httptest.Server) {
	t.Helper()
	server, _, _ := newTestServer(t, func(config *ServerConfig) {
		config.ServiceRegistry = NewAllowAllServiceRegistry()
	})
	httpServer := httptest.NewServer(server.HTTPHandler("/cas"))
	t.Cleanup(httpServer.Close)
	client, err := NewClient(ClientConfig{ServerURL: httpServer.URL + "/cas", ServiceURL: testAppService})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return server, client, httpServer
}

func TestClientURLs(t *testing.T) {
	client, err := NewClient(ClientConfig{ServerURL: "https://cas.example.com/cas/"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	login := client.LoginURL("https://app.example.com/callback?x=1&y=2")
	parsed, err := url.Parse(login)
	if err != nil {
		t.Fatalf("LoginURL: %v", err)
	}
	if parsed.Scheme+"://"+parsed.Host+parsed.Path != "https://cas.example.com/cas/login" {
		t.Fatalf("LoginURL path = %q", login)
	}
	if parsed.Query().Get("service") != "https://app.example.com/callback?x=1&y=2" {
		t.Fatalf("LoginURL service = %q", parsed.Query().Get("service"))
	}
	if got := client.LoginURL(""); got != "https://cas.example.com/cas/login" {
		t.Fatalf("LoginURL with no service = %q", got)
	}
	logout := client.LogoutURL("https://app.example.com/bye")
	if !strings.Contains(logout, "/cas/logout?") || !strings.Contains(logout, "service=https%3A%2F%2Fapp.example.com%2Fbye") {
		t.Fatalf("LogoutURL = %q", logout)
	}
}

func TestClientNewClientValidation(t *testing.T) {
	cases := []string{"", "not-a-url", "/relative/path", "ftp://cas.example.com"}
	for _, serverURL := range cases {
		if _, err := NewClient(ClientConfig{ServerURL: serverURL}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("NewClient(%q) error = %v, want ErrInvalidConfig", serverURL, err)
		}
	}
}

func TestClientValidate(t *testing.T) {
	server, client, _ := newClientFixture(t)
	_, st := issueTestTickets(t, server, testAppService)
	response, err := client.Validate(context.Background(), st.ID, "")
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !response.Success || response.User != "alice" {
		t.Fatalf("Validate = %#v", response)
	}
	if got := response.Attributes["email"]; len(got) != 1 || got[0] != "alice@example.com" {
		t.Fatalf("Validate attributes = %#v", response.Attributes)
	}
	if len(response.Raw) == 0 || response.Code != "" || response.Message != "" {
		t.Fatalf("Validate raw/code = %#v", response)
	}
	replay, err := client.Validate(context.Background(), st.ID, testAppService)
	if err != nil {
		t.Fatalf("replay Validate: %v", err)
	}
	if replay.Success || replay.Code != ErrorCodeInvalidTicket || replay.Message == "" {
		t.Fatalf("replay = %#v", replay)
	}
}

func TestClientValidateV3(t *testing.T) {
	server, client, _ := newClientFixture(t)
	_, st := issueTestTickets(t, server, testAppService)
	response, err := client.ValidateV3(context.Background(), st.ID, testAppService)
	if err != nil {
		t.Fatalf("ValidateV3: %v", err)
	}
	if !response.Success || response.User != "alice" {
		t.Fatalf("ValidateV3 = %#v", response)
	}
	if got := response.Attributes["role"]; len(got) != 1 || got[0] != "admin" {
		t.Fatalf("ValidateV3 attributes = %#v", response.Attributes)
	}
}

func TestClientValidateCAS10(t *testing.T) {
	server, client, _ := newClientFixture(t)
	_, st := issueTestTickets(t, server, testAppService)
	response, err := client.ValidateCAS10(context.Background(), st.ID, testAppService)
	if err != nil {
		t.Fatalf("ValidateCAS10: %v", err)
	}
	if !response.Success || response.User != "alice" {
		t.Fatalf("ValidateCAS10 = %#v", response)
	}
	replay, err := client.ValidateCAS10(context.Background(), st.ID, testAppService)
	if err != nil {
		t.Fatalf("replay ValidateCAS10: %v", err)
	}
	if replay.Success || replay.Code != ErrorCodeInvalidTicket {
		t.Fatalf("replay ValidateCAS10 = %#v", replay)
	}
}

func TestClientValidateServiceMismatch(t *testing.T) {
	server, client, _ := newClientFixture(t)
	_, st := issueTestTickets(t, server, testAppService)
	response, err := client.Validate(context.Background(), st.ID, testOtherService)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if response.Success || response.Code != ErrorCodeInvalidService {
		t.Fatalf("mismatch response = %#v", response)
	}
}

func TestClientProxy(t *testing.T) {
	server, client, _ := newClientFixture(t)
	principal := testPrincipal()
	tgt, err := server.issueTicket(context.Background(), TicketTGT, principal, principal.Subject, "", nil, server.config.TGTTimeout, false, false)
	if err != nil {
		t.Fatalf("issue TGT: %v", err)
	}
	pgt, err := server.issueTicket(context.Background(), TicketPGT, principal, principal.Subject, "https://proxy.example.com/cb", tgt, server.config.ProxyGrantingTicketTimeout, false, false)
	if err != nil {
		t.Fatalf("issue PGT: %v", err)
	}
	proxyResponse, err := client.Proxy(context.Background(), pgt.ID, testAPIEndpoint)
	if err != nil {
		t.Fatalf("Proxy: %v", err)
	}
	if !proxyResponse.Success || !strings.HasPrefix(proxyResponse.ProxyTicket, TicketPrefixPT) {
		t.Fatalf("Proxy = %#v", proxyResponse)
	}
	validation, err := client.ProxyValidate(context.Background(), proxyResponse.ProxyTicket, testAPIEndpoint)
	if err != nil {
		t.Fatalf("ProxyValidate: %v", err)
	}
	if !validation.Success || validation.User != "alice" {
		t.Fatalf("ProxyValidate = %#v", validation)
	}
	if len(validation.Proxies) != 1 || validation.Proxies[0] != "https://proxy.example.com/cb" {
		t.Fatalf("ProxyValidate proxies = %#v", validation.Proxies)
	}
	failure, err := client.Proxy(context.Background(), "PGT-unknown", testAPIEndpoint)
	if err != nil {
		t.Fatalf("Proxy unknown: %v", err)
	}
	if failure.Success || failure.Code != ErrorCodeInvalidTicket {
		t.Fatalf("Proxy unknown = %#v", failure)
	}
}

func TestClientParsesCAS10TextFallback(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("yes\ncarol\n"))
	}))
	defer httpServer.Close()
	client, err := NewClient(ClientConfig{ServerURL: httpServer.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	response, err := client.Validate(context.Background(), "ST-any", testAppService)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !response.Success || response.User != "carol" {
		t.Fatalf("fallback response = %#v", response)
	}
}

func TestClientRejectsBadResponses(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		wantErr error
	}{
		{"http error", http.StatusInternalServerError, "boom", ErrClientRequest},
		{"malformed xml", http.StatusOK, "<cas:serviceResponse", ErrInvalidResponse},
		{"empty", http.StatusOK, "", ErrInvalidResponse},
		{"unknown envelope", http.StatusOK, "<cas:serviceResponse xmlns:cas=\"http://www.yale.edu/tp/cas\"></cas:serviceResponse>", ErrInvalidResponse},
		{"bad text", http.StatusOK, "maybe\nalice", ErrInvalidResponse},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer httpServer.Close()
			client, err := NewClient(ClientConfig{ServerURL: httpServer.URL})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			if _, err := client.Validate(context.Background(), "ST-any", testAppService); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Validate error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestClientRefusesRedirects(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://elsewhere.example.com/", http.StatusFound)
	}))
	defer httpServer.Close()
	client, err := NewClient(ClientConfig{ServerURL: httpServer.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := client.Validate(ctx, "ST-any", testAppService); !errors.Is(err, ErrClientRequest) {
		t.Fatalf("redirect Validate error = %v, want ErrClientRequest", err)
	}
}

func TestClientMissingService(t *testing.T) {
	client, err := NewClient(ClientConfig{ServerURL: "https://cas.example.com/cas"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Validate(context.Background(), "ST-any", ""); !errors.Is(err, ErrInvalidService) {
		t.Fatalf("Validate without service error = %v, want ErrInvalidService", err)
	}
}

func TestClientJSONValidation(t *testing.T) {
	server, _, _ := newTestServer(t, func(config *ServerConfig) {
		config.ServiceRegistry = NewAllowAllServiceRegistry()
	})
	httpServer := httptest.NewServer(server.HTTPHandler("/cas"))
	t.Cleanup(httpServer.Close)
	client, err := NewClient(ClientConfig{
		ServerURL:        httpServer.URL + "/cas",
		ServiceURL:       testAppService,
		ValidationFormat: "json",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, st := issueTestTickets(t, server, testAppService)
	response, err := client.Validate(context.Background(), st.ID, "")
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !response.Success || response.User != "alice" {
		t.Fatalf("Validate = %#v", response)
	}
	if got := response.Attributes["email"]; len(got) != 1 || got[0] != "alice@example.com" {
		t.Fatalf("Validate attributes = %#v", response.Attributes)
	}
	if strings.TrimSpace(string(response.Raw))[0] != '{' {
		t.Fatalf("Validate raw is not JSON: %s", response.Raw)
	}
	replay, err := client.Validate(context.Background(), st.ID, testAppService)
	if err != nil {
		t.Fatalf("replay Validate: %v", err)
	}
	if replay.Success || replay.Code != ErrorCodeInvalidTicket || replay.Message == "" {
		t.Fatalf("replay = %#v", replay)
	}

	_, st = issueTestTickets(t, server, testAppService)
	response, err = client.ValidateV3(context.Background(), st.ID, "")
	if err != nil {
		t.Fatalf("ValidateV3: %v", err)
	}
	if !response.Success || len(response.Attributes["role"]) != 1 {
		t.Fatalf("ValidateV3 = %#v", response)
	}
	_, st = issueTestTickets(t, server, testAppService)
	response, err = client.ProxyValidate(context.Background(), st.ID, "")
	if err != nil {
		t.Fatalf("ProxyValidate: %v", err)
	}
	if !response.Success || response.User != "alice" {
		t.Fatalf("ProxyValidate = %#v", response)
	}
	_, st = issueTestTickets(t, server, testAppService)
	response, err = client.ProxyValidateV3(context.Background(), st.ID, "")
	if err != nil {
		t.Fatalf("ProxyValidateV3: %v", err)
	}
	if !response.Success || len(response.Attributes["role"]) != 1 {
		t.Fatalf("ProxyValidateV3 = %#v", response)
	}
	_, st = issueTestTickets(t, server, testAppService)
	response, err = client.ValidateCAS10(context.Background(), st.ID, "")
	if err != nil {
		t.Fatalf("ValidateCAS10: %v", err)
	}
	if !response.Success || response.User != "alice" {
		t.Fatalf("ValidateCAS10 = %#v", response)
	}
	if strings.HasPrefix(strings.TrimSpace(string(response.Raw)), "{") {
		t.Fatalf("ValidateCAS10 negotiated JSON: %s", response.Raw)
	}
}

func TestClientValidationFormatConfig(t *testing.T) {
	cases := []struct {
		format string
		want   string
	}{
		{"", ""},
		{"xml", ""},
		{"XML", ""},
		{"json", "json"},
		{" JSON ", "json"},
	}
	for _, tc := range cases {
		client, err := NewClient(ClientConfig{ServerURL: "https://cas.example.com/cas", ValidationFormat: tc.format})
		if err != nil {
			t.Fatalf("NewClient(%q): %v", tc.format, err)
		}
		if got := client.Config().ValidationFormat; got != tc.want {
			t.Fatalf("format %q normalized to %q, want %q", tc.format, got, tc.want)
		}
	}
	if _, err := NewClient(ClientConfig{ServerURL: "https://cas.example.com/cas", ValidationFormat: "yaml"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid format error = %v, want ErrInvalidConfig", err)
	}
}

func TestClientJSONRequestAndXMLFallback(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("format"); got != "json" {
			t.Errorf("format = %q, want json", got)
		}
		if accept := r.Header.Get("Accept"); !strings.Contains(accept, "application/json") {
			t.Errorf("Accept = %q, want application/json", accept)
		}
		w.Header().Set("Content-Type", casContentType)
		_, _ = w.Write([]byte(`<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationSuccess><cas:user>alice</cas:user></cas:authenticationSuccess></cas:serviceResponse>`))
	}))
	t.Cleanup(httpServer.Close)
	client, err := NewClient(ClientConfig{
		ServerURL:        httpServer.URL,
		ServiceURL:       testAppService,
		ValidationFormat: "json",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	response, err := client.Validate(context.Background(), "ST-any", "")
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !response.Success || response.User != "alice" {
		t.Fatalf("fallback response = %#v", response)
	}
}

func TestParseJSONValidationResponse(t *testing.T) {
	response, err := parseJSONValidationResponse([]byte(`{"authenticationSuccess":{"user":"alice","attributes":{"role":"admin","groups":["a","b"],"none":null}}}`))
	if err != nil {
		t.Fatalf("parse success: %v", err)
	}
	if !response.Success || response.User != "alice" {
		t.Fatalf("success = %#v", response)
	}
	if got := response.Attributes["role"]; len(got) != 1 || got[0] != "admin" {
		t.Fatalf("scalar attribute = %#v", response.Attributes)
	}
	if got := response.Attributes["groups"]; len(got) != 2 {
		t.Fatalf("array attribute = %#v", response.Attributes)
	}
	if got, ok := response.Attributes["none"]; !ok || got != nil {
		t.Fatalf("null attribute = %#v", response.Attributes)
	}
	response, err = parseJSONValidationResponse([]byte(`{"authenticationSuccess":{"user":"bob","proxyGrantingTicket":"PGT-1","proxies":["https://proxy.example.com"]}}`))
	if err != nil {
		t.Fatalf("parse proxy success: %v", err)
	}
	if response.ProxyGrantingTicket != "PGT-1" || len(response.Proxies) != 1 {
		t.Fatalf("proxy success = %#v", response)
	}
	response, err = parseJSONValidationResponse([]byte(`{"authenticationFailure":{"code":"INVALID_TICKET","description":" Ticket is invalid "}}`))
	if err != nil {
		t.Fatalf("parse failure: %v", err)
	}
	if response.Success || response.Code != ErrorCodeInvalidTicket || response.Message != "Ticket is invalid" {
		t.Fatalf("failure = %#v", response)
	}
	for _, raw := range []string{"{", "{}", `{"authenticationSuccess":{"user":1}}`} {
		if _, err := parseJSONValidationResponse([]byte(raw)); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("parse %q error = %v, want ErrInvalidResponse", raw, err)
		}
	}
}

func TestParseValidationResponseRejectsMissingUser(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{
			name: "xml empty user",
			raw:  `<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationSuccess><cas:user></cas:user></cas:authenticationSuccess></cas:serviceResponse>`,
		},
		{
			name: "xml missing user",
			raw:  `<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationSuccess><cas:attributes><cas:role>admin</cas:role></cas:attributes></cas:authenticationSuccess></cas:serviceResponse>`,
		},
		{
			name: "xml whitespace user",
			raw:  `<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationSuccess><cas:user>   </cas:user></cas:authenticationSuccess></cas:serviceResponse>`,
		},
		{
			name: "json empty user",
			raw:  `{"authenticationSuccess":{"user":""}}`,
		},
		{
			name: "json missing user",
			raw:  `{"authenticationSuccess":{"attributes":{"role":["admin"]}}}`,
		},
		{
			name: "json whitespace user",
			raw:  `{"authenticationSuccess":{"user":"   "}}`,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := parseValidationResponse([]byte(testCase.raw)); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("error = %v, want ErrInvalidResponse", err)
			}
		})
	}
}

func TestClientRejectsValidationWithoutUser(t *testing.T) {
	bodies := map[string]string{
		"xml":  `<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationSuccess><cas:user></cas:user></cas:authenticationSuccess></cas:serviceResponse>`,
		"json": `{"authenticationSuccess":{"user":""}}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", casContentType)
				_, _ = w.Write([]byte(body))
			}))
			t.Cleanup(httpServer.Close)
			client, err := NewClient(ClientConfig{ServerURL: httpServer.URL, ServiceURL: testAppService})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			response, err := client.Validate(context.Background(), "ST-any", "")
			if response != nil || !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("Validate = %#v, %v; want nil, ErrInvalidResponse", response, err)
			}
		})
	}
}

func TestClientSendLogoutRequest(t *testing.T) {
	service, receiver := newLogoutReceiver(t, http.StatusOK, 0)
	server, _, store, _ := newSLOServer(t, []string{service.URL})
	httpServer := httptest.NewServer(server.HTTPHandler("/cas"))
	t.Cleanup(httpServer.Close)
	client, err := NewClient(ClientConfig{ServerURL: httpServer.URL + "/cas", ServiceURL: testAppService})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	tgt, st := issueTestTickets(t, server, testAppService)
	second, err := server.issueTicket(context.Background(), TicketST, testPrincipal(), "user-1", service.URL, tgt, server.config.ServiceTicketTimeout, false, false)
	if err != nil {
		t.Fatalf("issue second ST: %v", err)
	}
	if err := client.SendLogoutRequest(context.Background(), "", st.ID); err != nil {
		t.Fatalf("SendLogoutRequest: %v", err)
	}
	for _, id := range []string{st.ID, second.ID} {
		if _, err := store.Get(context.Background(), id); !errors.Is(err, ErrTicketNotFound) {
			t.Fatalf("ticket %q survived: %v", id, err)
		}
	}
	requests := receiver.snapshot()
	if len(requests) != 1 || requests[0].SessionIndex != second.ID || requests[0].NameIdentifier != "alice" {
		t.Fatalf("deliveries = %#v", requests)
	}
	if err := client.SendLogoutRequest(context.Background(), "", ""); !errors.Is(err, ErrInvalidLogoutRequest) {
		t.Fatalf("empty SendLogoutRequest error = %v, want ErrInvalidLogoutRequest", err)
	}
	if err := client.SendLogoutRequest(nil, "", "ST-unknown"); err != nil {
		t.Fatalf("nil-context unknown session = %v", err)
	}
}

func TestClientSendLogoutRequestFailures(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(failing.Close)
	client, err := NewClient(ClientConfig{ServerURL: failing.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := client.SendLogoutRequest(context.Background(), "alice", ""); !errors.Is(err, ErrClientRequest) {
		t.Fatalf("non-2xx error = %v, want ErrClientRequest", err)
	}
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedURL := closed.URL
	closed.Close()
	client, err = NewClient(ClientConfig{ServerURL: closedURL})
	if err != nil {
		t.Fatalf("NewClient closed: %v", err)
	}
	if err := client.SendLogoutRequest(context.Background(), "", "ST-any"); !errors.Is(err, ErrClientRequest) {
		t.Fatalf("connection error = %v, want ErrClientRequest", err)
	}
}
