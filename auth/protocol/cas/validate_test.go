package cas

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/base64"
)

func TestServiceValidateSuccessAndSingleUse(t *testing.T) {
	server, store, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	_, st := issueTestTickets(t, server, testAppService)
	recorder := serve(t, handler, http.MethodGet, validateURL("serviceValidate", st.ID, testAppService, nil), nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if contentType := recorder.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/xml") {
		t.Fatalf("Content-Type = %q, want text/xml", contentType)
	}
	body := recorder.Body.String()
	for _, fragment := range []string{
		`<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">`,
		"<cas:authenticationSuccess>",
		"<cas:user>alice</cas:user>",
		"<cas:attributes>",
		"<cas:email>alice@example.com</cas:email>",
		"<cas:role>admin</cas:role>",
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("validation body missing %q: %s", fragment, body)
		}
	}
	stored, err := store.Get(t.Context(), st.ID)
	if err != nil || !stored.Consumed() {
		t.Fatalf("stored ST consumed = %v, err = %v", stored != nil && stored.Consumed(), err)
	}
	replay := serve(t, handler, http.MethodGet, validateURL("serviceValidate", st.ID, testAppService, nil), nil)
	if replay.Code != http.StatusOK {
		t.Fatalf("replay status = %d, want 200", replay.Code)
	}
	if !strings.Contains(replay.Body.String(), `code="INVALID_TICKET"`) {
		t.Fatalf("replay body = %s", replay.Body.String())
	}
}

func TestP3ServiceValidateAttributeForm(t *testing.T) {
	server, _, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	_, st := issueTestTickets(t, server, testAppService)
	recorder := serve(t, handler, http.MethodGet, validateURL("p3/serviceValidate", st.ID, testAppService, nil), nil)
	body := recorder.Body.String()
	if !strings.Contains(body, `<cas:attribute name="email" value="alice@example.com"/>`) {
		t.Fatalf("CAS 3.0 attribute missing: %s", body)
	}
	if strings.Contains(body, "<cas:email>") {
		t.Fatalf("CAS 3.0 body used the CAS 2.0 attribute form: %s", body)
	}
	if !strings.Contains(body, "<cas:user>alice</cas:user>") {
		t.Fatalf("CAS 3.0 user missing: %s", body)
	}
}

func TestCAS10Validate(t *testing.T) {
	server, _, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	_, st := issueTestTickets(t, server, testAppService)
	recorder := serve(t, handler, http.MethodGet, validateURL("validate", st.ID, testAppService, nil), nil)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "yes\nalice\n" {
		t.Fatalf("CAS 1.0 success = %d %q", recorder.Code, recorder.Body.String())
	}
	recorder = serve(t, handler, http.MethodGet, validateURL("validate", st.ID, testAppService, nil), nil)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "no\n\n" {
		t.Fatalf("CAS 1.0 failure = %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestValidateServiceMismatchKeepsTicket(t *testing.T) {
	server, store, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	_, st := issueTestTickets(t, server, testAppService)
	mismatch := serve(t, handler, http.MethodGet, validateURL("serviceValidate", st.ID, testOtherService, nil), nil)
	if !strings.Contains(mismatch.Body.String(), `code="INVALID_SERVICE"`) {
		t.Fatalf("mismatch body = %s", mismatch.Body.String())
	}
	stored, err := store.Get(t.Context(), st.ID)
	if err != nil || stored.Consumed() {
		t.Fatalf("service mismatch consumed the ticket")
	}
	success := serve(t, handler, http.MethodGet, validateURL("serviceValidate", st.ID, testAppService, nil), nil)
	if !strings.Contains(success.Body.String(), "<cas:authenticationSuccess>") {
		t.Fatalf("correct service failed after mismatch: %s", success.Body.String())
	}
}

func TestValidateUnregisteredService(t *testing.T) {
	server, _, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	_, st := issueTestTickets(t, server, testAppService)
	recorder := serve(t, handler, http.MethodGet, validateURL("serviceValidate", st.ID, "https://evil.example.net/", nil), nil)
	if !strings.Contains(recorder.Body.String(), `code="INVALID_SERVICE"`) {
		t.Fatalf("body = %s", recorder.Body.String())
	}
}

func TestValidateExpiredTicket(t *testing.T) {
	server, _, clock := newTestServer(t)
	handler := newTestRouter(t, server)
	_, st := issueTestTickets(t, server, testAppService)
	clock.Advance(DefaultServiceTicketTimeout + time.Second)
	recorder := serve(t, handler, http.MethodGet, validateURL("serviceValidate", st.ID, testAppService, nil), nil)
	if !strings.Contains(recorder.Body.String(), `code="INVALID_TICKET"`) {
		t.Fatalf("body = %s", recorder.Body.String())
	}
}

func TestValidateRenewParameter(t *testing.T) {
	server, _, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	_, st := issueTestTickets(t, server, testAppService)
	extra := url.Values{}
	extra.Set("renew", "true")
	recorder := serve(t, handler, http.MethodGet, validateURL("serviceValidate", st.ID, testAppService, extra), nil)
	if !strings.Contains(recorder.Body.String(), `code="INVALID_TICKET"`) {
		t.Fatalf("renew mismatch body = %s", recorder.Body.String())
	}
	recorder = serve(t, handler, http.MethodGet, validateURL("serviceValidate", st.ID, testAppService, nil), nil)
	if !strings.Contains(recorder.Body.String(), "<cas:authenticationSuccess>") {
		t.Fatalf("renew mismatch consumed the ticket: %s", recorder.Body.String())
	}

	loginExtra := url.Values{}
	loginExtra.Set("renew", "true")
	loginRecorder := loginForm(t, handler, "alice", "secret", testAppService, loginExtra)
	renewalTicket := ticketFromLocation(t, loginRecorder)
	recorder = serve(t, handler, http.MethodGet, validateURL("serviceValidate", renewalTicket, testAppService, extra), nil)
	if !strings.Contains(recorder.Body.String(), "<cas:authenticationSuccess>") {
		t.Fatalf("renewal ticket rejected: %s", recorder.Body.String())
	}
}

// TestCAS10ValidateRenew checks that CAS 1.0 honors renew instead of ignoring it. | TestCAS10ValidateRenew
// 检查 CAS 1.0 会执行 renew 要求而不是忽略它。
func TestCAS10ValidateRenew(t *testing.T) {
	server, store, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	_, st := issueTestTickets(t, server, testAppService)
	extra := url.Values{}
	extra.Set("renew", "true")
	recorder := serve(t, handler, http.MethodGet, validateURL("validate", st.ID, testAppService, extra), nil)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "no\n\n" {
		t.Fatalf("CAS 1.0 renew mismatch = %d %q", recorder.Code, recorder.Body.String())
	}
	stored, err := store.Get(t.Context(), st.ID)
	if err != nil || stored.Consumed() {
		t.Fatalf("CAS 1.0 renew mismatch consumed the ticket: %v", err)
	}
	recorder = serve(t, handler, http.MethodGet, validateURL("validate", st.ID, testAppService, nil), nil)
	if recorder.Body.String() != "yes\nalice\n" {
		t.Fatalf("CAS 1.0 ticket unusable after renew mismatch: %q", recorder.Body.String())
	}

	loginExtra := url.Values{}
	loginExtra.Set("renew", "true")
	loginRecorder := loginForm(t, handler, "alice", "secret", testAppService, loginExtra)
	renewalTicket := ticketFromLocation(t, loginRecorder)
	recorder = serve(t, handler, http.MethodGet, validateURL("validate", renewalTicket, testAppService, extra), nil)
	if recorder.Body.String() != "yes\nalice\n" {
		t.Fatalf("CAS 1.0 renewal ticket rejected: %q", recorder.Body.String())
	}
}

func TestValidateMissingParameters(t *testing.T) {
	server, _, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	recorder := serve(t, handler, http.MethodGet, "/cas/serviceValidate?service="+url.QueryEscape(testAppService), nil)
	if !strings.Contains(recorder.Body.String(), `code="INVALID_REQUEST"`) {
		t.Fatalf("missing ticket body = %s", recorder.Body.String())
	}
	recorder = serve(t, handler, http.MethodGet, "/cas/serviceValidate?ticket=ST-x", nil)
	if !strings.Contains(recorder.Body.String(), `code="INVALID_REQUEST"`) {
		t.Fatalf("missing service body = %s", recorder.Body.String())
	}
}

func TestServiceValidateRejectsWrongTicketType(t *testing.T) {
	server, _, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	tgt, _ := issueTestTickets(t, server, testAppService)
	recorder := serve(t, handler, http.MethodGet, validateURL("serviceValidate", tgt.ID, testAppService, nil), nil)
	if !strings.Contains(recorder.Body.String(), `code="INVALID_TICKET"`) {
		t.Fatalf("TGT validation body = %s", recorder.Body.String())
	}
}

func TestProxyTicketFlow(t *testing.T) {
	callbacks := make(chan url.Values, 4)
	callback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callbacks <- r.URL.Query()
		w.WriteHeader(http.StatusOK)
	}))
	defer callback.Close()
	pgtURL := callback.URL + "/pgt?existing=1"

	server, store, _ := newTestServer(t, func(config *ServerConfig) {
		config.ServiceRegistry = NewAllowAllServiceRegistry()
		config.AllowInsecurePGTCallback = true
	})
	handler := newTestRouter(t, server)
	tgt, st := issueTestTickets(t, server, testAppService)

	extra := url.Values{}
	extra.Set("pgtUrl", pgtURL)
	recorder := serve(t, handler, http.MethodGet, validateURL("serviceValidate", st.ID, testAppService, extra), nil)
	body := recorder.Body.String()
	if !strings.Contains(body, "<cas:authenticationSuccess>") {
		t.Fatalf("validation with pgtUrl failed: %s", body)
	}
	pgtID := elementText(t, body, "proxyGrantingTicket")
	if !strings.HasPrefix(pgtID, TicketPrefixPGT) {
		t.Fatalf("response PGT = %q", pgtID)
	}
	select {
	case query := <-callbacks:
		if query.Get("pgtId") != pgtID {
			t.Fatalf("callback pgtId = %q, want %q", query.Get("pgtId"), pgtID)
		}
		if !strings.HasPrefix(query.Get("pgtIou"), TicketPrefixPGTIOU) {
			t.Fatalf("callback pgtIou = %q", query.Get("pgtIou"))
		}
		if query.Get("existing") != "1" {
			t.Fatalf("callback lost the pgtUrl query parameters: %v", query)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("pgtUrl callback was not called")
	}
	pgt, err := store.Get(t.Context(), pgtID)
	if err != nil || pgt.Type != TicketPGT || pgt.Service != pgtURL || pgt.RootTGTID != tgt.ID {
		t.Fatalf("stored PGT = %#v, err = %v", pgt, err)
	}

	proxyRecorder := serve(t, handler, http.MethodGet, "/cas/proxy?pgt="+url.QueryEscape(pgtID)+"&targetService="+url.QueryEscape(testAPIEndpoint), nil)
	proxyBody := proxyRecorder.Body.String()
	if !strings.Contains(proxyBody, "<cas:proxySuccess>") {
		t.Fatalf("proxy response = %s", proxyBody)
	}
	ptID := elementText(t, proxyBody, "proxyTicket")
	if !strings.HasPrefix(ptID, TicketPrefixPT) {
		t.Fatalf("proxy ticket = %q", ptID)
	}
	pt, err := store.Get(t.Context(), ptID)
	if err != nil || pt.Service != testAPIEndpoint || pt.ParentID != pgtID || pt.RootTGTID != tgt.ID {
		t.Fatalf("stored PT = %#v, err = %v", pt, err)
	}
	if len(pt.ProxyChain) != 1 || pt.ProxyChain[0] != pgtURL {
		t.Fatalf("PT proxy chain = %#v, want %q", pt.ProxyChain, pgtURL)
	}

	validateRecorder := serve(t, handler, http.MethodGet, validateURL("proxyValidate", ptID, testAPIEndpoint, nil), nil)
	validateBody := validateRecorder.Body.String()
	if !strings.Contains(validateBody, "<cas:authenticationSuccess>") {
		t.Fatalf("PT validation failed: %s", validateBody)
	}
	if !strings.Contains(validateBody, "<cas:proxies><cas:proxy>"+pgtURL+"</cas:proxy></cas:proxies>") {
		t.Fatalf("PT validation lacks proxies: %s", validateBody)
	}
	replay := serve(t, handler, http.MethodGet, validateURL("proxyValidate", ptID, testAPIEndpoint, nil), nil)
	if !strings.Contains(replay.Body.String(), `code="INVALID_TICKET"`) {
		t.Fatalf("PT replay = %s", replay.Body.String())
	}

	secondProxy := serve(t, handler, http.MethodGet, "/cas/proxy?pgt="+url.QueryEscape(pgtID)+"&targetService="+url.QueryEscape(testAPIEndpoint), nil)
	secondPT := elementText(t, secondProxy.Body.String(), "proxyTicket")
	if secondPT == ptID || !strings.HasPrefix(secondPT, TicketPrefixPT) {
		t.Fatalf("second proxy ticket = %q, want a fresh PT", secondPT)
	}
}

func TestProxyRejectsInvalidRequests(t *testing.T) {
	server, _, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	recorder := serve(t, handler, http.MethodGet, "/cas/proxy", nil)
	if !strings.Contains(recorder.Body.String(), `code="INVALID_REQUEST"`) {
		t.Fatalf("missing params body = %s", recorder.Body.String())
	}
	recorder = serve(t, handler, http.MethodGet, "/cas/proxy?pgt=PGT-unknown&targetService="+url.QueryEscape(testAPIEndpoint), nil)
	if !strings.Contains(recorder.Body.String(), `code="INVALID_TICKET"`) {
		t.Fatalf("unknown PGT body = %s", recorder.Body.String())
	}
	_, st := issueTestTickets(t, server, testAppService)
	recorder = serve(t, handler, http.MethodGet, "/cas/proxy?pgt="+url.QueryEscape(st.ID)+"&targetService="+url.QueryEscape(testAPIEndpoint), nil)
	if !strings.Contains(recorder.Body.String(), `code="INVALID_TICKET"`) {
		t.Fatalf("ST used as PGT body = %s", recorder.Body.String())
	}
}

func TestPGTCallbackFailureRevokesTicket(t *testing.T) {
	callback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer callback.Close()
	server, store, _ := newTestServer(t, func(config *ServerConfig) {
		config.ServiceRegistry = NewAllowAllServiceRegistry()
		config.AllowInsecurePGTCallback = true
	})
	handler := newTestRouter(t, server)
	tgt, st := issueTestTickets(t, server, testAppService)
	extra := url.Values{}
	extra.Set("pgtUrl", callback.URL+"/pgt")
	recorder := serve(t, handler, http.MethodGet, validateURL("serviceValidate", st.ID, testAppService, extra), nil)
	if !strings.Contains(recorder.Body.String(), `code="INVALID_PROXY_CALLBACK"`) {
		t.Fatalf("body = %s", recorder.Body.String())
	}
	family, err := store.ListByRootTGT(t.Context(), tgt.ID)
	if err != nil {
		t.Fatalf("ListByRootTGT: %v", err)
	}
	for _, ticket := range family {
		if ticket.Type == TicketPGT {
			t.Fatalf("failed callback left a PGT behind")
		}
	}
}

func TestPGTRequiresHTTPS(t *testing.T) {
	server, _, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	_, st := issueTestTickets(t, server, testAppService)
	extra := url.Values{}
	extra.Set("pgtUrl", "http://proxy.example.com/pgt")
	recorder := serve(t, handler, http.MethodGet, validateURL("serviceValidate", st.ID, testAppService, extra), nil)
	if !strings.Contains(recorder.Body.String(), `code="INVALID_PROXY_CALLBACK"`) {
		t.Fatalf("body = %s", recorder.Body.String())
	}
}

func TestPrincipalProviderRefreshesAttributes(t *testing.T) {
	server, _, _ := newTestServer(t, func(config *ServerConfig) {
		config.PrincipalProvider = PrincipalProviderFunc(func(context.Context, string) (*auth.Principal, error) {
			return &auth.Principal{
				Subject:    "user-1",
				Username:   "alice",
				Attributes: map[string]string{"department": "engineering"},
			}, nil
		})
	})
	handler := newTestRouter(t, server)
	_, st := issueTestTickets(t, server, testAppService)
	recorder := serve(t, handler, http.MethodGet, validateURL("serviceValidate", st.ID, testAppService, nil), nil)
	body := recorder.Body.String()
	if !strings.Contains(body, "<cas:department>engineering</cas:department>") {
		t.Fatalf("refreshed attribute missing: %s", body)
	}
	if strings.Contains(body, "<cas:email>") {
		t.Fatalf("stale snapshot attribute leaked: %s", body)
	}
}

func TestSAMLValidate(t *testing.T) {
	server, _, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	_, st := issueTestTickets(t, server, testAppService)
	samlRequest := `<samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol"><samlp:AssertionArtifact>` + st.ID + `</samlp:AssertionArtifact></samlp:Request>`
	encoded := base64.StdEncoding.EncodeToString([]byte(samlRequest))
	form := url.Values{}
	form.Set("SAMLRequest", encoded)
	recorder := serve(t, handler, http.MethodPost, "/cas/samlValidate?TARGET="+url.QueryEscape(testAppService), form, nil)
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	for _, fragment := range []string{
		`<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">`,
		`<saml1p:Response xmlns:saml1p="urn:oasis:names:tc:SAML:1.0:protocol"`,
		`<saml1:Assertion xmlns:saml1="urn:oasis:names:tc:SAML:1.0:assertion"`,
		"<saml1:NameIdentifier>alice</saml1:NameIdentifier>",
		"<saml1:AttributeValue>alice@example.com</saml1:AttributeValue>",
		"<saml1:Audience>" + testAppService + "</saml1:Audience>",
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("SAML response missing %q: %s", fragment, body)
		}
	}
	replay := serve(t, handler, http.MethodPost, "/cas/samlValidate?TARGET="+url.QueryEscape(testAppService), form, nil)
	if !strings.Contains(replay.Body.String(), "SOAP-ENV:Fault") {
		t.Fatalf("SAML replay = %s", replay.Body.String())
	}
	missing := serve(t, handler, http.MethodPost, "/cas/samlValidate?TARGET="+url.QueryEscape(testAppService), url.Values{}, nil)
	if !strings.Contains(missing.Body.String(), "SOAP-ENV:Fault") {
		t.Fatalf("SAML missing request = %s", missing.Body.String())
	}
}

func TestSAMLValidateGetterAndCustomBuilder(t *testing.T) {
	server, _, _ := newTestServer(t, func(config *ServerConfig) {
		config.SAMLResponseBuilder = func(_ context.Context, validation *SAMLValidation) ([]byte, error) {
			return []byte("<custom>" + validation.User + "</custom>"), nil
		}
	})
	handler := newTestRouter(t, server)
	_, st := issueTestTickets(t, server, testAppService)
	samlRequest := `<Request><AssertionArtifact>` + st.ID + `</AssertionArtifact></Request>`
	encoded := base64.StdEncoding.EncodeToString([]byte(samlRequest))
	recorder := serve(t, handler, http.MethodGet, "/cas/samlValidate?TARGET="+url.QueryEscape(testAppService)+"&SAMLRequest="+url.QueryEscape(encoded), nil)
	if recorder.Body.String() != "<custom>alice</custom>" {
		t.Fatalf("custom builder body = %q", recorder.Body.String())
	}
}

func TestValidateMethodNotAllowed(t *testing.T) {
	server, _, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	_, st := issueTestTickets(t, server, testAppService)
	recorder := serve(t, handler, http.MethodPost, validateURL("serviceValidate", st.ID, testAppService, nil), url.Values{})
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", recorder.Code)
	}
}
