package cas

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth/crypto/xmlsig"
)

// newLogoutSigningKey returns a fresh ECDSA P-256 key for logout signature tests. |
// newLogoutSigningKey 为登出签名测试返回新的 ECDSA P-256 密钥。
func newLogoutSigningKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	return key
}

// signLogoutRequest builds and signs a LogoutRequest, returning the signed XML and its parsed form.
// The signature is enveloped in the request and carries an embedded KeyValue so tests can verify
// with TrustKeyInfo. | signLogoutRequest 构建并签名一个 LogoutRequest，返回已签名 XML 与解析结果。
// 签名封套在请求内并携带内嵌 KeyValue，使测试可用 TrustKeyInfo 校验。
func signLogoutRequest(t *testing.T, key *ecdsa.PrivateKey, nameIdentifier, sessionIndex string, now time.Time) ([]byte, *LogoutRequest) {
	t.Helper()
	document, err := BuildLogoutRequest(nameIdentifier, sessionIndex, now)
	if err != nil {
		t.Fatalf("BuildLogoutRequest: %v", err)
	}
	parsed, err := ParseLogoutRequest(string(document))
	if err != nil {
		t.Fatalf("ParseLogoutRequest: %v", err)
	}
	signed, err := xmlsig.Sign(document, xmlsig.SignOptions{
		PrivateKey:     key,
		ID:             parsed.ID,
		IncludeKeyInfo: true,
	})
	if err != nil {
		t.Fatalf("sign logout request: %v", err)
	}
	return signed, parsed
}

// logoutRequestForm wraps a document in the logoutRequest form parameter. | logoutRequestForm 把文档
// 包装进 logoutRequest 表单参数。
func logoutRequestForm(document []byte) url.Values {
	return url.Values{logoutRequestParameter: {string(document)}}
}

// TestLogoutRequestSignatureAccepted covers a valid signature with a required-signature policy. |
// TestLogoutRequestSignatureAccepted 覆盖要求签名策略下的有效签名。
func TestLogoutRequestSignatureAccepted(t *testing.T) {
	service, originReceiver := newLogoutReceiver(t, http.StatusOK, 0)
	otherService, otherReceiver := newLogoutReceiver(t, http.StatusOK, 0)
	key := newLogoutSigningKey(t)
	server, registry, store, _ := newSLOServer(t, []string{service.URL, otherService.URL}, func(config *ServerConfig) {
		config.LogoutRequestSignatureVerifier = &LogoutRequestXMLDSigVerifier{TrustKeyInfo: true}
		config.RequireSignedLogoutRequest = true
	})
	handler := newTestRouter(t, server)
	cookie, st := loginAndTicket(t, handler, service.URL)
	tgt, err := store.Get(t.Context(), cookie.Value)
	if err != nil {
		t.Fatalf("load TGT: %v", err)
	}
	other, err := server.issueTicket(t.Context(), TicketST, testPrincipal(), "user-1", otherService.URL, tgt, server.config.ServiceTicketTimeout, false, false)
	if err != nil {
		t.Fatalf("issue other ST: %v", err)
	}
	document, parsed := signLogoutRequest(t, key, "alice", st, server.nowTime())
	if parsed.SessionIndex != st {
		t.Fatalf("signed SessionIndex = %q, want %q", parsed.SessionIndex, st)
	}
	recorder := serve(t, handler, http.MethodPost, "/cas/logout", logoutRequestForm(document))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", recorder.Code, recorder.Body.String())
	}
	if registry.Len() != 0 {
		t.Fatalf("sessions survived: %d", registry.Len())
	}
	for _, id := range []string{cookie.Value, st, other.ID} {
		if _, err := store.Get(t.Context(), id); !errors.Is(err, ErrTicketNotFound) {
			t.Fatalf("ticket %q survived: %v", id, err)
		}
	}
	if originReceiver.count() != 0 {
		t.Fatalf("origin service received %d deliveries, want 0", originReceiver.count())
	}
	if requests := otherReceiver.snapshot(); len(requests) != 1 || requests[0].SessionIndex != other.ID {
		t.Fatalf("deliveries = %#v", requests)
	}
}

// TestLogoutRequestSignatureRejected covers a tampered signed document. |
// TestLogoutRequestSignatureRejected 覆盖被篡改的已签名文档。
func TestLogoutRequestSignatureRejected(t *testing.T) {
	service, receiver := newLogoutReceiver(t, http.StatusOK, 0)
	key := newLogoutSigningKey(t)
	server, registry, store, _ := newSLOServer(t, []string{service.URL}, func(config *ServerConfig) {
		config.LogoutRequestSignatureVerifier = &LogoutRequestXMLDSigVerifier{TrustKeyInfo: true}
		config.RequireSignedLogoutRequest = true
	})
	handler := newTestRouter(t, server)
	_, st := loginAndTicket(t, handler, service.URL)
	document, _ := signLogoutRequest(t, key, "alice", st, server.nowTime())
	tampered := strings.Replace(string(document), st, "ST-other", 1)
	if tampered == string(document) {
		t.Fatal("test document did not contain the session index")
	}
	recorder := serve(t, handler, http.MethodPost, "/cas/logout", logoutRequestForm([]byte(tampered)))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", recorder.Code, recorder.Body.String())
	}
	if registry.Len() != 1 {
		t.Fatalf("tampered request revoked sessions: %d", registry.Len())
	}
	if _, err := store.Get(t.Context(), st); err != nil {
		t.Fatalf("tampered request revoked the ticket: %v", err)
	}
	if receiver.count() != 0 {
		t.Fatalf("tampered request delivered %d notifications", receiver.count())
	}
}

// TestLogoutRequestUnsignedPolicy covers required, optional and missing-verifier policies. |
// TestLogoutRequestUnsignedPolicy 覆盖强制、可选与缺失校验器的策略。
func TestLogoutRequestUnsignedPolicy(t *testing.T) {
	t.Run("unsigned rejected when required", func(t *testing.T) {
		service, receiver := newLogoutReceiver(t, http.StatusOK, 0)
		server, registry, store, _ := newSLOServer(t, []string{service.URL}, func(config *ServerConfig) {
			config.LogoutRequestSignatureVerifier = &LogoutRequestXMLDSigVerifier{TrustKeyInfo: true}
			config.RequireSignedLogoutRequest = true
		})
		handler := newTestRouter(t, server)
		_, st := loginAndTicket(t, handler, service.URL)
		document, err := BuildLogoutRequest("alice", st, server.nowTime())
		if err != nil {
			t.Fatalf("BuildLogoutRequest: %v", err)
		}
		recorder := serve(t, handler, http.MethodPost, "/cas/logout", logoutRequestForm(document))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body: %s", recorder.Code, recorder.Body.String())
		}
		if registry.Len() != 1 || receiver.count() != 0 {
			t.Fatalf("unsigned request changed state: sessions=%d deliveries=%d", registry.Len(), receiver.count())
		}
		if _, err := store.Get(t.Context(), st); err != nil {
			t.Fatalf("unsigned request revoked the ticket: %v", err)
		}
	})

	t.Run("unsigned allowed by default", func(t *testing.T) {
		service, _ := newLogoutReceiver(t, http.StatusOK, 0)
		server, registry, _, _ := newSLOServer(t, []string{service.URL}, func(config *ServerConfig) {
			config.LogoutRequestSignatureVerifier = &LogoutRequestXMLDSigVerifier{TrustKeyInfo: true}
		})
		handler := newTestRouter(t, server)
		_, st := loginAndTicket(t, handler, service.URL)
		document, err := BuildLogoutRequest("alice", st, server.nowTime())
		if err != nil {
			t.Fatalf("BuildLogoutRequest: %v", err)
		}
		recorder := serve(t, handler, http.MethodGet, "/cas/logout?logoutRequest="+url.QueryEscape(string(document)), nil)
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", recorder.Code, recorder.Body.String())
		}
		if registry.Len() != 0 {
			t.Fatalf("unsigned optional request did not revoke: %d", registry.Len())
		}
	})

	t.Run("signed rejected without verifier", func(t *testing.T) {
		service, receiver := newLogoutReceiver(t, http.StatusOK, 0)
		key := newLogoutSigningKey(t)
		server, registry, store, _ := newSLOServer(t, []string{service.URL})
		handler := newTestRouter(t, server)
		_, st := loginAndTicket(t, handler, service.URL)
		document, _ := signLogoutRequest(t, key, "alice", st, server.nowTime())
		recorder := serve(t, handler, http.MethodPost, "/cas/logout", logoutRequestForm(document))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body: %s", recorder.Code, recorder.Body.String())
		}
		if registry.Len() != 1 || receiver.count() != 0 {
			t.Fatalf("unverifiable signature changed state: sessions=%d deliveries=%d", registry.Len(), receiver.count())
		}
		if _, err := store.Get(t.Context(), st); err != nil {
			t.Fatalf("unverifiable signature revoked the ticket: %v", err)
		}
	})
}

// TestLogoutRequestSignatureWrapping covers wrapped and duplicate-ID documents. |
// TestLogoutRequestSignatureWrapping 覆盖包裹与重复 ID 文档。
func TestLogoutRequestSignatureWrapping(t *testing.T) {
	service, receiver := newLogoutReceiver(t, http.StatusOK, 0)
	key := newLogoutSigningKey(t)
	server, registry, store, _ := newSLOServer(t, []string{service.URL}, func(config *ServerConfig) {
		config.LogoutRequestSignatureVerifier = &LogoutRequestXMLDSigVerifier{TrustKeyInfo: true}
	})
	handler := newTestRouter(t, server)
	_, st := loginAndTicket(t, handler, service.URL)
	signed, parsed := signLogoutRequest(t, key, "alice", st, server.nowTime())
	signedRequest := string(signed)
	if start := strings.Index(signedRequest, "<samlp:LogoutRequest"); start > 0 {
		signedRequest = signedRequest[start:]
	}
	evil := func(id string) string {
		return `<samlp:LogoutRequest xmlns:samlp="` + samlProtocolNamespace + `" ID="` + id + `">` +
			`<samlp:SessionIndex>` + st + `</samlp:SessionIndex></samlp:LogoutRequest>`
	}

	cases := []struct {
		name     string
		document string
	}{
		{"unsigned request before signed request", `<root>` + evil("_evil") + signedRequest + `</root>`},
		{"duplicate ID", `<root>` + evil(parsed.ID) + signedRequest + `</root>`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := serve(t, handler, http.MethodPost, "/cas/logout", logoutRequestForm([]byte(tc.document)))
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body: %s", recorder.Code, recorder.Body.String())
			}
			if registry.Len() != 1 {
				t.Fatalf("wrapped request revoked sessions: %d", registry.Len())
			}
			if _, err := store.Get(t.Context(), st); err != nil {
				t.Fatalf("wrapped request revoked the ticket: %v", err)
			}
			if receiver.count() != 0 {
				t.Fatalf("wrapped request delivered %d notifications", receiver.count())
			}
		})
	}
}

// TestLogoutRequestSignatureVerifierHelpers covers the exported verifier adapters. |
// TestLogoutRequestSignatureVerifierHelpers 覆盖导出的校验器适配器。
func TestLogoutRequestSignatureVerifierHelpers(t *testing.T) {
	var verifier *LogoutRequestXMLDSigVerifier
	if err := verifier.VerifyLogoutRequest(context.Background(), []byte("<root/>"), "_id"); !errors.Is(err, ErrInvalidLogoutSignature) {
		t.Fatalf("nil verifier err = %v", err)
	}
	emptyID := &LogoutRequestXMLDSigVerifier{TrustKeyInfo: true}
	if err := emptyID.VerifyLogoutRequest(context.Background(), []byte("<root/>"), ""); !errors.Is(err, ErrInvalidLogoutSignature) {
		t.Fatalf("empty ID err = %v", err)
	}
	var function LogoutRequestSignatureVerifierFunc
	if err := function.VerifyLogoutRequest(context.Background(), nil, "_id"); !errors.Is(err, ErrInvalidLogoutSignature) {
		t.Fatalf("nil function err = %v", err)
	}
	if !logoutRequestHasSignature([]byte(`<root><Signature/></root>`)) {
		t.Fatal("signature without a namespace was not detected")
	}
	if !logoutRequestHasSignature([]byte(`<root><ds:Signature xmlns:ds="` + xmlsig.NamespaceXMLDSig + `"/></root>`)) {
		t.Fatal("XMLDSig signature was not detected")
	}
	if logoutRequestHasSignature([]byte(`<root><NotSignature/></root>`)) {
		t.Fatal("unrelated element was detected as a signature")
	}
}
