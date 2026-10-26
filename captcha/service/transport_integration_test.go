package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shibingli/ydx/captcha/core"
	"github.com/shibingli/ydx/captcha/transport"
	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/router"
)

func TestHandlerCreateVerifyAndImage(t *testing.T) {
	m := newTestManager(t, nil)
	h := transport.NewHandler(m, transport.HandlerOptions{})
	createBody := []byte(`{"type":"text","action":"login","locale":"zh-CN"}`)
	createReq := httptest.NewRequest(http.MethodPost, "/captcha/challenge", strings.NewReader(string(createBody)))
	createReq.Header.Set("Content-Type", "application/json")
	createRec := httptest.NewRecorder()
	h.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", createRec.Code, createRec.Body.String())
	}
	var created testAPIResponse
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if !created.OK || created.Challenge == nil || created.Challenge.ID == "" {
		t.Fatalf("unexpected create response: %s", createRec.Body.String())
	}
	payload, ok, err := m.store.Get(context.Background(), m.recordKey(created.Challenge.ID))
	if err != nil || !ok {
		t.Fatalf("record: ok=%v err=%v", ok, err)
	}
	record, err := decodeRecord(payload)
	if err != nil {
		t.Fatal(err)
	}
	key := strings.TrimPrefix(created.Challenge.Images[0].URL, "image/")
	imgReq := httptest.NewRequest(http.MethodGet, "/captcha/image/"+key, nil)
	imgRec := httptest.NewRecorder()
	h.ServeHTTP(imgRec, imgReq)
	if imgRec.Code != http.StatusOK || imgRec.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("image status=%d type=%q", imgRec.Code, imgRec.Header().Get("Content-Type"))
	}
	answer := answerFor(t, record)
	verifyReqBody, _ := json.Marshal(VerifyRequest{ID: created.Challenge.ID, Answer: answer})
	verifyReq := httptest.NewRequest(http.MethodPost, "/captcha/verify", strings.NewReader(string(verifyReqBody)))
	verifyRec := httptest.NewRecorder()
	h.ServeHTTP(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("verify status=%d body=%s", verifyRec.Code, verifyRec.Body.String())
	}
	var verified testAPIResponse
	if err := json.Unmarshal(verifyRec.Body.Bytes(), &verified); err != nil {
		t.Fatal(err)
	}
	if !verified.OK || verified.Result == nil || verified.Result.Token == "" {
		t.Fatalf("unexpected verify response: %s", verifyRec.Body.String())
	}
}

func TestHandlerAssetsAndNotFound(t *testing.T) {
	m := newTestManager(t, nil)
	h := transport.NewHandler(m, transport.HandlerOptions{})
	req := httptest.NewRequest(http.MethodGet, "/captcha/assets/yd-captcha.js", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "YdCaptcha") {
		t.Fatalf("asset status=%d body=%s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/captcha/assets/../secret", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("traversal status=%d", rec.Code)
	}
}

func TestHandlerOriginAndBodyLimit(t *testing.T) {
	m := newTestManager(t, func(o *Options) {
		o.AllowedOrigins = []string{"https://example.com"}
	})
	h := transport.NewHandler(m, transport.HandlerOptions{MaxBodyBytes: 16})
	req := httptest.NewRequest(http.MethodPost, "/captcha/challenge", strings.NewReader(`{"action":"login","padding":"0123456789"}`))
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("origin status=%d body=%s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodPost, "/captcha/challenge", strings.NewReader(`{"action":"login","padding":"0123456789"}`))
	req.Header.Set("Origin", "https://example.com")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("body status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Fatalf("missing CORS header: %v", rec.Header())
	}
}

func TestHandlerYDBind(t *testing.T) {
	m := newTestManager(t, nil)
	h := transport.NewHandler(m, transport.HandlerOptions{Prefix: "/verify"})
	r := router.New()
	h.Bind(r)
	req := httptest.NewRequest(http.MethodPost, "/verify/challenge", strings.NewReader(`{"action":"login"}`))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("yd status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestProtectMiddleware(t *testing.T) {
	m := newTestManager(t, nil)
	token, err := m.signer.issue(context.Background(), TokenClaims{ChallengeID: "ch_1", Action: "login"})
	if err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := transport.ClaimsFromContext(r.Context())
		if !ok || claims.ChallengeID != "ch_1" {
			t.Errorf("missing claims")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	protected := transport.NewHTTPMiddleware(m, "login", transport.ProtectOptions{})(next)
	req := httptest.NewRequest(http.MethodPost, "/private", nil)
	req.Header.Set(transport.TokenHeader, token)
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("protected status=%d body=%s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodPost, "/private", nil)
	req.Header.Set(transport.TokenHeader, token)
	rec = httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("replay status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandlerMapsCaptureDetection(t *testing.T) {
	m := newTestManager(t, func(o *Options) { o.CaptureMode = CaptureReject })
	h := transport.NewHandler(m, transport.HandlerOptions{})
	req := httptest.NewRequest(http.MethodPost, "/captcha/challenge", strings.NewReader(`{"action":"login","signals":{"screenshot_key":true}}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"capture_detected"`) {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestHandlerRejectsNonJSONPost(t *testing.T) {
	m := newTestManager(t, nil)
	h := transport.NewHandler(m, transport.HandlerOptions{})
	req := httptest.NewRequest(http.MethodPost, "/captcha/challenge", strings.NewReader(`{"action":"login"}`))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandlerNegotiatesLocale(t *testing.T) {
	m := newTestManager(t, nil)
	h := transport.NewHandler(m, transport.HandlerOptions{})
	localizer, err := core.NewLocalizer(testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"type":"text","action":"login"}`)
	req := httptest.NewRequest(http.MethodPost, "/captcha/challenge", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Language", "ja-JP, en;q=0.8")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Language"); got != "ja" {
		t.Fatalf("Content-Language = %q", got)
	}
	var response testAPIResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Challenge == nil || response.Challenge.Prompt.Text != localizer.Message("ja", "prompt.text") {
		t.Fatalf("prompt = %+v", response.Challenge)
	}

	req = httptest.NewRequest(http.MethodPost, "/captcha/challenge", strings.NewReader(`{"type":"text","action":"login","locale":"fr"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Language", "de")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Language") != "fr" {
		t.Fatalf("body locale status=%d language=%q", rec.Code, rec.Header().Get("Content-Language"))
	}

	req = httptest.NewRequest(http.MethodPost, "/captcha/challenge?lang=ko", strings.NewReader(`{`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Language", "de")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("error status=%d", rec.Code)
	}
	var failure testAPIResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &failure); err != nil {
		t.Fatal(err)
	}
	if failure.Error == nil || failure.Error.Message != localizer.Message("ko", "error.invalid_request") {
		t.Fatalf("error = %+v", failure.Error)
	}
	if rec.Header().Get("Content-Language") != "ko" {
		t.Fatalf("error Content-Language = %q", rec.Header().Get("Content-Language"))
	}
}

func TestHandlerCORSReflectsCustomHeaders(t *testing.T) {
	m := newTestManager(t, func(o *Options) {
		o.AllowedOrigins = []string{"https://example.com"}
	})
	h := transport.NewHandler(m, transport.HandlerOptions{})
	req := httptest.NewRequest(http.MethodOptions, "/captcha/challenge", nil)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Headers", "X-Api-Key, Authorization, Bad Header")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight status=%d", rec.Code)
	}
	allow := rec.Header().Get("Access-Control-Allow-Headers")
	if !strings.Contains(allow, "X-Api-Key") || !strings.Contains(allow, "Authorization") {
		t.Fatalf("allow-headers = %q", allow)
	}
	if strings.Contains(allow, "Bad Header") {
		t.Fatalf("unsafe header reflected: %q", allow)
	}
}
