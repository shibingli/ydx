package kms

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/router"
)

// newTestHTTPPair builds a service and server for HTTP tests. | newTestHTTPPair 为 HTTP 测试构建服务与服务器。
func newTestHTTPPair(t *testing.T, serviceConfig Config, serverConfig ServerConfig) (*Server, *Service, *testClock) {
	t.Helper()
	service, clock := newServiceForTest(t, serviceConfig)
	server, err := NewServer(service, serverConfig)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return server, service, clock
}

// jsonRequest performs one JSON request against handler. | jsonRequest 对 handler 执行一次 JSON 请求。
func jsonRequest(t *testing.T, handler http.Handler, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		payload = encoded
	}
	return rawRequest(t, handler, method, target, string(payload))
}

// rawRequest performs one request with a raw body. | rawRequest 用原始请求体执行一次请求。
func rawRequest(t *testing.T, handler http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// decodeResponse decodes a JSON response body. | decodeResponse 解码 JSON 响应体。
func decodeResponse(t *testing.T, recorder *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(recorder.Body.Bytes(), dst); err != nil {
		t.Fatalf("decode response %q: %v", recorder.Body.String(), err)
	}
}

// expectStatus asserts the response status. | expectStatus 断言响应状态。
func expectStatus(t *testing.T, recorder *httptest.ResponseRecorder, want int) {
	t.Helper()
	if recorder.Code != want {
		t.Fatalf("status = %d, want %d, body = %s", recorder.Code, want, recorder.Body.String())
	}
}

// expectErrorCode asserts a stable error code. | expectErrorCode 断言稳定错误码。
func expectErrorCode(t *testing.T, recorder *httptest.ResponseRecorder, code string) {
	t.Helper()
	var body errorBody
	decodeResponse(t, recorder, &body)
	if body.Error.Code != code {
		t.Fatalf("error code = %q, want %q, body = %s", body.Error.Code, code, recorder.Body.String())
	}
	if strings.Contains(body.Error.Message, "-----BEGIN") {
		t.Fatalf("error message leaked key material: %q", body.Error.Message)
	}
}

func TestServerRouterEndToEnd(t *testing.T) {
	server, _, clock := newTestHTTPPair(t, Config{ExportPolicy: ExportPolicy{AllowPrivate: false}}, ServerConfig{})
	r := router.New()
	server.Register(r, "kms")

	createRecorder := jsonRequest(t, r, http.MethodPost, "/kms/keys", createKeyJSON{
		Type:       KeyTypeAES,
		Bits:       256,
		Alias:      "api-key",
		Tags:       []string{"prod", "api"},
		Exportable: true,
		Metadata:   map[string]string{"team": "crypto"},
	})
	expectStatus(t, createRecorder, http.StatusCreated)
	var created Key
	decodeResponse(t, createRecorder, &created)
	if created.ID == "" || created.State != StatePreActive || created.Alias != "api-key" || created.Material != nil {
		t.Fatalf("created key = %+v", created)
	}
	keyPath := "/kms/keys/" + created.ID

	activateRecorder := jsonRequest(t, r, http.MethodPost, keyPath+"/activate", nil)
	expectStatus(t, activateRecorder, http.StatusOK)
	var activated Key
	decodeResponse(t, activateRecorder, &activated)
	if activated.State != StateActive || activated.ActivatedAt.IsZero() {
		t.Fatalf("activated key = %+v", activated)
	}

	getRecorder := jsonRequest(t, r, http.MethodGet, keyPath, nil)
	expectStatus(t, getRecorder, http.StatusOK)
	var fetched Key
	decodeResponse(t, getRecorder, &fetched)
	if fetched.ID != created.ID || fetched.State != StateActive || fetched.Material != nil {
		t.Fatalf("fetched key = %+v", fetched)
	}

	plaintext := []byte("router secret payload")
	aad := []byte("tenant=acme")
	encryptRecorder := jsonRequest(t, r, http.MethodPost, "/kms/encrypt", encryptJSON{
		KeyID:     created.ID,
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
		AAD:       base64.StdEncoding.EncodeToString(aad),
	})
	expectStatus(t, encryptRecorder, http.StatusOK)
	var encrypted ciphertextResponse
	decodeResponse(t, encryptRecorder, &encrypted)
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted.Ciphertext)
	if err != nil || !bytes.HasPrefix(ciphertext, cipherMagic) {
		t.Fatalf("ciphertext = %q, %v", encrypted.Ciphertext, err)
	}

	decryptRecorder := jsonRequest(t, r, http.MethodPost, "/kms/decrypt", decryptJSON{
		KeyID:      created.ID,
		Ciphertext: encrypted.Ciphertext,
		AAD:        base64.StdEncoding.EncodeToString(aad),
	})
	expectStatus(t, decryptRecorder, http.StatusOK)
	var decrypted plaintextResponse
	decodeResponse(t, decryptRecorder, &decrypted)
	decoded, err := base64.StdEncoding.DecodeString(decrypted.Plaintext)
	if err != nil || !bytes.Equal(decoded, plaintext) {
		t.Fatalf("decrypted = %q, %v", decrypted.Plaintext, err)
	}
	wrongAADRecorder := jsonRequest(t, r, http.MethodPost, "/kms/decrypt", decryptJSON{
		KeyID:      created.ID,
		Ciphertext: encrypted.Ciphertext,
		AAD:        base64.StdEncoding.EncodeToString([]byte("tenant=other")),
	})
	expectStatus(t, wrongAADRecorder, http.StatusBadRequest)
	expectErrorCode(t, wrongAADRecorder, "authentication_failed")

	versionsRecorder := jsonRequest(t, r, http.MethodGet, keyPath+"/versions", nil)
	expectStatus(t, versionsRecorder, http.StatusOK)
	var versions versionListResponse
	decodeResponse(t, versionsRecorder, &versions)
	if versions.Count != 1 || len(versions.Versions) != 1 || versions.Versions[0].Material != nil {
		t.Fatalf("versions = %+v", versions)
	}

	rotateRecorder := jsonRequest(t, r, http.MethodPost, keyPath+"/rotate", nil)
	expectStatus(t, rotateRecorder, http.StatusOK)
	var rotated Key
	decodeResponse(t, rotateRecorder, &rotated)
	if rotated.Version != 2 {
		t.Fatalf("rotated version = %d, want 2", rotated.Version)
	}
	legacyDecrypt := jsonRequest(t, r, http.MethodPost, "/kms/decrypt", decryptJSON{
		KeyID:      created.ID,
		Ciphertext: encrypted.Ciphertext,
		AAD:        base64.StdEncoding.EncodeToString(aad),
	})
	expectStatus(t, legacyDecrypt, http.StatusOK)

	signCreate := jsonRequest(t, r, http.MethodPost, "/kms/keys", createKeyJSON{Type: KeyTypeECDSA, Bits: 256, Alias: "signer"})
	expectStatus(t, signCreate, http.StatusCreated)
	var signingKey Key
	decodeResponse(t, signCreate, &signingKey)
	expectStatus(t, jsonRequest(t, r, http.MethodPost, "/kms/keys/"+signingKey.ID+"/activate", nil), http.StatusOK)
	message := []byte("message over the router")
	signRecorder := jsonRequest(t, r, http.MethodPost, "/kms/sign", signJSON{
		KeyID: signingKey.ID,
		Data:  base64.StdEncoding.EncodeToString(message),
	})
	expectStatus(t, signRecorder, http.StatusOK)
	var signed signatureResponse
	decodeResponse(t, signRecorder, &signed)
	if signed.Signature == "" || signed.Algorithm == "" {
		t.Fatalf("signature response = %+v", signed)
	}
	verifyRecorder := jsonRequest(t, r, http.MethodPost, "/kms/verify", signJSON{
		KeyID:     signingKey.ID,
		Data:      base64.StdEncoding.EncodeToString(message),
		Signature: signed.Signature,
	})
	expectStatus(t, verifyRecorder, http.StatusOK)
	var verified verifyResponse
	decodeResponse(t, verifyRecorder, &verified)
	if !verified.Valid {
		t.Fatal("valid signature did not verify")
	}
	tamperedVerify := jsonRequest(t, r, http.MethodPost, "/kms/verify", signJSON{
		KeyID:     signingKey.ID,
		Data:      base64.StdEncoding.EncodeToString([]byte("tampered")),
		Signature: signed.Signature,
	})
	expectStatus(t, tamperedVerify, http.StatusOK)
	decodeResponse(t, tamperedVerify, &verified)
	if verified.Valid {
		t.Fatal("tampered message verified")
	}

	listRecorder := jsonRequest(t, r, http.MethodGet, "/kms/keys?tag=prod&state=active&q=api", nil)
	expectStatus(t, listRecorder, http.StatusOK)
	var listed keyListResponse
	decodeResponse(t, listRecorder, &listed)
	if listed.Count != 1 || len(listed.Keys) != 1 || listed.Keys[0].ID != created.ID || listed.Keys[0].Material != nil {
		t.Fatalf("listed keys = %+v", listed)
	}

	updateRecorder := jsonRequest(t, r, http.MethodPatch, keyPath, updateKeyJSON{
		Alias:    stringPointer("renamed-key"),
		Metadata: map[string]string{"owner": "platform"},
		Tags:     stringSlicePointer([]string{"prod"}),
	})
	expectStatus(t, updateRecorder, http.StatusOK)
	var updated Key
	decodeResponse(t, updateRecorder, &updated)
	if updated.Alias != "renamed-key" || updated.Metadata["owner"] != "platform" || len(updated.Tags) != 1 {
		t.Fatalf("updated key = %+v", updated)
	}

	dataKeyRecorder := jsonRequest(t, r, http.MethodPost, "/kms/generate-data-key", generateDataKeyJSON{
		KeyID:  created.ID,
		Length: 32,
		AAD:    base64.StdEncoding.EncodeToString([]byte("dek-aad")),
	})
	expectStatus(t, dataKeyRecorder, http.StatusOK)
	var dataKey dataKeyResponse
	decodeResponse(t, dataKeyRecorder, &dataKey)
	wrappedDEK, err := base64.StdEncoding.DecodeString(dataKey.Wrapped)
	if err != nil || !bytes.HasPrefix(wrappedDEK, wrappedMagic) || len(dataKey.Plaintext) == 0 {
		t.Fatalf("data key response = %+v, %v", dataKey, err)
	}

	randomRecorder := jsonRequest(t, r, http.MethodPost, "/kms/random", randomJSON{Length: 16})
	expectStatus(t, randomRecorder, http.StatusOK)
	var random randomResponse
	decodeResponse(t, randomRecorder, &random)
	rawRandom, err := base64.StdEncoding.DecodeString(random.Random)
	if err != nil || len(rawRandom) != 16 {
		t.Fatalf("random = %q, %v", random.Random, err)
	}

	auditRecorder := jsonRequest(t, r, http.MethodGet, "/kms/audit?keyId="+created.ID, nil)
	expectStatus(t, auditRecorder, http.StatusOK)
	var audit auditListResponse
	decodeResponse(t, auditRecorder, &audit)
	if audit.Count < 6 || len(audit.Events) != audit.Count {
		t.Fatalf("audit events = %+v", audit)
	}
	seen := make(map[string]bool)
	for _, event := range audit.Events {
		seen[event.Operation] = true
		if strings.Contains(event.Operation, "secret") {
			t.Fatalf("audit leaked payload: %+v", event)
		}
	}
	for _, operation := range []string{OperationKeyCreate, OperationKeyActivate, OperationEncrypt, OperationDecrypt, OperationKeyRotate} {
		if !seen[operation] {
			t.Errorf("missing audit operation %q", operation)
		}
	}
	if strings.Contains(auditRecorder.Body.String(), encrypted.Ciphertext) {
		t.Fatal("audit response leaked ciphertext")
	}

	exportRecorder := jsonRequest(t, r, http.MethodPost, keyPath+"/export", exportKeyJSON{Format: ExportFormatRaw, Private: true})
	expectStatus(t, exportRecorder, http.StatusForbidden)
	expectErrorCode(t, exportRecorder, "export_denied")
	publicExport := jsonRequest(t, r, http.MethodPost, "/kms/keys/"+signingKey.ID+"/export", exportKeyJSON{Format: ExportFormatPEM})
	expectStatus(t, publicExport, http.StatusOK)
	var publicKey ExportedKey
	decodeResponse(t, publicExport, &publicKey)
	if publicKey.Private || !bytes.Contains(publicKey.PublicMaterial, []byte("BEGIN PUBLIC KEY")) {
		t.Fatalf("public export = %+v", publicKey)
	}

	deleteRecorder := jsonRequest(t, r, http.MethodDelete, keyPath+"?delay=60", nil)
	expectStatus(t, deleteRecorder, http.StatusOK)
	var scheduled Key
	decodeResponse(t, deleteRecorder, &scheduled)
	if scheduled.State != StatePendingDeletion || !scheduled.DeleteAfter.Equal(clock.Now().Add(time.Minute)) {
		t.Fatalf("scheduled key = %+v", scheduled)
	}
	encryptAfterDelete := jsonRequest(t, r, http.MethodPost, "/kms/encrypt", encryptJSON{
		KeyID:     created.ID,
		Plaintext: base64.StdEncoding.EncodeToString([]byte("nope")),
	})
	expectStatus(t, encryptAfterDelete, http.StatusConflict)
	expectErrorCode(t, encryptAfterDelete, "key_not_usable")

	missingRecorder := jsonRequest(t, r, http.MethodGet, "/kms/keys/does-not-exist", nil)
	expectStatus(t, missingRecorder, http.StatusNotFound)
	expectErrorCode(t, missingRecorder, "not_found")

	malformedRecorder := rawRequest(t, r, http.MethodPost, "/kms/encrypt", "{not-json")
	expectStatus(t, malformedRecorder, http.StatusBadRequest)
	expectErrorCode(t, malformedRecorder, "invalid_request")

	badBase64Recorder := jsonRequest(t, r, http.MethodPost, "/kms/decrypt", decryptJSON{KeyID: created.ID, Ciphertext: "!!!"})
	expectStatus(t, badBase64Recorder, http.StatusBadRequest)
	expectErrorCode(t, badBase64Recorder, "invalid_request")

	for _, recorder := range []*httptest.ResponseRecorder{createRecorder, listRecorder, auditRecorder, malformedRecorder} {
		if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("Cache-Control = %q, want no-store", got)
		}
		if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
			t.Fatalf("Content-Type = %q", got)
		}
	}
}

func TestServerHTTPHandlerEndToEnd(t *testing.T) {
	server, _, _ := newTestHTTPPair(t, Config{}, ServerConfig{})
	handler := server.HTTPHandler("kms/")

	createRecorder := jsonRequest(t, handler, http.MethodPost, "/kms/keys", createKeyJSON{Type: KeyTypeAES, Bits: 256, Alias: "http-key"})
	expectStatus(t, createRecorder, http.StatusCreated)
	var created Key
	decodeResponse(t, createRecorder, &created)
	if created.ID == "" || created.State != StatePreActive {
		t.Fatalf("created key = %+v", created)
	}
	expectStatus(t, jsonRequest(t, handler, http.MethodPost, "/kms/keys/"+created.ID+"/activate", nil), http.StatusOK)

	plaintext := []byte("net/http payload")
	encryptRecorder := jsonRequest(t, handler, http.MethodPost, "/kms/encrypt", encryptJSON{
		KeyID:     created.ID,
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	})
	expectStatus(t, encryptRecorder, http.StatusOK)
	var encrypted ciphertextResponse
	decodeResponse(t, encryptRecorder, &encrypted)
	decryptRecorder := jsonRequest(t, handler, http.MethodPost, "/kms/decrypt", decryptJSON{
		KeyID:      created.ID,
		Ciphertext: encrypted.Ciphertext,
	})
	expectStatus(t, decryptRecorder, http.StatusOK)
	var decrypted plaintextResponse
	decodeResponse(t, decryptRecorder, &decrypted)
	decoded, err := base64.StdEncoding.DecodeString(decrypted.Plaintext)
	if err != nil || !bytes.Equal(decoded, plaintext) {
		t.Fatalf("decrypted = %q, %v", decrypted.Plaintext, err)
	}
	auditRecorder := jsonRequest(t, handler, http.MethodGet, "/kms/audit?keyId="+created.ID, nil)
	expectStatus(t, auditRecorder, http.StatusOK)
	var audit auditListResponse
	decodeResponse(t, auditRecorder, &audit)
	if audit.Count == 0 {
		t.Fatal("no audit events over net/http")
	}

	missingRecorder := jsonRequest(t, handler, http.MethodGet, "/kms/keys/missing-key", nil)
	expectStatus(t, missingRecorder, http.StatusNotFound)
	expectErrorCode(t, missingRecorder, "not_found")
	malformedRecorder := rawRequest(t, handler, http.MethodPost, "/kms/encrypt", "{")
	expectStatus(t, malformedRecorder, http.StatusBadRequest)
	expectErrorCode(t, malformedRecorder, "invalid_request")
	methodRecorder := jsonRequest(t, handler, http.MethodPut, "/kms/keys", nil)
	expectStatus(t, methodRecorder, http.StatusMethodNotAllowed)

	for _, recorder := range []*httptest.ResponseRecorder{createRecorder, encryptRecorder, missingRecorder} {
		headers := recorder.Header()
		if headers.Get("Cache-Control") != "no-store" || headers.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("security headers = %v", headers)
		}
	}

	rootHandler := server.HTTPHandler("")
	rootCreate := jsonRequest(t, rootHandler, http.MethodPost, "/keys", createKeyJSON{Type: KeyTypeChaCha20})
	expectStatus(t, rootCreate, http.StatusCreated)

	var unavailable *Server
	unavailableRecorder := jsonRequest(t, unavailable.HTTPHandler(""), http.MethodGet, "/keys", nil)
	expectStatus(t, unavailableRecorder, http.StatusServiceUnavailable)
	expectErrorCode(t, unavailableRecorder, "unavailable")
}

func TestServerAuthorizer(t *testing.T) {
	server, service, _ := newTestHTTPPair(t, Config{}, ServerConfig{})
	key := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeAES}, true)
	type call struct {
		action string
		keyID  string
	}
	var calls []call
	server.authorizer = func(_ context.Context, _ *http.Request, action, keyID string) error {
		calls = append(calls, call{action: action, keyID: keyID})
		switch action {
		case ActionEncrypt:
			return ErrForbidden
		case ActionRandom:
			return ErrUnauthorized
		case ActionAudit:
			return errs.New("custom denial | 自定义拒绝")
		}
		return nil
	}
	handler := server.HTTPHandler("")

	encryptRecorder := jsonRequest(t, handler, http.MethodPost, "/encrypt", encryptJSON{
		KeyID:     key.ID,
		Plaintext: base64.StdEncoding.EncodeToString([]byte("denied")),
	})
	expectStatus(t, encryptRecorder, http.StatusForbidden)
	expectErrorCode(t, encryptRecorder, "forbidden")

	randomRecorder := jsonRequest(t, handler, http.MethodPost, "/random", randomJSON{Length: 8})
	expectStatus(t, randomRecorder, http.StatusUnauthorized)
	expectErrorCode(t, randomRecorder, "unauthorized")

	auditRecorder := jsonRequest(t, handler, http.MethodGet, "/audit", nil)
	expectStatus(t, auditRecorder, http.StatusForbidden)
	expectErrorCode(t, auditRecorder, "forbidden")

	getRecorder := jsonRequest(t, handler, http.MethodGet, "/keys/"+key.ID, nil)
	expectStatus(t, getRecorder, http.StatusOK)

	if len(calls) != 4 {
		t.Fatalf("authorizer calls = %+v", calls)
	}
	if calls[0].action != ActionEncrypt || calls[0].keyID != key.ID {
		t.Fatalf("first authorizer call = %+v", calls[0])
	}
	if calls[1].action != ActionRandom || calls[1].keyID != "" {
		t.Fatalf("second authorizer call = %+v", calls[1])
	}
	if calls[3].action != ActionKeyGet {
		t.Fatalf("fourth authorizer call = %+v", calls[3])
	}
}

func TestServerBodyLimit(t *testing.T) {
	server, _, _ := newTestHTTPPair(t, Config{}, ServerConfig{MaxBodyBytes: 64})
	handler := server.HTTPHandler("")

	small := rawRequest(t, handler, http.MethodPost, "/keys", `{"type":"AES"}`)
	expectStatus(t, small, http.StatusCreated)

	largeMetadata := make([]byte, 256)
	for i := range largeMetadata {
		largeMetadata[i] = 'x'
	}
	large := jsonRequest(t, handler, http.MethodPost, "/keys", createKeyJSON{Type: KeyTypeAES, Metadata: map[string]string{"blob": string(largeMetadata)}})
	expectStatus(t, large, http.StatusBadRequest)
	expectErrorCode(t, large, "invalid_request")
}

func TestNewServerValidation(t *testing.T) {
	if _, err := NewServer(nil, ServerConfig{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewServer(nil) err = %v, want ErrInvalidConfig", err)
	}
	service, _ := newServiceForTest(t, Config{})
	server, err := NewServer(service, ServerConfig{MaxBodyBytes: -1})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if server.Service() != service || server.maxBodyBytes != defaultMaxBodyBytes {
		t.Fatalf("server defaults = %+v", server)
	}
	if normalizePrefix("///") != "" || normalizePrefix("kms//") != "/kms" || normalizePrefix("/kms/") != "/kms" {
		t.Fatalf("normalizePrefix results = %q, %q, %q", normalizePrefix("///"), normalizePrefix("kms//"), normalizePrefix("/kms/"))
	}
}

func stringPointer(value string) *string { return &value }

func stringSlicePointer(value []string) *[]string { return &value }
