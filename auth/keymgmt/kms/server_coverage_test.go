package kms

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/shibingli/ydx/base64"
)

// TestServerHTTPLifecycleAndErrors covers the net/http surface, lifecycle routes, update, export,
// filters and negative query handling. | TestServerHTTPLifecycleAndErrors 覆盖 net/http 接口、生命周期
// 路由、更新、导出、过滤与查询参数失败路径。
func TestServerHTTPLifecycleAndErrors(t *testing.T) {
	server, service, clock := newTestHTTPPair(t, Config{ExportPolicy: ExportPolicy{AllowPrivate: true}}, ServerConfig{})
	handler := server.HTTPHandler("/api")

	createRecorder := jsonRequest(t, handler, http.MethodPost, "/api/keys", createKeyJSON{
		ID:         "http-life",
		Type:       KeyTypeAES,
		Bits:       256,
		Alias:      "before",
		Tags:       []string{"b", "a"},
		Metadata:   map[string]string{"team": "core"},
		Exportable: true,
	})
	expectStatus(t, createRecorder, http.StatusCreated)
	var created Key
	decodeResponse(t, createRecorder, &created)
	if created.ID != "http-life" || created.State != StatePreActive {
		t.Fatalf("created = %+v", created)
	}

	alias := "after"
	tags := []string{"z", "a", "z"}
	rotation := int64(60)
	exportable := true
	updateRecorder := jsonRequest(t, handler, http.MethodPatch, "/api/keys/http-life", updateKeyJSON{
		Alias:           &alias,
		Tags:            &tags,
		RotationSeconds: &rotation,
		Exportable:      &exportable,
		Metadata:        map[string]string{"team": "crypto"},
	})
	expectStatus(t, updateRecorder, http.StatusOK)
	var updated Key
	decodeResponse(t, updateRecorder, &updated)
	if updated.Alias != "after" || len(updated.Tags) != 2 || updated.RotationInterval != time.Minute || !updated.Exportable || updated.Metadata["team"] != "crypto" {
		t.Fatalf("updated = %+v", updated)
	}
	badAlias := "bad\x00"
	badUpdate := jsonRequest(t, handler, http.MethodPatch, "/api/keys/http-life", updateKeyJSON{Alias: &badAlias})
	expectStatus(t, badUpdate, http.StatusBadRequest)
	negativeRotation := int64(-1)
	badRotation := jsonRequest(t, handler, http.MethodPatch, "/api/keys/http-life", updateKeyJSON{RotationSeconds: &negativeRotation})
	expectStatus(t, badRotation, http.StatusBadRequest)
	missingUpdate := jsonRequest(t, handler, http.MethodPatch, "/api/keys/absent", updateKeyJSON{Alias: &alias})
	expectStatus(t, missingUpdate, http.StatusNotFound)

	listRecorder := jsonRequest(t, handler, http.MethodGet, "/api/keys?q=after&tag=a&state=pre-active&type=AES&usage=encrypt&limit=1&offset=0", nil)
	expectStatus(t, listRecorder, http.StatusOK)
	var list keyListResponse
	decodeResponse(t, listRecorder, &list)
	if list.Count != 1 || list.Keys[0].ID != "http-life" || list.Keys[0].Material != nil {
		t.Fatalf("list = %+v", list)
	}
	expectStatus(t, jsonRequest(t, handler, http.MethodGet, "/api/keys?limit=x", nil), http.StatusBadRequest)
	expectStatus(t, jsonRequest(t, handler, http.MethodGet, "/api/keys?offset=-1", nil), http.StatusBadRequest)
	expectStatus(t, jsonRequest(t, handler, http.MethodGet, "/api/keys/http-life/versions", nil), http.StatusOK)

	exportRecorder := jsonRequest(t, handler, http.MethodPost, "/api/keys/http-life/export", exportKeyJSON{Format: ExportFormatRaw, Private: true})
	expectStatus(t, exportRecorder, http.StatusOK)
	var exported ExportedKey
	decodeResponse(t, exportRecorder, &exported)
	if !exported.Private || len(exported.Material) != 32 {
		t.Fatalf("exported = %+v", exported)
	}
	expectStatus(t, jsonRequest(t, handler, http.MethodPost, "/api/keys/http-life/export", exportKeyJSON{Format: ExportFormat("bogus")}), http.StatusBadRequest)
	expectStatus(t, jsonRequest(t, handler, http.MethodPost, "/api/keys/http-life/export", exportKeyJSON{Version: 99, Private: true}), http.StatusNotFound)
	expectStatus(t, jsonRequest(t, handler, http.MethodPost, "/api/keys/absent/export", exportKeyJSON{}), http.StatusNotFound)

	expectStatus(t, jsonRequest(t, handler, http.MethodPost, "/api/keys/http-life/activate", nil), http.StatusOK)
	rotateRecorder := jsonRequest(t, handler, http.MethodPost, "/api/keys/http-life/rotate", nil)
	expectStatus(t, rotateRecorder, http.StatusOK)
	var rotated Key
	decodeResponse(t, rotateRecorder, &rotated)
	if rotated.Version != 2 {
		t.Fatalf("rotated version = %d", rotated.Version)
	}
	versionsRecorder := jsonRequest(t, handler, http.MethodGet, "/api/keys/http-life/versions", nil)
	expectStatus(t, versionsRecorder, http.StatusOK)
	var versions versionListResponse
	decodeResponse(t, versionsRecorder, &versions)
	if versions.Count != 2 || len(versions.Versions[0].Material) != 0 {
		t.Fatalf("versions = %+v", versions)
	}
	expectStatus(t, jsonRequest(t, handler, http.MethodPost, "/api/keys/http-life/deactivate", nil), http.StatusOK)
	expectStatus(t, jsonRequest(t, handler, http.MethodPost, "/api/keys/http-life/compromise", nil), http.StatusOK)
	expectStatus(t, jsonRequest(t, handler, http.MethodDelete, "/api/keys/http-life?delay=-1", nil), http.StatusBadRequest)
	deleteRecorder := jsonRequest(t, handler, http.MethodDelete, "/api/keys/http-life", nil)
	expectStatus(t, deleteRecorder, http.StatusOK)
	var pending Key
	decodeResponse(t, deleteRecorder, &pending)
	if pending.State != StatePendingDeletion || pending.DeleteAfter.IsZero() {
		t.Fatalf("pending = %+v", pending)
	}
	destroyRecorder := jsonRequest(t, handler, http.MethodPost, "/api/keys/http-life/destroy", nil)
	expectStatus(t, destroyRecorder, http.StatusOK)
	var destroyed Key
	decodeResponse(t, destroyRecorder, &destroyed)
	if destroyed.State != StateDestroyed || destroyed.Material != nil {
		t.Fatalf("destroyed = %+v", destroyed)
	}
	expectStatus(t, jsonRequest(t, handler, http.MethodPost, "/api/keys/http-life/activate", nil), http.StatusConflict)

	randomRecorder := jsonRequest(t, handler, http.MethodPost, "/api/random", randomJSON{Length: 16})
	expectStatus(t, randomRecorder, http.StatusOK)
	var random randomResponse
	decodeResponse(t, randomRecorder, &random)
	if len(random.Random) == 0 {
		t.Fatal("random response empty")
	}
	expectStatus(t, jsonRequest(t, handler, http.MethodPost, "/api/random", randomJSON{Length: 0}), http.StatusBadRequest)
	expectStatus(t, jsonRequest(t, handler, http.MethodPost, "/api/generate-data-key", generateDataKeyJSON{KeyID: "absent", Length: 16}), http.StatusNotFound)

	signKeyRecorder := jsonRequest(t, handler, http.MethodPost, "/api/keys", createKeyJSON{ID: "http-sign", Type: KeyTypeEd25519, Exportable: false})
	expectStatus(t, signKeyRecorder, http.StatusCreated)
	expectStatus(t, jsonRequest(t, handler, http.MethodPost, "/api/keys/http-sign/activate", nil), http.StatusOK)
	data := base64.StdEncoding.EncodeToString([]byte("signed payload"))
	signRecorder := jsonRequest(t, handler, http.MethodPost, "/api/sign", signJSON{KeyID: "http-sign", Data: data})
	expectStatus(t, signRecorder, http.StatusOK)
	var signature signatureResponse
	decodeResponse(t, signRecorder, &signature)
	if signature.Signature == "" || signature.Algorithm != "Ed25519" {
		t.Fatalf("signature = %+v", signature)
	}
	verifyRecorder := jsonRequest(t, handler, http.MethodPost, "/api/verify", signJSON{KeyID: "http-sign", Data: data, Signature: signature.Signature})
	expectStatus(t, verifyRecorder, http.StatusOK)
	var verified verifyResponse
	decodeResponse(t, verifyRecorder, &verified)
	if !verified.Valid {
		t.Fatal("signature must verify")
	}
	expectStatus(t, jsonRequest(t, handler, http.MethodPost, "/api/verify", signJSON{KeyID: "http-sign", Data: "not-base64!", Signature: signature.Signature}), http.StatusBadRequest)
	expectStatus(t, jsonRequest(t, handler, http.MethodPost, "/api/verify", signJSON{KeyID: "http-sign", Data: data, Signature: signature.Signature, Hash: "md5"}), http.StatusBadRequest)
	expectStatus(t, jsonRequest(t, handler, http.MethodPost, "/api/sign", signJSON{KeyID: "http-life", Data: data}), http.StatusConflict)

	expectStatus(t, jsonRequest(t, handler, http.MethodGet, "/api/audit?limit=x", nil), http.StatusBadRequest)
	expectStatus(t, jsonRequest(t, handler, http.MethodGet, "/api/audit?since=not-a-time", nil), http.StatusBadRequest)
	expectStatus(t, jsonRequest(t, handler, http.MethodGet, "/api/audit?descending=maybe", nil), http.StatusBadRequest)
	auditRecorder := jsonRequest(t, handler, http.MethodGet, "/api/audit?descending=true&limit=5&operation=key.create", nil)
	expectStatus(t, auditRecorder, http.StatusOK)
	var audit auditListResponse
	decodeResponse(t, auditRecorder, &audit)
	if audit.Count == 0 || audit.Count > 5 {
		t.Fatalf("audit count = %d", audit.Count)
	}

	keys := []*Key{{ID: "b", CreatedAt: clock.Now()}, {ID: "a", CreatedAt: clock.Now()}, {ID: "c", CreatedAt: clock.Now()}}
	sortKeys(keys)
	if keys[0].ID != "a" || keys[1].ID != "b" || keys[2].ID != "c" {
		t.Fatalf("sortKeys = %s,%s,%s", keys[0].ID, keys[1].ID, keys[2].ID)
	}
	if service.Now().IsZero() {
		t.Fatal("service clock must be set")
	}
}

// TestServerAuthorizerAndUnavailable covers authorizer mapping and nil-server behavior.
// | TestServerAuthorizerAndUnavailable 覆盖授权器映射与空服务器行为。
func TestServerAuthorizerAndUnavailable(t *testing.T) {
	service, _ := newServiceForTest(t, Config{})
	if _, err := NewServer(nil, ServerConfig{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewServer(nil) err = %v", err)
	}
	var nilServer *Server
	if nilServer.Service() != nil {
		t.Fatal("nil server Service must be nil")
	}
	unavailable := nilServer.HTTPHandler("")
	expectStatus(t, jsonRequest(t, unavailable, http.MethodGet, "/keys", nil), http.StatusServiceUnavailable)
	nilServer.Register(nil, "")

	server, err := NewServer(service, ServerConfig{Authorizer: func(_ context.Context, _ *http.Request, _, _ string) error {
		return ErrUnauthorized
	}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	handler := server.HTTPHandler("")
	expectStatus(t, jsonRequest(t, handler, http.MethodGet, "/keys", nil), http.StatusUnauthorized)

	server, err = NewServer(service, ServerConfig{Authorizer: func(_ context.Context, _ *http.Request, _, _ string) error {
		return ErrForbidden
	}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	expectStatus(t, jsonRequest(t, server.HTTPHandler(""), http.MethodGet, "/keys", nil), http.StatusForbidden)

	server, err = NewServer(service, ServerConfig{Authorizer: func(_ context.Context, _ *http.Request, _, _ string) error {
		return errors.New("opaque authorization failure")
	}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	expectStatus(t, jsonRequest(t, server.HTTPHandler(""), http.MethodGet, "/keys", nil), http.StatusForbidden)
}
