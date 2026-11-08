package scim

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// doRaw performs a router request with an explicit Content-Type; an empty value sends no header. |
// doRaw 以显式 Content-Type 执行路由器请求；空值不发送该头。
func (e *testEnv) doRaw(method, path, contentType string, body []byte) *httptest.ResponseRecorder {
	e.t.Helper()
	request := httptest.NewRequest(method, e.prefix+path, bytes.NewReader(body))
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	recorder := httptest.NewRecorder()
	e.engine.ServeHTTP(recorder, request)
	return recorder
}

// TestWriteContentTypeValidation verifies SCIM write requests accept only the RFC 7644 JSON media
// types and report HTTP 415 for anything else. | TestWriteContentTypeValidation 校验 SCIM 写请求只
// 接受 RFC 7644 的 JSON 媒体类型，其它一律返回 HTTP 415。
func TestWriteContentTypeValidation(t *testing.T) {
	env := newTestEnv(t, Options{}, "/scim")

	accepted := []string{ContentType, ContentTypeJSON, ContentType + "; charset=utf-8", "Application/SCIM+JSON"}
	for index, mediaType := range accepted {
		payload := []byte(`{"userName":"ct-accept-` + strconv.Itoa(index) + `"}`)
		recorder := env.doRaw(http.MethodPost, "/Users", mediaType, payload)
		requireStatus(t, recorder, http.StatusCreated)
	}
	rejected := []string{"", "text/plain", "application/xml", "application/scim+json; broken", "application"}
	for index, mediaType := range rejected {
		payload := []byte(`{"userName":"ct-reject-` + strconv.Itoa(index) + `"}`)
		recorder := env.doRaw(http.MethodPost, "/Users", mediaType, payload)
		requireError(t, recorder, http.StatusUnsupportedMediaType, "")
	}
	if names := listUserNames(t, env.store); len(names) != len(accepted) {
		t.Fatalf("stored users = %v", names)
	}

	user := env.mustCreateUser(map[string]any{"userName": "ct-target", "displayName": "Original"})
	recorder := env.doRaw(http.MethodPut, "/Users/"+user.ID, "text/plain",
		[]byte(`{"userName":"ct-target","displayName":"Changed"}`))
	requireError(t, recorder, http.StatusUnsupportedMediaType, "")
	recorder = env.doRaw(http.MethodPatch, "/Users/"+user.ID, "",
		[]byte(`{"schemas":["`+PatchOpSchema+`"],"Operations":[{"op":"replace","path":"displayName","value":"Changed"}]}`))
	requireError(t, recorder, http.StatusUnsupportedMediaType, "")
	stored, err := env.store.GetUser(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("GetUser error = %v", err)
	}
	if stored.DisplayName != "Original" {
		t.Fatalf("rejected media type changed the profile: %q", stored.DisplayName)
	}

	recorder = env.doRaw(http.MethodPost, "/Groups", "text/plain", []byte(`{"displayName":"ct-group"}`))
	requireError(t, recorder, http.StatusUnsupportedMediaType, "")
	recorder = env.doRaw(http.MethodPost, "/Users/.search", "text/plain", []byte(`{}`))
	requireError(t, recorder, http.StatusUnsupportedMediaType, "")
	recorder = env.doRaw(http.MethodPost, "/Bulk", "text/plain",
		[]byte(`{"Operations":[{"method":"POST","path":"/Users","data":{"userName":"ct-bulk"}}]}`))
	requireError(t, recorder, http.StatusUnsupportedMediaType, "")

	getRequest := httptest.NewRequest(http.MethodGet, env.prefix+"/Users/"+user.ID, nil)
	getRequest.Header.Set("Content-Type", "text/plain")
	getRecorder := httptest.NewRecorder()
	env.engine.ServeHTTP(getRecorder, getRequest)
	requireStatus(t, getRecorder, http.StatusOK)

	deleteRequest := httptest.NewRequest(http.MethodDelete, env.prefix+"/Users/"+user.ID, nil)
	deleteRequest.Header.Set("Content-Type", "text/plain")
	deleteRecorder := httptest.NewRecorder()
	env.engine.ServeHTTP(deleteRecorder, deleteRequest)
	requireStatus(t, deleteRecorder, http.StatusNoContent)
}

// TestAllowAnyContentType verifies the explicit compatibility opt-out accepts other media types. |
// TestAllowAnyContentType 校验显式兼容开关接受其它媒体类型。
func TestAllowAnyContentType(t *testing.T) {
	env := newTestEnv(t, Options{AllowAnyContentType: true}, "/scim")
	recorder := env.doRaw(http.MethodPost, "/Users", "text/plain", []byte(`{"userName":"ct-relaxed"}`))
	requireStatus(t, recorder, http.StatusCreated)
	recorder = env.doRaw(http.MethodPost, "/Users", "", []byte(`{"userName":"ct-relaxed-missing"}`))
	requireStatus(t, recorder, http.StatusCreated)
}
