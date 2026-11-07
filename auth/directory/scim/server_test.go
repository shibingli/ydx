package scim

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/shibingli/ydx/auth"
	ydxjson "github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/router"
)

// testEnv bundles a Server, its MemoryStore and a ydx router mount. | testEnv 组合 Server、MemoryStore
// 与 ydx 路由器挂载。
type testEnv struct {
	// t is the current test. | t 是当前测试。
	t *testing.T
	// server is the SCIM server. | server 是 SCIM 服务端。
	server *Server
	// store is the backing in-memory store. | store 是底层内存存储。
	store *MemoryStore
	// engine is the ydx router. | engine 是 ydx 路由器。
	engine *router.Router
	// prefix is the mount prefix. | prefix 是挂载前缀。
	prefix string
}

// newTestEnv creates a test environment with a MemoryStore and router mount. | newTestEnv 创建带
// MemoryStore 与路由器挂载的测试环境。
func newTestEnv(t *testing.T, options Options, prefix string) *testEnv {
	t.Helper()
	store, _ := options.Store.(*MemoryStore)
	if options.Store == nil {
		store = NewMemoryStore()
		options.Store = store
	}
	server, err := New(options)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	engine := router.New()
	server.Register(engine, prefix)
	return &testEnv{t: t, server: server, store: store, engine: engine, prefix: normalizePrefix(prefix)}
}

// do performs a router request with an empty body or a JSON encoded body. | do 执行路由器请求，body
// 为 nil 或 JSON 编码对象。
func (e *testEnv) do(method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	e.t.Helper()
	return e.doContext(context.Background(), method, path, body, headers)
}

// doContext performs a router request with ctx attached to the request. | doContext 执行附带 ctx 的
// 路由器请求。
func (e *testEnv) doContext(ctx context.Context, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	e.t.Helper()
	var data []byte
	if body != nil {
		if raw, ok := body.([]byte); ok {
			data = raw
		} else {
			encoded, err := ydxjson.Marshal(body)
			if err != nil {
				e.t.Fatalf("marshal body error = %v", err)
			}
			data = encoded
		}
	}
	request := httptest.NewRequest(method, e.prefix+path, bytes.NewReader(data))
	request = request.WithContext(ctx)
	if body != nil {
		request.Header.Set("Content-Type", ContentType)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	e.engine.ServeHTTP(recorder, request)
	return recorder
}

// decodeResponse decodes a SCIM response body into T. | decodeResponse 把 SCIM 响应体解码为 T。
func decodeResponse[T any](t *testing.T, recorder *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	if err := ydxjson.Unmarshal(recorder.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response %q error = %v", recorder.Body.String(), err)
	}
	return out
}

// requireStatus asserts the response status. | requireStatus 断言响应状态。
func requireStatus(t *testing.T, recorder *httptest.ResponseRecorder, want int) {
	t.Helper()
	if recorder.Code != want {
		t.Fatalf("status = %d, want %d, body = %s", recorder.Code, want, recorder.Body.String())
	}
	if want == http.StatusNoContent || want == http.StatusNotModified {
		if recorder.Body.Len() != 0 {
			t.Fatalf("%d body = %q", want, recorder.Body.String())
		}
		return
	}
	if got := recorder.Header().Get("Content-Type"); got != ContentType {
		t.Fatalf("Content-Type = %q, want %q", got, ContentType)
	}
}

// requireError asserts the response status, scimType and returns the error body. | requireError 断言
// 响应状态与 scimType 并返回错误体。
func requireError(t *testing.T, recorder *httptest.ResponseRecorder, status int, scimType string) Error {
	t.Helper()
	requireStatus(t, recorder, status)
	body := decodeResponse[Error](t, recorder)
	if body.Status != intString(status) {
		t.Fatalf("error status = %q, want %d", body.Status, status)
	}
	if body.ScimType != scimType {
		t.Fatalf("scimType = %q, want %q, detail = %q", body.ScimType, scimType, body.Detail)
	}
	if len(body.Schemas) != 1 || body.Schemas[0] != ErrorSchema {
		t.Fatalf("error schemas = %v", body.Schemas)
	}
	return body
}

// mustCreateUser creates a User through the router and returns it. | mustCreateUser 经路由器创建
// User 并返回。
func (e *testEnv) mustCreateUser(payload map[string]any) User {
	e.t.Helper()
	recorder := e.do(http.MethodPost, "/Users", payload, nil)
	requireStatus(e.t, recorder, http.StatusCreated)
	return decodeResponse[User](e.t, recorder)
}

// mustCreateGroup creates a Group through the router and returns it. | mustCreateGroup 经路由器创建
// Group 并返回。
func (e *testEnv) mustCreateGroup(payload map[string]any) Group {
	e.t.Helper()
	recorder := e.do(http.MethodPost, "/Groups", payload, nil)
	requireStatus(e.t, recorder, http.StatusCreated)
	return decodeResponse[Group](e.t, recorder)
}

// rawListResponse is a ListResponse with untyped resources for attribute tests. | rawListResponse 是
// 资源未类型化的 ListResponse，用于属性测试。
type rawListResponse struct {
	Schemas      []string         `json:"schemas"`
	TotalResults int              `json:"totalResults"`
	StartIndex   int              `json:"startIndex"`
	ItemsPerPage int              `json:"itemsPerPage"`
	Resources    []map[string]any `json:"Resources"`
}

func TestRouterUserCRUD(t *testing.T) {
	var provisionedID, provisionedPassword string
	env := newTestEnv(t, Options{
		PasswordSetter: func(ctx context.Context, user *User, password string) error {
			provisionedID = user.ID
			provisionedPassword = password
			return nil
		},
		DocumentationURI: "https://example.com/docs",
	}, "/scim")

	recorder := env.do(http.MethodPost, "/Users", map[string]any{
		"userName":    "Alice",
		"displayName": "Alice Smith",
		"password":    "initial-secret",
		"emails": []any{
			map[string]any{"value": "alice@example.com", "type": "work", "primary": true},
		},
	}, nil)
	requireStatus(t, recorder, http.StatusCreated)
	created := decodeResponse[User](t, recorder)
	if created.ID == "" || created.UserName != "Alice" || !created.ActiveValue() {
		t.Fatalf("created = %+v", created)
	}
	if provisionedID != created.ID || provisionedPassword != "initial-secret" {
		t.Fatalf("password hook = %q, %q", provisionedID, provisionedPassword)
	}
	if strings.Contains(recorder.Body.String(), "initial-secret") || strings.Contains(recorder.Body.String(), `"password"`) {
		t.Fatalf("password leaked in body: %s", recorder.Body.String())
	}
	if location := recorder.Header().Get("Location"); !strings.HasSuffix(location, "/scim/Users/"+created.ID) {
		t.Fatalf("Location = %q", location)
	}
	if created.Meta == nil || created.Meta.ResourceType != ResourceTypeNameUser || created.Meta.Location == "" {
		t.Fatalf("meta = %+v", created.Meta)
	}
	etag := recorder.Header().Get("ETag")
	if etag == "" || created.Meta.Version != etag {
		t.Fatalf("ETag = %q, meta version = %q", etag, created.Meta.Version)
	}
	stored, err := env.store.GetUser(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("GetUser error = %v", err)
	}
	if stored.Password != "" {
		t.Fatalf("stored password = %q", stored.Password)
	}

	recorder = env.do(http.MethodGet, "/Users/"+created.ID, nil, nil)
	requireStatus(t, recorder, http.StatusOK)
	if recorder.Header().Get("ETag") != etag {
		t.Fatalf("GET ETag = %q, want %q", recorder.Header().Get("ETag"), etag)
	}

	recorder = env.do(http.MethodPut, "/Users/"+created.ID, map[string]any{
		"userName":    "Alice",
		"displayName": "Alice Jones",
		"title":       "Manager",
	}, map[string]string{"If-Match": etag})
	requireStatus(t, recorder, http.StatusOK)
	replaced := decodeResponse[User](t, recorder)
	if replaced.DisplayName != "Alice Jones" || replaced.ID != created.ID || replaced.Meta.Created != created.Meta.Created {
		t.Fatalf("replaced = %+v", replaced)
	}
	if replaced.Meta.Version == etag {
		t.Fatalf("version did not change")
	}

	recorder = env.do(http.MethodPatch, "/Users/"+created.ID, PatchRequest{
		Schemas: []string{PatchOpSchema},
		Operations: []PatchOperation{
			{Op: "replace", Path: "nickName", Value: "Ali"},
		},
	}, nil)
	requireStatus(t, recorder, http.StatusOK)
	patched := decodeResponse[User](t, recorder)
	if patched.NickName != "Ali" {
		t.Fatalf("patched = %+v", patched)
	}

	recorder = env.do(http.MethodDelete, "/Users/"+created.ID, nil, map[string]string{"If-Match": patched.Meta.Version})
	requireStatus(t, recorder, http.StatusNoContent)
	if recorder.Body.Len() != 0 {
		t.Fatalf("DELETE body = %q", recorder.Body.String())
	}
	recorder = env.do(http.MethodGet, "/Users/"+created.ID, nil, nil)
	requireError(t, recorder, http.StatusNotFound, "")

	recorder = env.do(http.MethodGet, "/Users", nil, nil)
	requireStatus(t, recorder, http.StatusOK)
	page := decodeResponse[rawListResponse](t, recorder)
	if page.TotalResults != 0 || page.ItemsPerPage != 0 || page.StartIndex != 1 || len(page.Resources) != 0 {
		t.Fatalf("empty page = %+v", page)
	}
	if !strings.Contains(recorder.Body.String(), `"Resources":[]`) {
		t.Fatalf("empty Resources missing: %s", recorder.Body.String())
	}
}

func TestETagPreconditions(t *testing.T) {
	env := newTestEnv(t, Options{}, "/scim")
	recorder := env.do(http.MethodPost, "/Users", map[string]any{"userName": "etag-user"}, nil)
	requireStatus(t, recorder, http.StatusCreated)
	user := decodeResponse[User](t, recorder)
	etag := recorder.Header().Get("ETag")
	if etag == "" {
		t.Fatalf("missing ETag")
	}

	recorder = env.do(http.MethodGet, "/Users/"+user.ID, nil, map[string]string{"If-None-Match": etag})
	requireStatus(t, recorder, http.StatusNotModified)
	if recorder.Body.Len() != 0 {
		t.Fatalf("304 body = %q", recorder.Body.String())
	}
	if recorder.Header().Get("ETag") != etag {
		t.Fatalf("304 ETag = %q", recorder.Header().Get("ETag"))
	}

	recorder = env.do(http.MethodGet, "/Users/"+user.ID, nil, map[string]string{"If-None-Match": `W/"other"`})
	requireStatus(t, recorder, http.StatusOK)

	recorder = env.do(http.MethodGet, "/Users/"+user.ID, nil, map[string]string{"If-Match": `W/"stale"`})
	requireError(t, recorder, http.StatusPreconditionFailed, "invalidVers")

	recorder = env.do(http.MethodPut, "/Users/"+user.ID, map[string]any{"userName": "etag-user"},
		map[string]string{"If-Match": `W/"stale"`})
	requireError(t, recorder, http.StatusPreconditionFailed, "invalidVers")

	recorder = env.do(http.MethodPatch, "/Users/"+user.ID, PatchRequest{
		Operations: []PatchOperation{{Op: "replace", Path: "displayName", Value: "x"}},
	}, map[string]string{"If-Match": `W/"stale"`})
	requireError(t, recorder, http.StatusPreconditionFailed, "invalidVers")

	recorder = env.do(http.MethodDelete, "/Users/"+user.ID, nil, map[string]string{"If-Match": `W/"stale"`})
	requireError(t, recorder, http.StatusPreconditionFailed, "invalidVers")

	recorder = env.do(http.MethodPut, "/Users/"+user.ID, map[string]any{"userName": "etag-user", "displayName": "updated"},
		map[string]string{"If-Match": "*"})
	requireStatus(t, recorder, http.StatusOK)
	updated := decodeResponse[User](t, recorder)
	if updated.Meta.Version == etag {
		t.Fatalf("If-Match * replacement did not change version")
	}

	recorder = env.do(http.MethodPut, "/Users/"+user.ID, map[string]any{"userName": "etag-user"},
		map[string]string{"If-None-Match": "*"})
	requireError(t, recorder, http.StatusPreconditionFailed, "invalidVers")
}

func TestPaginationSortingAndAttributeSelection(t *testing.T) {
	env := newTestEnv(t, Options{MaxResults: 3}, "/scim")
	for _, name := range []string{"alice", "bob", "carol", "dave", "eve"} {
		env.mustCreateUser(map[string]any{
			"userName":    name,
			"displayName": strings.ToUpper(name),
			"title":       "Engineer",
			"emails": []any{
				map[string]any{"value": name + "@example.com", "type": "work", "primary": true},
			},
		})
	}

	query := url.Values{}
	query.Set("sortBy", "userName")
	query.Set("sortOrder", "descending")
	query.Set("startIndex", "2")
	query.Set("count", "2")
	recorder := env.do(http.MethodGet, "/Users?"+query.Encode(), nil, nil)
	requireStatus(t, recorder, http.StatusOK)
	page := decodeResponse[rawListResponse](t, recorder)
	if page.TotalResults != 5 || page.StartIndex != 2 || page.ItemsPerPage != 2 || len(page.Resources) != 2 {
		t.Fatalf("page = %+v", page)
	}
	if page.Resources[0]["userName"] != "dave" || page.Resources[1]["userName"] != "carol" {
		t.Fatalf("page names = %v, %v", page.Resources[0]["userName"], page.Resources[1]["userName"])
	}

	query = url.Values{}
	query.Set("filter", `title eq "Engineer" and userName sw "a"`)
	recorder = env.do(http.MethodGet, "/Users?"+query.Encode(), nil, nil)
	requireStatus(t, recorder, http.StatusOK)
	page = decodeResponse[rawListResponse](t, recorder)
	if page.TotalResults != 1 || page.Resources[0]["userName"] != "alice" {
		t.Fatalf("filtered page = %+v", page)
	}

	query = url.Values{}
	query.Set("attributes", "userName,emails.value")
	recorder = env.do(http.MethodGet, "/Users?count=1&"+query.Encode(), nil, nil)
	requireStatus(t, recorder, http.StatusOK)
	page = decodeResponse[rawListResponse](t, recorder)
	if len(page.Resources) != 1 {
		t.Fatalf("projected page = %+v", page)
	}
	projected := page.Resources[0]
	if projected["userName"] == nil || projected["id"] == nil || projected["meta"] == nil || projected["schemas"] == nil {
		t.Fatalf("required attributes missing: %+v", projected)
	}
	if _, exists := projected["displayName"]; exists {
		t.Fatalf("displayName was not excluded: %+v", projected)
	}
	emails, ok := projected["emails"].([]any)
	if !ok || len(emails) != 1 {
		t.Fatalf("emails = %#v", projected["emails"])
	}
	email, ok := emails[0].(map[string]any)
	if !ok || len(email) != 1 || email["value"] == nil {
		t.Fatalf("projected email = %#v", emails[0])
	}

	query = url.Values{}
	query.Set("excludedAttributes", "emails,displayName")
	recorder = env.do(http.MethodGet, "/Users?count=1&"+query.Encode(), nil, nil)
	requireStatus(t, recorder, http.StatusOK)
	page = decodeResponse[rawListResponse](t, recorder)
	if _, exists := page.Resources[0]["emails"]; exists {
		t.Fatalf("emails were not excluded: %+v", page.Resources[0])
	}
	if _, exists := page.Resources[0]["displayName"]; exists {
		t.Fatalf("displayName was not excluded: %+v", page.Resources[0])
	}

	recorder = env.do(http.MethodGet, "/Users?count=4", nil, nil)
	requireError(t, recorder, http.StatusBadRequest, "tooMany")
	recorder = env.do(http.MethodGet, "/Users?count=-1", nil, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidValue")
	recorder = env.do(http.MethodGet, "/Users?startIndex=-1", nil, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidValue")
	recorder = env.do(http.MethodGet, "/Users?sortOrder=sideways", nil, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidValue")
	recorder = env.do(http.MethodGet, "/Users?attributes=userName&excludedAttributes=title", nil, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidValue")
	recorder = env.do(http.MethodGet, "/Users?attributes=emails%5Btype+eq+%22work%22%5D", nil, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidValue")
}

func TestSearchEndpoints(t *testing.T) {
	env := newTestEnv(t, Options{MaxResults: 2}, "/scim")
	for _, name := range []string{"alice", "bob", "carol"} {
		env.mustCreateUser(map[string]any{"userName": name, "title": "Engineer"})
	}
	recorder := env.do(http.MethodPost, "/Users/.search", SearchRequest{
		Filter:     `title eq "Engineer"`,
		SortBy:     "userName",
		SortOrder:  "descending",
		StartIndex: 1,
		Count:      2,
	}, nil)
	requireStatus(t, recorder, http.StatusOK)
	page := decodeResponse[rawListResponse](t, recorder)
	if page.TotalResults != 3 || len(page.Resources) != 2 || page.Resources[0]["userName"] != "carol" {
		t.Fatalf("search page = %+v", page)
	}

	recorder = env.do(http.MethodPost, "/Users/.search", SearchRequest{Filter: `userName eq "nobody"`}, nil)
	requireStatus(t, recorder, http.StatusOK)
	page = decodeResponse[rawListResponse](t, recorder)
	if page.TotalResults != 0 || len(page.Resources) != 0 {
		t.Fatalf("empty search = %+v", page)
	}

	recorder = env.do(http.MethodPost, "/Users/.search", SearchRequest{Filter: "not valid"}, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidFilter")
	recorder = env.do(http.MethodPost, "/Users/.search", SearchRequest{Count: 3}, nil)
	requireError(t, recorder, http.StatusBadRequest, "tooMany")
	recorder = env.do(http.MethodPost, "/Users/.search", SearchRequest{SortOrder: "nope"}, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidValue")
	recorder = env.do(http.MethodPost, "/Users/.search", SearchRequest{
		Attributes:         []string{"userName"},
		ExcludedAttributes: []string{"title"},
	}, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidValue")

	groupRecorder := env.do(http.MethodPost, "/Groups", map[string]any{"displayName": "search-group"}, nil)
	requireStatus(t, groupRecorder, http.StatusCreated)
	recorder = env.do(http.MethodPost, "/Groups/.search", SearchRequest{Filter: `displayName sw "search"`}, nil)
	requireStatus(t, recorder, http.StatusOK)
	groupPage := decodeResponse[struct {
		TotalResults int              `json:"totalResults"`
		Resources    []map[string]any `json:"Resources"`
	}](t, recorder)
	if groupPage.TotalResults != 1 || len(groupPage.Resources) != 1 {
		t.Fatalf("group search = %+v", groupPage)
	}
}

func TestGroupCRUDAndPatch(t *testing.T) {
	env := newTestEnv(t, Options{}, "/scim")
	user := env.mustCreateUser(map[string]any{"userName": "member-one"})
	group := env.mustCreateGroup(map[string]any{
		"displayName": "Admins",
		"members": []any{
			map[string]any{"value": user.ID, "display": "Member One", "type": "User"},
		},
	})
	if group.ID == "" || group.Meta == nil || len(group.Members) != 1 {
		t.Fatalf("group = %+v", group)
	}
	if location := group.Meta.Location; !strings.HasSuffix(location, "/scim/Groups/"+group.ID) {
		t.Fatalf("group location = %q", location)
	}

	recorder := env.do(http.MethodGet, "/Groups/"+group.ID, nil, nil)
	requireStatus(t, recorder, http.StatusOK)
	if recorder.Header().Get("ETag") != group.Meta.Version {
		t.Fatalf("group ETag mismatch")
	}

	second := env.mustCreateUser(map[string]any{"userName": "member-two"})
	recorder = env.do(http.MethodPatch, "/Groups/"+group.ID, PatchRequest{
		Schemas: []string{PatchOpSchema},
		Operations: []PatchOperation{
			{Op: "replace", Path: "displayName", Value: "Operators"},
			{Op: "add", Path: "members", Value: map[string]any{"value": second.ID, "display": "Member Two"}},
		},
	}, nil)
	requireStatus(t, recorder, http.StatusOK)
	patched := decodeResponse[Group](t, recorder)
	if patched.DisplayName != "Operators" || len(patched.Members) != 2 {
		t.Fatalf("patched group = %+v", patched)
	}

	recorder = env.do(http.MethodPatch, "/Groups/"+group.ID, PatchRequest{
		Operations: []PatchOperation{{Op: "remove", Path: `members[value eq "` + user.ID + `"]`}},
	}, nil)
	requireStatus(t, recorder, http.StatusOK)
	patched = decodeResponse[Group](t, recorder)
	if len(patched.Members) != 1 || patched.Members[0].Value != second.ID {
		t.Fatalf("members = %+v", patched.Members)
	}

	recorder = env.do(http.MethodPut, "/Groups/"+group.ID, map[string]any{
		"displayName": "Operators",
		"members": []any{
			map[string]any{"value": second.ID, "display": "Member Two", "type": "User"},
		},
	}, map[string]string{"If-Match": patched.Meta.Version})
	requireStatus(t, recorder, http.StatusOK)
	replaced := decodeResponse[Group](t, recorder)
	if replaced.DisplayName != "Operators" || len(replaced.Members) != 1 {
		t.Fatalf("replaced group = %+v", replaced)
	}

	recorder = env.do(http.MethodDelete, "/Groups/"+group.ID, nil, nil)
	requireStatus(t, recorder, http.StatusNoContent)
	recorder = env.do(http.MethodGet, "/Groups/"+group.ID, nil, nil)
	requireError(t, recorder, http.StatusNotFound, "")

	recorder = env.do(http.MethodPost, "/Groups", map[string]any{"displayName": "Admins"}, nil)
	requireStatus(t, recorder, http.StatusCreated)
	recorder = env.do(http.MethodPost, "/Groups", map[string]any{"displayName": "admins"}, nil)
	requireError(t, recorder, http.StatusConflict, "uniqueness")
}

func TestScimTypeErrors(t *testing.T) {
	env := newTestEnv(t, Options{}, "/scim")
	env.mustCreateUser(map[string]any{"userName": "duplicate"})

	recorder := env.do(http.MethodPost, "/Users", map[string]any{"userName": "Duplicate"}, nil)
	requireError(t, recorder, http.StatusConflict, "uniqueness")

	recorder = env.do(http.MethodGet, `/Users?filter=userName+xx+%22a%22`, nil, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidFilter")

	recorder = env.do(http.MethodPost, "/Users", map[string]any{"displayName": "missing userName"}, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidValue")

	recorder = env.do(http.MethodPost, "/Users", []byte(`{"userName":`), map[string]string{"Content-Type": ContentType})
	requireError(t, recorder, http.StatusBadRequest, "invalidSyntax")

	user := env.mustCreateUser(map[string]any{"userName": "patch-target"})
	recorder = env.do(http.MethodPatch, "/Users/"+user.ID, PatchRequest{
		Schemas:    []string{PatchOpSchema},
		Operations: []PatchOperation{{Op: "replace", Path: "id", Value: "other"}},
	}, nil)
	requireError(t, recorder, http.StatusBadRequest, "mutability")

	recorder = env.do(http.MethodPatch, "/Users/"+user.ID, PatchRequest{
		Operations: []PatchOperation{{Op: "replace", Path: "unknownAttr", Value: "x"}},
	}, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidPath")

	recorder = env.do(http.MethodPatch, "/Users/"+user.ID, PatchRequest{
		Operations: []PatchOperation{{Op: "remove", Path: `emails[type eq "missing"]`}},
	}, nil)
	requireError(t, recorder, http.StatusBadRequest, "noTarget")

	recorder = env.do(http.MethodPatch, "/Users/"+user.ID, PatchRequest{Schemas: []string{PatchOpSchema}}, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidSyntax")

	recorder = env.do(http.MethodPatch, "/Users/"+user.ID, PatchRequest{
		Schemas:    []string{UserSchema},
		Operations: []PatchOperation{{Op: "replace", Path: "displayName", Value: "x"}},
	}, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidSyntax")

	recorder = env.do(http.MethodPatch, "/Users/"+user.ID, PatchRequest{
		Operations: []PatchOperation{{Op: "copy", Path: "displayName", Value: "x"}},
	}, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidSyntax")

	recorder = env.do(http.MethodGet, "/Users/missing", nil, nil)
	requireError(t, recorder, http.StatusNotFound, "")
}

func TestPasswordProvisioning(t *testing.T) {
	env := newTestEnv(t, Options{}, "/scim")
	recorder := env.do(http.MethodPost, "/Users", map[string]any{
		"userName": "with-password",
		"password": "secret",
	}, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidValue")
	recorder = env.do(http.MethodGet, "/Users", nil, nil)
	requireStatus(t, recorder, http.StatusOK)
	if page := decodeResponse[rawListResponse](t, recorder); page.TotalResults != 0 {
		t.Fatalf("user was persisted despite missing hook: %+v", page)
	}
	env.mustCreateUser(map[string]any{"userName": "without-password"})

	var calls int
	env = newTestEnv(t, Options{PasswordSetter: func(ctx context.Context, user *User, password string) error {
		calls++
		if password == "rejected" {
			return errors.New("rejected by hook")
		}
		return nil
	}}, "/scim")
	recorder = env.do(http.MethodPost, "/Users", map[string]any{
		"userName": "hooked",
		"password": "accepted",
	}, nil)
	requireStatus(t, recorder, http.StatusCreated)
	created := decodeResponse[User](t, recorder)
	if calls != 1 {
		t.Fatalf("hook calls = %d", calls)
	}
	recorder = env.do(http.MethodPost, "/Users", map[string]any{
		"userName": "rejected",
		"password": "rejected",
	}, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidValue")
	stored, err := env.store.GetUser(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("GetUser error = %v", err)
	}
	if stored.Password != "" {
		t.Fatalf("stored password = %q", stored.Password)
	}
	recorder = env.do(http.MethodGet, "/Users", nil, nil)
	page := decodeResponse[rawListResponse](t, recorder)
	if page.TotalResults != 1 {
		t.Fatalf("failed hook did not roll back: %+v", page)
	}
}

func TestMeEndpoints(t *testing.T) {
	env := newTestEnv(t, Options{}, "/scim")
	user := env.mustCreateUser(map[string]any{"userName": "me-user", "displayName": "Me"})
	principal := &auth.Principal{Subject: user.ID}
	ctx := auth.ContextWithPrincipal(context.Background(), principal)

	recorder := env.do(http.MethodGet, "/Me", nil, nil)
	requireError(t, recorder, http.StatusUnauthorized, "")
	if recorder.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q", recorder.Header().Get("WWW-Authenticate"))
	}

	recorder = env.doContext(ctx, http.MethodGet, "/Me", nil, nil)
	requireStatus(t, recorder, http.StatusOK)
	me := decodeResponse[User](t, recorder)
	if me.ID != user.ID || me.UserName != "me-user" {
		t.Fatalf("me = %+v", me)
	}

	recorder = env.doContext(ctx, http.MethodPut, "/Me", map[string]any{
		"userName":    "me-user",
		"displayName": "Me Updated",
	}, nil)
	requireStatus(t, recorder, http.StatusOK)
	if updated := decodeResponse[User](t, recorder); updated.DisplayName != "Me Updated" || updated.ID != user.ID {
		t.Fatalf("updated me = %+v", updated)
	}

	recorder = env.doContext(ctx, http.MethodPatch, "/Me", PatchRequest{
		Operations: []PatchOperation{{Op: "replace", Path: "title", Value: "Owner"}},
	}, nil)
	requireStatus(t, recorder, http.StatusOK)
	if patched := decodeResponse[User](t, recorder); patched.Title != "Owner" {
		t.Fatalf("patched me = %+v", patched)
	}

	recorder = env.doContext(ctx, http.MethodDelete, "/Users/"+user.ID, nil, nil)
	requireStatus(t, recorder, http.StatusNoContent)
	recorder = env.doContext(ctx, http.MethodGet, "/Me", nil, nil)
	requireError(t, recorder, http.StatusNotFound, "")
}

func TestAuthorizer(t *testing.T) {
	var actions []string
	env := newTestEnv(t, Options{Authorizer: func(ctx context.Context, r *http.Request, action, resource string) error {
		actions = append(actions, action+":"+resource)
		if action == ActionDelete && resource == ResourceTypeNameUser {
			return ErrForbidden
		}
		if resource == ResourceBulk {
			return errors.New("bulk denied")
		}
		return nil
	}}, "/scim")
	user := env.mustCreateUser(map[string]any{"userName": "authorized"})
	recorder := env.do(http.MethodDelete, "/Users/"+user.ID, nil, nil)
	requireStatus(t, recorder, http.StatusForbidden)
	recorder = env.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{{Method: "DELETE", Path: "/Users/" + user.ID}},
	}, nil)
	requireStatus(t, recorder, http.StatusForbidden)

	found := false
	for _, action := range actions {
		if action == "create:User" {
			found = true
		}
	}
	if !found {
		t.Fatalf("authorizer actions = %v", actions)
	}

	denied := newTestEnv(t, Options{Authorizer: func(ctx context.Context, r *http.Request, action, resource string) error {
		return ErrUnauthorized
	}}, "/scim")
	recorder = denied.do(http.MethodGet, "/Users", nil, nil)
	requireError(t, recorder, http.StatusUnauthorized, "")
	if recorder.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q", recorder.Header().Get("WWW-Authenticate"))
	}

	generic := newTestEnv(t, Options{Authorizer: func(ctx context.Context, r *http.Request, action, resource string) error {
		return errors.New("no access")
	}}, "/scim")
	recorder = generic.do(http.MethodGet, "/Users", nil, nil)
	requireError(t, recorder, http.StatusForbidden, "")
}

func TestDiscoveryEndpoints(t *testing.T) {
	env := newTestEnv(t, Options{
		DocumentationURI:   "https://example.com/scim-docs",
		MaxResults:         50,
		BulkMaxOperations:  10,
		BulkMaxPayloadSize: 4096,
	}, "/scim")

	recorder := env.do(http.MethodGet, "/ServiceProviderConfig", nil, nil)
	requireStatus(t, recorder, http.StatusOK)
	config := decodeResponse[ServiceProviderConfig](t, recorder)
	if !config.Patch.Supported || !config.Bulk.Supported || !config.Filter.Supported || !config.Sort.Supported || !config.ETag.Supported {
		t.Fatalf("config features = %+v", config)
	}
	if config.Bulk.MaxOperations != 10 || config.Bulk.MaxPayloadSize != 4096 || config.Filter.MaxResults != 50 {
		t.Fatalf("config limits = %+v", config)
	}
	if config.ChangePassword.Supported {
		t.Fatalf("changePassword should be false without a hook")
	}
	if config.DocumentationURI != "https://example.com/scim-docs" {
		t.Fatalf("documentationUri = %q", config.DocumentationURI)
	}
	if len(config.AuthenticationSchemes) != 1 || config.AuthenticationSchemes[0].Type != "oauthbearertoken" {
		t.Fatalf("authenticationSchemes = %+v", config.AuthenticationSchemes)
	}

	type resourceTypeList struct {
		TotalResults int                      `json:"totalResults"`
		Resources    []ResourceTypeDefinition `json:"Resources"`
	}
	recorder = env.do(http.MethodGet, "/ResourceTypes", nil, nil)
	requireStatus(t, recorder, http.StatusOK)
	resourceTypes := decodeResponse[resourceTypeList](t, recorder)
	if resourceTypes.TotalResults != 2 || len(resourceTypes.Resources) != 2 {
		t.Fatalf("resource types = %+v", resourceTypes)
	}
	if resourceTypes.Resources[0].ID != ResourceTypeNameUser || len(resourceTypes.Resources[0].SchemaExtensions) != 1 {
		t.Fatalf("user resource type = %+v", resourceTypes.Resources[0])
	}
	recorder = env.do(http.MethodGet, "/ResourceTypes/User", nil, nil)
	requireStatus(t, recorder, http.StatusOK)
	userType := decodeResponse[ResourceTypeDefinition](t, recorder)
	if userType.Schema != UserSchema {
		t.Fatalf("user type schema = %q", userType.Schema)
	}
	recorder = env.do(http.MethodGet, "/ResourceTypes/missing", nil, nil)
	requireError(t, recorder, http.StatusNotFound, "")

	type schemaList struct {
		TotalResults int                `json:"totalResults"`
		Resources    []SchemaDefinition `json:"Resources"`
	}
	recorder = env.do(http.MethodGet, "/Schemas", nil, nil)
	requireStatus(t, recorder, http.StatusOK)
	schemas := decodeResponse[schemaList](t, recorder)
	if schemas.TotalResults != 3 || len(schemas.Resources) != 3 {
		t.Fatalf("schemas = %+v", schemas)
	}
	ids := make(map[string]bool)
	for _, definition := range schemas.Resources {
		ids[definition.ID] = true
		if len(definition.Attributes) == 0 {
			t.Fatalf("schema %q has no attributes", definition.ID)
		}
	}
	if !ids[UserSchema] || !ids[GroupSchema] || !ids[EnterpriseUserSchema] {
		t.Fatalf("schema ids = %v", ids)
	}
	recorder = env.do(http.MethodGet, "/Schemas/"+url.PathEscape(UserSchema), nil, nil)
	requireStatus(t, recorder, http.StatusOK)
	schema := decodeResponse[SchemaDefinition](t, recorder)
	if schema.ID != UserSchema {
		t.Fatalf("schema id = %q", schema.ID)
	}
	recorder = env.do(http.MethodGet, "/Schemas/"+url.PathEscape(EnterpriseUserSchema), nil, nil)
	requireStatus(t, recorder, http.StatusOK)
	if schema := decodeResponse[SchemaDefinition](t, recorder); schema.ID != EnterpriseUserSchema {
		t.Fatalf("enterprise schema id = %q", schema.ID)
	}
	recorder = env.do(http.MethodGet, "/Schemas/urn:example:unknown", nil, nil)
	requireError(t, recorder, http.StatusNotFound, "")
}

func TestBulkOperations(t *testing.T) {
	env := newTestEnv(t, Options{}, "/scim")
	recorder := env.do(http.MethodPost, "/Bulk", BulkRequest{
		Schemas: []string{BulkRequestSchema},
		Operations: []BulkOperation{
			{
				BulkID: "user-a",
				Method: "POST",
				Path:   "/Users",
				Data: map[string]any{
					"userName":    "bulk-user",
					"displayName": "Bulk User",
					"emails":      []any{map[string]any{"value": "bulk@example.com"}},
				},
			},
			{
				BulkID: "group-a",
				Method: "POST",
				Path:   "/Groups",
				Data: map[string]any{
					"displayName": "Bulk Group",
					"members":     []any{map[string]any{"value": "bulkId:user-a", "type": "User"}},
				},
			},
			{
				Method: "PATCH",
				Path:   "/Users/bulkId:user-a",
				Data: PatchRequest{
					Schemas: []string{PatchOpSchema},
					Operations: []PatchOperation{
						{Op: "replace", Path: "displayName", Value: "Bulk Updated"},
					},
				},
			},
			{
				Method: "DELETE",
				Path:   "/Users/bulkId:user-a",
			},
		},
	}, nil)
	requireStatus(t, recorder, http.StatusOK)
	response := decodeResponse[BulkResponse](t, recorder)
	if len(response.Operations) != 4 {
		t.Fatalf("operations = %+v", response.Operations)
	}
	wantStatuses := []string{"201", "201", "200", "204"}
	for i, want := range wantStatuses {
		if response.Operations[i].Status != want {
			t.Fatalf("operation %d status = %q, want %q, result = %+v", i, response.Operations[i].Status, want, response.Operations[i])
		}
	}
	if response.Operations[0].BulkID != "user-a" || response.Operations[0].Location == "" {
		t.Fatalf("created user result = %+v", response.Operations[0])
	}
	userBody, ok := response.Operations[0].Response.(map[string]any)
	if !ok {
		t.Fatalf("created user response = %#v", response.Operations[0].Response)
	}
	userID, _ := userBody["id"].(string)
	if userID == "" {
		t.Fatalf("created user body = %+v", userBody)
	}
	groupBody, ok := response.Operations[1].Response.(map[string]any)
	if !ok {
		t.Fatalf("created group response = %#v", response.Operations[1].Response)
	}
	groupID, _ := groupBody["id"].(string)
	group, err := env.store.GetGroup(context.Background(), groupID)
	if err != nil {
		t.Fatalf("GetGroup error = %v", err)
	}
	if len(group.Members) != 1 || group.Members[0].Value != userID {
		t.Fatalf("bulkId was not substituted: %+v", group.Members)
	}
	if _, err := env.store.GetUser(context.Background(), userID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted bulk user error = %v", err)
	}

	recorder = env.do(http.MethodPost, "/Bulk", BulkRequest{
		FailOnErrors: 1,
		Operations: []BulkOperation{
			{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "fail-user"}},
			{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "fail-user"}},
			{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "unreached-user"}},
		},
	}, nil)
	requireStatus(t, recorder, http.StatusOK)
	response = decodeResponse[BulkResponse](t, recorder)
	if len(response.Operations) != 2 || response.Operations[0].Status != "201" || response.Operations[1].Status != "409" {
		t.Fatalf("failOnErrors response = %+v", response.Operations)
	}

	recorder = env.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{
			{BulkID: "dup", Method: "POST", Path: "/Users", Data: map[string]any{"userName": "dup-one"}},
			{BulkID: "dup", Method: "POST", Path: "/Users", Data: map[string]any{"userName": "dup-two"}},
		},
	}, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidValue")

	recorder = env.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{
			{Method: "GET", Path: "/Users"},
		},
	}, nil)
	requireStatus(t, recorder, http.StatusOK)
	response = decodeResponse[BulkResponse](t, recorder)
	if response.Operations[0].Status != "400" {
		t.Fatalf("unsupported method result = %+v", response.Operations[0])
	}

	recorder = env.do(http.MethodPost, "/Bulk", BulkRequest{}, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidSyntax")
}

func TestBulkVersionAndLimits(t *testing.T) {
	env := newTestEnv(t, Options{BulkMaxOperations: 1}, "/scim")
	recorder := env.do(http.MethodPost, "/Users", map[string]any{"userName": "bulk-version"}, nil)
	requireStatus(t, recorder, http.StatusCreated)
	user := decodeResponse[User](t, recorder)

	recorder = env.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{
			{
				Method:  "PATCH",
				Path:    "/Users/" + user.ID,
				Version: `W/"stale"`,
				Data: PatchRequest{Operations: []PatchOperation{
					{Op: "replace", Path: "displayName", Value: "x"},
				}},
			},
		},
	}, nil)
	requireStatus(t, recorder, http.StatusOK)
	response := decodeResponse[BulkResponse](t, recorder)
	if response.Operations[0].Status != "412" {
		t.Fatalf("version result = %+v", response.Operations[0])
	}
	if failure, ok := response.Operations[0].Response.(map[string]any); !ok || failure["scimType"] != "invalidVers" {
		t.Fatalf("version failure body = %#v", response.Operations[0].Response)
	}

	recorder = env.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{
			{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "one"}},
			{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "two"}},
		},
	}, nil)
	requireError(t, recorder, http.StatusBadRequest, "tooMany")

	small := newTestEnv(t, Options{BulkMaxPayloadSize: 128}, "/scim")
	large := strings.Repeat("x", 200)
	recorder = small.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{{Method: "POST", Path: "/Users", Data: map[string]any{"userName": large}}},
	}, nil)
	requireError(t, recorder, http.StatusBadRequest, "tooMany")
}

func TestNativeHTTPHandler(t *testing.T) {
	env := newTestEnv(t, Options{}, "/scim")
	ts := httptest.NewServer(env.server.HTTPHandler("/scim"))
	defer ts.Close()

	response, err := http.Get(ts.URL + "/scim/Users")
	if err != nil {
		t.Fatalf("GET error = %v", err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != ContentType {
		response.Body.Close()
		t.Fatalf("GET status = %d, content type = %q", response.StatusCode, response.Header.Get("Content-Type"))
	}
	response.Body.Close()

	response, err = http.Get(ts.URL + "/other/Users")
	if err != nil {
		t.Fatalf("GET outside prefix error = %v", err)
	}
	if response.StatusCode != http.StatusNotFound {
		response.Body.Close()
		t.Fatalf("outside prefix status = %d", response.StatusCode)
	}
	response.Body.Close()

	createBody, _ := ydxjson.Marshal(map[string]any{"userName": "native-user"})
	response, err = http.Post(ts.URL+"/scim/Users", ContentType, bytes.NewReader(createBody))
	if err != nil {
		t.Fatalf("POST error = %v", err)
	}
	if response.StatusCode != http.StatusCreated {
		response.Body.Close()
		t.Fatalf("POST status = %d", response.StatusCode)
	}
	var created User
	if err := ydxjson.NewDecoder(response.Body).Decode(&created); err != nil {
		response.Body.Close()
		t.Fatalf("decode create error = %v", err)
	}
	response.Body.Close()

	request, _ := http.NewRequest(http.MethodPost, ts.URL+"/scim/Users/"+created.ID, nil)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("method request error = %v", err)
	}
	if response.StatusCode != http.StatusMethodNotAllowed {
		response.Body.Close()
		t.Fatalf("unsupported method status = %d", response.StatusCode)
	}
	if allow := response.Header.Get("Allow"); !strings.Contains(allow, http.MethodPatch) {
		response.Body.Close()
		t.Fatalf("Allow = %q", allow)
	}
	response.Body.Close()

	request, _ = http.NewRequest(http.MethodGet, ts.URL+"/scim/Schemas/"+url.PathEscape(UserSchema), nil)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("schema request error = %v", err)
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("schema status = %d", response.StatusCode)
	}
	response.Body.Close()
}

func TestBaseURLLocation(t *testing.T) {
	env := newTestEnv(t, Options{BaseURL: "https://idp.example/scim"}, "/scim")
	recorder := env.do(http.MethodPost, "/Users", map[string]any{"userName": "public-url"}, nil)
	requireStatus(t, recorder, http.StatusCreated)
	user := decodeResponse[User](t, recorder)
	if !strings.HasPrefix(user.Meta.Location, "https://idp.example/scim/Users/") {
		t.Fatalf("location = %q", user.Meta.Location)
	}
	if user.Meta.Location != "https://idp.example/scim/Users/"+user.ID {
		t.Fatalf("location = %q", user.Meta.Location)
	}
}
