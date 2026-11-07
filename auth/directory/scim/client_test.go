package scim

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// startClientServer starts a SCIM server and returns a client rooted at it. | startClientServer 启动
// SCIM 服务端并返回以其为根地址的客户端。
func startClientServer(t *testing.T, env *testEnv, options ...ClientOption) (*Client, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(env.server.HTTPHandler(env.prefix))
	t.Cleanup(ts.Close)
	client, err := NewClient(ts.URL+env.prefix, options...)
	if err != nil {
		t.Fatalf("NewClient error = %v", err)
	}
	return client, ts
}

func TestClientUserLifecycle(t *testing.T) {
	env := newTestEnv(t, Options{}, "/scim")
	client, _ := startClientServer(t, env)
	ctx := context.Background()

	created, err := client.CreateUser(ctx, &User{
		UserName:    "client-user",
		DisplayName: "Client User",
		Emails:      []MultiValue{{Value: "client@example.com", Type: "work", Primary: true}},
	})
	if err != nil {
		t.Fatalf("CreateUser error = %v", err)
	}
	if created.ID == "" || created.UserName != "client-user" || created.Meta == nil || created.Meta.Version == "" {
		t.Fatalf("created = %+v", created)
	}

	page, err := client.ListUsers(ctx, ListOptions{Filter: `userName eq "client-user"`, Count: 10})
	if err != nil {
		t.Fatalf("ListUsers error = %v", err)
	}
	if page.TotalResults != 1 || len(page.Resources) != 1 || page.Resources[0].ID != created.ID {
		t.Fatalf("page = %+v", page)
	}

	got, err := client.GetUser(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetUser error = %v", err)
	}
	if got.Meta == nil || got.Meta.Version != created.Meta.Version {
		t.Fatalf("got version = %+v", got.Meta)
	}

	if _, err := client.GetUser(ctx, created.ID, WithIfNoneMatch(got.Meta.Version)); !errors.Is(err, ErrNotModified) {
		t.Fatalf("GetUser If-None-Match error = %v, want ErrNotModified", err)
	}

	_, err = client.ReplaceUser(ctx, &User{ID: created.ID, UserName: "client-user", DisplayName: "Stale"}, WithIfMatch(`W/"stale"`))
	if !errors.Is(err, ErrInvalidVersion) {
		t.Fatalf("ReplaceUser stale error = %v, want ErrInvalidVersion", err)
	}
	var failure *ErrorResponse
	if !errors.As(err, &failure) {
		t.Fatalf("ReplaceUser error type = %T", err)
	}
	if failure.StatusCode != http.StatusPreconditionFailed || failure.ScimType != "invalidVers" {
		t.Fatalf("failure = %+v", failure)
	}

	updated, err := client.ReplaceUser(ctx, &User{ID: created.ID, UserName: "client-user", DisplayName: "Updated"},
		WithIfMatch(got.Meta.Version))
	if err != nil {
		t.Fatalf("ReplaceUser error = %v", err)
	}
	if updated.DisplayName != "Updated" || updated.ID != created.ID {
		t.Fatalf("updated = %+v", updated)
	}

	patched, err := client.PatchUser(ctx, created.ID, []PatchOperation{
		{Op: "replace", Path: "title", Value: "Owner"},
	})
	if err != nil {
		t.Fatalf("PatchUser error = %v", err)
	}
	if patched.Title != "Owner" {
		t.Fatalf("patched = %+v", patched)
	}

	search, err := client.SearchUsers(ctx, SearchRequest{Filter: `title eq "Owner"`, SortBy: "userName", Count: 5})
	if err != nil {
		t.Fatalf("SearchUsers error = %v", err)
	}
	if search.TotalResults != 1 || search.Resources[0].ID != created.ID {
		t.Fatalf("search = %+v", search)
	}

	selected, err := client.ListUsers(ctx, ListOptions{Attributes: []string{"userName"}, Count: 1})
	if err != nil {
		t.Fatalf("ListUsers attributes error = %v", err)
	}
	if len(selected.Resources) != 1 || selected.Resources[0].UserName == "" || selected.Resources[0].DisplayName != "" {
		t.Fatalf("selected = %+v", selected.Resources)
	}

	if err := client.DeleteUser(ctx, created.ID, WithIfMatch(patched.Meta.Version)); err != nil {
		t.Fatalf("DeleteUser error = %v", err)
	}
	_, err = client.GetUser(ctx, created.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetUser deleted error = %v, want ErrNotFound", err)
	}
	if !errors.As(err, &failure) || failure.StatusCode != http.StatusNotFound {
		t.Fatalf("deleted failure = %+v", failure)
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("error text = %q", err.Error())
	}
}

func TestClientGroupLifecycle(t *testing.T) {
	env := newTestEnv(t, Options{}, "/scim")
	client, _ := startClientServer(t, env)
	ctx := context.Background()

	member, err := client.CreateUser(ctx, &User{UserName: "group-member", DisplayName: "Member"})
	if err != nil {
		t.Fatalf("CreateUser error = %v", err)
	}
	created, err := client.CreateGroup(ctx, &Group{
		DisplayName: "Client Group",
		Members:     []GroupMember{{Value: member.ID, Display: member.DisplayName, Type: "User"}},
	})
	if err != nil {
		t.Fatalf("CreateGroup error = %v", err)
	}
	if created.ID == "" || len(created.Members) != 1 || created.Meta == nil {
		t.Fatalf("created group = %+v", created)
	}

	page, err := client.ListGroups(ctx, ListOptions{Filter: `displayName eq "client group"`, Count: 10})
	if err != nil {
		t.Fatalf("ListGroups error = %v", err)
	}
	if page.TotalResults != 1 || page.Resources[0].ID != created.ID {
		t.Fatalf("group page = %+v", page)
	}

	got, err := client.GetGroup(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetGroup error = %v", err)
	}
	if _, err := client.GetGroup(ctx, created.ID, WithIfNoneMatch(got.Meta.Version)); !errors.Is(err, ErrNotModified) {
		t.Fatalf("GetGroup If-None-Match error = %v, want ErrNotModified", err)
	}

	patched, err := client.PatchGroup(ctx, created.ID, []PatchOperation{
		{Op: "replace", Path: "displayName", Value: "Client Group Renamed"},
	}, WithIfMatch(got.Meta.Version))
	if err != nil {
		t.Fatalf("PatchGroup error = %v", err)
	}
	if patched.DisplayName != "Client Group Renamed" || len(patched.Members) != 1 {
		t.Fatalf("patched group = %+v", patched)
	}

	replaced, err := client.ReplaceGroup(ctx, &Group{
		ID:          created.ID,
		DisplayName: "Client Group Replaced",
		Members:     []GroupMember{{Value: member.ID, Display: "Member", Type: "User"}},
	}, WithIfMatch(patched.Meta.Version))
	if err != nil {
		t.Fatalf("ReplaceGroup error = %v", err)
	}
	if replaced.DisplayName != "Client Group Replaced" || len(replaced.Members) != 1 {
		t.Fatalf("replaced group = %+v", replaced)
	}

	search, err := client.SearchGroups(ctx, SearchRequest{Filter: `displayName sw "Client Group"`})
	if err != nil {
		t.Fatalf("SearchGroups error = %v", err)
	}
	if search.TotalResults != 1 || len(search.Resources) != 1 {
		t.Fatalf("group search = %+v", search)
	}

	if err := client.DeleteGroup(ctx, created.ID, WithIfMatch(replaced.Meta.Version)); err != nil {
		t.Fatalf("DeleteGroup error = %v", err)
	}
	if _, err := client.GetGroup(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetGroup deleted error = %v, want ErrNotFound", err)
	}
}

func TestClientIterator(t *testing.T) {
	env := newTestEnv(t, Options{}, "/scim")
	client, _ := startClientServer(t, env)
	ctx := context.Background()
	for _, name := range []string{"iter-a", "iter-b", "iter-c", "iter-d", "iter-e"} {
		if _, err := client.CreateUser(ctx, &User{UserName: name}); err != nil {
			t.Fatalf("CreateUser %s error = %v", name, err)
		}
	}

	iterator := client.IterateUsers(ctx, ListOptions{Filter: `userName sw "iter-"`, Count: 2, SortBy: "userName"})
	var names []string
	for {
		user, ok, err := iterator.Next()
		if err != nil {
			t.Fatalf("Next error = %v", err)
		}
		if !ok {
			break
		}
		names = append(names, user.UserName)
	}
	if len(names) != 5 {
		t.Fatalf("iterated names = %v", names)
	}
	if names[0] != "iter-a" || names[4] != "iter-e" {
		t.Fatalf("iteration order = %v", names)
	}
	if iterator.TotalResults() != 5 {
		t.Fatalf("TotalResults = %d", iterator.TotalResults())
	}
	if user, ok, err := iterator.Next(); err != nil || ok || user != nil {
		t.Fatalf("Next after exhaustion = %v, %v, %v", user, ok, err)
	}

	groupIterator := client.IterateGroups(ctx, ListOptions{Count: 1})
	if _, ok, err := groupIterator.Next(); err != nil || ok {
		t.Fatalf("empty group iteration = %v, %v", ok, err)
	}
	if groupIterator.TotalResults() != 0 {
		t.Fatalf("empty group total = %d", groupIterator.TotalResults())
	}
}

func TestClientAuthenticationHeaders(t *testing.T) {
	var authorization, userAgent string
	env := newTestEnv(t, Options{Authorizer: func(ctx context.Context, r *http.Request, action, resource string) error {
		authorization = r.Header.Get("Authorization")
		userAgent = r.Header.Get("User-Agent")
		return nil
	}}, "/scim")
	client, ts := startClientServer(t, env, WithBearerToken("test-token"), WithUserAgent("scim-test-agent"))
	ctx := context.Background()
	if _, err := client.ListUsers(ctx, ListOptions{}); err != nil {
		t.Fatalf("ListUsers error = %v", err)
	}
	if authorization != "Bearer test-token" {
		t.Fatalf("Authorization = %q", authorization)
	}
	if userAgent != "scim-test-agent" {
		t.Fatalf("User-Agent = %q", userAgent)
	}

	basicClient, err := NewClient(ts.URL+"/scim", WithBasicAuth("user", "pass"))
	if err != nil {
		t.Fatalf("NewClient basic error = %v", err)
	}
	if _, err := basicClient.ListUsers(ctx, ListOptions{}); err != nil {
		t.Fatalf("ListUsers basic error = %v", err)
	}
	username, password, ok := parseBasicAuthorization(authorization)
	if !ok || username != "user" || password != "pass" {
		t.Fatalf("basic Authorization = %q, %v, %v", authorization, username, password)
	}
}

// parseBasicAuthorization decodes a basic Authorization header for tests. | parseBasicAuthorization
// 为测试解码基本认证 Authorization 响应头。
func parseBasicAuthorization(header string) (string, string, bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return "", "", false
	}
	request, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err != nil {
		return "", "", false
	}
	request.Header.Set("Authorization", header)
	return request.BasicAuth()
}

func TestClientTypedErrors(t *testing.T) {
	env := newTestEnv(t, Options{MaxResults: 2}, "/scim")
	client, _ := startClientServer(t, env)
	ctx := context.Background()

	_, err := client.ListUsers(ctx, ListOptions{Count: 3})
	if !errors.Is(err, ErrTooMany) {
		t.Fatalf("ListUsers too many error = %v", err)
	}
	var failure *ErrorResponse
	if !errors.As(err, &failure) || failure.ScimType != "tooMany" {
		t.Fatalf("too many failure = %+v", failure)
	}

	_, err = client.ListUsers(ctx, ListOptions{Filter: "userName xx"})
	if !errors.Is(err, ErrInvalidFilter) {
		t.Fatalf("ListUsers invalid filter error = %v", err)
	}

	_, err = client.ListUsers(ctx, ListOptions{Attributes: []string{"userName"}, ExcludedAttributes: []string{"title"}})
	if !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("ListUsers mutually exclusive error = %v", err)
	}

	_, err = client.SearchUsers(ctx, SearchRequest{Filter: "not valid"})
	if !errors.Is(err, ErrInvalidFilter) {
		t.Fatalf("SearchUsers invalid filter error = %v", err)
	}

	_, err = client.CreateUser(ctx, &User{UserName: "typed-error"})
	if err != nil {
		t.Fatalf("CreateUser error = %v", err)
	}
	_, err = client.CreateUser(ctx, &User{UserName: "Typed-Error"})
	if !errors.Is(err, ErrUniqueness) {
		t.Fatalf("CreateUser duplicate error = %v", err)
	}
	if errors.As(err, &failure) && failure.ScimType != "uniqueness" {
		t.Fatalf("uniqueness failure = %+v", failure)
	}

	_, err = client.GetUser(ctx, "missing-id")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetUser missing error = %v", err)
	}

	if _, err := client.ListGroups(ctx, ListOptions{}); err != nil {
		t.Fatalf("ListGroups error = %v", err)
	}
}

func TestClientArgumentValidation(t *testing.T) {
	for _, baseURL := range []string{"", "   ", "relative/path", "://missing-scheme"} {
		if _, err := NewClient(baseURL); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("NewClient(%q) error = %v, want ErrInvalidConfig", baseURL, err)
		}
	}
	client, err := NewClient("https://example.com/scim/")
	if err != nil {
		t.Fatalf("NewClient error = %v", err)
	}
	if client.BaseURL() != "https://example.com/scim" {
		t.Fatalf("BaseURL = %q", client.BaseURL())
	}
	ctx := context.Background()
	if _, err := client.CreateUser(ctx, nil); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("CreateUser nil error = %v", err)
	}
	if _, err := client.ReplaceUser(ctx, &User{}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("ReplaceUser missing id error = %v", err)
	}
	if _, err := client.GetUser(ctx, ""); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("GetUser empty id error = %v", err)
	}
	if _, err := client.PatchUser(ctx, "id", nil); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("PatchUser empty operations error = %v", err)
	}
	if _, err := client.CreateGroup(ctx, nil); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("CreateGroup nil error = %v", err)
	}
	if _, err := client.ReplaceGroup(ctx, &Group{}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("ReplaceGroup missing id error = %v", err)
	}
	if _, err := client.GetGroup(ctx, " "); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("GetGroup empty id error = %v", err)
	}
	if _, err := client.PatchGroup(ctx, "id", nil); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("PatchGroup empty operations error = %v", err)
	}
	uninitialized := &Client{}
	if _, err := uninitialized.ListUsers(ctx, ListOptions{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("uninitialized ListUsers error = %v", err)
	}
	var nilClient *Client
	if nilClient.BaseURL() != "" {
		t.Fatalf("nil BaseURL = %q", nilClient.BaseURL())
	}
	if _, err := nilClient.ListUsers(ctx, ListOptions{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil ListUsers error = %v", err)
	}
}
