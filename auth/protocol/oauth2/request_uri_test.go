package oauth2

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// requireFetchError asserts an RFC 9101 fetch error code. | requireFetchError 断言 RFC 9101 抓取错误码。
func requireFetchError(t *testing.T, err error, code string) {
	t.Helper()
	var oauthErr *Error
	if !errors.As(err, &oauthErr) || oauthErr.Code != code {
		t.Fatalf("error = %v want code %q", err, code)
	}
}

// objectHandler serves a fixed request object and counts fetches. | objectHandler 提供固定请求对象并
// 统计抓取次数。
func objectHandler(body *string, fetches *int32, contentType string, status int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(fetches, 1)
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		if body != nil {
			_, _ = w.Write([]byte(*body))
		}
	}
}

func TestRequestURIExternalFetch(t *testing.T) {
	var fetches int32
	var body string
	server := httptest.NewServer(objectHandler(&body, &fetches, "application/oauth-authz-req+jwt", http.StatusOK))
	defer server.Close()
	objectURI := server.URL + "/object"

	key, _ := newTestJWTKey(t)
	verifier, _ := pkcePair(t)
	claims := requestObjectClaims("web", codeAuthorizationValues(flowClient(), verifier), flowNow)
	body = signRequestObject(t, key, claims)

	authServer, client, _ := requestObjectServer(t, func(config *ServerConfig, client *Client) {
		client.JWKS = publicJWKS(t, key)
		client.RequestURIs = []string{objectURI}
		config.RequestURIs = RequestURIConfig{
			Enabled:             true,
			RequireRegistration: true,
			AllowLoopback:       true,
			Timeout:             2 * time.Second,
			CacheTTL:            time.Minute,
		}
	})
	resp := authorize(t, authServer, url.Values{
		"client_id":   {client.ID},
		"request_uri": {objectURI},
	})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d", resp.StatusCode)
	}
	values := locationValues(t, resp)
	if values.Get("code") == "" || values.Get("state") != "state-1" {
		t.Fatalf("response = %v", values)
	}
	if got := atomic.LoadInt32(&fetches); got != 1 {
		t.Fatalf("fetches = %d want 1", got)
	}
}

func TestRequestURIDisabled(t *testing.T) {
	authServer, client, _ := requestObjectServer(t, func(config *ServerConfig, client *Client) {
		client.RequestURIs = []string{"https://client.example/object"}
		config.RequestURIs = RequestURIConfig{Enabled: false, RequireRegistration: true}
	})
	w := doRequest(t, authServer.Authorize, http.MethodGet, "/authorize?"+url.Values{
		"client_id":   {client.ID},
		"request_uri": {"https://client.example/object"},
	}.Encode(), nil, nil)
	requireErrorCode(t, w, http.StatusBadRequest, ErrorRequestURINotSupported)
}

func TestRequestURIFetchErrors(t *testing.T) {
	key, _ := newTestJWTKey(t)
	verifier, _ := pkcePair(t)
	object := signRequestObject(t, key, requestObjectClaims("web", codeAuthorizationValues(flowClient(), verifier), flowNow))
	cases := []struct {
		name        string
		body        string
		contentType string
		status      int
		maxSize     int64
		want        string
	}{
		{
			name:        "bad content type",
			body:        object,
			contentType: "text/html",
			status:      http.StatusOK,
			want:        ErrorInvalidRequestURI,
		},
		{
			name:        "non 200",
			body:        object,
			contentType: "application/jwt",
			status:      http.StatusInternalServerError,
			want:        ErrorInvalidRequestURI,
		},
		{
			name:        "oversized",
			body:        object,
			contentType: "application/jwt",
			status:      http.StatusOK,
			maxSize:     8,
			want:        ErrorInvalidRequestURI,
		},
		{
			name:        "empty",
			body:        "",
			contentType: "application/jwt",
			status:      http.StatusOK,
			want:        ErrorInvalidRequestURI,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.body
			var fetches int32
			server := httptest.NewServer(objectHandler(&body, &fetches, tc.contentType, tc.status))
			defer server.Close()
			client := flowClient()
			client.RequestURIs = []string{server.URL + "/object"}
			cache := newRequestURICache(RequestURIConfig{
				Enabled:             true,
				RequireRegistration: true,
				AllowLoopback:       true,
				MaxSize:             tc.maxSize,
			}, func() time.Time { return flowNow })
			_, err := cache.Fetch(context.Background(), client, server.URL+"/object")
			requireFetchError(t, err, tc.want)
		})
	}
}

func TestRequestURIRedirectRefused(t *testing.T) {
	var fetches int32
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fetches, 1)
		if r.URL.Path == "/object" {
			http.Redirect(w, r, "/other", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	cache := newRequestURICache(RequestURIConfig{
		Enabled:             true,
		RequireRegistration: true,
		AllowLoopback:       true,
	}, func() time.Time { return flowNow })
	client := flowClient()
	client.RequestURIs = []string{server.URL + "/object"}
	_, err := cache.Fetch(context.Background(), client, server.URL+"/object")
	requireFetchError(t, err, ErrorInvalidRequestURI)
	if got := atomic.LoadInt32(&fetches); got != 1 {
		t.Fatalf("redirect was followed, fetches = %d", got)
	}
}

func TestRequestURIFetchFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	objectURI := server.URL + "/object"
	server.Close()
	cache := newRequestURICache(RequestURIConfig{
		Enabled:             true,
		RequireRegistration: true,
		AllowLoopback:       true,
	}, func() time.Time { return flowNow })
	client := flowClient()
	client.RequestURIs = []string{objectURI}
	_, err := cache.Fetch(context.Background(), client, objectURI)
	requireFetchError(t, err, ErrorInvalidRequestURI)
}

func TestRequestURIValidationRules(t *testing.T) {
	registered := flowClient()
	registered.RequestURIs = []string{
		"https://client.example/object",
		"https://client.example:8443/object",
	}
	caches := map[string]*requestURICache{
		"registration": newRequestURICache(RequestURIConfig{
			Enabled:             true,
			RequireRegistration: true,
		}, func() time.Time { return flowNow }),
		"hosts": newRequestURICache(RequestURIConfig{
			Enabled:      true,
			AllowedHosts: []string{"client.example", "https://api.example:9443"},
		}, func() time.Time { return flowNow }),
		"loopback": newRequestURICache(RequestURIConfig{
			Enabled:       true,
			AllowLoopback: true,
			AllowedHosts:  []string{"127.0.0.1:8080"},
		}, func() time.Time { return flowNow }),
	}
	cases := []struct {
		name    string
		cache   *requestURICache
		client  *Client
		uri     string
		wantErr bool
	}{
		{name: "registered", cache: caches["registration"], client: registered, uri: "https://client.example/object"},
		{name: "registered with port", cache: caches["registration"], client: registered, uri: "https://client.example:8443/object"},
		{name: "unregistered", cache: caches["registration"], client: registered, uri: "https://client.example/other", wantErr: true},
		{name: "unregistered query differs", cache: caches["registration"], client: registered, uri: "https://client.example/object?x=1", wantErr: true},
		{name: "empty", cache: caches["registration"], client: registered, uri: "", wantErr: true},
		{name: "too long", cache: caches["registration"], client: registered, uri: "https://client.example/" + strings.Repeat("a", 2100), wantErr: true},
		{name: "relative", cache: caches["registration"], client: registered, uri: "/object", wantErr: true},
		{name: "userinfo", cache: caches["registration"], client: registered, uri: "https://user@client.example/object", wantErr: true},
		{name: "fragment", cache: caches["registration"], client: registered, uri: "https://client.example/object#frag", wantErr: true},
		{name: "ftp", cache: caches["registration"], client: registered, uri: "ftp://client.example/object", wantErr: true},
		{name: "plain http public", cache: caches["registration"], client: registered, uri: "http://client.example/object", wantErr: true},
		{name: "nil client", cache: caches["registration"], client: nil, uri: "https://client.example/object", wantErr: true},
		{name: "loopback denied", cache: caches["registration"], client: registered, uri: "https://127.0.0.1/object", wantErr: true},
		{name: "private ip", cache: caches["registration"], client: registered, uri: "https://10.1.2.3/object", wantErr: true},
		{name: "loopback allowed", cache: caches["loopback"], client: registered, uri: "http://127.0.0.1:8080/object"},
		{name: "host allowed", cache: caches["hosts"], client: registered, uri: "https://client.example/anything"},
		{name: "host with port allowed", cache: caches["hosts"], client: registered, uri: "https://api.example:9443/anything"},
		{name: "host denied", cache: caches["hosts"], client: registered, uri: "https://evil.example/object", wantErr: true},
		{name: "wrong port denied", cache: caches["hosts"], client: registered, uri: "https://api.example:9444/anything", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.cache.validateURI(tc.client, tc.uri)
			if tc.wantErr {
				requireFetchError(t, err, ErrorInvalidRequestURI)
				return
			}
			if err != nil {
				t.Fatalf("validateURI: %v", err)
			}
		})
	}
}

func TestRequestURICacheAndSingleUse(t *testing.T) {
	var body string
	var fetches int32
	server := httptest.NewServer(objectHandler(&body, &fetches, "application/jwt", http.StatusOK))
	defer server.Close()
	objectURI := server.URL + "/object"
	client := flowClient()
	client.RequestURIs = []string{objectURI}

	now := flowNow
	clock := func() time.Time { return now }
	cache := newRequestURICache(RequestURIConfig{
		Enabled:             true,
		RequireRegistration: true,
		AllowLoopback:       true,
		CacheTTL:            time.Minute,
	}, clock)
	body = "signed-object"
	for i := 0; i < 2; i++ {
		got, err := cache.Fetch(context.Background(), client, objectURI)
		if err != nil || got != body {
			t.Fatalf("fetch %d = %q err=%v", i, got, err)
		}
	}
	if got := atomic.LoadInt32(&fetches); got != 1 {
		t.Fatalf("cached fetches = %d want 1", got)
	}
	now = now.Add(2 * time.Minute)
	if _, err := cache.Fetch(context.Background(), client, objectURI); err != nil {
		t.Fatalf("refetch: %v", err)
	}
	if got := atomic.LoadInt32(&fetches); got != 2 {
		t.Fatalf("refetches = %d want 2", got)
	}

	now = flowNow
	single := newRequestURICache(RequestURIConfig{
		Enabled:             true,
		RequireRegistration: true,
		AllowLoopback:       true,
		CacheTTL:            time.Minute,
		SingleUse:           true,
	}, clock)
	if _, err := single.Fetch(context.Background(), client, objectURI); err != nil {
		t.Fatalf("first single-use fetch: %v", err)
	}
	_, err := single.Fetch(context.Background(), client, objectURI)
	requireFetchError(t, err, ErrorInvalidRequestURI)
	// The single-use record expires together with the cache TTL. | 一次性记录随缓存 TTL 一起过期。
	now = now.Add(2 * time.Minute)
	if _, err := single.Fetch(context.Background(), client, objectURI); err != nil {
		t.Fatalf("fetch after single-use expiry: %v", err)
	}

	noCache := newRequestURICache(RequestURIConfig{
		Enabled:             true,
		RequireRegistration: true,
		AllowLoopback:       true,
		CacheTTL:            -1,
	}, clock)
	before := atomic.LoadInt32(&fetches)
	if _, err := noCache.Fetch(context.Background(), client, objectURI); err != nil {
		t.Fatal(err)
	}
	if _, err := noCache.Fetch(context.Background(), client, objectURI); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&fetches); got != before+2 {
		t.Fatalf("no-cache fetches = %d want %d", got, before+2)
	}
}

func TestRequestURICacheCapacity(t *testing.T) {
	cache := newRequestURICache(RequestURIConfig{
		Enabled:      true,
		AllowedHosts: []string{"client.example"},
		CacheTTL:     time.Minute,
	}, func() time.Time { return flowNow })
	for i := 0; i < requestObjectCacheCapacity+8; i++ {
		cache.store("https://client.example/object?i="+strconv.Itoa(i), "body")
	}
	if len(cache.entries) != requestObjectCacheCapacity {
		t.Fatalf("cache size = %d want %d", len(cache.entries), requestObjectCacheCapacity)
	}
}

func TestRequestURISingleUseCapacity(t *testing.T) {
	cache := newRequestURICache(RequestURIConfig{
		Enabled:   true,
		CacheTTL:  time.Minute,
		SingleUse: true,
	}, func() time.Time { return flowNow })
	for i := 0; i < requestURISingleUseCapacity+8; i++ {
		if !cache.beginUse("https://client.example/object?i=" + strconv.Itoa(i)) {
			t.Fatalf("beginUse(%d) reported a duplicate", i)
		}
	}
	if len(cache.used) != requestURISingleUseCapacity {
		t.Fatalf("single-use size = %d want %d", len(cache.used), requestURISingleUseCapacity)
	}
}

func TestRequestURIHelpers(t *testing.T) {
	if !requestObjectContentType("application/oauth-authz-req+jwt; charset=utf-8") {
		t.Fatal("request object media type rejected")
	}
	if !requestObjectContentType("") || !requestObjectContentType("application/octet-stream") {
		t.Fatal("generic media type rejected")
	}
	if requestObjectContentType("application/json") {
		t.Fatal("JSON media type accepted")
	}
	if clientAllowsRequestURI(nil, "https://client.example/object") {
		t.Fatal("nil client allows a request URI")
	}
	parsed, err := url.Parse("https://client.example:8443/object")
	if err != nil {
		t.Fatal(err)
	}
	if requestURIHostAllowed(nil, []string{"client.example"}) {
		t.Fatal("nil URL allowed")
	}
	if !requestURIHostAllowed(parsed, []string{"", "client.example:8443"}) {
		t.Fatal("host:port entry rejected")
	}
	if !requestURIHostAllowed(parsed, []string{"https://client.example"}) {
		t.Fatal("scheme entry rejected")
	}
	if requestURIHostAllowed(parsed, []string{"other.example"}) {
		t.Fatal("wrong host allowed")
	}
}
