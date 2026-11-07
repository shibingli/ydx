package jwt

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// httpFixture builds a valid HS256 token and the matching native middleware. |
// httpFixture 构造一个有效的 HS256 令牌与对应的原生中间件。
func httpFixture(t *testing.T, lookup string) (string, func(http.Handler) http.Handler) {
	t.Helper()
	key := any([]byte("0123456789abcdef0123456789abcdef"))
	token, err := Sign(map[string]any{"sub": "alice"}, key, HS256, SignOptions{})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	mw := HTTPMiddleware(HTTPMiddlewareOptions{
		KeyFunc:     func(Header) (any, error) { return key, nil },
		TokenLookup: lookup,
		ParseOptions: ParseOptions{
			ValidAlgs: []Alg{HS256},
		},
	})
	return token, mw
}

// TestHTTPMiddlewareHeaderAndFromRequest proves the bearer header lookup and the
// request-context token accessor. | TestHTTPMiddlewareHeaderAndFromRequest 证明
// Bearer 头提取与请求上下文令牌访问器。
func TestHTTPMiddlewareHeaderAndFromRequest(t *testing.T) {
	token, mw := httpFixture(t, "header:Authorization:Bearer ")
	called := false
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		tok, ok := FromRequest(r)
		if !ok || tok == nil {
			t.Error("FromRequest did not find the verified token")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusNoContent {
		t.Fatalf("called=%v status=%d, want true/204", called, rec.Code)
	}
}

// TestHTTPMiddlewareQueryAndCookie proves the query and cookie lookup forms. |
// TestHTTPMiddlewareQueryAndCookie 证明 query 与 cookie 两种提取形式。
func TestHTTPMiddlewareQueryAndCookie(t *testing.T) {
	t.Run("query", func(t *testing.T) {
		token, mw := httpFixture(t, "query:token")
		req := httptest.NewRequest(http.MethodGet, "/?token="+token, nil)
		rec := httptest.NewRecorder()
		mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", rec.Code)
		}
	})
	t.Run("cookie", func(t *testing.T) {
		token, mw := httpFixture(t, "cookie:jwt")
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "jwt", Value: token})
		rec := httptest.NewRecorder()
		mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", rec.Code)
		}
	})
}

// TestHTTPMiddlewareRejectsMissingAndInvalid proves failures are 401 and never
// reach the handler or leak the parsing reason. | TestHTTPMiddlewareRejectsMissingAndInvalid
// 证明失败返回 401、不会到达处理器，也不会泄露解析原因。
func TestHTTPMiddlewareRejectsMissingAndInvalid(t *testing.T) {
	cases := []struct {
		name  string
		token string
	}{
		{"missing", ""},
		{"invalid", "not-a-jwt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, mw := httpFixture(t, "header:Authorization:Bearer ")
			called := false
			h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if called {
				t.Fatal("handler must not run on an authentication failure")
			}
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			if body := strings.ToLower(rec.Body.String()); strings.Contains(body, "signature") || strings.Contains(body, "parse") {
				t.Fatalf("body leaks the failure reason: %q", rec.Body.String())
			}
		})
	}
}

// TestHTTPMiddlewareCustomErrorHandler proves the hook receives the original
// sentinel. | TestHTTPMiddlewareCustomErrorHandler 证明钩子收到原始哨兵错误。
func TestHTTPMiddlewareCustomErrorHandler(t *testing.T) {
	var got error
	mw := HTTPMiddleware(HTTPMiddlewareOptions{
		KeyFunc: func(Header) (any, error) { return []byte("0123456789abcdef0123456789abcdef"), nil },
		ErrorHandler: func(w http.ResponseWriter, err error) {
			got = err
			w.WriteHeader(http.StatusTeapot)
		},
	})
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !errors.Is(got, ErrTokenNotFound) {
		t.Fatalf("error = %v, want ErrTokenNotFound", got)
	}
	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want 418", rec.Code)
	}
}
