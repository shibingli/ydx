package federation

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestDoRequestPreservesContextCause verifies that a cancelled provider request keeps the
// context cause on the error chain while still hiding the endpoint. |
// TestDoRequestPreservesContextCause 校验被取消的提供方请求在错误链上保留上下文原因，同时
// 仍然不暴露端点。
func TestDoRequestPreservesContextCause(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-release
	}))
	t.Cleanup(func() {
		close(release)
		server.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, _, err := getProvider(ctx, server.Client(), server.URL+"/userinfo", nil)
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("error = %v, want ErrTransport | 错误 = %v，期望 ErrTransport", err, err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded | 错误 = %v，期望 context.DeadlineExceeded", err, err)
	}
	if strings.Contains(err.Error(), "/userinfo") {
		t.Fatalf("error leaks the provider endpoint: %v | 错误泄露提供方端点：%v", err, err)
	}
}
