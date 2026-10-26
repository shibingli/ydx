package transport

import (
	"context"
	"net/netip"

	"github.com/shibingli/ydx/captcha/core"
)

// Manager is the service surface used by HTTP and YD adapters. | Manager 是 HTTP 与 YD 适配器使用的服务接口。
type Manager interface {
	Create(ctx context.Context, req core.CreateRequest) (*core.Challenge, error)
	Verify(ctx context.Context, req core.VerifyRequest) (*core.VerifyResult, error)
	SendCode(ctx context.Context, req core.SendRequest) (*core.Challenge, error)
	VerifyToken(ctx context.Context, token, action string) (*core.TokenClaims, error)
	ConsumeToken(ctx context.Context, token, action string) (*core.TokenClaims, error)
	Image(ctx context.Context, key string) ([]byte, string, bool, error)
	AllowedOrigins() []string
	TrustedProxies() []netip.Prefix
	NormalizeLocale(locale string) string
	ErrorMessage(locale string, err error) string
}
