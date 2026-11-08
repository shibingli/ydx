package oidc

import (
	"context"
	"time"

	"github.com/shibingli/ydx/errs"
)

// StartCleanup starts the periodic cleanup scheduler of the embedded OAuth server. | StartCleanup
// 启动内嵌 OAuth 服务器的周期清理调度器。
//
// The scheduler removes expired authorization codes, access and refresh tokens, device codes,
// pushed authorization requests, request_uri entries and DPoP nonces. The first pass runs
// immediately and an interval of zero or less selects five minutes. Calling StartCleanup while a
// scheduler is already running is a no-op. StopCleanup must be called during shutdown because the
// goroutine never exits on its own. | 调度器删除过期授权码、访问与刷新令牌、设备码、推送授权请求、
// request_uri 条目与 DPoP nonce。首次清理立即执行，间隔为零或负数时选择 5 分钟。调度器已运行时再次
// 调用 StartCleanup 是无操作。关闭时必须调用 StopCleanup，因为协程不会自行退出。
func (p *Provider) StartCleanup(interval time.Duration) error {
	if p == nil || p.oauth == nil {
		return errs.Detail(ErrInvalidConfig, "provider has no OAuth server | 提供方没有 OAuth 服务器")
	}
	return p.oauth.StartCleanup(interval)
}

// StopCleanup stops the embedded OAuth server's cleanup scheduler and waits for it to exit. |
// StopCleanup 停止内嵌 OAuth 服务器的清理调度器并等待其退出。
func (p *Provider) StopCleanup() {
	if p == nil || p.oauth == nil {
		return
	}
	p.oauth.StopCleanup()
}

// Cleanup performs one cleanup pass over the embedded OAuth server's temporary state. | Cleanup
// 对内嵌 OAuth 服务器的临时状态执行一次清理。
func (p *Provider) Cleanup(ctx context.Context) error {
	if p == nil || p.oauth == nil {
		return errs.Detail(ErrInvalidConfig, "provider has no OAuth server | 提供方没有 OAuth 服务器")
	}
	return p.oauth.Cleanup(ctx)
}
