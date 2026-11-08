package oauth2

import (
	"context"
	"errors"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
)

// defaultCleanupInterval is the periodic cleanup interval used when none is supplied. |
// defaultCleanupInterval 是未提供周期时使用的清理间隔。
const defaultCleanupInterval = 5 * time.Minute

// StartCleanup starts a background goroutine that periodically removes expired authorization codes,
// refresh and access tokens, device codes, pushed authorization requests, request_uri entries and
// DPoP nonces. | StartCleanup 启动后台协程，周期删除过期授权码、刷新与访问令牌、设备码、推送授权
// 请求、request_uri 条目与 DPoP nonce。
//
// The first pass runs immediately. An interval of zero or less selects five minutes. Calling
// StartCleanup while a scheduler is already running is a no-op and returns nil, so the first
// configured interval remains in effect. StopCleanup must be called during shutdown; the goroutine
// never exits on its own. The pass calls Store.Cleanup and the temporary-state pruners, so a slow
// Store.Cleanup delays StopCleanup. | 首次清理立即执行。间隔为零或负数时选择 5 分钟。调度器已运行时
// 再次调用 StartCleanup 是无操作并返回 nil，因此首个配置的间隔继续生效。关闭时必须调用
// StopCleanup；协程不会自行退出。清理会调用 Store.Cleanup 与临时状态剪除器，因此缓慢的
// Store.Cleanup 会延迟 StopCleanup。
func (s *Server) StartCleanup(interval time.Duration) error {
	if s == nil {
		return errs.Detail(ErrInvalidConfig, "server is nil | 服务器为空")
	}
	if interval <= 0 {
		interval = defaultCleanupInterval
	}
	s.cleanupMu.Lock()
	defer s.cleanupMu.Unlock()
	if s.cleanupCancel != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.cleanupCancel = cancel
	s.cleanupDone = done
	go s.cleanupLoop(ctx, done, interval)
	return nil
}

// StopCleanup stops the periodic cleanup goroutine and waits for it to exit. | StopCleanup 停止周期
// 清理协程并等待其退出。
//
// It is safe to call StopCleanup repeatedly and concurrently with StartCleanup. A stop only waits
// for the scheduler it observed, so a concurrent StartCleanup can begin a fresh scheduler. |
// StopCleanup 可重复调用，也可与 StartCleanup 并发调用。一次停止只等待它观察到的调度器，因此并发的
// StartCleanup 可以启动新的调度器。
func (s *Server) StopCleanup() {
	if s == nil {
		return
	}
	s.cleanupMu.Lock()
	cancel := s.cleanupCancel
	done := s.cleanupDone
	s.cleanupCancel = nil
	s.cleanupDone = nil
	s.cleanupMu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
}

// Cleanup performs one cleanup pass over the store, the request_uri cache and DPoP nonce stores. |
// Cleanup 对存储、request_uri 缓存与 DPoP nonce 存储执行一次清理。
//
// StartCleanup invokes it periodically. Callers may also invoke it directly, for example from an
// external scheduler or before a backup. Errors from Store.Cleanup are joined and returned; pruner
// failures cannot be reported because the pruner interface has no error result. | StartCleanup 会
// 周期调用它。调用方也可直接调用，例如从外部调度器或备份前。Store.Cleanup 的错误会合并返回；剪除器
// 接口没有错误结果，因此无法报告剪除失败。
func (s *Server) Cleanup(ctx context.Context) error {
	if s == nil {
		return errs.Detail(ErrInvalidConfig, "server is nil | 服务器为空")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	now := s.Now()
	var failures []error
	if s.config.Store != nil {
		failures = append(failures, s.config.Store.Cleanup(ctx, now))
	}
	s.requestURIs.pruneNow(now)
	if store := s.config.DPoPNonceStore; store != nil {
		store.Prune(now)
	}
	if pruner, ok := s.config.DPoPVerifier.(dpopNoncePruner); ok {
		pruner.PruneDPoPNonces(now)
	}
	return errors.Join(failures...)
}

// cleanupLoop runs cleanup immediately and then on every tick until ctx is canceled. | cleanupLoop
// 立即执行一次清理，之后每个周期执行，直到 ctx 被取消。
func (s *Server) cleanupLoop(ctx context.Context, done chan struct{}, interval time.Duration) {
	defer close(done)
	s.runCleanup(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runCleanup(ctx)
		}
	}
}

// runCleanup executes one pass and logs a failure without stopping the scheduler. | runCleanup 执行
// 一次清理并记录失败，但不停止调度器。
func (s *Server) runCleanup(ctx context.Context) {
	if err := s.Cleanup(ctx); err != nil && s.config.Logger != nil {
		s.config.Logger.Warn("oauth2: periodic cleanup failed | oauth2：周期清理失败", log.Err(err))
	}
}
