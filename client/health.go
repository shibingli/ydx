package client

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/shibingli/ydx/log"
)

// StartHealth launches one active-health goroutine for the set; it exits on ctx
// cancellation or Close. Calling it again is a no-op. | StartHealth 为集合启动一个主动健康
// goroutine；ctx 取消或 Close 时退出。重复调用无操作。
func (hs *HostSet) StartHealth(ctx context.Context, rt http.RoundTripper, logger *log.Logger) {
	if rt == nil {
		return
	}
	hs.startHealth(ctx, func(*Host) http.RoundTripper { return rt }, logger)
}

// startHealth launches active checks with a per-host transport selector. | startHealth 用逐 Host 传输选择器启动主动检查。
func (hs *HostSet) startHealth(ctx context.Context, choose func(*Host) http.RoundTripper, logger *log.Logger) {
	if hs == nil || choose == nil || hs.closed.Load() || !hs.AnyActive() {
		return
	}
	hs.healthMu.Lock()
	if hs.healthStarted || hs.closed.Load() {
		hs.healthMu.Unlock()
		return
	}
	hs.healthStarted = true
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	hs.healthCancel = cancel
	hs.healthWG.Add(1)
	hs.healthMu.Unlock()
	go hs.healthLoop(ctx, choose, logger)
}

// healthLoop periodically checks every active host from one goroutine. | healthLoop 用单个 goroutine 周期性检查每个主动 Host。
func (hs *HostSet) healthLoop(ctx context.Context, choose func(*Host) http.RoundTripper, logger *log.Logger) {
	defer hs.healthWG.Done()
	interval := hs.minHealthInterval()
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	next := make([]time.Time, len(hs.entries))
	now := hs.now()
	for i, entry := range hs.entries {
		if entry.host.Health.Active {
			next[i] = now
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now = hs.now()
			for i, entry := range hs.entries {
				if !entry.host.Health.Active || now.Before(next[i]) {
					continue
				}
				next[i] = now.Add(entry.host.Health.Interval)
				hs.checkHost(ctx, choose(entry.host), entry, logger)
			}
		}
	}
}

// checkHost performs one active health request and records the outcome. | checkHost 执行一次主动健康请求并记录结果。
func (hs *HostSet) checkHost(ctx context.Context, rt http.RoundTripper, entry *hostEntry, logger *log.Logger) {
	if rt == nil {
		hs.recordFailure(entry, ErrHealthCheck)
		if logger != nil {
			logger.Warn("client: health transport unavailable | client：健康检查传输不可用", log.Str("host", entry.host.Name))
		}
		return
	}
	target := *entry.host.URL
	target.Path = joinHealthPath(target.Path, entry.host.Health.Path)
	target.RawPath = ""
	target.RawQuery = ""
	target.ForceQuery = false
	target.Fragment = ""
	checkCtx, cancel := context.WithTimeout(ctx, entry.host.Health.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(checkCtx, http.MethodHead, target.String(), nil)
	if err != nil {
		hs.recordFailure(entry, err)
		return
	}
	for key, values := range entry.host.Headers {
		if strings.EqualFold(key, "Host") {
			if len(values) > 0 {
				req.Host = values[len(values)-1]
			}
			continue
		}
		req.Header[key] = append([]string(nil), values...)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		closeResponseBody(resp)
		err = redactRequestError(err, req.URL)
		hs.recordFailure(entry, err)
		if logger != nil {
			logger.Warn("client: health check failed | client：健康检查失败", log.Str("host", entry.host.Name), log.Err(err))
		}
		return
	}
	if resp == nil {
		hs.recordFailure(entry, ErrInvalidResponse)
		return
	}
	if resp.Body != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
	}
	if healthStatusOK(entry.host.Health.ExpectStatus, resp.StatusCode) {
		hs.recordSuccess(entry)
		return
	}
	hs.recordFailure(entry, ErrHealthCheck)
	if logger != nil {
		logger.Warn("client: health check status | client：健康检查状态异常", log.Str("host", entry.host.Name), log.Int("status", resp.StatusCode))
	}
}

// minHealthInterval returns the smallest active check interval. | minHealthInterval 返回最小的主动检查间隔。
func (hs *HostSet) minHealthInterval() time.Duration {
	var min time.Duration
	for _, entry := range hs.entries {
		if !entry.host.Health.Active {
			continue
		}
		interval := entry.host.Health.Interval
		if min == 0 || interval < min {
			min = interval
		}
	}
	return min
}

// joinHealthPath joins a base path and a health path without duplicate slashes. | joinHealthPath 拼接 base 与健康路径，避免重复斜杠。
func joinHealthPath(base, path string) string {
	if path == "" {
		path = "/"
	}
	if base == "" || base == "/" {
		if path[0] != '/' {
			return "/" + path
		}
		return path
	}
	base = strings.TrimSuffix(base, "/")
	if path == "/" {
		return base + "/"
	}
	if path[0] != '/' {
		return base + "/" + path
	}
	return base + path
}

// healthStatusOK reports whether status is accepted by the health policy. | healthStatusOK 报告状态码是否被健康策略接受。
func healthStatusOK(expected []int, status int) bool {
	if len(expected) == 0 {
		return status >= 200 && status < 300
	}
	for _, candidate := range expected {
		if candidate == status {
			return true
		}
	}
	return false
}
