package wsfed

import (
	"context"
	"strings"
	"time"

	authwsfed "github.com/shibingli/ydx/auth/protocol/wsfed"
	"github.com/shibingli/ydx/errs"
)

// SaveRequest stores an outstanding request keyed by Wctx. | SaveRequest 按 Wctx 保存未完成请求。
//
// A zero CreatedAt is set to the current time and a zero ExpiresAt to ten minutes later, matching
// the in-memory store. Times are stored in UTC, and the Redis expiry mirrors ExpiresAt so abandoned
// requests are reclaimed. | 零值 CreatedAt 使用当前时间，零值 ExpiresAt 使用十分钟后，与内存存储
// 一致。时间以 UTC 存储，Redis 期限与 ExpiresAt 对应，因此被放弃的请求会被回收。
func (s *Store) SaveRequest(ctx context.Context, state authwsfed.RequestState) error {
	ctx, err := normalizeContext(ctx)
	if err != nil {
		return err
	}
	state.Wctx = strings.TrimSpace(state.Wctx)
	if state.Wctx == "" {
		return errs.Detail(authwsfed.ErrInvalidRequest, "wctx is required | 需要 wctx")
	}
	now := time.Now()
	if state.CreatedAt.IsZero() {
		state.CreatedAt = now
	}
	if state.ExpiresAt.IsZero() {
		state.ExpiresAt = now.Add(defaultRequestTTL)
	}
	state.CreatedAt = utcTime(state.CreatedAt)
	state.ExpiresAt = utcTime(state.ExpiresAt)
	data, err := encodeRequest(state)
	if err != nil {
		return err
	}
	ttl := time.Until(state.ExpiresAt)
	if ttl < minimumTTL {
		ttl = minimumTTL
	}
	if err := s.client.Set(ctx, s.keys.request(state.Wctx), data, ttl).Err(); err != nil {
		return s.backend("save request", err)
	}
	return nil
}

// TakeRequest atomically consumes a request and reports whether it was present and fresh.
// | TakeRequest 原子消费请求，并报告是否存在且未过期。
//
// The read and delete run in one Lua script, so exactly one of several concurrent callers, in any
// application instance, can receive true for one record. An expired record is discarded and
// reported as absent. | 读取与删除在单个 Lua 脚本中完成，因此在任意应用实例的并发调用中，只有一个
// 调用能对同一条记录得到 true。过期记录会被丢弃并按不存在报告。
func (s *Store) TakeRequest(ctx context.Context, wctx string) (authwsfed.RequestState, bool, error) {
	ctx, err := normalizeContext(ctx)
	if err != nil {
		return authwsfed.RequestState{}, false, err
	}
	wctx = strings.TrimSpace(wctx)
	if wctx == "" {
		return authwsfed.RequestState{}, false, nil
	}
	reply, err := scriptTakeRequest.Run(ctx, s.client, []string{s.keys.request(wctx)}).Slice()
	if err != nil {
		return authwsfed.RequestState{}, false, s.backend("take request", err)
	}
	if len(reply) < 2 || intValue(reply[0]) != 1 {
		return authwsfed.RequestState{}, false, nil
	}
	state, err := decodeRequest([]byte(stringValue(reply[1])))
	if err != nil {
		return authwsfed.RequestState{}, false, err
	}
	if !state.ExpiresAt.IsZero() && !time.Now().Before(state.ExpiresAt) {
		return authwsfed.RequestState{}, false, nil
	}
	return state, true, nil
}
