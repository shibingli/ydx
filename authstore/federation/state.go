package federation

import (
	"context"
	"strconv"
	"time"

	authfederation "github.com/shibingli/ydx/auth/protocol/federation"
	"github.com/shibingli/ydx/errs"
)

// Save stores a state record. | Save 保存 state 记录。
//
// A nil or empty record reports federation.ErrStateMismatch. A record already expired at the Redis
// clock reports federation.ErrStateExpired, and a live duplicate state reports
// federation.ErrStateMismatch. A missing ExpiresAt is derived from CreatedAt plus Options.TTL, and a
// missing CreatedAt is set to the current UTC time. The record is serialized before it reaches Redis
// and normalized to UTC, so later caller mutations cannot change stored state. Redis removes the
// physical key at the logical deadline plus a five-minute classification window; before that window
// ends the record is already logically expired and cannot be consumed. Backend failures report
// ErrStoreUnavailable without address or state text; context cancellation and deadline errors are
// returned unchanged. | nil 或空记录返回 federation.ErrStateMismatch。以 Redis 时钟判断已过期的
// 记录返回 federation.ErrStateExpired，有效但重复的 state 返回 federation.ErrStateMismatch。
// 缺失的 ExpiresAt 由 CreatedAt 加 Options.TTL 得出，缺失的 CreatedAt 设为当前 UTC 时间。记录在
// 进入 Redis 前会被序列化并规范化为 UTC，因此调用方后续修改不会改变已存状态。Redis 在逻辑期限
// 加五分钟分类窗口后删除物理键；窗口结束前记录已逻辑过期且不可消费。后端故障以
// ErrStoreUnavailable 返回且不携带地址或 state 文本；上下文取消与超时错误原样返回。
func (s *Store) Save(ctx context.Context, record *authfederation.StateRecord) error {
	if s == nil {
		return errs.Detail(authfederation.ErrInvalidConfig, "state store is nil | state 存储为空")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if record == nil || record.State == "" {
		return errs.Detail(authfederation.ErrStateMismatch, "state record is empty | state 记录为空")
	}
	now := time.Now().UTC()
	stored := cloneStateRecord(record)
	normalizeStateTimes(stored)
	if stored.CreatedAt.IsZero() {
		stored.CreatedAt = now
	}
	if stored.ExpiresAt.IsZero() {
		stored.ExpiresAt = stored.CreatedAt.Add(s.ttl)
	}
	data, err := encodeState(stored)
	if err != nil {
		return err
	}
	expireSec, expireNsec := clockFields(stored.ExpiresAt)
	keyDeadline := strconv.FormatInt(unixMilliCeil(stored.ExpiresAt.Add(expiredStateRetention)), 10)
	status, err := s.runInt(ctx, scriptSave, "save state",
		[]string{s.keys.state(stored.State)}, string(data), expireSec, expireNsec, keyDeadline)
	if err != nil {
		return err
	}
	switch status {
	case -1:
		return errs.Detail(authfederation.ErrStateExpired, "state record is already expired | state 记录已过期")
	case 0:
		return errs.Detail(authfederation.ErrStateMismatch, "state already exists | state 已存在")
	case 1:
		return nil
	default:
		return errs.Detail(ErrStoreUnavailable, "save state returned %d | 保存 state 返回 %d", status, status)
	}
}

// Consume atomically removes and returns a state record. | Consume 原子删除并返回 state 记录。
//
// A missing or empty state reports federation.ErrStateMismatch, an expired record reports
// federation.ErrStateExpired and a corrupt stored record reports ErrStoreUnavailable. The record is
// removed inside the same Lua script that reads it, so exactly one concurrent caller succeeds. The
// returned record is a fresh deep copy with every non-zero time normalized to UTC. Backend failures
// report ErrStoreUnavailable without address or state text; context cancellation and deadline
// errors are returned unchanged. | 缺失或空 state 返回 federation.ErrStateMismatch，过期记录返回
// federation.ErrStateExpired，存储记录损坏返回 ErrStoreUnavailable。记录在读取它的同一个 Lua
// 脚本内删除，因此并发调用中恰好一个成功。返回的记录是全新的深拷贝，所有非零时间规范化为 UTC。
// 后端故障以 ErrStoreUnavailable 返回且不携带地址或 state 文本；上下文取消与超时错误原样返回。
func (s *Store) Consume(ctx context.Context, state string) (*authfederation.StateRecord, error) {
	if s == nil {
		return nil, errs.Detail(authfederation.ErrInvalidConfig, "state store is nil | state 存储为空")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if state == "" {
		return nil, errs.Detail(authfederation.ErrStateMismatch, "state is empty | state 为空")
	}
	reply, err := s.runSlice(ctx, scriptConsume, "consume state",
		[]string{s.keys.state(state)})
	if err != nil {
		return nil, err
	}
	if len(reply) < 2 {
		return nil, errs.Detail(ErrStoreUnavailable, "consume state returned an invalid reply | 消费 state 返回无效应答")
	}
	switch stringValue(reply[0]) {
	case "-1":
		return nil, errs.Detail(authfederation.ErrStateMismatch, "unknown state | 未知 state")
	case "-2":
		return nil, errs.Detail(authfederation.ErrStateExpired, "state expired | state 已过期")
	case "0":
		record, decodeErr := decodeState([]byte(stringValue(reply[1])))
		if decodeErr != nil {
			return nil, decodeErr
		}
		return record, nil
	default:
		return nil, errs.Detail(ErrStoreUnavailable, "consume state returned an unknown status | 消费 state 返回未知状态")
	}
}
