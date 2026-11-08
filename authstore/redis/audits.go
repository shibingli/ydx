package redis

import (
	"context"
	"sort"
	"strconv"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
)

// auditStore implements auth.AuditStore on Redis. | auditStore 在 Redis 上实现 auth.AuditStore。
type auditStore struct {
	base
}

// auditStore satisfies auth.AuditStore. | auditStore 满足 auth.AuditStore。
var _ auth.AuditStore = (*auditStore)(nil)

// auditPageChunk bounds one HMGET when a page scans many audit records.
// | auditPageChunk 限定扫描大量审计记录时单次 HMGET 的大小。
const auditPageChunk = 512

// RecordAudit appends an event atomically. | RecordAudit 原子追加事件。
func (s *auditStore) RecordAudit(ctx context.Context, event *auth.AuditEvent) error {
	if event == nil {
		return errs.Detail(auth.ErrInvalidRequest, "event is nil | 事件为空")
	}
	data, err := encodeAudit(event)
	if err != nil {
		return err
	}
	score := utcTime(event.At).UnixNano()
	if _, err := s.runInt(ctx, scriptAuditAppend, "record audit",
		[]string{s.keys.auditSeq(), s.keys.auditEvents(), s.keys.auditIndex()},
		string(data), strconv.FormatInt(score, 10),
	); err != nil {
		return err
	}
	return nil
}

// ListAudit returns a filtered page and the total matching count.
// | ListAudit 返回过滤后的一页与匹配总数。
func (s *auditStore) ListAudit(ctx context.Context, query auth.AuditQuery) ([]*auth.AuditEvent, int, error) {
	seqs, err := s.client.ZRange(ctx, s.keys.auditIndex(), 0, -1).Result()
	if err != nil {
		return nil, 0, s.backend("list audit", err)
	}
	events := make([]*auth.AuditEvent, 0, len(seqs))
	for start := 0; start < len(seqs); start += auditPageChunk {
		end := start + auditPageChunk
		if end > len(seqs) {
			end = len(seqs)
		}
		values, err := s.client.HMGet(ctx, s.keys.auditEvents(), seqs[start:end]...).Result()
		if err != nil {
			return nil, 0, s.backend("list audit", err)
		}
		for _, value := range values {
			if value == nil {
				return nil, 0, errs.Detail(auth.ErrStoreUnavailable, "stored audit event is missing | 存储的审计事件缺失")
			}
			event, err := decodeAudit([]byte(stringValue(value)))
			if err != nil {
				return nil, 0, err
			}
			events = append(events, event)
		}
	}
	filtered := make([]*auth.AuditEvent, 0, len(events))
	for _, event := range events {
		if query.Type != "" && event.Type != query.Type {
			continue
		}
		if query.UserID != "" && event.UserID != query.UserID {
			continue
		}
		if query.ActorID != "" && event.ActorID != query.ActorID {
			continue
		}
		if query.Outcome != "" && event.Outcome != query.Outcome {
			continue
		}
		if !query.Since.IsZero() && event.At.Before(query.Since) {
			continue
		}
		if !query.Until.IsZero() && event.At.After(query.Until) {
			continue
		}
		filtered = append(filtered, event)
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].At.Equal(filtered[j].At) {
			return filtered[i].ID < filtered[j].ID
		}
		return filtered[i].At.Before(filtered[j].At)
	})
	if query.Descending {
		for i, j := 0, len(filtered)-1; i < j; i, j = i+1, j-1 {
			filtered[i], filtered[j] = filtered[j], filtered[i]
		}
	}
	total := len(filtered)
	start, end := pageBounds(query.Offset, query.Limit, total)
	return filtered[start:end], total, nil
}
