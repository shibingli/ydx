package kms

import (
	"context"
	"strconv"
	"time"

	authkms "github.com/shibingli/ydx/auth/keymgmt/kms"
	"github.com/shibingli/ydx/errs"
	ydxjson "github.com/shibingli/ydx/json"
)

// auditPageChunk bounds one HMGET when a page scans many audit records. | auditPageChunk 限定扫描
// 大量审计记录时单次 HMGET 的大小。
const auditPageChunk = 512

// AppendAudit stores one audit event and assigns ID and At when they are empty. | AppendAudit 保存
// 一个审计事件，并在 ID 与 At 为空时赋值。
//
// The sequence allocation, record write and time index update run in one Lua script, so concurrent
// instances never overwrite each other's events. | 序号分配、记录写入与时间索引更新在同一个 Lua
// 脚本内执行，因此并发实例绝不会互相覆盖事件。
func (s *Store) AppendAudit(ctx context.Context, event *authkms.AuditEvent) error {
	if err := s.ready(); err != nil {
		return err
	}
	if event == nil {
		return errs.Detail(authkms.ErrInvalidRequest, "nil audit event | 审计事件为空")
	}
	stored := event.Clone()
	if stored.ID == "" {
		id, err := randomID()
		if err != nil {
			return err
		}
		stored.ID = id
	}
	if stored.At.IsZero() {
		stored.At = time.Now().UTC()
	} else {
		stored.At = stored.At.UTC()
	}
	data, err := encodeAudit(stored)
	if err != nil {
		return err
	}
	defer zeroBytes(data)
	_, err = s.runInt(ctx, scriptAuditAppend, "append audit",
		[]string{s.keys.auditSeq(), s.keys.auditEvents(), s.keys.auditIndex()},
		string(data), strconv.FormatInt(stored.At.UnixNano(), 10))
	return err
}

// ListAudit returns deep copies of the matching events in the requested order. | ListAudit 按请求
// 顺序返回匹配事件的深拷贝。
func (s *Store) ListAudit(ctx context.Context, filter authkms.AuditFilter) ([]*authkms.AuditEvent, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	sequences, err := s.client.ZRange(ctx, s.keys.auditIndex(), 0, -1).Result()
	if err != nil {
		return nil, backend("list audit", err)
	}
	events := make([]*authkms.AuditEvent, 0, len(sequences))
	for start := 0; start < len(sequences); start += auditPageChunk {
		end := start + auditPageChunk
		if end > len(sequences) {
			end = len(sequences)
		}
		values, err := s.client.HMGet(ctx, s.keys.auditEvents(), sequences[start:end]...).Result()
		if err != nil {
			return nil, backend("list audit", err)
		}
		for _, value := range values {
			if value == nil {
				return nil, errs.Detail(authkms.ErrStoreUnavailable, "stored audit event is missing | 存储的审计事件缺失")
			}
			event, err := decodeAudit(stringValue(value))
			if err != nil {
				return nil, err
			}
			events = append(events, event)
		}
	}
	matched := make([]*authkms.AuditEvent, 0, len(events))
	for _, event := range events {
		if auditMatches(filter, event) {
			matched = append(matched, event)
		}
	}
	sortAudit(matched, filter.Descending)
	return paginateAudit(matched, filter.Offset, filter.Limit), nil
}

// encodeAudit returns the JSON form of one audit event. | encodeAudit 返回单个审计事件的 JSON 形式。
func encodeAudit(event *authkms.AuditEvent) ([]byte, error) {
	data, err := ydxjson.Marshal(event)
	if err != nil {
		return nil, errs.Detail(authkms.ErrInvalidRequest, "audit event cannot be encoded | 审计事件无法编码")
	}
	return data, nil
}

// stringValue converts a go-redis reply element to a string. | stringValue 把 go-redis 应答元素
// 转换为字符串。
func stringValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case []byte:
		return string(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case uint64:
		return strconv.FormatUint(typed, 10)
	default:
		return ""
	}
}
