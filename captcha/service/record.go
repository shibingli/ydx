package service

import (
	"context"
	"time"

	"github.com/shibingli/ydx/captcha/core"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// encodeRecord serializes a record for a Store. | encodeRecord 把记录序列化给 Store。
func encodeRecord(record *Record) ([]byte, error) {
	payload, err := json.Marshal(record)
	if err != nil {
		return nil, errs.Wrap(err, ErrStore)
	}
	return payload, nil
}

// decodeRecord deserializes a stored record. | decodeRecord 反序列化已存储记录。
func decodeRecord(payload []byte) (*Record, error) {
	var record Record
	if err := json.Unmarshal(payload, &record); err != nil {
		return nil, errs.Wrap(err, ErrStore)
	}
	return &record, nil
}

// defaultType returns the first enabled type, preferring text. | defaultType 返回首个启用类型，优先文本。
func (m *Manager) defaultType() Type {
	if m.typeEnabled(TypeText) {
		return TypeText
	}
	if len(m.opts.Types) > 0 {
		return m.opts.Types[0]
	}
	return TypeText
}

// adaptiveType steps up the challenge family as risk rises. | adaptiveType 随风险升高升级验证码类型。
func (m *Manager) adaptiveType(score int) Type {
	if score >= 60 && m.typeEnabled(TypeClickText) {
		return TypeClickText
	}
	if score >= 40 && m.typeEnabled(TypeSlide) {
		return TypeSlide
	}
	return m.defaultType()
}

// storeImages persists generated images and builds public descriptors. | storeImages 持久化生成的图片并构建公开描述。
func (m *Manager) storeImages(ctx context.Context, data []ImageData) ([]string, []Image, error) {
	keys := make([]string, 0, len(data))
	images := make([]Image, 0, len(data))
	for _, img := range data {
		publicKey, err := randomID(16)
		if err != nil {
			m.deleteImageKeys(ctx, keys)
			return nil, nil, err
		}
		storeKey := m.opts.KeyPrefix + "img:" + publicKey
		if err := m.images.Put(ctx, storeKey, img.Data, img.MIME, m.opts.ChallengeTTL+30*time.Second); err != nil {
			m.deleteImageKeys(ctx, keys)
			return nil, nil, errs.Wrap(err, ErrStore)
		}
		keys = append(keys, storeKey)
		images = append(images, Image{Name: img.Name, URL: "image/" + publicKey, Width: img.Width, Height: img.Height, MIME: img.MIME})
	}
	return keys, images, nil
}

// deleteImages removes every image referenced by a record. | deleteImages 删除记录引用的全部图片。
func (m *Manager) deleteImages(ctx context.Context, record *Record) {
	if record == nil {
		return
	}
	for _, key := range record.Images {
		if err := m.images.Delete(ctx, key); err != nil {
			m.logWarn("captcha image delete failed | 验证码图片删除失败", err)
		}
	}
}

// deleteImageKeys removes store keys. | deleteImageKeys 删除存储键。
func (m *Manager) deleteImageKeys(ctx context.Context, keys []string) {
	for _, key := range keys {
		if err := m.images.Delete(ctx, key); err != nil {
			m.logWarn("captcha image cleanup failed | 验证码图片清理失败", err)
		}
	}
}

// resaveRecord stores a record again with its remaining lifetime. | resaveRecord 以剩余存活时间重新存储记录。
func (m *Manager) resaveRecord(ctx context.Context, record *Record, now time.Time) error {
	remaining := record.ExpiresAt.Sub(now)
	if remaining <= 0 {
		return ErrExpired
	}
	payload, err := encodeRecord(record)
	if err != nil {
		return err
	}
	if err := m.store.Put(ctx, m.recordKey(record.ID), payload, remaining); err != nil {
		return errs.Wrap(err, ErrStore)
	}
	return nil
}

// restoreRecord re-stores a taken record after an infrastructure failure. | restoreRecord 在基础设施故障后重新存储已取出的记录。
//
// It uses a detached context so a cancelled request does not destroy a valid
// challenge. | 使用独立上下文，避免已取消的请求销毁有效挑战。
func (m *Manager) restoreRecord(record *Record, now time.Time) {
	if record == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = m.resaveRecord(ctx, record, now)
}

// failRecord consumes one attempt and either re-stores or exhausts the challenge. | failRecord 消费一次尝试并重新存储或耗尽挑战。
func (m *Manager) failRecord(ctx context.Context, record *Record, now time.Time, meta Meta, failure error, reasons ...string) error {
	record.Attempts++
	record.RiskReasons = appendReasons(record.RiskReasons, reasons)
	auditErr := failure
	if record.Attempts >= record.MaxAttempts {
		auditErr = ErrTooManyAttempts
	}
	m.auditSince(ctx, now, AuditEvent{RequestID: meta.RequestID, ChallengeID: record.ID, Action: record.Action, Type: record.Type, Outcome: AuditFailed, IP: meta.IP, Country: record.Geo.Country, Target: record.Target, Risk: record.Risk, Reasons: reasons, ErrorCode: core.ErrorCode(auditErr)})
	if record.Attempts >= record.MaxAttempts {
		m.deleteImages(ctx, record)
		return ErrTooManyAttempts
	}
	if err := m.resaveRecord(ctx, record, now); err != nil {
		return err
	}
	return failure
}

// recordKey names a challenge record in the store. | recordKey 命名存储中的挑战记录。
func (m *Manager) recordKey(id string) string { return m.opts.KeyPrefix + "ch:" + id }
