package kms

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"

	authkms "github.com/shibingli/ydx/auth/keymgmt/kms"
	"github.com/shibingli/ydx/errs"
	ydxjson "github.com/shibingli/ydx/json"
)

// keyEnvelope is the persisted form of authkms.Key. Material is tagged json:"-" on Key, so it is
// carried explicitly next to the metadata; versions are stored in their own hash.
// | keyEnvelope 是 authkms.Key 的持久化形态。Material 在 Key 上标记为 json:"-"，因此与元数据
// 并排显式携带；版本保存在独立哈希中。
type keyEnvelope struct {
	// Key is the serializable key metadata. | Key 是可序列化的密钥元数据。
	Key authkms.Key `json:"key"`
	// Material is the private or symmetric key material. | Material 是私钥或对称密钥材料。
	Material []byte `json:"material,omitempty"`
}

// versionEnvelope is the persisted form of authkms.KeyVersion. | versionEnvelope 是
// authkms.KeyVersion 的持久化形态。
type versionEnvelope struct {
	// Version is the version number duplicated for corruption checks. | Version 是用于损坏校验的版本号副本。
	Version uint32 `json:"version"`
	// Meta is the serializable version metadata. | Meta 是可序列化的版本元数据。
	Meta authkms.KeyVersion `json:"meta"`
	// Material is the private or symmetric version material. | Material 是私钥或对称版本材料。
	Material []byte `json:"material,omitempty"`
}

// encodeKey returns the JSON form of key without material duplication. | encodeKey 返回 key 的 JSON
// 形式，且不重复保存材料。
//
// The caller keeps ownership of key; the function works on a clone and clears the serialized
// material copy before returning. | 调用方保留 key 的所有权；函数在克隆上工作，并在返回前清除
// 序列化所用的材料副本。
func encodeKey(key *authkms.Key) ([]byte, error) {
	clone := key.Clone()
	normalizeKeyTimes(clone)
	record := keyEnvelope{Key: *clone, Material: clone.Material}
	record.Key.Material = nil
	record.Key.Revision = 0
	record.Key.Versions = nil
	data, err := ydxjson.Marshal(record)
	zeroBytes(record.Material)
	if err != nil {
		return nil, errs.Detail(authkms.ErrInvalidRequest, "key cannot be encoded | 密钥无法编码")
	}
	return data, nil
}

// decodeKey parses one stored key record. | decodeKey 解析一条已存密钥记录。
//
// The decoded value is freshly allocated, so callers never share slices or maps with another
// reader. | 解码值是全新分配的，因此调用方不会与其它读取者共享切片或映射。
func decodeKey(data string) (*authkms.Key, error) {
	if data == "" {
		return nil, errs.Detail(authkms.ErrStoreUnavailable, "stored key is empty | 存储的密钥为空")
	}
	var record keyEnvelope
	raw := []byte(data)
	err := ydxjson.Unmarshal(raw, &record)
	zeroBytes(raw)
	if err != nil {
		zeroBytes(record.Material)
		return nil, errs.Detail(authkms.ErrStoreUnavailable, "stored key is corrupt | 存储的密钥数据损坏")
	}
	key := record.Key
	key.Material = record.Material
	normalizeKeyTimes(&key)
	return &key, nil
}

// encodeVersion returns the JSON form of version without material duplication. | encodeVersion 返回
// version 的 JSON 形式，且不重复保存材料。
func encodeVersion(version *authkms.KeyVersion) ([]byte, error) {
	clone := version.Clone()
	normalizeVersionTimes(clone)
	record := versionEnvelope{Version: clone.Version, Meta: *clone, Material: clone.Material}
	record.Meta.Material = nil
	data, err := ydxjson.Marshal(record)
	zeroBytes(record.Material)
	if err != nil {
		return nil, errs.Detail(authkms.ErrInvalidRequest, "key version cannot be encoded | 密钥版本无法编码")
	}
	return data, nil
}

// decodeVersion parses one stored version record. | decodeVersion 解析一条已存版本记录。
func decodeVersion(data string) (*authkms.KeyVersion, error) {
	if data == "" {
		return nil, errs.Detail(authkms.ErrStoreUnavailable, "stored key version is empty | 存储的密钥版本为空")
	}
	var record versionEnvelope
	raw := []byte(data)
	err := ydxjson.Unmarshal(raw, &record)
	zeroBytes(raw)
	if err != nil {
		zeroBytes(record.Material)
		return nil, errs.Detail(authkms.ErrStoreUnavailable, "stored key version is corrupt | 存储的密钥版本数据损坏")
	}
	if record.Version != record.Meta.Version {
		zeroBytes(record.Material)
		return nil, errs.Detail(authkms.ErrStoreUnavailable, "stored key version number is corrupt | 存储的密钥版本号损坏")
	}
	version := record.Meta
	version.Material = record.Material
	normalizeVersionTimes(&version)
	return &version, nil
}

// decodeAudit parses one stored audit event. | decodeAudit 解析一条已存审计事件。
func decodeAudit(data string) (*authkms.AuditEvent, error) {
	if data == "" {
		return nil, errs.Detail(authkms.ErrStoreUnavailable, "stored audit event is empty | 存储的审计事件为空")
	}
	var event authkms.AuditEvent
	raw := []byte(data)
	err := ydxjson.Unmarshal(raw, &event)
	zeroBytes(raw)
	if err != nil {
		return nil, errs.Detail(authkms.ErrStoreUnavailable, "stored audit event is corrupt | 存储的审计事件数据损坏")
	}
	event.At = utcTime(event.At)
	return &event, nil
}

// utcTime normalizes a non-zero time to UTC and keeps the zero value canonical. | utcTime 把非零
// 时间规范化为 UTC，并保持零值的规范形态。
func utcTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Time{}
	}
	return value.UTC()
}

// normalizeKeyTimes converts every non-zero time carried by key to UTC. | normalizeKeyTimes 把密钥
// 携带的每个非零时间转换为 UTC。
func normalizeKeyTimes(key *authkms.Key) {
	if key == nil {
		return
	}
	key.CreatedAt = utcTime(key.CreatedAt)
	key.ActivatedAt = utcTime(key.ActivatedAt)
	key.DeactivatedAt = utcTime(key.DeactivatedAt)
	key.CompromisedAt = utcTime(key.CompromisedAt)
	key.DestroyedAt = utcTime(key.DestroyedAt)
	key.DeleteAfter = utcTime(key.DeleteAfter)
}

// normalizeVersionTimes converts every non-zero time carried by version to UTC. |
// normalizeVersionTimes 把版本携带的每个非零时间转换为 UTC。
func normalizeVersionTimes(version *authkms.KeyVersion) {
	if version == nil {
		return
	}
	version.CreatedAt = utcTime(version.CreatedAt)
	version.ActivatedAt = utcTime(version.ActivatedAt)
	version.DeactivatedAt = utcTime(version.DeactivatedAt)
	version.DestroyedAt = utcTime(version.DestroyedAt)
}

// zeroBytes overwrites b with zeroes. | zeroBytes 用零覆盖 b。
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// randomID returns a 32-character lowercase hex event identifier. | randomID 返回 32 字符小写十六
// 进制事件标识。
func randomID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", errs.Wrap(err, authkms.ErrRandomSource)
	}
	return hex.EncodeToString(raw[:]), nil
}

// createdAtScore renders a creation time as the all-keys index score. | createdAtScore 把创建时间
// 渲染为全部键索引评分。
func createdAtScore(createdAt time.Time) string {
	if createdAt.IsZero() {
		return "0"
	}
	return strconv.FormatInt(createdAt.UTC().UnixNano(), 10)
}

// filterMatches reports whether key passes filter. It mirrors the semantics of the in-memory
// store: Query is a case-insensitive substring over ID, alias and metadata values.
// | filterMatches 报告 key 是否通过 filter。它复刻内存存储的语义：Query 是作用于 ID、别名与
// 元数据值的大小写不敏感子串。
func filterMatches(filter authkms.KeyFilter, key *authkms.Key) bool {
	if key == nil {
		return false
	}
	if filter.State != "" && key.State != filter.State {
		return false
	}
	if filter.Type != "" && key.Type != filter.Type {
		return false
	}
	if filter.Usage != "" && !key.UsageMask.Has(filter.Usage) {
		return false
	}
	if filter.ParentID != "" && key.ParentID != filter.ParentID {
		return false
	}
	if filter.Tag != "" {
		found := false
		for _, tag := range key.Tags {
			if tag == filter.Tag {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if filter.Query != "" {
		query := strings.ToLower(filter.Query)
		if !containsFold(key.ID, query) && !containsFold(key.Alias, query) {
			found := false
			for _, value := range key.Metadata {
				if containsFold(value, query) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}

// containsFold reports whether value contains the already-lowercased needle. | containsFold 报告
// value 是否包含已转小写的 needle。
func containsFold(value, needle string) bool {
	if needle == "" {
		return true
	}
	return strings.Contains(strings.ToLower(value), needle)
}

// sortKeys orders keys by creation time, then identifier, for deterministic listings. | sortKeys
// 按创建时间再按标识排序，使列表输出确定。
func sortKeys(list []*authkms.Key) {
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].CreatedAt.Equal(list[j].CreatedAt) {
			return list[i].ID < list[j].ID
		}
		return list[i].CreatedAt.Before(list[j].CreatedAt)
	})
}

// paginateKeys applies offset and limit to an already ordered key list. | paginateKeys 对已排序的
// 密钥列表应用 offset 与 limit。
func paginateKeys(list []*authkms.Key, offset, limit int) []*authkms.Key {
	if offset > 0 {
		if offset >= len(list) {
			return []*authkms.Key{}
		}
		list = list[offset:]
	}
	if limit > 0 && limit < len(list) {
		list = list[:limit]
	}
	return list
}

// auditMatches reports whether event passes filter. | auditMatches 报告 event 是否通过 filter。
func auditMatches(filter authkms.AuditFilter, event *authkms.AuditEvent) bool {
	if event == nil {
		return false
	}
	if filter.Operation != "" && event.Operation != filter.Operation {
		return false
	}
	if filter.KeyID != "" && event.KeyID != filter.KeyID {
		return false
	}
	if filter.Actor != "" && event.Actor != filter.Actor {
		return false
	}
	if filter.Outcome != "" && event.Outcome != filter.Outcome {
		return false
	}
	if !filter.Since.IsZero() && event.At.Before(filter.Since) {
		return false
	}
	if !filter.Until.IsZero() && event.At.After(filter.Until) {
		return false
	}
	return true
}

// sortAudit orders events chronologically with a stable tie-break on ID. | sortAudit 按时间排序，
// 并以 ID 稳定打破平局。
func sortAudit(events []*authkms.AuditEvent, descending bool) {
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].At.Equal(events[j].At) {
			if descending {
				return events[i].ID > events[j].ID
			}
			return events[i].ID < events[j].ID
		}
		if descending {
			return events[i].At.After(events[j].At)
		}
		return events[i].At.Before(events[j].At)
	})
}

// paginateAudit applies offset and limit to an already ordered audit list. | paginateAudit 对已排序
// 的审计列表应用 offset 与 limit。
func paginateAudit(events []*authkms.AuditEvent, offset, limit int) []*authkms.AuditEvent {
	if offset > 0 {
		if offset >= len(events) {
			return []*authkms.AuditEvent{}
		}
		events = events[offset:]
	}
	if limit > 0 && limit < len(events) {
		events = events[:limit]
	}
	return events
}
