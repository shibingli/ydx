package scim

import (
	"time"

	scimlib "github.com/shibingli/ydx/auth/directory/scim"
	"github.com/shibingli/ydx/errs"
	ydxjson "github.com/shibingli/ydx/json"
)

// userRecord is the persisted envelope of one SCIM User. | userRecord 是单个 SCIM User 的持久化封装。
type userRecord struct {
	// User is the embedded resource. | User 是内嵌资源。
	User *scimlib.User `json:"user"`
}

// groupRecord is the persisted envelope of one SCIM Group. | groupRecord 是单个 SCIM Group 的持久化封装。
type groupRecord struct {
	// Group is the embedded resource. | Group 是内嵌资源。
	Group *scimlib.Group `json:"group"`
}

// encodeUser serializes one user after normalizing its metadata times and dropping any caller
// supplied entity tag, which is regenerated atomically by the write script.
// | encodeUser 规范化用户元数据时间并丢弃调用方提供的实体标签后序列化该用户；实体标签由写入脚本原子重建。
func encodeUser(user *scimlib.User) ([]byte, error) {
	stored := user.Clone()
	if stored.Meta != nil {
		normalizeMetaTimes(stored.Meta)
		stored.Meta.Version = ""
	}
	return marshalRecord(userRecord{User: stored}, "User")
}

// decodeUser deserializes one user and overlays the entity tag stored in the record hash.
// | decodeUser 反序列化单个用户，并覆盖记录哈希中存储的实体标签。
func decodeUser(data []byte, version string) (*scimlib.User, error) {
	var record userRecord
	if err := unmarshalRecord(data, &record, "User"); err != nil {
		return nil, err
	}
	if record.User == nil {
		return nil, corruptRecord("User")
	}
	user := record.User.Clone()
	if user.Meta == nil {
		user.Meta = &scimlib.Meta{}
	}
	if version != "" {
		user.Meta.Version = version
	}
	normalizeMetaTimes(user.Meta)
	return user, nil
}

// encodeGroup serializes one group after normalizing its metadata times and dropping any caller
// supplied entity tag. | encodeGroup 规范化组元数据时间并丢弃调用方提供的实体标签后序列化该组。
func encodeGroup(group *scimlib.Group) ([]byte, error) {
	stored := group.Clone()
	if stored.Meta != nil {
		normalizeMetaTimes(stored.Meta)
		stored.Meta.Version = ""
	}
	return marshalRecord(groupRecord{Group: stored}, "Group")
}

// decodeGroup deserializes one group and overlays the entity tag stored in the record hash.
// | decodeGroup 反序列化单个组，并覆盖记录哈希中存储的实体标签。
func decodeGroup(data []byte, version string) (*scimlib.Group, error) {
	var record groupRecord
	if err := unmarshalRecord(data, &record, "Group"); err != nil {
		return nil, err
	}
	if record.Group == nil {
		return nil, corruptRecord("Group")
	}
	group := record.Group.Clone()
	if group.Meta == nil {
		group.Meta = &scimlib.Meta{}
	}
	if version != "" {
		group.Meta.Version = version
	}
	normalizeMetaTimes(group.Meta)
	return group, nil
}

// marshalRecord converts one record and maps encoding failures to scim.ErrInvalidValue.
// | marshalRecord 转换一条记录，并把编码失败映射为 scim.ErrInvalidValue。
func marshalRecord(value any, kind string) ([]byte, error) {
	data, err := ydxjson.Marshal(value)
	if err != nil {
		return nil, errs.Detail(scimlib.ErrInvalidValue, "%s cannot be encoded | %s 无法编码", kind, kind)
	}
	return data, nil
}

// unmarshalRecord converts one stored record and maps corruption to scim.ErrStoreUnavailable.
// | unmarshalRecord 转换一条已存记录，并把损坏映射为 scim.ErrStoreUnavailable。
func unmarshalRecord(data []byte, out any, kind string) error {
	if len(data) == 0 {
		return errs.Detail(scimlib.ErrStoreUnavailable, "stored %s is empty | 存储的 %s 为空", kind, kind)
	}
	if err := ydxjson.Unmarshal(data, out); err != nil {
		return corruptRecord(kind)
	}
	return nil
}

// corruptRecord reports one malformed stored record without exposing decoder internals.
// | corruptRecord 报告单条损坏的已存记录，且不暴露解码器内部信息。
func corruptRecord(kind string) error {
	return errs.Detail(scimlib.ErrStoreUnavailable, "stored %s is corrupt | 存储的 %s 数据损坏", kind, kind)
}

// normalizeMetaTimes rewrites RFC3339 metadata timestamps in UTC. | normalizeMetaTimes 把 RFC3339
// 元数据时间戳重写为 UTC。
func normalizeMetaTimes(meta *scimlib.Meta) {
	if meta == nil {
		return
	}
	meta.Created = normalizeTimeText(meta.Created)
	meta.LastModified = normalizeTimeText(meta.LastModified)
}

// normalizeTimeText parses an RFC3339 timestamp and renders it in UTC; unparseable text is kept
// unchanged. | normalizeTimeText 解析 RFC3339 时间戳并以 UTC 渲染；无法解析的文本保持不变。
func normalizeTimeText(value string) string {
	if value == "" {
		return ""
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return value
	}
	return parsed.UTC().Format(time.RFC3339)
}
