package saml

import (
	"strconv"
	"time"

	samlapi "github.com/shibingli/ydx/auth/protocol/saml"
	"github.com/shibingli/ydx/errs"
	ydxjson "github.com/shibingli/ydx/json"
)

// utcTime normalizes a non-zero time to UTC and keeps the zero value canonical.
// | utcTime 把非零时间规范化为 UTC，并保持零值的规范形态。
func utcTime(t time.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}
	return t.UTC()
}

// expiryFields encodes an optional deadline as a flag plus whole seconds and nanoseconds. The
// split keeps exact nanosecond comparisons possible inside Redis Lua, whose numbers cannot
// represent a Unix nanosecond timestamp without precision loss. | expiryFields 把可选期限编码为
// 标志、整秒与纳秒。拆分使 Redis Lua 内可以进行精确纳秒比较，因为 Lua 数字无法无损表示 Unix 纳秒
// 时间戳。
func expiryFields(t time.Time) (hasExpiry, sec, nsec string) {
	if t.IsZero() {
		return "0", "0", "0"
	}
	t = t.UTC()
	return "1", strconv.FormatInt(t.Unix(), 10), strconv.FormatInt(int64(t.Nanosecond()), 10)
}

// clockFields encodes an instant as whole seconds and nanoseconds.
// | clockFields 把时刻编码为整秒与纳秒。
func clockFields(t time.Time) (sec, nsec string) {
	t = t.UTC()
	return strconv.FormatInt(t.Unix(), 10), strconv.FormatInt(int64(t.Nanosecond()), 10)
}

// flag renders a boolean as the "1"/"0" form used by the scripts.
// | flag 把布尔值渲染为脚本使用的 "1"/"0" 形式。
func flag(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

// stringValue converts one script reply element to text. | stringValue 把单个脚本应答元素转换为文本。
func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	default:
		return ""
	}
}

// intValue converts one script reply element to an integer. | intValue 把单个脚本应答元素转换为整数。
func intValue(value any) (int64, error) {
	switch typed := value.(type) {
	case int64:
		return typed, nil
	case string:
		return parseInt(typed)
	case []byte:
		return parseInt(string(typed))
	default:
		return 0, errs.Detail(ErrStoreUnavailable, "script reply is not an integer | 脚本应答不是整数")
	}
}

// parseInt parses an integer reply element. | parseInt 解析整数应答元素。
func parseInt(value string) (int64, error) {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, errs.Detail(ErrStoreUnavailable, "script reply is not an integer | 脚本应答不是整数")
	}
	return parsed, nil
}

// marshalRecord converts one record to JSON and maps encoding failures to invalid without
// exposing library internals. | marshalRecord 把一条记录转换为 JSON，并把编码失败映射为 invalid，
// 且不暴露库内部信息。
func marshalRecord(value any, kind string, invalid error) ([]byte, error) {
	data, err := ydxjson.Marshal(value)
	if err != nil {
		return nil, errs.Detail(invalid, "%s cannot be encoded | %s 无法编码", kind, kind)
	}
	return data, nil
}

// unmarshalRecord converts one stored record and maps corruption to ErrStoreUnavailable.
// | unmarshalRecord 转换一条已存记录，并把损坏映射为 ErrStoreUnavailable。
func unmarshalRecord(data []byte, out any, kind string) error {
	if len(data) == 0 {
		return errs.Detail(ErrStoreUnavailable, "stored %s is empty | 存储的 %s 为空", kind, kind)
	}
	if err := ydxjson.Unmarshal(data, out); err != nil {
		return errs.Detail(ErrStoreUnavailable, "stored %s is corrupt | 存储的 %s 数据损坏", kind, kind)
	}
	return nil
}

// encodeRequest serializes one request with UTC times. | encodeRequest 序列化单个请求并使用 UTC 时间。
func encodeRequest(request *samlapi.RequestState) ([]byte, error) {
	c := request.Clone()
	normalizeRequestTimes(c)
	return marshalRecord(c, "request", samlapi.ErrInvalidRequest)
}

// decodeRequest deserializes one request and normalizes its times. | decodeRequest 反序列化单个请求并规范化其时间。
func decodeRequest(data []byte) (*samlapi.RequestState, error) {
	var request samlapi.RequestState
	if err := unmarshalRecord(data, &request, "request"); err != nil {
		return nil, err
	}
	normalizeRequestTimes(&request)
	return &request, nil
}

// normalizeRequestTimes normalizes every time carried by a request.
// | normalizeRequestTimes 规范化请求携带的每个时间。
func normalizeRequestTimes(request *samlapi.RequestState) {
	request.CreatedAt = utcTime(request.CreatedAt)
	request.ExpiresAt = utcTime(request.ExpiresAt)
}

// encodeSession serializes one session with UTC times. | encodeSession 序列化单个会话并使用 UTC 时间。
func encodeSession(session *samlapi.Session) ([]byte, error) {
	c := session.Clone()
	normalizeSessionTimes(c)
	return marshalRecord(c, "session", samlapi.ErrInvalidRequest)
}

// decodeSession deserializes one session and normalizes its times. | decodeSession 反序列化单个会话并规范化其时间。
func decodeSession(data []byte) (*samlapi.Session, error) {
	var session samlapi.Session
	if err := unmarshalRecord(data, &session, "session"); err != nil {
		return nil, err
	}
	normalizeSessionTimes(&session)
	return &session, nil
}

// normalizeSessionTimes normalizes every time carried by a session.
// | normalizeSessionTimes 规范化会话携带的每个时间。
func normalizeSessionTimes(session *samlapi.Session) {
	session.CreatedAt = utcTime(session.CreatedAt)
	session.ExpiresAt = utcTime(session.ExpiresAt)
}

// encodeArtifact serializes one artifact record with UTC times. | encodeArtifact 序列化单条工件记录并使用 UTC 时间。
func encodeArtifact(record *samlapi.ArtifactRecord) ([]byte, error) {
	c := record.Clone()
	normalizeArtifactTimes(c)
	return marshalRecord(c, "artifact record", samlapi.ErrArtifactInvalid)
}

// decodeArtifact deserializes one artifact record and normalizes its times. | decodeArtifact 反序列化工件记录并规范化其时间。
func decodeArtifact(data []byte) (*samlapi.ArtifactRecord, error) {
	var record samlapi.ArtifactRecord
	if err := unmarshalRecord(data, &record, "artifact record"); err != nil {
		return nil, err
	}
	normalizeArtifactTimes(&record)
	return &record, nil
}

// normalizeArtifactTimes normalizes every time carried by an artifact record.
// | normalizeArtifactTimes 规范化工件记录携带的每个时间。
func normalizeArtifactTimes(record *samlapi.ArtifactRecord) {
	record.IssuedAt = utcTime(record.IssuedAt)
	record.ExpiresAt = utcTime(record.ExpiresAt)
}
