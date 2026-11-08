package federation

import (
	"strconv"
	"time"

	authfederation "github.com/shibingli/ydx/auth/protocol/federation"
	"github.com/shibingli/ydx/errs"
	ydxjson "github.com/shibingli/ydx/json"
)

// Hash field names shared by the Redis records. | Redis 记录共享的哈希字段名。
const (
	// fieldData carries the serialized state record. | fieldData 携带序列化的 state 记录。
	fieldData = "data"
	// fieldExpireSec carries the expiry second. | fieldExpireSec 携带期限秒。
	fieldExpireSec = "expSec"
	// fieldExpireNsec carries the expiry nanosecond. | fieldExpireNsec 携带期限纳秒。
	fieldExpireNsec = "expNsec"
)

// encodeState returns the JSON form of a normalized deep copy of record. | encodeState 返回 record
// 规范化深拷贝的 JSON 形式。
func encodeState(record *authfederation.StateRecord) ([]byte, error) {
	stored := cloneStateRecord(record)
	normalizeStateTimes(stored)
	data, err := ydxjson.Marshal(stored)
	if err != nil {
		return nil, errs.Detail(ErrStoreUnavailable, "encode state record failed | 编码 state 记录失败")
	}
	return data, nil
}

// decodeState deserializes one state record and normalizes its times. | decodeState 反序列化单个
// state 记录并规范化其时间。
func decodeState(data []byte) (*authfederation.StateRecord, error) {
	var record authfederation.StateRecord
	if err := ydxjson.Unmarshal(data, &record); err != nil {
		return nil, errs.Detail(ErrStoreUnavailable, "stored state record is invalid | 存储的 state 记录非法")
	}
	normalizeStateTimes(&record)
	return &record, nil
}

// cloneStateRecord returns a deep copy of a state record. StateRecord contains only strings and
// time values, so copying the struct is a complete deep copy. | cloneStateRecord 返回 state 记录的
// 深拷贝。StateRecord 只包含字符串与时间值，因此复制结构体即为完整深拷贝。
func cloneStateRecord(record *authfederation.StateRecord) *authfederation.StateRecord {
	if record == nil {
		return nil
	}
	copied := *record
	return &copied
}

// normalizeStateTimes normalizes every time carried by a state record. | normalizeStateTimes
// 规范化 state 记录携带的每个时间。
func normalizeStateTimes(record *authfederation.StateRecord) {
	record.CreatedAt = utcTime(record.CreatedAt)
	record.ExpiresAt = utcTime(record.ExpiresAt)
}

// clockFields encodes an instant as whole seconds and nanoseconds, both safe for Lua numbers.
// | clockFields 把时刻编码为整秒与纳秒，两者都可安全表示为 Lua 数字。
func clockFields(at time.Time) (string, string) {
	at = at.UTC()
	return strconv.FormatInt(at.Unix(), 10), strconv.FormatInt(int64(at.Nanosecond()), 10)
}

// utcTime returns at in UTC and leaves the zero time unchanged. | utcTime 以 UTC 返回 at，并保持
// 零值时间不变。
func utcTime(at time.Time) time.Time {
	if at.IsZero() {
		return at
	}
	return at.UTC()
}
