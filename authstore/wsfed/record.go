package wsfed

import (
	"time"

	authwsfed "github.com/shibingli/ydx/auth/protocol/wsfed"
	"github.com/shibingli/ydx/errs"
	ydxjson "github.com/shibingli/ydx/json"
)

// encodeRequest serializes one request state so the store owns no caller memory.
// | encodeRequest 序列化单个请求状态，使存储不持有调用方内存。
func encodeRequest(state authwsfed.RequestState) ([]byte, error) {
	data, err := ydxjson.Marshal(state)
	if err != nil {
		return nil, errs.Detail(authwsfed.ErrInvalidRequest,
			"request state cannot be encoded | 请求状态无法编码")
	}
	return data, nil
}

// decodeRequest deserializes one request state and normalizes every time to UTC.
// | decodeRequest 反序列化单个请求状态，并把每个时间规范化为 UTC。
func decodeRequest(data []byte) (authwsfed.RequestState, error) {
	var state authwsfed.RequestState
	if len(data) == 0 {
		return state, errs.Detail(ErrCorruptRecord, "stored request state is empty | 存储的请求状态为空")
	}
	if err := ydxjson.Unmarshal(data, &state); err != nil {
		return state, errs.Detail(ErrCorruptRecord, "stored request state is corrupt | 存储的请求状态损坏")
	}
	state.CreatedAt = utcTime(state.CreatedAt)
	state.ExpiresAt = utcTime(state.ExpiresAt)
	return state, nil
}

// utcTime normalizes a non-zero time to UTC and keeps the zero value canonical.
// | utcTime 把非零时间规范化为 UTC，并保持零值的规范形态。
func utcTime(at time.Time) time.Time {
	if at.IsZero() {
		return time.Time{}
	}
	return at.UTC()
}
