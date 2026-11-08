package webauthn

import (
	"strconv"
	"time"

	authwebauthn "github.com/shibingli/ydx/auth/mfa/webauthn"
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	ydxjson "github.com/shibingli/ydx/json"
)

// encodeCeremony serializes one ceremony so the store owns no caller memory.
// | encodeCeremony 序列化单个流程，使存储不持有调用方内存。
func encodeCeremony(ceremony *authwebauthn.Ceremony) ([]byte, error) {
	cloned := *ceremony
	cloned.CreatedAt = utcTime(cloned.CreatedAt)
	cloned.ExpiresAt = utcTime(cloned.ExpiresAt)
	data, err := ydxjson.Marshal(cloned)
	if err != nil {
		return nil, errs.Detail(authwebauthn.ErrInvalidRequest,
			"ceremony cannot be encoded | 流程无法编码")
	}
	return data, nil
}

// decodeCeremony deserializes one ceremony and normalizes every time to UTC.
// | decodeCeremony 反序列化单个流程，并把每个时间规范化为 UTC。
func decodeCeremony(data []byte) (*authwebauthn.Ceremony, error) {
	var ceremony authwebauthn.Ceremony
	if len(data) == 0 {
		return nil, errs.Detail(ErrCorruptRecord, "stored ceremony is empty | 存储的流程为空")
	}
	if err := ydxjson.Unmarshal(data, &ceremony); err != nil {
		return nil, errs.Detail(ErrCorruptRecord, "stored ceremony is corrupt | 存储的流程损坏")
	}
	ceremony.CreatedAt = utcTime(ceremony.CreatedAt)
	ceremony.ExpiresAt = utcTime(ceremony.ExpiresAt)
	return &ceremony, nil
}

// encodeCredential serializes one credential record and normalizes every time to UTC.
// | encodeCredential 序列化单条凭据记录，并把每个时间规范化为 UTC。
func encodeCredential(credential *authwebauthn.Credential) ([]byte, error) {
	cloned := credential.Clone()
	normalizeCredential(cloned)
	data, err := ydxjson.Marshal(cloned)
	if err != nil {
		return nil, errs.Detail(authwebauthn.ErrInvalidCredential,
			"credential cannot be encoded | 凭据无法编码")
	}
	return data, nil
}

// credentialFromFields decodes one credential hash and overlays the authoritative state fields.
// | credentialFromFields 解码单个凭据哈希并覆盖权威状态字段。
func credentialFromFields(fields map[string]string) (*authwebauthn.Credential, error) {
	raw, ok := fields[fieldData]
	if !ok || raw == "" {
		return nil, errs.Detail(authwebauthn.ErrInvalidCredential,
			"stored credential data is empty | 存储的凭据数据为空")
	}
	var credential authwebauthn.Credential
	if err := ydxjson.Unmarshal([]byte(raw), &credential); err != nil {
		return nil, errs.Detail(authwebauthn.ErrInvalidCredential,
			"stored credential is corrupt | 存储的凭据损坏")
	}
	if value, ok := fields[fieldSignCount]; ok && value != "" {
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, errs.Detail(authwebauthn.ErrInvalidCredential,
				"stored credential sign count is corrupt | 存储的凭据签名计数器损坏")
		}
		credential.SignCount = uint32(parsed)
	}
	if value, ok := fields[fieldBackupState]; ok && value != "" {
		credential.BackupState = value == "1"
	}
	normalizeCredential(&credential)
	return &credential, nil
}

// normalizeCredential normalizes every time carried by a credential. | normalizeCredential 规范化
// 凭据携带的每个时间。
func normalizeCredential(credential *authwebauthn.Credential) {
	if credential == nil {
		return
	}
	credential.CreatedAt = utcTime(credential.CreatedAt)
	credential.LastUsedAt = utcTime(credential.LastUsedAt)
}

// utcTime normalizes a non-zero time to UTC and keeps the zero value canonical.
// | utcTime 把非零时间规范化为 UTC，并保持零值的规范形态。
func utcTime(at time.Time) time.Time {
	if at.IsZero() {
		return time.Time{}
	}
	return at.UTC()
}

// credentialIDString returns the unpadded base64url credential ID used in keys and set members.
// | credentialIDString 返回键与集合成员使用的无填充 base64url 凭据 ID。
func credentialIDString(credentialID []byte) string {
	return base64.RawURLEncoding.EncodeToString(credentialID)
}
