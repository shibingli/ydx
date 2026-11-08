package oauth2

import (
	"strconv"
	"time"

	"github.com/shibingli/ydx/auth"
	authoauth2 "github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/errs"
	ydxjson "github.com/shibingli/ydx/json"
)

// Hash field names shared by the Redis records. | Redis 记录共享的哈希字段名。
const (
	// fieldData carries the JSON record. | fieldData 携带 JSON 记录。
	fieldData = "data"
	// fieldUsed marks a consumed one-time record. | fieldUsed 标记已消费的一次性记录。
	fieldUsed = "used"
	// fieldRevoked marks a revoked record. | fieldRevoked 标记已撤销记录。
	fieldRevoked = "revoked"
	// fieldFamilySet names the family index of a refresh token. | fieldFamilySet 命名刷新令牌的家族索引。
	fieldFamilySet = "familySet"
	// fieldSubjectSet names the subject index of a refresh token. | fieldSubjectSet 命名刷新令牌的主体索引。
	fieldSubjectSet = "subjectSet"
	// fieldStatus carries a device-code status. | fieldStatus 携带设备码状态。
	fieldStatus = "status"
	// fieldInterval carries a device polling interval in nanoseconds. | fieldInterval 携带设备轮询间隔（纳秒）。
	fieldInterval = "interval"
	// fieldHasLast reports whether lastSec/lastNsec are meaningful. | fieldHasLast 报告 lastSec/lastNsec 是否有意义。
	fieldHasLast = "hasLast"
	// fieldLastSec carries the last-poll second. | fieldLastSec 携带最后轮询秒。
	fieldLastSec = "lastSec"
	// fieldLastNsec carries the last-poll nanosecond. | fieldLastNsec 携带最后轮询纳秒。
	fieldLastNsec = "lastNsec"
	// fieldHasExp reports whether expSec/expNsec are meaningful. | fieldHasExp 报告 expSec/expNsec 是否有意义。
	fieldHasExp = "hasExp"
	// fieldExpSec carries an expiry second. | fieldExpSec 携带期限秒。
	fieldExpSec = "expSec"
	// fieldExpNsec carries an expiry nanosecond. | fieldExpNsec 携带期限纳秒。
	fieldExpNsec = "expNsec"
	// fieldUserID carries an approved device user ID. | fieldUserID 携带已批准设备的用户标识。
	fieldUserID = "userID"
	// fieldSubject carries an approved device subject. | fieldSubject 携带已批准设备的主体。
	fieldSubject = "subject"
	// fieldPrincipal carries an approved principal JSON value. | fieldPrincipal 携带已批准主体的 JSON 值。
	fieldPrincipal = "principal"
	// fieldDPoPJKT carries an approved DPoP key thumbprint. | fieldDPoPJKT 携带已批准的 DPoP 密钥指纹。
	fieldDPoPJKT = "dpopJKT"
	// fieldClient carries a device-code client ID for Lua-side ownership checks.
	// | fieldClient 携带设备码客户端标识，供 Lua 侧属主检查。
	fieldClient = "client"
	// fieldUserCode carries a device short user code. | fieldUserCode 携带设备短用户码。
	fieldUserCode = "userCode"
	// fieldUserIndex names the user-code index key of a device code. | fieldUserIndex 命名设备码的用户码索引键。
	fieldUserIndex = "userIndex"
)

// clientRecord is the persisted form of a client registration. SecretHash, the TTL overrides and
// the dynamic-registration fields are tagged json:"-" on Client, so they are carried explicitly
// outside the embedded record. | clientRecord 是客户端注册的持久化形态。SecretHash、TTL 覆盖与
// 动态注册字段在 Client 上标记为 json:"-"，因此在嵌入记录之外显式携带。
type clientRecord struct {
	// Client is the public registration data. | Client 是公开注册数据。
	Client authoauth2.Client `json:"client"`
	// SecretHash is the client secret hash. | SecretHash 是客户端密钥哈希。
	SecretHash string `json:"secret_hash,omitempty"`
	// AccessTokenTTL is the access-token lifetime override. | AccessTokenTTL 是访问令牌寿命覆盖。
	AccessTokenTTL time.Duration `json:"access_token_ttl,omitempty"`
	// RefreshTokenTTL is the refresh-token lifetime override. | RefreshTokenTTL 是刷新令牌寿命覆盖。
	RefreshTokenTTL time.Duration `json:"refresh_token_ttl,omitempty"`
	// AuthorizationCodeTTL is the authorization-code lifetime override.
	// | AuthorizationCodeTTL 是授权码寿命覆盖。
	AuthorizationCodeTTL time.Duration `json:"authorization_code_ttl,omitempty"`
	// RegistrationAccessTokenHash protects the registration management endpoint.
	// | RegistrationAccessTokenHash 保护注册管理端点。
	RegistrationAccessTokenHash string `json:"registration_access_token_hash,omitempty"`
	// RegistrationClientURI is the management endpoint URI. | RegistrationClientURI 是管理端点 URI。
	RegistrationClientURI string `json:"registration_client_uri,omitempty"`
}

// encodeCode serializes one authorization code. | encodeCode 序列化单个授权码。
func encodeCode(code *authoauth2.AuthorizationCode) ([]byte, error) {
	cloned := normalizeCode(code.Clone())
	return marshalRecord(cloned, "authorization code")
}

// decodeCode deserializes one authorization code and applies the consumed flag.
// | decodeCode 反序列化单个授权码并应用消费标志。
func decodeCode(data []byte, used bool) (*authoauth2.AuthorizationCode, error) {
	var code authoauth2.AuthorizationCode
	if err := unmarshalRecord(data, &code, "authorization code"); err != nil {
		return nil, err
	}
	code.Used = used
	normalizeCode(&code)
	return &code, nil
}

// encodeRefresh serializes one refresh token. | encodeRefresh 序列化单个刷新令牌。
func encodeRefresh(token *authoauth2.RefreshToken) ([]byte, error) {
	cloned := normalizeRefresh(token.Clone())
	return marshalRecord(cloned, "refresh token")
}

// decodeRefresh deserializes one refresh token and applies its state flags.
// | decodeRefresh 反序列化单个刷新令牌并应用状态标志。
func decodeRefresh(data []byte, used, revoked bool) (*authoauth2.RefreshToken, error) {
	var token authoauth2.RefreshToken
	if err := unmarshalRecord(data, &token, "refresh token"); err != nil {
		return nil, err
	}
	token.Used = used
	token.Revoked = revoked
	normalizeRefresh(&token)
	return &token, nil
}

// encodeAccess serializes one opaque access token. | encodeAccess 序列化单个不透明访问令牌。
func encodeAccess(token *authoauth2.AccessToken) ([]byte, error) {
	cloned := normalizeAccess(token.Clone())
	return marshalRecord(cloned, "access token")
}

// decodeAccess deserializes one opaque access token and applies its revocation flag.
// | decodeAccess 反序列化单个不透明访问令牌并应用撤销标志。
func decodeAccess(data []byte, revoked bool) (*authoauth2.AccessToken, error) {
	var token authoauth2.AccessToken
	if err := unmarshalRecord(data, &token, "access token"); err != nil {
		return nil, err
	}
	token.Revoked = revoked
	normalizeAccess(&token)
	return &token, nil
}

// encodeDevice serializes one device authorization grant. | encodeDevice 序列化单个设备授权许可。
func encodeDevice(code *authoauth2.DeviceCode) ([]byte, error) {
	cloned := normalizeDevice(code.Clone())
	return marshalRecord(cloned, "device code")
}

// devicePairs returns the flat hash field/value pairs for one device code. The user-code index
// field is included only when includeIndex is true, so UpdateDeviceCode keeps the original index
// registration just like the in-memory store. | devicePairs 返回单个设备码的扁平哈希字段/值对。
// 仅当 includeIndex 为 true 时包含用户码索引字段，因此 UpdateDeviceCode 与内存存储一样保留原始
// 索引注册。
func devicePairs(code *authoauth2.DeviceCode, userIndex string, includeIndex bool) ([]any, error) {
	data, err := encodeDevice(code)
	if err != nil {
		return nil, err
	}
	principal, err := encodePrincipal(code.Principal)
	if err != nil {
		return nil, err
	}
	hasLast, lastSec, lastNsec := "0", "0", "0"
	if !code.LastPolledAt.IsZero() {
		hasLast = "1"
		lastSec, lastNsec = clockFields(code.LastPolledAt)
	}
	hasExp, expSec, expNsec := expiryFields(code.ExpiresAt)
	pairs := []any{
		fieldData, string(data),
		fieldStatus, code.Status,
		fieldInterval, strconv.FormatInt(int64(code.Interval), 10),
		fieldHasLast, hasLast,
		fieldLastSec, lastSec,
		fieldLastNsec, lastNsec,
		fieldHasExp, hasExp,
		fieldExpSec, expSec,
		fieldExpNsec, expNsec,
		fieldUserID, code.UserID,
		fieldSubject, code.Subject,
		fieldPrincipal, principal,
		fieldDPoPJKT, code.DPoPJKT,
		fieldClient, code.ClientID,
		fieldUserCode, code.UserCode,
	}
	if includeIndex {
		pairs = append(pairs, fieldUserIndex, userIndex)
	}
	return pairs, nil
}

// deviceFromFields decodes the data field and overlays the authoritative state fields.
// | deviceFromFields 解码 data 字段并覆盖权威状态字段。
func deviceFromFields(fields map[string]string) (*authoauth2.DeviceCode, error) {
	code, err := decodeDevice([]byte(fields[fieldData]))
	if err != nil {
		return nil, err
	}
	code.Status = fields[fieldStatus]
	if raw, ok := fields[fieldInterval]; ok && raw != "" {
		interval, parseErr := strconv.ParseInt(raw, 10, 64)
		if parseErr != nil {
			return nil, errs.Detail(authoauth2.ErrServerError, "stored device interval is corrupt | 存储的设备间隔损坏")
		}
		code.Interval = time.Duration(interval)
	}
	code.LastPolledAt = time.Time{}
	if fields[fieldHasLast] == "1" {
		sec, err := strconv.ParseInt(fields[fieldLastSec], 10, 64)
		if err != nil {
			return nil, errs.Detail(authoauth2.ErrServerError, "stored device poll clock is corrupt | 存储的设备轮询时钟损坏")
		}
		nsec, err := strconv.ParseInt(fields[fieldLastNsec], 10, 64)
		if err != nil {
			return nil, errs.Detail(authoauth2.ErrServerError, "stored device poll clock is corrupt | 存储的设备轮询时钟损坏")
		}
		code.LastPolledAt = time.Unix(sec, nsec).UTC()
	}
	if fields[fieldHasExp] == "1" {
		sec, err := strconv.ParseInt(fields[fieldExpSec], 10, 64)
		if err != nil {
			return nil, errs.Detail(authoauth2.ErrServerError, "stored device expiry is corrupt | 存储的设备期限损坏")
		}
		nsec, err := strconv.ParseInt(fields[fieldExpNsec], 10, 64)
		if err != nil {
			return nil, errs.Detail(authoauth2.ErrServerError, "stored device expiry is corrupt | 存储的设备期限损坏")
		}
		code.ExpiresAt = time.Unix(sec, nsec).UTC()
	}
	code.UserID = fields[fieldUserID]
	code.Subject = fields[fieldSubject]
	code.DPoPJKT = fields[fieldDPoPJKT]
	principal, err := decodePrincipal(fields[fieldPrincipal])
	if err != nil {
		return nil, err
	}
	code.Principal = principal
	return code, nil
}

// decodeDevice deserializes one device authorization grant. | decodeDevice 反序列化单个设备授权许可。
func decodeDevice(data []byte) (*authoauth2.DeviceCode, error) {
	var code authoauth2.DeviceCode
	if err := unmarshalRecord(data, &code, "device code"); err != nil {
		return nil, err
	}
	normalizeDevice(&code)
	return &code, nil
}

// encodePAR serializes one pushed authorization request. | encodePAR 序列化单个推送授权请求。
func encodePAR(request *authoauth2.PARRequest) ([]byte, error) {
	cloned := normalizePAR(request.Clone())
	return marshalRecord(cloned, "pushed authorization request")
}

// decodePAR deserializes one pushed authorization request and applies the consumed flag.
// | decodePAR 反序列化单个推送授权请求并应用消费标志。
func decodePAR(data []byte, used bool) (*authoauth2.PARRequest, error) {
	var request authoauth2.PARRequest
	if err := unmarshalRecord(data, &request, "pushed authorization request"); err != nil {
		return nil, err
	}
	request.Used = used
	normalizePAR(&request)
	return &request, nil
}

// encodeClient serializes one client registration. | encodeClient 序列化单个客户端注册。
func encodeClient(client *authoauth2.Client) ([]byte, error) {
	cloned := normalizeClient(cloneClient(client))
	record := clientRecord{
		Client:                      *cloned,
		SecretHash:                  cloned.SecretHash,
		AccessTokenTTL:              cloned.AccessTokenTTL,
		RefreshTokenTTL:             cloned.RefreshTokenTTL,
		AuthorizationCodeTTL:        cloned.AuthorizationCodeTTL,
		RegistrationAccessTokenHash: cloned.RegistrationAccessTokenHash,
		RegistrationClientURI:       cloned.RegistrationClientURI,
	}
	return marshalRecord(record, "client")
}

// decodeClient deserializes one client registration. | decodeClient 反序列化单个客户端注册。
func decodeClient(data []byte) (*authoauth2.Client, error) {
	var record clientRecord
	if err := unmarshalRecord(data, &record, "client"); err != nil {
		return nil, err
	}
	client := cloneClient(&record.Client)
	client.SecretHash = record.SecretHash
	client.AccessTokenTTL = record.AccessTokenTTL
	client.RefreshTokenTTL = record.RefreshTokenTTL
	client.AuthorizationCodeTTL = record.AuthorizationCodeTTL
	client.RegistrationAccessTokenHash = record.RegistrationAccessTokenHash
	client.RegistrationClientURI = record.RegistrationClientURI
	normalizeClient(client)
	return client, nil
}

// cloneClient returns a deep copy of a client registration. | cloneClient 返回客户端注册的深拷贝。
func cloneClient(client *authoauth2.Client) *authoauth2.Client {
	if client == nil {
		return nil
	}
	out := *client
	out.RedirectURIs = append([]string(nil), client.RedirectURIs...)
	out.GrantTypes = append([]string(nil), client.GrantTypes...)
	out.ResponseTypes = append([]string(nil), client.ResponseTypes...)
	out.Scopes = append([]string(nil), client.Scopes...)
	out.RequestURIs = append([]string(nil), client.RequestURIs...)
	out.TLSClientAuthSANs = append([]string(nil), client.TLSClientAuthSANs...)
	out.JWKS = append([]byte(nil), client.JWKS...)
	out.PostLogoutRedirectURIs = append([]string(nil), client.PostLogoutRedirectURIs...)
	out.Contacts = append([]string(nil), client.Contacts...)
	if len(client.Metadata) > 0 {
		out.Metadata = make(map[string]string, len(client.Metadata))
		for key, value := range client.Metadata {
			out.Metadata[key] = value
		}
	}
	return &out
}

// encodeScope serializes one scope definition. | encodeScope 序列化单个作用域定义。
func encodeScope(scope authoauth2.Scope) ([]byte, error) {
	cloned := scope
	cloned.Claims = append([]string(nil), scope.Claims...)
	return marshalRecord(cloned, "scope")
}

// decodeScope deserializes one scope definition. | decodeScope 反序列化单个作用域定义。
func decodeScope(data []byte) (authoauth2.Scope, error) {
	var scope authoauth2.Scope
	if err := unmarshalRecord(data, &scope, "scope"); err != nil {
		return authoauth2.Scope{}, err
	}
	scope.Claims = append([]string(nil), scope.Claims...)
	return scope, nil
}

// encodePrincipal serializes an optional principal for a device state field.
// | encodePrincipal 为设备状态字段序列化可选主体。
func encodePrincipal(principal *auth.Principal) (string, error) {
	if principal == nil {
		return "", nil
	}
	cloned := normalizePrincipal(principal.Clone())
	data, err := ydxjson.Marshal(cloned)
	if err != nil {
		return "", errs.Detail(authoauth2.ErrInvalidRequest, "principal cannot be encoded | 主体无法编码")
	}
	return string(data), nil
}

// decodePrincipal deserializes an optional principal from a device state field.
// | decodePrincipal 从设备状态字段反序列化可选主体。
func decodePrincipal(raw string) (*auth.Principal, error) {
	if raw == "" {
		return nil, nil
	}
	var principal auth.Principal
	if err := ydxjson.Unmarshal([]byte(raw), &principal); err != nil {
		return nil, errs.Detail(authoauth2.ErrServerError, "stored principal is corrupt | 存储的主体已损坏")
	}
	normalizePrincipal(&principal)
	return &principal, nil
}

// marshalRecord converts one record and maps encoding failures without exposing library internals.
// | marshalRecord 转换一条记录，并映射编码失败且不暴露库内部信息。
func marshalRecord(value any, kind string) ([]byte, error) {
	data, err := ydxjson.Marshal(value)
	if err != nil {
		return nil, errs.Detail(authoauth2.ErrInvalidRequest, "%s cannot be encoded | %s 无法编码", kind, kind)
	}
	return data, nil
}

// unmarshalRecord converts one stored record and maps corruption to ErrServerError.
// | unmarshalRecord 转换一条已存记录，并把损坏映射为 ErrServerError。
func unmarshalRecord(data []byte, out any, kind string) error {
	if len(data) == 0 {
		return errs.Detail(authoauth2.ErrServerError, "stored %s is empty | 存储的 %s 为空", kind, kind)
	}
	if err := ydxjson.Unmarshal(data, out); err != nil {
		return errs.Detail(authoauth2.ErrServerError, "stored %s is corrupt | 存储的 %s 数据损坏", kind, kind)
	}
	return nil
}

// utcTime normalizes non-zero times to UTC and keeps the zero value canonical.
// | utcTime 把非零时间规范化为 UTC，并保持零值的规范形态。
func utcTime(at time.Time) time.Time {
	if at.IsZero() {
		return time.Time{}
	}
	return at.UTC()
}

// normalizePrincipal normalizes every time carried by a principal and returns it.
// | normalizePrincipal 规范化主体携带的每个时间并返回该主体。
func normalizePrincipal(principal *auth.Principal) *auth.Principal {
	if principal == nil {
		return nil
	}
	principal.AuthTime = utcTime(principal.AuthTime)
	principal.IssuedAt = utcTime(principal.IssuedAt)
	principal.ExpiresAt = utcTime(principal.ExpiresAt)
	return principal
}

// normalizeCode normalizes every time carried by an authorization code.
// | normalizeCode 规范化授权码携带的每个时间。
func normalizeCode(code *authoauth2.AuthorizationCode) *authoauth2.AuthorizationCode {
	if code == nil {
		return nil
	}
	code.AuthTime = utcTime(code.AuthTime)
	code.CreatedAt = utcTime(code.CreatedAt)
	code.ExpiresAt = utcTime(code.ExpiresAt)
	code.Principal = normalizePrincipal(code.Principal)
	return code
}

// normalizeRefresh normalizes every time carried by a refresh token.
// | normalizeRefresh 规范化刷新令牌携带的每个时间。
func normalizeRefresh(token *authoauth2.RefreshToken) *authoauth2.RefreshToken {
	if token == nil {
		return nil
	}
	token.AuthTime = utcTime(token.AuthTime)
	token.CreatedAt = utcTime(token.CreatedAt)
	token.ExpiresAt = utcTime(token.ExpiresAt)
	token.Principal = normalizePrincipal(token.Principal)
	return token
}

// normalizeAccess normalizes every time carried by an access token.
// | normalizeAccess 规范化访问令牌携带的每个时间。
func normalizeAccess(token *authoauth2.AccessToken) *authoauth2.AccessToken {
	if token == nil {
		return nil
	}
	token.AuthTime = utcTime(token.AuthTime)
	token.IssuedAt = utcTime(token.IssuedAt)
	token.ExpiresAt = utcTime(token.ExpiresAt)
	token.Principal = normalizePrincipal(token.Principal)
	return token
}

// normalizeDevice normalizes every time carried by a device code.
// | normalizeDevice 规范化设备码携带的每个时间。
func normalizeDevice(code *authoauth2.DeviceCode) *authoauth2.DeviceCode {
	if code == nil {
		return nil
	}
	code.LastPolledAt = utcTime(code.LastPolledAt)
	code.CreatedAt = utcTime(code.CreatedAt)
	code.ExpiresAt = utcTime(code.ExpiresAt)
	code.Principal = normalizePrincipal(code.Principal)
	return code
}

// normalizePAR normalizes every time carried by a pushed authorization request.
// | normalizePAR 规范化推送授权请求携带的每个时间。
func normalizePAR(request *authoauth2.PARRequest) *authoauth2.PARRequest {
	if request == nil {
		return nil
	}
	request.CreatedAt = utcTime(request.CreatedAt)
	request.ExpiresAt = utcTime(request.ExpiresAt)
	return request
}

// normalizeClient normalizes every time carried by a client registration.
// | normalizeClient 规范化客户端注册携带的每个时间。
func normalizeClient(client *authoauth2.Client) *authoauth2.Client {
	if client == nil {
		return nil
	}
	client.CreatedAt = utcTime(client.CreatedAt)
	client.UpdatedAt = utcTime(client.UpdatedAt)
	return client
}
