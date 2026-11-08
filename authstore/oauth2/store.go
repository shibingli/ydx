package oauth2

import (
	"context"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/shibingli/ydx/auth"
	authoauth2 "github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/errs"
)

// store is the Redis implementation of authoauth2.Store. | store 是 authoauth2.Store 的 Redis 实现。
type store struct {
	// base carries the shared client and key namespace. | base 承载共享客户端与键命名空间。
	base
}

// Store is the Redis implementation of authoauth2.Store. | Store 是 authoauth2.Store 的 Redis 实现。
var _ authoauth2.Store = (*store)(nil)

// SaveAuthorizationCode stores a new code atomically. | SaveAuthorizationCode 原子保存新授权码。
func (s *store) SaveAuthorizationCode(ctx context.Context, code *authoauth2.AuthorizationCode) error {
	if code == nil || code.CodeHash == "" {
		return errs.Detail(authoauth2.ErrInvalidRequest, "authorization code is empty | 授权码为空")
	}
	data, err := encodeCode(code)
	if err != nil {
		return err
	}
	hasExp, expSec, expNsec := expiryFields(code.ExpiresAt)
	status, err := s.runInt(ctx, scriptCodeSave, "save authorization code",
		[]string{s.keys.code(code.CodeHash), s.keys.codesAll()},
		string(data), hasExp, expSec, expNsec, flag(code.Used))
	if err != nil {
		return err
	}
	if status == 1 {
		return errs.Detail(authoauth2.ErrServerError, "authorization code hash collision | 授权码哈希碰撞")
	}
	return nil
}

// ConsumeAuthorizationCode atomically consumes a code. | ConsumeAuthorizationCode 原子消费授权码。
func (s *store) ConsumeAuthorizationCode(ctx context.Context, codeHash string, now time.Time) (*authoauth2.AuthorizationCode, error) {
	nowSec, nowNsec := clockFields(now)
	values, err := s.runStrings(ctx, scriptCodeConsume, "consume authorization code",
		[]string{s.keys.code(codeHash)}, nowSec, nowNsec)
	if err != nil {
		return nil, err
	}
	if len(values) < 2 {
		return nil, errs.Detail(authoauth2.ErrServerError, "redis reply is truncated | Redis 应答被截断")
	}
	switch values[0] {
	case "0":
		return decodeCode([]byte(values[1]), true)
	case "-1":
		return nil, errs.Detail(authoauth2.ErrInvalidGrant, "unknown authorization code | 未知授权码")
	case "-2":
		return nil, errs.Detail(authoauth2.ErrInvalidGrant, "authorization code already used | 授权码已被使用")
	case "-3":
		return nil, errs.Detail(authoauth2.ErrInvalidGrant, "authorization code expired | 授权码已过期")
	default:
		return nil, errs.Detail(authoauth2.ErrServerError, "redis reply carries an unknown status | Redis 应答携带未知状态")
	}
}

// SaveRefreshToken stores a new refresh token atomically. | SaveRefreshToken 原子保存新刷新令牌。
func (s *store) SaveRefreshToken(ctx context.Context, token *authoauth2.RefreshToken) error {
	if token == nil || token.TokenHash == "" {
		return errs.Detail(authoauth2.ErrInvalidRequest, "refresh token is empty | 刷新令牌为空")
	}
	data, err := encodeRefresh(token)
	if err != nil {
		return err
	}
	hasExp, expSec, expNsec := expiryFields(token.ExpiresAt)
	status, err := s.runInt(ctx, scriptRefreshSave, "save refresh token",
		[]string{
			s.keys.refreshToken(token.TokenHash),
			s.keys.refreshAll(),
			s.keys.refreshFamily(token.FamilyID),
			s.keys.refreshSubject(token.ClientID, token.Subject),
		},
		string(data), flag(token.Used), flag(token.Revoked), hasExp, expSec, expNsec)
	if err != nil {
		return err
	}
	if status == 1 {
		return errs.Detail(authoauth2.ErrServerError, "refresh token hash collision | 刷新令牌哈希碰撞")
	}
	return nil
}

// GetRefreshToken returns a refresh token without changing its state. | GetRefreshToken 返回刷新令牌但不改变状态。
func (s *store) GetRefreshToken(ctx context.Context, tokenHash string) (*authoauth2.RefreshToken, error) {
	fields, err := s.hashFields(ctx, s.keys.refreshToken(tokenHash), "get refresh token")
	if err != nil {
		return nil, err
	}
	if len(fields) == 0 {
		return nil, errs.Detail(authoauth2.ErrInvalidGrant, "unknown refresh token | 未知刷新令牌")
	}
	return refreshFromFields(fields)
}

// refreshFromFields decodes one refresh-token hash. | refreshFromFields 解码单个刷新令牌哈希。
func refreshFromFields(fields map[string]string) (*authoauth2.RefreshToken, error) {
	return decodeRefresh([]byte(fields[fieldData]), fields[fieldUsed] == "1", fields[fieldRevoked] == "1")
}

// RotateRefreshToken atomically consumes oldHash and stores replacement. | RotateRefreshToken 原子消费
// oldHash 并保存 replacement。
func (s *store) RotateRefreshToken(ctx context.Context, oldHash string, replacement *authoauth2.RefreshToken, now time.Time) (bool, error) {
	if replacement == nil || replacement.TokenHash == "" {
		return false, errs.Detail(authoauth2.ErrInvalidRequest, "replacement refresh token is empty | 替换刷新令牌为空")
	}
	data, err := encodeRefresh(replacement)
	if err != nil {
		return false, err
	}
	nowSec, nowNsec := clockFields(now)
	hasExp, expSec, expNsec := expiryFields(replacement.ExpiresAt)
	status, err := s.runInt(ctx, scriptRefreshRotate, "rotate refresh token",
		[]string{
			s.keys.refreshToken(oldHash),
			s.keys.refreshToken(replacement.TokenHash),
			s.keys.refreshAll(),
			s.keys.refreshFamily(replacement.FamilyID),
			s.keys.refreshSubject(replacement.ClientID, replacement.Subject),
		},
		nowSec, nowNsec, string(data), flag(replacement.Used), flag(replacement.Revoked),
		hasExp, expSec, expNsec)
	if err != nil {
		return false, err
	}
	switch status {
	case 0:
		return true, nil
	case 1:
		return false, nil
	case 2:
		return false, errs.Detail(authoauth2.ErrServerError, "refresh token hash collision | 刷新令牌哈希碰撞")
	default:
		return false, errs.Detail(authoauth2.ErrServerError, "redis reply carries an unknown status | Redis 应答携带未知状态")
	}
}

// RevokeRefreshToken revokes one token or its whole family. | RevokeRefreshToken 撤销单个令牌或其整个家族。
func (s *store) RevokeRefreshToken(ctx context.Context, tokenHash string, revokeFamily bool) error {
	status, err := s.runInt(ctx, scriptRefreshRevoke, "revoke refresh token",
		[]string{s.keys.refreshToken(tokenHash)}, flag(revokeFamily))
	if err != nil {
		return err
	}
	if status == 1 {
		return errs.Detail(authoauth2.ErrInvalidGrant, "unknown refresh token | 未知刷新令牌")
	}
	return nil
}

// RevokeRefreshTokensForSubject revokes every refresh token of a client and subject.
// | RevokeRefreshTokensForSubject 撤销客户端与主体的全部刷新令牌。
func (s *store) RevokeRefreshTokensForSubject(ctx context.Context, clientID, subject string) (int, error) {
	count, err := s.runInt(ctx, scriptRefreshRevokeSubject, "revoke refresh tokens for subject",
		[]string{s.keys.refreshSubject(clientID, subject)})
	if err != nil {
		return 0, err
	}
	return int(count), nil
}

// SaveAccessToken stores an opaque access token atomically. | SaveAccessToken 原子保存不透明访问令牌。
func (s *store) SaveAccessToken(ctx context.Context, token *authoauth2.AccessToken) error {
	if token == nil || token.TokenHash == "" {
		return errs.Detail(authoauth2.ErrInvalidRequest, "access token is empty | 访问令牌为空")
	}
	data, err := encodeAccess(token)
	if err != nil {
		return err
	}
	hasExp, expSec, expNsec := expiryFields(token.ExpiresAt)
	status, err := s.runInt(ctx, scriptAccessSave, "save access token",
		[]string{s.keys.accessToken(token.TokenHash), s.keys.accessAll()},
		string(data), flag(token.Revoked), hasExp, expSec, expNsec)
	if err != nil {
		return err
	}
	if status == 1 {
		return errs.Detail(authoauth2.ErrServerError, "access token hash collision | 访问令牌哈希碰撞")
	}
	return nil
}

// GetAccessToken returns an access token without changing its state. | GetAccessToken 返回访问令牌但不改变状态。
func (s *store) GetAccessToken(ctx context.Context, tokenHash string) (*authoauth2.AccessToken, error) {
	fields, err := s.hashFields(ctx, s.keys.accessToken(tokenHash), "get access token")
	if err != nil {
		return nil, err
	}
	if len(fields) == 0 {
		return nil, errs.Detail(authoauth2.ErrInvalidGrant, "unknown access token | 未知访问令牌")
	}
	return decodeAccess([]byte(fields[fieldData]), fields[fieldRevoked] == "1")
}

// RevokeAccessToken revokes one access token. | RevokeAccessToken 撤销单个访问令牌。
func (s *store) RevokeAccessToken(ctx context.Context, tokenHash string) error {
	status, err := s.runInt(ctx, scriptAccessRevoke, "revoke access token",
		[]string{s.keys.accessToken(tokenHash)})
	if err != nil {
		return err
	}
	if status == 1 {
		return errs.Detail(authoauth2.ErrInvalidGrant, "unknown access token | 未知访问令牌")
	}
	return nil
}

// SaveDeviceCode stores a device authorization grant atomically. | SaveDeviceCode 原子保存设备授权许可。
func (s *store) SaveDeviceCode(ctx context.Context, code *authoauth2.DeviceCode) error {
	if code == nil || code.DeviceCodeHash == "" || code.UserCode == "" {
		return errs.Detail(authoauth2.ErrInvalidRequest, "device code is empty | 设备码为空")
	}
	indexKey := s.keys.deviceUser(code.UserCode)
	pairs, err := devicePairs(code, indexKey, true)
	if err != nil {
		return err
	}
	status, err := s.runInt(ctx, scriptDeviceSave, "save device code",
		[]string{s.keys.device(code.DeviceCodeHash), s.keys.devicesAll(), indexKey}, pairs...)
	if err != nil {
		return err
	}
	switch status {
	case 0:
		return nil
	case 1:
		return errs.Detail(authoauth2.ErrServerError, "device code hash collision | 设备码哈希碰撞")
	case 2:
		return errs.Detail(authoauth2.ErrServerError, "user code collision | 用户码碰撞")
	default:
		return errs.Detail(authoauth2.ErrServerError, "redis reply carries an unknown status | Redis 应答携带未知状态")
	}
}

// GetDeviceCodeByUserCode returns a grant by its short user code. | GetDeviceCodeByUserCode 按短用户码返回许可。
func (s *store) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*authoauth2.DeviceCode, error) {
	values, err := s.runStrings(ctx, scriptDeviceByUser, "get device code by user code",
		[]string{s.keys.deviceUser(userCode)})
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, errs.Detail(authoauth2.ErrInvalidGrant, "unknown user code | 未知用户码")
	}
	fields, err := pairsToFields(values)
	if err != nil {
		return nil, err
	}
	return deviceFromFields(fields)
}

// GetDeviceCode returns a grant by device-code hash. | GetDeviceCode 按设备码哈希返回许可。
func (s *store) GetDeviceCode(ctx context.Context, deviceCodeHash string) (*authoauth2.DeviceCode, error) {
	fields, err := s.hashFields(ctx, s.keys.device(deviceCodeHash), "get device code")
	if err != nil {
		return nil, err
	}
	if len(fields) == 0 {
		return nil, errs.Detail(authoauth2.ErrInvalidGrant, "unknown device code | 未知设备码")
	}
	return deviceFromFields(fields)
}

// UpdateDeviceCode replaces a grant while preserving its original user-code index.
// | UpdateDeviceCode 替换许可并保留原始用户码索引。
func (s *store) UpdateDeviceCode(ctx context.Context, code *authoauth2.DeviceCode) error {
	if code == nil || code.DeviceCodeHash == "" {
		return errs.Detail(authoauth2.ErrInvalidRequest, "device code is empty | 设备码为空")
	}
	pairs, err := devicePairs(code, "", false)
	if err != nil {
		return err
	}
	status, err := s.runInt(ctx, scriptDeviceUpdate, "update device code",
		[]string{s.keys.device(code.DeviceCodeHash)}, pairs...)
	if err != nil {
		return err
	}
	if status == 1 {
		return errs.Detail(authoauth2.ErrInvalidGrant, "unknown device code | 未知设备码")
	}
	return nil
}

// PollDeviceCode atomically applies RFC 8628 token-endpoint polling. | PollDeviceCode 原子应用 RFC 8628
// 令牌端点轮询。
func (s *store) PollDeviceCode(ctx context.Context, deviceCodeHash, clientID string, now time.Time) (*authoauth2.DeviceCode, bool, error) {
	nowSec, nowNsec := clockFields(now)
	values, err := s.runStrings(ctx, scriptDevicePoll, "poll device code",
		[]string{s.keys.device(deviceCodeHash)}, clientID, nowSec, nowNsec)
	if err != nil {
		return nil, false, err
	}
	if len(values) == 0 {
		return nil, false, errs.Detail(authoauth2.ErrServerError, "redis reply is truncated | Redis 应答被截断")
	}
	switch values[0] {
	case "-1":
		return nil, false, errs.Detail(authoauth2.ErrInvalidGrant, "unknown device code | 未知设备码")
	case "-2":
		return nil, false, errs.Detail(authoauth2.ErrInvalidGrant, "device code belongs to another client | 设备码属于其他客户端")
	case "0":
	default:
		return nil, false, errs.Detail(authoauth2.ErrServerError, "redis reply carries an unknown status | Redis 应答携带未知状态")
	}
	if len(values) < 3 {
		return nil, false, errs.Detail(authoauth2.ErrServerError, "redis reply is truncated | Redis 应答被截断")
	}
	fields, err := pairsToFields(values[3:])
	if err != nil {
		return nil, false, err
	}
	code, err := deviceFromFields(fields)
	if err != nil {
		return nil, false, err
	}
	code.Status = values[1]
	return code, values[2] == "1", nil
}

// SetDeviceCodeStatus atomically approves or denies a pending grant. | SetDeviceCodeStatus 原子批准或拒绝
// 等待中的许可。
func (s *store) SetDeviceCodeStatus(ctx context.Context, userCode, status string, now time.Time, principal *auth.Principal) (*authoauth2.DeviceCode, error) {
	if status != authoauth2.DeviceApproved && status != authoauth2.DeviceDenied {
		return nil, errs.Detail(authoauth2.ErrInvalidRequest, "unsupported device status | 不支持的设备状态")
	}
	if status == authoauth2.DeviceApproved && principal == nil {
		return nil, authoauth2.ErrAccessDenied
	}
	subject, dpopJKT := "", ""
	recordDPoP := false
	principalJSON := ""
	if principal != nil {
		subject = principal.Subject
		if principal.Attributes != nil {
			dpopJKT = principal.Attributes["dpop_jkt"]
			recordDPoP = true
		}
		encoded, err := encodePrincipal(principal)
		if err != nil {
			return nil, err
		}
		principalJSON = encoded
	}
	nowSec, nowNsec := clockFields(now)
	values, err := s.runStrings(ctx, scriptDeviceSetStatus, "set device code status",
		[]string{s.keys.deviceUser(userCode)}, status, nowSec, nowNsec, subject, principalJSON, dpopJKT, flag(recordDPoP))
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, errs.Detail(authoauth2.ErrServerError, "redis reply is truncated | Redis 应答被截断")
	}
	switch values[0] {
	case "-1":
		return nil, errs.Detail(authoauth2.ErrInvalidGrant, "unknown user code | 未知用户码")
	case "-2":
		return nil, errs.Detail(authoauth2.ErrInvalidGrant, "device code expired | 设备码已过期")
	case "-3":
		return nil, errs.Detail(authoauth2.ErrInvalidGrant, "device code is not pending | 设备码不在等待状态")
	case "0":
	default:
		return nil, errs.Detail(authoauth2.ErrServerError, "redis reply carries an unknown status | Redis 应答携带未知状态")
	}
	fields, err := pairsToFields(values[1:])
	if err != nil {
		return nil, err
	}
	return deviceFromFields(fields)
}

// SavePAR stores a pushed authorization request atomically. | SavePAR 原子保存推送授权请求。
func (s *store) SavePAR(ctx context.Context, request *authoauth2.PARRequest) error {
	if request == nil || request.RequestURI == "" {
		return errs.Detail(authoauth2.ErrInvalidRequest, "pushed authorization request is empty | 推送授权请求为空")
	}
	data, err := encodePAR(request)
	if err != nil {
		return err
	}
	hasExp, expSec, expNsec := expiryFields(request.ExpiresAt)
	status, err := s.runInt(ctx, scriptPARSave, "save pushed authorization request",
		[]string{s.keys.par(request.RequestURI), s.keys.parAll()},
		string(data), hasExp, expSec, expNsec, flag(request.Used))
	if err != nil {
		return err
	}
	if status == 1 {
		return errs.Detail(authoauth2.ErrServerError, "request URI collision | 请求 URI 碰撞")
	}
	return nil
}

// ConsumePAR atomically consumes a pushed authorization request. | ConsumePAR 原子消费推送授权请求。
func (s *store) ConsumePAR(ctx context.Context, requestURI string, now time.Time) (*authoauth2.PARRequest, error) {
	nowSec, nowNsec := clockFields(now)
	values, err := s.runStrings(ctx, scriptPARConsume, "consume pushed authorization request",
		[]string{s.keys.par(requestURI)}, nowSec, nowNsec)
	if err != nil {
		return nil, err
	}
	if len(values) < 2 {
		return nil, errs.Detail(authoauth2.ErrServerError, "redis reply is truncated | Redis 应答被截断")
	}
	switch values[0] {
	case "0":
		return decodePAR([]byte(values[1]), true)
	case "-1":
		return nil, errs.Detail(authoauth2.ErrInvalidRequest, "unknown or used request_uri | 未知或已用的 request_uri")
	case "-2":
		return nil, errs.Detail(authoauth2.ErrInvalidRequest, "request_uri expired | request_uri 已过期")
	default:
		return nil, errs.Detail(authoauth2.ErrServerError, "redis reply carries an unknown status | Redis 应答携带未知状态")
	}
}

// Cleanup removes expired records from every index. | Cleanup 从每个索引删除过期记录。
func (s *store) Cleanup(ctx context.Context, now time.Time) error {
	nowSec, nowNsec := clockFields(now)
	steps := []struct {
		op     string
		script *goredis.Script
		key    string
	}{
		{"cleanup authorization codes", scriptCleanupExpiring, s.keys.codesAll()},
		{"cleanup refresh tokens", scriptCleanupRefresh, s.keys.refreshAll()},
		{"cleanup access tokens", scriptCleanupExpiring, s.keys.accessAll()},
		{"cleanup device codes", scriptCleanupDevices, s.keys.devicesAll()},
		{"cleanup pushed authorization requests", scriptCleanupExpiring, s.keys.parAll()},
	}
	for _, step := range steps {
		if _, err := s.runInt(ctx, step.script, step.op, []string{step.key}, nowSec, nowNsec); err != nil {
			return err
		}
	}
	return nil
}
