package oauth2

import (
	"context"
	"net/url"
	"time"

	"github.com/shibingli/ydx/auth"
)

// Store persists OAuth grants, tokens, device codes and pushed authorization requests. | Store 持久化
// OAuth 许可、令牌、设备码与推送授权请求。
//
// Implementations must be safe for concurrent use. Hash-keyed lookups receive the value produced by
// auth.HashToken; raw bearer values are never stored by the server. | 实现必须可并发安全使用。按哈希
// 查询的键接收 auth.HashToken 的产物；服务器从不存储原始承载值。
type Store interface {
	// SaveAuthorizationCode stores a new code. | SaveAuthorizationCode 保存新授权码。
	SaveAuthorizationCode(ctx context.Context, code *AuthorizationCode) error
	// ConsumeAuthorizationCode atomically marks a code used and returns it. | ConsumeAuthorizationCode 原子地标记授权码已用并返回。
	ConsumeAuthorizationCode(ctx context.Context, codeHash string, now time.Time) (*AuthorizationCode, error)
	// SaveRefreshToken stores a new refresh token. | SaveRefreshToken 保存新刷新令牌。
	SaveRefreshToken(ctx context.Context, token *RefreshToken) error
	// GetRefreshToken returns a token without changing its state. | GetRefreshToken 返回令牌但不改变状态。
	GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error)
	// RotateRefreshToken atomically consumes oldHash and stores replacement. | RotateRefreshToken 原子消费 oldHash 并保存 replacement。
	RotateRefreshToken(ctx context.Context, oldHash string, replacement *RefreshToken, now time.Time) (bool, error)
	// RevokeRefreshToken revokes one token or its whole family. | RevokeRefreshToken 撤销单个令牌或其整个家族。
	RevokeRefreshToken(ctx context.Context, tokenHash string, revokeFamily bool) error
	// RevokeRefreshTokensForSubject revokes every refresh token of a client and subject. | RevokeRefreshTokensForSubject 撤销客户端与主体的全部刷新令牌。
	RevokeRefreshTokensForSubject(ctx context.Context, clientID, subject string) (int, error)
	// SaveAccessToken stores an opaque access token. | SaveAccessToken 保存不透明访问令牌。
	SaveAccessToken(ctx context.Context, token *AccessToken) error
	// GetAccessToken returns an access token without changing its state. | GetAccessToken 返回访问令牌但不改变状态。
	GetAccessToken(ctx context.Context, tokenHash string) (*AccessToken, error)
	// RevokeAccessToken revokes one access token. | RevokeAccessToken 撤销单个访问令牌。
	RevokeAccessToken(ctx context.Context, tokenHash string) error
	// SaveDeviceCode stores a device authorization grant. | SaveDeviceCode 保存设备授权许可。
	SaveDeviceCode(ctx context.Context, code *DeviceCode) error
	// GetDeviceCodeByUserCode returns a grant by its short user code. | GetDeviceCodeByUserCode 按短用户码返回许可。
	GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error)
	// GetDeviceCode returns a grant by device-code hash. | GetDeviceCode 按设备码哈希返回许可。
	GetDeviceCode(ctx context.Context, deviceCodeHash string) (*DeviceCode, error)
	// UpdateDeviceCode replaces a grant. | UpdateDeviceCode 替换许可。
	UpdateDeviceCode(ctx context.Context, code *DeviceCode) error
	// PollDeviceCode atomically applies RFC 8628 token-endpoint polling for clientID.
	//
	// A pending grant updates LastPolledAt when its interval has elapsed; otherwise Interval grows
	// by five seconds and accepted is false. An approved grant becomes DeviceUsed. The grant is
	// never changed when it belongs to another client. | PollDeviceCode 为 clientID 原子应用
	// RFC 8628 令牌端点轮询。等待中的许可在间隔到达时更新 LastPolledAt，否则 Interval 增加 5 秒
	// 且 accepted 为 false。已批准的许可转为 DeviceUsed。许可不属于该客户端时绝不修改。
	PollDeviceCode(ctx context.Context, deviceCodeHash, clientID string, now time.Time) (*DeviceCode, bool, error)
	// SetDeviceCodeStatus atomically moves a pending grant to DeviceApproved or DeviceDenied.
	// principal supplies the approving subject. | SetDeviceCodeStatus 原子地把等待中的许可改为
	// DeviceApproved 或 DeviceDenied；principal 提供批准主体。
	SetDeviceCodeStatus(ctx context.Context, userCode, status string, now time.Time, principal *auth.Principal) (*DeviceCode, error)
	// SavePAR stores a pushed authorization request. | SavePAR 保存推送授权请求。
	SavePAR(ctx context.Context, request *PARRequest) error
	// ConsumePAR atomically marks a request URI used and returns it. | ConsumePAR 原子地标记请求 URI 已用并返回。
	ConsumePAR(ctx context.Context, requestURI string, now time.Time) (*PARRequest, error)
	// Cleanup removes expired records. | Cleanup 删除过期记录。
	Cleanup(ctx context.Context, now time.Time) error
}

// Clone returns a deep copy of the code. | Clone 返回授权码深拷贝。
func (c *AuthorizationCode) Clone() *AuthorizationCode {
	if c == nil {
		return nil
	}
	out := *c
	out.Scopes = append([]string(nil), c.Scopes...)
	out.AMR = append([]string(nil), c.AMR...)
	out.Resource = append([]string(nil), c.Resource...)
	out.Principal = c.Principal.Clone()
	return &out
}

// Clone returns a deep copy of the refresh token. | Clone 返回刷新令牌深拷贝。
func (t *RefreshToken) Clone() *RefreshToken {
	if t == nil {
		return nil
	}
	out := *t
	out.Scopes = append([]string(nil), t.Scopes...)
	out.Audience = append([]string(nil), t.Audience...)
	out.AMR = append([]string(nil), t.AMR...)
	out.Principal = t.Principal.Clone()
	return &out
}

// Clone returns a deep copy of the access token. | Clone 返回访问令牌深拷贝。
func (t *AccessToken) Clone() *AccessToken {
	if t == nil {
		return nil
	}
	out := *t
	out.Scopes = append([]string(nil), t.Scopes...)
	out.Audience = append([]string(nil), t.Audience...)
	out.AMR = append([]string(nil), t.AMR...)
	out.Principal = t.Principal.Clone()
	return &out
}

// Clone returns a deep copy of the device code. | Clone 返回设备码深拷贝。
func (d *DeviceCode) Clone() *DeviceCode {
	if d == nil {
		return nil
	}
	out := *d
	out.Scopes = append([]string(nil), d.Scopes...)
	out.Audience = append([]string(nil), d.Audience...)
	out.Principal = d.Principal.Clone()
	return &out
}

// Clone returns a deep copy of the pushed authorization request. | Clone 返回推送授权请求深拷贝。
func (p *PARRequest) Clone() *PARRequest {
	if p == nil {
		return nil
	}
	out := *p
	out.Params = cloneValues(p.Params)
	return &out
}

// cloneValues returns a deep copy of v. | cloneValues 返回 v 的深拷贝。
func cloneValues(v url.Values) url.Values {
	if len(v) == 0 {
		return nil
	}
	out := make(url.Values, len(v))
	for key, values := range v {
		out[key] = append([]string(nil), values...)
	}
	return out
}

// Device code states. | 设备码状态。
const (
	// DevicePending is a grant waiting for user approval. | DevicePending 是等待用户批准的许可。
	DevicePending = "pending"
	// DeviceApproved is a grant approved by the user. | DeviceApproved 是用户已批准的许可。
	DeviceApproved = "approved"
	// DeviceDenied is a grant denied by the user. | DeviceDenied 是用户已拒绝的许可。
	DeviceDenied = "denied"
	// DeviceUsed is a grant already exchanged for tokens. | DeviceUsed 是已兑换令牌的许可。
	DeviceUsed = "used"
	// DeviceExpired is a grant past its deadline. | DeviceExpired 是超过期限的许可。
	DeviceExpired = "expired"
)
