package oauth2

import (
	"context"
	"sync"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
)

// deviceSlowDownIncrement is the RFC 8628 interval increase after a too-frequent poll. | deviceSlowDownIncrement
// 是 RFC 8628 规定的轮询过快后间隔增量。
const deviceSlowDownIncrement = 5 * time.Second

// MemoryStore is a concurrency-safe in-memory Store. | MemoryStore 是并发安全的内存 Store。
//
// It is intended for tests and single-process deployments. Multi-process deployments need a shared
// store so token rotation, revocation and replay detection stay consistent across nodes. | 它用于测试
// 与单进程部署。多进程部署需要共享存储，才能让令牌轮换、撤销与重放检测跨节点一致。
type MemoryStore struct {
	// mu guards every map below. | mu 保护下面的每个映射。
	mu sync.RWMutex
	// codes indexes authorization codes by hash. | codes 按哈希索引授权码。
	codes map[string]*AuthorizationCode
	// refresh indexes refresh tokens by hash. | refresh 按哈希索引刷新令牌。
	refresh map[string]*RefreshToken
	// access indexes opaque access tokens by hash. | access 按哈希索引不透明访问令牌。
	access map[string]*AccessToken
	// devices indexes device codes by hash. | devices 按哈希索引设备码。
	devices map[string]*DeviceCode
	// userCodes maps a short user code to its device-code hash. | userCodes 把短用户码映射到设备码哈希。
	userCodes map[string]string
	// pars indexes pushed authorization requests by request URI. | pars 按请求 URI 索引推送授权请求。
	pars map[string]*PARRequest
}

// NewMemoryStore returns an empty in-memory OAuth store. | NewMemoryStore 返回空的内存 OAuth 存储。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		codes:     make(map[string]*AuthorizationCode),
		refresh:   make(map[string]*RefreshToken),
		access:    make(map[string]*AccessToken),
		devices:   make(map[string]*DeviceCode),
		userCodes: make(map[string]string),
		pars:      make(map[string]*PARRequest),
	}
}

// SaveAuthorizationCode stores a new code. | SaveAuthorizationCode 保存新授权码。
func (s *MemoryStore) SaveAuthorizationCode(_ context.Context, code *AuthorizationCode) error {
	if code == nil || code.CodeHash == "" {
		return errs.Detail(ErrInvalidRequest, "authorization code is empty | 授权码为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.codes[code.CodeHash]; exists {
		return errs.Detail(ErrServerError, "authorization code hash collision | 授权码哈希碰撞")
	}
	s.codes[code.CodeHash] = code.Clone()
	return nil
}

// ConsumeAuthorizationCode atomically consumes a code. | ConsumeAuthorizationCode 原子消费授权码。
func (s *MemoryStore) ConsumeAuthorizationCode(_ context.Context, codeHash string, now time.Time) (*AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	code, ok := s.codes[codeHash]
	if !ok {
		return nil, errs.Detail(ErrInvalidGrant, "unknown authorization code | 未知授权码")
	}
	if code.Used {
		return nil, errs.Detail(ErrInvalidGrant, "authorization code already used | 授权码已被使用")
	}
	if !code.ExpiresAt.IsZero() && !now.Before(code.ExpiresAt) {
		return nil, errs.Detail(ErrInvalidGrant, "authorization code expired | 授权码已过期")
	}
	code.Used = true
	return code.Clone(), nil
}

// SaveRefreshToken stores a new refresh token. | SaveRefreshToken 保存新刷新令牌。
func (s *MemoryStore) SaveRefreshToken(_ context.Context, token *RefreshToken) error {
	if token == nil || token.TokenHash == "" {
		return errs.Detail(ErrInvalidRequest, "refresh token is empty | 刷新令牌为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.refresh[token.TokenHash]; exists {
		return errs.Detail(ErrServerError, "refresh token hash collision | 刷新令牌哈希碰撞")
	}
	s.refresh[token.TokenHash] = token.Clone()
	return nil
}

// GetRefreshToken returns a refresh token without changing its state. | GetRefreshToken 返回刷新令牌但不改变状态。
func (s *MemoryStore) GetRefreshToken(_ context.Context, tokenHash string) (*RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	token, ok := s.refresh[tokenHash]
	if !ok {
		return nil, errs.Detail(ErrInvalidGrant, "unknown refresh token | 未知刷新令牌")
	}
	return token.Clone(), nil
}

// RotateRefreshToken atomically consumes oldHash and stores replacement. | RotateRefreshToken 原子消费 oldHash 并保存 replacement。
func (s *MemoryStore) RotateRefreshToken(_ context.Context, oldHash string, replacement *RefreshToken, now time.Time) (bool, error) {
	if replacement == nil || replacement.TokenHash == "" {
		return false, errs.Detail(ErrInvalidRequest, "replacement refresh token is empty | 替换刷新令牌为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.refresh[oldHash]
	if !ok || old.Used || old.Revoked || (!old.ExpiresAt.IsZero() && !now.Before(old.ExpiresAt)) {
		return false, nil
	}
	if _, exists := s.refresh[replacement.TokenHash]; exists {
		return false, errs.Detail(ErrServerError, "refresh token hash collision | 刷新令牌哈希碰撞")
	}
	old.Used = true
	s.refresh[replacement.TokenHash] = replacement.Clone()
	return true, nil
}

// RevokeRefreshToken revokes one token or its whole family. | RevokeRefreshToken 撤销单个令牌或其整个家族。
func (s *MemoryStore) RevokeRefreshToken(_ context.Context, tokenHash string, revokeFamily bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.refresh[tokenHash]
	if !ok {
		return errs.Detail(ErrInvalidGrant, "unknown refresh token | 未知刷新令牌")
	}
	if !revokeFamily {
		token.Revoked = true
		return nil
	}
	family := token.FamilyID
	for _, candidate := range s.refresh {
		if candidate.FamilyID == family {
			candidate.Revoked = true
		}
	}
	return nil
}

// RevokeRefreshTokensForSubject revokes every token of a client and subject. | RevokeRefreshTokensForSubject 撤销客户端与主体的全部令牌。
func (s *MemoryStore) RevokeRefreshTokensForSubject(_ context.Context, clientID, subject string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, token := range s.refresh {
		if token.ClientID == clientID && token.Subject == subject && !token.Revoked {
			token.Revoked = true
			n++
		}
	}
	return n, nil
}

// SaveAccessToken stores an opaque access token. | SaveAccessToken 保存不透明访问令牌。
func (s *MemoryStore) SaveAccessToken(_ context.Context, token *AccessToken) error {
	if token == nil || token.TokenHash == "" {
		return errs.Detail(ErrInvalidRequest, "access token is empty | 访问令牌为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.access[token.TokenHash]; exists {
		return errs.Detail(ErrServerError, "access token hash collision | 访问令牌哈希碰撞")
	}
	s.access[token.TokenHash] = token.Clone()
	return nil
}

// GetAccessToken returns an access token without changing its state. | GetAccessToken 返回访问令牌但不改变状态。
func (s *MemoryStore) GetAccessToken(_ context.Context, tokenHash string) (*AccessToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	token, ok := s.access[tokenHash]
	if !ok {
		return nil, errs.Detail(ErrInvalidGrant, "unknown access token | 未知访问令牌")
	}
	return token.Clone(), nil
}

// RevokeAccessToken revokes an access token. | RevokeAccessToken 撤销访问令牌。
func (s *MemoryStore) RevokeAccessToken(_ context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.access[tokenHash]
	if !ok {
		return errs.Detail(ErrInvalidGrant, "unknown access token | 未知访问令牌")
	}
	token.Revoked = true
	return nil
}

// SaveDeviceCode stores a device authorization grant. | SaveDeviceCode 保存设备授权许可。
func (s *MemoryStore) SaveDeviceCode(_ context.Context, code *DeviceCode) error {
	if code == nil || code.DeviceCodeHash == "" || code.UserCode == "" {
		return errs.Detail(ErrInvalidRequest, "device code is empty | 设备码为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.devices[code.DeviceCodeHash]; exists {
		return errs.Detail(ErrServerError, "device code hash collision | 设备码哈希碰撞")
	}
	if _, exists := s.userCodes[code.UserCode]; exists {
		return errs.Detail(ErrServerError, "user code collision | 用户码碰撞")
	}
	s.devices[code.DeviceCodeHash] = code.Clone()
	s.userCodes[code.UserCode] = code.DeviceCodeHash
	return nil
}

// GetDeviceCodeByUserCode returns a grant by its short user code. | GetDeviceCodeByUserCode 按短用户码返回许可。
func (s *MemoryStore) GetDeviceCodeByUserCode(_ context.Context, userCode string) (*DeviceCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hash, ok := s.userCodes[userCode]
	if !ok {
		return nil, errs.Detail(ErrInvalidGrant, "unknown user code | 未知用户码")
	}
	return s.devices[hash].Clone(), nil
}

// GetDeviceCode returns a grant by device-code hash. | GetDeviceCode 按设备码哈希返回许可。
func (s *MemoryStore) GetDeviceCode(_ context.Context, deviceCodeHash string) (*DeviceCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	code, ok := s.devices[deviceCodeHash]
	if !ok {
		return nil, errs.Detail(ErrInvalidGrant, "unknown device code | 未知设备码")
	}
	return code.Clone(), nil
}

// UpdateDeviceCode replaces a grant. | UpdateDeviceCode 替换许可。
func (s *MemoryStore) UpdateDeviceCode(_ context.Context, code *DeviceCode) error {
	if code == nil || code.DeviceCodeHash == "" {
		return errs.Detail(ErrInvalidRequest, "device code is empty | 设备码为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.devices[code.DeviceCodeHash]; !ok {
		return errs.Detail(ErrInvalidGrant, "unknown device code | 未知设备码")
	}
	s.devices[code.DeviceCodeHash] = code.Clone()
	return nil
}

// PollDeviceCode atomically applies token-endpoint polling. | PollDeviceCode 原子应用令牌端点轮询。
func (s *MemoryStore) PollDeviceCode(_ context.Context, deviceCodeHash, clientID string, now time.Time) (*DeviceCode, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	code, ok := s.devices[deviceCodeHash]
	if !ok {
		return nil, false, errs.Detail(ErrInvalidGrant, "unknown device code | 未知设备码")
	}
	if code.ClientID != clientID {
		return nil, false, errs.Detail(ErrInvalidGrant, "device code belongs to another client | 设备码属于其他客户端")
	}
	if !code.ExpiresAt.IsZero() && !now.Before(code.ExpiresAt) {
		code.Status = DeviceExpired
		return code.Clone(), false, nil
	}
	switch code.Status {
	case DevicePending:
		interval := code.Interval
		if interval <= 0 {
			interval = deviceSlowDownIncrement
		}
		if !code.LastPolledAt.IsZero() && now.Sub(code.LastPolledAt) < interval {
			// RFC 8628 section 3.5: every subsequent poll must back off by five seconds. | RFC 8628
			// 第 3.5 节：之后每次轮询都必须后退 5 秒。
			code.Interval = interval + deviceSlowDownIncrement
			return code.Clone(), false, nil
		}
		code.LastPolledAt = now
		return code.Clone(), true, nil
	case DeviceApproved:
		// Return the pre-transition state so the caller can issue tokens exactly once. | 返回转换前
		// 状态，使调用方恰好签发一次令牌。
		approved := code.Clone()
		code.Status = DeviceUsed
		return approved, true, nil
	default:
		return code.Clone(), true, nil
	}
}

// SetDeviceCodeStatus atomically approves or denies a pending grant. | SetDeviceCodeStatus 原子批准或拒绝等待中的许可。
func (s *MemoryStore) SetDeviceCodeStatus(_ context.Context, userCode, status string, now time.Time, principal *auth.Principal) (*DeviceCode, error) {
	if status != DeviceApproved && status != DeviceDenied {
		return nil, errs.Detail(ErrInvalidRequest, "unsupported device status | 不支持的设备状态")
	}
	if status == DeviceApproved && principal == nil {
		return nil, ErrAccessDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hash, ok := s.userCodes[userCode]
	if !ok {
		return nil, errs.Detail(ErrInvalidGrant, "unknown user code | 未知用户码")
	}
	code := s.devices[hash]
	if !code.ExpiresAt.IsZero() && !now.Before(code.ExpiresAt) {
		code.Status = DeviceExpired
		return nil, errs.Detail(ErrInvalidGrant, "device code expired | 设备码已过期")
	}
	if code.Status != DevicePending {
		return nil, errs.Detail(ErrInvalidGrant, "device code is not pending | 设备码不在等待状态")
	}
	code.Status = status
	if status == DeviceApproved {
		code.UserID = principal.Subject
		code.Subject = principal.Subject
		code.Principal = principal.Clone()
		if principal.Attributes != nil {
			code.DPoPJKT = principal.Attributes["dpop_jkt"]
		}
	}
	return code.Clone(), nil
}

// SavePAR stores a pushed authorization request. | SavePAR 保存推送授权请求。
func (s *MemoryStore) SavePAR(_ context.Context, request *PARRequest) error {
	if request == nil || request.RequestURI == "" {
		return errs.Detail(ErrInvalidRequest, "pushed authorization request is empty | 推送授权请求为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.pars[request.RequestURI]; exists {
		return errs.Detail(ErrServerError, "request URI collision | 请求 URI 碰撞")
	}
	s.pars[request.RequestURI] = request.Clone()
	return nil
}

// ConsumePAR atomically consumes a pushed authorization request. | ConsumePAR 原子消费推送授权请求。
func (s *MemoryStore) ConsumePAR(_ context.Context, requestURI string, now time.Time) (*PARRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	request, ok := s.pars[requestURI]
	if !ok || request.Used {
		return nil, errs.Detail(ErrInvalidRequest, "unknown or used request_uri | 未知或已用的 request_uri")
	}
	if !request.ExpiresAt.IsZero() && !now.Before(request.ExpiresAt) {
		return nil, errs.Detail(ErrInvalidRequest, "request_uri expired | request_uri 已过期")
	}
	request.Used = true
	return request.Clone(), nil
}

// Cleanup removes expired records. | Cleanup 删除过期记录。
func (s *MemoryStore) Cleanup(_ context.Context, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, code := range s.codes {
		if !code.ExpiresAt.IsZero() && !now.Before(code.ExpiresAt) {
			delete(s.codes, hash)
		}
	}
	for hash, token := range s.refresh {
		if !token.ExpiresAt.IsZero() && !now.Before(token.ExpiresAt) {
			delete(s.refresh, hash)
		}
	}
	for hash, token := range s.access {
		if !token.ExpiresAt.IsZero() && !now.Before(token.ExpiresAt) {
			delete(s.access, hash)
		}
	}
	for hash, code := range s.devices {
		if !code.ExpiresAt.IsZero() && !now.Before(code.ExpiresAt) {
			delete(s.devices, hash)
			delete(s.userCodes, code.UserCode)
		}
	}
	for uri, request := range s.pars {
		if !request.ExpiresAt.IsZero() && !now.Before(request.ExpiresAt) {
			delete(s.pars, uri)
		}
	}
	return nil
}
