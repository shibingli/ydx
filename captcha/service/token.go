package service

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"time"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// tokenVersion is the wire version prefix of verification tokens. | tokenVersion 是验证令牌的线上版本前缀。
const tokenVersion = "v1"

// tokenParts is the number of dot-separated token segments. | tokenParts 是令牌的点分隔段数。
const tokenParts = 4

// ephemeralKeyID is the key identifier used when no secret is configured. | ephemeralKeyID 是未配置密钥时使用的 key 标识。
const ephemeralKeyID = "ephemeral"

// tokenSigner issues and verifies HMAC-SHA256 verification tokens. | tokenSigner 签发并验证 HMAC-SHA256 验证令牌。
type tokenSigner struct {
	store     Store
	now       func() time.Time
	keys      map[string][]byte
	keyID     string
	issuer    string
	ttl       time.Duration
	oneTime   bool
	ephemeral bool
}

// newTokenSigner normalizes signing options. | newTokenSigner 归一化签名选项。
func newTokenSigner(o Options, store Store, now func() time.Time) (*tokenSigner, error) {
	keys := make(map[string][]byte, len(o.Keys)+1)
	keyID := strings.TrimSpace(o.KeyID)
	if keyID == "" {
		keyID = "k1"
	}
	if !validTokenKeyID(keyID) {
		return nil, errs.Detail(ErrInvalidOptions, "key id must be visible ASCII without dots or spaces | key 标识必须是可见 ASCII 且不含点或空格")
	}
	for id, key := range o.Keys {
		if !validTokenKeyID(id) {
			return nil, errs.Detail(ErrInvalidOptions, "invalid token key id %q | 非法令牌 key 标识 %q", id, id)
		}
		if len(key) < 16 {
			return nil, errs.Detail(ErrInvalidOptions, "token key %q is shorter than 16 bytes | 令牌 key %q 短于 16 字节", id, id)
		}
		keys[id] = append([]byte(nil), key...)
	}
	secret := append([]byte(nil), o.Secret...)
	ephemeral := false
	if len(keys) == 0 {
		if len(secret) == 0 {
			secret = make([]byte, 32)
			if _, err := rand.Read(secret); err != nil {
				return nil, errs.Wrap(err, ErrInvalidOptions)
			}
			ephemeral = true
		}
		if len(secret) < 16 {
			return nil, errs.Detail(ErrInvalidOptions, "token secret is shorter than 16 bytes | 令牌密钥短于 16 字节")
		}
		keys[keyID] = secret
	} else if _, ok := keys[keyID]; !ok {
		return nil, errs.Detail(ErrInvalidOptions, "active token key %q is missing | 缺少活动令牌 key %q", keyID, keyID)
	}
	if store == nil {
		return nil, errs.Detail(ErrInvalidOptions, "nil token store | 令牌存储为 nil")
	}
	ttl := o.TokenTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &tokenSigner{
		store:     store,
		now:       now,
		keys:      keys,
		keyID:     keyID,
		issuer:    o.Issuer,
		ttl:       ttl,
		oneTime:   !o.TokenReusable,
		ephemeral: ephemeral,
	}, nil
}

// issue signs claims and persists the one-time marker when enabled. | issue 签发载荷，并在启用时保存一次性标记。
func (s *tokenSigner) issue(ctx context.Context, claims TokenClaims) (string, error) {
	now := s.now()
	if claims.IssuedAt == 0 {
		claims.IssuedAt = now.Unix()
	}
	if claims.ExpiresAt == 0 {
		claims.ExpiresAt = now.Add(s.ttl).Unix()
	}
	if claims.Nonce == "" {
		nonce, err := randomID(16)
		if err != nil {
			return "", errs.Wrap(err, ErrStore)
		}
		claims.Nonce = nonce
	}
	if s.issuer != "" {
		claims.Issuer = s.issuer
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", errs.Wrap(err, ErrStore)
	}
	body := tokenVersion + "." + s.keyID + "." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, s.keys[s.keyID])
	_, _ = mac.Write([]byte(body))
	token := body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if s.oneTime {
		if err := s.store.Put(ctx, tokenKey(claims.Nonce), []byte{1}, s.ttl); err != nil {
			return "", errs.Wrap(err, ErrStore)
		}
	}
	return token, nil
}

// verify validates a token and optionally consumes its one-time marker. | verify 验证令牌，并可消费其一次性标记。
func (s *tokenSigner) verify(ctx context.Context, token, action string, consume bool) (*TokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != tokenParts || parts[0] != tokenVersion {
		return nil, ErrTokenInvalid
	}
	key, ok := s.keys[parts[1]]
	if !ok {
		return nil, ErrTokenInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil || len(signature) != sha256.Size {
		return nil, ErrTokenInvalid
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1] + "." + parts[2]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return nil, ErrTokenInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrTokenInvalid
	}
	var claims TokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errs.Wrap(err, ErrTokenInvalid)
	}
	if claims.Action != action {
		return nil, errs.Detail(ErrTokenInvalid, "action mismatch | action 不匹配")
	}
	if claims.ChallengeID == "" || claims.Nonce == "" {
		return nil, ErrTokenInvalid
	}
	if s.issuer != "" && claims.Issuer != s.issuer {
		return nil, ErrTokenInvalid
	}
	if s.now().Unix() >= claims.ExpiresAt {
		return nil, ErrTokenExpired
	}
	if consume && s.oneTime {
		_, ok, err := s.store.Take(ctx, tokenKey(claims.Nonce))
		if err != nil {
			return nil, errs.Wrap(err, ErrStore)
		}
		if !ok {
			return nil, ErrTokenUsed
		}
	}
	return &claims, nil
}

// validTokenKeyID reports whether a key identifier is header-safe. | validTokenKeyID 报告 key 标识是否适合放入头部。
func validTokenKeyID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if c <= 0x20 || c >= 0x7f || c == '.' {
			return false
		}
	}
	return true
}

// tokenKey names the one-time marker of a token. | tokenKey 命名令牌的一次性标记。
func tokenKey(nonce string) string { return "tk:" + nonce }

// randomID returns n cryptographically random bytes encoded as URL-safe Base64. | randomID 返回 n 个密码学随机字节的 URL 安全 Base64。
func randomID(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", errs.Wrap(err, ErrStore)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
