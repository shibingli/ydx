package redis

import (
	"context"
	"errors"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
)

// tokenStore implements auth.TokenStore on Redis. | tokenStore 在 Redis 上实现 auth.TokenStore。
type tokenStore struct {
	base
}

// tokenStore satisfies auth.TokenStore. | tokenStore 满足 auth.TokenStore。
var _ auth.TokenStore = (*tokenStore)(nil)

// CreateToken stores a token, replacing the record with the same purpose and hash and preserving
// the consumed state carried by token. | CreateToken 保存令牌，替换相同用途与哈希的记录，并保留
// token 携带的消费状态。
func (s *tokenStore) CreateToken(ctx context.Context, token *auth.OneTimeToken) error {
	if token == nil || token.Hash == "" || token.Purpose == "" {
		return errs.Detail(auth.ErrInvalidRequest, "token fields are empty | 令牌字段为空")
	}
	data, err := encodeToken(token)
	if err != nil {
		return err
	}
	hasExpiry, expireSec, expireNsec := expiryFields(token.ExpiresAt)
	tokenKey := s.keys.token(token.Purpose, token.Hash)
	newUserSet := s.keys.tokensByUser(token.UserID, token.Purpose)
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		oldUser, err := s.client.HGet(ctx, tokenKey, "user").Result()
		if errors.Is(err, goredis.Nil) {
			oldUser = ""
		} else if err != nil {
			return s.backend("create token", err)
		}
		code, err := s.runInt(ctx, scriptTokenCreate, "create token",
			[]string{tokenKey, newUserSet, s.keys.tokensByUser(oldUser, token.Purpose)},
			string(data), token.UserID, oldUser, tokenKey, flag(!token.UsedAt.IsZero()),
			hasExpiry, expireSec, expireNsec,
		)
		if err != nil {
			return err
		}
		switch code {
		case 0:
			return nil
		case 1:
			continue
		default:
			return errs.Detail(auth.ErrStoreUnavailable, "create token returned %d | 创建令牌返回 %d", code, code)
		}
	}
	return errs.Detail(auth.ErrConflict, "create token for purpose %[1]q is contended | 为用途 %[1]q 创建令牌存在竞争", token.Purpose)
}

// ConsumeToken atomically marks a token used and returns a deep copy.
// | ConsumeToken 原子地把令牌标记为已用并返回深拷贝。
func (s *tokenStore) ConsumeToken(ctx context.Context, hash, purpose string, now time.Time) (*auth.OneTimeToken, error) {
	nowSec, nowNsec := clockFields(now)
	reply, err := s.runSlice(ctx, scriptTokenConsume, "consume token",
		[]string{s.keys.token(purpose, hash)}, nowSec, nowNsec)
	if err != nil {
		return nil, err
	}
	if len(reply) < 2 {
		return nil, errs.Detail(auth.ErrStoreUnavailable, "consume token returned an invalid reply | 消费令牌返回无效应答")
	}
	switch stringValue(reply[0]) {
	case "-1":
		return nil, auth.ErrTokenInvalid
	case "-2":
		return nil, auth.ErrTokenUsed
	case "-3":
		return nil, auth.ErrTokenExpired
	case "0":
		token, err := decodeToken([]byte(stringValue(reply[1])))
		if err != nil {
			return nil, err
		}
		token.UsedAt = utcTime(now)
		return token, nil
	default:
		return nil, errs.Detail(auth.ErrStoreUnavailable, "consume token returned an unknown status | 消费令牌返回未知状态")
	}
}

// PeekToken returns a token without consuming it. | PeekToken 返回令牌但不消费。
func (s *tokenStore) PeekToken(ctx context.Context, hash, purpose string, now time.Time) (*auth.OneTimeToken, error) {
	values, err := s.client.HMGet(ctx, s.keys.token(purpose, hash),
		"data", "used", "hasExpiry", "expireSec", "expireNsec").Result()
	if err != nil {
		return nil, s.backend("peek token", err)
	}
	if len(values) < 5 || allNil(values) || values[0] == nil {
		return nil, auth.ErrTokenInvalid
	}
	if stringValue(values[1]) == "1" {
		return nil, auth.ErrTokenUsed
	}
	if stringValue(values[2]) == "1" {
		expireSec, secErr := parseInt(stringValue(values[3]))
		expireNsec, nsecErr := parseInt(stringValue(values[4]))
		if secErr != nil || nsecErr != nil {
			return nil, errs.Detail(auth.ErrStoreUnavailable, "stored token expiry is corrupt | 存储的令牌期限损坏")
		}
		if expired(true, expireSec, expireNsec, now) {
			return nil, auth.ErrTokenExpired
		}
	}
	return decodeToken([]byte(stringValue(values[0])))
}

// DeleteTokensByUser removes every token of a user and purpose and returns the number removed.
// | DeleteTokensByUser 删除用户某用途的全部令牌并返回删除数量。
func (s *tokenStore) DeleteTokensByUser(ctx context.Context, userID, purpose string) (int, error) {
	count, err := s.runInt(ctx, scriptTokensDeleteByUser, "delete tokens by user",
		[]string{s.keys.tokensByUser(userID, purpose)})
	if err != nil {
		return 0, err
	}
	return int(count), nil
}
