package webauthn

import (
	"context"
	"time"

	authwebauthn "github.com/shibingli/ydx/auth/mfa/webauthn"
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
)

// Put stores a ceremony keyed by the unpadded base64url challenge. | Put 以无填充 base64url 挑战为
// 键保存流程。
//
// The ceremony is serialized, so later mutations of the caller value never change the stored copy.
// A zero ExpiresAt stores the ceremony without a Redis expiry. Otherwise the Redis key outlives the
// ceremony by a fixed retention window, which lets Consume distinguish an expired ceremony from an
// unknown one, matching the in-memory store. | 流程会被序列化，因此调用方后续修改不会改变已存副本。
// 零值 ExpiresAt 存储的流程没有 Redis 期限。否则 Redis 键会比流程多保留一个固定窗口，使 Consume
// 能区分已过期流程与未知流程，与内存存储一致。
func (s *Store) Put(ctx context.Context, ceremony *authwebauthn.Ceremony) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if ceremony == nil || len(ceremony.Challenge) == 0 {
		return errs.Detail(authwebauthn.ErrInvalidRequest, "ceremony has no challenge | 流程缺少挑战")
	}
	challenge := base64.RawURLEncoding.EncodeToString(ceremony.Challenge)
	data, err := encodeCeremony(ceremony)
	if err != nil {
		return err
	}
	var ttl time.Duration
	if !ceremony.ExpiresAt.IsZero() {
		ttl = time.Until(ceremony.ExpiresAt) + expiredChallengeRetention
		if ttl < minimumTTL {
			ttl = minimumTTL
		}
	}
	if err := s.client.Set(ctx, s.keys.challenge(challenge), data, ttl).Err(); err != nil {
		return s.backend("put challenge", err)
	}
	return nil
}

// Consume removes and returns a ceremony by challenge. | Consume 按挑战移除并返回流程。
//
// The read and delete run in one Lua script, so exactly one of several concurrent callers, in any
// application instance, can consume one ceremony. An unknown key reports
// webauthn.ErrChallengeNotFound; a consumed ceremony past ExpiresAt reports
// webauthn.ErrChallengeExpired. | 读取与删除在单个 Lua 脚本中完成，因此在任意应用实例的并发调用中，
// 只有一个调用能消费同一个流程。未知键返回 webauthn.ErrChallengeNotFound；已消费但超过 ExpiresAt
// 的流程返回 webauthn.ErrChallengeExpired。
func (s *Store) Consume(ctx context.Context, challenge string) (*authwebauthn.Ceremony, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if challenge == "" {
		return nil, errs.Detail(authwebauthn.ErrChallengeNotFound, "challenge %q | 挑战 %q",
			challenge, challenge)
	}
	reply, err := scriptConsumeChallenge.Run(ctx, s.client, []string{s.keys.challenge(challenge)}).Slice()
	if err != nil {
		return nil, s.backend("consume challenge", err)
	}
	if len(reply) < 2 || intValue(reply[0]) != 1 {
		return nil, errs.Detail(authwebauthn.ErrChallengeNotFound, "challenge %q | 挑战 %q",
			challenge, challenge)
	}
	ceremony, err := decodeCeremony([]byte(stringValue(reply[1])))
	if err != nil {
		return nil, err
	}
	if !ceremony.ExpiresAt.IsZero() && time.Now().After(ceremony.ExpiresAt) {
		expired := ceremony.ExpiresAt.UTC().Format(time.RFC3339)
		return nil, errs.Detail(authwebauthn.ErrChallengeExpired,
			"challenge %q expired at %s | 挑战 %q 于 %s 过期",
			challenge, expired, challenge, expired)
	}
	return ceremony, nil
}
