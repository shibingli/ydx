package webauthn_test

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	authwebauthn "github.com/shibingli/ydx/auth/mfa/webauthn"
	webauthnstore "github.com/shibingli/ydx/authstore/webauthn"
	"github.com/shibingli/ydx/base64"
)

// TestChallengeLifecycle covers put, consume, expiry and repeat consumption.
// | TestChallengeLifecycle 覆盖保存、消费、过期与重复消费。
func TestChallengeLifecycle(t *testing.T) {
	first, second := newPair(t)
	zone := time.FixedZone("CST", 8*60*60)
	created := time.Now().Add(time.Hour).In(zone)
	expires := created.Add(2 * time.Minute)
	ceremony := sampleCeremony(expires)
	ceremony.CreatedAt = created
	if err := first.Put(testContext, ceremony); err != nil {
		t.Fatalf("put: %v | 保存挑战失败", err)
	}
	challenge := base64.RawURLEncoding.EncodeToString(ceremony.Challenge)
	got, err := second.Consume(testContext, challenge)
	if err != nil {
		t.Fatalf("consume across instances: %v | 跨实例消费失败", err)
	}
	if got.ID != ceremony.ID || got.Kind != ceremony.Kind || got.UserID != ceremony.UserID {
		t.Fatalf("ceremony = %+v | 流程字段不一致", got)
	}
	if string(got.Challenge) != string(ceremony.Challenge) {
		t.Fatalf("challenge = %x | 挑战不一致", got.Challenge)
	}
	if string(got.UserHandle) != string(ceremony.UserHandle) || got.RPID != ceremony.RPID {
		t.Fatalf("user handle or RP ID mismatch | 用户句柄或依赖方标识不一致")
	}
	if len(got.Origins) != 2 || got.Origins[1] != ceremony.Origins[1] {
		t.Fatalf("origins = %v | 来源不一致", got.Origins)
	}
	if len(got.Algorithms) != 2 || got.Algorithms[1] != ceremony.Algorithms[1] {
		t.Fatalf("algorithms = %v | 算法不一致", got.Algorithms)
	}
	if len(got.AllowCredentialIDs) != 2 || string(got.AllowCredentialIDs[1]) != string(ceremony.AllowCredentialIDs[1]) {
		t.Fatalf("allow credential IDs = %v | 允许凭据 ID 不一致", got.AllowCredentialIDs)
	}
	if !got.CreatedAt.Equal(created) || !got.ExpiresAt.Equal(expires) {
		t.Fatalf("times = %v/%v | 时间不一致", got.CreatedAt, got.ExpiresAt)
	}
	if got.CreatedAt.Location() != time.UTC || got.ExpiresAt.Location() != time.UTC {
		t.Fatalf("times not UTC: %v/%v | 时间未规范化为 UTC", got.CreatedAt, got.ExpiresAt)
	}
	if _, err := first.Consume(testContext, challenge); !errors.Is(err, authwebauthn.ErrChallengeNotFound) {
		t.Fatalf("second consume = %v, want ErrChallengeNotFound | 二次消费未返回不存在", err)
	}
}

// TestChallengeNoExpiry verifies that a zero ExpiresAt never expires logically.
// | TestChallengeNoExpiry 验证零值 ExpiresAt 永不过期。
func TestChallengeNoExpiry(t *testing.T) {
	first, second := newPair(t)
	ceremony := sampleCeremony(time.Time{})
	if err := first.Put(testContext, ceremony); err != nil {
		t.Fatalf("put: %v | 保存挑战失败", err)
	}
	challenge := base64.RawURLEncoding.EncodeToString(ceremony.Challenge)
	if _, err := second.Consume(testContext, challenge); err != nil {
		t.Fatalf("consume: %v | 消费失败", err)
	}
	if _, err := second.Consume(testContext, challenge); !errors.Is(err, authwebauthn.ErrChallengeNotFound) {
		t.Fatalf("repeat consume = %v | 重复消费未被拒绝", err)
	}
}

// TestChallengeExpired verifies that an expired ceremony reports ErrChallengeExpired once and is
// then gone. | TestChallengeExpired 验证过期流程只报告一次 ErrChallengeExpired，随后消失。
func TestChallengeExpired(t *testing.T) {
	first, second := newPair(t)
	ceremony := sampleCeremony(time.Now().Add(-time.Minute))
	if err := first.Put(testContext, ceremony); err != nil {
		t.Fatalf("put expired: %v | 保存已过期挑战失败", err)
	}
	challenge := base64.RawURLEncoding.EncodeToString(ceremony.Challenge)
	if _, err := second.Consume(testContext, challenge); !errors.Is(err, authwebauthn.ErrChallengeExpired) {
		t.Fatalf("consume expired = %v, want ErrChallengeExpired | 过期挑战错误不符", err)
	}
	if _, err := first.Consume(testContext, challenge); !errors.Is(err, authwebauthn.ErrChallengeNotFound) {
		t.Fatalf("consume expired twice = %v, want ErrChallengeNotFound | 过期挑战未被删除", err)
	}
}

// TestChallengeValidation covers invalid ceremonies, contexts and unknown challenges.
// | TestChallengeValidation 覆盖非法流程、上下文与未知挑战。
func TestChallengeValidation(t *testing.T) {
	server := miniredis.RunT(t)
	store := newStoreOn(t, server, "")
	if err := store.Put(testContext, nil); !errors.Is(err, authwebauthn.ErrInvalidRequest) {
		t.Fatalf("nil ceremony = %v, want ErrInvalidRequest | nil 流程错误不符", err)
	}
	if err := store.Put(testContext, &authwebauthn.Ceremony{}); !errors.Is(err, authwebauthn.ErrInvalidRequest) {
		t.Fatalf("empty challenge = %v, want ErrInvalidRequest | 空挑战错误不符", err)
	}
	if _, err := store.Consume(testContext, ""); !errors.Is(err, authwebauthn.ErrChallengeNotFound) {
		t.Fatalf("empty consume = %v, want ErrChallengeNotFound | 空挑战消费错误不符", err)
	}
	if _, err := store.Consume(testContext, "unknown"); !errors.Is(err, authwebauthn.ErrChallengeNotFound) {
		t.Fatalf("unknown consume = %v, want ErrChallengeNotFound | 未知挑战错误不符", err)
	}
	var nilContext context.Context
	ceremony := sampleCeremony(time.Now().Add(time.Minute))
	if err := store.Put(nilContext, ceremony); !errors.Is(err, authwebauthn.ErrInvalidRequest) {
		t.Fatalf("nil context put = %v, want ErrInvalidRequest | nil 上下文保存错误不符", err)
	}
	if _, err := store.Consume(nilContext, ceremony.ID); !errors.Is(err, authwebauthn.ErrInvalidRequest) {
		t.Fatalf("nil context consume = %v, want ErrInvalidRequest | nil 上下文消费错误不符", err)
	}
	cancelled, cancel := context.WithCancel(testContext)
	cancel()
	if err := store.Put(cancelled, ceremony); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled put = %v, want context.Canceled | 取消上下文保存错误不符", err)
	}
	if _, err := store.Consume(cancelled, ceremony.ID); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled consume = %v, want context.Canceled | 取消上下文消费错误不符", err)
	}
}

// TestChallengeDeepCopy verifies Put serializes the ceremony and Consume returns a fresh value.
// | TestChallengeDeepCopy 验证 Put 序列化流程且 Consume 返回全新值。
func TestChallengeDeepCopy(t *testing.T) {
	first, second := newPair(t)
	ceremony := sampleCeremony(time.Now().Add(time.Minute))
	challenge := base64.RawURLEncoding.EncodeToString(ceremony.Challenge)
	wantOrigin := ceremony.Origins[0]
	wantAlgorithm := ceremony.Algorithms[0]
	wantCredential := string(ceremony.AllowCredentialIDs[0])
	if err := first.Put(testContext, ceremony); err != nil {
		t.Fatalf("put: %v | 保存挑战失败", err)
	}
	ceremony.Challenge[0] ^= 0xff
	ceremony.Origins[0] = "https://mutated.example.com"
	ceremony.Algorithms[0] = 999
	ceremony.AllowCredentialIDs[0][0] ^= 0xff
	got, err := second.Consume(testContext, challenge)
	if err != nil {
		t.Fatalf("consume: %v | 消费失败", err)
	}
	if got.Origins[0] != wantOrigin || got.Algorithms[0] != wantAlgorithm {
		t.Fatalf("stored ceremony shares caller memory: %v/%v | 存储流程共享了调用方内存", got.Origins, got.Algorithms)
	}
	if string(got.AllowCredentialIDs[0]) != wantCredential {
		t.Fatalf("stored credential ID shares caller memory | 存储的凭据 ID 共享了调用方内存")
	}
}

// TestChallengeCorruptRecord verifies that undecodable values report ErrCorruptRecord.
// | TestChallengeCorruptRecord 验证无法解码的值报告 ErrCorruptRecord。
func TestChallengeCorruptRecord(t *testing.T) {
	server := miniredis.RunT(t)
	store := newStoreOn(t, server, "")
	ceremony := sampleCeremony(time.Now().Add(time.Minute))
	challenge := base64.RawURLEncoding.EncodeToString(ceremony.Challenge)
	if err := store.Put(testContext, ceremony); err != nil {
		t.Fatalf("put: %v | 保存挑战失败", err)
	}
	key := webauthnstore.DefaultKeyPrefix + "{authstore:webauthn}:challenge:" +
		strconv.Itoa(len(challenge)) + ":" + challenge
	raw := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = raw.Close()
	})
	if err := raw.Set(testContext, key, "not-json", 0).Err(); err != nil {
		t.Fatalf("overwrite challenge: %v | 覆盖挑战失败", err)
	}
	if _, err := store.Consume(testContext, challenge); !errors.Is(err, webauthnstore.ErrCorruptRecord) {
		t.Fatalf("corrupt consume = %v, want ErrCorruptRecord | 损坏流程错误不符", err)
	}
}

// TestChallengeConcurrentConsumeExactlyOnce models many instances racing for one ceremony.
// | TestChallengeConcurrentConsumeExactlyOnce 模拟多实例争抢同一个流程。
func TestChallengeConcurrentConsumeExactlyOnce(t *testing.T) {
	first, second := newPair(t)
	ceremony := sampleCeremony(time.Now().Add(time.Minute))
	challenge := base64.RawURLEncoding.EncodeToString(ceremony.Challenge)
	if err := first.Put(testContext, ceremony); err != nil {
		t.Fatalf("put: %v | 保存挑战失败", err)
	}
	var successes atomic.Int64
	var notFound atomic.Int64
	var failures atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		store := first
		if i%2 == 1 {
			store = second
		}
		wg.Add(1)
		go func(store *webauthnstore.Store) {
			defer wg.Done()
			_, err := store.Consume(testContext, challenge)
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, authwebauthn.ErrChallengeNotFound):
				notFound.Add(1)
			default:
				failures.Add(1)
			}
		}(store)
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("consume failures = %d | 消费失败次数非零", failures.Load())
	}
	if successes.Load() != 1 {
		t.Fatalf("consume successes = %d, want 1 | 成功消费次数不为 1", successes.Load())
	}
	if notFound.Load() != 63 {
		t.Fatalf("not found = %d, want 63 | 未找到次数不为 63", notFound.Load())
	}
}
