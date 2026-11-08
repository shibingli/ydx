package redis_test

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
)

// sampleToken returns one one-time token. | sampleToken 返回单个一次性令牌。
func sampleToken(hash, userID, purpose string, created time.Time) *auth.OneTimeToken {
	return &auth.OneTimeToken{
		Hash:      hash,
		UserID:    userID,
		Purpose:   purpose,
		Metadata:  map[string]string{"flow": purpose},
		CreatedAt: created,
		ExpiresAt: created.Add(time.Hour),
	}
}

// TestTokenCreateAndPeek covers creation, peeking, purpose isolation and validation.
// | TestTokenCreateAndPeek 覆盖创建、查看、用途隔离与校验。
func TestTokenCreateAndPeek(t *testing.T) {
	first, second := newPair(t)
	created := testTime(2026, time.November, 1, 0, 0, 0)
	token := sampleToken("hash-1", "u1", "reset_password", created)
	if err := first.Tokens.CreateToken(testContext, token); err != nil {
		t.Fatalf("create: %v | 创建失败", err)
	}
	got, err := second.Tokens.PeekToken(testContext, "hash-1", "reset_password", created.Add(time.Minute))
	if err != nil {
		t.Fatalf("cross-instance peek: %v | 跨实例查看失败", err)
	}
	if got.UserID != "u1" || got.Metadata["flow"] != "reset_password" || !got.UsedAt.IsZero() {
		t.Fatalf("token fields lost: %#v | 令牌字段丢失", got)
	}
	if _, err := first.Tokens.PeekToken(testContext, "hash-1", "verify_email", created); !errors.Is(err, auth.ErrTokenInvalid) {
		t.Fatalf("purpose isolation error = %v | 用途隔离错误不符", err)
	}
	if _, err := first.Tokens.PeekToken(testContext, "missing", "reset_password", created); !errors.Is(err, auth.ErrTokenInvalid) {
		t.Fatalf("missing error = %v | 不存在令牌错误不符", err)
	}
	for _, bad := range []*auth.OneTimeToken{
		nil,
		{},
		{Hash: "h"},
		{Purpose: "p"},
	} {
		if err := first.Tokens.CreateToken(testContext, bad); !errors.Is(err, auth.ErrInvalidRequest) {
			t.Fatalf("invalid token %#v error = %v | 非法令牌错误不符", bad, err)
		}
	}
	if err := first.Tokens.CreateToken(testContext, sampleToken("hash-2", "u1", "reset_password", created)); err != nil {
		t.Fatalf("second token: %v | 创建第二个令牌失败", err)
	}
}

// TestTokenConsume covers single-use semantics, exact expiry boundaries and not-found results.
// | TestTokenConsume 覆盖单次使用语义、精确过期边界与不存在结果。
func TestTokenConsume(t *testing.T) {
	stores := newStores(t, "")
	base := time.Date(2026, time.November, 2, 12, 0, 0, 123456789, time.UTC)
	token := sampleToken("hash-1", "u1", "reset_password", base)
	token.ExpiresAt = base.Add(time.Hour)
	if err := stores.Tokens.CreateToken(testContext, token); err != nil {
		t.Fatalf("create: %v | 创建失败", err)
	}
	got, err := stores.Tokens.ConsumeToken(testContext, "hash-1", "reset_password", base.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("consume: %v | 消费失败", err)
	}
	if got.UsedAt.IsZero() || !got.UsedAt.Equal(base.Add(2*time.Minute)) || got.UsedAt.Location() != time.UTC {
		t.Fatalf("usedAt = %v | 消费时间不符", got.UsedAt)
	}
	if _, err := stores.Tokens.ConsumeToken(testContext, "hash-1", "reset_password", base.Add(3*time.Minute)); !errors.Is(err, auth.ErrTokenUsed) {
		t.Fatalf("second consume error = %v, want ErrTokenUsed | 二次消费错误不符", err)
	}
	if _, err := stores.Tokens.PeekToken(testContext, "hash-1", "reset_password", base.Add(3*time.Minute)); !errors.Is(err, auth.ErrTokenUsed) {
		t.Fatalf("peek used error = %v, want ErrTokenUsed | 查看已用令牌错误不符", err)
	}
	if _, err := stores.Tokens.ConsumeToken(testContext, "missing", "reset_password", base); !errors.Is(err, auth.ErrTokenInvalid) {
		t.Fatalf("missing consume error = %v | 消费不存在令牌错误不符", err)
	}
	exact := sampleToken("hash-exact", "u1", "reset_password", base)
	exact.ExpiresAt = base.Add(2 * time.Minute)
	if err := stores.Tokens.CreateToken(testContext, exact); err != nil {
		t.Fatalf("create exact: %v | 创建边界令牌失败", err)
	}
	if _, err := stores.Tokens.ConsumeToken(testContext, "hash-exact", "reset_password", base.Add(2*time.Minute)); !errors.Is(err, auth.ErrTokenExpired) {
		t.Fatalf("exact expiry error = %v, want ErrTokenExpired | 精确过期错误不符", err)
	}
	if _, err := stores.Tokens.PeekToken(testContext, "hash-exact", "reset_password", base.Add(2*time.Minute)); !errors.Is(err, auth.ErrTokenExpired) {
		t.Fatalf("peek expiry error = %v, want ErrTokenExpired | 查看过期令牌错误不符", err)
	}
	edge := sampleToken("hash-edge", "u1", "reset_password", base)
	edge.ExpiresAt = base.Add(time.Nanosecond)
	if err := stores.Tokens.CreateToken(testContext, edge); err != nil {
		t.Fatalf("create edge: %v | 创建纳秒边界令牌失败", err)
	}
	if _, err := stores.Tokens.ConsumeToken(testContext, "hash-edge", "reset_password", base); err != nil {
		t.Fatalf("consume one nanosecond before expiry: %v | 过期前一纳秒消费失败", err)
	}
	noExpiry := sampleToken("hash-no-expiry", "u1", "reset_password", base)
	noExpiry.ExpiresAt = time.Time{}
	if err := stores.Tokens.CreateToken(testContext, noExpiry); err != nil {
		t.Fatalf("create no-expiry: %v | 创建无期限令牌失败", err)
	}
	if _, err := stores.Tokens.ConsumeToken(testContext, "hash-no-expiry", "reset_password", base.Add(1000*time.Hour)); err != nil {
		t.Fatalf("consume no-expiry: %v | 无期限令牌消费失败", err)
	}
}

// TestTokenCreatePreservesUsedState verifies that a previously consumed token remains unusable
// until replaced by a fresh token. | TestTokenCreatePreservesUsedState 验证已消费令牌在替换为新令牌前
// 保持不可用。
func TestTokenCreatePreservesUsedState(t *testing.T) {
	stores := newStores(t, "")
	base := testTime(2026, time.November, 2, 6, 0, 0)
	used := sampleToken("hash-used", "u1", "reset_password", base)
	used.UsedAt = base.Add(-time.Minute)
	if err := stores.Tokens.CreateToken(testContext, used); err != nil {
		t.Fatalf("create used: %v | 创建已用令牌失败", err)
	}
	if _, err := stores.Tokens.PeekToken(testContext, "hash-used", "reset_password", base); !errors.Is(err, auth.ErrTokenUsed) {
		t.Fatalf("peek used error = %v, want ErrTokenUsed | 查看已用令牌错误不符", err)
	}
	if _, err := stores.Tokens.ConsumeToken(testContext, "hash-used", "reset_password", base); !errors.Is(err, auth.ErrTokenUsed) {
		t.Fatalf("consume used error = %v, want ErrTokenUsed | 消费已用令牌错误不符", err)
	}
	fresh := sampleToken("hash-used", "u1", "reset_password", base)
	if err := stores.Tokens.CreateToken(testContext, fresh); err != nil {
		t.Fatalf("replace fresh: %v | 替换新令牌失败", err)
	}
	if _, err := stores.Tokens.ConsumeToken(testContext, "hash-used", "reset_password", base.Add(time.Minute)); err != nil {
		t.Fatalf("consume fresh replacement: %v | 消费新替换令牌失败", err)
	}
}

// TestTokenCreateReplaces covers same-purpose replacement, consumed-state reset and owner migration.
// | TestTokenCreateReplaces 覆盖同用途替换、消费状态重置与属主迁移。
func TestTokenCreateReplaces(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.November, 3, 0, 0, 0)
	if err := first.Tokens.CreateToken(testContext, sampleToken("hash-1", "u1", "reset_password", base)); err != nil {
		t.Fatalf("create: %v | 创建失败", err)
	}
	if _, err := first.Tokens.ConsumeToken(testContext, "hash-1", "reset_password", base.Add(time.Minute)); err != nil {
		t.Fatalf("consume: %v | 消费失败", err)
	}
	replacement := sampleToken("hash-1", "u2", "reset_password", base.Add(time.Hour))
	replacement.Metadata = map[string]string{"flow": "replacement"}
	if err := second.Tokens.CreateToken(testContext, replacement); err != nil {
		t.Fatalf("replace: %v | 替换失败", err)
	}
	peeked, err := first.Tokens.PeekToken(testContext, "hash-1", "reset_password", base.Add(90*time.Minute))
	if err != nil {
		t.Fatalf("peek replacement: %v | 查看替换令牌失败", err)
	}
	if peeked.UserID != "u2" || !peeked.UsedAt.IsZero() || peeked.Metadata["flow"] != "replacement" {
		t.Fatalf("replacement state = %#v | 替换后状态不符", peeked)
	}
	if removed, err := first.Tokens.DeleteTokensByUser(testContext, "u1", "reset_password"); err != nil || removed != 0 {
		t.Fatalf("old owner delete removed=%d err=%v | 旧属主索引未迁移", removed, err)
	}
	if _, err := first.Tokens.PeekToken(testContext, "hash-1", "reset_password", base.Add(90*time.Minute)); err != nil {
		t.Fatalf("old owner delete removed token: %v | 旧属主删除误删令牌", err)
	}
	if removed, err := second.Tokens.DeleteTokensByUser(testContext, "u2", "reset_password"); err != nil || removed != 1 {
		t.Fatalf("new owner delete removed=%d err=%v | 新属主索引不符", removed, err)
	}
	if _, err := first.Tokens.PeekToken(testContext, "hash-1", "reset_password", base.Add(90*time.Minute)); !errors.Is(err, auth.ErrTokenInvalid) {
		t.Fatalf("token survived delete: %v | 令牌删除后仍存在", err)
	}
}

// TestTokenDeleteByUser covers purpose scoping, counts and isolation across users.
// | TestTokenDeleteByUser 覆盖用途范围、计数与用户隔离。
func TestTokenDeleteByUser(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.November, 4, 0, 0, 0)
	tokens := []*auth.OneTimeToken{
		sampleToken("h1", "u1", "reset_password", base),
		sampleToken("h2", "u1", "reset_password", base),
		sampleToken("h3", "u1", "verify_email", base),
		sampleToken("h4", "u2", "reset_password", base),
	}
	for _, token := range tokens {
		if err := first.Tokens.CreateToken(testContext, token); err != nil {
			t.Fatalf("create %s: %v | 创建令牌失败", token.Hash, err)
		}
	}
	removed, err := second.Tokens.DeleteTokensByUser(testContext, "u1", "reset_password")
	if err != nil || removed != 2 {
		t.Fatalf("removed=%d err=%v, want 2 | 删除数量不符", removed, err)
	}
	for _, hash := range []string{"h1", "h2"} {
		if _, err := first.Tokens.PeekToken(testContext, hash, "reset_password", base); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("%s survived: %v | 已删令牌仍存在", hash, err)
		}
	}
	for _, tc := range []struct {
		hash    string
		purpose string
	}{
		{"h3", "verify_email"},
		{"h4", "reset_password"},
	} {
		if _, err := first.Tokens.PeekToken(testContext, tc.hash, tc.purpose, base); err != nil {
			t.Fatalf("%s/%s was removed: %v | 其它用途或用户令牌被误删", tc.hash, tc.purpose, err)
		}
	}
	removed, err = first.Tokens.DeleteTokensByUser(testContext, "nobody", "reset_password")
	if err != nil || removed != 0 {
		t.Fatalf("empty removed=%d err=%v | 空删除结果不符", removed, err)
	}
}

// TestTokenDeepCopy verifies metadata isolation and UTC normalization.
// | TestTokenDeepCopy 验证元数据隔离与 UTC 规范化。
func TestTokenDeepCopy(t *testing.T) {
	stores := newStores(t, "")
	zone := time.FixedZone("UTC-5", -5*3600)
	created := time.Date(2026, time.November, 5, 8, 0, 0, 0, zone)
	token := sampleToken("hash-1", "u1", "reset_password", created)
	if err := stores.Tokens.CreateToken(testContext, token); err != nil {
		t.Fatalf("create: %v | 创建失败", err)
	}
	token.Metadata["flow"] = "mutated"
	token.UserID = "mutated"
	got, err := stores.Tokens.PeekToken(testContext, "hash-1", "reset_password", created.Add(time.Minute))
	if err != nil {
		t.Fatalf("peek: %v | 查看失败", err)
	}
	if got.Metadata["flow"] != "reset_password" || got.UserID != "u1" {
		t.Fatalf("input mutation leaked: %#v | 输入修改泄露到存储", got)
	}
	if got.CreatedAt.Location() != time.UTC || !got.CreatedAt.Equal(created) {
		t.Fatalf("createdAt = %v | 创建时间未规范化为 UTC", got.CreatedAt)
	}
	got.Metadata["flow"] = "returned-mutation"
	again, err := stores.Tokens.PeekToken(testContext, "hash-1", "reset_password", created.Add(time.Minute))
	if err != nil || again.Metadata["flow"] != "reset_password" {
		t.Fatalf("returned mutation persisted: %v, %v | 返回值修改影响了存储", again, err)
	}
	consumed, err := stores.Tokens.ConsumeToken(testContext, "hash-1", "reset_password", created.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("consume: %v | 消费失败", err)
	}
	consumed.Metadata["flow"] = "returned-mutation"
	if _, err := stores.Tokens.PeekToken(testContext, "hash-1", "reset_password", created.Add(2*time.Minute)); !errors.Is(err, auth.ErrTokenUsed) {
		t.Fatalf("consumed token peek error = %v | 已消费令牌查看错误不符", err)
	}
}

// TestTokenConcurrentConsume verifies that exactly one of many concurrent consumers through two
// instances succeeds. | TestTokenConcurrentConsume 验证两个实例上大量并发消费者中恰好一个成功。
func TestTokenConcurrentConsume(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.November, 6, 0, 0, 0)
	const workers = 24
	if err := first.Tokens.CreateToken(testContext, sampleToken("shared", "u1", "reset_password", base)); err != nil {
		t.Fatalf("create: %v | 创建失败", err)
	}
	var successes atomic.Int32
	errsCh := make(chan error, workers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			stores := first
			if i%2 == 1 {
				stores = second
			}
			<-start
			_, err := stores.Tokens.ConsumeToken(testContext, "shared", "reset_password", base.Add(time.Minute))
			if err == nil {
				successes.Add(1)
				errsCh <- nil
				return
			}
			errsCh <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(errsCh)
	used := 0
	for err := range errsCh {
		switch {
		case err == nil:
		case errors.Is(err, auth.ErrTokenUsed):
			used++
		default:
			t.Fatalf("unexpected consume error: %v | 意外消费错误", err)
		}
	}
	if got := successes.Load(); got != 1 {
		t.Fatalf("successes=%d | 并发消费成功数量不符", got)
	}
	if used != workers-1 {
		t.Fatalf("used=%d, want %d | 已用错误数量不符", used, workers-1)
	}
	if _, err := first.Tokens.PeekToken(testContext, "shared", "reset_password", base.Add(time.Minute)); !errors.Is(err, auth.ErrTokenUsed) {
		t.Fatalf("final peek error = %v | 并发消费后状态不符", err)
	}
}

// TestTokenConcurrentCreateMigration verifies that concurrent replacements leave the token owned by
// exactly one user set. | TestTokenConcurrentCreateMigration 验证并发替换后令牌恰好归属一个用户集合。
func TestTokenConcurrentCreateMigration(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.November, 7, 0, 0, 0)
	const workers = 16
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			stores := first
			if i%2 == 1 {
				stores = second
			}
			if err := stores.Tokens.CreateToken(testContext,
				sampleToken("shared", fmt.Sprintf("u%d", i), "reset_password", base)); err != nil &&
				!errors.Is(err, auth.ErrConflict) {
				t.Errorf("create %d: %v | 并发替换失败", i, err)
			}
		}(i)
	}
	wg.Wait()
	total := 0
	for i := 0; i < workers; i++ {
		removed, err := first.Tokens.DeleteTokensByUser(testContext, fmt.Sprintf("u%d", i), "reset_password")
		if err != nil {
			t.Fatalf("delete u%d: %v | 删除用户令牌失败", i, err)
		}
		total += removed
	}
	if total != 1 {
		t.Fatalf("token memberships = %d, want 1 | 令牌用户归属数量不符", total)
	}
	if _, err := second.Tokens.PeekToken(testContext, "shared", "reset_password", base); !errors.Is(err, auth.ErrTokenInvalid) {
		t.Fatalf("token survived membership cleanup: %v | 令牌未被清理", err)
	}
}
