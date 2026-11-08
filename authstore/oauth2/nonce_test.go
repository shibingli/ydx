package oauth2_test

import (
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	authoauth2 "github.com/shibingli/ydx/auth/protocol/oauth2"
	oauth2store "github.com/shibingli/ydx/authstore/oauth2"
)

// TestDPoPNonces covers issuance, cross-instance acceptance, expiry, pruning and capacity.
// | TestDPoPNonces 覆盖签发、跨实例接受、过期、清理与容量。
func TestDPoPNonces(t *testing.T) {
	first, second := newPair(t, oauth2store.Options{MaxDPoPNonces: 2})
	base := testTime(2026, time.July, 10, 10, 0, 0)
	nonce, err := first.DPoPNonces.Issue(testContext, base, 0)
	if err != nil || nonce == "" {
		t.Fatalf("issue = %q, %v | 签发 nonce 失败", nonce, err)
	}
	accepted, err := second.DPoPNonces.Accept(testContext, nonce, base.Add(time.Minute))
	if err != nil || !accepted {
		t.Fatalf("cross-instance accept = %v, %v | 跨实例接受失败", accepted, err)
	}
	other, err := first.DPoPNonces.Issue(testContext, base, time.Minute)
	if err != nil || other == "" || other == nonce {
		t.Fatalf("second issue = %q, %v | 第二次签发不符", other, err)
	}
	for _, invalid := range []string{"", string(make([]byte, 513))} {
		accepted, err := first.DPoPNonces.Accept(testContext, invalid, base)
		if err != nil || accepted {
			t.Fatalf("invalid nonce accepted: %q, %v, %v | 无效 nonce 被接受", invalid, accepted, err)
		}
	}
	shortLived, err := first.DPoPNonces.Issue(testContext, base, time.Minute)
	if err != nil {
		t.Fatalf("issue short: %v | 签发短期 nonce 失败", err)
	}
	if accepted, err := second.DPoPNonces.Accept(testContext, shortLived, base.Add(time.Minute-time.Nanosecond)); err != nil || !accepted {
		t.Fatalf("pre-expiry accept = %v, %v | 期限前接受失败", accepted, err)
	}
	if accepted, err := second.DPoPNonces.Accept(testContext, shortLived, base.Add(time.Minute)); err != nil || accepted {
		t.Fatalf("exact-expiry accept = %v, %v; want false | 精确期限应拒绝", accepted, err)
	}
	if accepted, err := second.DPoPNonces.Accept(testContext, shortLived, base.Add(2*time.Minute)); err != nil || accepted {
		t.Fatalf("post-expiry accept = %v, %v; want false | 过期后应拒绝", accepted, err)
	}
	second.DPoPNonces.Prune(base.Add(90 * time.Second))
	if accepted, err := first.DPoPNonces.Accept(testContext, shortLived, base.Add(90*time.Second)); err != nil || accepted {
		t.Fatalf("pruned nonce accepted = %v, %v | 已清理 nonce 被接受", accepted, err)
	}
}

// TestDPoPNonceCapacity verifies that the population bound evicts the soonest-expiring nonce.
// | TestDPoPNonceCapacity 验证数量上限会淘汰最早过期的 nonce。
func TestDPoPNonceCapacity(t *testing.T) {
	stores := newStoresOn(t, miniredis.RunT(t), oauth2store.Options{MaxDPoPNonces: 2})
	base := testTime(2026, time.August, 10, 10, 0, 0)
	n1, err := stores.DPoPNonces.Issue(testContext, base, time.Minute)
	if err != nil {
		t.Fatalf("issue n1: %v | 签发 n1 失败", err)
	}
	n2, err := stores.DPoPNonces.Issue(testContext, base, 2*time.Minute)
	if err != nil {
		t.Fatalf("issue n2: %v | 签发 n2 失败", err)
	}
	n3, err := stores.DPoPNonces.Issue(testContext, base, 3*time.Minute)
	if err != nil {
		t.Fatalf("issue n3: %v | 签发 n3 失败", err)
	}
	if accepted, err := stores.DPoPNonces.Accept(testContext, n1, base); err != nil || accepted {
		t.Fatalf("n1 survived eviction: %v, %v | n1 未被淘汰", accepted, err)
	}
	for _, nonce := range []string{n2, n3} {
		if accepted, err := stores.DPoPNonces.Accept(testContext, nonce, base); err != nil || !accepted {
			t.Fatalf("nonce %q was evicted: %v, %v | nonce 被误淘汰", nonce, accepted, err)
		}
	}
}

// TestDPoPReplay covers empty identifiers, cross-instance replay rejection and expiry.
// | TestDPoPReplay 覆盖空标识、跨实例重放拒绝与过期。
func TestDPoPReplay(t *testing.T) {
	first, second := newPair(t, oauth2store.Options{})
	if _, err := first.DPoPReplay.Accept(testContext, "", time.Now().Add(time.Hour)); !errors.Is(err, authoauth2.ErrInvalidDPoPProof) {
		t.Fatalf("empty jti error = %v, want ErrInvalidDPoPProof | 空 jti 错误不符", err)
	}
	expires := time.Now().Add(time.Hour)
	if accepted, err := first.DPoPReplay.Accept(testContext, "jti-1", expires); err != nil || !accepted {
		t.Fatalf("first accept = %v, %v | 首次接受失败", accepted, err)
	}
	if accepted, err := second.DPoPReplay.Accept(testContext, "jti-1", expires); err != nil || accepted {
		t.Fatalf("replay accept = %v, %v; want false | 重放应被拒绝", accepted, err)
	}
	if accepted, err := second.DPoPReplay.Accept(testContext, "jti-2", expires); err != nil || !accepted {
		t.Fatalf("fresh jti = %v, %v | 新 jti 应被接受", accepted, err)
	}
	if accepted, err := first.DPoPReplay.Accept(testContext, "already-past", time.Now().Add(-time.Hour)); err != nil || !accepted {
		t.Fatalf("past jti = %v, %v | 已过期 jti 首次应接受", accepted, err)
	}
	if accepted, err := second.DPoPReplay.Accept(testContext, "already-past", time.Now().Add(-time.Hour)); err != nil || !accepted {
		t.Fatalf("past jti second = %v, %v | 未记录的过期 jti 应再次接受", accepted, err)
	}
	short := time.Now().Add(100 * time.Millisecond)
	if accepted, err := first.DPoPReplay.Accept(testContext, "short-jti", short); err != nil || !accepted {
		t.Fatalf("short first = %v, %v | 短期 jti 首次接受失败", accepted, err)
	}
	time.Sleep(250 * time.Millisecond)
	if accepted, err := second.DPoPReplay.Accept(testContext, "short-jti", time.Now().Add(time.Hour)); err != nil || !accepted {
		t.Fatalf("expired jti = %v, %v; want accepted after expiry | 过期 jti 应重新接受", accepted, err)
	}
}
