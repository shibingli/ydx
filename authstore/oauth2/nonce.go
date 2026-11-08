package oauth2

import (
	"context"
	"time"

	"github.com/shibingli/ydx/auth"
	authoauth2 "github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/errs"
)

// defaultDPoPNonceTTL is the lifetime used when Issue receives a non-positive ttl.
// | defaultDPoPNonceTTL 是 Issue 收到非正数寿命时使用的默认寿命。
const defaultDPoPNonceTTL = 5 * time.Minute

// maxDPoPNonceLength bounds an accepted nonce, matching the in-memory store.
// | maxDPoPNonceLength 限定可接受的 nonce 长度，与内存存储一致。
const maxDPoPNonceLength = 512

// DPoPNonceStore is the Redis implementation of authoauth2.DPoPNonceStore. Nonces are shared by
// every instance and remain valid after a restart until their exact deadline. The store keeps a
// hard population bound: at the bound it first reclaims expired nonces, then evicts the
// soonest-expiring live nonce. | DPoPNonceStore 是 authoauth2.DPoPNonceStore 的 Redis 实现。
// nonce 在所有实例间共享，且在精确期限前跨重启有效。存储保持硬性数量上限：到达上限时先回收
// 过期 nonce，再淘汰最早过期的有效 nonce。
type DPoPNonceStore struct {
	// base carries the shared client and key namespace. | base 承载共享客户端与键命名空间。
	base
	// capacity is the hard nonce population bound. | capacity 是 nonce 数量硬上限。
	capacity int
}

// DPoPNonceStore satisfies the authoauth2 nonce port. | DPoPNonceStore 满足 authoauth2 nonce 端口。
var _ authoauth2.DPoPNonceStore = (*DPoPNonceStore)(nil)

// Issue returns a fresh unpredictable nonce valid for ttl from now. | Issue 返回从 now 起 ttl 内有效的
// 新不可预测 nonce。
func (s *DPoPNonceStore) Issue(ctx context.Context, now time.Time, ttl time.Duration) (string, error) {
	if s == nil {
		return "", errs.Detail(authoauth2.ErrServerError, "nonce store is nil | nonce 存储为空")
	}
	if ttl <= 0 {
		ttl = defaultDPoPNonceTTL
	}
	nonce, err := auth.RandomToken(32)
	if err != nil {
		return "", err
	}
	now = now.UTC()
	expires := now.Add(ttl)
	expSec, expNsec := clockFields(expires)
	nowSec, nowNsec := clockFields(now)
	capacity := s.capacity
	if capacity <= 0 {
		capacity = defaultMaxDPoPNonces
	}
	status, err := s.runInt(ctx, scriptNonceIssue, "issue DPoP nonce",
		[]string{s.keys.noncesExpiry(), s.keys.noncesIndex()},
		nonce, expSec, expNsec, nowSec, nowNsec, strconvFormatInt(int64(capacity)))
	if err != nil {
		return "", err
	}
	if status != 1 {
		return "", errs.Detail(authoauth2.ErrServerError, "redis reply carries an unknown status | Redis 应答携带未知状态")
	}
	return nonce, nil
}

// Accept reports whether nonce was issued by this store and has not expired at now.
// | Accept 报告 nonce 是否由本存储签发且在 now 时尚未过期。
func (s *DPoPNonceStore) Accept(ctx context.Context, nonce string, now time.Time) (bool, error) {
	if s == nil {
		return false, errs.Detail(authoauth2.ErrServerError, "nonce store is nil | nonce 存储为空")
	}
	if nonce == "" || len(nonce) > maxDPoPNonceLength {
		return false, nil
	}
	now = now.UTC()
	nowSec, nowNsec := clockFields(now)
	status, err := s.runInt(ctx, scriptNonceAccept, "accept DPoP nonce",
		[]string{s.keys.noncesExpiry(), s.keys.noncesIndex()}, nonce, nowSec, nowNsec)
	if err != nil {
		return false, err
	}
	return status == 1, nil
}

// Prune removes expired nonces. The method has no error return, so a backend failure is ignored;
// the capacity bound still prevents unbounded growth. | Prune 删除过期 nonce。该方法没有错误返回，
// 因此后端故障会被忽略；容量上限仍能防止无限增长。
func (s *DPoPNonceStore) Prune(now time.Time) {
	if s == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), pruneTimeout)
	defer cancel()
	nowSec, nowNsec := clockFields(now.UTC())
	_, _ = s.runInt(ctx, scriptNoncePrune, "prune DPoP nonces",
		[]string{s.keys.noncesExpiry(), s.keys.noncesIndex()}, nowSec, nowNsec)
}

// DPoPReplayStore is the Redis implementation of authoauth2.DPoPReplayStore. A proof identifier
// is recorded atomically for every instance until its proof deadline. | DPoPReplayStore 是
// authoauth2.DPoPReplayStore 的 Redis 实现。证明标识在所有实例间原子记录，直到证明期限。
type DPoPReplayStore struct {
	// base carries the shared client and key namespace. | base 承载共享客户端与键命名空间。
	base
}

// DPoPReplayStore satisfies the authoauth2 replay port. | DPoPReplayStore 满足 authoauth2 重放端口。
var _ authoauth2.DPoPReplayStore = (*DPoPReplayStore)(nil)

// Accept records jti until expiresAt and reports whether it was fresh. | Accept 记录 jti 到
// expiresAt 并报告是否为新鲜值。
func (s *DPoPReplayStore) Accept(ctx context.Context, jti string, expiresAt time.Time) (bool, error) {
	if jti == "" {
		return false, errs.Detail(authoauth2.ErrInvalidDPoPProof, "jti is empty | jti 为空")
	}
	if s == nil {
		return false, errs.Detail(authoauth2.ErrServerError, "replay store is nil | 重放存储为空")
	}
	now := time.Now().UTC()
	nowSec, nowNsec := clockFields(now)
	hasExp, expSec, expNsec := expiryFields(expiresAt)
	ttlMillis := "0"
	if hasExp == "1" {
		remaining := expiresAt.UTC().Sub(now)
		if remaining > 0 {
			ttl := remaining / time.Millisecond
			if remaining%time.Millisecond != 0 {
				ttl++
			}
			if ttl < 1 {
				ttl = 1
			}
			ttlMillis = strconvFormatInt(int64(ttl))
		}
	}
	status, err := s.runInt(ctx, scriptReplayAccept, "accept DPoP replay identifier",
		[]string{s.keys.replayJTI(jti)}, expSec, expNsec, nowSec, nowNsec, ttlMillis)
	if err != nil {
		return false, err
	}
	return status == 1, nil
}
