package oauth2

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// DPoPNonceHeader is the RFC 9449 response header carrying a server nonce. | DPoPNonceHeader 是
// RFC 9449 承载服务器 nonce 的响应头。
const DPoPNonceHeader = "DPoP-Nonce"

// ErrorUseDPoPNonce is the RFC 9449 error code that asks a client to retry with a fresh nonce. |
// ErrorUseDPoPNonce 是 RFC 9449 要求客户端使用新 nonce 重试的错误码。
const ErrorUseDPoPNonce = "use_dpop_nonce"

// defaultDPoPNonceTTL is the lifetime of a challenged nonce. | defaultDPoPNonceTTL 是挑战 nonce 的寿命。
const defaultDPoPNonceTTL = 5 * time.Minute

// memoryDPoPNonceCapacity bounds the nonce map so a flood of proofs cannot grow it without limit. |
// memoryDPoPNonceCapacity 限定 nonce 映射大小，避免证明洪泛使其无限增长。
const memoryDPoPNonceCapacity = 8192

// maxDPoPNonceLength bounds an accepted nonce string. | maxDPoPNonceLength 限定可接受的 nonce 长度。
const maxDPoPNonceLength = 512

// ErrDPoPNonceRequired reports that a DPoP proof must carry a fresh server nonce. | ErrDPoPNonceRequired
// 表示 DPoP 证明必须携带新的服务器 nonce。
var ErrDPoPNonceRequired = errs.New("oauth2: DPoP nonce required | oauth2：需要 DPoP nonce")

// DPoPNonceStore issues and validates RFC 9449 DPoP nonces. | DPoPNonceStore 签发并校验 RFC 9449
// DPoP nonce。
//
// RFC 9449 treats nonces as time-window values that may be reused until they expire; replay
// protection comes from the proof jti, not from single-use nonces. Implementations must be safe for
// concurrent use and should bound their storage. | RFC 9449 把 nonce 视为时间窗取值，在过期前可重复
// 使用；重放保护来自证明 jti，而不是一次性 nonce。实现必须并发安全，并应限制存储规模。
type DPoPNonceStore interface {
	// Issue returns a fresh unpredictable nonce valid for ttl from now. | Issue 返回从 now 起 ttl 内
	// 有效的新不可预测 nonce。
	Issue(ctx context.Context, now time.Time, ttl time.Duration) (string, error)
	// Accept reports whether nonce was issued by this store and has not expired at now. | Accept
	// 报告 nonce 是否由本存储签发且在 now 时尚未过期。
	Accept(ctx context.Context, nonce string, now time.Time) (bool, error)
	// Prune removes expired nonces. | Prune 删除过期 nonce。
	Prune(now time.Time)
}

// MemoryDPoPNonceStore is a concurrency-safe in-process DPoP nonce store. | MemoryDPoPNonceStore 是
// 并发安全的内存 DPoP nonce 存储。
//
// It is intended for a single process. Deployments with several authorization or resource servers
// need a shared implementation so a nonce issued by one node is accepted by another. | 它用于单进程。
// 多授权服务器或多资源服务器的部署需要共享实现，使一个节点签发的 nonce 可被另一个节点接受。
type MemoryDPoPNonceStore struct {
	// mu guards nonces. | mu 保护 nonces。
	mu sync.Mutex
	// nonces maps each issued nonce to its expiry. | nonces 把每个已签发 nonce 映射到过期时间。
	nonces map[string]time.Time
}

// NewMemoryDPoPNonceStore returns an empty nonce store. | NewMemoryDPoPNonceStore 返回空 nonce 存储。
func NewMemoryDPoPNonceStore() *MemoryDPoPNonceStore {
	return &MemoryDPoPNonceStore{nonces: make(map[string]time.Time)}
}

// Issue returns a fresh nonce valid for ttl from now. | Issue 返回从 now 起 ttl 内有效的新 nonce。
func (s *MemoryDPoPNonceStore) Issue(_ context.Context, now time.Time, ttl time.Duration) (string, error) {
	if s == nil {
		return "", errs.Detail(ErrServerError, "nonce store is nil | nonce 存储为空")
	}
	if ttl <= 0 {
		ttl = defaultDPoPNonceTTL
	}
	nonce, err := auth.RandomToken(32)
	if err != nil {
		return "", err
	}
	now = now.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.nonces) >= memoryDPoPNonceCapacity {
		// Reclaim elapsed nonces before evicting a live one, then keep the bound hard under a
		// flood. Scanning only at the capacity boundary keeps the normal Issue path O(1). | 淘汰
		// 有效 nonce 之前先回收已过期项，并在洪泛下保持硬上限。只在容量边界扫描使常规 Issue
		// 路径保持 O(1)。
		s.pruneLocked(now)
		for len(s.nonces) >= memoryDPoPNonceCapacity {
			for key := range s.nonces {
				delete(s.nonces, key)
				break
			}
		}
	}
	s.nonces[nonce] = now.Add(ttl)
	return nonce, nil
}

// Accept reports whether nonce is valid at now. | Accept 报告 nonce 在 now 时是否有效。
func (s *MemoryDPoPNonceStore) Accept(_ context.Context, nonce string, now time.Time) (bool, error) {
	if s == nil {
		return false, errs.Detail(ErrServerError, "nonce store is nil | nonce 存储为空")
	}
	if nonce == "" || len(nonce) > maxDPoPNonceLength {
		return false, nil
	}
	now = now.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	expires, ok := s.nonces[nonce]
	if !ok {
		return false, nil
	}
	// The request path only checks the presented nonce so verification stays O(1); expired entries
	// are reclaimed in bulk by Prune, the cleanup scheduler, or the capacity boundary. | 请求路径只
	// 检查呈现的 nonce，使校验保持 O(1)；其余过期项由 Prune、清理调度器或容量边界批量回收。
	if !now.Before(expires) {
		delete(s.nonces, nonce)
		return false, nil
	}
	return true, nil
}

// Prune removes expired nonces. | Prune 删除过期 nonce。
func (s *MemoryDPoPNonceStore) Prune(now time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now.UTC())
}

// pruneLocked removes expired nonces; the caller holds the mutex. | pruneLocked 删除过期 nonce；调用方
// 持有互斥锁。
func (s *MemoryDPoPNonceStore) pruneLocked(now time.Time) {
	for nonce, expires := range s.nonces {
		if !now.Before(expires) {
			delete(s.nonces, nonce)
		}
	}
}

// DPoPNonceRequiredError reports that a proof was rejected in nonce mode and carries the fresh nonce
// a server must return in the DPoP-Nonce header. | DPoPNonceRequiredError 表示证明在 nonce 模式下被
// 拒绝，并携带服务器必须放入 DPoP-Nonce 响应头的新 nonce。
type DPoPNonceRequiredError struct {
	// Nonce is the fresh nonce for the DPoP-Nonce response header. | Nonce 是用于 DPoP-Nonce 响应头的
	// 新 nonce。
	Nonce string
	// Detail explains why the proof nonce was rejected. | Detail 说明证明 nonce 被拒绝的原因。
	Detail string
}

// Error returns the use_dpop_nonce error string. | Error 返回 use_dpop_nonce 错误字符串。
func (e *DPoPNonceRequiredError) Error() string {
	if e == nil {
		return ""
	}
	if e.Detail == "" {
		return "oauth2: " + ErrorUseDPoPNonce
	}
	return "oauth2: " + ErrorUseDPoPNonce + ": " + e.Detail
}

// Unwrap returns ErrDPoPNonceRequired so errors.Is classifies the failure. | Unwrap 返回
// ErrDPoPNonceRequired，使 errors.Is 能对该失败分类。
func (e *DPoPNonceRequiredError) Unwrap() error { return ErrDPoPNonceRequired }

// DPoPNonceIssuer issues nonces for DPoP-Nonce response headers. | DPoPNonceIssuer 为 DPoP-Nonce
// 响应头签发 nonce。
type DPoPNonceIssuer interface {
	// IssueDPoPNonce returns a fresh nonce valid at now, or an empty string when nonce mode is
	// disabled. | IssueDPoPNonce 返回 now 时有效的新 nonce；未启用 nonce 模式时返回空字符串。
	IssueDPoPNonce(ctx context.Context, now time.Time) (string, error)
}

// dpopNoncePruner removes expired nonces from a verifier-owned store. | dpopNoncePruner 删除校验器
// 自有存储中的过期 nonce。
type dpopNoncePruner interface {
	// PruneDPoPNonces removes nonces expired at now. | PruneDPoPNonces 删除在 now 已过期的 nonce。
	PruneDPoPNonces(now time.Time)
}

// WriteDPoPChallenge writes an RFC 9449 challenge for err and reports whether it handled the error.
// | WriteDPoPChallenge 为 err 写出 RFC 9449 挑战并报告是否已处理该错误。
//
// A DPoPNonceRequiredError produces HTTP 401 with a WWW-Authenticate DPoP error="use_dpop_nonce"
// challenge and a fresh DPoP-Nonce header; any other invalid proof produces HTTP 401 with
// error="invalid_dpop_proof". Resource servers should call it instead of writing their own
// challenge, because the nonce must come from the verifier that rejected the proof. Callers must
// only use it for token-authentication failures, never after a response has been written. |
// DPoPNonceRequiredError 生成 HTTP 401、WWW-Authenticate DPoP error="use_dpop_nonce" 挑战与新的
// DPoP-Nonce 响应头；其他无效证明生成 HTTP 401 与 error="invalid_dpop_proof"。资源服务器应调用它
// 而不是自行写挑战，因为 nonce 必须来自拒绝该证明的校验器。调用方只能把它用于令牌认证失败，绝不能
// 在响应已写出后使用。
func WriteDPoPChallenge(w http.ResponseWriter, err error) bool {
	if w == nil || err == nil {
		return false
	}
	var nonceErr *DPoPNonceRequiredError
	if errors.As(err, &nonceErr) {
		if nonceErr.Nonce != "" {
			w.Header().Set(DPoPNonceHeader, nonceErr.Nonce)
		}
		w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
		writeJSON(w, http.StatusUnauthorized, NewError(ErrorUseDPoPNonce, "a fresh DPoP nonce is required | 需要新的 DPoP nonce"))
		return true
	}
	if errors.Is(err, ErrInvalidDPoPProof) {
		w.Header().Set("WWW-Authenticate", `DPoP error="invalid_dpop_proof"`)
		writeJSON(w, http.StatusUnauthorized, NewError(ErrorInvalidDPoPProof, "invalid DPoP proof | DPoP 证明无效"))
		return true
	}
	return false
}

// isUseDPoPNonceResponse reports whether an HTTP response carries the RFC 9449 use_dpop_nonce
// challenge in a JSON error body or a WWW-Authenticate header. | isUseDPoPNonceResponse 报告 HTTP
// 响应是否在 JSON 错误正文或 WWW-Authenticate 头中携带 RFC 9449 use_dpop_nonce 挑战。
func isUseDPoPNonceResponse(status int, header http.Header, body []byte) bool {
	if status != http.StatusBadRequest && status != http.StatusUnauthorized {
		return false
	}
	if header != nil {
		challenge := strings.ToLower(header.Get("WWW-Authenticate"))
		if strings.Contains(challenge, `error="use_dpop_nonce"`) {
			return true
		}
	}
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &payload); err == nil && payload.Error == ErrorUseDPoPNonce {
		return true
	}
	return false
}
