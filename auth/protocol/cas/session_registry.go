package cas

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// DefaultServiceSessionGCInterval is the default janitor interval of the memory session registry. |
// DefaultServiceSessionGCInterval 是内存会话注册表清理器的默认间隔。
const DefaultServiceSessionGCInterval = time.Minute

// ServiceSession records one service session created when an ST or PT is validated. Sessions are the
// server-side state behind CAS Single Logout: the session index is the ST/PT identifier the service
// received, and it lets the CAS server notify every participating service when the user logs out. |
// ServiceSession 记录 ST 或 PT 校验通过后建立的一个服务会话。会话是 CAS 单点登出的服务端状态：
// 会话索引是服务收到的 ST/PT 标识，CAS 服务端据此在用户登出时通知每个参与服务。
//
// A session intentionally outlives the single-use ticket it names, because a service keeps its own
// login session after the ticket has been consumed. | 会话有意比它命名的单次票据存活更久，因为票据
// 被消费后服务仍会保留自己的登录会话。
type ServiceSession struct {
	// IssuedAt is when the ticket was issued. | IssuedAt 是票据签发时间。
	IssuedAt time.Time
	// ExpiresAt bounds the session. Zero means the session never expires, which custom registries
	// may use when they manage lifetime externally. | ExpiresAt 限定会话寿命。零值表示永不过期，
	// 供自行管理生命周期的自定义注册表使用。
	ExpiresAt time.Time
	// SessionIndex is the ST/PT identifier used as the CAS session index. | SessionIndex 是用作 CAS
	// 会话索引的 ST/PT 标识。
	SessionIndex string
	// User is the protocol user identifier returned to the service, for example "alice". | User 是
	// 返回给服务的协议用户标识，例如 "alice"。
	User string
	// UserID is the backend account identifier used by the ticket store, for example "user-1". |
	// UserID 是票据存储使用的后端账号标识，例如 "user-1"。
	UserID string
	// Service is the service URL that received the ticket. | Service 是接收票据的服务 URL。
	Service string
	// TGTID is the Ticket Granting Ticket at the root of the session. | TGTID 是会话根部的票据授予票据。
	TGTID string
	// TicketID is the validated ticket identifier, equal to SessionIndex. | TicketID 是已校验的票据
	// 标识，与 SessionIndex 相同。
	TicketID string
	// TicketType is ST or PT. | TicketType 是 ST 或 PT。
	TicketType TicketType
	// Renewal reports a session created by a forced re-authentication. | Renewal 表示会话来自强制
	// 重新认证。
	Renewal bool
	// RememberMe reports a persistent login request. | RememberMe 表示持久登录请求。
	RememberMe bool
}

// Clone returns a copy of session. | Clone 返回 session 的副本。
func (s *ServiceSession) Clone() *ServiceSession {
	if s == nil {
		return nil
	}
	copy := *s
	return &copy
}

// Active reports whether the session has not expired at now. A zero ExpiresAt is always active. |
// Active 报告会话在 now 时刻是否尚未过期。零值 ExpiresAt 始终有效。
func (s *ServiceSession) Active(now time.Time) bool {
	if s == nil {
		return false
	}
	return s.ExpiresAt.IsZero() || now.Before(s.ExpiresAt)
}

// ServiceSessionRegistry stores the service sessions used by CAS Single Logout. Implementations must
// be safe for concurrent use and should support cancellation through ctx. Deletion is idempotent:
// removing an unknown session succeeds. | ServiceSessionRegistry 存储 CAS 单点登出使用的服务会话。实现
// 必须并发安全，并应通过 ctx 支持取消。删除是幂等的：删除不存在的会话视为成功。
type ServiceSessionRegistry interface {
	// Register stores session, replacing the record with the same SessionIndex. | Register 保存
	// session，替换相同 SessionIndex 的记录。
	Register(ctx context.Context, session *ServiceSession) error
	// Get returns the session with the given index, or ErrSessionNotFound. | Get 返回指定索引的会话，
	// 不存在时返回 ErrSessionNotFound。
	Get(ctx context.Context, sessionIndex string) (*ServiceSession, error)
	// ListByTGT returns every session rooted at tgtID. | ListByTGT 返回以 tgtID 为根的全部会话。
	ListByTGT(ctx context.Context, tgtID string) ([]*ServiceSession, error)
	// ListByUser returns every session of user. | ListByUser 返回用户的全部会话。
	ListByUser(ctx context.Context, user string) ([]*ServiceSession, error)
	// Delete removes one session and succeeds when it is absent. | Delete 删除一个会话，不存在时也成功。
	Delete(ctx context.Context, sessionIndex string) error
	// DeleteByTGT removes and returns every session rooted at tgtID. | DeleteByTGT 删除并返回以
	// tgtID 为根的全部会话。
	DeleteByTGT(ctx context.Context, tgtID string) ([]*ServiceSession, error)
	// DeleteByUser removes and returns every session of user. | DeleteByUser 删除并返回用户的全部会话。
	DeleteByUser(ctx context.Context, user string) ([]*ServiceSession, error)
	// DeleteExpired removes sessions whose deadline passed at now. | DeleteExpired 删除在 now 时刻
	// 已过期限的会话。
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
}

// MemoryServiceSessionRegistry is an in-memory ServiceSessionRegistry safe for concurrent use. | MemoryServiceSessionRegistry
// 是并发安全的内存 ServiceSessionRegistry。
//
// Records live in the process; a multi-node CAS deployment must provide a shared implementation.
// StartGC runs a background janitor that removes expired sessions; Close stops it. | 记录仅存在于进程
// 内；多节点 CAS 部署必须提供共享实现。StartGC 运行删除过期会话的后台清理器；Close 停止它。
type MemoryServiceSessionRegistry struct {
	sessions map[string]*ServiceSession
	byTGT    map[string]map[string]struct{}
	byUser   map[string]map[string]struct{}
	stopCh   chan struct{}
	doneCh   chan struct{}
	clock    func() time.Time
	// mu guards every field below. | mu 保护下面的每个字段。
	mu       sync.Mutex
	stopped  bool
	gcActive bool
}

// NewMemoryServiceSessionRegistry returns an empty memory registry. | NewMemoryServiceSessionRegistry
// 返回空的内存注册表。
func NewMemoryServiceSessionRegistry() *MemoryServiceSessionRegistry {
	return &MemoryServiceSessionRegistry{
		sessions: make(map[string]*ServiceSession),
		byTGT:    make(map[string]map[string]struct{}),
		byUser:   make(map[string]map[string]struct{}),
		clock:    func() time.Time { return time.Now().UTC() },
	}
}

// SetClock replaces the time source used by the janitor; it is intended for deterministic tests. |
// SetClock 替换清理器使用的时间源；用于确定性测试。
func (r *MemoryServiceSessionRegistry) SetClock(clock func() time.Time) {
	if clock == nil {
		return
	}
	r.mu.Lock()
	r.clock = clock
	r.mu.Unlock()
}

// Register stores a deep copy of session, replacing any record with the same index. | Register 保存
// session 的深拷贝，替换相同索引的记录。
func (r *MemoryServiceSessionRegistry) Register(_ context.Context, session *ServiceSession) error {
	if session == nil || session.SessionIndex == "" {
		return errs.Detail(ErrInvalidRequest, "service session is nil or has no index | 服务会话为空或缺少索引")
	}
	stored := session.Clone()
	if stored.TicketID == "" {
		stored.TicketID = stored.SessionIndex
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.sessions[stored.SessionIndex]; ok {
		r.untrackLocked(old)
	}
	r.sessions[stored.SessionIndex] = stored
	r.trackLocked(stored)
	return nil
}

// Get returns a copy of the session with the given index. | Get 返回指定索引会话的副本。
func (r *MemoryServiceSessionRegistry) Get(_ context.Context, sessionIndex string) (*ServiceSession, error) {
	if sessionIndex == "" {
		return nil, ErrSessionNotFound
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	session, ok := r.sessions[sessionIndex]
	if !ok || !secureCompare(session.SessionIndex, sessionIndex) {
		return nil, ErrSessionNotFound
	}
	return session.Clone(), nil
}

// ListByTGT returns every session rooted at tgtID. | ListByTGT 返回以 tgtID 为根的全部会话。
func (r *MemoryServiceSessionRegistry) ListByTGT(_ context.Context, tgtID string) ([]*ServiceSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.collectLocked(r.byTGT[tgtID]), nil
}

// ListByUser returns every session of user. | ListByUser 返回用户的全部会话。
func (r *MemoryServiceSessionRegistry) ListByUser(_ context.Context, user string) ([]*ServiceSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.collectLocked(r.byUser[user]), nil
}

// Delete removes one session; deleting an absent session succeeds. | Delete 删除一个会话；删除不存在的
// 会话视为成功。
func (r *MemoryServiceSessionRegistry) Delete(_ context.Context, sessionIndex string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deleteLocked(sessionIndex)
	return nil
}

// DeleteByTGT removes and returns every session rooted at tgtID. | DeleteByTGT 删除并返回以 tgtID 为根
// 的全部会话。
func (r *MemoryServiceSessionRegistry) DeleteByTGT(_ context.Context, tgtID string) ([]*ServiceSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.deleteSetLocked(r.byTGT[tgtID]), nil
}

// DeleteByUser removes and returns every session of user. | DeleteByUser 删除并返回用户的全部会话。
func (r *MemoryServiceSessionRegistry) DeleteByUser(_ context.Context, user string) ([]*ServiceSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.deleteSetLocked(r.byUser[user]), nil
}

// DeleteExpired removes sessions whose deadline passed at now and returns the count. | DeleteExpired
// 删除在 now 时刻已过期限的会话并返回数量。
func (r *MemoryServiceSessionRegistry) DeleteExpired(_ context.Context, now time.Time) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	indexes := make([]string, 0)
	for index, session := range r.sessions {
		if !session.ExpiresAt.IsZero() && !now.Before(session.ExpiresAt) {
			indexes = append(indexes, index)
		}
	}
	for _, index := range indexes {
		r.deleteLocked(index)
	}
	return len(indexes), nil
}

// Len returns the number of stored sessions. | Len 返回已存会话数量。
func (r *MemoryServiceSessionRegistry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}

// StartGC starts the expiry janitor. Repeated calls are ignored, and a registry that was stopped
// stays stopped. The goroutine exits when Close or Stop is called. | StartGC 启动过期清理器。重复调用
// 会被忽略，已停止的注册表保持停止。goroutine 在调用 Close 或 Stop 时退出。
func (r *MemoryServiceSessionRegistry) StartGC(interval time.Duration) {
	if interval <= 0 {
		interval = DefaultServiceSessionGCInterval
	}
	r.mu.Lock()
	if r.stopped || r.gcActive {
		r.mu.Unlock()
		return
	}
	r.gcActive = true
	r.stopCh = make(chan struct{})
	r.doneCh = make(chan struct{})
	stop, done := r.stopCh, r.doneCh
	r.mu.Unlock()
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				r.mu.Lock()
				now := r.clock()
				r.mu.Unlock()
				_, _ = r.DeleteExpired(context.Background(), now)
			}
		}
	}()
}

// Stop terminates the janitor and waits for it to exit. It is safe to call more than once. | Stop
// 终止清理器并等待其退出。可以安全地多次调用。
func (r *MemoryServiceSessionRegistry) Stop() {
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return
	}
	r.stopped = true
	stop, done := r.stopCh, r.doneCh
	if stop != nil {
		close(stop)
	}
	r.mu.Unlock()
	if done != nil {
		<-done
	}
}

// Close stops the janitor and implements io.Closer. | Close 停止清理器并实现 io.Closer。
func (r *MemoryServiceSessionRegistry) Close() error {
	r.Stop()
	return nil
}

// deleteSetLocked removes and returns the sessions named by set; the caller must hold mu. | deleteSetLocked
// 删除并返回 set 指定的会话；调用方必须持有 mu。
func (r *MemoryServiceSessionRegistry) deleteSetLocked(set map[string]struct{}) []*ServiceSession {
	if len(set) == 0 {
		return nil
	}
	indexes := make([]string, 0, len(set))
	for index := range set {
		indexes = append(indexes, index)
	}
	sort.Strings(indexes)
	removed := make([]*ServiceSession, 0, len(indexes))
	for _, index := range indexes {
		if session, ok := r.sessions[index]; ok {
			removed = append(removed, session.Clone())
			r.deleteLocked(index)
		}
	}
	return removed
}

// collectLocked clones the sessions named by set and sorts them by issue time. | collectLocked 克隆
// set 指定的会话并按签发时间排序。
func (r *MemoryServiceSessionRegistry) collectLocked(set map[string]struct{}) []*ServiceSession {
	if len(set) == 0 {
		return nil
	}
	out := make([]*ServiceSession, 0, len(set))
	for index := range set {
		if session, ok := r.sessions[index]; ok {
			out = append(out, session.Clone())
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IssuedAt.Equal(out[j].IssuedAt) {
			return out[i].SessionIndex < out[j].SessionIndex
		}
		return out[i].IssuedAt.Before(out[j].IssuedAt)
	})
	return out
}

// trackLocked adds the index entries of session; the caller must hold mu. | trackLocked 添加 session
// 的索引项；调用方必须持有 mu。
func (r *MemoryServiceSessionRegistry) trackLocked(session *ServiceSession) {
	if session.TGTID != "" {
		addIndex(r.byTGT, session.TGTID, session.SessionIndex)
	}
	if session.User != "" {
		addIndex(r.byUser, session.User, session.SessionIndex)
	}
	if session.UserID != "" && session.UserID != session.User {
		addIndex(r.byUser, session.UserID, session.SessionIndex)
	}
}

// untrackLocked removes the index entries of session; the caller must hold mu. | untrackLocked 移除
// session 的索引项；调用方必须持有 mu。
func (r *MemoryServiceSessionRegistry) untrackLocked(session *ServiceSession) {
	if session.TGTID != "" {
		removeIndex(r.byTGT, session.TGTID, session.SessionIndex)
	}
	if session.User != "" {
		removeIndex(r.byUser, session.User, session.SessionIndex)
	}
	if session.UserID != "" && session.UserID != session.User {
		removeIndex(r.byUser, session.UserID, session.SessionIndex)
	}
}

// deleteLocked removes index and its index entries; the caller must hold mu. | deleteLocked 删除 index
// 及其索引项；调用方必须持有 mu。
func (r *MemoryServiceSessionRegistry) deleteLocked(index string) {
	if session, ok := r.sessions[index]; ok {
		r.untrackLocked(session)
		delete(r.sessions, index)
	}
}
