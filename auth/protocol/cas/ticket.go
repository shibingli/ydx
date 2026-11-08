package cas

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
)

// Sentinel errors of the ticket model and store. | 票据模型与存储的哨兵错误。
var (
	// ErrInvalidConfig reports a missing or contradictory server configuration. | ErrInvalidConfig 表示服务端配置缺失或互相矛盾。
	ErrInvalidConfig = errs.New("cas: invalid configuration | cas：配置非法")
	// ErrInvalidRequest reports malformed caller input. | ErrInvalidRequest 表示调用方输入非法。
	ErrInvalidRequest = errs.New("cas: invalid request | cas：请求非法")
	// ErrTicketNotFound reports an unknown ticket identifier. | ErrTicketNotFound 表示票据标识不存在。
	ErrTicketNotFound = errs.New("cas: ticket not found | cas：票据不存在")
	// ErrTicketExpired reports a ticket past its expiry. | ErrTicketExpired 表示票据已过有效期。
	ErrTicketExpired = errs.New("cas: ticket expired | cas：票据已过期")
	// ErrTicketUsed reports an already consumed single-use ticket. | ErrTicketUsed 表示一次性票据已被消费。
	ErrTicketUsed = errs.New("cas: ticket already used | cas：票据已被使用")
	// ErrTicketGeneration reports a failed random-source read while minting a ticket. | ErrTicketGeneration 表示签发票据时随机源读取失败。
	ErrTicketGeneration = errs.New("cas: ticket generation failed | cas：票据生成失败")
	// ErrTicketTypeMismatch reports a ticket used where another type is required. | ErrTicketTypeMismatch 表示票据类型与用途不符。
	ErrTicketTypeMismatch = errs.New("cas: ticket type mismatch | cas：票据类型不匹配")
	// ErrInvalidTicket reports a ticket that cannot be validated. | ErrInvalidTicket 表示票据无法通过校验。
	ErrInvalidTicket = errs.New("cas: invalid ticket | cas：票据无效")
	// ErrInvalidService reports a service that is empty or not registered. | ErrInvalidService 表示服务为空或未注册。
	ErrInvalidService = errs.New("cas: invalid service | cas：服务无效")
	// ErrServiceNotRegistered reports a service rejected by the registry. | ErrServiceNotRegistered 表示服务被注册表拒绝。
	ErrServiceNotRegistered = errs.New("cas: service not registered | cas：服务未注册")
	// ErrInvalidProxyCallback reports a PGT callback that failed or is disallowed. | ErrInvalidProxyCallback 表示 PGT 回调失败或被禁止。
	ErrInvalidProxyCallback = errs.New("cas: invalid proxy callback | cas：代理回调无效")
	// ErrInsecureProxyCallback reports a plain-HTTP PGT callback. | ErrInsecureProxyCallback 表示明文 HTTP 的 PGT 回调。
	ErrInsecureProxyCallback = errs.New("cas: proxy callback must use HTTPS | cas：代理回调必须使用 HTTPS")
	// ErrInvalidCredentials reports a failed login. | ErrInvalidCredentials 表示登录失败。
	ErrInvalidCredentials = errs.New("cas: invalid credentials | cas：凭据无效")
	// ErrPrincipalMissing reports a ticket without a usable principal. | ErrPrincipalMissing 表示票据没有可用的主体。
	ErrPrincipalMissing = errs.New("cas: principal missing | cas：主体缺失")
	// ErrClientRequest reports a failed client HTTP exchange. | ErrClientRequest 表示客户端 HTTP 交换失败。
	ErrClientRequest = errs.New("cas: client request failed | cas：客户端请求失败")
	// ErrInvalidResponse reports a protocol response that cannot be parsed. | ErrInvalidResponse 表示无法解析的协议响应。
	ErrInvalidResponse = errs.New("cas: invalid protocol response | cas：协议响应非法")
	// ErrUnsupportedProtocol reports a protocol version the client cannot speak. | ErrUnsupportedProtocol 表示客户端不支持的协议版本。
	ErrUnsupportedProtocol = errs.New("cas: unsupported protocol version | cas：不支持的协议版本")
	// ErrInvalidLogoutRequest reports a malformed, oversized or unauthenticated SAML logout request. |
	// ErrInvalidLogoutRequest 表示格式错误、超大或未经认证的 SAML 登出请求。
	ErrInvalidLogoutRequest = errs.New("cas: invalid logout request | cas：登出请求非法")
	// ErrInvalidLogoutSignature reports a missing, unverifiable or invalid XML signature on a SAML
	// LogoutRequest. | ErrInvalidLogoutSignature 表示 SAML LogoutRequest 缺少、无法校验或包含无效的
	// XML 签名。
	ErrInvalidLogoutSignature = errs.New("cas: invalid logout request signature | cas：登出请求签名无效")
	// ErrLogoutDelivery reports a failed back-channel logout delivery. | ErrLogoutDelivery 表示后端登出投递失败。
	ErrLogoutDelivery = errs.New("cas: logout delivery failed | cas：登出投递失败")
	// ErrSessionNotFound reports an unknown service session. | ErrSessionNotFound 表示服务会话不存在。
	ErrSessionNotFound = errs.New("cas: service session not found | cas：服务会话不存在")
)

// TicketType names a CAS ticket class. | TicketType 命名 CAS 票据类别。
type TicketType string

// The supported ticket classes. | 支持的票据类别。
const (
	// TicketTGT is a Ticket Granting Ticket. | TicketTGT 是票据授予票据。
	TicketTGT TicketType = "TGT"
	// TicketST is a Service Ticket. | TicketST 是服务票据。
	TicketST TicketType = "ST"
	// TicketPGT is a Proxy Granting Ticket. | TicketPGT 是代理授予票据。
	TicketPGT TicketType = "PGT"
	// TicketPT is a Proxy Ticket. | TicketPT 是代理票据。
	TicketPT TicketType = "PT"
)

// Prefix returns the protocol identifier prefix of t, or an empty string for an unknown type. |
// Prefix 返回 t 的协议标识前缀；未知类型返回空串。
func (t TicketType) Prefix() string {
	switch t {
	case TicketTGT:
		return TicketPrefixTGT
	case TicketST:
		return TicketPrefixST
	case TicketPGT:
		return TicketPrefixPGT
	case TicketPT:
		return TicketPrefixPT
	}
	return ""
}

// NewTicketID returns a fresh opaque ticket identifier carrying the prefix of typ. | NewTicketID
// 返回携带 typ 前缀的新的不透明票据标识。
//
// The random part is 24 bytes of operating-system entropy encoded as unpadded base64url, which is
// equivalent to 192 bits and far beyond brute-force reach. | 随机部分为 24 字节操作系统熵的免填充
// base64url 编码，相当于 192 位，远超暴力破解范围。
func NewTicketID(typ TicketType) (string, error) {
	prefix := typ.Prefix()
	if prefix == "" {
		return "", errs.Detail(ErrTicketTypeMismatch, "unknown ticket type %[1]q | 未知票据类型 %[1]q", string(typ))
	}
	token, err := auth.RandomToken(24)
	if err != nil {
		return "", errs.Wrap(err, ErrTicketGeneration)
	}
	return prefix + token, nil
}

// Ticket is one server-side CAS ticket record. | Ticket 是一条服务端 CAS 票据记录。
//
// The record is immutable once saved except for ConsumedAt, which the store updates atomically when
// a single-use ticket is consumed. | 记录保存后不可变，只有 ConsumedAt 会在一次性票据被原子消费时由
// 存储更新。
type Ticket struct {
	// IssuedAt is when the ticket was created. | IssuedAt 是票据创建时间。
	IssuedAt time.Time
	// ExpiresAt is the deadline after which the ticket is invalid. | ExpiresAt 是票据失效的截止时间。
	ExpiresAt time.Time
	// ConsumedAt is non-zero once the ticket has been used. | ConsumedAt 在票据被使用后非零。
	ConsumedAt time.Time
	// Principal is the authentication snapshot used to answer validations. | Principal 是用于回答校验的认证快照。
	Principal *auth.Principal
	// ID is the full protocol identifier including the TGT-/ST-/PGT-/PT- prefix. | ID 是包含 TGT-/ST-/PGT-/PT- 前缀的完整协议标识。
	ID string
	// Type is the ticket class. | Type 是票据类别。
	Type TicketType
	// UserID is the authenticated account identifier. | UserID 是已认证账号标识。
	UserID string
	// Service is the URL the ticket is bound to. For a PGT it is the pgtUrl callback URL. |
	// Service 是票据绑定的 URL；对 PGT 而言是 pgtUrl 回调 URL。
	Service string
	// ParentID is the identifier of the ticket that produced this one. | ParentID 是签发本票据的上级票据标识。
	ParentID string
	// RootTGTID is the TGT at the root of the ticket family. | RootTGTID 是票据族根部的 TGT。
	RootTGTID string
	// ProxyChain lists the pgtUrl of every proxy traversed so far. | ProxyChain 列出已经过的每个代理 pgtUrl。
	ProxyChain []string
	// Renewal reports that the ticket descends from a forced re-authentication. | Renewal 表示票据源自强制重新认证。
	Renewal bool
	// RememberMe reports that the user asked for a persistent login. | RememberMe 表示用户请求持久登录。
	RememberMe bool
}

// Clone returns a deep copy of t. | Clone 返回 t 的深拷贝。
func (t *Ticket) Clone() *Ticket {
	if t == nil {
		return nil
	}
	c := *t
	c.Principal = t.Principal.Clone()
	c.ProxyChain = append([]string(nil), t.ProxyChain...)
	return &c
}

// Consumed reports whether the ticket has already been used. | Consumed 报告票据是否已被使用。
func (t *Ticket) Consumed() bool { return t != nil && !t.ConsumedAt.IsZero() }

// Active reports whether the ticket may be used at now. | Active 报告票据在 now 时刻是否可用。
func (t *Ticket) Active(now time.Time) bool {
	return t.ActiveWithSkew(now, 0)
}

// ActiveWithSkew is Active with a tolerance for clock skew. A non-zero skew extends the effective
// deadline by skew. | ActiveWithSkew 是带时钟偏移容忍的 Active。非零 skew 把有效期限延长 skew。
func (t *Ticket) ActiveWithSkew(now time.Time, skew time.Duration) bool {
	if t == nil || t.ID == "" || t.Consumed() {
		return false
	}
	return now.Before(t.ExpiresAt.Add(skew))
}

// TicketStore persists tickets for a Server. | TicketStore 为 Server 持久化票据。
//
// Implementations must make Consume atomic so two concurrent validations of the same single-use
// ticket cannot both succeed, and must never return internal pointers that a caller could mutate. |
// 实现必须保证 Consume 的原子性，使同一一次性票据的并发校验不会同时成功，并且绝不返回调用方可修改的
// 内部指针。
type TicketStore interface {
	// Save stores ticket, replacing any record with the same identifier. | Save 保存 ticket，替换相同标识的记录。
	Save(ctx context.Context, ticket *Ticket) error
	// Get returns a ticket by identifier, including expired and consumed records. | Get 按标识返回票据，包含已过期与已消费记录。
	Get(ctx context.Context, id string) (*Ticket, error)
	// Consume atomically checks typ, expiry and single-use state, then marks the ticket used. It
	// returns ErrTicketNotFound, ErrTicketTypeMismatch, ErrTicketExpired or ErrTicketUsed when the
	// ticket cannot be consumed. | Consume 原子检查 typ、有效期与单次使用状态，然后标记已用。无法消费时
	// 返回 ErrTicketNotFound、ErrTicketTypeMismatch、ErrTicketExpired 或 ErrTicketUsed。
	Consume(ctx context.Context, id string, typ TicketType, now time.Time) (*Ticket, error)
	// Delete removes one ticket; deleting an absent ticket succeeds. | Delete 删除一张票据；删除不存在的票据视为成功。
	Delete(ctx context.Context, id string) error
	// DeleteByRootTGT removes a TGT and every ticket derived from it. | DeleteByRootTGT 删除 TGT 及其派生的全部票据。
	DeleteByRootTGT(ctx context.Context, tgtID string) (int, error)
	// DeleteByUser removes every ticket of a user. | DeleteByUser 删除用户的全部票据。
	DeleteByUser(ctx context.Context, userID string) (int, error)
	// DeleteExpired removes tickets whose deadline passed at now. | DeleteExpired 删除在 now 时刻已过期限的票据。
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
	// ListByService returns every ticket currently bound to service. | ListByService 返回当前绑定到 service 的全部票据。
	ListByService(ctx context.Context, service string) ([]*Ticket, error)
	// ListByRootTGT returns the TGT and every derived ticket. | ListByRootTGT 返回 TGT 及其派生的全部票据。
	ListByRootTGT(ctx context.Context, tgtID string) ([]*Ticket, error)
}

// MemoryTicketStore is an in-memory TicketStore safe for concurrent use. | MemoryTicketStore 是并发安全的内存 TicketStore。
//
// Records live in the process; a multi-node CAS deployment must provide a shared implementation of
// TicketStore. StartGC runs a background janitor that removes expired records; Close stops it. |
// 记录仅存在于进程内；多节点 CAS 部署必须提供共享的 TicketStore 实现。StartGC 运行删除过期记录的后台
// 清理器；Close 停止它。
type MemoryTicketStore struct {
	tickets map[string]*Ticket
	bySvc   map[string]map[string]struct{}
	byRoot  map[string]map[string]struct{}
	byUser  map[string]map[string]struct{}
	stopCh  chan struct{}
	doneCh  chan struct{}
	clock   func() time.Time
	// mu guards every field below. | mu 保护下面的每个字段。
	mu       sync.Mutex
	stopped  bool
	gcActive bool
}

// NewMemoryTicketStore returns an empty memory store. | NewMemoryTicketStore 返回空的内存存储。
func NewMemoryTicketStore() *MemoryTicketStore {
	return &MemoryTicketStore{
		tickets: make(map[string]*Ticket),
		bySvc:   make(map[string]map[string]struct{}),
		byRoot:  make(map[string]map[string]struct{}),
		byUser:  make(map[string]map[string]struct{}),
		clock:   func() time.Time { return time.Now().UTC() },
	}
}

// SetClock replaces the time source used by the janitor; it is intended for deterministic tests. |
// SetClock 替换清理器使用的时间源；用于确定性测试。
func (s *MemoryTicketStore) SetClock(clock func() time.Time) {
	if clock == nil {
		return
	}
	s.mu.Lock()
	s.clock = clock
	s.mu.Unlock()
}

// Save stores a deep copy of ticket. | Save 保存 ticket 的深拷贝。
func (s *MemoryTicketStore) Save(_ context.Context, ticket *Ticket) error {
	if ticket == nil || ticket.ID == "" {
		return errs.Detail(ErrInvalidRequest, "ticket is nil or has no id | 票据为空或缺少 ID")
	}
	stored := ticket.Clone()
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.tickets[stored.ID]; ok {
		s.untrackLocked(old)
	}
	s.tickets[stored.ID] = stored
	s.trackLocked(stored)
	return nil
}

// Get returns a copy of the ticket with the given identifier. | Get 返回指定标识票据的副本。
func (s *MemoryTicketStore) Get(_ context.Context, id string) (*Ticket, error) {
	if id == "" {
		return nil, ErrTicketNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ticket, ok := s.tickets[id]
	if !ok || !secureCompare(ticket.ID, id) {
		return nil, ErrTicketNotFound
	}
	return ticket.Clone(), nil
}

// Consume atomically marks a single-use ticket used and returns a copy of it. | Consume 原子地把一次性票据标记为已用并返回其副本。
func (s *MemoryTicketStore) Consume(_ context.Context, id string, typ TicketType, now time.Time) (*Ticket, error) {
	if id == "" {
		return nil, ErrTicketNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ticket, ok := s.tickets[id]
	if !ok || !secureCompare(ticket.ID, id) {
		return nil, ErrTicketNotFound
	}
	if typ != "" && ticket.Type != typ {
		return nil, errs.Detail(ErrTicketTypeMismatch, "want %[1]s, got %[2]s | 期望 %[1]s，实际 %[2]s", string(typ), string(ticket.Type))
	}
	if ticket.Consumed() {
		return nil, errs.Detail(ErrTicketUsed, "ticket consumed | 票据已消费")
	}
	if !now.Before(ticket.ExpiresAt) {
		return nil, errs.Detail(ErrTicketExpired, "ticket deadline passed | 票据期限已过")
	}
	ticket.ConsumedAt = now.UTC()
	return ticket.Clone(), nil
}

// Delete removes one ticket. | Delete 删除一张票据。
func (s *MemoryTicketStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteLocked(id)
	return nil
}

// deleteLocked removes id and its index entries; the caller must hold mu. | deleteLocked 删除 id
// 及其索引项；调用方必须持有 mu。
func (s *MemoryTicketStore) deleteLocked(id string) {
	if ticket, ok := s.tickets[id]; ok {
		s.untrackLocked(ticket)
		delete(s.tickets, id)
	}
}

// DeleteByRootTGT removes a TGT and every derived ticket. | DeleteByRootTGT 删除 TGT 及其派生的全部票据。
func (s *MemoryTicketStore) DeleteByRootTGT(_ context.Context, tgtID string) (int, error) {
	if tgtID == "" {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.byRoot[tgtID]))
	for id := range s.byRoot[tgtID] {
		ids = append(ids, id)
	}
	for _, id := range ids {
		s.deleteLocked(id)
	}
	return len(ids), nil
}

// DeleteByUser removes every ticket of a user. | DeleteByUser 删除用户的全部票据。
func (s *MemoryTicketStore) DeleteByUser(_ context.Context, userID string) (int, error) {
	if userID == "" {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.byUser[userID]))
	for id := range s.byUser[userID] {
		ids = append(ids, id)
	}
	for _, id := range ids {
		s.deleteLocked(id)
	}
	return len(ids), nil
}

// DeleteExpired removes tickets whose deadline passed at now. | DeleteExpired 删除在 now 时刻已过期限的票据。
func (s *MemoryTicketStore) DeleteExpired(_ context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0)
	for id, ticket := range s.tickets {
		if !now.Before(ticket.ExpiresAt) {
			ids = append(ids, id)
		}
	}
	for _, id := range ids {
		s.deleteLocked(id)
	}
	return len(ids), nil
}

// ListByService returns every ticket bound to service. | ListByService 返回绑定到 service 的全部票据。
func (s *MemoryTicketStore) ListByService(_ context.Context, service string) ([]*Ticket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.collectLocked(s.bySvc[service]), nil
}

// ListByRootTGT returns the TGT and every ticket derived from it. | ListByRootTGT 返回 TGT 及其派生的全部票据。
func (s *MemoryTicketStore) ListByRootTGT(_ context.Context, tgtID string) ([]*Ticket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.collectLocked(s.byRoot[tgtID]), nil
}

// collectLocked clones the tickets named by set and sorts them by issue time. | collectLocked
// 克隆 set 指定的票据并按签发时间排序。
func (s *MemoryTicketStore) collectLocked(set map[string]struct{}) []*Ticket {
	if len(set) == 0 {
		return nil
	}
	out := make([]*Ticket, 0, len(set))
	for id := range set {
		if ticket, ok := s.tickets[id]; ok {
			out = append(out, ticket.Clone())
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IssuedAt.Equal(out[j].IssuedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].IssuedAt.Before(out[j].IssuedAt)
	})
	return out
}

// trackLocked adds the index entries of ticket; the caller must hold mu. | trackLocked 添加 ticket
// 的索引项；调用方必须持有 mu。
func (s *MemoryTicketStore) trackLocked(ticket *Ticket) {
	if ticket.Service != "" {
		addIndex(s.bySvc, ticket.Service, ticket.ID)
	}
	if ticket.RootTGTID != "" {
		addIndex(s.byRoot, ticket.RootTGTID, ticket.ID)
	}
	if ticket.UserID != "" {
		addIndex(s.byUser, ticket.UserID, ticket.ID)
	}
}

// untrackLocked removes the index entries of ticket; the caller must hold mu. | untrackLocked
// 移除 ticket 的索引项；调用方必须持有 mu。
func (s *MemoryTicketStore) untrackLocked(ticket *Ticket) {
	if ticket.Service != "" {
		removeIndex(s.bySvc, ticket.Service, ticket.ID)
	}
	if ticket.RootTGTID != "" {
		removeIndex(s.byRoot, ticket.RootTGTID, ticket.ID)
	}
	if ticket.UserID != "" {
		removeIndex(s.byUser, ticket.UserID, ticket.ID)
	}
}

// addIndex inserts id into index[key]. | addIndex 把 id 插入 index[key]。
func addIndex(index map[string]map[string]struct{}, key, id string) {
	set := index[key]
	if set == nil {
		set = make(map[string]struct{})
		index[key] = set
	}
	set[id] = struct{}{}
}

// removeIndex removes id from index[key] and the empty key. | removeIndex 从 index[key] 移除 id，并清理空键。
func removeIndex(index map[string]map[string]struct{}, key, id string) {
	set, ok := index[key]
	if !ok {
		return
	}
	delete(set, id)
	if len(set) == 0 {
		delete(index, key)
	}
}

// StartGC starts the expiry janitor. Repeated calls are ignored, and a store that was stopped stays
// stopped. The goroutine exits when Close or Stop is called. | StartGC 启动过期清理器。重复调用会被
// 忽略，已停止的存储保持停止。goroutine 在调用 Close 或 Stop 时退出。
func (s *MemoryTicketStore) StartGC(interval time.Duration) {
	if interval <= 0 {
		interval = DefaultTicketStoreGCInterval
	}
	s.mu.Lock()
	if s.stopped || s.gcActive {
		s.mu.Unlock()
		return
	}
	s.gcActive = true
	s.stopCh = make(chan struct{})
	s.doneCh = make(chan struct{})
	stop, done := s.stopCh, s.doneCh
	s.mu.Unlock()
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				s.mu.Lock()
				now := s.clock()
				s.mu.Unlock()
				_, _ = s.DeleteExpired(context.Background(), now)
			}
		}
	}()
}

// Stop terminates the janitor and waits for it to exit. It is safe to call more than once. | Stop
// 终止清理器并等待其退出。可以安全地多次调用。
func (s *MemoryTicketStore) Stop() {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	stop, done := s.stopCh, s.doneCh
	if stop != nil {
		close(stop)
	}
	s.mu.Unlock()
	if done != nil {
		<-done
	}
}

// Close stops the janitor and implements io.Closer. | Close 停止清理器并实现 io.Closer。
func (s *MemoryTicketStore) Close() error {
	s.Stop()
	return nil
}

// Len returns the number of stored tickets. | Len 返回已存票据数量。
func (s *MemoryTicketStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tickets)
}
