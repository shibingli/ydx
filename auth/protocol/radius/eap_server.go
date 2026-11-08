package radius

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/errs"
)

// DefaultEndpointTimeout is the default EAP session lifetime. | DefaultEndpointTimeout 是 EAP 会话的
// 默认有效期。
const DefaultEndpointTimeout = 30 * time.Second

// DefaultEAPMaxSessions is the default number of concurrent EAP sessions. | DefaultEAPMaxSessions 是
// 并发 EAP 会话的默认上限。
const DefaultEAPMaxSessions = 4096

// DefaultEAPFragmentSize is the default maximum number of TLS bytes carried by one EAP Request. |
// DefaultEAPFragmentSize 是单个 EAP Request 承载的 TLS 字节默认上限。
const DefaultEAPFragmentSize = 3000

// EAPPhase is the internal state-machine phase of an EAP session. | EAPPhase 是 EAP 会话的内部状态机
// 阶段。
type EAPPhase uint8

// EAP session phases. | EAP 会话阶段。
const (
	// EAPPhaseAwaitIdentity waits for an EAP Response/Identity. | EAPPhaseAwaitIdentity 等待 EAP Response/Identity。
	EAPPhaseAwaitIdentity EAPPhase = iota
	// EAPPhaseMethodChallenge waits for the peer's response to a method challenge. | EAPPhaseMethodChallenge 等待对端对方法挑战的响应。
	EAPPhaseMethodChallenge
	// EAPPhaseMSCHAPv2Success waits for the peer to acknowledge MS-CHAPv2 Success. | EAPPhaseMSCHAPv2Success 等待对端确认 MS-CHAPv2 Success。
	EAPPhaseMSCHAPv2Success
	// EAPPhaseTLSHandshake drives a TLS handshake. | EAPPhaseTLSHandshake 驱动 TLS 握手。
	EAPPhaseTLSHandshake
	// EAPPhaseTLSComplete waits for the final EAP-TLS acknowledgement. | EAPPhaseTLSComplete 等待最终的 EAP-TLS 确认。
	EAPPhaseTLSComplete
	// EAPPhaseTTLSPhase2 authenticates inside an EAP-TTLS tunnel. | EAPPhaseTTLSPhase2 在 EAP-TTLS 隧道内认证。
	EAPPhaseTTLSPhase2
	// EAPPhaseTTLSSuccess waits for the peer to acknowledge inner TTLS success. | EAPPhaseTTLSSuccess 等待对端确认 TTLS 内部成功。
	EAPPhaseTTLSSuccess
	// EAPPhasePEAPIdentity requests and receives the inner PEAP identity. | EAPPhasePEAPIdentity 请求并接收 PEAP 内部身份。
	EAPPhasePEAPIdentity
	// EAPPhasePEAPMSCHAPv2 authenticates with EAP-MSCHAPv2 inside PEAP. | EAPPhasePEAPMSCHAPv2 在 PEAP 内用 EAP-MSCHAPv2 认证。
	EAPPhasePEAPMSCHAPv2
	// EAPPhasePEAPSuccess waits for the peer to acknowledge the inner PEAP success. | EAPPhasePEAPSuccess 等待对端确认 PEAP 内部成功。
	EAPPhasePEAPSuccess
	// EAPPhaseComplete marks a completed session. | EAPPhaseComplete 标记已完成的会话。
	EAPPhaseComplete
)

// EAPServerConfig configures an EAPServer. | EAPServerConfig 配置 EAPServer。
//
// EAPServer implements AccessAuthenticator, so it can be passed directly to
// AccessServerConfig.Authenticator. It negotiates EAP-MD5, EAP-MSCHAPv2, EAP-TLS, EAP-TTLS and
// PEAPv0, generates Access-Challenge state, enforces session timeouts and bounds concurrent sessions.
// | EAPServer 实现 AccessAuthenticator，因此可直接传给 AccessServerConfig.Authenticator。它协商
// EAP-MD5、EAP-MSCHAPv2、EAP-TLS、EAP-TTLS 与 PEAPv0，生成 Access-Challenge 状态，强制会话超时，
// 并限制并发会话数。
type EAPServerConfig struct {
	// Password resolves cleartext passwords for EAP-MD5, EAP-MSCHAPv2, EAP-TTLS PAP,
	// EAP-TTLS MS-CHAPv2 and PEAPv0 inner EAP-MSCHAPv2. It is required for those methods. | Password
	// 为 EAP-MD5、EAP-MSCHAPv2、EAP-TTLS PAP、EAP-TTLS MS-CHAPv2 与 PEAPv0 内部 EAP-MSCHAPv2 解析
	// 明文口令。这些方法需要该字段。
	Password EAPPasswordLookup
	// TLSConfig configures the server certificate for EAP-TLS, EAP-TTLS and PEAPv0. The server clones
	// it and enforces TLS 1.2 as the minimum version when MinVersion is zero. Client certificate
	// policy and VerifyPeerCertificate callbacks are honored as configured. | TLSConfig 为 EAP-TLS、
	// EAP-TTLS 与 PEAPv0 配置服务器证书。服务器会克隆它，并在 MinVersion 为零时强制最低 TLS 1.2。
	// 客户端证书策略与 VerifyPeerCertificate 回调按配置生效。
	TLSConfig *tls.Config
	// IdentityFromCertificate extracts the authenticated identity from a verified peer certificate
	// for EAP-TLS; nil uses the subject CommonName, then the first DNS name. | IdentityFromCertificate
	// 从 EAP-TLS 已校验的对端证书提取认证身份；nil 依次使用主题 CommonName 与首个 DNS 名。
	IdentityFromCertificate func(certificate *x509.Certificate) string
	// Methods is the ordered list of offered EAP methods. Nil selects EAP-TLS, PEAP, EAP-TTLS,
	// EAP-MSCHAPv2 and EAP-MD5 when their prerequisites are configured. The peer may select a later
	// configured method with an EAP Nak. | Methods 是按序提供的 EAP 方法列表。nil 时按已配置前提
	// 选择 EAP-TLS、PEAP、EAP-TTLS、EAP-MSCHAPv2 与 EAP-MD5。对端可用 EAP Nak 选择列表中靠后的
	// 已配置方法。
	Methods []EAPType
	// Timeout bounds one EAP conversation; zero selects DefaultEndpointTimeout. | Timeout 约束一次
	// EAP 交互；零值选择 DefaultEndpointTimeout。
	Timeout time.Duration
	// MaxSessions is the maximum number of concurrent EAP conversations; zero selects
	// DefaultEAPMaxSessions. | MaxSessions 是并发 EAP 交互上限；零值选择 DefaultEAPMaxSessions。
	MaxSessions int
	// FragmentSize is the maximum number of TLS bytes carried by one EAP Request; zero selects
	// DefaultEAPFragmentSize. It must be positive and may be reduced to exercise fragmentation. |
	// FragmentSize 是单个 EAP Request 承载的 TLS 字节上限；零值选择 DefaultEAPFragmentSize。必须为
	// 正数，可调低以测试分片。
	FragmentSize int
	// RequireClientCertificate rejects EAP-TLS, EAP-TTLS and PEAP handshakes without a verified client
	// certificate. TLSConfig.ClientAuth is also honored. | RequireClientCertificate 拒绝未携带已校验
	// 客户端证书的 EAP-TLS、EAP-TTLS 与 PEAP 握手。TLSConfig.ClientAuth 同样生效。
	RequireClientCertificate bool
	// TTLSInnerMethods is the ordered list of accepted EAP-TTLS phase-2 methods. Nil selects
	// EAP-MSCHAPv2 and PAP when Password is set. Only EAPTypeMSCHAPv2 and EAPTypeIdentity (PAP) are
	// valid. | TTLSInnerMethods 是接受的 EAP-TTLS 第二阶段方法列表。nil 时在 Password 设置的情况下
	// 选择 EAP-MSCHAPv2 与 PAP。仅 EAPTypeMSCHAPv2 与 EAPTypeIdentity（PAP）有效。
	TTLSInnerMethods []EAPType
}

// EAPServer is a concurrency-safe EAP authenticator and AccessAuthenticator. | EAPServer 是并发安全的
// EAP 认证器与 AccessAuthenticator。
//
// It maintains one session per RADIUS State value, generates fresh EAP identifiers for every
// Request, caches the response to a retransmitted EAP Identifier, expires idle sessions after Timeout
// and evicts the oldest session when MaxSessions is reached. | 它按 RADIUS State 值维护会话，为每个
// Request 生成新的 EAP 标识符，缓存对重传 EAP Identifier 的响应，在 Timeout 后使空闲会话过期，并在
// 达到 MaxSessions 时淘汰最旧会话。
type EAPServer struct {
	password      EAPPasswordLookup
	tlsConfig     *tls.Config
	identity      func(*x509.Certificate) string
	methods       []EAPType
	ttlsMethods   []EAPType
	timeout       time.Duration
	maxSessions   int
	fragmentSize  int
	requireClient bool

	mu       sync.Mutex
	sessions map[string]*eapSession
	order    []string
	closed   bool
}

// eapSession is one EAP conversation. | eapSession 是一次 EAP 交互。
type eapSession struct {
	server       *EAPServer
	state        []byte
	username     string
	identity     string
	method       EAPType
	phase        EAPPhase
	challenge    []byte
	mschapIdent  uint8
	tls          *eapTLSEngine
	tlsAssembler eapTLSReassembler
	tlsQueue     []eapTLSFragment
	tlsMethod    EAPType
	tlsDone      bool
	tlsPost      bool
	mschapKeys   *MSCHAPv2ServerResult
	successValue []byte
	inner        *eapTTLSState
	peap         *eapPEAPState
	cache        map[uint8]*AccessServerResult
	requestID    uint8
	expiresNano  atomic.Int64
	completed    bool
	closed       bool
	mu           sync.Mutex
}

// setExpiry records the session deadline. It is safe under either the session lock or the server
// lock because the deadline is consulted from both lock domains. | setExpiry 记录会话截止时间。
// 截止时间会从两个锁域读取，因此使用原子写入以保证在会话锁或服务器锁下均安全。
func (s *eapSession) setExpiry(deadline time.Time) {
	s.expiresNano.Store(deadline.UnixNano())
}

// expired reports whether now is past the session deadline. | expired 报告 now 是否超过会话截止时间。
func (s *eapSession) expired(now time.Time) bool {
	return now.UnixNano() > s.expiresNano.Load()
}

// NewEAPServer validates config and returns an EAP server. | NewEAPServer 校验 config 并返回 EAP 服务器。
func NewEAPServer(config EAPServerConfig) (*EAPServer, error) {
	if config.Timeout < 0 {
		return nil, errs.Detail(ErrInvalidConfig, "EAP timeout must not be negative")
	}
	if config.Timeout == 0 {
		config.Timeout = DefaultEndpointTimeout
	}
	if config.MaxSessions < 0 {
		return nil, errs.Detail(ErrInvalidConfig, "EAP max sessions must not be negative")
	}
	if config.MaxSessions == 0 {
		config.MaxSessions = DefaultEAPMaxSessions
	}
	if config.FragmentSize < 0 {
		return nil, errs.Detail(ErrInvalidConfig, "EAP fragment size must not be negative")
	}
	if config.FragmentSize == 0 {
		config.FragmentSize = DefaultEAPFragmentSize
	}
	methods := config.Methods
	if len(methods) == 0 {
		methods = defaultEAPMethods(config)
	}
	if len(methods) == 0 {
		return nil, errs.Detail(ErrInvalidConfig, "no EAP method is available; configure Password, TLSConfig or Methods")
	}
	for _, method := range methods {
		if err := validateEAPMethod(method, config); err != nil {
			return nil, err
		}
	}
	if config.TLSConfig != nil {
		config.TLSConfig = config.TLSConfig.Clone()
		if config.TLSConfig.MinVersion == 0 {
			config.TLSConfig.MinVersion = tls.VersionTLS12
		}
		if config.RequireClientCertificate &&
			(config.TLSConfig.ClientAuth == tls.NoClientCert || config.TLSConfig.ClientAuth == 0) {
			config.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}
	ttlsMethods := config.TTLSInnerMethods
	if len(ttlsMethods) == 0 && config.Password != nil {
		ttlsMethods = []EAPType{EAPTypeMSCHAPv2, EAPTypeIdentity}
	}
	for _, method := range ttlsMethods {
		if method != EAPTypeMSCHAPv2 && method != EAPTypeIdentity {
			return nil, errs.Detail(ErrInvalidConfig, "unsupported EAP-TTLS inner method %d", uint8(method))
		}
		if config.Password == nil {
			return nil, errs.Detail(ErrInvalidConfig, "EAP-TTLS inner methods require Password")
		}
	}
	return &EAPServer{
		password:      config.Password,
		tlsConfig:     config.TLSConfig,
		identity:      config.IdentityFromCertificate,
		methods:       append([]EAPType(nil), methods...),
		ttlsMethods:   append([]EAPType(nil), ttlsMethods...),
		timeout:       config.Timeout,
		maxSessions:   config.MaxSessions,
		fragmentSize:  config.FragmentSize,
		requireClient: config.RequireClientCertificate,
		sessions:      make(map[string]*eapSession, config.MaxSessions),
	}, nil
}

// defaultEAPMethods selects methods whose prerequisites are configured. | defaultEAPMethods 选择前提
// 已配置的方法。
func defaultEAPMethods(config EAPServerConfig) []EAPType {
	var methods []EAPType
	if config.TLSConfig != nil {
		methods = append(methods, EAPTypeTLS, EAPTypePEAP, EAPTypeTTLS)
	}
	if config.Password != nil {
		methods = append(methods, EAPTypeMSCHAPv2, EAPTypeMD5)
	}
	return methods
}

// validateEAPMethod verifies that a configured method has its prerequisites. | validateEAPMethod 校验
// 配置的方法具备前提。
func validateEAPMethod(method EAPType, config EAPServerConfig) error {
	switch method {
	case EAPTypeMD5, EAPTypeMSCHAPv2:
		if config.Password == nil {
			return errs.Detail(ErrInvalidConfig, "EAP method %d requires Password", uint8(method))
		}
	case EAPTypeTLS, EAPTypeTTLS, EAPTypePEAP:
		if config.TLSConfig == nil {
			return errs.Detail(ErrInvalidConfig, "EAP method %d requires TLSConfig", uint8(method))
		}
	case EAPTypeIdentity, EAPTypeNotification, EAPTypeNak, EAPTypeExpanded:
		return errs.Detail(ErrInvalidConfig, "EAP method %d cannot be offered by the server", uint8(method))
	default:
		return errs.Detail(ErrInvalidConfig, "unsupported EAP method %d", uint8(method))
	}
	return nil
}

// AuthenticateAccess implements AccessAuthenticator. | AuthenticateAccess 实现 AccessAuthenticator。
func (s *EAPServer) AuthenticateAccess(ctx context.Context, request *AccessServerRequest) (*AccessServerResult, error) {
	if s == nil {
		return nil, errs.Detail(ErrInvalidConfig, "EAP server is nil")
	}
	if request == nil {
		return nil, errs.Detail(ErrInvalidRequest, "access request is nil")
	}
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	packet := request.EAPPacket
	if len(request.State) == 0 {
		return s.startConversation(ctx, request, packet)
	}
	session, err := s.lookupSession(request.State)
	if err != nil {
		return s.failureWithoutSession(request, nil, MSCHAPv2FailureMalformed)
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return nil, ErrServerClosed
	}
	if packet == nil {
		return s.failureLocked(session, request.Identifier, 0)
	}
	if cached := session.cache[packet.Identifier]; cached != nil {
		return cloneAccessServerResult(cached), nil
	}
	if session.phase == EAPPhaseComplete {
		return s.failureLocked(session, packet.Identifier, 0)
	}
	if packet.Identifier != session.requestID {
		return s.failureLocked(session, packet.Identifier, 0)
	}
	result, err := s.processPacketLocked(ctx, session, request, packet)
	if err != nil {
		if ctxErr(ctx) != nil {
			return nil, err
		}
		return s.failureLocked(session, packet.Identifier, 0)
	}
	session.setExpiry(time.Now().Add(s.timeout))
	s.cacheLocked(session, packet.Identifier, result)
	return result, nil
}

// startConversation creates a session for a new Access-Request. | startConversation 为新 Access-Request
// 创建会话。
func (s *EAPServer) startConversation(ctx context.Context, request *AccessServerRequest, packet *EAPPacket) (*AccessServerResult, error) {
	if packet != nil {
		if packet.Code != EAPCodeResponse {
			return s.failureWithoutSession(request, packet, MSCHAPv2FailureMalformed)
		}
		if packet.Type != EAPTypeIdentity {
			return s.failureWithoutSession(request, packet, MSCHAPv2FailureMalformed)
		}
	}
	session, err := s.newSession(request.UserName)
	if err != nil {
		return nil, err
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return nil, ErrServerClosed
	}
	if packet == nil {
		identifier := session.nextIdentifier()
		session.phase = EAPPhaseAwaitIdentity
		session.requestID = identifier
		return s.requestResultLocked(session, EAPTypeIdentity, nil, identifier)
	}
	identity, err := EAPResponseIdentity(packet)
	if err != nil {
		return s.failureLocked(session, packet.Identifier, 0)
	}
	session.identity = identity
	if session.username == "" {
		session.username = identity
	}
	session.phase = EAPPhaseMethodChallenge
	// The peer's Identity Response carries the Identifier of the Request it answered. The first
	// method Request must use a fresh Identifier so its retransmission cache cannot collide with
	// that Response. | 对端 Identity Response 携带其所应答 Request 的 Identifier。首个方法 Request
	// 必须使用新 Identifier，避免其重传缓存与该 Response 冲突。
	session.requestID = packet.Identifier
	result, err := s.startMethodLocked(ctx, session, s.methods[0], request)
	if err != nil {
		return nil, err
	}
	s.cacheLocked(session, packet.Identifier, result)
	return result, nil
}

// newSession allocates and registers a session. | newSession 分配并注册会话。
func (s *EAPServer) newSession(userName string) (*eapSession, error) {
	state := make([]byte, 32)
	if _, err := rand.Read(state); err != nil {
		return nil, errs.Wrap(err, ErrInternal)
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrServerClosed
	}
	s.pruneLocked(now)
	if len(s.sessions) >= s.maxSessions {
		s.evictOldestLocked()
	}
	session := &eapSession{
		server:   s,
		state:    state,
		username: userName,
		cache:    make(map[uint8]*AccessServerResult, 4),
	}
	session.setExpiry(now.Add(s.timeout))
	s.sessions[string(state)] = session
	s.order = append(s.order, string(state))
	return session, nil
}

// lookupSession returns the live session for a State value. | lookupSession 返回 State 值对应的活跃会话。
func (s *EAPServer) lookupSession(state []byte) (*eapSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrServerClosed
	}
	key := string(state)
	session, ok := s.sessions[key]
	if !ok {
		return nil, errs.Detail(ErrEAPState, "unknown EAP state")
	}
	if session.expired(time.Now()) {
		s.removeLocked(key)
		return nil, errs.Detail(ErrEAPState, "expired EAP state")
	}
	return session, nil
}

// pruneLocked removes expired sessions. The caller must hold s.mu. | pruneLocked 删除过期会话。调用方
// 必须持有 s.mu。
func (s *EAPServer) pruneLocked(now time.Time) {
	live := s.order[:0]
	for _, key := range s.order {
		session, ok := s.sessions[key]
		if !ok {
			continue
		}
		if session.expired(now) {
			delete(s.sessions, key)
			continue
		}
		live = append(live, key)
	}
	s.order = live
}

// evictOldestLocked removes the oldest session. The caller must hold s.mu. | evictOldestLocked 删除最旧
// 会话。调用方必须持有 s.mu。
func (s *EAPServer) evictOldestLocked() {
	for len(s.order) > 0 {
		key := s.order[0]
		s.order = s.order[1:]
		if _, ok := s.sessions[key]; ok {
			delete(s.sessions, key)
			return
		}
	}
}

// removeLocked removes one session. The caller must hold s.mu. | removeLocked 删除一个会话。调用方必须
// 持有 s.mu。
func (s *EAPServer) removeLocked(key string) {
	delete(s.sessions, key)
	for i, candidate := range s.order {
		if candidate == key {
			s.order = append(s.order[:i], s.order[i+1:]...)
			return
		}
	}
}

// Close discards every EAP session and rejects further authentication. | Close 丢弃全部 EAP 会话并拒绝
// 后续认证。
func (s *EAPServer) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	sessions := make([]*eapSession, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}
	s.sessions = make(map[string]*eapSession)
	s.order = nil
	s.mu.Unlock()
	for _, session := range sessions {
		session.mu.Lock()
		session.closed = true
		engine := session.tls
		session.mu.Unlock()
		if engine != nil {
			engine.close()
		}
	}
	return nil
}

// processPacketLocked dispatches one Response for a live session. The caller must hold session.mu. |
// processPacketLocked 为活跃会话分派一个 Response。调用方必须持有 session.mu。
func (s *EAPServer) processPacketLocked(ctx context.Context, session *eapSession, request *AccessServerRequest, packet *EAPPacket) (*AccessServerResult, error) {
	if packet.Code != EAPCodeResponse {
		return s.failureLocked(session, packet.Identifier, 0)
	}
	if session.phase == EAPPhaseAwaitIdentity {
		identity, err := EAPResponseIdentity(packet)
		if err != nil {
			return s.failureLocked(session, packet.Identifier, 0)
		}
		session.identity = identity
		session.username = identity
		session.phase = EAPPhaseMethodChallenge
		return s.startMethodLocked(ctx, session, s.methods[0], request)
	}
	if packet.Type == EAPTypeNak && session.phase == EAPPhaseMethodChallenge {
		method, ok := s.chooseMethod(packet.Data)
		if !ok {
			return s.failureLocked(session, packet.Identifier, 0)
		}
		if session.tls != nil {
			session.tls.close()
			session.tls = nil
		}
		return s.startMethodLocked(ctx, session, method, request)
	}
	if packet.Type != session.method {
		return s.failureLocked(session, packet.Identifier, 0)
	}
	switch session.method {
	case EAPTypeMD5:
		return s.processMD5Locked(ctx, session, packet)
	case EAPTypeMSCHAPv2:
		return s.processEAPMSCHAPv2Locked(ctx, session, packet)
	case EAPTypeTLS:
		return s.processEAPTLSLocked(ctx, session, packet)
	case EAPTypeTTLS:
		return s.processEAPTTLSLocked(ctx, session, packet)
	case EAPTypePEAP:
		return s.processEAPPEAPLocked(ctx, session, packet)
	default:
		return s.failureLocked(session, packet.Identifier, 0)
	}
}

// chooseMethod selects the first offered method named by an EAP Nak. | chooseMethod 选择 EAP Nak 中
// 命名的首个已提供方法。
func (s *EAPServer) chooseMethod(suggested []byte) (EAPType, bool) {
	for _, candidate := range suggested {
		method := EAPType(candidate)
		for _, offered := range s.methods {
			if offered == method {
				return method, true
			}
		}
	}
	return 0, false
}

// startMethodLocked creates the first method Request. The caller must hold session.mu. | startMethodLocked
// 创建首个方法 Request。调用方必须持有 session.mu。
func (s *EAPServer) startMethodLocked(ctx context.Context, session *eapSession, method EAPType, request *AccessServerRequest) (*AccessServerResult, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	session.method = method
	session.phase = EAPPhaseMethodChallenge
	session.challenge = nil
	session.mschapIdent = 0
	session.mschapKeys = nil
	session.successValue = nil
	session.tlsQueue = nil
	session.tlsAssembler = eapTLSReassembler{}
	session.tlsDone = false
	session.tlsPost = false
	session.inner = nil
	session.peap = nil
	switch method {
	case EAPTypeMD5:
		challenge := make([]byte, 16)
		if _, err := rand.Read(challenge); err != nil {
			return nil, errs.Wrap(err, ErrInternal)
		}
		session.challenge = challenge
		data := make([]byte, 0, 17+len("radius"))
		data = append(data, 16)
		data = append(data, challenge...)
		data = append(data, "radius"...)
		identifier := session.nextIdentifier()
		session.requestID = identifier
		return s.requestResultLocked(session, method, data, identifier)
	case EAPTypeMSCHAPv2:
		challenge, err := GenerateMSCHAPv2Challenge()
		if err != nil {
			return nil, err
		}
		identifier := session.nextIdentifier()
		session.mschapIdent = identifier
		session.challenge = append([]byte(nil), challenge[:]...)
		data := make([]byte, 0, 18+len("radius"))
		data = append(data, 1, identifier)
		data = append(data, challenge[:]...)
		data = append(data, "radius"...)
		session.requestID = identifier
		return s.requestResultLocked(session, method, data, identifier)
	case EAPTypeTLS, EAPTypeTTLS, EAPTypePEAP:
		if s.tlsConfig == nil {
			return s.failureLocked(session, session.requestID, 0)
		}
		engine, err := newEAPTLSEngine(s.tlsConfig)
		if err != nil {
			return nil, err
		}
		session.tls = engine
		session.phase = EAPPhaseTLSHandshake
		session.tlsMethod = method
		identifier := session.nextIdentifier()
		session.requestID = identifier
		start := eapTLSFragment{flags: EAPTLSFlagStart}
		return s.tlsRequestResultLocked(session, method, start, identifier)
	default:
		return s.failureLocked(session, session.requestID, 0)
	}
}

// processMD5Locked verifies EAP-MD5. | processMD5Locked 校验 EAP-MD5。
func (s *EAPServer) processMD5Locked(ctx context.Context, session *eapSession, packet *EAPPacket) (*AccessServerResult, error) {
	if len(packet.Data) < 17 || int(packet.Data[0]) != 16 {
		return s.failureLocked(session, packet.Identifier, 0)
	}
	password, err := lookupEAPPassword(ctx, s.password, session.username)
	if err != nil {
		if isUnknownUser(err) {
			return s.failureLocked(session, packet.Identifier, 0)
		}
		return nil, err
	}
	defer zeroBytes(password)
	digest := md5.New()
	digest.Write([]byte{packet.Identifier})
	digest.Write(password)
	digest.Write(session.challenge)
	expected := digest.Sum(nil)
	defer zeroBytes(expected)
	if len(packet.Data) < 17 || !constantTimeEqual(expected, packet.Data[1:17]) {
		return s.failureLocked(session, packet.Identifier, 0)
	}
	return s.successLocked(session, packet.Identifier, nil, session.username)
}

// processEAPMSCHAPv2Locked verifies an EAP-MSCHAPv2 Response and issues its Success message. |
// processEAPMSCHAPv2Locked 校验 EAP-MSCHAPv2 Response 并发出 Success 消息。
func (s *EAPServer) processEAPMSCHAPv2Locked(ctx context.Context, session *eapSession, packet *EAPPacket) (*AccessServerResult, error) {
	if session.phase == EAPPhaseMSCHAPv2Success {
		if len(packet.Data) != 0 {
			return s.failureLocked(session, packet.Identifier, 0)
		}
		return s.successLocked(session, packet.Identifier, session.mschapKeys, session.username)
	}
	if len(packet.Data) != 52 || packet.Data[0] != 2 {
		return s.failureLocked(session, packet.Identifier, 0)
	}
	radiusResponse := make([]byte, msCHAPv2ResponseLength)
	radiusResponse[0] = packet.Data[1]
	if radiusResponse[0] != session.mschapIdent {
		return s.failureLocked(session, packet.Identifier, MSCHAPv2FailureChallengeMismatch)
	}
	radiusResponse[1] = packet.Data[2]
	copy(radiusResponse[2:18], packet.Data[3:19])
	copy(radiusResponse[18:26], packet.Data[19:27])
	copy(radiusResponse[26:50], packet.Data[27:51])
	defer zeroBytes(radiusResponse)
	password, err := lookupEAPPassword(ctx, s.password, session.username)
	if err != nil {
		if isUnknownUser(err) {
			return s.failureLocked(session, packet.Identifier, MSCHAPv2FailureUnknownUser)
		}
		return nil, err
	}
	defer zeroBytes(password)
	result, err := VerifyMSCHAPv2Server(session.username, string(password), session.challenge, radiusResponse)
	if err != nil {
		return s.failureLocked(session, packet.Identifier, MSCHAPv2FailureMalformed)
	}
	if !result.Succeeded() {
		return s.failureLocked(session, packet.Identifier, result.Failure)
	}
	session.mschapKeys = result
	session.successValue = append([]byte(nil), result.AuthenticatorResponse...)
	identifier := session.nextIdentifier()
	session.requestID = identifier
	session.phase = EAPPhaseMSCHAPv2Success
	responseData := make([]byte, 0, 2+42)
	responseData = append(responseData, 3, packet.Data[1])
	responseData = append(responseData, result.AuthenticatorResponse...)
	return s.requestResultLocked(session, EAPTypeMSCHAPv2, responseData, identifier)
}

// requestResultLocked builds an Access-Challenge carrying one EAP Request. The caller must hold
// session.mu. | requestResultLocked 构建携带一个 EAP Request 的 Access-Challenge。调用方必须持有
// session.mu。
func (s *EAPServer) requestResultLocked(session *eapSession, method EAPType, data []byte, identifier uint8) (*AccessServerResult, error) {
	packet := newEAPRequest(identifier, method, data)
	raw, err := packet.MarshalBinary()
	if err != nil {
		return nil, err
	}
	attributes := Attributes{}
	if err := AppendEAPMessage(&attributes, raw); err != nil {
		return nil, err
	}
	return &AccessServerResult{
		Challenge:  true,
		State:      append([]byte(nil), session.state...),
		Attributes: attributes,
		Identity:   session.identity,
	}, nil
}

// tlsRequestResultLocked builds an Access-Challenge carrying one EAP TLS fragment and queues the
// rest. The caller must hold session.mu. | tlsRequestResultLocked 构建携带一个 EAP TLS 分片的
// Access-Challenge 并排队其余分片。调用方必须持有 session.mu。
func (s *EAPServer) tlsRequestResultLocked(session *eapSession, method EAPType, fragment eapTLSFragment, identifier uint8) (*AccessServerResult, error) {
	return s.requestResultLocked(session, method, fragment.bytes(), identifier)
}

// successLocked builds an EAP-Success Access-Accept. The caller must hold session.mu. | successLocked
// 构建 EAP-Success Access-Accept。调用方必须持有 session.mu。
func (s *EAPServer) successLocked(session *eapSession, identifier uint8, keys *MSCHAPv2ServerResult, identity string) (*AccessServerResult, error) {
	packet := newEAPSuccess(identifier)
	raw, err := packet.MarshalBinary()
	if err != nil {
		return nil, err
	}
	attributes := Attributes{}
	if err := AppendEAPMessage(&attributes, raw); err != nil {
		return nil, err
	}
	session.phase = EAPPhaseComplete
	session.completed = true
	result := &AccessServerResult{
		Accept:     true,
		Attributes: attributes,
		Identity:   identity,
	}
	if keys != nil && keys.Succeeded() {
		result.MPPESendKey = append([]byte(nil), keys.MPPESendKey...)
		result.MPPERecvKey = append([]byte(nil), keys.MPPERecvKey...)
	}
	return result, nil
}

// failureLocked builds an EAP-Failure Access-Reject. The caller must hold session.mu. |
// failureLocked 构建 EAP-Failure Access-Reject。调用方必须持有 session.mu。
func (s *EAPServer) failureLocked(session *eapSession, identifier uint8, reason MSCHAPv2FailureReason) (*AccessServerResult, error) {
	packet := newEAPFailure(identifier)
	raw, err := packet.MarshalBinary()
	if err != nil {
		return nil, err
	}
	attributes := Attributes{}
	if err := AppendEAPMessage(&attributes, raw); err != nil {
		return nil, err
	}
	if session != nil {
		session.phase = EAPPhaseComplete
		session.completed = true
	}
	_ = reason
	return &AccessServerResult{
		Accept:       false,
		Attributes:   attributes,
		ReplyMessage: "authentication failed",
	}, nil
}

// failureWithoutSession builds an EAP-Failure Access-Reject for a request without a live session. |
// failureWithoutSession 为没有活跃会话的请求构建 EAP-Failure Access-Reject。
func (s *EAPServer) failureWithoutSession(request *AccessServerRequest, packet *EAPPacket, reason MSCHAPv2FailureReason) (*AccessServerResult, error) {
	identifier := request.Identifier
	if packet != nil {
		identifier = packet.Identifier
	}
	return s.failureLocked(nil, identifier, reason)
}

// cacheLocked stores a copy of the result for an incoming EAP identifier. The caller must hold
// session.mu. | cacheLocked 按入站 EAP 标识符保存结果副本。调用方必须持有 session.mu。
func (s *EAPServer) cacheLocked(session *eapSession, identifier uint8, result *AccessServerResult) {
	if len(session.cache) >= 4 {
		for key := range session.cache {
			delete(session.cache, key)
			break
		}
	}
	session.cache[identifier] = cloneAccessServerResult(result)
}

// nextIdentifier returns a fresh EAP identifier for an outgoing Request. | nextIdentifier 为出站 Request
// 返回新的 EAP 标识符。
func (s *eapSession) nextIdentifier() uint8 {
	s.requestID++
	return s.requestID
}

// cloneAccessServerResult deep-copies a result for replay. | cloneAccessServerResult 为重放深拷贝结果。
func cloneAccessServerResult(result *AccessServerResult) *AccessServerResult {
	if result == nil {
		return nil
	}
	cloned := &AccessServerResult{
		ReplyMessage: result.ReplyMessage,
		Identity:     result.Identity,
		Attributes:   result.Attributes.Clone(),
		Accept:       result.Accept,
		Challenge:    result.Challenge,
	}
	cloned.State = append([]byte(nil), result.State...)
	cloned.MPPESendKey = append([]byte(nil), result.MPPESendKey...)
	cloned.MPPERecvKey = append([]byte(nil), result.MPPERecvKey...)
	return cloned
}

// hasMethod reports whether the server offers method. | hasMethod 报告服务器是否提供 method。
func (s *EAPServer) hasMethod(method EAPType) bool {
	for _, offered := range s.methods {
		if offered == method {
			return true
		}
	}
	return false
}

// hasTTLSInner reports whether the server accepts an inner EAP-TTLS method. | hasTTLSInner 报告服务器
// 是否接受某个 EAP-TTLS 内部方法。
func (s *EAPServer) hasTTLSInner(method EAPType) bool {
	for _, offered := range s.ttlsMethods {
		if offered == method {
			return true
		}
	}
	return false
}

// certificateIdentity extracts an identity from a verified peer certificate. | certificateIdentity 从
// 已校验对端证书提取身份。
func (s *EAPServer) certificateIdentity(certificate *x509.Certificate) string {
	if certificate == nil {
		return ""
	}
	if s.identity != nil {
		return strings.TrimSpace(s.identity(certificate))
	}
	if name := strings.TrimSpace(certificate.Subject.CommonName); name != "" {
		return name
	}
	if len(certificate.DNSNames) > 0 {
		return certificate.DNSNames[0]
	}
	return ""
}
