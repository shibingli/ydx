package webauthn

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"strings"
	"sync"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
)

// Defaults applied by New when Config leaves a field at its zero value. | New 在 Config 字段为零值时应用的默认值。
const (
	// DefaultChallengeLength is the default random challenge size in bytes. | DefaultChallengeLength 是默认随机挑战字节数。
	DefaultChallengeLength = 32
	// MinChallengeLength is the smallest accepted challenge size in bytes. | MinChallengeLength 是允许的最小挑战字节数。
	MinChallengeLength = 16
	// MaxChallengeLength is the largest accepted challenge size in bytes. | MaxChallengeLength 是允许的最大挑战字节数。
	MaxChallengeLength = 64
	// DefaultTimeout is the default ceremony lifetime. | DefaultTimeout 是默认流程生命周期。
	DefaultTimeout = 60 * time.Second
	// maxUserHandleLength is the WebAuthn user handle limit in bytes. | maxUserHandleLength 是 WebAuthn 用户句柄字节上限。
	maxUserHandleLength = 64
)

// CeremonyKind distinguishes registration from authentication state. | CeremonyKind 区分注册与认证状态。
type CeremonyKind string

// The ceremony kinds. | 流程类型。
const (
	// CeremonyRegistration is a navigator.credentials.create ceremony. | CeremonyRegistration 是 navigator.credentials.create 流程。
	CeremonyRegistration CeremonyKind = "registration"
	// CeremonyAuthentication is a navigator.credentials.get ceremony. | CeremonyAuthentication 是 navigator.credentials.get 流程。
	CeremonyAuthentication CeremonyKind = "authentication"
)

// Ceremony is the server-side state of one in-flight WebAuthn ceremony. | Ceremony 是一个进行中 WebAuthn 流程的服务端状态。
//
// BeginRegistration, BeginLogin and BeginDiscoverableLogin place a deep copy in Config.ChallengeStore
// and return it for the caller's session. Finish methods consume that copy and compare it with the
// caller-supplied value, so storing the returned Ceremony in the user's session prevents ceremony
// swapping. The struct is JSON-serializable. | BeginRegistration、BeginLogin 与
// BeginDiscoverableLogin 会把深拷贝放入 Config.ChallengeStore 并返回给调用方会话。Finish 方法消费该
// 副本并与调用方传入值比较，因此把返回的 Ceremony 存入用户会话可防止流程调换。该结构可 JSON 序列化。
type Ceremony struct {
	// ID is the unpadded base64url challenge and the ChallengeStore key. | ID 是无填充 base64url 挑战，也是 ChallengeStore 键。
	ID string `json:"id"`
	// Kind is registration or authentication. | Kind 是注册或认证。
	Kind CeremonyKind `json:"kind"`
	// Challenge is the raw random challenge. | Challenge 是原始随机挑战。
	Challenge []byte `json:"challenge"`
	// UserID is the owning user ID, empty for discoverable login. | UserID 是所属用户 ID，可发现登录时为空。
	UserID string `json:"userId,omitempty"`
	// UserHandle is the raw WebAuthn user handle. | UserHandle 是原始 WebAuthn 用户句柄。
	UserHandle []byte `json:"userHandle,omitempty"`
	// Username is the account login name during registration. | Username 是注册时的账号登录名。
	Username string `json:"username,omitempty"`
	// DisplayName is the account display name during registration. | DisplayName 是注册时的账号展示名称。
	DisplayName string `json:"displayName,omitempty"`
	// RPID is the effective relying party identifier. | RPID 是生效的依赖方标识。
	RPID string `json:"rpId"`
	// Origins are the accepted origins. | Origins 是可接受的来源。
	Origins []string `json:"origins"`
	// UserVerification is the effective user verification policy. | UserVerification 是生效的用户验证策略。
	UserVerification UserVerificationRequirement `json:"userVerification"`
	// Attestation is the effective attestation conveyance preference. | Attestation 是生效的认证声明传递偏好。
	Attestation ConveyancePreference `json:"attestation,omitempty"`
	// ResidentKey is the effective discoverable-credential requirement. | ResidentKey 是生效的可发现凭据要求。
	ResidentKey ResidentKeyRequirement `json:"residentKey,omitempty"`
	// Algorithms are the offered COSE algorithms. | Algorithms 是提供的 COSE 算法。
	Algorithms []int `json:"algorithms,omitempty"`
	// AllowCredentialIDs are the raw IDs accepted during authentication. | AllowCredentialIDs 是认证期间可接受的原始 ID。
	AllowCredentialIDs [][]byte `json:"allowCredentialIds,omitempty"`
	// ExcludeCredentialIDs are the raw IDs excluded during registration. | ExcludeCredentialIDs 是注册期间排除的原始 ID。
	ExcludeCredentialIDs [][]byte `json:"excludeCredentialIds,omitempty"`
	// Discoverable reports a user-less authentication ceremony. | Discoverable 表示无用户认证流程。
	Discoverable bool `json:"discoverable,omitempty"`
	// CredentialName is the label persisted with a newly registered credential. | CredentialName 是随新注册凭据保存的标签。
	CredentialName string `json:"credentialName,omitempty"`
	// RegistrationExtensions are the requested registration extensions. | RegistrationExtensions 是请求的注册扩展。
	RegistrationExtensions *RegistrationExtensions `json:"registrationExtensions,omitempty"`
	// AuthenticationExtensions are the requested authentication extensions. | AuthenticationExtensions 是请求的认证扩展。
	AuthenticationExtensions *AuthenticationExtensions `json:"authenticationExtensions,omitempty"`
	// TokenBindingID is the configured token binding identifier. | TokenBindingID 是配置的令牌绑定标识。
	TokenBindingID string `json:"tokenBindingId,omitempty"`
	// RequireTokenBinding reports whether token binding is mandatory. | RequireTokenBinding 表示令牌绑定是否为强制。
	RequireTokenBinding bool `json:"requireTokenBinding,omitempty"`
	// AllowCrossOrigin reports whether cross-origin requests are accepted. | AllowCrossOrigin 表示是否接受跨来源请求。
	AllowCrossOrigin bool `json:"allowCrossOrigin,omitempty"`
	// AllowedTopOrigins lists additional accepted top origins. | AllowedTopOrigins 列出额外接受的顶层来源。
	AllowedTopOrigins []string `json:"allowedTopOrigins,omitempty"`
	// CreatedAt is the ceremony creation time. | CreatedAt 是流程创建时间。
	CreatedAt time.Time `json:"createdAt"`
	// ExpiresAt is the ceremony expiry time; zero means no expiry. | ExpiresAt 是流程过期时间；零值表示不过期。
	ExpiresAt time.Time `json:"expiresAt"`
}

// ChallengeStore stores in-flight ceremonies keyed by their unpadded base64url challenge. | ChallengeStore 以无填充 base64url 挑战为键保存进行中的流程。
//
// Put must deep-copy the ceremony. Consume must remove the entry atomically and return
// ErrChallengeNotFound for an unknown key or ErrChallengeExpired for an expired entry. Implementations
// must be safe for concurrent use. | Put 必须深拷贝流程。Consume 必须原子地移除条目，并在键不存在时返回
// ErrChallengeNotFound、条目过期时返回 ErrChallengeExpired。实现必须可并发使用。
type ChallengeStore interface {
	// Put stores a ceremony. | Put 保存流程。
	Put(ctx context.Context, ceremony *Ceremony) error
	// Consume removes and returns a ceremony by challenge. | Consume 按挑战移除并返回流程。
	Consume(ctx context.Context, challenge string) (*Ceremony, error)
}

// CredentialStore persists registered WebAuthn credentials. | CredentialStore 持久化已注册的 WebAuthn 凭据。
//
// Implementations must be safe for concurrent use. | 实现必须可并发使用。
type CredentialStore interface {
	// GetByCredentialID returns a credential by raw credential ID. | GetByCredentialID 按原始凭据 ID 返回凭据。
	GetByCredentialID(ctx context.Context, credentialID []byte) (*Credential, error)
	// Save stores a new credential and returns ErrCredentialExists on a duplicate ID. | Save 保存新凭据，ID 重复时返回 ErrCredentialExists。
	Save(ctx context.Context, credential *Credential) error
	// UpdateSignCount persists a new authenticator sign count. | UpdateSignCount 持久化新的认证器签名计数器。
	UpdateSignCount(ctx context.Context, credentialID []byte, signCount uint32) error
	// ListByUser returns every credential owned by userID. | ListByUser 返回 userID 拥有的全部凭据。
	ListByUser(ctx context.Context, userID string) ([]*Credential, error)
}

// Config configures a Service. | Config 配置 Service。
type Config struct {
	// RPDisplayName is the human-readable relying party name shown by clients. Required. | RPDisplayName 是客户端展示的人类可读依赖方名称。必填。
	RPDisplayName string
	// RPID is the effective relying party identifier, a bare domain. Required. | RPID 是生效的依赖方标识，为裸域名。必填。
	RPID string
	// RPOrigins lists the exact accepted origins, for example "https://example.com". Required. | RPOrigins 列出精确可接受的来源，例如 "https://example.com"。必填。
	RPOrigins []string
	// ChallengeLength is the random challenge size in bytes. Zero means DefaultChallengeLength. | ChallengeLength 是随机挑战字节数。零值表示 DefaultChallengeLength。
	ChallengeLength int
	// Timeout is the ceremony lifetime. Zero means DefaultTimeout. | Timeout 是流程生命周期。零值表示 DefaultTimeout。
	Timeout time.Duration
	// UserVerification is the default policy. Empty means UserVerificationPreferred. | UserVerification 是默认策略。空值表示 UserVerificationPreferred。
	UserVerification UserVerificationRequirement
	// Attestation is the default conveyance preference. Empty means ConveyanceNone. | Attestation 是默认传递偏好。空值表示 ConveyanceNone。
	Attestation ConveyancePreference
	// ChallengeStore stores ceremony state. Nil uses an in-memory store. | ChallengeStore 保存流程状态。为空时使用内存存储。
	ChallengeStore ChallengeStore
	// CredentialStore stores registered credentials. Nil uses an in-memory store. | CredentialStore 保存已注册凭据。为空时使用内存存储。
	CredentialStore CredentialStore
	// CounterPolicy selects the sign-counter regression policy. Empty means CounterStrict. | CounterPolicy 选择签名计数器回退策略。空值表示 CounterStrict。
	CounterPolicy CounterPolicy
	// AttestationRoots is the trust anchor pool for attestation certificate chains. Nil parses but does not trust chains. | AttestationRoots 是认证声明证书链的信任锚池。为空时解析但不对链建立信任。
	AttestationRoots *x509.CertPool
	// SafetyNetRoots is the trust anchor pool for android-safetynet certificate chains. Nil falls back to AttestationRoots. | SafetyNetRoots 是 android-safetynet 证书链的信任锚池。为空时回退到 AttestationRoots。
	SafetyNetRoots *x509.CertPool
	// AndroidKeyRoots is the trust anchor pool for android-key certificate chains. Nil falls back to AttestationRoots. | AndroidKeyRoots 是 android-key 证书链的信任锚池。为空时回退到 AttestationRoots。
	AndroidKeyRoots *x509.CertPool
	// AndroidKeyVerifier overrides the built-in android-key KeyDescription and trust checks. Nil uses the built-in checks. | AndroidKeyVerifier 覆盖内置 android-key KeyDescription 与信任校验。为空时使用内置校验。
	AndroidKeyVerifier AndroidKeyVerifier
	// AndroidPackageName is the APK package name required from Android attestation formats. Empty falls back to ClientData.AndroidPackageName. | AndroidPackageName 是 Android 认证声明格式要求的 APK 包名。为空时回退到 ClientData.AndroidPackageName。
	AndroidPackageName string
	// SafetyNetVerifier overrides the built-in Android SafetyNet JWS verification. | SafetyNetVerifier 覆盖内置 Android SafetyNet JWS 校验。
	SafetyNetVerifier SafetyNetVerifier
	// Clock supplies the current time. Nil uses time.Now. | Clock 提供当前时间。为空时使用 time.Now。
	Clock func() time.Time
	// Algorithms lists the offered COSE algorithms. Nil means DefaultAlgorithms. | Algorithms 列出提供的 COSE 算法。为空表示 DefaultAlgorithms。
	Algorithms []int
	// TokenBindingID is the expected token binding identifier. | TokenBindingID 是期望的令牌绑定标识。
	TokenBindingID string
	// RequireTokenBinding requires the tokenBinding client data member. | RequireTokenBinding 要求 tokenBinding 客户端数据成员。
	RequireTokenBinding bool
	// AllowCrossOrigin permits cross-origin ceremonies. | AllowCrossOrigin 允许跨来源流程。
	AllowCrossOrigin bool
	// AllowedTopOrigins lists accepted top-level origins for cross-origin ceremonies. | AllowedTopOrigins 列出跨来源流程可接受的顶层来源。
	AllowedTopOrigins []string
}

// Service runs WebAuthn registration and authentication ceremonies. | Service 运行 WebAuthn 注册与认证流程。
//
// A Service is safe for concurrent use after New returns. | New 返回后 Service 可安全并发使用。
type Service struct {
	rpDisplayName  string
	rpID           string
	origins        []string
	challengeLen   int
	timeout        time.Duration
	userVerif      UserVerificationRequirement
	attestation    ConveyancePreference
	challenges     ChallengeStore
	credentials    CredentialStore
	counterPolicy  CounterPolicy
	roots          *x509.CertPool
	safetynetRoots *x509.CertPool
	androidRoots   *x509.CertPool
	androidKey     AndroidKeyVerifier
	androidPackage string
	safetynet      SafetyNetVerifier
	clock          func() time.Time
	algorithms     []int
	tokenBinding   string
	requireTB      bool
	allowCross     bool
	topOrigins     []string
	signLocks      [64]sync.Mutex
}

// New validates config and returns a Service. | New 校验 config 并返回 Service。
func New(config Config) (*Service, error) {
	s := &Service{
		rpDisplayName:  strings.TrimSpace(config.RPDisplayName),
		challengeLen:   config.ChallengeLength,
		timeout:        config.Timeout,
		userVerif:      config.UserVerification,
		attestation:    config.Attestation,
		challenges:     config.ChallengeStore,
		credentials:    config.CredentialStore,
		counterPolicy:  config.CounterPolicy,
		roots:          config.AttestationRoots,
		safetynetRoots: config.SafetyNetRoots,
		androidRoots:   config.AndroidKeyRoots,
		androidKey:     config.AndroidKeyVerifier,
		androidPackage: strings.TrimSpace(config.AndroidPackageName),
		safetynet:      config.SafetyNetVerifier,
		clock:          config.Clock,
		tokenBinding:   config.TokenBindingID,
		requireTB:      config.RequireTokenBinding,
		allowCross:     config.AllowCrossOrigin,
		topOrigins:     config.AllowedTopOrigins,
	}
	if s.rpDisplayName == "" {
		return nil, errs.Detail(ErrInvalidConfig, "RP display name is empty | RP 展示名称为空")
	}
	rpID, err := normalizeRPID(config.RPID)
	if err != nil {
		return nil, err
	}
	s.rpID = rpID
	if len(config.RPOrigins) == 0 {
		return nil, errs.Detail(ErrInvalidConfig, "RP origins are empty | RP 来源为空")
	}
	seenOrigins := make(map[string]struct{}, len(config.RPOrigins))
	for _, raw := range config.RPOrigins {
		origin, err := normalizeOrigin(raw)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidConfig, "invalid RP origin %q | 非法 RP 来源 %q", raw, raw)
		}
		if !originMatchesRPID(origin, s.rpID) {
			return nil, errs.Detail(ErrInvalidConfig, "RP origin %q is outside RP ID %q | RP 来源 %q 不在 RP ID %q 内", origin, s.rpID, origin, s.rpID)
		}
		if _, ok := seenOrigins[origin]; ok {
			continue
		}
		seenOrigins[origin] = struct{}{}
		s.origins = append(s.origins, origin)
	}
	if s.challengeLen == 0 {
		s.challengeLen = DefaultChallengeLength
	}
	if s.challengeLen < MinChallengeLength || s.challengeLen > MaxChallengeLength {
		return nil, errs.Detail(ErrInvalidConfig, "challenge length %d is outside %d..%d | 挑战长度 %d 超出 %d..%d",
			s.challengeLen, MinChallengeLength, MaxChallengeLength, s.challengeLen, MinChallengeLength, MaxChallengeLength)
	}
	if s.timeout == 0 {
		s.timeout = DefaultTimeout
	}
	if s.timeout < 0 {
		return nil, errs.Detail(ErrInvalidConfig, "timeout is negative | 超时为负数")
	}
	if s.userVerif == "" {
		s.userVerif = UserVerificationPreferred
	}
	if !validUserVerification(s.userVerif) {
		return nil, errs.Detail(ErrInvalidConfig, "user verification %q | 用户验证 %q", s.userVerif, s.userVerif)
	}
	if s.attestation == "" {
		s.attestation = ConveyanceNone
	}
	if !validConveyance(s.attestation) {
		return nil, errs.Detail(ErrInvalidConfig, "attestation %q | 认证声明 %q", s.attestation, s.attestation)
	}
	if s.counterPolicy == "" {
		s.counterPolicy = CounterStrict
	}
	if !validCounterPolicy(s.counterPolicy) {
		return nil, errs.Detail(ErrInvalidConfig, "counter policy %q | 计数器策略 %q", s.counterPolicy, s.counterPolicy)
	}
	algorithms := config.Algorithms
	if algorithms == nil {
		algorithms = DefaultAlgorithms()
	}
	algorithms, err = validAlgorithms(algorithms)
	if err != nil {
		return nil, err
	}
	s.algorithms = algorithms
	if s.challenges == nil {
		s.challenges = NewMemoryChallengeStore()
	}
	if s.credentials == nil {
		s.credentials = NewMemoryCredentialStore()
	}
	if s.clock == nil {
		s.clock = time.Now
	}
	if s.allowCross && len(s.topOrigins) == 0 {
		return nil, errs.Detail(ErrInvalidConfig, "cross-origin is enabled without allowed top origins | 启用跨来源但未提供允许的顶层来源")
	}
	normalizedTop := make([]string, 0, len(s.topOrigins))
	for _, raw := range s.topOrigins {
		origin, err := normalizeOrigin(raw)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidConfig, "invalid top origin %q | 非法顶层来源 %q", raw, raw)
		}
		normalizedTop = append(normalizedTop, origin)
	}
	s.topOrigins = normalizedTop
	return s, nil
}

// RPID returns the normalized relying party identifier. | RPID 返回规范化后的依赖方标识。
func (s *Service) RPID() string { return s.rpID }

// RPDisplayName returns the configured relying party display name. | RPDisplayName 返回配置的依赖方展示名称。
func (s *Service) RPDisplayName() string { return s.rpDisplayName }

// CounterPolicy returns the effective sign-counter policy. | CounterPolicy 返回生效的签名计数器策略。
func (s *Service) CounterPolicy() CounterPolicy {
	if s == nil {
		return CounterStrict
	}
	return s.counterPolicy
}

// now returns the configured current time. | now 返回配置的当前时间。
func (s *Service) now() time.Time { return s.clock() }

// newCeremonyBase allocates a challenge and the shared policy snapshot. | newCeremonyBase 分配挑战与共享策略快照。
func (s *Service) newCeremonyBase(kind CeremonyKind, timeout time.Duration) (*Ceremony, error) {
	if timeout <= 0 {
		timeout = s.timeout
	}
	challenge := make([]byte, s.challengeLen)
	if _, err := rand.Read(challenge); err != nil {
		return nil, errs.Wrap(err, ErrChallengeGeneration)
	}
	now := s.now()
	return &Ceremony{
		ID:                  base64.RawURLEncoding.EncodeToString(challenge),
		Kind:                kind,
		Challenge:           challenge,
		RPID:                s.rpID,
		Origins:             append([]string(nil), s.origins...),
		UserVerification:    s.userVerif,
		Attestation:         s.attestation,
		TokenBindingID:      s.tokenBinding,
		RequireTokenBinding: s.requireTB,
		AllowCrossOrigin:    s.allowCross,
		AllowedTopOrigins:   append([]string(nil), s.topOrigins...),
		CreatedAt:           now,
		ExpiresAt:           now.Add(timeout),
	}, nil
}

// putCeremony stores a deep copy and returns the original. | putCeremony 保存深拷贝并返回原值。
func (s *Service) putCeremony(ctx context.Context, ceremony *Ceremony) (*Ceremony, error) {
	if err := s.challenges.Put(ctx, cloneCeremony(ceremony)); err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidRequest, "challenge store rejected the ceremony | 挑战存储拒绝了流程")
	}
	return ceremony, nil
}

// clientDataVerifyOptions builds expected client data values from a ceremony. | clientDataVerifyOptions 从流程构建客户端数据期望值。
func (c *Ceremony) clientDataVerifyOptions(typ string) ClientDataVerifyOptions {
	return ClientDataVerifyOptions{
		Type:                typ,
		Challenge:           c.Challenge,
		Origins:             c.Origins,
		RPID:                c.RPID,
		AllowCrossOrigin:    c.AllowCrossOrigin,
		AllowedTopOrigins:   c.AllowedTopOrigins,
		TokenBindingID:      c.TokenBindingID,
		RequireTokenBinding: c.RequireTokenBinding,
	}
}

// cloneCeremony returns a deep copy. | cloneCeremony 返回深拷贝。
func cloneCeremony(c *Ceremony) *Ceremony {
	if c == nil {
		return nil
	}
	out := *c
	out.Challenge = append([]byte(nil), c.Challenge...)
	out.UserHandle = append([]byte(nil), c.UserHandle...)
	out.Origins = append([]string(nil), c.Origins...)
	out.Algorithms = append([]int(nil), c.Algorithms...)
	out.AllowedTopOrigins = append([]string(nil), c.AllowedTopOrigins...)
	if len(c.AllowCredentialIDs) > 0 {
		out.AllowCredentialIDs = make([][]byte, len(c.AllowCredentialIDs))
		for i := range c.AllowCredentialIDs {
			out.AllowCredentialIDs[i] = append([]byte(nil), c.AllowCredentialIDs[i]...)
		}
	}
	if len(c.ExcludeCredentialIDs) > 0 {
		out.ExcludeCredentialIDs = make([][]byte, len(c.ExcludeCredentialIDs))
		for i := range c.ExcludeCredentialIDs {
			out.ExcludeCredentialIDs[i] = append([]byte(nil), c.ExcludeCredentialIDs[i]...)
		}
	}
	if c.RegistrationExtensions != nil {
		ext := *c.RegistrationExtensions
		out.RegistrationExtensions = &ext
	}
	if c.AuthenticationExtensions != nil {
		ext := *c.AuthenticationExtensions
		if c.AuthenticationExtensions.HMACGetSecret != nil {
			input := *c.AuthenticationExtensions.HMACGetSecret
			ext.HMACGetSecret = &input
		}
		out.AuthenticationExtensions = &ext
	}
	return &out
}

// validateDescription checks a caller-supplied credential label. | validateDescription 校验调用方提供的凭据标签。
func validateDescription(name string) string {
	name = strings.TrimSpace(name)
	if len(name) > 256 {
		name = name[:256]
	}
	return name
}

// userHandleFor returns the WebAuthn user handle for an auth user. | userHandleFor 返回认证用户的 WebAuthn 用户句柄。
func userHandleFor(user *auth.User) ([]byte, error) {
	if user == nil {
		return nil, errs.Detail(ErrInvalidRequest, "nil user | 用户为空")
	}
	id := strings.TrimSpace(user.ID)
	if id == "" {
		return nil, errs.Detail(ErrInvalidRequest, "user ID is empty | 用户 ID 为空")
	}
	handle := []byte(user.ID)
	if len(handle) > maxUserHandleLength {
		return nil, errs.Detail(ErrInvalidRequest, "user ID is %d bytes, WebAuthn allows at most %d | 用户 ID 为 %d 字节，WebAuthn 最多允许 %d",
			len(handle), maxUserHandleLength, len(handle), maxUserHandleLength)
	}
	return handle, nil
}

// usernameFor returns the account name shown by the authenticator. | usernameFor 返回认证器展示的账号名称。
func usernameFor(user *auth.User) string {
	if name := strings.TrimSpace(user.Username); name != "" {
		return name
	}
	return user.ID
}

// displayNameFor returns the human-readable account name. | displayNameFor 返回人类可读账号名称。
func displayNameFor(user *auth.User) string {
	if name := strings.TrimSpace(user.DisplayName); name != "" {
		return name
	}
	return usernameFor(user)
}
