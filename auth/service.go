package auth

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
)

// Token purposes used by Service. | Service 使用的令牌用途。
const (
	// PurposeVerifyEmail marks an email-verification token. | PurposeVerifyEmail 标记邮箱验证令牌。
	PurposeVerifyEmail = "verify_email"
	// PurposeResetPassword marks a password-reset token. | PurposeResetPassword 标记口令重置令牌。
	PurposeResetPassword = "reset_password"
	// PurposeInvite marks an account-invitation token. | PurposeInvite 标记账号邀请令牌。
	PurposeInvite = "invite"
	// PurposeMFARecovery marks a recovery-code challenge. | PurposeMFARecovery 标记恢复码挑战。
	PurposeMFARecovery = "mfa_recovery"
	// PurposeMFALogin marks a short-lived challenge issued after the password phase. | PurposeMFALogin
	// 标记口令阶段之后签发的短期挑战。
	PurposeMFALogin = "mfa_login"
)

// defaultMFATokenTTL is the lifetime of the password-phase MFA challenge. | defaultMFATokenTTL 是口令阶段
// MFA 挑战的寿命。
const defaultMFATokenTTL = 5 * time.Minute

// LockoutPolicy configures failed-login lockout. | LockoutPolicy 配置登录失败锁定。
type LockoutPolicy struct {
	// MaxAttempts is the consecutive failure count that triggers a lock; zero defaults to 5. | MaxAttempts 是触发锁定的连续失败次数；零值默认 5。
	MaxAttempts int
	// BaseLockout is the first lock duration; zero defaults to one minute. | BaseLockout 是首次锁定时长；零值默认 1 分钟。
	BaseLockout time.Duration
	// MaxLockout caps exponential backoff; zero defaults to one hour. | MaxLockout 限制指数退避；零值默认 1 小时。
	MaxLockout time.Duration
}

// DefaultLockoutPolicy returns the default failed-login policy. | DefaultLockoutPolicy 返回默认登录失败策略。
func DefaultLockoutPolicy() LockoutPolicy {
	return LockoutPolicy{MaxAttempts: 5, BaseLockout: time.Minute, MaxLockout: time.Hour}
}

// lockDuration returns the exponential lock duration for attempt count. | lockDuration 返回尝试次数的指数锁定时长。
func (p LockoutPolicy) lockDuration(attempts int) time.Duration {
	maxAttempts := p.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	base := p.BaseLockout
	if base <= 0 {
		base = time.Minute
	}
	maxLock := p.MaxLockout
	if maxLock <= 0 {
		maxLock = time.Hour
	}
	over := attempts - maxAttempts
	if over < 0 {
		over = 0
	}
	if over > 16 {
		over = 16
	}
	d := base << uint(over)
	if d > maxLock || d <= 0 {
		return maxLock
	}
	return d
}

// Hooks are optional lifecycle callbacks. | Hooks 是可选的生命周期回调。
//
// A non-nil error aborts the operation; After callbacks run only after the state change succeeded. | 非空错误会中止操作；After 回调只在状态变更成功后运行。
type Hooks struct {
	// BeforeRegister runs before a user is persisted. | BeforeRegister 在用户持久化前运行。
	BeforeRegister func(ctx context.Context, user *User) error
	// AfterRegister runs after a user is persisted. | AfterRegister 在用户持久化后运行。
	AfterRegister func(ctx context.Context, user *User) error
	// BeforeLogin runs after the password verified but before a session is created. | BeforeLogin 在口令校验通过、会话创建前运行。
	BeforeLogin func(ctx context.Context, user *User) error
	// AfterLogin runs after a session is created. | AfterLogin 在会话创建后运行。
	AfterLogin func(ctx context.Context, user *User, session *Session) error
	// AfterAudit runs after an audit event is stored. | AfterAudit 在审计事件存储后运行。
	AfterAudit func(ctx context.Context, event *AuditEvent)
}

// Config configures Service. | Config 配置 Service。
type Config struct {
	// Stores are the persistence ports. | Stores 是持久化端口。
	Stores Stores
	// Passwords is the password hash manager; nil means Argon2id with recommended parameters. | Passwords 是口令哈希管理器；空值表示推荐参数的 Argon2id。
	Passwords PasswordHasher
	// Policy is the password policy. Unset length fields and a nil CommonPasswords are filled per
	// field from DefaultPasswordPolicy; boolean rules keep their literal values. | Policy 是口令策略。
	// 未设置的长度字段与 nil 的 CommonPasswords 会逐字段从 DefaultPasswordPolicy 补齐；布尔规则按
	// 字面值生效。
	Policy PasswordPolicy
	// Session is the session configuration; the zero value uses DefaultSessionConfig. | Session 是会话配置；零值使用 DefaultSessionConfig。
	Session SessionConfig
	// Lockout is the failed-login policy; the zero value uses DefaultLockoutPolicy. | Lockout 是登录失败策略；零值使用 DefaultLockoutPolicy。
	Lockout LockoutPolicy
	// RequireEmailVerification puts new accounts in UserPending until the email is verified. It
	// applies to password registration and to federated provisioning when the upstream identity
	// carries a non-empty but unverified email. Identities without an email and already linked
	// accounts are never moved to UserPending, so existing users cannot be locked out. |
	// RequireEmailVerification 让新账号在邮箱验证前处于 UserPending。该规则适用于口令注册，以及上游
	// 身份带有非空但未验证邮箱时的联邦预配。没有邮箱的身份与已关联账号绝不会被置为 UserPending，
	// 因此既有用户不会被锁死。
	RequireEmailVerification bool
	// ResetTokenTTL is the password-reset token lifetime; zero defaults to one hour. | ResetTokenTTL 是口令重置令牌寿命；零值默认 1 小时。
	ResetTokenTTL time.Duration
	// VerifyTokenTTL is the email-verification token lifetime; zero defaults to 24 hours. | VerifyTokenTTL 是邮箱验证令牌寿命；零值默认 24 小时。
	VerifyTokenTTL time.Duration
	// MFATokenTTL is the password-phase MFA challenge lifetime; zero defaults to 5 minutes. | MFATokenTTL
	// 是口令阶段 MFA 挑战的寿命；零值默认 5 分钟。
	MFATokenTTL time.Duration
	// RequireMFAToken rejects CompleteMFA calls that omit the MFAToken returned by Authenticate. The
	// default false preserves the legacy flow, where knowledge of a user ID and a valid factor code
	// is enough; that flow skips proof of the password phase and should be disabled for new
	// deployments. | RequireMFAToken 拒绝未回传 Authenticate 所返回 MFAToken 的 CompleteMFA 调用。
	// 默认 false 保留旧流程：只要知道用户 ID 与有效因素验证码即可完成，跳过了口令阶段证明，新部署
	// 应禁用该旧流程。
	RequireMFAToken bool
	// LoginSnapshot reports whether Service updates LastLoginAt and LastLoginIP. | LoginSnapshot 报告 Service 是否更新 LastLoginAt 与 LastLoginIP。
	LoginSnapshot bool
	// Hooks are optional lifecycle callbacks. | Hooks 是可选生命周期回调。
	Hooks Hooks
	// Logger receives operational warnings; nil disables logging. | Logger 接收运行告警；空值禁用日志。
	Logger *log.Logger
	// Clock overrides time for tests. | Clock 为测试替换时间。
	Clock func() time.Time
}

// Service is the account-lifecycle facade over the stores and session manager. | Service 是存储与会话管理器之上的账号生命周期门面。
type Service struct {
	stores      Stores
	hash        PasswordHasher
	policy      PasswordPolicy
	sessions    *SessionManager
	lockout     LockoutPolicy
	config      Config
	verifiers   map[CredentialType]MFAVerifier
	verifiersMu sync.RWMutex
	dummyHash   string
	dummyOnce   sync.Once
	mfaTokenTTL time.Duration
	logger      *log.Logger
	now         func() time.Time
}

// New returns a Service. | New 返回 Service。
func New(config Config) (*Service, error) {
	if err := config.Stores.Validate(); err != nil {
		return nil, err
	}
	hash := config.Passwords
	if hash == nil {
		defaultHash, err := NewArgon2idHasher(DefaultArgon2idConfig())
		if err != nil {
			return nil, err
		}
		hash = defaultHash
	}
	policy := config.Policy.withDefaults()
	lockout := config.Lockout
	defaults := DefaultLockoutPolicy()
	if lockout.MaxAttempts <= 0 {
		lockout.MaxAttempts = defaults.MaxAttempts
	}
	if lockout.BaseLockout <= 0 {
		lockout.BaseLockout = defaults.BaseLockout
	}
	if lockout.MaxLockout <= 0 {
		lockout.MaxLockout = defaults.MaxLockout
	}
	if config.ResetTokenTTL <= 0 {
		config.ResetTokenTTL = time.Hour
	}
	if config.VerifyTokenTTL <= 0 {
		config.VerifyTokenTTL = 24 * time.Hour
	}
	if config.MFATokenTTL <= 0 {
		config.MFATokenTTL = defaultMFATokenTTL
	}
	manager, err := NewSessionManager(config.Stores.Sessions, config.Stores.Users, config.Session)
	if err != nil {
		return nil, err
	}
	if config.Clock != nil {
		manager.SetClock(config.Clock)
	}
	return &Service{
		stores:      config.Stores,
		hash:        hash,
		policy:      policy,
		sessions:    manager,
		lockout:     lockout,
		config:      config,
		verifiers:   make(map[CredentialType]MFAVerifier),
		mfaTokenTTL: config.MFATokenTTL,
		logger:      config.Logger,
		now:         config.Clock,
	}, nil
}

// Stores returns the persistence ports. | Stores 返回持久化端口。
func (s *Service) Stores() Stores { return s.stores }

// Sessions returns the session manager. | Sessions 返回会话管理器。
func (s *Service) Sessions() *SessionManager { return s.sessions }

// Policy returns the password policy. | Policy 返回口令策略。
func (s *Service) Policy() PasswordPolicy { return s.policy }

// PasswordHasher returns the configured password hash manager. | PasswordHasher 返回配置的口令哈希管理器。
func (s *Service) PasswordHasher() PasswordHasher { return s.hash }

// RegisterMFAVerifier installs the verifier for one factor type. | RegisterMFAVerifier 安装一种因素类型的校验器。
func (s *Service) RegisterMFAVerifier(typ CredentialType, verifier MFAVerifier) {
	s.verifiersMu.Lock()
	defer s.verifiersMu.Unlock()
	if s.verifiers == nil {
		s.verifiers = make(map[CredentialType]MFAVerifier)
	}
	s.verifiers[typ] = verifier
}

// mfaVerifier returns the verifier registered for typ. | mfaVerifier 返回为 typ 注册的校验器。
func (s *Service) mfaVerifier(typ CredentialType) MFAVerifier {
	s.verifiersMu.RLock()
	defer s.verifiersMu.RUnlock()
	return s.verifiers[typ]
}

// nowTime returns the current UTC time. | nowTime 返回当前 UTC 时间。
func (s *Service) nowTime() time.Time { return Now(s.now) }

// RegisterInput is the input of Service.Register. | RegisterInput 是 Service.Register 的输入。
type RegisterInput struct {
	// Username is the unique login name. | Username 是唯一登录名。
	Username string
	// Email is the primary email address. | Email 是主邮箱地址。
	Email string
	// Phone is the primary phone number. | Phone 是主手机号。
	Phone string
	// Password is the plaintext password; it is hashed before storage. | Password 是明文口令；存储前会哈希。
	Password string
	// DisplayName is the human-readable name. | DisplayName 是展示名称。
	DisplayName string
	// Metadata holds application-defined scalar attributes. | Metadata 保存应用自定义标量属性。
	Metadata map[string]string
	// Active overrides the pending state when email verification is required. | Active 在要求邮箱验证时覆盖待激活状态。
	Active bool
	// ExternalID links the account to an upstream directory identifier. | ExternalID 把账号关联到上级目录标识。
	ExternalID string
}

// Register creates a user account. | Register 创建用户账号。
func (s *Service) Register(ctx context.Context, input RegisterInput) (*User, error) {
	username := strings.TrimSpace(input.Username)
	email := strings.TrimSpace(input.Email)
	phone := strings.TrimSpace(input.Phone)
	if username == "" && email == "" && phone == "" {
		return nil, errs.Detail(ErrInvalidRequest, "username, email or phone is required | 用户名、邮箱或手机号至少需要一个")
	}
	if input.Password == "" {
		return nil, errs.Detail(ErrInvalidRequest, "password is required | 口令必填")
	}
	now := s.nowTime()
	user := &User{
		ID:          NewID("usr"),
		Username:    username,
		Email:       email,
		Phone:       phone,
		DisplayName: strings.TrimSpace(input.DisplayName),
		Status:      UserActive,
		CreatedAt:   now,
		UpdatedAt:   now,
		ExternalID:  input.ExternalID,
		Metadata:    cloneStrings(input.Metadata),
	}
	if s.config.RequireEmailVerification && !input.Active {
		user.Status = UserPending
	}
	if err := s.policy.Validate(ctx, input.Password, user); err != nil {
		return nil, err
	}
	encoded, err := s.hash.Hash(input.Password)
	if err != nil {
		return nil, err
	}
	user.PasswordHash = encoded
	user.PasswordChangedAt = now
	if s.config.Hooks.BeforeRegister != nil {
		if err := s.config.Hooks.BeforeRegister(ctx, user); err != nil {
			return nil, err
		}
	}
	if err := s.stores.Users.CreateUser(ctx, user); err != nil {
		return nil, err
	}
	s.audit(ctx, &AuditEvent{
		Type: "user.registered", ActorID: user.ID, UserID: user.ID, Outcome: "success",
	})
	if s.config.Hooks.AfterRegister != nil {
		if err := s.config.Hooks.AfterRegister(ctx, user); err != nil {
			return nil, err
		}
	}
	return user, nil
}

// AuthenticateInput is the input of Service.Authenticate. | AuthenticateInput 是 Service.Authenticate 的输入。
type AuthenticateInput struct {
	// Login is a username, email address or phone number. | Login 是用户名、邮箱地址或手机号。
	Login string
	// Password is the plaintext password. | Password 是明文口令。
	Password string
	// ClientID identifies the application or OAuth client. | ClientID 标识应用或 OAuth 客户端。
	ClientID string
	// Request supplies session metadata and is optional. | Request 提供会话元数据，可为空。
	Request *http.Request
	// AMR records the authentication methods; it defaults to ["pwd"]. | AMR 记录认证方法；默认 ["pwd"]。
	AMR []string
	// ACR is the authentication context class reference. | ACR 是认证上下文类引用。
	ACR string
	// SkipMFA completes the login without a second factor; only trusted callers should set it. | SkipMFA 跳过第二因素完成登录；仅可信调用方应设置。
	SkipMFA bool
}

// AuthenticateResult is the outcome of a successful password phase. | AuthenticateResult 是口令阶段成功后的结果。
type AuthenticateResult struct {
	// User is the authenticated account. | User 是已认证账号。
	User *User
	// Session is nil when MFA is still required. | Session 在仍需多因素时为空。
	Session *Session
	// MFARequired reports that CompleteMFA must be called. | MFARequired 表示必须调用 CompleteMFA。
	MFARequired bool
	// MFAToken is a short-lived, single-use challenge binding CompleteMFA to this password phase.
	// Clients should return it unchanged; an empty value keeps the legacy caller-supplied UserID
	// behavior. | MFAToken 是短期单次挑战，把 CompleteMFA 绑定到本次口令阶段。客户端应原样返回；
	// 空值保留旧的由调用方提供 UserID 的行为。
	MFAToken string
	// PasswordExpired reports that the password exceeded the policy age. | PasswordExpired 表示口令超过策略有效期。
	PasswordExpired bool
	// Rehashed reports that the stored hash was upgraded during this login. | Rehashed 表示本次登录升级了存储哈希。
	Rehashed bool
}

// Authenticate verifies a password and, when no second factor is enrolled, creates a session. | Authenticate
// 校验口令，并在未登记第二因素时创建会话。
//
// An unknown account and a wrong password both return ErrInvalidCredentials. A known locked or
// disabled account returns the specific sentinel so the application can show the right message. | 未知
// 账号与错误口令都返回 ErrInvalidCredentials；已知的锁定或禁用账号返回具体哨兵，便于应用展示正确提示。
func (s *Service) Authenticate(ctx context.Context, input AuthenticateInput) (*AuthenticateResult, error) {
	now := s.nowTime()
	user, err := s.findByLogin(ctx, input.Login)
	if err != nil {
		if !errors.Is(err, ErrUserNotFound) {
			return nil, err
		}
		// Spend the same hash work as a known account so response timing does not disclose whether
		// the login exists. | 对未知账号执行同样的哈希开销，避免响应时间泄露登录标识是否存在。
		s.verifyDummyPassword(input.Password)
		s.audit(ctx, &AuditEvent{
			Type: "login.failed", IP: requestIP(input.Request), UserAgent: userAgent(input.Request),
			Outcome: "failure", Detail: map[string]string{"reason": "unknown_login"},
		})
		return nil, ErrInvalidCredentials
	}
	if err := user.CanLogin(now); err != nil {
		s.audit(ctx, &AuditEvent{
			Type: "login.denied", UserID: user.ID, IP: requestIP(input.Request), UserAgent: userAgent(input.Request),
			Outcome: "denied", Detail: map[string]string{"reason": err.Error()},
		})
		return nil, err
	}
	ok, err := s.hash.Verify(input.Password, user.PasswordHash)
	if err != nil || !ok {
		s.recordFailure(ctx, user, now, input.Request)
		return nil, ErrInvalidCredentials
	}
	if err := user.CanLogin(now); err != nil {
		return nil, err
	}
	if user.Status == UserLocked && !user.LockedUntil.IsZero() && !now.Before(user.LockedUntil) {
		// A temporary administrative lock expired: restore the account instead of leaving it in a
		// state where the next login sees UserLocked with a zero deadline. | 临时管理锁定已过期：
		// 恢复账号，避免下次登录看到 UserLocked 且期限为零而永久拒登。
		user.Status = UserActive
	}
	mfaPending := user.MFAEnabled && !input.SkipMFA
	if !mfaPending {
		// A successful password phase alone must not clear the shared lockout counter while a second
		// factor is still pending, otherwise wrong factors can be retried without limit. | 第二因素
		// 仍需验证时，仅口令阶段成功不得清除共享锁定计数，否则错误的因素可被无限重试。
		user.FailedLoginAttempts = 0
		user.LockedUntil = time.Time{}
	}
	rehashed := false
	if s.hash.NeedsRehash(user.PasswordHash) {
		if upgraded, err := s.hash.Hash(input.Password); err == nil {
			user.PasswordHistory = pushPasswordHistory(user.PasswordHash, user.PasswordHistory, s.policy.History)
			user.PasswordHash = upgraded
			// A hash upgrade does not change the password, so it must not extend the maximum
			// password age. | 哈希升级没有改变口令，因此不得延长口令最长有效期。
			rehashed = true
		}
	}
	user.UpdatedAt = now
	passwordExpired := s.policy.Expired(user, now)
	if s.config.LoginSnapshot {
		user.LastLoginAt = now
		user.LastLoginIP = requestIP(input.Request)
	}
	if err := s.stores.Users.UpdateUser(ctx, user); err != nil {
		return nil, err
	}
	if s.config.Hooks.BeforeLogin != nil {
		if err := s.config.Hooks.BeforeLogin(ctx, user); err != nil {
			return nil, err
		}
	}
	if mfaPending {
		challenge, err := s.issueMFAChallenge(ctx, user.ID, now)
		if err != nil {
			return nil, err
		}
		s.audit(ctx, &AuditEvent{
			Type: "login.mfa_required", UserID: user.ID, IP: requestIP(input.Request),
			UserAgent: userAgent(input.Request), Outcome: "success",
		})
		return &AuthenticateResult{
			User: user, MFARequired: true, MFAToken: challenge,
			PasswordExpired: passwordExpired, Rehashed: rehashed,
		}, nil
	}
	amr := input.AMR
	if len(amr) == 0 {
		amr = []string{"pwd"}
	}
	session, err := s.sessions.Create(ctx, user.ID, input.ClientID, input.Request, amr, input.ACR)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, &AuditEvent{
		Type: "login.succeeded", ActorID: user.ID, UserID: user.ID, SessionID: session.ID,
		ClientID: input.ClientID, IP: requestIP(input.Request), UserAgent: userAgent(input.Request), Outcome: "success",
	})
	if s.config.Hooks.AfterLogin != nil {
		if err := s.config.Hooks.AfterLogin(ctx, user, session); err != nil {
			return nil, err
		}
	}
	return &AuthenticateResult{User: user, Session: session, PasswordExpired: passwordExpired, Rehashed: rehashed}, nil
}

// recordFailure increments the failure counter and applies lockout. | recordFailure 增加失败计数并应用锁定。
func (s *Service) recordFailure(ctx context.Context, user *User, now time.Time, r *http.Request) {
	s.recordFailureAs(ctx, user, now, r, "login.failed")
}

// recordFailureAs records one failed authentication attempt under eventType. | recordFailureAs 在
// eventType 事件下记录一次认证失败。
func (s *Service) recordFailureAs(ctx context.Context, user *User, now time.Time, r *http.Request, eventType string) {
	user.FailedLoginAttempts++
	if user.FailedLoginAttempts >= s.lockout.MaxAttempts {
		user.LockedUntil = now.Add(s.lockout.lockDuration(user.FailedLoginAttempts))
	}
	user.UpdatedAt = now
	if err := s.stores.Users.UpdateUser(ctx, user); err != nil && s.logger != nil {
		s.logger.Warn("auth: failed to record authentication failure | auth：记录认证失败失败", log.Err(err))
	}
	s.audit(ctx, &AuditEvent{
		Type: eventType, UserID: user.ID, IP: requestIP(r), UserAgent: userAgent(r),
		Outcome: "failure", Detail: map[string]string{"attempts": strconv.Itoa(user.FailedLoginAttempts)},
	})
}

// verifyDummyPassword performs one hash verification against a generated throwaway hash. | verifyDummyPassword
// 对一个生成的临时哈希执行一次校验。
func (s *Service) verifyDummyPassword(password string) {
	s.dummyOnce.Do(func() {
		s.dummyHash, _ = s.hash.Hash("ydx-auth-dummy-password")
	})
	if s.dummyHash != "" {
		_, _ = s.hash.Verify(password, s.dummyHash)
	}
}

// issueMFAChallenge stores and returns a single-use password-phase MFA challenge. | issueMFAChallenge
// 保存并返回单次口令阶段 MFA 挑战。
func (s *Service) issueMFAChallenge(ctx context.Context, userID string, now time.Time) (string, error) {
	raw, err := RandomToken(32)
	if err != nil {
		return "", err
	}
	// Only the challenge of the latest password phase may complete; older challenges would otherwise
	// stay valid until their TTL and accumulate in the token store. | 只允许最近一次口令阶段的挑战
	// 完成登录；否则旧挑战会在 TTL 内继续有效并在令牌存储中累积。
	if _, err := s.stores.Tokens.DeleteTokensByUser(ctx, userID, PurposeMFALogin); err != nil {
		return "", err
	}
	token := &OneTimeToken{
		Hash:      HashToken(raw),
		UserID:    userID,
		Purpose:   PurposeMFALogin,
		CreatedAt: now,
		ExpiresAt: now.Add(s.mfaTokenTTL),
	}
	if err := s.stores.Tokens.CreateToken(ctx, token); err != nil {
		return "", err
	}
	return raw, nil
}

// peekMFAChallenge validates a password-phase challenge for userID without consuming it. | peekMFAChallenge
// 校验 userID 的口令阶段挑战但不消费。
func (s *Service) peekMFAChallenge(ctx context.Context, raw, userID string, now time.Time) error {
	if raw == "" {
		return nil
	}
	token, err := s.stores.Tokens.PeekToken(ctx, HashToken(raw), PurposeMFALogin, now)
	if err != nil {
		return err
	}
	if token.UserID != userID {
		return errs.Detail(ErrTokenInvalid, "MFA challenge belongs to another user | MFA 挑战属于其他用户")
	}
	return nil
}

// consumeMFAChallenge burns a validated password-phase challenge. | consumeMFAChallenge 烧掉已校验的口令阶段挑战。
func (s *Service) consumeMFAChallenge(ctx context.Context, raw string, now time.Time) error {
	if raw == "" {
		return nil
	}
	_, err := s.stores.Tokens.ConsumeToken(ctx, HashToken(raw), PurposeMFALogin, now)
	return err
}

// CompleteMFA finishes authentication with a second factor. | CompleteMFA 用第二因素完成认证。
//
// When Authenticate returned a non-empty MFAToken the caller must pass it back; the token binds the
// completion to the password phase, expires quickly and is consumed on success. Failed attempts
// share the password lockout counter so the factor cannot be brute forced without limit. With
// Config.RequireMFAToken enabled an empty MFAToken is rejected, closing the legacy flow that trusts
// a caller-supplied UserID. | 当 Authenticate 返回非空 MFAToken 时调用方必须回传；该令牌把完成
// 动作绑定到口令阶段、快速过期并在成功时消费。失败尝试与口令锁定计数共享，因素无法被无限暴力
// 尝试。启用 Config.RequireMFAToken 后空的 MFAToken 会被拒绝，从而关闭信任调用方 UserID 的旧流程。
func (s *Service) CompleteMFA(ctx context.Context, input CompleteMFAInput) (*AuthenticateResult, error) {
	if input.UserID == "" {
		return nil, errs.Detail(ErrInvalidRequest, "user id is empty | 用户 ID 为空")
	}
	if input.MFAToken == "" && s.config.RequireMFAToken {
		return nil, errs.Detail(ErrInvalidRequest, "MFA token is required | 必须提供 MFA 令牌")
	}
	now := s.nowTime()
	user, err := s.stores.Users.GetUser(ctx, input.UserID)
	if err != nil {
		return nil, err
	}
	if err := user.CanLogin(now); err != nil {
		return nil, err
	}
	if !user.MFAEnabled {
		return nil, errs.Detail(ErrMFAInvalid, "account has no enabled second factor | 账号没有启用的第二因素")
	}
	if err := s.peekMFAChallenge(ctx, input.MFAToken, user.ID, now); err != nil {
		return nil, err
	}
	credentials, err := s.stores.Credentials.ListCredentialsByUser(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	verified := false
	var used *Credential
	for _, credential := range credentials {
		if credential.Disabled || credential.Type == CredentialPassword {
			continue
		}
		if input.CredentialID != "" && credential.ID != input.CredentialID {
			continue
		}
		verifier := s.mfaVerifier(credential.Type)
		if verifier == nil {
			continue
		}
		ok, err := verifier.Verify(ctx, user, credential, input.Response)
		if err != nil {
			continue
		}
		if ok {
			verified = true
			used = credential
			break
		}
	}
	if !verified {
		s.recordFailureAs(ctx, user, now, input.Request, "mfa.failed")
		return nil, ErrMFAInvalid
	}
	if err := s.consumeMFAChallenge(ctx, input.MFAToken, now); err != nil {
		return nil, err
	}
	used.LastUsedAt = now
	used.UpdatedAt = now
	if err := s.stores.Credentials.UpdateCredential(ctx, used); err != nil {
		return nil, err
	}
	user.FailedLoginAttempts = 0
	user.LockedUntil = time.Time{}
	user.UpdatedAt = now
	if s.config.LoginSnapshot {
		user.LastLoginAt = now
		user.LastLoginIP = requestIP(input.Request)
	}
	if err := s.stores.Users.UpdateUser(ctx, user); err != nil {
		return nil, err
	}
	amr := append([]string{"pwd"}, string(used.Type))
	session, err := s.sessions.Create(ctx, user.ID, input.ClientID, input.Request, amr, input.ACR)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, &AuditEvent{
		Type: "login.succeeded", ActorID: user.ID, UserID: user.ID, SessionID: session.ID,
		ClientID: input.ClientID, IP: requestIP(input.Request), UserAgent: userAgent(input.Request),
		Outcome: "success", Detail: map[string]string{"amr": string(used.Type)},
	})
	if s.config.Hooks.AfterLogin != nil {
		if err := s.config.Hooks.AfterLogin(ctx, user, session); err != nil {
			return nil, err
		}
	}
	return &AuthenticateResult{User: user, Session: session}, nil
}

// CompleteMFAInput is the input of Service.CompleteMFA. | CompleteMFAInput 是 Service.CompleteMFA 的输入。
type CompleteMFAInput struct {
	// UserID is the account that passed the password phase. | UserID 是通过口令阶段的账号。
	UserID string
	// CredentialID optionally selects one enrolled factor. | CredentialID 可选地选择一个已登记因素。
	CredentialID string
	// Response is the factor-specific proof, such as a TOTP code. | Response 是因素相关的证明，例如 TOTP 验证码。
	Response string
	// MFAToken is the hidden challenge returned by Authenticate when MFARequired is true. When set,
	// it must match the user and a still-valid password phase and is consumed on success. | MFAToken
	// 是 Authenticate 在 MFARequired 为 true 时返回的隐藏挑战。设置后必须与用户及仍有效的口令阶段匹配，
	// 并在成功时消费。
	MFAToken string
	// ClientID identifies the application or OAuth client. | ClientID 标识应用或 OAuth 客户端。
	ClientID string
	// Request supplies session metadata and is optional. | Request 提供会话元数据，可为空。
	Request *http.Request
	// ACR is the authentication context class reference. | ACR 是认证上下文类引用。
	ACR string
}

// findByLogin resolves a login identifier. | findByLogin 解析登录标识。
func (s *Service) findByLogin(ctx context.Context, login string) (*User, error) {
	login = strings.TrimSpace(login)
	if login == "" {
		return nil, ErrUserNotFound
	}
	if strings.Contains(login, "@") {
		user, err := s.stores.Users.GetUserByEmail(ctx, login)
		if err == nil {
			return user, nil
		}
		if !errors.Is(err, ErrUserNotFound) {
			return nil, err
		}
	}
	if looksLikePhone(login) {
		user, err := s.stores.Users.GetUserByPhone(ctx, login)
		if err == nil {
			return user, nil
		}
		if !errors.Is(err, ErrUserNotFound) {
			return nil, err
		}
	}
	return s.stores.Users.GetUserByUsername(ctx, login)
}

// looksLikePhone reports whether s can be normalized to a phone lookup key. | looksLikePhone 报告 s 能否规范化为手机号查询键。
//
// It accepts the same separators and country-code forms as normalizePhone, so a login written as
// "+86 138-0013-8000" or "0086 13800138000" reaches the phone index. | 它接受与 normalizePhone 相同的
// 分隔符与国家码形式，因此写成 "+86 138-0013-8000" 或 "0086 13800138000" 的登录名会进入手机号索引。
func looksLikePhone(s string) bool {
	_, ok := normalizePhone(s)
	return ok
}

// ChangePassword verifies the current password and replaces it. | ChangePassword 校验当前口令并替换。
func (s *Service) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	user, err := s.stores.Users.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	ok, err := s.hash.Verify(oldPassword, user.PasswordHash)
	if err != nil || !ok {
		return ErrInvalidCredentials
	}
	if err := s.policy.Validate(ctx, newPassword, user); err != nil {
		return err
	}
	if err := checkPasswordReuse(ctx, s.hash, newPassword, user.PasswordHash, user.PasswordHistory); err != nil {
		return err
	}
	encoded, err := s.hash.Hash(newPassword)
	if err != nil {
		return err
	}
	now := s.nowTime()
	user.PasswordHistory = pushPasswordHistory(user.PasswordHash, user.PasswordHistory, s.policy.History)
	user.PasswordHash = encoded
	user.PasswordChangedAt = now
	user.UpdatedAt = now
	if err := s.stores.Users.UpdateUser(ctx, user); err != nil {
		return err
	}
	s.audit(ctx, &AuditEvent{Type: "password.changed", ActorID: user.ID, UserID: user.ID, Outcome: "success"})
	return nil
}

// RequestPasswordReset creates a single-use reset token. | RequestPasswordReset 创建单次重置令牌。
//
// The caller must deliver the raw token out of band and must not reveal whether the login exists
// to an untrusted user. | 调用方必须带外投递原始令牌，且不得向不可信用户泄露登录标识是否存在。
func (s *Service) RequestPasswordReset(ctx context.Context, login string) (string, *User, error) {
	user, err := s.findByLogin(ctx, login)
	if err != nil {
		return "", nil, err
	}
	raw, err := RandomToken(32)
	if err != nil {
		return "", nil, err
	}
	now := s.nowTime()
	token := &OneTimeToken{
		Hash:      HashToken(raw),
		UserID:    user.ID,
		Purpose:   PurposeResetPassword,
		CreatedAt: now,
		ExpiresAt: now.Add(s.config.ResetTokenTTL),
	}
	if _, err := s.stores.Tokens.DeleteTokensByUser(ctx, user.ID, PurposeResetPassword); err != nil {
		return "", nil, err
	}
	if err := s.stores.Tokens.CreateToken(ctx, token); err != nil {
		return "", nil, err
	}
	s.audit(ctx, &AuditEvent{Type: "password.reset_requested", ActorID: user.ID, UserID: user.ID, Outcome: "success"})
	return raw, user, nil
}

// ResetPassword consumes a reset token and replaces the password. | ResetPassword 消费重置令牌并替换口令。
func (s *Service) ResetPassword(ctx context.Context, rawToken, newPassword string) error {
	now := s.nowTime()
	hash := HashToken(rawToken)
	token, err := s.stores.Tokens.PeekToken(ctx, hash, PurposeResetPassword, now)
	if err != nil {
		return err
	}
	user, err := s.stores.Users.GetUser(ctx, token.UserID)
	if err != nil {
		return err
	}
	if err := s.policy.Validate(ctx, newPassword, user); err != nil {
		return err
	}
	if err := checkPasswordReuse(ctx, s.hash, newPassword, user.PasswordHash, user.PasswordHistory); err != nil {
		return err
	}
	encoded, err := s.hash.Hash(newPassword)
	if err != nil {
		return err
	}
	// Consume only after every validation passed, so a weak or reused password does not burn the
	// user's only reset token. | 只有全部校验通过后才消费令牌，弱口令或重复口令不会烧掉用户唯一的重置令牌。
	if _, err := s.stores.Tokens.ConsumeToken(ctx, hash, PurposeResetPassword, now); err != nil {
		return err
	}
	user.PasswordHistory = pushPasswordHistory(user.PasswordHash, user.PasswordHistory, s.policy.History)
	user.PasswordHash = encoded
	user.PasswordChangedAt = now
	user.FailedLoginAttempts = 0
	if user.Status != UserLocked {
		// Preserve an explicit administrative lock; only clear the lockout deadline of an otherwise
		// usable account. | 保留显式管理锁定；仅清除本可使用账号的锁定截止时间。
		user.LockedUntil = time.Time{}
	}
	user.UpdatedAt = now
	if err := s.stores.Users.UpdateUser(ctx, user); err != nil {
		return err
	}
	if _, err := s.sessions.RevokeUser(ctx, user.ID, "password_reset"); err != nil {
		return err
	}
	s.audit(ctx, &AuditEvent{Type: "password.reset", ActorID: user.ID, UserID: user.ID, Outcome: "success"})
	return nil
}

// RequestEmailVerification creates a single-use email-verification token. | RequestEmailVerification 创建单次邮箱验证令牌。
func (s *Service) RequestEmailVerification(ctx context.Context, userID string) (string, error) {
	user, err := s.stores.Users.GetUser(ctx, userID)
	if err != nil {
		return "", err
	}
	if user.Email == "" {
		return "", errs.Detail(ErrInvalidRequest, "user has no email | 用户没有邮箱")
	}
	if user.EmailVerified {
		return "", errs.Detail(ErrInvalidRequest, "email already verified | 邮箱已验证")
	}
	raw, err := RandomToken(32)
	if err != nil {
		return "", err
	}
	now := s.nowTime()
	if _, err := s.stores.Tokens.DeleteTokensByUser(ctx, user.ID, PurposeVerifyEmail); err != nil {
		return "", err
	}
	token := &OneTimeToken{
		Hash:      HashToken(raw),
		UserID:    user.ID,
		Purpose:   PurposeVerifyEmail,
		CreatedAt: now,
		ExpiresAt: now.Add(s.config.VerifyTokenTTL),
	}
	if err := s.stores.Tokens.CreateToken(ctx, token); err != nil {
		return "", err
	}
	s.audit(ctx, &AuditEvent{Type: "email.verification_requested", ActorID: user.ID, UserID: user.ID, Outcome: "success"})
	return raw, nil
}

// VerifyEmail consumes an email-verification token. | VerifyEmail 消费邮箱验证令牌。
func (s *Service) VerifyEmail(ctx context.Context, rawToken string) (*User, error) {
	now := s.nowTime()
	token, err := s.stores.Tokens.ConsumeToken(ctx, HashToken(rawToken), PurposeVerifyEmail, now)
	if err != nil {
		return nil, err
	}
	user, err := s.stores.Users.GetUser(ctx, token.UserID)
	if err != nil {
		return nil, err
	}
	user.EmailVerified = true
	if user.Status == UserPending {
		user.Status = UserActive
	}
	user.UpdatedAt = now
	if err := s.stores.Users.UpdateUser(ctx, user); err != nil {
		return nil, err
	}
	s.audit(ctx, &AuditEvent{Type: "email.verified", ActorID: user.ID, UserID: user.ID, Outcome: "success"})
	return user, nil
}

// RegisterCredential stores a new enrolled factor. | RegisterCredential 保存新的已登记因素。
func (s *Service) RegisterCredential(ctx context.Context, credential *Credential) (*Credential, error) {
	if credential == nil || credential.UserID == "" || credential.Type == "" {
		return nil, errs.Detail(ErrInvalidRequest, "credential, user id or type is empty | 凭据、用户 ID 或类型为空")
	}
	user, err := s.stores.Users.GetUser(ctx, credential.UserID)
	if err != nil {
		return nil, err
	}
	now := s.nowTime()
	stored := credential.Clone()
	stored.ID = NewID("cred")
	stored.CreatedAt = now
	stored.UpdatedAt = now
	if err := s.stores.Credentials.CreateCredential(ctx, stored); err != nil {
		return nil, err
	}
	if credential.Type != CredentialPassword && !credential.Disabled {
		user.MFAEnabled = true
		user.UpdatedAt = now
		if err := s.stores.Users.UpdateUser(ctx, user); err != nil {
			return nil, err
		}
	}
	s.audit(ctx, &AuditEvent{
		Type: "credential.registered", ActorID: user.ID, UserID: user.ID, Outcome: "success",
		Detail: map[string]string{"type": string(stored.Type)},
	})
	return stored, nil
}

// ListCredentials returns the factors of a user without secrets. | ListCredentials 返回用户的可见因素，不含密钥。
func (s *Service) ListCredentials(ctx context.Context, userID string) ([]*Credential, error) {
	credentials, err := s.stores.Credentials.ListCredentialsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	for i, credential := range credentials {
		if credential == nil {
			continue
		}
		// The store needs the secret for verification, but listing must not hand it back to callers
		// that only render account settings. | 存储需要密钥用于校验，但列表不得把它交还给仅渲染账号
		// 设置的调用方。
		sanitized := credential.Clone()
		sanitized.Secret = ""
		credentials[i] = sanitized
	}
	return credentials, nil
}

// RemoveCredential deletes a factor and clears MFAEnabled when no factor remains. | RemoveCredential 删除因素，并在无剩余因素时清除 MFAEnabled。
func (s *Service) RemoveCredential(ctx context.Context, userID, credentialID string) error {
	credential, err := s.stores.Credentials.GetCredential(ctx, credentialID)
	if err != nil {
		return err
	}
	if credential.UserID != userID {
		return errs.Detail(ErrCredentialNotFound, "credential does not belong to user | 凭据不属于该用户")
	}
	if err := s.stores.Credentials.DeleteCredential(ctx, credentialID); err != nil {
		return err
	}
	remaining, err := s.stores.Credentials.ListCredentialsByUser(ctx, userID)
	if err != nil {
		return err
	}
	enabled := false
	for _, credential := range remaining {
		if credential.Type != CredentialPassword && !credential.Disabled {
			enabled = true
			break
		}
	}
	if user, err := s.stores.Users.GetUser(ctx, userID); err == nil {
		user.MFAEnabled = enabled
		user.UpdatedAt = s.nowTime()
		if err := s.stores.Users.UpdateUser(ctx, user); err != nil {
			return err
		}
	}
	s.audit(ctx, &AuditEvent{Type: "credential.removed", ActorID: userID, UserID: userID, Outcome: "success"})
	return nil
}

// LinkIdentity attaches an external identity to a user. | LinkIdentity 把外部身份关联到用户。
func (s *Service) LinkIdentity(ctx context.Context, userID string, identity *Identity) (*Identity, error) {
	if identity == nil || identity.Provider == "" || identity.Subject == "" {
		return nil, errs.Detail(ErrInvalidRequest, "identity fields are empty | 身份字段为空")
	}
	if _, err := s.stores.Users.GetUser(ctx, userID); err != nil {
		return nil, err
	}
	now := s.nowTime()
	stored := identity.Clone()
	stored.UserID = userID
	if stored.CreatedAt.IsZero() {
		stored.CreatedAt = now
	}
	stored.UpdatedAt = now
	if err := s.stores.Identities.CreateIdentity(ctx, stored); err != nil {
		return nil, err
	}
	s.audit(ctx, &AuditEvent{
		Type: "identity.linked", ActorID: userID, UserID: userID, Outcome: "success",
		Detail: map[string]string{"provider": stored.Provider},
	})
	return stored, nil
}

// UnlinkIdentity removes an external identity link. | UnlinkIdentity 删除外部身份关联。
func (s *Service) UnlinkIdentity(ctx context.Context, provider, subject string) error {
	identity, err := s.stores.Identities.GetIdentity(ctx, provider, subject)
	if err != nil {
		return err
	}
	if err := s.stores.Identities.DeleteIdentity(ctx, provider, subject); err != nil {
		return err
	}
	s.audit(ctx, &AuditEvent{
		Type: "identity.unlinked", ActorID: identity.UserID, UserID: identity.UserID, Outcome: "success",
		Detail: map[string]string{"provider": provider},
	})
	return nil
}

// UserByIdentity returns the user linked to an external identity. | UserByIdentity 返回与外部身份关联的用户。
func (s *Service) UserByIdentity(ctx context.Context, provider, subject string) (*User, error) {
	identity, err := s.stores.Identities.GetIdentity(ctx, provider, subject)
	if err != nil {
		return nil, err
	}
	return s.stores.Users.GetUser(ctx, identity.UserID)
}

// EnsureUserFromIdentity returns the linked user or provisions a new account. | EnsureUserFromIdentity 返回已关联用户或预配新账号。
//
// Account linking by verified email is opt-in through linkByEmail. Without it a new account is
// created, which avoids an account-takeover path through an unverified upstream claim. When
// RequireEmailVerification is enabled, a new account whose upstream email is non-empty but
// unverified is provisioned as UserPending; identities without an email and already linked
// accounts are returned unchanged so existing users are not locked out. | 通过已验证邮箱自动关联需
// 显式开启 linkByEmail；未开启时创建新账号，避免经由未验证上游声明接管账号。启用
// RequireEmailVerification 时，上游邮箱非空但未验证的新账号会以 UserPending 预配；没有邮箱的身份
// 与已关联账号原样返回，避免锁死既有用户。
func (s *Service) EnsureUserFromIdentity(ctx context.Context, identity *Identity, linkByEmail bool) (*User, error) {
	if identity == nil || identity.Provider == "" || identity.Subject == "" {
		return nil, errs.Detail(ErrInvalidRequest, "identity fields are empty | 身份字段为空")
	}
	if user, err := s.UserByIdentity(ctx, identity.Provider, identity.Subject); err == nil {
		return user, nil
	} else if !errors.Is(err, ErrIdentityNotFound) {
		return nil, err
	}
	if linkByEmail && identity.Email != "" && identity.EmailVerified {
		if user, err := s.stores.Users.GetUserByEmail(ctx, identity.Email); err == nil {
			if _, err := s.LinkIdentity(ctx, user.ID, identity); err != nil {
				return nil, err
			}
			return user, nil
		} else if !errors.Is(err, ErrUserNotFound) {
			return nil, err
		}
	}
	now := s.nowTime()
	username := identity.Username
	if username == "" {
		username = identity.Provider + "_" + sanitizeUsername(identity.Subject)
	}
	status := UserActive
	if s.config.RequireEmailVerification && identity.Email != "" && !identity.EmailVerified {
		// An unverified upstream email cannot prove ownership; keep the new account pending until
		// the user completes email verification locally. Identities without an email stay active
		// because there is nothing to verify. | 未验证的上游邮箱无法证明归属；新账号保持待定，直到
		// 用户在本地完成邮箱验证。没有邮箱的身份保持活跃，因为没有可验证对象。
		status = UserPending
	}
	user := &User{
		ID:            NewID("usr"),
		Username:      username,
		Email:         identity.Email,
		EmailVerified: identity.EmailVerified,
		DisplayName:   identity.Name,
		Status:        status,
		CreatedAt:     now,
		UpdatedAt:     now,
		Metadata:      cloneStrings(identity.Raw),
	}
	if err := s.stores.Users.CreateUser(ctx, user); err != nil {
		return nil, err
	}
	if _, err := s.LinkIdentity(ctx, user.ID, identity); err != nil {
		// Do not leave an orphan account behind when the link cannot be written. | 关联写入失败时不要
		// 留下孤儿账号。
		if cleanupErr := s.stores.Users.DeleteUser(ctx, user.ID); cleanupErr != nil && s.logger != nil {
			s.logger.Warn("auth: failed to roll back provisioned user | auth：回滚预配用户失败", log.Err(cleanupErr))
		}
		return nil, err
	}
	s.audit(ctx, &AuditEvent{Type: "user.provisioned", ActorID: user.ID, UserID: user.ID, Outcome: "success"})
	return user, nil
}

// sanitizeUsername converts a subject into a safe login fragment. | sanitizeUsername 把 subject 转换为安全的登录片段。
func sanitizeUsername(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s) && len(out) < 32; i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return NewID("u")
	}
	return string(out)
}

// LockUser locks an account until the given time. | LockUser 把账号锁定到给定时间。
func (s *Service) LockUser(ctx context.Context, userID string, until time.Time) error {
	user, err := s.stores.Users.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	user.Status = UserLocked
	user.LockedUntil = until
	user.UpdatedAt = s.nowTime()
	if err := s.stores.Users.UpdateUser(ctx, user); err != nil {
		return err
	}
	if _, err := s.sessions.RevokeUser(ctx, userID, "account_locked"); err != nil {
		return err
	}
	s.audit(ctx, &AuditEvent{Type: "user.locked", ActorID: userID, UserID: userID, Outcome: "success"})
	return nil
}

// UnlockUser removes a lock and resets failed attempts. | UnlockUser 解除锁定并重置失败次数。
func (s *Service) UnlockUser(ctx context.Context, userID string) error {
	user, err := s.stores.Users.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if user.Status == UserLocked {
		user.Status = UserActive
	}
	user.LockedUntil = time.Time{}
	user.FailedLoginAttempts = 0
	user.UpdatedAt = s.nowTime()
	if err := s.stores.Users.UpdateUser(ctx, user); err != nil {
		return err
	}
	s.audit(ctx, &AuditEvent{Type: "user.unlocked", ActorID: userID, UserID: userID, Outcome: "success"})
	return nil
}

// DisableUser disables an account and revokes its sessions. | DisableUser 禁用账号并撤销其会话。
func (s *Service) DisableUser(ctx context.Context, userID string) error {
	user, err := s.stores.Users.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	user.Status = UserDisabled
	user.UpdatedAt = s.nowTime()
	if err := s.stores.Users.UpdateUser(ctx, user); err != nil {
		return err
	}
	if _, err := s.sessions.RevokeUser(ctx, userID, "account_disabled"); err != nil {
		return err
	}
	s.audit(ctx, &AuditEvent{Type: "user.disabled", ActorID: userID, UserID: userID, Outcome: "success"})
	return nil
}

// EnableUser re-enables a disabled account and clears any temporary lockout. | EnableUser 重新启用被禁用的账号并清除临时锁定。
func (s *Service) EnableUser(ctx context.Context, userID string) error {
	user, err := s.stores.Users.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	user.Status = UserActive
	// An operator re-enabling an account expects the login to work; a lock left over from before a
	// disable would otherwise keep rejecting the account until its deadline. | 运维重新启用账号后应能
	// 登录；禁用前遗留的锁定否则会持续拒绝该账号直到期限结束。
	user.LockedUntil = time.Time{}
	user.FailedLoginAttempts = 0
	user.UpdatedAt = s.nowTime()
	if err := s.stores.Users.UpdateUser(ctx, user); err != nil {
		return err
	}
	s.audit(ctx, &AuditEvent{Type: "user.enabled", ActorID: userID, UserID: userID, Outcome: "success"})
	return nil
}

// DeleteUser removes an account and its sessions, identities, credentials and tokens. | DeleteUser 删除账号及其会话、身份、凭据与令牌。
func (s *Service) DeleteUser(ctx context.Context, userID string) error {
	if _, err := s.stores.Users.GetUser(ctx, userID); err != nil {
		return err
	}
	if _, err := s.sessions.RevokeUser(ctx, userID, "account_deleted"); err != nil {
		return err
	}
	if _, err := s.stores.Sessions.DeleteSessionsByUser(ctx, userID); err != nil {
		return err
	}
	identities, err := s.stores.Identities.ListIdentitiesByUser(ctx, userID)
	if err != nil {
		return err
	}
	for _, identity := range identities {
		if err := s.stores.Identities.DeleteIdentity(ctx, identity.Provider, identity.Subject); err != nil {
			return err
		}
	}
	credentials, err := s.stores.Credentials.ListCredentialsByUser(ctx, userID)
	if err != nil {
		return err
	}
	for _, credential := range credentials {
		if err := s.stores.Credentials.DeleteCredential(ctx, credential.ID); err != nil {
			return err
		}
	}
	for _, purpose := range []string{PurposeResetPassword, PurposeVerifyEmail, PurposeInvite, PurposeMFARecovery, PurposeMFALogin} {
		if _, err := s.stores.Tokens.DeleteTokensByUser(ctx, userID, purpose); err != nil {
			return err
		}
	}
	if err := s.stores.Users.DeleteUser(ctx, userID); err != nil {
		return err
	}
	s.audit(ctx, &AuditEvent{Type: "user.deleted", ActorID: userID, UserID: userID, Outcome: "success"})
	return nil
}

// PrincipalForUser builds a principal from a stored user. | PrincipalForUser 从已存用户构建主体。
func (s *Service) PrincipalForUser(user *User) *Principal {
	return DefaultPrincipal(user, nil)
}

// Audit records an event through the service audit store. | Audit 通过服务审计存储记录事件。
func (s *Service) Audit(ctx context.Context, event *AuditEvent) {
	s.audit(ctx, event)
}

// audit normalizes and stores an event. | audit 规范化并存储事件。
func (s *Service) audit(ctx context.Context, event *AuditEvent) {
	if event == nil || s.stores.Audits == nil {
		return
	}
	if event.ID == "" {
		event.ID = NewID("evt")
	}
	if event.At.IsZero() {
		event.At = s.nowTime()
	}
	if err := s.stores.Audits.RecordAudit(ctx, event); err != nil {
		if s.logger != nil {
			s.logger.Warn("auth: audit write failed | auth：审计写入失败", log.Err(err))
		}
		return
	}
	if s.config.Hooks.AfterAudit != nil {
		s.config.Hooks.AfterAudit(ctx, event)
	}
}

// checkPasswordReuse rejects a password equal to the current one or any history entry. | checkPasswordReuse
// 拒绝与当前口令或任一历史口令相同的口令。
func checkPasswordReuse(ctx context.Context, hasher PasswordHasher, password, current string, history []string) error {
	if current != "" && hasher != nil {
		if ok, err := hasher.Verify(password, current); err == nil && ok {
			return ErrPasswordReused
		}
	}
	return CheckHistory(ctx, hasher, password, history)
}

// pushPasswordHistory prepends old and trims the history to limit. | pushPasswordHistory 前插 old 并把历史裁剪到 limit。
func pushPasswordHistory(old string, history []string, limit int) []string {
	if old == "" || limit <= 0 {
		return history
	}
	out := make([]string, 0, minInt(limit, len(history)+1))
	out = append(out, old)
	for _, encoded := range history {
		if len(out) >= limit {
			break
		}
		if encoded != old {
			out = append(out, encoded)
		}
	}
	return out
}

// cloneStrings returns a copy of m. | cloneStrings 返回 m 的副本。
func cloneStrings(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// minInt returns the smaller of a and b. | minInt 返回 a 与 b 的较小值。
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// userAgent returns the request user agent or an empty string. | userAgent 返回请求 User-Agent 或空串。
func userAgent(r *http.Request) string {
	if r == nil {
		return ""
	}
	return r.UserAgent()
}
