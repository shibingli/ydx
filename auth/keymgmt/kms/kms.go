package kms

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
	ydlog "github.com/shibingli/ydx/log"
)

// Config configures a Service. | Config 配置 Service。
type Config struct {
	// Store is the required persistence backend. | Store 是必需的持久化后端。
	Store Store
	// RootKey optionally supplies an at-rest wrapping key of type AES, ChaCha20 or SM4. Its Material
	// is used to encrypt stored key material with AES-GCM. | RootKey 可选地提供 AES、ChaCha20 或 SM4
	// 类型的静态包装密钥。其 Material 用于以 AES-GCM 加密存储的密钥材料。
	RootKey *Key
	// Passphrase optionally derives the at-rest wrapping key with PBKDF2-HMAC-SHA256. RootKey and
	// Passphrase are mutually exclusive. | Passphrase 可选地用 PBKDF2-HMAC-SHA256 派生静态包装密钥。
	// RootKey 与 Passphrase 互斥。
	Passphrase string
	// Clock supplies UTC time; nil means time.Now. | Clock 提供 UTC 时间；nil 表示 time.Now。
	Clock func() time.Time
	// Audit overrides the audit sink; nil falls back to Store. | Audit 覆盖审计接收器；nil 回退到 Store。
	Audit AuditSink
	// Wrapper overrides at-rest material wrapping. It takes precedence over RootKey and Passphrase. | Wrapper
	// 覆盖静态材料包装。它优先于 RootKey 与 Passphrase。
	Wrapper Wrapper
	// RequireAtRestEncryption rejects construction when no at-rest protection is configured.
	// RootKey, Passphrase or a custom Wrapper satisfies the requirement; the service never
	// generates an ephemeral wrapping key implicitly. | RequireAtRestEncryption 在未配置任何静态
	// 保护时拒绝构建。RootKey、Passphrase 或自定义 Wrapper 均可满足该要求；服务绝不会隐式生成
	// 临时包装密钥。
	RequireAtRestEncryption bool
	// Logger receives diagnostics; nil means the ydx/log default logger. | Logger 接收诊断信息；nil 表示 ydx/log 默认日志器。
	Logger *ydlog.Logger
	// ExportPolicy authorizes private export service-wide; the zero value denies it. | ExportPolicy
	// 在服务范围授权私钥导出；零值拒绝。
	ExportPolicy ExportPolicy
	// DefaultRotationInterval is copied to keys created without an explicit interval. | DefaultRotationInterval
	// 复制到未显式指定间隔的新密钥。
	DefaultRotationInterval time.Duration
	// DeletionDelay is the default ScheduleDelete delay when delay is zero. | DeletionDelay 是 delay 为零时 ScheduleDelete 的默认延迟。
	DeletionDelay time.Duration
	// MaxDataKeyLength caps GenerateDataKey and DeriveKey output; zero means 1024 bytes. | MaxDataKeyLength
	// 限制 GenerateDataKey 与 DeriveKey 的输出；零表示 1024 字节。
	MaxDataKeyLength int
}

// Service is a full-stack key management service: lifecycle, envelope encryption, signing, wrapping,
// derivation and auditing. | Service 是全栈密钥管理服务：生命周期、信封加密、签名、包装、派生与审计。
type Service struct {
	// store is the persistence backend. | store 是持久化后端。
	store Store
	// keys is the material-safe read facade used by Service.GetKey and Service.ListKeys. | keys 是
	// Service.GetKey 与 Service.ListKeys 使用的材料安全读取门面。
	keys *KeyStore
	// clock supplies UTC time. | clock 提供 UTC 时间。
	clock func() time.Time
	// audit receives every operation event. | audit 接收每个操作事件。
	audit AuditSink
	// logger receives diagnostics. | logger 接收诊断信息。
	logger *ydlog.Logger
	// wrapper encrypts private material at rest; nil stores material as provided. | wrapper 静态加密
	// 私钥材料；nil 表示按提供的内容存储。
	wrapper Wrapper
	// exportPolicy authorizes private export service-wide. | exportPolicy 在服务范围授权私钥导出。
	exportPolicy ExportPolicy
	// defaultRotation is copied to new keys without an explicit interval. | defaultRotation 复制到
	// 未显式指定间隔的新密钥。
	defaultRotation time.Duration
	// deletionDelay is the default ScheduleDelete delay. | deletionDelay 是 ScheduleDelete 的默认延迟。
	deletionDelay time.Duration
	// maxDataKeyLength caps generated and derived key lengths. | maxDataKeyLength 限制生成与派生的密钥长度。
	maxDataKeyLength int
	// nonces tracks recently used nonces per key version to reject reuse. | nonces 按密钥版本跟踪近期
	// 使用的 nonce 以拒绝重用。
	nonces sync.Map
}

// New builds a Service from config. | New 由 config 构建 Service。
//
// It returns ErrInvalidConfig for a nil Store, for using both RootKey and Passphrase, for an
// invalid at-rest key, or when RequireAtRestEncryption is set without RootKey, Passphrase or
// Wrapper. | Store 为空、同时使用 RootKey 与 Passphrase、静态密钥非法，或在
// RequireAtRestEncryption 开启但未提供 RootKey、Passphrase 或 Wrapper 时返回 ErrInvalidConfig。
func New(config Config) (*Service, error) {
	if config.Store == nil {
		return nil, errs.Detail(ErrInvalidConfig, "store is required | 必须提供存储")
	}
	if config.RootKey != nil && config.Passphrase != "" {
		return nil, errs.Detail(ErrInvalidConfig, "RootKey and Passphrase are mutually exclusive | RootKey 与 Passphrase 互斥")
	}
	if config.RequireAtRestEncryption && config.Wrapper == nil && config.RootKey == nil && config.Passphrase == "" {
		return nil, errs.Detail(ErrInvalidConfig, "at-rest encryption is required but no RootKey, Passphrase or Wrapper is configured | 要求静态加密但未配置 RootKey、Passphrase 或 Wrapper")
	}
	wrapper := config.Wrapper
	if wrapper == nil {
		var err error
		wrapper, err = newAtRestWrapper(config.RootKey, config.Passphrase)
		if err != nil {
			return nil, err
		}
	}
	logger := config.Logger
	if logger == nil {
		logger = ydlog.Default()
	}
	audit := config.Audit
	if audit == nil {
		audit = config.Store
	}
	maxKeyLength := config.MaxDataKeyLength
	if maxKeyLength <= 0 {
		maxKeyLength = defaultMaxDerivedLength
	}
	service := &Service{
		store:            config.Store,
		keys:             NewKeyStore(config.Store, config.ExportPolicy),
		clock:            config.Clock,
		audit:            audit,
		logger:           logger,
		wrapper:          wrapper,
		exportPolicy:     config.ExportPolicy,
		defaultRotation:  config.DefaultRotationInterval,
		deletionDelay:    config.DeletionDelay,
		maxDataKeyLength: maxKeyLength,
	}
	return service, nil
}

// NewService builds a Service from config. It is an alias for New and enforces the same
// at-rest requirements. | NewService 由 config 构建 Service。它是 New 的别名，并执行相同的
// 静态加密要求。
func NewService(config Config) (*Service, error) {
	return New(config)
}

// Store returns the backing store. | Store 返回底层存储。
func (s *Service) Store() Store {
	if s == nil {
		return nil
	}
	return s.store
}

// Now returns the configured clock time in UTC. | Now 返回配置时钟的 UTC 时间。
func (s *Service) Now() time.Time {
	if s == nil || s.clock == nil {
		return time.Now().UTC()
	}
	return s.clock().UTC()
}

// AtRestEnabled reports whether private key material is wrapped at rest. It is false
// when the service stores material as provided. | AtRestEnabled 报告私钥材料是否在静态存储
// 时被包装。服务按原样存储材料时返回 false。
func (s *Service) AtRestEnabled() bool {
	if s == nil {
		return false
	}
	return s.wrapper != nil
}

// Keys returns the material-safe read facade. | Keys 返回材料安全读取门面。
func (s *Service) Keys() *KeyStore {
	if s == nil {
		return nil
	}
	return s.keys
}

// ExportPolicy returns the service export policy. | ExportPolicy 返回服务导出策略。
func (s *Service) ExportPolicy() ExportPolicy {
	if s == nil {
		return ExportPolicy{}
	}
	return s.exportPolicy
}

// emit appends one audit event, logging failures without failing the operation. | emit 追加一个审计
// 事件，失败时记录日志但不使操作失败。
func (s *Service) emit(ctx context.Context, operation, keyID string, version uint32, outcome string, detail map[string]string) {
	if s == nil || s.audit == nil {
		return
	}
	event := &AuditEvent{
		Operation:  operation,
		Actor:      ActorFromContext(ctx),
		KeyID:      keyID,
		KeyVersion: version,
		Outcome:    outcome,
		Detail:     detail,
		At:         s.Now(),
	}
	if err := s.audit.AppendAudit(ctx, event); err != nil {
		s.log().Warn("kms: audit append failed | kms：审计写入失败",
			ydlog.Str("operation", operation), ydlog.Str("key_id", keyID), ydlog.Err(err))
	}
}

// succeed records a successful operation. | succeed 记录成功操作。
func (s *Service) succeed(ctx context.Context, operation, keyID string, version uint32, detail map[string]string) {
	s.emit(ctx, operation, keyID, version, OutcomeSuccess, detail)
}

// deny records a policy denial. | deny 记录策略拒绝。
func (s *Service) deny(ctx context.Context, operation, keyID string, detail map[string]string) {
	s.emit(ctx, operation, keyID, 0, OutcomeDenied, detail)
}

// fail records a failed operation with its classified error label. | fail 记录失败操作及其分类错误标签。
func (s *Service) fail(ctx context.Context, operation, keyID string, version uint32, err error) {
	detail := map[string]string{"error": errorLabel(err)}
	s.emit(ctx, operation, keyID, version, OutcomeFailure, detail)
}

// log returns a usable logger. | log 返回可用的日志器。
func (s *Service) log() *ydlog.Logger {
	if s != nil && s.logger != nil {
		return s.logger
	}
	return ydlog.Default()
}

// rememberNonce records a nonce for keyID/version and reports whether it is fresh. | rememberNonce
// 为 keyID/version 记录 nonce，并报告其是否为新值。
func (s *Service) rememberNonce(keyID string, version uint32, nonce []byte) bool {
	if len(nonce) != gcmNonceSize {
		return false
	}
	var value [gcmNonceSize]byte
	copy(value[:], nonce)
	key := keyID + "/" + strconvUint32(version)
	entry, _ := s.nonces.LoadOrStore(key, newNonceCache(nonceCacheSize))
	return entry.(*nonceCache).add(value)
}

// forgetNonceVersion drops the nonce history of one key version. | forgetNonceVersion 丢弃单个密钥
// 版本的 nonce 历史。
func (s *Service) forgetNonceVersion(keyID string, version uint32) {
	if s == nil || keyID == "" {
		return
	}
	s.nonces.Delete(keyID + "/" + strconvUint32(version))
}

// forgetNonces drops the nonce history of every version of keyID. | forgetNonces 丢弃 keyID 全部
// 版本的 nonce 历史。
func (s *Service) forgetNonces(keyID string) {
	if s == nil || keyID == "" {
		return
	}
	prefix := keyID + "/"
	s.nonces.Range(func(key, _ any) bool {
		if name, ok := key.(string); ok && strings.HasPrefix(name, prefix) {
			s.nonces.Delete(key)
		}
		return true
	})
}

// nonceCache is a bounded insertion-ordered nonce set. | nonceCache 是有界、按插入排序的 nonce 集合。
type nonceCache struct {
	// mu guards the fields below. | mu 保护下面的字段。
	mu sync.Mutex
	// seen holds every retained nonce. | seen 保存保留的全部 nonce。
	seen map[[gcmNonceSize]byte]struct{}
	// order preserves insertion order for eviction. | order 保留插入顺序用于淘汰。
	order [][gcmNonceSize]byte
	// max is the retained capacity. | max 是保留容量。
	max int
}

// newNonceCache returns a cache retaining at most capacity nonces. | newNonceCache 返回最多保留
// capacity 个 nonce 的缓存。
func newNonceCache(capacity int) *nonceCache {
	if capacity <= 0 {
		capacity = nonceCacheSize
	}
	return &nonceCache{seen: make(map[[gcmNonceSize]byte]struct{}, capacity), max: capacity}
}

// add records value and reports whether it was absent. | add 记录 value 并报告其此前是否不存在。
func (c *nonceCache) add(value [gcmNonceSize]byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.seen[value]; ok {
		return false
	}
	if len(c.order) >= c.max {
		oldest := c.order[0]
		delete(c.seen, oldest)
		c.order = c.order[1:]
	}
	c.seen[value] = struct{}{}
	c.order = append(c.order, value)
	return true
}

// Constants shared by the cryptographic paths. | 密码路径共享的常量。
const (
	// gcmNonceSize is the 96-bit GCM nonce mandated by the envelope format. | gcmNonceSize 是信封格式要求的 96 位 GCM nonce。
	gcmNonceSize = 12
	// nonceCacheSize bounds the per-version nonce history. | nonceCacheSize 限制每个版本的 nonce 历史。
	nonceCacheSize = 4096
	// defaultMaxDerivedLength caps derived and generated key lengths. | defaultMaxDerivedLength 限制派生与生成的密钥长度。
	defaultMaxDerivedLength = 1024
	// maxKeyIDLength bounds an identifier inside a binary envelope. | maxKeyIDLength 限制二进制信封中的标识长度。
	maxKeyIDLength = 1024
)

// randomBytes returns n bytes from crypto/rand. | randomBytes 从 crypto/rand 返回 n 字节。
func randomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errs.Detail(ErrInvalidRequest, "invalid random length %[1]d | 随机长度 %[1]d 非法", n)
	}
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		return nil, errs.Wrap(err, ErrRandomSource)
	}
	return out, nil
}

// randomID returns a 32-character lowercase hex identifier. | randomID 返回 32 字符小写十六进制标识。
func randomID() (string, error) {
	raw, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// zeroBytes overwrites b with zeroes. | zeroBytes 用零覆盖 b。
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// lowerASCII lowercases s for case-insensitive matching. | lowerASCII 把 s 转小写用于大小写不敏感匹配。
func lowerASCII(s string) string { return strings.ToLower(s) }

// containsFold reports whether s contains the already-lowercased needle. | containsFold 报告 s 是否
// 包含已转小写的 needle。
func containsFold(s, needle string) bool {
	if needle == "" {
		return true
	}
	return strings.Contains(strings.ToLower(s), needle)
}

// errorsIs is a local alias for errors.Is. | errorsIs 是 errors.Is 的本地别名。
func errorsIs(err, target error) bool { return errors.Is(err, target) }

// strconvUint32 formats v without importing strconv at every call site. | strconvUint32 格式化 v，
// 避免在每个调用点导入 strconv。
func strconvUint32(v uint32) string {
	if v == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// errorLabel returns a stable, secret-free label for an error. | errorLabel 返回稳定且不含机密的错误标签。
func errorLabel(err error) string {
	if err == nil {
		return "none"
	}
	switch {
	case errors.Is(err, ErrNotFound):
		return "not_found"
	case errors.Is(err, ErrKeyExists):
		return "key_exists"
	case errors.Is(err, ErrAliasExists):
		return "alias_exists"
	case errors.Is(err, ErrAliasNotFound):
		return "alias_not_found"
	case errors.Is(err, ErrVersionNotFound):
		return "version_not_found"
	case errors.Is(err, ErrVersionExists):
		return "version_exists"
	case errors.Is(err, ErrConflict):
		return "conflict"
	case errors.Is(err, ErrInvalidState):
		return "invalid_state"
	case errors.Is(err, ErrKeyNotUsable):
		return "key_not_usable"
	case errors.Is(err, ErrUsageNotAllowed):
		return "usage_not_allowed"
	case errors.Is(err, ErrInvalidKeyType):
		return "invalid_key_type"
	case errors.Is(err, ErrInvalidKeySize):
		return "invalid_key_size"
	case errors.Is(err, ErrInvalidMaterial):
		return "invalid_material"
	case errors.Is(err, ErrInvalidCiphertext):
		return "invalid_ciphertext"
	case errors.Is(err, ErrAuthentication):
		return "authentication_failed"
	case errors.Is(err, ErrExportDenied):
		return "export_denied"
	case errors.Is(err, ErrNotSupported):
		return "not_supported"
	case errors.Is(err, ErrNonceReuse):
		return "nonce_reuse"
	case errors.Is(err, ErrRandomSource):
		return "random_source"
	case errors.Is(err, ErrInvalidRequest):
		return "invalid_request"
	case errors.Is(err, ErrInvalidConfig):
		return "invalid_config"
	case errors.Is(err, ErrUnauthorized):
		return "unauthorized"
	case errors.Is(err, ErrForbidden):
		return "forbidden"
	default:
		return "internal"
	}
}
