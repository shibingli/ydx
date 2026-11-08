package ldap

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

const (
	// DefaultTimeout is the per-exchange network timeout. | DefaultTimeout 是每次网络交换的超时。
	DefaultTimeout = 30 * time.Second
	// DefaultDialTimeout bounds TCP connection establishment and TLS handshakes. |
	// DefaultDialTimeout 限制 TCP 建连与 TLS 握手。
	DefaultDialTimeout = 10 * time.Second
	// DefaultMaxMessageSize is the largest accepted LDAP message. | DefaultMaxMessageSize 是接受的最大 LDAP 消息。
	DefaultMaxMessageSize = 64 << 20
	// DefaultPoolSize is the default maximum number of pooled connections. | DefaultPoolSize 是连接池的默认最大连接数。
	DefaultPoolSize = 4
	// DefaultMaxIdleTime is the default time an idle pooled connection is retained. |
	// DefaultMaxIdleTime 是空闲池连接默认保留时间。
	DefaultMaxIdleTime = 5 * time.Minute
	// DefaultIdleHealthCheckTimeout bounds one idle-connection liveness probe. |
	// DefaultIdleHealthCheckTimeout 限制单次空闲连接存活探测。
	DefaultIdleHealthCheckTimeout = 2 * time.Second
)

// HealthCheckMode selects the liveness probe a Pool runs on an idle connection
// before handing it to a borrower. | HealthCheckMode 选择连接池在把空闲连接交给借用方之前
// 执行的存活探测。
type HealthCheckMode int

const (
	// HealthCheckDisabled disables idle probing; Get returns a reused connection
	// without a round trip. It is the default. | HealthCheckDisabled 关闭空闲探测；Get
	// 不做往返即返回复用连接。这是默认值。
	HealthCheckDisabled HealthCheckMode = iota
	// HealthCheckWhoAmI probes with an RFC 4532 Who Am I request. It is the
	// cheapest round trip but requires server support for the extension. |
	// HealthCheckWhoAmI 使用 RFC 4532 Who Am I 请求探测。它是最便宜的往返，但需要服务端支持该扩展。
	HealthCheckWhoAmI
	// HealthCheckRootDSE probes with a base-scope search of the root DSE. Almost
	// every LDAP server supports it, at the cost of one search. |
	// HealthCheckRootDSE 通过根 DSE 的基础范围搜索探测。几乎所有 LDAP 服务端都支持，代价是一次搜索。
	HealthCheckRootDSE
)

// ReferralHandler receives referral URIs. The client never follows referrals
// automatically; this hook lets an application resolve or reject them under
// its own policy. | ReferralHandler 接收转介 URI。客户端从不自动跟随转介；该钩子让
// 应用按自身策略解析或拒绝转介。
type ReferralHandler func(ctx context.Context, urls []string) error

// Config configures a Client or Pool. | Config 配置 Client 或 Pool。
type Config struct {
	// URL is an ldap:// or ldaps:// endpoint, for example ldaps://dc1.example.com. |
	// URL 是 ldap:// 或 ldaps:// 地址，例如 ldaps://dc1.example.com。
	URL string
	// TLSConfig overrides TLS parameters. It is cloned, never mutated. | TLSConfig
	// 覆盖 TLS 参数；它会被克隆而不会被修改。
	TLSConfig *tls.Config
	// StartTLS upgrades a plain ldap:// connection before binding. | StartTLS 在绑定前把
	// 明文 ldap:// 连接升级为 TLS。
	StartTLS bool
	// Timeout bounds each write and each response read. Zero uses DefaultTimeout. |
	// Timeout 限制每次写入与每次响应读取。零使用 DefaultTimeout。
	Timeout time.Duration
	// DialTimeout bounds connection and TLS handshake setup. Zero uses DefaultDialTimeout. |
	// DialTimeout 限制建连与 TLS 握手。零使用 DefaultDialTimeout。
	DialTimeout time.Duration
	// MaxMessageSize bounds one BER LDAP message. Zero uses DefaultMaxMessageSize. |
	// MaxMessageSize 限制单条 BER LDAP 消息。零使用 DefaultMaxMessageSize。
	MaxMessageSize int
	// PoolSize is the maximum number of connections created by a Pool. Zero uses
	// DefaultPoolSize. Dial ignores it. | PoolSize 是连接池最大连接数。零使用 DefaultPoolSize。
	// Dial 忽略该字段。
	PoolSize int
	// MaxIdle bounds idle connections retained by a Pool. Zero uses PoolSize. | MaxIdle
	// 限制连接池保留的空闲连接数。零使用 PoolSize。
	MaxIdle int
	// MaxIdleTime bounds how long a Pool retains an idle connection. Zero uses
	// DefaultMaxIdleTime. | MaxIdleTime 限制连接池保留空闲连接的时间。零使用 DefaultMaxIdleTime。
	MaxIdleTime time.Duration
	// HealthCheck selects the liveness probe a Pool runs before reusing an idle
	// connection. A failed probe discards the connection and Get dials a
	// replacement. Newly dialed connections are not probed. Dial ignores it. | HealthCheck
	// 选择连接池复用空闲连接前执行的存活探测。探测失败会丢弃该连接，Get 重新拨号。新拨号的连接
	// 不做探测。Dial 忽略该字段。
	HealthCheck HealthCheckMode
	// IdleHealthCheckTimeout bounds one idle probe. Zero uses
	// DefaultIdleHealthCheckTimeout. The probe never inherits the borrower's
	// deadline, so a short operation deadline cannot discard a healthy connection. |
	// IdleHealthCheckTimeout 限制单次空闲探测。零使用 DefaultIdleHealthCheckTimeout。探测不继承
	// 借用方的期限，因此短操作期限不会丢弃健康连接。
	IdleHealthCheckTimeout time.Duration
	// RequireSASLPlainTLS rejects SASL PLAIN when the connection is not
	// TLS-protected. Empty credentials would otherwise cross the network in
	// cleartext. The default is false for compatibility; enable it whenever the
	// server supports StartTLS or LDAPS. | RequireSASLPlainTLS 在连接未受 TLS 保护时拒绝
	// SASL PLAIN，否则凭据会以明文经过网络。为了兼容默认值为 false；当服务端支持 StartTLS 或
	// LDAPS 时应启用。
	RequireSASLPlainTLS bool
	// BindDN optionally auto-binds with a simple bind after every connection. | BindDN
	// 可选地在每次连接后执行简单绑定。
	BindDN string
	// BindPassword is the auto-bind password. It is never included in errors or logs. |
	// BindPassword 是自动绑定口令，绝不会出现在错误或日志中。
	BindPassword string
	// ReferralHandler is the default referral hook. | ReferralHandler 是默认转介钩子。
	ReferralHandler ReferralHandler
}

// endpoint is a validated LDAP network endpoint. | endpoint 是校验后的 LDAP 网络端点。
type endpoint struct {
	address    string
	serverName string
	secure     bool
}

// normalizedConfig is the effective configuration after defaults. | normalizedConfig
// 是应用默认值后的有效配置。
type normalizedConfig struct {
	Config
	endpoint endpoint
	tls      *tls.Config
}

// Dial connects and optionally binds using cfg. The returned Client owns one
// connection and serializes operations on it; use NewPool for concurrency. | Dial
// 使用 cfg 建立连接并按需绑定。返回的 Client 拥有一个连接并串行化其上的操作；并发请使用
// NewPool。
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	client := &Client{cfg: normalized}
	if err := client.connectLocked(ctx); err != nil {
		client.closeConnLocked()
		return nil, err
	}
	if normalized.BindDN != "" {
		response, err := client.performSimpleBindLocked(ctx, normalized.BindDN, normalized.BindPassword)
		if err != nil {
			client.closeConnLocked()
			return nil, err
		}
		if response.Result.Code != ResultSuccess {
			client.closeConnLocked()
			return nil, newResultError("bind", response.Result)
		}
		client.auth = &authState{
			kind:     authSimple,
			dn:       normalized.BindDN,
			password: normalized.BindPassword,
		}
	}
	return client, nil
}

// DialURL connects to rawURL. An optional cfg supplies TLS, timeout, bind and
// pool defaults; its URL field is replaced by rawURL. | DialURL 连接 rawURL。可选 cfg
// 提供 TLS、超时、绑定与连接池默认值；其 URL 字段会被 rawURL 覆盖。
func DialURL(ctx context.Context, rawURL string, cfg ...Config) (*Client, error) {
	if len(cfg) > 1 {
		return nil, errs.Detail(ErrInvalidConfig, "DialURL accepts at most one config | DialURL 最多接受一个配置")
	}
	var effective Config
	if len(cfg) == 1 {
		effective = cfg[0]
	}
	effective.URL = rawURL
	return Dial(ctx, effective)
}

// normalizeConfig validates cfg and applies defaults. | normalizeConfig 校验 cfg
// 并应用默认值。
func normalizeConfig(cfg Config) (normalizedConfig, error) {
	ep, err := parseEndpoint(cfg.URL)
	if err != nil {
		return normalizedConfig{}, err
	}
	if cfg.StartTLS && ep.secure {
		return normalizedConfig{}, errs.Detail(ErrInvalidConfig, "StartTLS cannot be combined with ldaps | StartTLS 不能与 ldaps 同时使用")
	}
	if cfg.BindPassword != "" && cfg.BindDN == "" {
		return normalizedConfig{}, errs.Detail(ErrInvalidConfig, "bind password requires a bind DN | 绑定口令需要绑定 DN")
	}
	if cfg.BindDN != "" && cfg.BindPassword == "" {
		return normalizedConfig{}, errs.Detail(ErrInvalidConfig, "auto-bind DN requires a password; anonymous bind must be explicit | 自动绑定 DN 需要口令；匿名绑定必须显式执行")
	}
	if cfg.Timeout < 0 {
		return normalizedConfig{}, errs.Detail(ErrInvalidConfig, "negative timeout | 超时为负")
	}
	if cfg.DialTimeout < 0 {
		return normalizedConfig{}, errs.Detail(ErrInvalidConfig, "negative dial timeout | 建连超时为负")
	}
	if cfg.PoolSize < 0 || cfg.MaxIdle < 0 || cfg.MaxIdleTime < 0 {
		return normalizedConfig{}, errs.Detail(ErrInvalidConfig, "negative pool setting | 连接池设置为负")
	}
	if cfg.IdleHealthCheckTimeout < 0 {
		return normalizedConfig{}, errs.Detail(ErrInvalidConfig, "negative idle health check timeout | 空闲健康检查超时为负")
	}
	if cfg.HealthCheck < HealthCheckDisabled || cfg.HealthCheck > HealthCheckRootDSE {
		return normalizedConfig{}, errs.Detail(ErrInvalidConfig, "unsupported health check mode %d | 不支持的健康检查模式 %d", int(cfg.HealthCheck), int(cfg.HealthCheck))
	}
	if cfg.MaxMessageSize < 0 || cfg.MaxMessageSize > 1<<30 {
		return normalizedConfig{}, errs.Detail(ErrInvalidConfig, "max message size %d is out of range | 最大消息大小 %d 超出范围", cfg.MaxMessageSize, cfg.MaxMessageSize)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = DefaultDialTimeout
	}
	if cfg.MaxMessageSize == 0 {
		cfg.MaxMessageSize = DefaultMaxMessageSize
	}
	if cfg.PoolSize == 0 {
		cfg.PoolSize = DefaultPoolSize
	}
	if cfg.MaxIdle == 0 {
		cfg.MaxIdle = cfg.PoolSize
	}
	if cfg.MaxIdle == 0 {
		cfg.MaxIdle = 1
	}
	if cfg.MaxIdle > cfg.PoolSize {
		cfg.MaxIdle = cfg.PoolSize
	}
	if cfg.MaxIdleTime == 0 {
		cfg.MaxIdleTime = DefaultMaxIdleTime
	}
	if cfg.IdleHealthCheckTimeout == 0 {
		cfg.IdleHealthCheckTimeout = DefaultIdleHealthCheckTimeout
	}
	tlsConfig := cloneTLSConfig(cfg.TLSConfig, ep.serverName)
	cfg.TLSConfig = nil
	return normalizedConfig{Config: cfg, endpoint: ep, tls: tlsConfig}, nil
}

// parseEndpoint validates an LDAP URL and derives its host and port. | parseEndpoint
// 校验 LDAP URL 并推导主机与端口。
func parseEndpoint(raw string) (endpoint, error) {
	if strings.TrimSpace(raw) == "" {
		return endpoint{}, errs.Detail(ErrInvalidURL, "empty URL | 地址为空")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return endpoint{}, errs.WrapDetail(err, ErrInvalidURL, "cannot parse URL | 无法解析地址")
	}
	scheme := strings.ToLower(parsed.Scheme)
	var secure bool
	var defaultPort string
	switch scheme {
	case "ldap":
		defaultPort = "389"
	case "ldaps":
		secure = true
		defaultPort = "636"
	default:
		return endpoint{}, errs.Detail(ErrInvalidURL, "unsupported scheme %q | 不支持的协议 %q", parsed.Scheme, parsed.Scheme)
	}
	if parsed.Opaque != "" {
		return endpoint{}, errs.Detail(ErrInvalidURL, "opaque URLs are not supported | 不支持不透明地址")
	}
	if parsed.User != nil {
		return endpoint{}, errs.Detail(ErrInvalidURL, "userinfo is not allowed in an LDAP URL | LDAP 地址不允许 userinfo")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return endpoint{}, errs.Detail(ErrInvalidURL, "query and fragment are not allowed | 不允许查询与片段")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return endpoint{}, errs.Detail(ErrInvalidURL, "LDAP URL path is not an endpoint | LDAP 地址路径不是连接端点")
	}
	host := parsed.Hostname()
	if host == "" {
		return endpoint{}, errs.Detail(ErrInvalidURL, "missing host | 缺少主机")
	}
	port := parsed.Port()
	if port == "" {
		port = defaultPort
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return endpoint{}, errs.Detail(ErrInvalidURL, "invalid port %q | 端口 %q 非法", port, port)
	}
	return endpoint{
		address:    net.JoinHostPort(host, strconv.Itoa(number)),
		serverName: host,
		secure:     secure,
	}, nil
}

// cloneTLSConfig clones cfg and fills a secure default. | cloneTLSConfig 克隆 cfg
// 并填充安全默认值。
func cloneTLSConfig(cfg *tls.Config, serverName string) *tls.Config {
	var clone *tls.Config
	if cfg == nil {
		clone = &tls.Config{}
	} else {
		clone = cfg.Clone()
	}
	if clone.ServerName == "" {
		clone.ServerName = serverName
	}
	if clone.MinVersion == 0 {
		clone.MinVersion = tls.VersionTLS12
	}
	return clone
}
