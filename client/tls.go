package client

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
)

// TLSConfig configures outbound HTTPS trust, client certificates and pinning. | TLSConfig 配置出站 HTTPS 信任、客户端证书与证书固定。
type TLSConfig struct {
	// RootCAs replaces the system roots when set. | RootCAs 设置时替换系统根。
	RootCAs *x509.CertPool
	// GetClientCertificate supplies a client certificate dynamically. | GetClientCertificate 动态提供客户端证书。
	GetClientCertificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	// VerifyConnection runs after standard verification and pinning. | VerifyConnection 在标准校验与固定之后运行。
	VerifyConnection func(tls.ConnectionState) error
	// CertFile is the client certificate PEM path for mTLS. | CertFile 是 mTLS 客户端证书 PEM 路径。
	CertFile string
	// KeyFile is the client private key PEM path for mTLS. | KeyFile 是 mTLS 客户端私钥 PEM 路径。
	KeyFile string
	// ServerName overrides SNI and hostname verification. | ServerName 覆盖 SNI 与主机名校验。
	ServerName string
	// RootCAFiles appends PEM roots from files. | RootCAFiles 追加文件中的 PEM 根证书。
	RootCAFiles []string
	// CertPEM is an in-memory client certificate. | CertPEM 是内存客户端证书。
	CertPEM []byte
	// KeyPEM is an in-memory client private key. | KeyPEM 是内存客户端私钥。
	KeyPEM []byte
	// Certificates are preloaded client certificates. | Certificates 是预加载客户端证书。
	Certificates []tls.Certificate
	// CipherSuites limits TLS 1.0-1.2 cipher suites. | CipherSuites 限制 TLS 1.0-1.2 套件。
	CipherSuites []uint16
	// CurvePreferences limits key exchange curves. | CurvePreferences 限制密钥交换曲线。
	CurvePreferences []tls.CurveID
	// PinSHA256 lists base64 SPKI SHA-256 pins. | PinSHA256 列出 base64 SPKI SHA-256 固定值。
	PinSHA256 []string
	// SessionCacheSize is the client session cache size; 0 means 128, <0 disables. | SessionCacheSize 是客户端会话缓存大小；0 表示 128，<0 禁用。
	SessionCacheSize int
	// MinVersion is the minimum TLS version; 0 means TLS 1.2. | MinVersion 是最低 TLS 版本；0 表示 TLS 1.2。
	MinVersion uint16
	// MaxVersion is the maximum TLS version; 0 means library default. | MaxVersion 是最高 TLS 版本；0 表示库默认。
	MaxVersion uint16
	// DisableSystemRoots omits the system root pool. | DisableSystemRoots 省略系统根池。
	DisableSystemRoots bool
	// InsecureSkipVerify disables standard verification; an explicit escape hatch. | InsecureSkipVerify 关闭标准校验，是显式逃生口。
	InsecureSkipVerify bool
	// PinChain also checks intermediate/chain certificate pins. | PinChain 也校验中间/链证书固定。
	PinChain bool
}

// WithTLS sets the default TLS configuration. | WithTLS 设置默认 TLS 配置。
func WithTLS(cfg TLSConfig) Option {
	return func(o *options) error {
		cloned := cloneTLSConfig(cfg)
		o.TLSConfig = &cloned
		return nil
	}
}

// cloneTLSConfig snapshots mutable TLSConfig slices. | cloneTLSConfig 快照 TLSConfig 的可变切片。
func cloneTLSConfig(cfg TLSConfig) TLSConfig {
	cfg.RootCAFiles = append([]string(nil), cfg.RootCAFiles...)
	cfg.CertPEM = append([]byte(nil), cfg.CertPEM...)
	cfg.KeyPEM = append([]byte(nil), cfg.KeyPEM...)
	cfg.Certificates = append([]tls.Certificate(nil), cfg.Certificates...)
	cfg.CipherSuites = append([]uint16(nil), cfg.CipherSuites...)
	cfg.CurvePreferences = append([]tls.CurveID(nil), cfg.CurvePreferences...)
	cfg.PinSHA256 = append([]string(nil), cfg.PinSHA256...)
	return cfg
}

// WithHostTLS overrides TLS for one host name or host:port. | WithHostTLS 为一个主机名或 host:port 覆盖 TLS。
func WithHostTLS(host string, cfg TLSConfig) Option {
	return func(o *options) error {
		if host == "" {
			return errs.Detail(ErrTLSConfig, "empty TLS host | 空 TLS Host")
		}
		key := strings.ToLower(host)
		if strings.Contains(host, "://") {
			if parsed, err := url.Parse(host); err == nil && parsed.Host != "" {
				key = strings.ToLower(parsed.Host)
			}
		}
		if o.HostTLS == nil {
			o.HostTLS = make(map[string]TLSConfig)
		}
		o.HostTLS[key] = cloneTLSConfig(cfg)
		return nil
	}
}

// ReloadTLS re-reads certificate and root files and swaps TLS transports. | ReloadTLS 重新读取证书与根文件并替换 TLS 传输。
func (c *Client) ReloadTLS() error {
	if c == nil || c.engine == nil {
		return ErrClosed
	}
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.closed.Load() {
		return ErrClosed
	}
	return c.engine.reloadTLS()
}

// isTLSError reports whether err is a TLS trust/handshake failure. | isTLSError 报告 err 是否为 TLS 信任/握手失败。
func isTLSError(err error) bool {
	if err == nil {
		return false
	}
	var certErr *tls.CertificateVerificationError
	return errors.As(err, &certErr) || errors.Is(err, ErrTLSPin) ||
		errors.Is(err, ErrTLS) || errors.Is(err, ErrTLSConfig)
}

// tlsState owns one TLS configuration and its transport snapshot. | tlsState 拥有一份 TLS 配置及其传输快照。
type tlsState struct {
	base      *http.Transport
	transport atomic.Pointer[http.Transport]
	cfg       TLSConfig
}

// newTLSState builds the first TLS config and transport snapshot. | newTLSState 构建首个 TLS 配置与传输快照。
func newTLSState(cfg TLSConfig, base *http.Transport) (*tlsState, error) {
	if base == nil {
		return nil, errs.Detail(ErrTLSConfig, "TLS needs an *http.Transport | TLS 需要 *http.Transport")
	}
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	state := &tlsState{cfg: cfg, base: base}
	state.transport.Store(cloneTransport(base, tlsCfg))
	return state, nil
}

// current returns the active transport. | current 返回当前传输。
func (s *tlsState) current() *http.Transport {
	if s == nil {
		return nil
	}
	return s.transport.Load()
}

// reload rebuilds the config and transport, then closes old idle connections. | reload 重建配置与传输，并关闭旧空闲连接。
func (s *tlsState) reload() error {
	tlsCfg, err := buildTLSConfig(s.cfg)
	if err != nil {
		return err
	}
	next := cloneTransport(s.base, tlsCfg)
	old := s.transport.Swap(next)
	if old != nil {
		old.CloseIdleConnections()
	}
	return nil
}

// cloneTransport clones base and installs tlsCfg. | cloneTransport 克隆 base 并安装 tlsCfg。
func cloneTransport(base *http.Transport, tlsCfg *tls.Config) *http.Transport {
	clone := base.Clone()
	clone.TLSClientConfig = tlsCfg
	return clone
}

// safeVerifyConnection isolates panics in a user TLS verifier. | safeVerifyConnection 隔离用户 TLS 校验器中的 panic。
func safeVerifyConnection(fn func(tls.ConnectionState) error) func(tls.ConnectionState) error {
	if fn == nil {
		return nil
	}
	return func(state tls.ConnectionState) (err error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				err = errs.Detail(ErrTLSConfig, "TLS verify panic: %v | TLS 校验 panic：%v", recovered, recovered)
			}
		}()
		return fn(state)
	}
}

// safeGetClientCertificate isolates panics in a user certificate callback. | safeGetClientCertificate 隔离用户证书回调中的 panic。
func safeGetClientCertificate(fn func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if fn == nil {
		return nil
	}
	return func(info *tls.CertificateRequestInfo) (cert *tls.Certificate, err error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				cert, err = nil, errs.Detail(ErrTLSConfig, "TLS certificate panic: %v | TLS 证书回调 panic：%v", recovered, recovered)
			}
		}()
		return fn(info)
	}
}

// buildTLSConfig validates and materializes one TLS configuration. | buildTLSConfig 校验并物化一份 TLS 配置。
func buildTLSConfig(cfg TLSConfig) (*tls.Config, error) {
	var pool *x509.CertPool
	switch {
	case cfg.RootCAs != nil:
		pool = cfg.RootCAs.Clone()
	case !cfg.DisableSystemRoots:
		system, err := x509.SystemCertPool()
		if err != nil || system == nil {
			pool = x509.NewCertPool()
		} else {
			pool = system
		}
	default:
		pool = x509.NewCertPool()
	}
	if len(cfg.RootCAFiles) > 0 {
		pool = pool.Clone()
		for _, file := range cfg.RootCAFiles {
			data, err := os.ReadFile(file)
			if err != nil {
				return nil, errs.WrapDetail(err, ErrTLSConfig, "read root CA %s", file)
			}
			if !pool.AppendCertsFromPEM(data) {
				return nil, errs.Detail(ErrTLSConfig, "no certificates in %s | %s 中没有证书", file, file)
			}
		}
	}
	tlsCfg := &tls.Config{
		RootCAs:              pool,
		ServerName:           cfg.ServerName,
		MinVersion:           cfg.MinVersion,
		MaxVersion:           cfg.MaxVersion,
		CipherSuites:         append([]uint16(nil), cfg.CipherSuites...),
		InsecureSkipVerify:   cfg.InsecureSkipVerify,
		Certificates:         append([]tls.Certificate(nil), cfg.Certificates...),
		GetClientCertificate: safeGetClientCertificate(cfg.GetClientCertificate),
	}
	tlsCfg.CurvePreferences = append([]tls.CurveID(nil), cfg.CurvePreferences...)
	if tlsCfg.MinVersion == 0 {
		tlsCfg.MinVersion = tls.VersionTLS12
	}
	if tlsCfg.MaxVersion != 0 && tlsCfg.MinVersion > tlsCfg.MaxVersion {
		return nil, errs.Detail(ErrTLSConfig, "TLS minimum version exceeds maximum | TLS 最低版本高于最高版本")
	}
	if cfg.CertFile != "" || cfg.KeyFile != "" {
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return nil, errs.Detail(ErrTLSConfig, "cert and key files must be set together | 证书与私钥文件必须同时设置")
		}
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrTLSConfig, "load client certificate")
		}
		tlsCfg.Certificates = append(tlsCfg.Certificates, cert)
	}
	if len(cfg.CertPEM) > 0 || len(cfg.KeyPEM) > 0 {
		if len(cfg.CertPEM) == 0 || len(cfg.KeyPEM) == 0 {
			return nil, errs.Detail(ErrTLSConfig, "cert and key PEM must be set together | 证书与私钥 PEM 必须同时设置")
		}
		cert, err := tls.X509KeyPair(cfg.CertPEM, cfg.KeyPEM)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrTLSConfig, "parse client certificate PEM")
		}
		tlsCfg.Certificates = append(tlsCfg.Certificates, cert)
	}
	cacheSize := cfg.SessionCacheSize
	if cacheSize == 0 {
		cacheSize = 128
	}
	if cacheSize > 0 {
		tlsCfg.ClientSessionCache = tls.NewLRUClientSessionCache(cacheSize)
	}
	pins, err := decodePins(cfg.PinSHA256)
	if err != nil {
		return nil, err
	}
	if len(pins) > 0 || cfg.VerifyConnection != nil {
		userVerify := safeVerifyConnection(cfg.VerifyConnection)
		pinChain := cfg.PinChain
		tlsCfg.VerifyConnection = func(state tls.ConnectionState) error {
			if len(pins) > 0 {
				if err := verifyPins(state, pins, pinChain); err != nil {
					return err
				}
			}
			if userVerify != nil {
				return userVerify(state)
			}
			return nil
		}
	}
	return tlsCfg, nil
}

// decodePins decodes base64 SPKI SHA-256 pins. | decodePins 解码 base64 SPKI SHA-256 固定值。
func decodePins(values []string) ([][]byte, error) {
	if len(values) == 0 {
		return nil, nil
	}
	pins := make([][]byte, 0, len(values))
	for _, value := range values {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(decoded) != sha256.Size {
			return nil, errs.Detail(ErrTLSConfig, "invalid SHA-256 pin | 非法的 SHA-256 固定值")
		}
		pins = append(pins, decoded)
	}
	return pins, nil
}

// verifyPins checks the leaf and optionally the chain against pins. | verifyPins 用固定值检查叶子证书并可选检查链。
func verifyPins(state tls.ConnectionState, pins [][]byte, pinChain bool) error {
	if len(state.PeerCertificates) == 0 {
		return nil
	}
	if pinMatches(state.PeerCertificates[0], pins) {
		return nil
	}
	if pinChain {
		for _, cert := range state.PeerCertificates[1:] {
			if pinMatches(cert, pins) {
				return nil
			}
		}
	}
	return ErrTLSPin
}

// pinMatches reports whether cert's SPKI SHA-256 matches any pin. | pinMatches 报告证书 SPKI SHA-256 是否匹配任一固定值。
func pinMatches(cert *x509.Certificate, pins [][]byte) bool {
	if cert == nil {
		return false
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	for _, pin := range pins {
		if subtle.ConstantTimeCompare(sum[:], pin) == 1 {
			return true
		}
	}
	return false
}

// noteInsecure records and warns about an insecure TLS configuration. | noteInsecure 记录并告警不安全的 TLS 配置。
func (e *engine) noteInsecure(cfg *TLSConfig) {
	if e == nil || cfg == nil || !cfg.InsecureSkipVerify {
		return
	}
	e.counters.tlsInsecure.Add(1)
	if e.opts.Logger != nil {
		e.opts.Logger.Warn("client: TLS InsecureSkipVerify enabled | client：TLS 已启用 InsecureSkipVerify")
	}
}

// stateFor returns or lazily creates the state for a host TLS config. | stateFor 返回或惰性创建 Host TLS 配置的状态。
func (e *engine) stateFor(cfg *TLSConfig) (*tlsState, error) {
	if cfg == nil {
		return nil, errs.Detail(ErrTLSConfig, "nil host TLS | 空 Host TLS")
	}
	e.tlsMu.Lock()
	defer e.tlsMu.Unlock()
	if state := e.tlsByConfig[cfg]; state != nil {
		return state, nil
	}
	e.noteInsecure(cfg)
	if e.baseTransport == nil {
		return nil, errs.Detail(ErrTLSConfig, "host TLS needs an *http.Transport | Host TLS 需要 *http.Transport")
	}
	state, err := newTLSState(*cfg, e.baseTransport)
	if err != nil {
		return nil, err
	}
	e.tlsByConfig[cfg] = state
	e.tlsStates = append(e.tlsStates, state)
	return state, nil
}

// transportFor selects the base, host-specific or default TLS transport. | transportFor 选择基础、Host 专用或默认 TLS 传输。
func (e *engine) transportFor(host *Host) (http.RoundTripper, error) {
	if len(e.hostTLS) == 0 && (host == nil || host.TLS == nil) {
		return e.defaultTransport(), nil
	}
	if host != nil {
		if host.TLS != nil {
			state, err := e.stateFor(host.TLS)
			if err != nil {
				return nil, err
			}
			return state.current(), nil
		}
		if state := e.hostTLS[strings.ToLower(host.URL.Host)]; state != nil {
			return state.current(), nil
		}
		if state := e.hostTLS[strings.ToLower(host.URL.Hostname())]; state != nil {
			return state.current(), nil
		}
	}
	return e.defaultTransport(), nil
}

// transportForURL applies a hostname TLS override for direct requests. | transportForURL 为直连请求应用按主机名的 TLS 覆盖。
func (e *engine) transportForURL(u *url.URL) http.RoundTripper {
	if u != nil {
		if state := e.hostTLS[strings.ToLower(u.Host)]; state != nil {
			return state.current()
		}
		if state := e.hostTLS[strings.ToLower(u.Hostname())]; state != nil {
			return state.current()
		}
	}
	return e.defaultTransport()
}

// pruneTLS closes and forgets TLS states no longer referenced by a host set. | pruneTLS 关闭并遗忘不再被 Host 池引用的 TLS 状态。
func (e *engine) pruneTLS() {
	if e == nil {
		return
	}
	active := make(map[*TLSConfig]struct{})
	if e.opts.TLSConfig != nil {
		active[e.opts.TLSConfig] = struct{}{}
	}
	addSet := func(hs *HostSet) {
		if hs == nil {
			return
		}
		for _, entry := range hs.entries {
			if entry.host.TLS != nil {
				active[entry.host.TLS] = struct{}{}
			}
		}
	}
	addSet(e.hosts.Load())
	if rules := e.rules.Load(); rules != nil {
		for i := range rules.entries {
			addSet(rules.entries[i].rule.HostSet)
		}
	}
	e.tlsMu.Lock()
	defer e.tlsMu.Unlock()
	removed := false
	for cfg, state := range e.tlsByConfig {
		if _, ok := active[cfg]; ok {
			continue
		}
		state.current().CloseIdleConnections()
		delete(e.tlsByConfig, cfg)
		removed = true
	}
	if !removed {
		return
	}
	states := make([]*tlsState, 0, len(e.hostTLS)+len(e.tlsByConfig)+1)
	seen := make(map[*tlsState]struct{})
	appendState := func(state *tlsState) {
		if state == nil {
			return
		}
		if _, ok := seen[state]; ok {
			return
		}
		seen[state] = struct{}{}
		states = append(states, state)
	}
	appendState(e.defaultTLS)
	for _, state := range e.hostTLS {
		appendState(state)
	}
	for _, state := range e.tlsByConfig {
		appendState(state)
	}
	e.tlsStates = states
}

// healthTransport returns the per-host transport for active health checks. | healthTransport 返回主动健康检查使用的逐 Host 传输。
func (e *engine) healthTransport(host *Host) http.RoundTripper {
	transport, err := e.transportFor(host)
	if err != nil {
		return nil
	}
	return transport
}

// defaultTransport returns the transport used without a host pool. | defaultTransport 返回无 Host 池时使用的传输。
func (e *engine) defaultTransport() http.RoundTripper {
	if e.h2c != nil {
		secure := http.RoundTripper(e.baseTransport)
		if e.defaultTLS != nil {
			secure = e.defaultTLS.current()
		}
		return &schemeTransport{plain: e.h2c, secure: secure}
	}
	if e.defaultTLS != nil {
		return e.defaultTLS.current()
	}
	return e.base
}

// schemeTransport sends cleartext requests to the h2c transport and TLS
// requests to the secure transport. | schemeTransport 把明文请求交给 h2c 传输，
// TLS 请求交给安全传输。
type schemeTransport struct {
	plain  http.RoundTripper
	secure http.RoundTripper
}

// RoundTrip dispatches by URL scheme. | RoundTrip 按 URL scheme 分派。
func (s *schemeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req != nil && req.URL != nil && req.URL.Scheme == "http" {
		return s.plain.RoundTrip(req)
	}
	return s.secure.RoundTrip(req)
}

// CloseIdleConnections closes both underlying transports. | CloseIdleConnections 关闭两个底层传输的空闲连接。
func (s *schemeTransport) CloseIdleConnections() {
	if closer, ok := s.plain.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
	if closer, ok := s.secure.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// reloadTLS reloads every known TLS state. | reloadTLS 重新加载全部已知 TLS 状态。
func (e *engine) reloadTLS() error {
	e.tlsMu.Lock()
	states := append([]*tlsState(nil), e.tlsStates...)
	e.tlsMu.Unlock()
	var first error
	for _, state := range states {
		if err := state.reload(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// closeTLSIdle releases idle connections for every TLS transport. | closeTLSIdle 释放全部 TLS 传输的空闲连接。
func (e *engine) closeTLSIdle() {
	e.tlsMu.Lock()
	states := append([]*tlsState(nil), e.tlsStates...)
	e.tlsMu.Unlock()
	for _, state := range states {
		if tr := state.current(); tr != nil {
			tr.CloseIdleConnections()
		}
	}
}
