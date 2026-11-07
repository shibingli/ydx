package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/errs"
)

// ADConfig configures Active Directory discovery, service binding and
// authentication. | ADConfig 配置 Active Directory 发现、服务绑定与认证。
type ADConfig struct {
	// Domain is the DNS domain name, for example example.com. | Domain 是 DNS 域名，
	// 例如 example.com。
	Domain string
	// BaseDN optionally overrides the discovered defaultNamingContext. | BaseDN
	// 可选地覆盖发现的 defaultNamingContext。
	BaseDN string
	// URL is an explicit ldap:// or ldaps:// domain controller URL. Empty URL
	// enables DNS SRV discovery. | URL 是显式 ldap:// 或 ldaps:// 域控地址。空地址启用
	// DNS SRV 发现。
	URL string
	// TLSConfig configures LDAPS or StartTLS, including a private CA. | TLSConfig
	// 配置 LDAPS 或 StartTLS，包括私有 CA。
	TLSConfig *tls.Config
	// StartTLS upgrades an ldap:// connection before binding. | StartTLS 在绑定前升级
	// ldap:// 连接。
	StartTLS bool
	// Timeout bounds each LDAP exchange. Zero uses DefaultTimeout. | Timeout 限制每次
	// LDAP 交换。零使用 DefaultTimeout。
	Timeout time.Duration
	// DialTimeout bounds connection establishment and TLS handshakes. Zero uses
	// DefaultDialTimeout. | DialTimeout 限制建连与 TLS 握手。零使用 DefaultDialTimeout。
	DialTimeout time.Duration
	// MaxMessageSize bounds one BER message. Zero uses DefaultMaxMessageSize. | MaxMessageSize
	// 限制单条 BER 消息。零使用 DefaultMaxMessageSize。
	MaxMessageSize int
	// BindDN is the optional service account DN used for user and group searches.
	// | BindDN 是用于用户与组搜索的可选服务账号 DN。
	BindDN string
	// BindPassword is the service account password. It is never included in
	// errors or logs. | BindPassword 是服务账号口令，绝不会出现在错误或日志中。
	BindPassword string
	// Resolver overrides DNS resolution for SRV discovery. | Resolver 覆盖 SRV 发现的
	// DNS 解析器。
	Resolver *net.Resolver
	// ReferralHandler receives referrals. They are never followed automatically. |
	// ReferralHandler 接收转介，绝不会自动跟随。
	ReferralHandler ReferralHandler
}

// ActiveDirectory is a domain-aware LDAP facade. It keeps one service
// connection for searches and opens a fresh, isolated connection for each
// password authentication. | ActiveDirectory 是域感知的 LDAP 门面。它保留一条用于
// 搜索的服务连接，并为每次口令认证打开新的隔离连接。
type ActiveDirectory struct {
	domain string
	baseDN string
	url    string
	cfg    Config
	client *Client
	closed atomic.Bool
}

// NewActiveDirectory discovers or validates a domain controller, binds the
// service account when configured, and resolves the base DN. | NewActiveDirectory
// 发现或校验域控，在配置时绑定服务账号，并解析基础 DN。
func NewActiveDirectory(ctx context.Context, cfg ADConfig) (*ActiveDirectory, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg.BindDN != "" && cfg.BindPassword == "" {
		return nil, errs.Detail(ErrInvalidConfig, "service bind DN requires a password | 服务绑定 DN 需要口令")
	}
	if cfg.BindPassword != "" && cfg.BindDN == "" {
		return nil, errs.Detail(ErrInvalidConfig, "service bind password requires a DN | 服务绑定口令需要 DN")
	}
	if cfg.Timeout < 0 || cfg.DialTimeout < 0 || cfg.MaxMessageSize < 0 {
		return nil, errs.Detail(ErrInvalidConfig, "negative Active Directory setting | Active Directory 设置为负")
	}
	domain := normalizeADDomain(cfg.Domain)
	if domain == "" {
		domain = baseDNToDomain(cfg.BaseDN)
	}
	urls, err := adEndpointURLs(ctx, cfg, domain)
	if err != nil {
		return nil, err
	}
	connectionConfig := Config{
		TLSConfig:       cfg.TLSConfig,
		StartTLS:        cfg.StartTLS,
		Timeout:         cfg.Timeout,
		DialTimeout:     cfg.DialTimeout,
		MaxMessageSize:  cfg.MaxMessageSize,
		BindDN:          cfg.BindDN,
		BindPassword:    cfg.BindPassword,
		ReferralHandler: cfg.ReferralHandler,
	}
	var (
		client  *Client
		lastErr error
	)
	for _, rawURL := range urls {
		candidate := connectionConfig
		candidate.URL = rawURL
		client, err = Dial(ctx, candidate)
		if err == nil {
			break
		}
		lastErr = err
		if !adRetryable(err) {
			return nil, mapADError(err)
		}
	}
	if client == nil {
		if lastErr == nil {
			return nil, errs.Detail(ErrADDiscovery, "no Active Directory endpoint | 没有 Active Directory 端点")
		}
		return nil, mapADError(lastErr)
	}
	baseDN := strings.TrimSpace(cfg.BaseDN)
	if baseDN == "" {
		var rootErr error
		if root, err := client.RootDSE(ctx); err == nil {
			baseDN = strings.TrimSpace(root.First("defaultNamingContext"))
		} else {
			rootErr = err
		}
		if baseDN == "" {
			baseDN = domainToBaseDN(domain)
		}
		if baseDN == "" {
			_ = client.Close()
			if rootErr != nil {
				return nil, errs.WrapDetail(rootErr, ErrADDiscovery, "cannot resolve Active Directory base DN | 无法解析 Active Directory 基础 DN")
			}
			return nil, errs.Detail(ErrADDiscovery, "Active Directory base DN is empty | Active Directory 基础 DN 为空")
		}
	}
	if domain == "" {
		domain = baseDNToDomain(baseDN)
	}
	stored := connectionConfig
	stored.URL = client.cfg.URL
	stored.BindDN = ""
	stored.BindPassword = ""
	if cfg.TLSConfig != nil {
		stored.TLSConfig = cfg.TLSConfig.Clone()
	}
	ad := &ActiveDirectory{
		domain: domain,
		baseDN: baseDN,
		url:    client.cfg.URL,
		cfg:    stored,
		client: client,
	}
	return ad, nil
}

// Close closes the service connection. | Close 关闭服务连接。
func (ad *ActiveDirectory) Close() error {
	if ad == nil || ad.client == nil {
		return nil
	}
	ad.closed.Store(true)
	return ad.client.Close()
}

// Domain returns the Active Directory DNS domain. | Domain 返回 Active Directory
// DNS 域。
func (ad *ActiveDirectory) Domain() string {
	if ad == nil {
		return ""
	}
	return ad.domain
}

// BaseDN returns the resolved default naming context. | BaseDN 返回解析后的默认命名上下文。
func (ad *ActiveDirectory) BaseDN() string {
	if ad == nil {
		return ""
	}
	return ad.baseDN
}

// URL returns the selected domain-controller URL. | URL 返回选定的域控地址。
func (ad *ActiveDirectory) URL() string {
	if ad == nil {
		return ""
	}
	return ad.url
}

// Authenticate verifies a password with a fresh bind and returns the typed
// account. It accepts a DN, user@domain, DOMAIN\user, or a plain sAMAccountName
// when a domain or service connection can resolve it. An empty password is
// rejected before any network I/O. | Authenticate 用新绑定校验口令并返回类型化账号。
// 它接受 DN、user@domain、DOMAIN\user，或在域/服务连接可解析时的裸 sAMAccountName。
// 空口令会在任何网络 I/O 之前被拒绝。
func (ad *ActiveDirectory) Authenticate(ctx context.Context, username, password string) (*ADUser, error) {
	if ad == nil || ad.client == nil {
		return nil, ErrInvalidConfig
	}
	if ad.closed.Load() {
		return nil, ErrClosed
	}
	if password == "" {
		return nil, ErrEmptyPassword
	}
	identity := strings.TrimSpace(username)
	if identity == "" {
		return nil, errs.Detail(ErrInvalidConfig, "empty user identity | 用户身份为空")
	}
	var discovered *ADUser
	if found, err := ad.lookupUser(ctx, identity); err == nil {
		discovered = found
	} else if errors.Is(err, ErrAmbiguousUser) {
		return nil, err
	}
	bindName := ad.directBindName(identity)
	if discovered != nil && discovered.DN != "" {
		bindName = discovered.DN
	}
	if bindName == "" {
		return nil, errs.Detail(ErrInvalidConfig, "cannot derive bind name | 无法推导绑定名称")
	}
	userClient, err := ad.dialUserClient(ctx)
	if err != nil {
		return nil, mapADError(err)
	}
	defer func() {
		_ = userClient.Close()
	}()
	if err := userClient.Bind(ctx, bindName, password); err != nil {
		return nil, mapADError(err)
	}
	user := discovered
	if user == nil {
		user = minimalADUser(identity, bindName)
	}
	user.Authenticated = true
	return user, nil
}

// User returns the typed account for a DN, UPN, DOMAIN\user, or sAMAccountName.
// User searches use the service connection. | User 返回 DN、UPN、DOMAIN\user 或
// sAMAccountName 对应的类型化账号。用户搜索使用服务连接。
func (ad *ActiveDirectory) User(ctx context.Context, identity string) (*ADUser, error) {
	if ad == nil || ad.client == nil {
		return nil, ErrInvalidConfig
	}
	if ad.closed.Load() {
		return nil, ErrClosed
	}
	return ad.lookupUser(ctx, identity)
}

// Groups returns the distinguished names of groups containing the user. It
// first uses LDAP_MATCHING_RULE_IN_CHAIN and falls back to recursive memberOf
// traversal when that matching rule is rejected. | Groups 返回包含该用户的组可分辨名称。
// 它优先使用 LDAP_MATCHING_RULE_IN_CHAIN，在匹配规则被拒绝时回退到递归 memberOf 遍历。
func (ad *ActiveDirectory) Groups(ctx context.Context, username string) ([]string, error) {
	if ad == nil || ad.client == nil {
		return nil, ErrInvalidConfig
	}
	if ad.closed.Load() {
		return nil, ErrClosed
	}
	user, err := ad.lookupUser(ctx, username)
	if err != nil {
		return nil, err
	}
	groups, chainErr := ad.groupsInChain(ctx, user.DN)
	if chainErr == nil {
		return groups, nil
	}
	var resultErr *Error
	if !errors.As(chainErr, &resultErr) {
		return groups, chainErr
	}
	fallback, fallbackErr := ad.groupsRecursive(ctx, user.MemberOf)
	groups = dedupeADGroups(append(groups, fallback...))
	if fallbackErr != nil {
		return groups, fallbackErr
	}
	return groups, nil
}

// groupsInChain uses the recursive membership matching rule. | groupsInChain 使用
// 递归成员关系匹配规则。
func (ad *ActiveDirectory) groupsInChain(ctx context.Context, userDN string) ([]string, error) {
	if ad.client == nil {
		return nil, ErrServiceBindRequired
	}
	filter := And(
		Equal("objectCategory", "group"),
		ExtensibleMatch(ADMatchingRuleInChain, "member", userDN, false),
	)
	result, err := ad.client.Search(ctx, SearchOptions{
		BaseDN:     ad.baseDN,
		Scope:      ScopeWholeSubtree,
		Filter:     filter,
		Attributes: []string{"distinguishedName"},
		PageSize:   500,
	})
	if result == nil {
		return nil, err
	}
	groups := make([]string, 0, len(result.Entries))
	for _, entry := range result.Entries {
		dn := entry.DN
		if dn == "" {
			dn = entry.First("distinguishedName")
		}
		if dn != "" {
			groups = append(groups, dn)
		}
	}
	groups = dedupeADGroups(groups)
	if err != nil {
		return groups, err
	}
	return groups, nil
}

// groupsRecursive walks direct memberOf links breadth-first. | groupsRecursive
// 广度优先遍历直接 memberOf 链接。
func (ad *ActiveDirectory) groupsRecursive(ctx context.Context, memberOf []string) ([]string, error) {
	if ad.client == nil {
		return nil, ErrServiceBindRequired
	}
	queue := append([]string(nil), memberOf...)
	seen := make(map[string]struct{})
	var groups []string
	for len(queue) > 0 {
		dn := strings.TrimSpace(queue[0])
		queue = queue[1:]
		if dn == "" {
			continue
		}
		key := strings.ToLower(dn)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if len(seen) > maxADGroupResults {
			return groups, errs.Detail(ErrADDiscovery, "group expansion exceeded %d | 组展开超过 %d 个", maxADGroupResults, maxADGroupResults)
		}
		groups = append(groups, dn)
		entry, err := ad.lookupGroupEntry(ctx, dn)
		if err != nil {
			if errors.Is(err, ErrNoSuchObject) || errors.Is(err, ErrReferral) {
				continue
			}
			return groups, err
		}
		queue = append(queue, entry.Get("memberOf")...)
	}
	return dedupeADGroups(groups), nil
}

// lookupGroupEntry reads one group's memberOf attribute. | lookupGroupEntry 读取
// 单个组的 memberOf 属性。
func (ad *ActiveDirectory) lookupGroupEntry(ctx context.Context, dn string) (*Entry, error) {
	result, err := ad.client.Search(ctx, SearchOptions{
		BaseDN:     dn,
		Scope:      ScopeBaseObject,
		Filter:     Present("objectClass"),
		Attributes: []string{"memberOf"},
	})
	if result == nil {
		return nil, err
	}
	if len(result.Entries) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, errs.Detail(ErrNoSuchObject, "group %s not found | 组 %s 不存在", dn, dn)
	}
	return result.Entries[0], nil
}

// directBindName derives a bind name for identities that do not resolve by
// search. | directBindName 为无法通过搜索解析的身份推导绑定名称。
func (ad *ActiveDirectory) directBindName(identity string) string {
	if looksLikeDN(identity) || strings.ContainsAny(identity, "@\\") {
		return identity
	}
	if ad.domain != "" {
		return identity + "@" + ad.domain
	}
	return identity
}

// dialUserClient opens an isolated connection without service credentials. | dialUserClient
// 打开不使用服务凭据的隔离连接。
func (ad *ActiveDirectory) dialUserClient(ctx context.Context) (*Client, error) {
	cfg := ad.cfg
	cfg.URL = ad.url
	cfg.BindDN = ""
	cfg.BindPassword = ""
	return Dial(ctx, cfg)
}

// adEndpointURLs returns the explicit URL or sorted SRV targets. | adEndpointURLs
// 返回显式地址或排序后的 SRV 目标。
func adEndpointURLs(ctx context.Context, cfg ADConfig, domain string) ([]string, error) {
	if strings.TrimSpace(cfg.URL) != "" {
		return []string{strings.TrimSpace(cfg.URL)}, nil
	}
	if domain == "" {
		return nil, errs.Detail(ErrADDiscovery, "domain and URL are both empty | 域与地址均为空")
	}
	resolver := cfg.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	_, records, err := resolver.LookupSRV(ctx, "ldap", "tcp", "dc._msdcs."+domain)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrADDiscovery, "SRV _ldap._tcp.dc._msdcs.%s | SRV _ldap._tcp.dc._msdcs.%s", domain, domain)
	}
	sorted := append([]*net.SRV(nil), records...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Priority != sorted[j].Priority {
			return sorted[i].Priority < sorted[j].Priority
		}
		if sorted[i].Weight != sorted[j].Weight {
			return sorted[i].Weight > sorted[j].Weight
		}
		return sorted[i].Target < sorted[j].Target
	})
	urls := make([]string, 0, len(sorted))
	for _, record := range sorted {
		host := strings.TrimSuffix(strings.TrimSpace(record.Target), ".")
		if host == "" || host == "." || record.Port == 0 {
			continue
		}
		urls = append(urls, "ldap://"+net.JoinHostPort(host, strconv.Itoa(int(record.Port))))
	}
	if len(urls) == 0 {
		return nil, errs.Detail(ErrADDiscovery, "SRV lookup returned no usable domain controller | SRV 查询未返回可用域控")
	}
	return urls, nil
}

// adRetryable reports whether another domain controller may succeed. | adRetryable
// 报告另一个域控是否可能成功。
func adRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, ErrInvalidConfig) || errors.Is(err, ErrInvalidURL) || errors.Is(err, ErrEmptyPassword) {
		return false
	}
	var resultErr *Error
	if errors.As(err, &resultErr) {
		return resultErr.Code == ResultBusy || resultErr.Code == ResultUnavailable
	}
	return true
}

// normalizeADDomain trims whitespace and a trailing root dot. | normalizeADDomain
// 去除空白与末尾根点。
func normalizeADDomain(domain string) string {
	return strings.TrimSuffix(strings.TrimSpace(domain), ".")
}

// domainToBaseDN converts a DNS domain into a DC= naming context. It only accepts
// simple DNS labels. | domainToBaseDN 把 DNS 域转换为 DC= 命名上下文，仅接受简单
// DNS 标签。
func domainToBaseDN(domain string) string {
	domain = normalizeADDomain(domain)
	if domain == "" {
		return ""
	}
	labels := strings.Split(domain, ".")
	parts := make([]string, 0, len(labels))
	for _, label := range labels {
		if !validDNSLabel(label) {
			return ""
		}
		parts = append(parts, "DC="+label)
	}
	return strings.Join(parts, ",")
}

// baseDNToDomain extracts leading DC= components from a naming context. | baseDNToDomain
// 从命名上下文提取开头的 DC= 组件。
func baseDNToDomain(baseDN string) string {
	var labels []string
	for _, component := range strings.Split(baseDN, ",") {
		component = strings.TrimSpace(component)
		if len(component) < 4 || !strings.EqualFold(component[:3], "DC=") {
			break
		}
		value := strings.TrimSpace(component[3:])
		if value == "" {
			break
		}
		labels = append(labels, value)
	}
	return strings.Join(labels, ".")
}

// validDNSLabel reports whether label is a simple non-empty DNS label. | validDNSLabel
// 报告 label 是否为简单非空 DNS 标签。
func validDNSLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			return false
		}
	}
	return label[0] != '-' && label[len(label)-1] != '-'
}

// dedupeADGroups removes duplicate DNs case-insensitively while preserving
// order. | dedupeADGroups 在不改变顺序的前提下大小写不敏感地去重组 DN。
func dedupeADGroups(groups []string) []string {
	if len(groups) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(groups))
	deduped := make([]string, 0, len(groups))
	for _, group := range groups {
		if group == "" {
			continue
		}
		key := strings.ToLower(group)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, group)
	}
	return deduped
}
