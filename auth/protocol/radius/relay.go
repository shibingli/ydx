package radius

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Relay defaults and limits. | 中继默认值与限制。
const (
	// DefaultRelayMaxHops is the default maximum number of Proxy-State attributes a relay accepts
	// before declaring a forwarding loop. | DefaultRelayMaxHops 是中继在判定转发循环前接受的
	// Proxy-State 属性默认上限。
	DefaultRelayMaxHops = 16
	// MaxRelayLoopTokenLength is the largest relay loop token accepted by RelayConfig. |
	// MaxRelayLoopTokenLength 是 RelayConfig 接受的最大中继循环令牌长度。
	MaxRelayLoopTokenLength = 32
	// relayProxyStateMagic prefixes the Proxy-State value a Relay adds. | relayProxyStateMagic 是
	// Relay 添加的 Proxy-State 值前缀。
	relayProxyStateMagic = "YDRP"
	// relayProxyStateTokenLength is the default random loop token length. |
	// relayProxyStateTokenLength 是默认随机循环令牌长度。
	relayProxyStateTokenLength = 8
)

// RelayUpstream describes one upstream RADIUS server. | RelayUpstream 描述一个上游 RADIUS 服务器。
//
// Network, Address, Secret, TLSConfig, Timeout and Retries have the same meaning as the matching
// ClientConfig fields. Every upstream has its own Client, so a relay may use different transports,
// secrets and retry budgets for different upstreams. | Network、Address、Secret、TLSConfig、Timeout
// 与 Retries 的含义与对应的 ClientConfig 字段相同。每个上游拥有独立的 Client，因此同一中继可为
// 不同上游使用不同传输、密钥与重试预算。
type RelayUpstream struct {
	// TLSConfig configures RADIUS over TLS for this upstream. | TLSConfig 为此上游配置 RADIUS over TLS。
	TLSConfig *tls.Config
	// Name identifies the upstream in RelayResult and diagnostics; empty derives a name from the
	// network and address. | Name 在 RelayResult 与诊断中标识上游；空值由网络与地址推导。
	Name string
	// Network selects the transport, defaulting to "udp". | Network 选择传输，默认 "udp"。
	Network string
	// Address is the upstream "host:port". | Address 是上游 "host:port"。
	Address string
	// Secret is the upstream shared secret. The relay copies it into the upstream Client, which
	// zeroizes its copy in Close. | Secret 是上游共享密钥。中继会复制到上游 Client，并在 Close 时
	// 清零该副本。
	Secret []byte
	// Timeout is the base timeout of one upstream transmission attempt; zero selects
	// DefaultTimeout. | Timeout 是单次上游传输尝试的基础超时；零值选择 DefaultTimeout。
	Timeout time.Duration
	// Retries is the number of upstream retransmissions after the initial attempt. |
	// Retries 是首次上游尝试之后的重传次数。
	Retries int
}

// RelayConfig configures a Relay. | RelayConfig 配置 Relay。
type RelayConfig struct {
	// Dictionary resolves attribute names for the upstream clients; nil selects a fresh built-in
	// dictionary. The relay itself operates on numeric attributes and never rewrites them through
	// the dictionary. | Dictionary 为上游客户端解析属性名；nil 选择一份新的内置字典。中继本身按数值
	// 属性操作，绝不通过字典改写属性。
	Dictionary *Dictionary
	// Upstreams is the ordered failover list and must not be empty. A request is tried against each
	// upstream in order until one returns a valid response; an Access-Reject and an Accounting-
	// Response count as valid responses. | Upstreams 是有序故障转移列表，不得为空。请求按顺序尝试
	// 每个上游，直到一个返回合法响应；Access-Reject 与 Accounting-Response 都算合法响应。
	Upstreams []RelayUpstream
	// LoopToken overrides the random per-relay loop token. It must be 1 to 32 octets and is copied.
	// Two relay instances sharing a token detect requests that loop through each other. |
	// LoopToken 覆盖每中继随机循环令牌。长度必须为 1 到 32 字节，且会被复制。共享同一令牌的两个中继
	// 实例可以检测经过彼此的循环请求。
	LoopToken []byte
	// MaxHops is the maximum number of Proxy-State attributes on an incoming request; zero selects
	// DefaultRelayMaxHops and values above 255 are rejected because the relay marker stores the hop
	// count in one octet. | MaxHops 是入站请求上 Proxy-State 属性的最大数量；零值选择
	// DefaultRelayMaxHops，高于 255 的值会被拒绝，因为中继标记以一个字节保存跳数。
	MaxHops int
	// RequireMessageAuthenticator rejects Access-Requests without a valid Message-Authenticator
	// even when they carry no EAP-Message. Requests with an invalid value are always rejected. |
	// RequireMessageAuthenticator 拒绝不携带合法 Message-Authenticator 的 Access-Request，即使没有
	// EAP-Message。值非法的请求始终被拒绝。
	RequireMessageAuthenticator bool
}

// RelayResult is one translated upstream response. | RelayResult 是一个已转换的上游响应。
type RelayResult struct {
	// Packet is the decoded response signed for the downstream client. | Packet 是为下游客户端签名的
	// 已解码响应。
	Packet *Packet
	// Raw is the wire response signed with the downstream client's secret and identifier. It is
	// ready to send back to the NAS unchanged. | Raw 是使用下游客户端密钥与标识符签名的线格式响应，
	// 可直接原样发回 NAS。
	Raw []byte
	// Upstream is the RelayUpstream.Name that produced the response. | Upstream 是产生响应的
	// RelayUpstream.Name。
	Upstream string
}

// relayUpstream is one validated upstream and its client. | relayUpstream 是一个已校验的上游及其客户端。
type relayUpstream struct {
	name   string
	client *Client
}

// Relay forwards Access-Requests and Accounting-Requests between a downstream NAS and one or more
// upstream RADIUS servers. | Relay 在下游 NAS 与一个或多个上游 RADIUS 服务器之间转发 Access-Request
// 与 Accounting-Request。
//
// A Relay authenticates every incoming request with the downstream shared secret, validates a
// present Message-Authenticator, detects Proxy-State loops, preserves every received Proxy-State
// attribute, appends its own hop marker, re-encrypts PAP User-Password and RFC 2548 MS-MPPE keys for
// the upstream secret, maps identifiers and request authenticators, fails over across upstreams and
// signs the upstream response with the downstream secret. EAP packets are forwarded opaquely; the
// relay never terminates EAP. A Relay is safe for concurrent use, and Close may run while requests
// are in flight. | Relay 使用下游共享密钥认证每个入站请求、校验存在的 Message-Authenticator、检测
// Proxy-State 循环、保留收到的全部 Proxy-State 属性、追加自己的跳数标记、按上游密钥重新加密 PAP
// User-Password 与 RFC 2548 MS-MPPE 密钥、映射标识符与请求认证符、在上游间故障转移，并使用下游密钥
// 签名上游响应。EAP 报文被不透明转发；中继绝不终结 EAP。Relay 可并发使用，Close 可在请求处理期间
// 调用。
type Relay struct {
	dictionary *Dictionary
	token      []byte
	upstreams  []relayUpstream
	mu         sync.RWMutex
	maxHops    int
	closed     bool
	requireMA  bool
}

// NewRelay validates cfg and returns a relay. The relay does not open any sockets until a request
// is forwarded. | NewRelay 校验 cfg 并返回中继。中继在转发请求前不会打开任何套接字。
func NewRelay(cfg RelayConfig) (*Relay, error) {
	if len(cfg.Upstreams) == 0 {
		return nil, errs.Detail(ErrInvalidConfig, "at least one relay upstream is required")
	}
	maxHops := cfg.MaxHops
	if maxHops < 0 {
		return nil, errs.Detail(ErrInvalidConfig, "relay max hops must not be negative")
	}
	if maxHops == 0 {
		maxHops = DefaultRelayMaxHops
	}
	if maxHops > 255 {
		return nil, errs.Detail(ErrInvalidConfig, "relay max hops %d exceeds 255", maxHops)
	}
	if len(cfg.LoopToken) > MaxRelayLoopTokenLength {
		return nil, errs.Detail(ErrInvalidConfig, "relay loop token length %d exceeds %d", len(cfg.LoopToken), MaxRelayLoopTokenLength)
	}
	dictionary := cfg.Dictionary
	if dictionary == nil {
		dictionary = NewBuiltinDictionary()
	}
	token := append([]byte(nil), cfg.LoopToken...)
	if len(token) == 0 {
		token = make([]byte, relayProxyStateTokenLength)
		if _, err := rand.Read(token); err != nil {
			return nil, errs.Wrap(err, ErrInternal)
		}
	}
	relay := &Relay{
		dictionary: dictionary,
		token:      token,
		maxHops:    maxHops,
		requireMA:  cfg.RequireMessageAuthenticator,
	}
	for index, upstream := range cfg.Upstreams {
		name := strings.TrimSpace(upstream.Name)
		if name == "" {
			name = strings.TrimSpace(upstream.Address)
			if name == "" {
				name = "upstream-" + strconv.Itoa(index+1)
			}
		}
		client, err := NewClient(ClientConfig{
			Dictionary: dictionary,
			Network:    upstream.Network,
			Address:    upstream.Address,
			Secret:     upstream.Secret,
			Timeout:    upstream.Timeout,
			Retries:    upstream.Retries,
			TLSConfig:  upstream.TLSConfig,
		})
		if err != nil {
			for _, created := range relay.upstreams {
				_ = created.client.Close()
			}
			return nil, errs.WrapDetail(err, ErrInvalidConfig, "upstream %q", name)
		}
		relay.upstreams = append(relay.upstreams, relayUpstream{name: name, client: client})
	}
	return relay, nil
}

// Close closes every upstream client, zeroizing their shared-secret copies, and rejects further
// forwarding. Close is idempotent and safe for concurrent use. | Close 关闭全部上游客户端、清零其
// 共享密钥副本，并拒绝后续转发。Close 幂等且可并发使用。
func (r *Relay) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	upstreams := r.upstreams
	r.mu.Unlock()
	for _, upstream := range upstreams {
		_ = upstream.client.Close()
	}
	return nil
}

// ForwardAccess authenticates, translates and forwards one Access-Request. raw must be the exact
// received wire packet and secret the downstream client's shared secret. On success the returned
// raw response carries the downstream identifier and is signed with secret. | ForwardAccess 认证、
// 转换并转发一个 Access-Request。raw 必须是收到的原始线格式报文，secret 是下游客户端共享密钥。
// 成功时返回的原始响应携带下游标识符并使用 secret 签名。
func (r *Relay) ForwardAccess(ctx context.Context, raw []byte, secret []byte) (*RelayResult, error) {
	return r.forward(ctx, CodeAccessRequest, raw, secret)
}

// ForwardAccounting authenticates, translates and forwards one Accounting-Request. raw must be the
// exact received wire packet and secret the downstream client's shared secret. On success the
// returned raw response carries the downstream identifier and is signed with secret. |
// ForwardAccounting 认证、转换并转发一个 Accounting-Request。raw 必须是收到的原始线格式报文，
// secret 是下游客户端共享密钥。成功时返回的原始响应携带下游标识符并使用 secret 签名。
func (r *Relay) ForwardAccounting(ctx context.Context, raw []byte, secret []byte) (*RelayResult, error) {
	return r.forward(ctx, CodeAccountingRequest, raw, secret)
}

// relayPlainKey is one hidden MS-MPPE key decrypted from the incoming request. | relayPlainKey 是
// 从入站请求解出的一个隐藏 MS-MPPE 密钥。
type relayPlainKey struct {
	value      []byte
	vendorType uint8
}

// relayRequestPlan holds the secret-independent parts of a translated request plus zeroable
// plaintext credentials. | relayRequestPlan 保存转换后请求中与密钥无关的部分以及可清零的明文凭据。
type relayRequestPlan struct {
	fixed         Attributes
	passwords     [][]byte
	keys          []relayPlainKey
	marker        []byte
	chapChallenge []byte
	code          Code
	includeMA     bool
}

// zero overwrites every plaintext credential held by the plan. | zero 覆盖计划保存的全部明文凭据。
func (p *relayRequestPlan) zero() {
	if p == nil {
		return
	}
	for _, password := range p.passwords {
		zeroBytes(password)
	}
	for _, key := range p.keys {
		zeroBytes(key.value)
	}
}

// forward implements ForwardAccess and ForwardAccounting. | forward 实现 ForwardAccess 与
// ForwardAccounting。
func (r *Relay) forward(ctx context.Context, code Code, raw []byte, secret []byte) (*RelayResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := r.checkClosed(); err != nil {
		return nil, err
	}
	if len(secret) == 0 {
		return nil, errs.Detail(ErrInvalidRequest, "relay downstream shared secret is required")
	}
	packet, err := ParsePacket(raw)
	if err != nil {
		return nil, err
	}
	if packet.Code != code {
		return nil, errs.Detail(ErrUnexpectedCode, "relay received code %d, want %d", uint8(packet.Code), uint8(code))
	}
	plan, err := r.prepareRequest(code, packet, raw, secret)
	if err != nil {
		return nil, err
	}
	defer plan.zero()
	var lastErr error
	for _, upstream := range r.upstreams {
		result, err := r.forwardVia(ctx, upstream, plan, packet, secret)
		if err == nil {
			return result, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, contextError(ctxErr)
		}
		if errors.Is(err, ErrClosed) {
			return nil, err
		}
		lastErr = err
	}
	if lastErr == nil {
		return nil, errs.Detail(ErrNoUpstream, "no relay upstream is configured")
	}
	return nil, errs.WrapDetail(lastErr, ErrNoUpstream, "all %d relay upstream(s) failed", len(r.upstreams))
}

// forwardVia performs one upstream exchange and translates the response. | forwardVia 执行一次上游
// 交互并转换响应。
func (r *Relay) forwardVia(ctx context.Context, upstream relayUpstream, plan *relayRequestPlan, request *Packet, secret []byte) (*RelayResult, error) {
	upstreamSecret, err := upstream.client.secretSnapshot()
	if err != nil {
		return nil, err
	}
	defer zeroBytes(upstreamSecret)
	requireResponseMA := plan.includeMA && plan.code == CodeAccessRequest
	response, responseRaw, upstreamAuthenticator, err := upstream.client.exchange(ctx, plan.code, requireResponseMA, func(int) ([]byte, [16]byte, error) {
		return buildRelayedRequest(upstream.client, plan, upstreamSecret)
	})
	if err != nil {
		return nil, err
	}
	responsePresentMA, responseValidMA, err := verifyMessageAuthenticatorRaw(responseRaw, upstreamSecret, upstreamAuthenticator)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidResponse)
	}
	if responsePresentMA && !responseValidMA {
		return nil, errs.Detail(ErrMessageAuthenticator, "upstream response Message-Authenticator mismatch")
	}
	includeResponseMA := plan.includeMA || responsePresentMA
	attributes := response.Attributes.Clone()
	translated := make(Attributes, 0, len(attributes))
	for _, attribute := range attributes {
		switch {
		case attribute.Type == AttrMessageAuthenticator:
			continue
		case attribute.Type == AttrProxyState && r.ownsMarker(attribute.Value):
			continue
		case attribute.Type == AttrVendorSpecific && attribute.VendorID == VendorMicrosoft &&
			(attribute.VendorType == VendorMSMPPESendKey || attribute.VendorType == VendorMSMPPERecvKey):
			plain, decryptErr := DecryptMSMPPEKey(upstreamSecret, upstreamAuthenticator[:], attribute.Value)
			if decryptErr != nil {
				return nil, errs.Wrap(decryptErr, ErrInvalidResponse)
			}
			encrypted, encryptErr := EncryptMSMPPEKey(secret, request.Authenticator[:], plain)
			zeroBytes(plain)
			if encryptErr != nil {
				return nil, errs.Wrap(encryptErr, ErrInternal)
			}
			attribute.Value = encrypted
			translated = append(translated, attribute)
		default:
			translated = append(translated, attribute)
		}
	}
	if includeResponseMA {
		translated = append(translated, NewAttribute(AttrMessageAuthenticator, make([]byte, 16)))
	}
	responseRaw, err = MarshalPacket(&Packet{
		Code:          response.Code,
		Identifier:    request.Identifier,
		Authenticator: request.Authenticator,
		Attributes:    translated,
	})
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidResponse)
	}
	if includeResponseMA {
		if err := signMessageAuthenticator(responseRaw, secret, request.Authenticator); err != nil {
			return nil, errs.Wrap(err, ErrInternal)
		}
	}
	if err := applyResponseAuthenticator(responseRaw, secret); err != nil {
		return nil, errs.Wrap(err, ErrInternal)
	}
	finalPacket, err := ParsePacket(responseRaw)
	if err != nil {
		return nil, errs.Wrap(err, ErrInternal)
	}
	return &RelayResult{Packet: finalPacket, Raw: responseRaw, Upstream: upstream.name}, nil
}

// prepareRequest verifies an incoming request and builds the secret-independent forwarding plan. |
// prepareRequest 校验入站请求并构建与密钥无关的转发计划。
func (r *Relay) prepareRequest(code Code, packet *Packet, raw, secret []byte) (*relayRequestPlan, error) {
	hops, err := r.checkProxyState(packet.Attributes)
	if err != nil {
		return nil, err
	}
	present, valid, err := verifyInboundMessageAuthenticator(code, raw, secret, packet.Authenticator)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidRequest)
	}
	if present && !valid {
		return nil, errs.Detail(ErrMessageAuthenticator, "request Message-Authenticator mismatch")
	}
	if !present && (r.requireMA || (code == CodeAccessRequest && len(packet.Attributes.GetAll(AttrEAPMessage)) > 0)) {
		return nil, errs.Detail(ErrMessageAuthenticator, "request lacks a required Message-Authenticator")
	}
	if code == CodeAccountingRequest {
		if err := verifyAccountingRequestAuthenticator(raw, secret); err != nil {
			return nil, err
		}
	}
	plan := &relayRequestPlan{
		code:      code,
		includeMA: present,
		marker:    r.proxyStateMarker(hops + 1),
	}
	var hasCHAP bool
	for _, attribute := range packet.Attributes {
		switch {
		case attribute.Type == AttrMessageAuthenticator:
			continue
		case code == CodeAccessRequest && attribute.Type == AttrUserPassword:
			plain, decryptErr := DecryptUserPassword(secret, packet.Authenticator[:], attribute.Value)
			if decryptErr != nil {
				plan.zero()
				return nil, errs.Wrap(decryptErr, ErrInvalidRequest)
			}
			plan.passwords = append(plan.passwords, plain)
		case code == CodeAccessRequest && attribute.Type == AttrVendorSpecific &&
			attribute.VendorID == VendorMicrosoft &&
			(attribute.VendorType == VendorMSMPPESendKey || attribute.VendorType == VendorMSMPPERecvKey):
			plain, decryptErr := DecryptMSMPPEKey(secret, packet.Authenticator[:], attribute.Value)
			if decryptErr != nil {
				plan.zero()
				return nil, errs.Wrap(decryptErr, ErrInvalidRequest)
			}
			plan.keys = append(plan.keys, relayPlainKey{vendorType: attribute.VendorType, value: plain})
		default:
			if attribute.Type == AttrCHAPPassword {
				hasCHAP = true
			}
			plan.fixed = append(plan.fixed, attribute)
		}
	}
	plan.fixed = plan.fixed.Clone()
	if hasCHAP {
		if _, ok := packet.Attributes.Get(AttrCHAPChallenge); !ok {
			plan.chapChallenge = append([]byte(nil), packet.Authenticator[:]...)
		}
	}
	return plan, nil
}

// buildRelayedRequest encodes one upstream transmission attempt with a fresh identifier, Request
// Authenticator and upstream-secret encodings. | buildRelayedRequest 使用新的标识符、Request
// Authenticator 与上游密钥编码，编码一次上游传输尝试。
func buildRelayedRequest(client *Client, plan *relayRequestPlan, secret []byte) ([]byte, [16]byte, error) {
	var requestAuthenticator [16]byte
	attributes := plan.fixed.Clone()
	if plan.code == CodeAccessRequest {
		if _, err := rand.Read(requestAuthenticator[:]); err != nil {
			return nil, requestAuthenticator, errs.Wrap(err, ErrInternal)
		}
		for _, password := range plan.passwords {
			encrypted, err := EncryptUserPassword(secret, requestAuthenticator[:], password)
			if err != nil {
				return nil, requestAuthenticator, errs.Wrap(err, ErrInvalidRequest)
			}
			attributes = append(attributes, NewAttribute(AttrUserPassword, encrypted))
			zeroBytes(encrypted)
		}
		for _, key := range plan.keys {
			encrypted, err := EncryptMSMPPEKey(secret, requestAuthenticator[:], key.value)
			if err != nil {
				return nil, requestAuthenticator, errs.Wrap(err, ErrInvalidRequest)
			}
			attributes = append(attributes, NewVendorAttribute(VendorMicrosoft, key.vendorType, encrypted))
			zeroBytes(encrypted)
		}
		if len(plan.chapChallenge) != 0 {
			attributes = append(attributes, NewAttribute(AttrCHAPChallenge, plan.chapChallenge))
		}
	}
	attributes = append(attributes, NewAttribute(AttrProxyState, plan.marker))
	if plan.includeMA {
		attributes = append(attributes, NewAttribute(AttrMessageAuthenticator, make([]byte, 16)))
	}
	raw, err := MarshalPacket(&Packet{
		Code:          plan.code,
		Identifier:    client.nextIdentifier(),
		Authenticator: requestAuthenticator,
		Attributes:    attributes,
	})
	if err != nil {
		return nil, requestAuthenticator, errs.Wrap(err, ErrInvalidRequest)
	}
	if plan.includeMA && plan.code == CodeAccountingRequest {
		// RFC 2866 computes the Message-Authenticator with a zero Request Authenticator before the
		// accounting Request Authenticator itself is calculated over the packet including the
		// Message-Authenticator. | RFC 2866 要求先用全零 Request Authenticator 计算 Message-Authenticator，
		// 再在包含该 Message-Authenticator 的报文上计算计费 Request Authenticator。
		if err := signMessageAuthenticator(raw, secret, [16]byte{}); err != nil {
			return nil, requestAuthenticator, errs.Wrap(err, ErrInternal)
		}
	}
	if plan.code == CodeAccountingRequest {
		authenticator, err := accountingRequestAuthenticator(raw, secret)
		if err != nil {
			return nil, requestAuthenticator, errs.Wrap(err, ErrInvalidRequest)
		}
		requestAuthenticator = authenticator
		copy(raw[4:HeaderLength], requestAuthenticator[:])
	} else if plan.includeMA {
		if err := signMessageAuthenticator(raw, secret, requestAuthenticator); err != nil {
			return nil, requestAuthenticator, errs.Wrap(err, ErrInternal)
		}
	}
	return raw, requestAuthenticator, nil
}

// checkProxyState detects a loop and returns the number of received Proxy-State attributes. | checkProxyState
// 检测循环并返回收到的 Proxy-State 属性数量。
func (r *Relay) checkProxyState(attributes Attributes) (int, error) {
	states := attributes.GetAll(AttrProxyState)
	for _, state := range states {
		if r.ownsMarker(state.Value) {
			return 0, errs.Detail(ErrRelayLoop, "request carries this relay's Proxy-State marker")
		}
	}
	if len(states) >= r.maxHops {
		return 0, errs.Detail(ErrRelayLoop, "Proxy-State count %d reached limit %d", len(states), r.maxHops)
	}
	return len(states), nil
}

// proxyStateMarker returns the marker appended to a forwarded request. | proxyStateMarker 返回追加到
// 转发请求的标记。
func (r *Relay) proxyStateMarker(hops int) []byte {
	marker := make([]byte, 4+len(r.token)+1)
	copy(marker, relayProxyStateMagic)
	copy(marker[4:], r.token)
	marker[len(marker)-1] = byte(hops)
	return marker
}

// ownsMarker reports whether value was created by this relay. | ownsMarker 报告 value 是否由本中继创建。
func (r *Relay) ownsMarker(value []byte) bool {
	if len(value) != 4+len(r.token)+1 {
		return false
	}
	if string(value[:4]) != relayProxyStateMagic {
		return false
	}
	return constantTimeEqual(value[4:4+len(r.token)], r.token)
}

// checkClosed reports ErrClosed once Close has run. | checkClosed 在 Close 执行后返回 ErrClosed。
func (r *Relay) checkClosed() error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return ErrClosed
	}
	return nil
}
