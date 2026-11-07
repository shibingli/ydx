package ntlm

import (
	"crypto/rand"
	"strings"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Config configures an NTLMv2 client. Zero values select NTLMv2, strict
// target-info validation, a random client challenge, and the server-provided
// timestamp. | Config 配置 NTLMv2 客户端。零值选择 NTLMv2、严格目标信息校验、随机客户端
// 挑战与服务端提供的时间戳。
type Config struct {
	// Domain is the Active Directory domain, or empty when Username is a UPN or
	// carries DOMAIN\user. | Domain 是 Active Directory 域；当 Username 是 UPN 或带有
	// DOMAIN\user 时可为空。
	Domain string
	// Username is the account name. DOMAIN\user and user@realm forms are
	// accepted and normalized. | Username 是账户名。接受并规范化 DOMAIN\user 与
	// user@realm 形式。
	Username string
	// Password is the account password. It is never logged. | Password 是账户口令。
	// 绝不记录日志。
	Password string
	// Workstation is the optional client workstation name. | Workstation 是可选客户端
	// 工作站名称。
	Workstation string
	// ResponseMode selects NTLMv2 (default), NTLMv1, or the NTLM2 session
	// response. Non-default modes require AllowLegacy. | ResponseMode 选择 NTLMv2
	// （默认）、NTLMv1 或 NTLM2 会话响应。非默认模式需要 AllowLegacy。
	ResponseMode ResponseMode
	// AllowLegacy explicitly enables the legacy NTLMv1 and NTLM2 session
	// responses. It is false by default. | AllowLegacy 显式启用旧式 NTLMv1 与 NTLM2
	// 会话响应。默认值为 false。
	AllowLegacy bool
	// AllowMissingTargetInfo permits an NTLMv2 challenge without AV pairs. Active
	// Directory always supplies them, so the default is strict. | AllowMissingTargetInfo
	// 允许没有 AV 对的 NTLMv2 挑战。Active Directory 总会提供 AV 对，因此默认严格校验。
	AllowMissingTargetInfo bool
	// ForceMIC requests a MIC even when the server does not set MsvAvMICPresent.
	// MICs are implemented only for NTLMv2. | ForceMIC 即使在服务端未设置
	// MsvAvMICPresent 时也请求 MIC。MIC 仅为 NTLMv2 实现。
	ForceMIC bool
	// ChannelBindings is the optional 16-byte GSS channel-binding value to insert
	// as MsvAvChannelBindings. Use ChannelBindingHash to derive it from an RFC 5929
	// tls-server-end-point certificate hash. | ChannelBindings 是可选 16 字节 GSS
	// 通道绑定值，作为 MsvAvChannelBindings 插入。可用 ChannelBindingHash 从 RFC 5929
	// tls-server-end-point 证书哈希派生。
	ChannelBindings []byte
	// ClientChallenge overrides the random eight-byte client challenge. It exists
	// for deterministic tests and should be left nil in production. | ClientChallenge
	// 覆盖随机八字节客户端挑战。它用于确定性测试，生产环境应保持 nil。
	ClientChallenge []byte
	// Timestamp overrides the challenge timestamp. A zero value uses the server
	// MsvAvTimestamp pair, falling back to the current time. | Timestamp 覆盖挑战
	// 时间戳。零值使用服务端 MsvAvTimestamp 对，缺失时回退到当前时间。
	Timestamp time.Time
	// Version overrides the NTLMSSP version field sent by the client. | Version
	// 覆盖客户端发送的 NTLMSSP 版本字段。
	Version *Version
}

// clientState tracks the NTLMSSP exchange position. | clientState 跟踪 NTLMSSP 交换
// 位置。
type clientState uint8

const (
	clientStateIdle clientState = iota
	clientStateNegotiated
	clientStateAuthenticated
)

// baseClientFlags are the flags this client requests in the Type 1 message,
// excluding the mode-dependent extended-session-security bit. | baseClientFlags
// 是本客户端在 Type 1 消息中请求的标志，不含依赖模式的扩展会话安全位。
const baseClientFlags = FlagUnicode | FlagOEM | FlagRequestTarget | FlagNTLM |
	FlagAlwaysSign | FlagTargetInfo | FlagVersion | Flag128 | Flag56

// Client performs one NTLMSSP Type 1/Type 3 exchange against a server. A Client
// is safe for concurrent use, but each exchange must call Negotiate exactly once
// before Authenticate. | Client 对服务端执行一次 NTLMSSP Type 1/Type 3 交换。Client
// 可安全并发使用，但每次交换必须在 Authenticate 前恰好调用一次 Negotiate。
type Client struct {
	mu sync.Mutex

	domain                 string
	username               string
	workstation            string
	mode                   ResponseMode
	allowMissingTargetInfo bool
	forceMIC               bool
	channelBindings        []byte
	clientChallenge        []byte
	timestamp              time.Time
	version                *Version
	flags                  NegotiateFlags
	responseKey            []byte
	lmResponseKey          []byte

	negotiate []byte
	state     clientState
}

// NewClient validates config and derives the response keys. Plaintext passwords
// are not retained. Legacy modes are rejected unless AllowLegacy is true. |
// NewClient 校验 config 并派生响应密钥。不保留明文口令。除非 AllowLegacy 为 true，
// 否则拒绝旧式模式。
func NewClient(config Config) (*Client, error) {
	mode := config.ResponseMode
	switch mode {
	case ResponseNTLMv2, ResponseNTLMv1, ResponseNTLM2Session:
	default:
		return nil, errs.Detail(ErrUnsupported, "response mode %d is not implemented | 响应模式 %d 未实现", mode, mode)
	}
	if mode != ResponseNTLMv2 && !config.AllowLegacy {
		return nil, errs.Detail(ErrLegacyDisabled, "response mode %s requires AllowLegacy | 响应模式 %s 需要 AllowLegacy", mode, mode)
	}
	domain, username, err := SplitUsername(config.Username, config.Domain)
	if err != nil {
		return nil, err
	}
	if strings.IndexByte(config.Password, 0) >= 0 {
		return nil, errs.Detail(ErrCredentials, "password contains NUL | 口令包含 NUL")
	}
	workstation := strings.TrimSpace(config.Workstation)
	if strings.IndexByte(workstation, 0) >= 0 {
		return nil, errs.Detail(ErrCredentials, "workstation contains NUL | 工作站名称包含 NUL")
	}
	var challenge []byte
	if config.ClientChallenge != nil {
		if len(config.ClientChallenge) != 8 {
			return nil, errs.Detail(ErrCredentials, "client challenge is %d bytes, want 8 | 客户端挑战为 %d 字节，期望 8", len(config.ClientChallenge), len(config.ClientChallenge))
		}
		challenge = append([]byte(nil), config.ClientChallenge...)
	}
	var bindings []byte
	if config.ChannelBindings != nil {
		if mode != ResponseNTLMv2 {
			return nil, errs.Detail(ErrChannelBindings, "channel bindings require NTLMv2 | 通道绑定需要 NTLMv2")
		}
		if len(config.ChannelBindings) != 16 {
			return nil, errs.Detail(ErrChannelBindings, "channel bindings are %d bytes, want 16 | 通道绑定为 %d 字节，期望 16", len(config.ChannelBindings), len(config.ChannelBindings))
		}
		bindings = append([]byte(nil), config.ChannelBindings...)
	}
	if config.ForceMIC && mode != ResponseNTLMv2 {
		return nil, errs.Detail(ErrUnsupported, "MIC requires NTLMv2 | MIC 需要 NTLMv2")
	}
	flags := baseClientFlags
	if mode != ResponseNTLMv1 {
		flags |= FlagExtendedSessionSecurity
	}
	client := &Client{
		domain:                 domain,
		username:               username,
		workstation:            workstation,
		mode:                   mode,
		allowMissingTargetInfo: config.AllowMissingTargetInfo,
		forceMIC:               config.ForceMIC,
		channelBindings:        bindings,
		clientChallenge:        challenge,
		timestamp:              config.Timestamp,
		flags:                  flags,
	}
	if config.Version != nil {
		version := *config.Version
		client.version = &version
	}
	if mode == ResponseNTLMv2 {
		client.responseKey = NTLMv2Hash(config.Password, username, domain)
	} else {
		client.responseKey = ntHash(config.Password)
	}
	if mode == ResponseNTLMv1 {
		client.lmResponseKey, err = lmHash(config.Password)
		if err != nil {
			return nil, err
		}
	}
	return client, nil
}

// Negotiate builds and returns the Type 1 NEGOTIATE_MESSAGE. | Negotiate 构建并返回
// Type 1 NEGOTIATE_MESSAGE。
func (c *Client) Negotiate() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != clientStateIdle {
		return nil, errs.Detail(ErrClientState, "Negotiate may be called only once | Negotiate 只能调用一次")
	}
	message := &NegotiateMessage{
		Flags:       c.flags,
		Domain:      c.domain,
		Workstation: c.workstation,
		Version:     c.version,
	}
	encoded, err := message.Encode()
	if err != nil {
		return nil, err
	}
	c.negotiate = encoded
	c.state = clientStateNegotiated
	return append([]byte(nil), encoded...), nil
}

// Authenticate validates the raw Type 2 CHALLENGE_MESSAGE and returns the Type 3
// AUTHENTICATE_MESSAGE. The server challenge must support Unicode, must contain
// NTLM, must not be all zero, and for NTLMv2 must carry target info unless
// AllowMissingTargetInfo is set. A MIC is added when the server sets
// MsvAvMICPresent or ForceMIC is true. | Authenticate 校验原始 Type 2
// CHALLENGE_MESSAGE 并返回 Type 3 AUTHENTICATE_MESSAGE。服务端挑战必须支持 Unicode、
// 包含 NTLM、不能全零；除设置 AllowMissingTargetInfo 外，NTLMv2 必须携带目标信息。
// 当服务端设置 MsvAvMICPresent 或 ForceMIC 为 true 时添加 MIC。
func (c *Client) Authenticate(challengeData []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != clientStateNegotiated {
		return nil, errs.Detail(ErrClientState, "Authenticate requires a preceding Negotiate | Authenticate 需要先调用 Negotiate")
	}
	challenge, err := DecodeChallenge(challengeData)
	if err != nil {
		return nil, err
	}
	if !challenge.Flags.Has(FlagNTLM) && !challenge.Flags.Has(FlagNTLMOnly) {
		return nil, errs.Detail(ErrChallenge, "server challenge does not negotiate NTLM | 服务端挑战未协商 NTLM")
	}
	if !challenge.Flags.Has(FlagUnicode) {
		return nil, errs.Detail(ErrChallenge, "server challenge does not negotiate Unicode | 服务端挑战未协商 Unicode")
	}
	var zeroChallenge [8]byte
	if constantTimeEqual(challenge.ServerChallenge[:], zeroChallenge[:]) {
		return nil, errs.Detail(ErrChallenge, "server challenge is all zero | 服务端挑战全为零")
	}
	info := challenge.TargetInfo
	if c.mode == ResponseNTLMv2 && len(info.withoutEndOfList()) == 0 && !c.allowMissingTargetInfo {
		return nil, errs.Detail(ErrTargetInfo, "server challenge has no target info | 服务端挑战没有目标信息")
	}
	if c.mode == ResponseNTLM2Session && !challenge.Flags.Has(FlagExtendedSessionSecurity) {
		return nil, errs.Detail(ErrChallenge, "server does not negotiate extended session security | 服务端未协商扩展会话安全")
	}
	if c.mode == ResponseNTLMv1 && challenge.Flags.Has(FlagExtendedSessionSecurity) {
		return nil, errs.Detail(ErrChallenge, "server requires extended session security but NTLMv1 was selected | 服务端要求扩展会话安全，但已选择 NTLMv1")
	}
	if c.mode == ResponseNTLMv2 {
		info, err = c.applyChannelBindings(info)
		if err != nil {
			return nil, err
		}
	}
	avFlags, _ := info.Flags()
	micRequested := c.mode == ResponseNTLMv2 && (c.forceMIC || avFlags&AVFlagMICPresent != 0)
	if c.mode != ResponseNTLMv2 && avFlags&AVFlagMICPresent != 0 {
		return nil, errs.Detail(ErrUnsupported, "server requires a MIC, which needs NTLMv2 | 服务端要求 MIC，而 MIC 需要 NTLMv2")
	}
	timestamp := c.challengeTimestamp(info)
	clientChallenge := c.clientChallenge
	if clientChallenge == nil {
		clientChallenge = make([]byte, 8)
		if _, err := rand.Read(clientChallenge); err != nil {
			return nil, errs.WrapDetail(err, ErrRandom, "cannot generate client challenge | 无法生成客户端挑战")
		}
	}
	var lmResponse, ntResponse, sessionBaseKey []byte
	switch c.mode {
	case ResponseNTLMv2:
		targetInfo, err := info.withoutEndOfList().Encode()
		if err != nil {
			return nil, err
		}
		response, err := ComputeNTLMv2Response(c.responseKey, challenge.ServerChallenge[:], clientChallenge, timestamp, targetInfo)
		if err != nil {
			return nil, err
		}
		lmResponse = response.LMv2Response
		ntResponse = response.NTResponse
		sessionBaseKey = response.SessionBaseKey
	case ResponseNTLMv1:
		lmResponse, err = ntlmV1Response(c.lmResponseKey, challenge.ServerChallenge[:])
		if err != nil {
			return nil, err
		}
		ntResponse, err = ntlmV1Response(c.responseKey, challenge.ServerChallenge[:])
		if err != nil {
			return nil, err
		}
	case ResponseNTLM2Session:
		ntResponse, lmResponse, err = ntlm2SessionResponse(c.responseKey, challenge.ServerChallenge[:], clientChallenge)
		if err != nil {
			return nil, err
		}
	}
	negotiated := c.flags & challenge.Flags
	if !negotiated.Has(FlagUnicode) {
		return nil, errs.Detail(ErrChallenge, "negotiated flags lack Unicode | 协商标志缺少 Unicode")
	}
	message := &AuthenticateMessage{
		LMResponse:  lmResponse,
		NTResponse:  ntResponse,
		Domain:      c.domain,
		Username:    c.username,
		Workstation: c.workstation,
		Flags:       negotiated,
		Version:     c.version,
	}
	if micRequested {
		message.MIC = make([]byte, micSize)
		zeroed, err := message.Encode()
		if err != nil {
			return nil, err
		}
		macInput := make([]byte, 0, len(c.negotiate)+len(challengeData)+len(zeroed))
		macInput = append(macInput, c.negotiate...)
		macInput = append(macInput, challengeData...)
		macInput = append(macInput, zeroed...)
		message.MIC = hmacMD5(sessionBaseKey, macInput)
	}
	encoded, err := message.Encode()
	if err != nil {
		return nil, err
	}
	c.state = clientStateAuthenticated
	wipe(c.responseKey)
	wipe(c.lmResponseKey)
	c.responseKey = nil
	c.lmResponseKey = nil
	return encoded, nil
}

// applyChannelBindings verifies a server MsvAvChannelBindings pair and replaces
// it with the configured client value. A server binding without a configured
// client binding is rejected. The returned slice may have grown, so callers must
// use it instead of their input. | applyChannelBindings 校验服务端
// MsvAvChannelBindings 对并替换为配置的客户端值。服务端提供绑定而客户端未配置时拒绝。
// 返回的切片可能已增长，调用方必须使用返回值而不是输入值。
func (c *Client) applyChannelBindings(info TargetInfo) (TargetInfo, error) {
	serverBinding, present := info.Get(AVChannelBindings)
	if present {
		if c.channelBindings == nil {
			return nil, errs.Detail(ErrChannelBindings, "server requires channel bindings but none are configured | 服务端要求通道绑定，但未配置")
		}
		if !constantTimeEqual(serverBinding, c.channelBindings) {
			return nil, errs.Detail(ErrChannelBindings, "server channel bindings do not match | 服务端通道绑定不匹配")
		}
	}
	if c.channelBindings != nil {
		info.set(AVChannelBindings, c.channelBindings)
	}
	return info, nil
}

// challengeTimestamp returns the configured timestamp, else the server
// MsvAvTimestamp, else the current UTC time. | challengeTimestamp 返回配置的时间戳，
// 否则服务端 MsvAvTimestamp，最后回退到当前 UTC 时间。
func (c *Client) challengeTimestamp(info TargetInfo) time.Time {
	if !c.timestamp.IsZero() {
		return c.timestamp
	}
	if serverTime, ok := info.Timestamp(); ok && !serverTime.IsZero() {
		return serverTime
	}
	return time.Now().UTC()
}

// wipe clears sensitive bytes. | wipe 清除敏感字节。
func wipe(data []byte) {
	for index := range data {
		data[index] = 0
	}
}
