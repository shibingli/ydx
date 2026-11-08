package ntlm

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"sync"

	"github.com/shibingli/ydx/errs"
)

// baseAcceptorFlags are the flags an Acceptor advertises when AcceptorConfig
// leaves Flags zero. NTLMv2 does not require signing or key exchange, so those
// bits are not offered by default. | baseAcceptorFlags 是 AcceptorConfig 的 Flags
// 为零时 Acceptor 声明的标志。NTLMv2 不需要签名或密钥交换，因此默认不提供这些位。
const baseAcceptorFlags = FlagUnicode | FlagOEM | FlagRequestTarget | FlagNTLM |
	FlagAlwaysSign | FlagTargetInfo | FlagVersion | Flag128 | Flag56 |
	FlagExtendedSessionSecurity

// AcceptorConfig configures an NTLMv2 SPNEGO acceptor. Either ResponseKey or
// Password must be set. The acceptor supports one Type 1/Type 2/Type 3 exchange
// per instance. | AcceptorConfig 配置 NTLMv2 SPNEGO 接受方。必须设置 ResponseKey 或
// Password。每个实例支持一次 Type 1/Type 2/Type 3 交换。
type AcceptorConfig struct {
	// ResponseKey looks up the 16-byte NTLMv2Hash for an NTLM domain and user
	// name. It takes precedence over Password. | ResponseKey 按 NTLM 域与用户名查询
	// 16 字节 NTLMv2Hash。它优先于 Password。
	ResponseKey func(domain, username string) ([]byte, bool)
	// Password looks up the account password for an NTLM domain and user name.
	// The password is never logged or retained. | Password 按 NTLM 域与用户名查询账户
	// 口令。口令绝不记录日志或保留。
	Password func(domain, username string) (string, bool)
	// Domain is advertised as the NetBIOS domain AV pair and is the default
	// target name. | Domain 作为 NetBIOS 域 AV 对声明，并作为默认目标名称。
	Domain string
	// ServerName is advertised as the NetBIOS computer-name AV pair. | ServerName
	// 作为 NetBIOS 计算机名 AV 对声明。
	ServerName string
	// TargetName overrides the Type 2 target name. It defaults to Domain and
	// then ServerName. | TargetName 覆盖 Type 2 目标名称。默认依次使用 Domain 与
	// ServerName。
	TargetName string
	// ServerChallenge overrides the random eight-byte Type 2 nonce. It exists for
	// deterministic tests. | ServerChallenge 覆盖随机八字节 Type 2 随机数。它用于确定性测试。
	ServerChallenge []byte
	// TargetInfo overrides the generated AV pairs. Domain, ServerName and
	// RequireMIC are merged into a non-nil value. | TargetInfo 覆盖生成的 AV 对。
	// Domain、ServerName 与 RequireMIC 会合并到非 nil 值中。
	TargetInfo TargetInfo
	// Flags overrides the advertised negotiate flags. A zero value selects
	// baseAcceptorFlags. Sign, Seal and KeyExchange are added to the selected
	// set. | Flags 覆盖声明的协商标志。零值选择 baseAcceptorFlags。Sign、Seal 与
	// KeyExchange 会加入所选集合。
	Flags NegotiateFlags
	// Sign advertises and requires NTLMSSP message signing (FlagSign). Signing
	// requires NTLMv2 extended session security. | Sign 声明并要求 NTLMSSP 消息签名
	// （FlagSign）。签名需要 NTLMv2 扩展会话安全。
	Sign bool
	// Seal advertises and requires NTLMSSP message sealing (FlagSeal). Sealing
	// requires Sign. | Seal 声明并要求 NTLMSSP 消息密封（FlagSeal）。密封需要 Sign。
	Seal bool
	// KeyExchange advertises and requires NTLMSSP session-key exchange
	// (FlagKeyExchange). The Type 3 SessionKey field is decrypted with the
	// NTLMv2 SessionBaseKey and becomes the exported session key. | KeyExchange
	// 声明并要求 NTLMSSP 会话密钥交换（FlagKeyExchange）。Type 3 的 SessionKey 字段使用
	// NTLMv2 SessionBaseKey 解密，并成为导出会话密钥。
	KeyExchange bool
	// RequireMIC requires a Type 3 MIC and advertises MsvAvMICPresent. |
	// RequireMIC 要求 Type 3 MIC，并声明 MsvAvMICPresent。
	RequireMIC bool
	// RequireMechListMIC requires a client mechListMIC and sends
	// NegStateRequestMIC in the challenge. It applies only to SPNEGO framing. |
	// RequireMechListMIC 要求客户端 mechListMIC，并在挑战中发送 NegStateRequestMIC。
	// 它仅适用于 SPNEGO 分帧。
	RequireMechListMIC bool
	// SendMechListMIC makes the acceptor send its own mechListMIC in the final
	// NegTokenResp. | SendMechListMIC 使接受方在最终 NegTokenResp 中发送自己的
	// mechListMIC。
	SendMechListMIC bool
	// AllowRawNTLM accepts a bare Type 1 NTLMSSP token in addition to SPNEGO. |
	// AllowRawNTLM 除 SPNEGO 外还接受裸 Type 1 NTLMSSP 令牌。
	AllowRawNTLM bool
}

// AcceptResult is the outcome of a successfully verified acceptor exchange. |
// AcceptResult 是成功校验的接受方交换结果。
type AcceptResult struct {
	// Domain is the authenticated NTLM domain. | Domain 是已认证的 NTLM 域。
	Domain string
	// Username is the authenticated user name. | Username 是已认证的用户名。
	Username string
	// Workstation is the client workstation name. | Workstation 是客户端工作站名称。
	Workstation string
	// SessionBaseKey is the 16-byte NTLMv2 SessionBaseKey. It is keying material:
	// callers must protect it and zero it when no longer needed. | SessionBaseKey
	// 是 16 字节 NTLMv2 SessionBaseKey。它是密钥材料：调用方必须保护它，并在不再需要时
	// 清零。
	SessionBaseKey []byte
	// ExportedSessionKey is the 16-byte session key exported by the exchange.
	// With FlagKeyExchange it is the decrypted Type 3 SessionKey; otherwise it
	// equals SessionBaseKey. It is keying material: callers must protect it and
	// zero it when no longer needed. | ExportedSessionKey 是交换导出的 16 字节会话密钥。
	// 协商 FlagKeyExchange 时它是解密后的 Type 3 SessionKey；否则等于 SessionBaseKey。它是
	// 密钥材料：调用方必须保护它，并在不再需要时清零。
	ExportedSessionKey []byte
	// Flags is the negotiated flag set carried by the Type 3 message. | Flags 是
	// Type 3 消息携带的协商标志集。
	Flags NegotiateFlags
	// SPNEGO reports whether the exchange used SPNEGO framing. | SPNEGO 报告交换是否
	// 使用 SPNEGO 分帧。
	SPNEGO bool
	// MICVerified reports whether a Type 3 MIC was present and verified. |
	// MICVerified 报告是否校验了存在的 Type 3 MIC。
	MICVerified bool
	// MechListMICVerified reports whether a client mechListMIC was verified. |
	// MechListMICVerified 报告是否校验了客户端 mechListMIC。
	MechListMICVerified bool
}

// Acceptor validates NTLMv2 challenge-response authentication and, when SPNEGO
// framing is used, mechListMIC and Type 3 MIC values. All verification failures
// are fail closed. An Acceptor is safe for concurrent use, but one instance
// performs exactly one exchange. | Acceptor 校验 NTLMv2 挑战响应认证，并在使用
// SPNEGO 分帧时校验 mechListMIC 与 Type 3 MIC。所有校验失败均失败关闭。Acceptor 可安全
// 并发使用，但一个实例只执行一次交换。
type Acceptor struct {
	security           *SecuritySession
	targetName         string
	targetInfo         TargetInfo
	challengeOverride  []byte
	negotiate          []byte
	challenge          []byte
	mechTypesDER       []byte
	exportedSessionKey []byte

	config AcceptorConfig
	mu     sync.Mutex

	flags              NegotiateFlags
	serverChallenge    [8]byte
	state              SPNEGOState
	spnego             bool
	requireMechListMIC bool
	closed             bool
}

// NewAcceptor validates config and prepares a single-use acceptor. Domain,
// ServerName or TargetInfo must describe at least one AV pair so strict NTLMv2
// clients accept the challenge. | NewAcceptor 校验 config 并准备单次使用的接受方。
// Domain、ServerName 或 TargetInfo 必须描述至少一个 AV 对，以便严格 NTLMv2 客户端接受
// 挑战。
func NewAcceptor(config AcceptorConfig) (*Acceptor, error) {
	if config.ResponseKey == nil && config.Password == nil {
		return nil, errs.Detail(ErrAcceptorConfig, "ResponseKey or Password callback is required | 必须提供 ResponseKey 或 Password 回调")
	}
	if config.Seal && !config.Sign {
		return nil, errs.Detail(ErrAcceptorConfig, "message sealing requires message signing | 消息密封需要消息签名")
	}
	flags := config.Flags
	if flags == 0 {
		flags = baseAcceptorFlags
	}
	if config.Sign {
		flags |= FlagSign
	}
	if config.Seal {
		flags |= FlagSeal
	}
	if config.KeyExchange {
		flags |= FlagKeyExchange
	}
	if flags.Has(FlagSeal) && !flags.Has(FlagSign) {
		return nil, errs.Detail(ErrAcceptorConfig, "message sealing requires message signing | 消息密封需要消息签名")
	}
	if (flags.Has(FlagSign) || flags.Has(FlagSeal)) && !flags.Has(FlagExtendedSessionSecurity) {
		return nil, errs.Detail(ErrAcceptorConfig, "message signing and sealing require extended session security | 消息签名与密封需要扩展会话安全")
	}
	if !flags.Has(FlagNTLM) && !flags.Has(FlagNTLMOnly) {
		return nil, errs.Detail(ErrAcceptorConfig, "advertised flags do not include NTLM | 声明标志不包含 NTLM")
	}
	if !flags.Has(FlagUnicode) {
		return nil, errs.Detail(ErrAcceptorConfig, "advertised flags do not include Unicode | 声明标志不包含 Unicode")
	}
	var challenge []byte
	if config.ServerChallenge != nil {
		if len(config.ServerChallenge) != 8 {
			return nil, errs.Detail(ErrAcceptorConfig, "server challenge is %d bytes, want 8 | 服务端挑战为 %d 字节，期望 8", len(config.ServerChallenge), len(config.ServerChallenge))
		}
		challenge = append([]byte(nil), config.ServerChallenge...)
	}
	targetInfo, err := buildAcceptorTargetInfo(config)
	if err != nil {
		return nil, err
	}
	targetName := config.TargetName
	if targetName == "" {
		targetName = config.Domain
	}
	if targetName == "" {
		targetName = config.ServerName
	}
	return &Acceptor{
		config:            config,
		flags:             flags,
		targetInfo:        targetInfo,
		targetName:        targetName,
		challengeOverride: challenge,
		state:             SPNEGOStateInitial,
	}, nil
}

// buildAcceptorTargetInfo clones the configured AV pairs and merges the
// generated domain, computer name and MIC flag. | buildAcceptorTargetInfo 克隆配置
// 的 AV 对，并合并生成的域、计算机名与 MIC 标志。
func buildAcceptorTargetInfo(config AcceptorConfig) (TargetInfo, error) {
	info := config.TargetInfo.withoutEndOfList()
	if info == nil {
		info = make(TargetInfo, 0, 3)
	}
	if config.Domain != "" {
		if _, ok := info.Get(AVNbDomainName); !ok {
			info.set(AVNbDomainName, utf16LE(config.Domain))
		}
	}
	if config.ServerName != "" {
		if _, ok := info.Get(AVNbComputerName); !ok {
			info.set(AVNbComputerName, utf16LE(config.ServerName))
		}
	}
	if config.RequireMIC {
		flags, ok := info.Flags()
		if !ok {
			flags = 0
		}
		flags |= AVFlagMICPresent
		var value [4]byte
		binary.LittleEndian.PutUint32(value[:], flags)
		info.set(AVFlags, value[:])
	}
	if len(info.withoutEndOfList()) == 0 {
		return nil, errs.Detail(ErrAcceptorConfig, "target info is empty; set Domain, ServerName or TargetInfo | 目标信息为空；请设置 Domain、ServerName 或 TargetInfo")
	}
	if err := info.Validate(); err != nil {
		return nil, errs.WrapDetail(err, ErrAcceptorConfig, "acceptor target info is invalid | 接受方目标信息非法")
	}
	return info, nil
}

// AcceptInitial validates the client's Type 1 message and returns the Type 2
// challenge. With SPNEGO the result is a NegTokenResp carrying
// NegStateAcceptIncomplete or NegStateRequestMIC; with raw NTLM it is the bare
// CHALLENGE_MESSAGE. | AcceptInitial 校验客户端 Type 1 消息并返回 Type 2 挑战。
// 使用 SPNEGO 时结果是携带 NegStateAcceptIncomplete 或 NegStateRequestMIC 的
// NegTokenResp；使用裸 NTLM 时是裸 CHALLENGE_MESSAGE。
func (a *Acceptor) AcceptInitial(data []byte) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, errs.Detail(ErrAcceptorState, "acceptor is closed | 接受方已关闭")
	}
	if a.state != SPNEGOStateInitial {
		return nil, errs.Detail(ErrAcceptorState, "initial message was already processed or the exchange failed | 初始消息已处理或交换已失败")
	}
	spnego := true
	var negotiate []byte
	token, parseErr := ParseSPNEGOToken(data)
	if parseErr == nil {
		if !token.SupportsNTLM() {
			return a.failInitial(errs.Detail(ErrSPNEGO, "client does not offer NTLM | 客户端未提供 NTLM"))
		}
		if len(token.MechTypes) == 0 {
			return a.failInitial(errs.Detail(ErrSPNEGO, "initial SPNEGO token has no mechTypes | 初始 SPNEGO 令牌没有 mechTypes"))
		}
		if token.HasMechListMIC {
			return a.failInitial(errs.Detail(ErrMechListMIC, "an NTLM mechListMIC cannot precede the Type 2 challenge | NTLM mechListMIC 不能先于 Type 2 挑战"))
		}
		mechTypesDER := token.MechTypesDER
		if len(mechTypesDER) == 0 {
			var err error
			mechTypesDER, err = EncodeMechTypeList(token.MechTypes)
			if err != nil {
				return a.failInitial(err)
			}
		}
		negotiate = token.Token()
		if len(negotiate) == 0 {
			return a.failInitial(errs.Detail(ErrSPNEGO, "initial SPNEGO token carries no NTLM message | 初始 SPNEGO 令牌未携带 NTLM 消息"))
		}
		a.mechTypesDER = append([]byte(nil), mechTypesDER...)
		a.requireMechListMIC = !bytes.Equal(token.MechTypes[0], ntlmMechOID)
	} else {
		if !a.config.AllowRawNTLM {
			return a.failInitial(parseErr)
		}
		if !bytes.HasPrefix(data, []byte(Signature)) {
			return a.failInitial(parseErr)
		}
		spnego = false
		negotiate = data
	}
	if a.config.RequireMechListMIC {
		if !spnego {
			return a.failInitial(errs.Detail(ErrMechListMIC, "raw NTLM cannot carry a mechListMIC | 裸 NTLM 无法携带 mechListMIC"))
		}
		a.requireMechListMIC = true
	}
	negotiateMessage, err := DecodeNegotiate(negotiate)
	if err != nil {
		return a.failInitial(err)
	}
	if !negotiateMessage.Flags.Has(FlagNTLM) && !negotiateMessage.Flags.Has(FlagNTLMOnly) {
		return a.failInitial(errs.Detail(ErrMessage, "client does not negotiate NTLM | 客户端未协商 NTLM"))
	}
	if !negotiateMessage.Flags.Has(FlagUnicode) {
		return a.failInitial(errs.Detail(ErrMessage, "client does not negotiate Unicode | 客户端未协商 Unicode"))
	}
	var challenge [8]byte
	if a.challengeOverride != nil {
		copy(challenge[:], a.challengeOverride)
	} else if _, err := rand.Read(challenge[:]); err != nil {
		return a.failInitial(errs.WrapDetail(err, ErrRandom, "cannot generate the server challenge | 无法生成服务端挑战"))
	}
	challengeMessage := &ChallengeMessage{
		Flags:           a.flags,
		ServerChallenge: challenge,
		TargetName:      a.targetName,
		TargetInfo:      a.targetInfo,
	}
	challengeData, err := challengeMessage.Encode()
	if err != nil {
		return a.failInitial(err)
	}
	a.negotiate = append([]byte(nil), negotiate...)
	a.challenge = append([]byte(nil), challengeData...)
	a.serverChallenge = challenge
	a.spnego = spnego
	a.state = SPNEGOStateInProgress
	if !spnego {
		return append([]byte(nil), challengeData...), nil
	}
	state := NegStateAcceptIncomplete
	if a.requireMechListMIC {
		state = NegStateRequestMIC
	}
	response, err := EncodeSPNEGOToken(&SPNEGOToken{
		HasNegState:   true,
		NegState:      state,
		SupportedMech: ntlmMechOID,
		ResponseToken: challengeData,
	}, false)
	if err != nil {
		a.state = SPNEGOStateFailed
		return nil, err
	}
	return response, nil
}

// failInitial records a terminal failure and returns err. | failInitial 记录终止失败并
// 返回 err。
func (a *Acceptor) failInitial(err error) ([]byte, error) {
	a.state = SPNEGOStateFailed
	return nil, err
}

// AcceptFinal verifies the Type 3 message, Type 3 MIC and SPNEGO mechListMIC
// and returns the authenticated identity plus an optional final NegTokenResp to
// send to the client. The final token is nil for raw NTLM. | AcceptFinal 校验 Type 3
// 消息、Type 3 MIC 与 SPNEGO mechListMIC，并返回已认证身份以及可选的、要发送给客户端的
// 最终 NegTokenResp。裸 NTLM 的最终令牌为 nil。
func (a *Acceptor) AcceptFinal(data []byte) (*AcceptResult, []byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, nil, errs.Detail(ErrAcceptorState, "acceptor is closed | 接受方已关闭")
	}
	if a.state != SPNEGOStateInProgress {
		return nil, nil, errs.Detail(ErrAcceptorState, "acceptor is not waiting for a final message | 接受方未等待最终消息")
	}
	var authData, mechListMIC []byte
	var mechListMICPresent bool
	if a.spnego {
		token, err := ParseSPNEGOToken(data)
		if err != nil {
			return a.failFinal(err)
		}
		if !token.SupportsNTLM() {
			return a.failFinal(errs.Detail(ErrSPNEGO, "client does not select NTLM | 客户端未选择 NTLM"))
		}
		if token.HasNegState {
			switch token.NegState {
			case NegStateAcceptIncomplete:
			case NegStateReject:
				return a.failFinal(errs.Detail(ErrSPNEGOState, "client rejected SPNEGO negotiation | 客户端拒绝 SPNEGO 协商"))
			case NegStateRequestMIC:
				return a.failFinal(errs.Detail(ErrSPNEGOState, "client requested a mechListMIC after the final token | 客户端在最终令牌之后请求 mechListMIC"))
			case NegStateAcceptCompleted:
				return a.failFinal(errs.Detail(ErrSPNEGOState, "client must not send accept-completed | 客户端不得发送 accept-completed"))
			default:
				return a.failFinal(errs.Detail(ErrSPNEGO, "unknown SPNEGO negotiation state | 未知 SPNEGO 协商状态"))
			}
		}
		if len(token.ResponseToken) == 0 {
			return a.failFinal(errs.Detail(ErrSPNEGO, "final SPNEGO token carries no responseToken | 最终 SPNEGO 令牌未携带 responseToken"))
		}
		authData = token.ResponseToken
		mechListMIC = token.MechListMIC
		mechListMICPresent = token.HasMechListMIC
	} else {
		authData = data
	}
	message, err := DecodeAuthenticate(authData)
	if err != nil {
		return a.failFinal(err)
	}
	if !message.Flags.Has(FlagUnicode) {
		return a.failFinal(errs.Detail(ErrAuthentication, "Type 3 message does not negotiate Unicode | Type 3 消息未协商 Unicode"))
	}
	if !message.Flags.Has(FlagNTLM) && !message.Flags.Has(FlagNTLMOnly) {
		return a.failFinal(errs.Detail(ErrAuthentication, "Type 3 message does not negotiate NTLM | Type 3 消息未协商 NTLM"))
	}
	if message.Flags&^a.flags != 0 {
		return a.failFinal(errs.Detail(ErrAuthentication, "Type 3 flags contain bits the acceptor did not offer | Type 3 标志包含接受方未声明的位"))
	}
	if message.Flags.Has(FlagSeal) && !message.Flags.Has(FlagSign) {
		return a.failFinal(errs.Detail(ErrSessionSecurity, "Type 3 message negotiates sealing without signing | Type 3 消息协商密封但未协商签名"))
	}
	if (message.Flags.Has(FlagSign) || message.Flags.Has(FlagSeal)) && !message.Flags.Has(FlagExtendedSessionSecurity) {
		return a.failFinal(errs.Detail(ErrSessionSecurity, "message signing and sealing require extended session security | 消息签名与密封需要扩展会话安全"))
	}
	if a.config.Sign && !message.Flags.Has(FlagSign) {
		return a.failFinal(errs.Detail(ErrSigningNotNegotiated, "client did not negotiate the required message signing | 客户端未协商要求消息签名"))
	}
	if a.config.Seal && !message.Flags.Has(FlagSeal) {
		return a.failFinal(errs.Detail(ErrSealingNotNegotiated, "client did not negotiate the required message sealing | 客户端未协商要求消息密封"))
	}
	if a.config.KeyExchange && !message.Flags.Has(FlagKeyExchange) {
		return a.failFinal(errs.Detail(ErrSessionSecurity, "client did not negotiate the required session-key exchange | 客户端未协商要求的会话密钥交换"))
	}
	responseKey, err := a.lookupResponseKey(message.Domain, message.Username)
	if err != nil {
		return a.failFinal(err)
	}
	defer wipe(responseKey)
	sessionBaseKey, err := verifyNTLMv2(a.serverChallenge[:], responseKey, message)
	if err != nil {
		return a.failFinal(err)
	}
	defer wipe(sessionBaseKey)
	type3MICPresent, err := verifyType3MIC(a.negotiate, a.challenge, authData, message, sessionBaseKey)
	if err != nil {
		return a.failFinal(err)
	}
	if a.config.RequireMIC && !type3MICPresent {
		return a.failFinal(errs.Detail(ErrAuthentication, "Type 3 MIC is required | 要求 Type 3 MIC"))
	}
	var exportedSessionKey []byte
	var security *SecuritySession
	completed := false
	defer func() {
		wipe(exportedSessionKey)
		if !completed && security != nil {
			_ = security.Close()
		}
	}()
	if message.Flags.Has(FlagKeyExchange) {
		if len(message.SessionKey) != sessionKeySize {
			return a.failFinal(errs.Detail(ErrAuthentication, "Type 3 session key is %d bytes, want %d | Type 3 会话密钥为 %d 字节，期望 %d", len(message.SessionKey), sessionKeySize, len(message.SessionKey), sessionKeySize))
		}
		exportedSessionKey, err = rc4SessionKey(sessionBaseKey, message.SessionKey)
		if err != nil {
			return a.failFinal(err)
		}
	} else {
		// MS-NLMP marks the field unused without key exchange; some clients send
		// it anyway, so ignore it and use the SessionBaseKey. | MS-NLMP 规定未协商
		// 密钥交换时该字段不使用；部分客户端仍会填充，因此忽略它并使用 SessionBaseKey。
		exportedSessionKey = append([]byte(nil), sessionBaseKey...)
	}
	if message.Flags.Has(FlagSign) || message.Flags.Has(FlagSeal) {
		security, err = NewSecuritySession(RoleServer, exportedSessionKey, message.Flags)
		if err != nil {
			return a.failFinal(err)
		}
	}
	mechListMICVerified := false
	if a.spnego {
		required := a.requireMechListMIC || a.config.RequireMechListMIC || type3MICPresent
		if required && !mechListMICPresent {
			return a.failFinal(errs.Detail(ErrMechListMIC, "client mechListMIC is required | 要求客户端 mechListMIC"))
		}
		if mechListMICPresent {
			if err := VerifyMechListMIC(sessionBaseKey, a.mechTypesDER, mechListMIC, message.Flags); err != nil {
				return a.failFinal(err)
			}
			mechListMICVerified = true
		}
	}
	var finalToken []byte
	if a.spnego {
		var serverMIC []byte
		if a.config.SendMechListMIC {
			serverMIC, err = ComputeMechListMIC(sessionBaseKey, a.mechTypesDER, message.Flags)
			if err != nil {
				return a.failFinal(err)
			}
		}
		finalToken, err = EncodeSPNEGOToken(&SPNEGOToken{
			HasNegState:    true,
			NegState:       NegStateAcceptCompleted,
			SupportedMech:  ntlmMechOID,
			MechListMIC:    serverMIC,
			HasMechListMIC: serverMIC != nil,
		}, false)
		if err != nil {
			return a.failFinal(err)
		}
	}
	result := &AcceptResult{
		Domain:              message.Domain,
		Username:            message.Username,
		Workstation:         message.Workstation,
		Flags:               message.Flags,
		SessionBaseKey:      append([]byte(nil), sessionBaseKey...),
		ExportedSessionKey:  append([]byte(nil), exportedSessionKey...),
		SPNEGO:              a.spnego,
		MICVerified:         type3MICPresent,
		MechListMICVerified: mechListMICVerified,
	}
	a.exportedSessionKey = append([]byte(nil), exportedSessionKey...)
	a.security = security
	completed = true
	a.state = SPNEGOStateCompleted
	return result, finalToken, nil
}

// failFinal records a terminal failure and returns the acceptor error triple. |
// failFinal 记录终止失败并返回接受方错误三元组。
func (a *Acceptor) failFinal(err error) (*AcceptResult, []byte, error) {
	a.state = SPNEGOStateFailed
	return nil, nil, err
}

// State returns the current acceptor exchange state. | State 返回当前接受方交换状态。
func (a *Acceptor) State() SPNEGOState {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state
}

// lookupResponseKey resolves the NTLMv2 response key through the configured
// callback. Errors intentionally omit the account identity. | lookupResponseKey
// 通过配置的回调解析 NTLMv2 响应密钥。错误有意省略账户身份。
func (a *Acceptor) lookupResponseKey(domain, username string) ([]byte, error) {
	if a.config.ResponseKey != nil {
		key, ok := a.config.ResponseKey(domain, username)
		if !ok {
			return nil, errs.Detail(ErrAuthentication, "credentials were not found | 未找到凭据")
		}
		if len(key) != md4Size {
			return nil, errs.Detail(ErrAuthentication, "response key is %d bytes, want %d | 响应密钥为 %d 字节，期望 %d", len(key), md4Size, len(key), md4Size)
		}
		return append([]byte(nil), key...), nil
	}
	password, ok := a.config.Password(domain, username)
	if !ok {
		return nil, errs.Detail(ErrAuthentication, "credentials were not found | 未找到凭据")
	}
	return NTLMv2Hash(password, username, domain), nil
}

// verifyNTLMv2 validates the NTLMv2 NT proof string and optional LMv2 response
// and returns the SessionBaseKey. Only the NTLMv2 response format is accepted. |
// verifyNTLMv2 校验 NTLMv2 NT proof 字符串与可选 LMv2 响应，并返回 SessionBaseKey。
// 仅接受 NTLMv2 响应格式。
func verifyNTLMv2(serverChallenge, responseKey []byte, message *AuthenticateMessage) ([]byte, error) {
	if len(serverChallenge) != 8 {
		return nil, errs.Detail(ErrAuthentication, "server challenge is %d bytes, want 8 | 服务端挑战为 %d 字节，期望 8", len(serverChallenge), len(serverChallenge))
	}
	if len(responseKey) != md4Size {
		return nil, errs.Detail(ErrAuthentication, "response key has invalid length | 响应密钥长度非法")
	}
	ntResponse := message.NTResponse
	if len(ntResponse) < 16+28+4+4 {
		return nil, errs.Detail(ErrAuthentication, "NTLMv2 response is %d bytes, want at least %d | NTLMv2 响应为 %d 字节，至少需要 %d", len(ntResponse), 16+28+4+4, len(ntResponse), 16+28+4+4)
	}
	proof := ntResponse[:16]
	temp := ntResponse[16:]
	if temp[0] != 1 || temp[1] != 1 {
		return nil, errs.Detail(ErrAuthentication, "NTLMv2 response type is invalid | NTLMv2 响应类型非法")
	}
	zero := []byte{0, 0, 0, 0}
	for _, span := range [][2]int{{2, 4}, {4, 8}, {24, 28}, {len(temp) - 4, len(temp)}} {
		if !constantTimeEqual(temp[span[0]:span[1]], zero[:span[1]-span[0]]) {
			return nil, errs.Detail(ErrAuthentication, "NTLMv2 temporary field %d is not zero | NTLMv2 临时字段 %d 非零", span[0], span[0])
		}
	}
	if _, err := ParseTargetInfo(temp[28 : len(temp)-4]); err != nil {
		return nil, errs.WrapDetail(err, ErrAuthentication, "NTLMv2 target info is invalid | NTLMv2 目标信息非法")
	}
	clientChallenge := temp[16:24]
	if len(message.LMResponse) > 0 {
		if len(message.LMResponse) != 24 {
			return nil, errs.Detail(ErrAuthentication, "LMv2 response is %d bytes, want 24 | LMv2 响应为 %d 字节，期望 24", len(message.LMResponse), len(message.LMResponse))
		}
		if !constantTimeEqual(message.LMResponse[16:], clientChallenge) {
			return nil, errs.Detail(ErrAuthentication, "LMv2 client challenge does not match | LMv2 客户端挑战不匹配")
		}
		lmInput := make([]byte, 0, len(serverChallenge)+len(clientChallenge))
		lmInput = append(lmInput, serverChallenge...)
		lmInput = append(lmInput, clientChallenge...)
		expectedLM := hmacMD5(responseKey, lmInput)
		if !constantTimeEqual(message.LMResponse[:16], expectedLM) {
			return nil, errs.Detail(ErrAuthentication, "LMv2 response does not match | LMv2 响应不匹配")
		}
	}
	proofInput := make([]byte, 0, len(serverChallenge)+len(temp))
	proofInput = append(proofInput, serverChallenge...)
	proofInput = append(proofInput, temp...)
	expectedProof := hmacMD5(responseKey, proofInput)
	if !constantTimeEqual(proof, expectedProof) {
		return nil, errs.Detail(ErrAuthentication, "NT proof string does not match | NT proof 字符串不匹配")
	}
	return hmacMD5(responseKey, proof), nil
}

// verifyType3MIC verifies the Type 1/2/3 MIC when present and reports whether
// the message carried one. | verifyType3MIC 在存在时校验 Type 1/2/3 MIC，并报告消息
// 是否携带该 MIC。
func verifyType3MIC(negotiate, challenge, authData []byte, message *AuthenticateMessage, sessionBaseKey []byte) (bool, error) {
	zeroed, present, err := AuthenticateMICInput(authData)
	if err != nil {
		return false, err
	}
	if !present {
		return false, nil
	}
	if len(message.MIC) != micSize {
		return true, errs.Detail(ErrAuthentication, "Type 3 MIC has invalid length | Type 3 MIC 长度非法")
	}
	input := make([]byte, 0, len(negotiate)+len(challenge)+len(zeroed))
	input = append(input, negotiate...)
	input = append(input, challenge...)
	input = append(input, zeroed...)
	expected := hmacMD5(sessionBaseKey, input)
	if !constantTimeEqual(message.MIC, expected) {
		return true, errs.Detail(ErrAuthentication, "Type 3 MIC does not match | Type 3 MIC 不匹配")
	}
	return true, nil
}
