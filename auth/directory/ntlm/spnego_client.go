package ntlm

import (
	"sync"

	"github.com/shibingli/ydx/errs"
)

// SPNEGOClient drives the initiator side of a SPNEGO GSS-SPNEGO exchange that
// carries NTLMSSP messages. It wraps Client with NegTokenInit/NegTokenResp
// framing, NegState handling and mechListMIC generation and verification. A
// SPNEGOClient is safe for concurrent use, but one instance performs exactly one
// exchange. | SPNEGOClient 驱动承载 NTLMSSP 消息的 SPNEGO GSS-SPNEGO 交换的发起方。
// 它在 Client 之上增加 NegTokenInit/NegTokenResp 分帧、NegState 处理以及 mechListMIC
// 生成与校验。SPNEGOClient 可安全并发使用，但一个实例只执行一次交换。
type SPNEGOClient struct {
	client       *Client
	mechTypes    [][]byte
	mechTypesDER []byte
	mu           sync.Mutex

	state       SPNEGOState
	finalSent   bool
	micRequired bool
	closed      bool
}

// NewSPNEGOClient validates config, derives the NTLMv2 keys and prepares a
// SPNEGO initiator that advertises only NTLMSSP. | NewSPNEGOClient 校验 config、
// 派生 NTLMv2 密钥，并准备仅声明 NTLMSSP 的 SPNEGO 发起方。
func NewSPNEGOClient(config Config) (*SPNEGOClient, error) {
	client, err := NewClient(config)
	if err != nil {
		return nil, err
	}
	mechanisms := [][]byte{append([]byte(nil), ntlmMechOID...)}
	mechTypesDER, err := EncodeMechTypeList(mechanisms)
	if err != nil {
		return nil, err
	}
	return &SPNEGOClient{
		client:       client,
		mechTypes:    mechanisms,
		mechTypesDER: mechTypesDER,
		state:        SPNEGOStateInitial,
	}, nil
}

// InitialToken builds the GSS-API InitialContextToken carrying a NegTokenInit
// with the Type 1 NEGOTIATE_MESSAGE. InitialToken may be called only once. |
// InitialToken 构建携带 Type 1 NEGOTIATE_MESSAGE 的 NegTokenInit 的 GSS-API
// InitialContextToken。InitialToken 只能调用一次。
func (c *SPNEGOClient) InitialToken() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errs.Detail(ErrSPNEGOState, "SPNEGO client is closed | SPNEGO 客户端已关闭")
	}
	if c.state != SPNEGOStateInitial {
		return nil, errs.Detail(ErrSPNEGOState, "initial token was already produced or the exchange failed | 已生成初始令牌或交换已失败")
	}
	negotiate, err := c.client.Negotiate()
	if err != nil {
		c.state = SPNEGOStateFailed
		return nil, err
	}
	token, err := EncodeSPNEGOToken(&SPNEGOToken{
		MechTypes: c.mechTypes,
		MechToken: negotiate,
	}, true)
	if err != nil {
		c.state = SPNEGOStateFailed
		return nil, err
	}
	c.state = SPNEGOStateInProgress
	return token, nil
}

// AcceptToken processes one server token. The first call consumes the Type 2
// challenge wrapped in a NegTokenResp or NegTokenInit and returns the final
// NegTokenResp carrying the Type 3 message and mechListMIC. The second call
// consumes the optional server final token, verifies any server mechListMIC fail
// closed, and completes the exchange. | AcceptToken 处理一个服务端令牌。第一次调用
// 消费包装在 NegTokenResp 或 NegTokenInit 中的 Type 2 挑战，返回携带 Type 3 消息与
// mechListMIC 的最终 NegTokenResp。第二次调用消费可选的服务端最终令牌，失败关闭地校验
// 任何服务端 mechListMIC，并完成交换。
func (c *SPNEGOClient) AcceptToken(data []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errs.Detail(ErrSPNEGOState, "SPNEGO client is closed | SPNEGO 客户端已关闭")
	}
	if c.state != SPNEGOStateInProgress {
		return nil, errs.Detail(ErrSPNEGOState, "SPNEGO exchange is not in progress | SPNEGO 交换未在进行中")
	}
	if !c.finalSent {
		return c.acceptChallengeLocked(data)
	}
	return c.acceptFinalLocked(data)
}

// Complete marks the exchange completed when the server returns no final SPNEGO
// token. It is valid only after AcceptToken produced the final NegTokenResp. |
// Complete 在服务端未返回最终 SPNEGO 令牌时把交换标记为完成。仅当 AcceptToken 已生成
// 最终 NegTokenResp 后有效。
func (c *SPNEGOClient) Complete() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errs.Detail(ErrSPNEGOState, "SPNEGO client is closed | SPNEGO 客户端已关闭")
	}
	if c.state != SPNEGOStateInProgress || !c.finalSent {
		return errs.Detail(ErrSPNEGOState, "exchange has not reached the final token | 交换尚未到达最终令牌")
	}
	c.state = SPNEGOStateCompleted
	return nil
}

// State returns the current exchange state. | State 返回当前交换状态。
func (c *SPNEGOClient) State() SPNEGOState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// NegotiatedFlags returns the flags carried by the Type 3 message. It is valid
// only after the challenge has been processed. | NegotiatedFlags 返回 Type 3 消息
// 携带的标志。仅在处理挑战之后有效。
func (c *SPNEGOClient) NegotiatedFlags() (NegotiateFlags, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errs.Detail(ErrSPNEGOState, "SPNEGO client is closed | SPNEGO 客户端已关闭")
	}
	return c.client.NegotiatedFlags()
}

// SecuritySession returns the NTLMSSP signing and sealing state created by the
// wrapped Client. | SecuritySession 返回被包装的 Client 创建的 NTLMSSP 签名与密封状态。
func (c *SPNEGOClient) SecuritySession() (*SecuritySession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errs.Detail(ErrSPNEGOState, "SPNEGO client is closed | SPNEGO 客户端已关闭")
	}
	return c.client.SecuritySession()
}

// ExportedSessionKey returns a copy of the exported session key held by the
// wrapped Client. | ExportedSessionKey 返回被包装的 Client 持有的导出会话密钥副本。
func (c *SPNEGOClient) ExportedSessionKey() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errs.Detail(ErrSPNEGOState, "SPNEGO client is closed | SPNEGO 客户端已关闭")
	}
	return c.client.ExportedSessionKey()
}

// Sign returns a client-to-server NTLMSSP message signature. | Sign 返回客户端到服务端的
// NTLMSSP 消息签名。
func (c *SPNEGOClient) Sign(message []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errs.Detail(ErrSPNEGOState, "SPNEGO client is closed | SPNEGO 客户端已关闭")
	}
	return c.client.Sign(message)
}

// Verify checks a server-to-client NTLMSSP message signature. | Verify 校验服务端到客户端的
// NTLMSSP 消息签名。
func (c *SPNEGOClient) Verify(message, signature []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errs.Detail(ErrSPNEGOState, "SPNEGO client is closed | SPNEGO 客户端已关闭")
	}
	return c.client.Verify(message, signature)
}

// Seal encrypts a client-to-server message and appends its signature. | Seal 加密
// 客户端到服务端消息并附加其签名。
func (c *SPNEGOClient) Seal(message []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errs.Detail(ErrSPNEGOState, "SPNEGO client is closed | SPNEGO 客户端已关闭")
	}
	return c.client.Seal(message)
}

// Unseal decrypts a server-to-client sealed message and verifies its signature. |
// Unseal 解密服务端到客户端密封消息并校验其签名。
func (c *SPNEGOClient) Unseal(sealed []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errs.Detail(ErrSPNEGOState, "SPNEGO client is closed | SPNEGO 客户端已关闭")
	}
	return c.client.Unseal(sealed)
}

// Close wipes the wrapped client's session keys and closes its security session.
// Close is idempotent. | Close 清零被包装客户端的会话密钥并关闭其安全会话。Close 可重复
// 调用。
func (c *SPNEGOClient) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	return c.client.Close()
}

// fail records a terminal error and returns it. | fail 记录终止错误并返回。
func (c *SPNEGOClient) fail(err error) ([]byte, error) {
	c.state = SPNEGOStateFailed
	return nil, err
}

// acceptChallengeLocked validates a server challenge token and produces the
// final client token. | acceptChallengeLocked 校验服务端挑战令牌并生成最终客户端令牌。
func (c *SPNEGOClient) acceptChallengeLocked(data []byte) ([]byte, error) {
	token, err := ParseSPNEGOToken(data)
	if err != nil {
		return c.fail(err)
	}
	if !token.SupportsNTLM() {
		return c.fail(errs.Detail(ErrSPNEGO, "server does not select NTLM | 服务端未选择 NTLM"))
	}
	if token.HasNegState {
		switch token.NegState {
		case NegStateAcceptIncomplete:
		case NegStateRequestMIC:
			c.micRequired = true
		case NegStateReject:
			return c.fail(errs.Detail(ErrSPNEGOState, "server rejected SPNEGO negotiation | 服务端拒绝 SPNEGO 协商"))
		case NegStateAcceptCompleted:
			return c.fail(errs.Detail(ErrSPNEGOState, "server completed SPNEGO before NTLM authentication | 服务端在 NTLM 认证前完成 SPNEGO"))
		default:
			return c.fail(errs.Detail(ErrSPNEGO, "unknown SPNEGO negotiation state | 未知 SPNEGO 协商状态"))
		}
	}
	challenge := token.Token()
	if len(challenge) == 0 {
		return c.fail(errs.Detail(ErrSPNEGO, "server token carries no NTLM challenge | 服务端令牌未携带 NTLM 挑战"))
	}
	authenticate, err := c.client.Authenticate(challenge)
	if err != nil {
		return c.fail(err)
	}
	if token.HasMechListMIC {
		if err := c.client.VerifyMechListMIC(c.mechTypesDER, token.MechListMIC); err != nil {
			return c.fail(err)
		}
	}
	mic, micErr := c.client.MechListMIC(c.mechTypesDER)
	if micErr != nil {
		if c.micRequired {
			return c.fail(micErr)
		}
		mic = nil
	}
	final, err := EncodeSPNEGOResponseWithMIC(authenticate, mic)
	if err != nil {
		return c.fail(err)
	}
	c.finalSent = true
	return final, nil
}

// acceptFinalLocked validates the optional server final token. | acceptFinalLocked
// 校验可选的服务端最终令牌。
func (c *SPNEGOClient) acceptFinalLocked(data []byte) ([]byte, error) {
	token, err := ParseSPNEGOToken(data)
	if err != nil {
		return c.fail(err)
	}
	if !token.SupportsNTLM() {
		return c.fail(errs.Detail(ErrSPNEGO, "server does not select NTLM | 服务端未选择 NTLM"))
	}
	if token.HasNegState {
		switch token.NegState {
		case NegStateAcceptCompleted:
		case NegStateAcceptIncomplete:
			return c.fail(errs.Detail(ErrSPNEGOState, "server did not complete SPNEGO | 服务端未完成 SPNEGO"))
		case NegStateReject:
			return c.fail(errs.Detail(ErrSPNEGOState, "server rejected SPNEGO negotiation | 服务端拒绝 SPNEGO 协商"))
		case NegStateRequestMIC:
			return c.fail(errs.Detail(ErrSPNEGOState, "server requested a mechListMIC after the final token | 服务端在最终令牌之后请求 mechListMIC"))
		default:
			return c.fail(errs.Detail(ErrSPNEGO, "unknown SPNEGO negotiation state | 未知 SPNEGO 协商状态"))
		}
	}
	if token.HasMechListMIC {
		if err := c.client.VerifyMechListMIC(c.mechTypesDER, token.MechListMIC); err != nil {
			return c.fail(err)
		}
	}
	c.state = SPNEGOStateCompleted
	return nil, nil
}
