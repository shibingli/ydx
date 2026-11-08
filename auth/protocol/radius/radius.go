// Package radius implements pure-Go RADIUS client and server components for authentication,
// accounting and RFC 5176 dynamic authorization. | Package radius 实现纯 Go 的 RADIUS 认证、计费与
// RFC 5176 动态授权客户端与服务端组件。
//
// The package implements the RFC 2865 Access-Request, Access-Accept, Access-Reject and
// Access-Challenge exchange with PAP, CHAP and MS-CHAPv2 credentials; RFC 2866 accounting;
// RFC 2869/RFC 3579 EAP-Message passthrough with Message-Authenticator; RFC 5176 CoA-Request and
// Disconnect-Request with ACK/NAK, Error-Cause and Event-Timestamp; and RFC 6613/RFC 6614 RADIUS
// over TCP and TLS. AccessServer and AccountingServer are reusable responders over UDP, TCP or TLS:
// they resolve per-client shared secrets, verify Request Authenticators and Message-Authenticators,
// invoke a pluggable authenticator or accounting handler, and return signed responses. Packets are
// encoded and decoded with strict length validation, unknown attributes are preserved byte for
// byte, and every authenticator comparison is constant time. | 本包实现 RFC 2865 的 Access-Request、
// Access-Accept、Access-Reject 与 Access-Challenge 交互，支持 PAP、CHAP 与 MS-CHAPv2 凭据；
// RFC 2866 计费；RFC 2869/RFC 3579 的 EAP-Message 透传与 Message-Authenticator；RFC 5176 的
// CoA-Request 与 Disconnect-Request 及其 ACK/NAK、Error-Cause 与 Event-Timestamp；以及
// RFC 6613/RFC 6614 的 RADIUS over TCP 与 TLS。AccessServer 与 AccountingServer 是基于 UDP、
// TCP 或 TLS 的可复用响应器：解析每客户端共享密钥、校验 Request Authenticator 与
// Message-Authenticator、调用可插拔的认证器或计费处理器，并返回已签名的响应。报文编解码执行严格
// 的长度校验，未知属性按字节原样保留，所有认证符比较均为常量时间。
//
// On top of the client and responder primitives, the package provides an EAP server (EAP-MD5,
// EAP-MSCHAPv2, EAP-TLS, EAP-TTLS with PAP or MS-CHAPv2 inner authentication, and PEAPv0 with
// inner EAP-MSCHAPv2), a stateful MS-CHAPv2 responder, and a RADIUS relay and proxy. The EAP server
// implements the continuation state machine, fragment reassembly, Access-Challenge generation and
// Message-Authenticator handling and plugs into AccessServer as an AccessAuthenticator. Relay and
// ProxyServer forward Access-Request and Accounting-Request packets with Proxy-State preservation,
// loop detection, identifier and request-authenticator mapping, upstream failover and PAP/MS-MPPE
// re-encryption. AccountingServer optionally requires and verifies Message-Authenticator and
// suppresses duplicate records within a bounded window. | 在客户端与响应器原语之上，本包提供 EAP
// 服务器（EAP-MD5、EAP-MSCHAPv2、EAP-TLS、内层 PAP 或 MS-CHAPv2 的 EAP-TTLS，以及内层
// EAP-MSCHAPv2 的 PEAPv0）、有状态 MS-CHAPv2 响应器，以及 RADIUS 中继与代理。EAP 服务器实现续传
// 状态机、分片重组、Access-Challenge 生成与 Message-Authenticator 处理，并作为 AccessAuthenticator
// 接入 AccessServer。Relay 与 ProxyServer 转发 Access-Request 与 Accounting-Request，支持
// Proxy-State 保留、循环检测、标识符与请求认证符映射、上游故障转移以及 PAP/MS-MPPE 重新加密。
// AccountingServer 可选地要求并校验 Message-Authenticator，并在有界窗口内抑制重复记录。
//
// # Usage | 用法
//
//	client, err := radius.NewClient(radius.ClientConfig{
//	    Address:       "127.0.0.1:1812",
//	    Secret:        []byte("shared-secret"),
//	    NASIdentifier: "edge-1",
//	})
//	if err != nil {
//	    return err
//	}
//	defer client.Close()
//
//	response, err := client.AccessRequest(ctx, &radius.AccessRequest{
//	    UserName: "alice",
//	    Password: "correct horse battery staple",
//	})
//	if err != nil {
//	    return err
//	}
//	if response.Accepted() {
//	    // response.SessionTimeout, response.FilterID, response.FramedIPAddress, ...
//	}
//
// Accounting uses the same client and shared secret: | 计费使用同一客户端与共享密钥：
//
//	response, err := client.AccountRequest(ctx, &radius.AccountingRequest{
//	    StatusType: radius.AcctStatusStart,
//	    SessionID:  "session-1",
//	    UserName:   "alice",
//	})
//
// Access and accounting responders use a pluggable authenticator or handler: | 访问与计费响应器使用
// 可插拔的认证器或处理器：
//
//	server, err := radius.NewAccessServer(radius.AccessServerConfig{
//	    Address: "0.0.0.0:1812",
//	    Secret:  []byte("shared-secret"),
//	    Authenticator: radius.AccessAuthenticatorFunc(func(ctx context.Context, request *radius.AccessServerRequest) (*radius.AccessServerResult, error) {
//	        if request.VerifyPAP([]byte("correct horse battery staple")) {
//	            return &radius.AccessServerResult{Accept: true}, nil
//	        }
//	        return &radius.AccessServerResult{ReplyMessage: "access denied"}, nil
//	    }),
//	})
//	if err != nil {
//	    return err
//	}
//	defer server.Close()
//	if err := server.ListenAndServe(ctx); err != nil {
//	    return err
//	}
//
// RFC 5176 dynamic authorization uses the same client and shared secret: | RFC 5176 动态授权使用
// 同一客户端与共享密钥：
//
//	response, err := client.SendCoA(ctx, &radius.CoARequest{
//	    SessionID: "session-1",
//	    Attributes: radius.Attributes{
//	        radius.NewAttribute(radius.AttrFilterID, []byte("new-acl")),
//	    },
//	})
//	if errors.Is(err, radius.ErrCoANAK) {
//	    // response.ErrorCause classifies the rejection.
//	}
//
// Dynamic authorization has two roles. SendCoA and SendDisconnect implement the Dynamic
// Authorization Client (DAC) role. A DynamicServer implements the RFC 5176 NAS-side responder over
// UDP: it authenticates CoA-Request and Disconnect-Request packets, invokes a
// DynamicRequestHandler, and returns a signed ACK or NAK with Error-Cause, Reply-Message and extra
// attributes. A DynamicDuplicateCache keyed by source address, request code, Identifier and Request
// Authenticator replays the cached response for a retransmission without invoking the handler
// again. Retransmissions are byte-identical, with the same Identifier, Request Authenticator and
// Event-Timestamp, and UDP attempts reuse one source socket, so RFC 5176 section 3.6 duplicate
// detection works end to end. ACK and NAK packets are verified against the Request Authenticator
// and against any Message-Authenticator they carry. | 动态授权有两种角色。SendCoA 与
// SendDisconnect 实现动态授权客户端（DAC）角色。DynamicServer 实现基于 UDP 的 RFC 5176 NAS 侧
// 响应器：认证 CoA-Request 与 Disconnect-Request，调用 DynamicRequestHandler，并返回带
// Error-Cause、Reply-Message 与附加属性的已签名 ACK 或 NAK。以源地址、请求类型、Identifier 与
// Request Authenticator 为键的 DynamicDuplicateCache 会对重传重放缓存响应而不再调用处理器。重传
// 字节完全相同，Identifier、Request Authenticator 与 Event-Timestamp 均不变，且 UDP 各次尝试复用
// 同一个源套接字，因此 RFC 5176 第 3.6 节的重复检测可端到端生效。ACK 与 NAK 报文会依据 Request
// Authenticator 以及其携带的任何 Message-Authenticator 进行校验。
//
//	A server, err := radius.NewDynamicServer(radius.DynamicServerConfig{
//	    Address: "0.0.0.0:3799",
//	    Secret:  []byte("shared-secret"),
//	    Handler: radius.DynamicRequestHandlerFunc(func(ctx context.Context, request *radius.DynamicAuthorizationPacket) (*radius.DynamicAuthorizationResult, error) {
//	        return &radius.DynamicAuthorizationResult{Accept: true}, nil
//	    }),
//	})
//	if err != nil {
//	    return err
//	}
//	defer server.Close()
//	if err := server.ListenAndServe(ctx); err != nil {
//	    return err
//	}
//
// Remaining boundaries: relay and proxy forwarding covers Access-Request and Accounting-Request
// only; CoA-Request and Disconnect-Request are sent by the client or answered by DynamicServer and
// are never relayed. Relay supports UDP, TCP and TLS upstreams, while ProxyServer accepts UDP, TCP
// and TLS downstream connections and handles both Access-Request and Accounting-Request on one
// listener. EAP and MS-CHAPv2 challenge state
// and the accounting duplicate cache live in process memory; deployments with multiple instances
// need sticky routing or a shared front end. EAP-TLS, EAP-TTLS and PEAP terminate TLS inside the
// EAP server and do not provide a generic TLS record layer for arbitrary upper protocols.
// AccessServer and AccountingServer keep only in-memory transport state; user lookup, credential
// verification and accounting persistence belong to the callbacks. Dynamic authorization is
// UDP-only. | 剩余边界：中继与代理仅转发 Access-Request 与 Accounting-Request；CoA-Request 与
// Disconnect-Request 由客户端发送或由 DynamicServer 应答，绝不中继。Relay 支持 UDP、TCP 与 TLS
// 上游，ProxyServer 接受 UDP、TCP 与 TLS 下游连接，每个监听器处理一种请求码。EAP 与 MS-CHAPv2
// 挑战状态以及计费重复缓存保存在进程内存中；多实例部署需要粘性路由或共享前端。EAP-TLS、
// EAP-TTLS 与 PEAP 在 EAP 服务器内终结 TLS，不提供面向任意上层协议的通用 TLS 记录层。
// AccessServer 与 AccountingServer 仅保存在内存中的传输状态；用户查找、凭据校验与计费持久化由
// 回调负责。动态授权仅支持 UDP。
package radius

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Protocol limits defined by RFC 2865. | RFC 2865 定义的协议上限。
const (
	// HeaderLength is the fixed RADIUS header size in octets. | HeaderLength 是 RADIUS 固定头部的字节数。
	HeaderLength = 20
	// MaxPacketLength is the largest RADIUS packet in octets. | MaxPacketLength 是 RADIUS 报文的最大字节数。
	MaxPacketLength = 4096
	// MaxAttributeValueLength is the largest attribute value in octets. | MaxAttributeValueLength 是属性值的最大字节数。
	MaxAttributeValueLength = 253
	// DefaultTimeout is used when ClientConfig.Timeout is zero. | DefaultTimeout 是 ClientConfig.Timeout 为零时使用的超时。
	DefaultTimeout = 5 * time.Second
)

// Transport names accepted by ClientConfig.Network. | ClientConfig.Network 接受的传输名称。
const (
	// NetworkUDP selects RADIUS over UDP (RFC 2865). | NetworkUDP 选择基于 UDP 的 RADIUS（RFC 2865）。
	NetworkUDP = "udp"
	// NetworkTCP selects RADIUS over TCP (RFC 6613). | NetworkTCP 选择基于 TCP 的 RADIUS（RFC 6613）。
	NetworkTCP = "tcp"
	// NetworkTLS selects RADIUS over TLS (RFC 6614). | NetworkTLS 选择基于 TLS 的 RADIUS（RFC 6614）。
	NetworkTLS = "tls"
)

// Code is a RADIUS packet code. | Code 是 RADIUS 报文类型码。
type Code uint8

// RADIUS packet codes. | RADIUS 报文类型码。
const (
	// CodeAccessRequest asks the server to authenticate a user. | CodeAccessRequest 请求服务器认证用户。
	CodeAccessRequest Code = 1
	// CodeAccessAccept reports a successful authentication. | CodeAccessAccept 表示认证成功。
	CodeAccessAccept Code = 2
	// CodeAccessReject reports a failed authentication. | CodeAccessReject 表示认证失败。
	CodeAccessReject Code = 3
	// CodeAccountingRequest carries accounting records. | CodeAccountingRequest 携带计费记录。
	CodeAccountingRequest Code = 4
	// CodeAccountingResponse acknowledges an accounting request. | CodeAccountingResponse 确认计费请求。
	CodeAccountingResponse Code = 5
	// CodeAccessChallenge asks the client for more authentication information. | CodeAccessChallenge 要求客户端提供更多认证信息。
	CodeAccessChallenge Code = 11
	// CodeStatusServer is an RFC 5997 server status request. | CodeStatusServer 是 RFC 5997 服务器状态请求。
	CodeStatusServer Code = 12
	// CodeStatusClient is an RFC 5997 client status response. | CodeStatusClient 是 RFC 5997 客户端状态响应。
	CodeStatusClient Code = 13
	// CodeDisconnectRequest asks a NAS to disconnect a session. | CodeDisconnectRequest 要求 NAS 断开会话。
	CodeDisconnectRequest Code = 40
	// CodeDisconnectACK acknowledges a disconnect request. | CodeDisconnectACK 确认断开请求。
	CodeDisconnectACK Code = 41
	// CodeDisconnectNAK rejects a disconnect request. | CodeDisconnectNAK 拒绝断开请求。
	CodeDisconnectNAK Code = 42
	// CodeCoARequest asks a NAS to change session authorization. | CodeCoARequest 要求 NAS 变更会话授权。
	CodeCoARequest Code = 43
	// CodeCoAACK acknowledges a change-of-authorization request. | CodeCoAACK 确认授权变更请求。
	CodeCoAACK Code = 44
	// CodeCoANAK rejects a change-of-authorization request. | CodeCoANAK 拒绝授权变更请求。
	CodeCoANAK Code = 45
)

// AuthMethod selects how an AccessRequest encodes its credential. | AuthMethod 选择 AccessRequest 编码凭据的方式。
type AuthMethod uint8

// Authentication methods supported by AccessRequest. | AccessRequest 支持的认证方法。
const (
	// AuthPAP sends the password with RFC 2865 User-Password hiding. | AuthPAP 以 RFC 2865 的 User-Password 隐藏方式发送口令。
	AuthPAP AuthMethod = iota
	// AuthCHAP sends an RFC 2865 CHAP-Password response. | AuthCHAP 发送 RFC 2865 CHAP-Password 响应。
	AuthCHAP
	// AuthMSCHAPv2 sends RFC 2759 MS-CHAPv2 vendor attributes. | AuthMSCHAPv2 发送 RFC 2759 MS-CHAPv2 厂商属性。
	AuthMSCHAPv2
	// AuthEAP passes caller-supplied EAP packets through EAP-Message attributes. | AuthEAP 通过 EAP-Message 属性透传调用方提供的 EAP 报文。
	AuthEAP
	// AuthNone sends no credential attribute, which is useful to start a challenge exchange. | AuthNone 不发送凭据属性，适合发起挑战交互。
	AuthNone
)

// The declared sentinels of the package. | 包的哨兵错误声明。
//
// Every failure path returns one of them directly or through errs.Detail / errs.Wrap, so callers
// can classify errors with errors.Is instead of matching text. Error details never contain the
// shared secret or a user password. | 所有失败路径都直接返回其中之一，或经由 errs.Detail / errs.Wrap
// 包装，因此调用方可用 errors.Is 分类错误而无需匹配文案。错误细节绝不包含共享密钥或用户口令。
var (
	// ErrInvalidConfig reports a missing or contradictory client configuration. | ErrInvalidConfig 表示客户端配置缺失或互相矛盾。
	ErrInvalidConfig = errs.New("radius: invalid configuration | radius：配置非法")
	// ErrInvalidPacket reports a malformed RADIUS packet. | ErrInvalidPacket 表示 RADIUS 报文格式非法。
	ErrInvalidPacket = errs.New("radius: invalid packet | radius：报文非法")
	// ErrInvalidAttribute reports a malformed attribute or attribute value. | ErrInvalidAttribute 表示属性或属性值格式非法。
	ErrInvalidAttribute = errs.New("radius: invalid attribute | radius：属性非法")
	// ErrInvalidRequest reports malformed caller input. | ErrInvalidRequest 表示调用方输入非法。
	ErrInvalidRequest = errs.New("radius: invalid request | radius：请求非法")
	// ErrInvalidResponse reports a response that failed structural validation. | ErrInvalidResponse 表示响应未通过结构校验。
	ErrInvalidResponse = errs.New("radius: invalid response | radius：响应非法")
	// ErrAuthenticator reports an authenticator mismatch. UDP clients silently discard a
	// mismatching response and keep waiting, as RFC 2865 sections 4.2 and 4.4 require; the
	// sentinel is returned by explicit verification helpers, by stream transports that must close
	// the connection (RFC 6613 section 2.6.4), and by server-side request validation. |
	// ErrAuthenticator 表示认证符不匹配。UDP 客户端按 RFC 2865 第 4.2 与 4.4 节要求静默丢弃不匹配
	// 的响应并继续等待；该哨兵由显式校验辅助函数、必须关闭连接的流传输（RFC 6613 第 2.6.4 节）
	// 以及服务端请求校验返回。
	ErrAuthenticator = errs.New("radius: authenticator mismatch | radius：认证符不匹配")
	// ErrMessageAuthenticator reports a Message-Authenticator mismatch or a missing required one. | ErrMessageAuthenticator 表示 Message-Authenticator 不匹配或缺少必需值。
	ErrMessageAuthenticator = errs.New("radius: message authenticator mismatch | radius：消息认证符不匹配")
	// ErrUnexpectedCode reports a packet code that does not answer the request. | ErrUnexpectedCode 表示报文类型与请求不匹配。
	ErrUnexpectedCode = errs.New("radius: unexpected packet code | radius：报文类型不符")
	// ErrUnexpectedIdentifier reports a response carrying an identifier other than the current
	// attempt's. | ErrUnexpectedIdentifier 表示响应的标识符与当前尝试不一致。
	ErrUnexpectedIdentifier = errs.New("radius: identifier mismatch | radius：标识符不匹配")
	// ErrCoANAK reports a CoA-NAK response. The returned response carries the optional Error-Cause.
	// | ErrCoANAK 表示收到 CoA-NAK 响应。返回的响应携带可选的 Error-Cause。
	ErrCoANAK = errs.New("radius: change of authorization rejected | radius：授权变更被拒绝")
	// ErrDisconnectNAK reports a Disconnect-NAK response. The returned response carries the optional
	// Error-Cause. | ErrDisconnectNAK 表示收到 Disconnect-NAK 响应。返回的响应携带可选的
	// Error-Cause。
	ErrDisconnectNAK = errs.New("radius: disconnect rejected | radius：断开请求被拒绝")
	// ErrCanceled reports a request canceled through its context. | ErrCanceled 表示请求被上下文取消。
	ErrCanceled = errs.New("radius: request canceled | radius：请求已取消")
	// ErrTimeout reports that no response arrived before the retry budget was exhausted. | ErrTimeout 表示重试预算耗尽前未收到响应。
	ErrTimeout = errs.New("radius: no response from server | radius：服务器无响应")
	// ErrNetwork reports a transport failure such as a refused connection. | ErrNetwork 表示连接被拒绝等传输故障。
	ErrNetwork = errs.New("radius: network failure | radius：网络故障")
	// ErrClosed reports use of a client after Close. | ErrClosed 表示在 Close 之后使用客户端。
	ErrClosed = errs.New("radius: client closed | radius：客户端已关闭")
	// ErrServerClosed reports use of an AccessServer, AccountingServer or DynamicServer after Close.
	// | ErrServerClosed 表示在 Close 之后使用 AccessServer、AccountingServer 或 DynamicServer。
	ErrServerClosed = errs.New("radius: server closed | radius：服务器已关闭")
	// ErrDuplicateAttribute reports a dictionary registration conflict. | ErrDuplicateAttribute 表示字典注册冲突。
	ErrDuplicateAttribute = errs.New("radius: duplicate attribute registration | radius：属性注册重复")
	// ErrInternal reports an unexpected internal failure such as a random source error. | ErrInternal 表示随机源错误等内部故障。
	ErrInternal = errs.New("radius: internal error | radius：内部错误")
	// ErrEAPState reports an unknown, expired or already consumed EAP or MS-CHAPv2 session state. |
	// ErrEAPState 表示未知、过期或已使用的 EAP 或 MS-CHAPv2 会话状态。
	ErrEAPState = errs.New("radius: EAP state is unknown or expired | radius：EAP 状态未知或已过期")
	// ErrEAPUnknownUser reports that an EAP password lookup found no user. | ErrEAPUnknownUser 表示
	// EAP 口令查找未找到用户。
	ErrEAPUnknownUser = errs.New("radius: EAP user is unknown | radius：EAP 用户未知")
	// ErrEAPMethod reports an unsupported or unexpected EAP method for a session. | ErrEAPMethod 表示
	// 会话收到不支持或不符合预期的 EAP 方法。
	ErrEAPMethod = errs.New("radius: unsupported EAP method | radius：不支持的 EAP 方法")
	// ErrRelayLoop reports that a relayed request's Proxy-State indicates a forwarding loop or too
	// many hops. | ErrRelayLoop 表示中继请求的 Proxy-State 表明存在转发循环或跳数过多。
	ErrRelayLoop = errs.New("radius: relay loop detected | radius：检测到中继循环")
	// ErrNoUpstream reports that every configured relay upstream failed. | ErrNoUpstream 表示所有已
	// 配置的中继上游均失败。
	ErrNoUpstream = errs.New("radius: no relay upstream is available | radius：无可用中继上游")
)

// ClientConfig configures a Client. | ClientConfig 配置 Client。
type ClientConfig struct {
	// Dictionary resolves attribute names and enumerated values; nil selects a fresh built-in
	// dictionary. | Dictionary 解析属性名与枚举值；nil 选择一份新的内置字典。
	Dictionary *Dictionary
	// TLSConfig configures RADIUS over TLS. When nil, the system roots are used, the server name
	// is derived from Address and TLS 1.2 is the minimum version. | TLSConfig 配置 RADIUS over
	// TLS。为 nil 时使用系统根证书，服务器名取自 Address，最低版本为 TLS 1.2。
	TLSConfig *tls.Config
	// Network selects the transport: "udp" (the default), "udp4", "udp6", "tcp", "tcp4",
	// "tcp6", "tls", "tls4" or "tls6". TCP and TLS follow RFC 6613 and RFC 6614. | Network
	// 选择传输："udp"（默认）、"udp4"、"udp6"、"tcp"、"tcp4"、"tcp6"、"tls"、"tls4" 或 "tls6"。
	// TCP 与 TLS 遵循 RFC 6613 与 RFC 6614。
	Network string
	// Address is the server "host:port". When the port is omitted, 1812 is used for access
	// requests, 1813 for accounting requests and 3799 for RFC 5176 CoA and Disconnect requests over
	// UDP; TCP and TLS default to 2083. | Address 是服务器 "host:port"。省略端口时，UDP 的访问
	// 请求使用 1812、计费请求使用 1813、RFC 5176 CoA 与断开请求使用 3799；TCP 与 TLS 默认使用
	// 2083。
	Address string
	// NASIdentifier is the default NAS-Identifier attribute value. | NASIdentifier 是默认的 NAS-Identifier 属性值。
	NASIdentifier string
	// Secret is the shared secret used to authenticate and encrypt packets. The client copies it
	// and zeroes its copy in Close; the caller remains responsible for its own slice. | Secret
	// 是用于认证与加密报文的共享密钥。客户端会复制它并在 Close 时清零副本；调用方仍需自行清零
	// 自己的切片。
	Secret []byte
	// NASIPAddress is the default NAS-IP-Address attribute value and must be IPv4. | NASIPAddress
	// 是默认的 NAS-IP-Address 属性值，必须是 IPv4 地址。
	NASIPAddress net.IP
	// SourceIP binds outgoing sockets to a local address. | SourceIP 将出站套接字绑定到本地地址。
	SourceIP net.IP
	// Timeout is the base timeout of one transmission attempt; zero selects DefaultTimeout. Each
	// retransmission doubles the wait, up to eight times the base. | Timeout 是单次传输尝试的基础
	// 超时；零值选择 DefaultTimeout。每次重传将等待时间翻倍，最多为基础值的八倍。
	Timeout time.Duration
	// Retries is the number of retransmissions after the initial attempt. Negative values are
	// treated as zero. Access and accounting retransmissions use a fresh Identifier and request
	// authenticator. RFC 5176 CoA and Disconnect retransmissions are byte-identical, and their UDP
	// attempts reuse one local socket and therefore one source port, as RFC 5176 section 3.6
	// requires, so a DynamicServer's duplicate cache recognizes them. | Retries 是首次尝试之后的
	// 重传次数。负值按零处理。访问与计费重传使用新的 Identifier 与请求认证符。RFC 5176 CoA 与
	// 断开重传字节完全相同，其 UDP 各次尝试复用同一个本地套接字，因此源端口不变，符合 RFC 5176
	// 第 3.6 节要求，DynamicServer 的重复缓存可识别这些重传。
	Retries int
}

// Client is a concurrency-safe RADIUS client. | Client 是并发安全的 RADIUS 客户端。
//
// A Client may be shared by any number of goroutines. Each request uses its own transport
// connection, so responses cannot leak between concurrent callers. Close zeroes the shared
// secret copy and rejects further requests. | Client 可被任意数量的 goroutine 共享。每个请求使用
// 独立的传输连接，因此并发调用之间不会串扰响应。Close 会清零共享密钥副本并拒绝后续请求。
type Client struct {
	cfg        ClientConfig
	dictionary *Dictionary
	secret     []byte
	mu         sync.RWMutex
	nextID     atomic.Uint32
	closed     bool
}

// NewClient validates cfg and returns a client. | NewClient 校验 cfg 并返回客户端。
func NewClient(cfg ClientConfig) (*Client, error) {
	network, err := normalizeNetwork(cfg.Network)
	if err != nil {
		return nil, err
	}
	cfg.Network = network
	if strings.TrimSpace(cfg.Address) == "" {
		return nil, errs.Detail(ErrInvalidConfig, "address is required")
	}
	if len(cfg.Secret) == 0 {
		return nil, errs.Detail(ErrInvalidConfig, "shared secret is required")
	}
	if cfg.Timeout < 0 {
		return nil, errs.Detail(ErrInvalidConfig, "timeout must not be negative")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Retries < 0 {
		cfg.Retries = 0
	}
	if cfg.NASIPAddress != nil && cfg.NASIPAddress.To4() == nil {
		return nil, errs.Detail(ErrInvalidConfig, "NAS-IP-Address must be IPv4")
	}
	if cfg.SourceIP != nil && cfg.SourceIP.To16() == nil {
		return nil, errs.Detail(ErrInvalidConfig, "source IP is not a valid IP address")
	}
	if cfg.Dictionary == nil {
		cfg.Dictionary = NewBuiltinDictionary()
	}
	if cfg.TLSConfig != nil {
		cfg.TLSConfig = cfg.TLSConfig.Clone()
	}
	if cfg.NASIPAddress != nil {
		cfg.NASIPAddress = append(net.IP(nil), cfg.NASIPAddress...)
	}
	if cfg.SourceIP != nil {
		cfg.SourceIP = append(net.IP(nil), cfg.SourceIP...)
	}

	secret := append([]byte(nil), cfg.Secret...)
	// Drop the caller's slice from the stored configuration so only the zeroizable copy remains.
	// | 从保存的配置中移除调用方切片，只保留可清零的副本。
	cfg.Secret = nil
	c := &Client{
		cfg:        cfg,
		secret:     secret,
		dictionary: cfg.Dictionary,
	}
	var seed [4]byte
	if _, err := rand.Read(seed[:]); err != nil {
		zeroBytes(c.secret)
		return nil, errs.Wrap(err, ErrInternal)
	}
	c.nextID.Store(binary.BigEndian.Uint32(seed[:]))
	return c, nil
}

// Close zeroizes the client's copy of the shared secret and marks the client closed. Subsequent
// requests return ErrClosed. Close is idempotent and safe for concurrent use. | Close 清零客户端
// 的共享密钥副本并将客户端标记为已关闭。后续请求返回 ErrClosed。Close 幂等且可并发调用。
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	zeroBytes(c.secret)
	c.secret = nil
	c.closed = true
	return nil
}

// Dictionary returns the dictionary used by the client. | Dictionary 返回客户端使用的字典。
func (c *Client) Dictionary() *Dictionary {
	return c.dictionary
}

// nextIdentifier returns a fresh packet identifier. | nextIdentifier 返回新的报文标识符。
func (c *Client) nextIdentifier() uint8 {
	return uint8(c.nextID.Add(1))
}

// checkClosed reports ErrClosed once Close has run. | checkClosed 在 Close 执行后返回 ErrClosed。
func (c *Client) checkClosed() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return ErrClosed
	}
	return nil
}

// secretSnapshot returns a zeroable copy of the shared secret. | secretSnapshot 返回可清零的共享密钥副本。
func (c *Client) secretSnapshot() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return nil, ErrClosed
	}
	out := make([]byte, len(c.secret))
	copy(out, c.secret)
	return out, nil
}

// zeroBytes overwrites b with zeros. | zeroBytes 用零覆盖 b。
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// normalizeNetwork validates and canonicalizes a transport name. | normalizeNetwork 校验并规范化传输名称。
func normalizeNetwork(network string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(network))
	if n == "" {
		return NetworkUDP, nil
	}
	switch n {
	case "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6", "tls", "tls4", "tls6":
		return n, nil
	default:
		return "", errs.Detail(ErrInvalidConfig, "unsupported network %q", network)
	}
}
