// Package kerberos implements a pure-Go Kerberos V5 (RFC 4120) client, KDC
// transport, keytab handling, GSSAPI/SPNEGO initiator and acceptor. It is the
// authentication engine behind the LDAP SASL GSSAPI bind and never imports a
// third-party Kerberos or GSSAPI library. | Package kerberos 实现纯 Go 的 Kerberos V5
// （RFC 4120）客户端、KDC 传输、keytab 处理、GSSAPI/SPNEGO 发起方与接受方。它是 LDAP
// SASL GSSAPI 绑定背后的认证引擎，且绝不引入第三方 Kerberos 或 GSSAPI 库。
//
// # Protocol coverage | 协议覆盖
//
// The package encodes and decodes AS-REQ/AS-REP, TGS-REQ/TGS-REP, AP-REQ/AP-REP and
// KRB-ERROR with APPLICATION tags 10 through 15 and 30, including Ticket,
// EncryptedData, PrincipalName, HostAddress, KerberosTime, EncryptionKey,
// KDCOptions, LastReq, TransitedEncoding and PA data. PA-ENC-TIMESTAMP and
// PA-TGS-REQ pre-authentication are implemented. Client.Login performs the AS
// exchange, answers a KDC pre-authentication challenge (KRB-ERROR 25) with
// PA-ENC-TIMESTAMP, negotiates enctype and kvno against password or keytab
// credentials, and validates the returned ticket, identity and times.
// Client.GetServiceTicket obtains a service ticket for a service principal. | 本包
// 编解码带 APPLICATION 标签 10 至 15 与 30 的 AS-REQ/AS-REP、TGS-REQ/TGS-REP、AP-REQ/AP-REP
// 与 KRB-ERROR，包括 Ticket、EncryptedData、PrincipalName、HostAddress、KerberosTime、
// EncryptionKey、KDCOptions、LastReq、TransitedEncoding 与 PA 数据。实现了
// PA-ENC-TIMESTAMP 与 PA-TGS-REQ 预认证。Client.Login 执行 AS 交换，用
// PA-ENC-TIMESTAMP 应答 KDC 预认证挑战（KRB-ERROR 25），针对口令或 keytab 凭据协商
// enctype 与 kvno，并校验返回票据、身份与时间。Client.GetServiceTicket 为服务主体获取服务票据。
//
// # Cryptography | 加密
//
// aes128-cts-hmac-sha1-96 (17), aes256-cts-hmac-sha1-96 (18) and rc4-hmac (23) are
// supported end to end: RFC 3961 n-fold, RFC 3962 string2key with PBKDF2-HMAC-SHA1,
// key derivation, AES-CTS, HMAC-SHA1-96, and RFC 4757 RC4-HMAC with usage
// translation. Keytab files use the MIT 0x0502 format and honor kvno, enctype and
// duplicate entries. | 端到端支持 aes128-cts-hmac-sha1-96 (17)、
// aes256-cts-hmac-sha1-96 (18) 与 rc4-hmac (23)：RFC 3961 n-fold、带
// PBKDF2-HMAC-SHA1 的 RFC 3962 string2key、密钥派生、AES-CTS、HMAC-SHA1-96，以及带用途转换的
// RFC 4757 RC4-HMAC。keytab 文件使用 MIT 0x0502 格式，并正确处理 kvno、enctype 与重复条目。
//
// # KDC transport | KDC 传输
//
// Explicit KDC lists, DNS SRV discovery (_kerberos._udp and _kerberos._tcp), UDP
// with automatic TCP fallback on KRB-ERROR 52, TCP preference, per-exchange
// timeouts and retries are supported. KRB-ERROR codes map onto errs sentinels so
// callers can use errors.Is; DiscoverKDCs and DiscoverRealm expose discovery
// separately. | 支持显式 KDC 列表、DNS SRV 发现（_kerberos._udp 与 _kerberos._tcp）、
// UDP 在 KRB-ERROR 52 时自动回退 TCP、优先 TCP、每次交换超时与重试。KRB-ERROR 代码映射为
// errs 哨兵，调用方可使用 errors.Is 判定；DiscoverKDCs 与 DiscoverRealm 单独暴露发现能力。
//
// # GSSAPI and SPNEGO | GSSAPI 与 SPNEGO
//
// NewGSSClient builds an initiator context. InitialToken returns the GSS-framed
// AP-REQ, or a GSS-framed SPNEGO NegTokenInit when SPNEGO is enabled, and Step
// consumes the acceptor response, verifies the AP-REP for mutual authentication,
// and returns SPNEGO mechListMIC and request-mic replies. After completion, Wrap,
// Unwrap, MIC and VerifyMIC provide RFC 4121 per-message protection, falling back
// to RFC 4757 legacy tokens for rc4-hmac. NewAcceptor verifies AP-REQ tokens with a
// keytab, enforces ticket flags, principal, realm, authenticator time window,
// replay cache, GSS checksum and optional RFC 4121 channel bindings, then returns
// an AP-REP and a GSSSession whose Wrap, Unwrap, MIC and VerifyMIC are serialized
// and safe for concurrent request handling. | NewGSSClient 构建发起方上下文。
// InitialToken 返回 GSS 封装的 AP-REQ；启用 SPNEGO 时返回 GSS 封装的 SPNEGO
// NegTokenInit。Step 消费接受方响应，为双向认证校验 AP-REP，并返回 SPNEGO mechListMIC
// 与 request-mic 应答。完成后，Wrap、Unwrap、MIC 与 VerifyMIC 提供 RFC 4121 每条消息保护，
// rc4-hmac 回退到 RFC 4757 传统令牌。NewAcceptor 用 keytab 校验 AP-REQ 令牌，强制票据标志、
// 主体、realm、认证器时间窗口、重放缓存、GSS 校验和与可选的 RFC 4121 通道绑定，然后返回
// AP-REP 与 GSSSession；其 Wrap、Unwrap、MIC 与 VerifyMIC 已串行化，可安全用于并发请求处理。
//
// ChannelBindings is a 16-octet hash. For the SASL tls-server-end-point channel
// binding it is the hash of the TLS server certificate, allowing the acceptor to
// bind the Kerberos context to the TLS connection. Both constructors reject a
// non-empty binding whose length is not 16. | ChannelBindings 是 16 字节哈希。对于
// SASL tls-server-end-point 通道绑定，它是 TLS 服务端证书的哈希，使接受方能把 Kerberos 上下文
// 绑定到 TLS 连接。两个构造器都拒绝长度不为 16 的非空绑定。
//
// # YD router | YD 路由
//
// The package exposes no route of its own; mount the exchange on any handler. | 本包
// 不自带路由；把交换挂到任意处理器上即可。
//
//	client, _ := kerberos.NewClient(kerberos.Config{
//		KDC:        []string{"kdc.example.com:88"},
//		Realm:      "EXAMPLE.COM",
//		Principal:  "alice@EXAMPLE.COM",
//		KeyTabPath: "alice.keytab",
//	})
//	gss, _ := kerberos.NewGSSClient(kerberos.GSSClientOptions{
//		Client:     client,
//		Service:    "ldap/dc1.example.com",
//		MutualAuth: true,
//		SPNEGO:     true,
//	})
//	initial, _ := gss.InitialToken(ctx)
//
//	acceptor, _ := kerberos.NewAcceptor(kerberos.AcceptorOptions{
//		KeyTab:  serviceTab,
//		Service: "HTTP/web.example.com",
//		Realm:   "EXAMPLE.COM",
//	})
//	r := router.New()
//	r.HandleRaw(http.MethodPost, "/api/negotiate", func(w http.ResponseWriter, req *http.Request) {
//		// The caller extracts the Negotiate token from Authorization or a SASL frame.
//		reply, session, err := acceptor.Accept(token)
//		if err != nil {
//			http.Error(w, "authentication failed", http.StatusUnauthorized)
//			return
//		}
//		_ = session // bind session.ClientPrincipal to the request identity
//		if len(reply) != 0 {
//			w.Header().Set("WWW-Authenticate", "Negotiate "+encodeToken(reply))
//		}
//		w.WriteHeader(http.StatusNoContent)
//	})
//
// # Native net/http | 原生 net/http
//
//	mux.HandleFunc("POST /api/negotiate", func(w http.ResponseWriter, req *http.Request) {
//		reply, _, err := acceptor.Accept(token)
//		if err != nil {
//			w.Header().Set("WWW-Authenticate", "Negotiate")
//			http.Error(w, "authentication failed", http.StatusUnauthorized)
//			return
//		}
//		if len(reply) != 0 {
//			w.Header().Set("WWW-Authenticate", "Negotiate "+encodeToken(reply))
//		}
//		w.WriteHeader(http.StatusNoContent)
//	})
//
// Keytab files are loaded with ReadKeyTabFile or parsed with ParseKeyTab; a
// service acceptor normally pins both Service and Realm so a ticket for another
// service in the same realm is rejected. | keytab 文件用 ReadKeyTabFile 加载或用
// ParseKeyTab 解析；服务接受方通常同时固定 Service 与 Realm，从而拒绝同一 realm 中面向其它服务的票据。
//
// # Errors | 错误
//
// Failures are errs sentinels such as ErrInvalidConfig, ErrCredentials, ErrKDCUnavailable,
// ErrKDCTimeout, ErrPreAuthFailed, ErrBadIntegrity, ErrBadKVNO, ErrReplay,
// ErrClockSkew, ErrMutualAuthFailed and ErrSPNEGO. Wrap them with errors.Is and
// errors.As. Error strings never contain passwords or key material. | 失败使用
// errs 哨兵，例如 ErrInvalidConfig、ErrCredentials、ErrKDCUnavailable、ErrKDCTimeout、
// ErrPreAuthFailed、ErrBadIntegrity、ErrBadKVNO、ErrReplay、ErrClockSkew、
// ErrMutualAuthFailed 与 ErrSPNEGO。使用 errors.Is 与 errors.As 判定。错误文案绝不包含口令
// 或密钥材料。
package kerberos
