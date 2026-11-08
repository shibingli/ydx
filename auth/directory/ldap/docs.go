// Package ldap implements a pure-Go LDAPv3 client with Active Directory
// support. It provides BER framing, RFC 4515 filters, RFC 2696 paging,
// RFC 2891 sorting, StartTLS/LDAPS, SASL PLAIN/EXTERNAL/SCRAM/GSS-SPNEGO/NTLM,
// RFC 4752 GSSAPI authentication with Kerberos, CRUD and extended operations,
// pooling, and typed Active Directory authentication. | ldap 包实现纯 Go 的 LDAPv3
// 客户端并提供 Active Directory 支持。它提供 BER 分帧、RFC 4515 过滤器、RFC 2696 分页、
// RFC 2891 排序、StartTLS/LDAPS、SASL PLAIN/EXTERNAL/SCRAM/GSS-SPNEGO/NTLM、基于
// Kerberos 的 RFC 4752 GSSAPI 认证、CRUD 与扩展操作、连接池以及类型化 Active Directory 认证。
//
// The client never follows referrals automatically. Install a ReferralHandler
// or inspect SearchResult.Referrals and apply an application-specific policy.
// | 客户端绝不自动跟随转介。请安装 ReferralHandler，或检查 SearchResult.Referrals
// 并按应用策略处理。
//
// Basic native Go usage: | 原生 Go 基本用法：
//
//	client, err := ldap.DialURL(ctx, "ldaps://dc1.example.com")
//	if err != nil {
//		return err
//	}
//	defer client.Close()
//
//	entries, err := client.SearchEntries(ctx, ldap.SearchOptions{
//		BaseDN: "dc=example,dc=com",
//		Scope:  ldap.ScopeWholeSubtree,
//		Filter: ldap.And(
//			ldap.Equal("objectClass", "person"),
//			ldap.Equal("uid", "alice"),
//		),
//		Attributes: []string{"dn", "cn", "mail"},
//	})
//
// Active Directory password authentication: | Active Directory 口令认证：
//
//	ad, err := ldap.NewActiveDirectory(ctx, ldap.ADConfig{
//		Domain:       "example.com",
//		URL:          "ldaps://dc1.example.com",
//		BindDN:       "cn=svc,ou=services,dc=example,dc=com",
//		BindPassword: servicePassword,
//	})
//	if err != nil {
//		return err
//	}
//	defer ad.Close()
//
//	user, err := ad.Authenticate(ctx, `EXAMPLE\alice`, password)
//	if err != nil {
//		return err
//	}
//	if user.Disabled || user.Locked || user.PasswordExpired {
//		// Apply the account policy. | 应用账号策略。
//	}
//
// With a YD or net/http service, create the client during startup, share it
// through a Pool for parallel requests, and close the pool on shutdown. | 在 YD 或
// net/http 服务中，于启动期创建客户端，通过 Pool 共享给并行请求，并在关闭时关闭连接池。
//
// A Pool normally returns idle connections without a round trip. Set
// Config.HealthCheck to HealthCheckWhoAmI or HealthCheckRootDSE to probe a
// reused connection within Config.IdleHealthCheckTimeout; a failed probe is
// discarded and Get dials a replacement. Probing is disabled by default. Set
// Config.RequireSASLPlainTLS to keep SASL PLAIN credentials off cleartext
// links, and Config.RequireSimpleBindTLS to keep simple-bind passwords off
// them; both cover the automatic replay after a reconnect and are disabled by
// default for compatibility. | 连接池通常不做往返即返回空闲连接。
// 把 Config.HealthCheck 设为 HealthCheckWhoAmI 或 HealthCheckRootDSE，即可在
// Config.IdleHealthCheckTimeout 内探测复用的连接；探测失败会丢弃并由 Get 重新拨号。默认关闭
// 探测。设置 Config.RequireSASLPlainTLS 可避免 SASL PLAIN 凭据经过明文链路，设置
// Config.RequireSimpleBindTLS 可避免简单绑定口令经过明文链路；两者都覆盖重连后的自动重放，
// 为保持兼容默认关闭。
//
// NTLMv2 SASL authentication over LDAPS, using the peer certificate for
// tls-server-end-point channel binding: | 通过 LDAPS 使用对端证书进行
// tls-server-end-point 通道绑定的 NTLMv2 SASL 认证：
//
//	client, err := ldap.DialURL(ctx, "ldaps://dc1.example.com")
//	if err != nil {
//		return err
//	}
//	defer client.Close()
//
//	err = client.BindNTLM(ctx, ldap.NTLMOptions{
//		Username:       `EXAMPLE\alice`,
//		Password:       password,
//		ChannelBinding: true,
//	})
//
// BindNTLM uses GSS-SPNEGO by default and negotiates the SPNEGO mechListMIC,
// including servers that send NegStateRequestMIC; set RequireServerMIC to fail
// closed unless the server returns a valid final mechListMIC. The negotiated NTLM
// session key is retained only for MIC verification and is wiped when the
// connection closes or is replaced. LDAP SASL NTLM defines no PDU security
// layer, so this package never signs, seals or encrypts LDAP messages with NTLM.
// | BindNTLM 默认使用 GSS-SPNEGO 并协商 SPNEGO mechListMIC（包括发送
// NegStateRequestMIC 的服务端）；设置 RequireServerMIC 可在服务端未返回有效最终
// mechListMIC 时失败关闭。协商出的 NTLM 会话密钥仅用于 MIC 校验，并在连接关闭或被替换时
// 清零。LDAP SASL NTLM 不定义 PDU 安全层，因此本包绝不用 NTLM 对 LDAP 消息签名、密封或加密。
//
// Kerberos GSSAPI SASL authentication, optionally wrapped in SPNEGO and bound
// to the TLS server certificate with tls-server-end-point channel binding: |
// Kerberos GSSAPI SASL 认证，可选包装为 SPNEGO，并使用 tls-server-end-point 通道绑定
// 到 TLS 服务端证书：
//
//	krb, err := kerberos.NewClient(kerberos.Config{
//		Realm:     "EXAMPLE.COM",
//		Principal: "alice@EXAMPLE.COM",
//		KeyTabPath: keytabPath,
//	})
//	if err != nil {
//		return err
//	}
//	client, err := ldap.DialURL(ctx, "ldaps://dc1.example.com")
//	if err != nil {
//		return err
//	}
//	defer client.Close()
//
//	err = client.BindSASLGSSAPI(ctx, ldap.GSSAPIOptions{
//		Client:         krb,
//		Service:        "ldap/dc1.example.com",
//		ServiceRealm:   "EXAMPLE.COM",
//		AuthzID:        "u:alice@example.com",
//		SPNEGO:         true,
//		ChannelBinding: true,
//	})
//
// The GSSAPI bind always requires mutual authentication and negotiates the
// RFC 4752 no-security-layer option; a server that selects integrity or
// confidentiality is rejected because this client does not wrap subsequent
// LDAP messages. Set Config.GSSAPI to make every new connection, including a
// replay after a reconnect, authenticate the same way. | GSSAPI 绑定始终要求
// 双向认证，并协商 RFC 4752 无安全层选项；选择完整性或机密性层的服务端会被拒绝，因为
// 本客户端不封装后续 LDAP 消息。设置 Config.GSSAPI 可让每条新连接（包括重连后的重放）
// 以相同方式认证。
package ldap
