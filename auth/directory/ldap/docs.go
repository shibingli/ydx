// Package ldap implements a pure-Go LDAPv3 client with Active Directory
// support. It provides BER framing, RFC 4515 filters, RFC 2696 paging,
// RFC 2891 sorting, StartTLS/LDAPS, SASL PLAIN/EXTERNAL/SCRAM/GSS-SPNEGO/NTLM,
// CRUD and extended operations, pooling, and typed Active Directory
// authentication. | ldap 包实现纯 Go 的 LDAPv3 客户端并提供 Active Directory 支持。
// 它提供 BER 分帧、RFC 4515 过滤器、RFC 2696 分页、RFC 2891 排序、StartTLS/LDAPS、
// SASL PLAIN/EXTERNAL/SCRAM/GSS-SPNEGO/NTLM、CRUD 与扩展操作、连接池以及类型化
// Active Directory 认证。
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
// links; it is disabled by default for compatibility. | 连接池通常不做往返即返回空闲连接。
// 把 Config.HealthCheck 设为 HealthCheckWhoAmI 或 HealthCheckRootDSE，即可在
// Config.IdleHealthCheckTimeout 内探测复用的连接；探测失败会丢弃并由 Get 重新拨号。默认关闭
// 探测。设置 Config.RequireSASLPlainTLS 可避免 SASL PLAIN 凭据经过明文链路；为保持兼容默认关闭。
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
// This is an NTLMv2 client only. Kerberos/GSSAPI is a separate protocol and is
// not implemented by this package. | 本包仅实现 NTLMv2 客户端。Kerberos/GSSAPI 是
// 独立协议，本包未实现。
package ldap
