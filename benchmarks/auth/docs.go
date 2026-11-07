// Package auth contains the authentication and authorization benchmarks that live outside the
// component module, so github.com/shibingli/ydx/auth never depends on benchmark-only code or
// comparison libraries. | Package auth 保存位于组件模块之外的认证与授权基准，使
// github.com/shibingli/ydx/auth 不依赖基准专用代码或对比库。
//
// The comparisons cover JOSE/JWS, OTP, RBAC, LDAP filters, XML signatures and SAML interoperability
// against go-jose, jwx, pquerna/otp, casbin, go-ldap, goxmldsig and crewjam/saml. See README.md for
// the measured tables and methodology. | 对比覆盖 JOSE/JWS、OTP、RBAC、LDAP 过滤器、XML 签名与
// SAML 互操作，对象包括 go-jose、jwx、pquerna/otp、casbin、go-ldap、goxmldsig 与 crewjam/saml。
// 实测表与方法见 README.md。
//
// Run with | 运行方式：
//
//	cd benchmarks/auth
//	GOWORK=off go test -run '^$' -bench . -benchmem
package auth
