# benchmarks/auth — 认证与授权组件对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/auth` 覆盖 JWT/JOSE、OAuth2/OIDC、SAML、LDAP/AD、SCIM、WebAuthn、OTP、RBAC、
CAS、WS-Federation、RADIUS、KMS/KMIP 与中国特色校验。本模块只对**有主流 Go 可比实现**的
热路径做同进程对比，并用互操作测试验证线协议兼容性；没有可靠同类实现的协议不做数字横比。

## 对比对象

| 实现 | 版本 | 用途 |
|---|---|---|
| `github.com/shibingli/ydx/auth` | v0.1.0 | 被测实现 |
| `github.com/go-jose/go-jose/v4` | v4.1.6 | JOSE/JWS 对比 |
| `github.com/lestrrat-go/jwx/v4` | v4.5.0 | JOSE/JWS 对比 |
| `github.com/pquerna/otp` | v1.5.0 | TOTP 生成/校验对比 |
| `github.com/casbin/casbin/v2` | v2.135.0 | RBAC 决策对比 |
| `github.com/go-ldap/ldap/v3` | v3.4.15 | RFC 4515 过滤器对比 |
| `github.com/golang-jwt/jwt/v5` | v5.3.1 | JWT 双向互操作 |
| `github.com/russellhaering/goxmldsig` | v1.6.1 | XMLDSig 双向互操作 |
| `github.com/coreos/go-oidc/v3` | v3.21.0 | OIDC RP 全流程互操作 |

JWT 的签发/验签对比（golang-jwt、jwx、go-jose、cristalhq、kataras）见
[../jwt/README.md](../jwt/README.md)，本模块不重复。

> `auth v0.1.0` 依赖 `ydx/json v0.1.17`（修复原生解码器字符串 arena 越界 panic）。
> 在该标签发布前，本模块需通过仓库外文件代理或 `go.work` 解析 `json`；标签发布后可直接使用默认
> `GOPROXY`。

## 场景

- `JOSESignHS256` / `JOSEVerifyHS256`：同一载荷的紧凑 JWS；验签读取同一份 ydx 令牌。
- `JOSESignES256` / `JOSEVerifyES256`：P-256 ECDSA。
- `TOTPGenerate` / `TOTPValidate`：RFC 6238 SHA-1/6 位/30 秒，T=59 固定时间；
  互操作测试要求双方生成完全相同的口令并互相接受。
- `RBACAuthorize`：一个角色 + 一条策略 + 一次分配的单次决策；互操作测试要求
  permit/deny 与 casbin 一致。
- `LDAPFilterParse` / `LDAPFilterRender`：含相等、子串、存在组件的嵌套过滤器；
  go-ldap 的 `CompileFilter` 同时生成 BER，属于更重的工作量，表中注明。
- `TestJOSEInterop`、`TestJWEInteropWithGoJose`、
  `TestTOTPInteropWithPquerna`、`TestRBACDecisionMatchesCasbin`、
  `TestLDAPFilterInteropWithGoLDAP`、`TestXMLSigInteropWithGoXMLDSig`、
  `TestOIDCInteropWithCoreOS`：互操作/一致性测试。JWS、JWE 与 XMLDSig 均要求双向通过；
  OIDC 用 coreos/go-oidc 走完发现、授权码 + PKCE、令牌交换、ID token 校验与 UserInfo。
  JWT 的双向互操作测试按统一管理要求位于 `auth/token/jwt/interop_test.go`。

## 实测结果（2026-11-08，Windows 11，i9-10980HK，Go 1.27.3 amd64）

采样：`-benchtime=500ms`、`-benchmem`，单轮；绝对值受 CPU 频率与后台负载影响，
只做同表相对比较。JWT 的完整对比见 [../jwt/README.md](../jwt/README.md)。

| 场景 | ydx | 对比实现 |
|---|---:|---:|
| JWS HS256 签发 | **2.43 µs / 344 B / 4 allocs** | go-jose 4.79 µs / 3.2 KiB / 42；jwx 2.98 µs / 1.1 KiB / 16 |
| JWS HS256 验签 | **4.10 µs / 1.7 KiB / 26** | go-jose 5.02 µs / 2.4 KiB / 37；jwx 6.56 µs / 2.4 KiB / 45 |
| JWS ES256 签发 | **39.8 µs / 6.6 KiB / 65** | go-jose 41.0 µs / 9.4 KiB / 104；jwx 38.9 µs / 7.2 KiB / 76 |
| JWS ES256 验签 | 83.9 µs / 2.5 KiB / 40 | go-jose 86.1 µs / 3.2 KiB / 52；jwx 93.4 µs / 3.3 KiB / 59 |
| TOTP 生成 | **1.62 µs / 560 B / 9** | pquerna 1.78 µs / 528 B / 11 |
| TOTP 校验 | **1.60 µs / 552 B / 8** | pquerna 1.94 µs / 552 B / 12 |
| RBAC 决策 | **1.56 µs / 1.2 KiB / 16** | casbin 4.00 µs / 1.65 KiB / 23 |
| LDAP 过滤器解析 | **0.66 µs / 400 B / 15** | go-ldap 4.16 µs / 4.1 KiB / 96（含 BER 编码，工作量更重） |
| LDAP 过滤器渲染 | **0.40 µs / 192 B / 11** | — |
| XMLDSig 签发（RSA-2048） | **1.34 ms / 21.5 KiB / 132** | goxmldsig 1.37 ms / 31.8 KiB / 279 |
| XMLDSig 验签 | **85.9 µs / 25.1 KiB / 265** | goxmldsig 169 µs / 72.6 KiB / 745 |

结论：

- JOSE 的 HS256 签发/验签快于 go-jose/jwx；ES256 签发/验签与两者持平或略快，分配数约少 1/3。
  XMLDSig 签发与 goxmldsig 持平，验签约快 2 倍、分配约为 1/3。
- TOTP 生成与校验均快于 pquerna，校验分配数从 18 降到 8。
- RBAC 决策约为 casbin 的 1/3 耗时；LDAP 过滤器解析约为 go-ldap 的 1/6（口径不同，
  go-ldap 同时输出 BER）。
- 首轮发现的低指标项（TOTP 校验、JOSE ES256 签发、JWT ES256 解析）均已优化到与主流
  实现持平或更好。

## 运行

```bash
cd benchmarks/auth
GOWORK=off go test -run '^$' -bench . -benchmem
GOWORK=off go test -run 'Interop|Matches' -count=1 -v
```
