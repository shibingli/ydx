# auth — 认证与权限工具集

`github.com/shibingli/ydx/auth` 是 ydx 的认证与权限工具集。它以**一个独立模块 + 多个协议子包**
的形式提供身份、凭据、会话、账号生命周期，以及 OAuth 2.1、OpenID Connect、SAML 2.0、LDAP/AD、
SCIM 2.0、WebAuthn、TOTP/HOTP、RBAC/ABAC、CAS、联邦登录与 RADIUS。所有实现均为纯 Go、无 cgo，
不依赖任何第三方认证框架；JSON、Base64、XML、JWT 分别复用 `ydx/json`、`ydx/base64`、`ydx/xml`、
`auth/token/jwt`。

## 目录规范

`auth` 按领域分组，**不允许新增平铺子包**：

| 领域目录 | 用途 | 当前包 |
|---|---|---|
| `auth/token/` | 令牌格式与 JOSE | `jwt`、`jose` |
| `auth/protocol/` | 认证/SSO 线协议 | `oauth2`、`oidc`、`saml`、`cas`、`wsfed`、`federation`、`radius` |
| `auth/directory/` | 目录服务、预配与 AD 认证 | `ldap`、`scim`、`ntlm` |
| `auth/mfa/` | 多因素认证 | `otp`、`webauthn` |
| `auth/authz/` | 授权模型 | `rbac` |
| `auth/keymgmt/` | 密钥管理 | `kms`、`kmip` |
| `auth/crypto/` | 密码学格式与算法封装 | `xmlsig` |
| `auth/identity/` | 身份数据与本地化校验 | `cn` |

新包必须放在对应领域目录下，目录名等于包名，并带有同名主文件（如
`auth/protocol/saml/saml.go`）；`repotest` 会强制校验该布局。

## 包索引

| 包 | 职责 | 主要标准 |
|---|---|---|
| `auth` | 用户、主体、身份关联、会话、密码策略、审计、账号生命周期 | NIST SP 800-63B 口令与认证建议 |
| `auth/token/jwt` | JWT 签发、验签、中间件（原根目录 `jwt` 模块迁入）、iat/多 issuer/多 audience、low-S | RFC 7515/7518/7519、RFC 7797 |
| `auth/token/jose` | JWK/JWKS、JWS、JWE、密钥缓存与远程 JWKS、JWS/JWE JSON/Flattened、多签名、detached、b64=false | RFC 7515-7519、7638、7797、3394、8037 |
| `auth/protocol/oauth2` | 授权服务器与客户端、令牌、自省、撤销、PAR、设备码、令牌交换、DPoP/DPoP nonce、mTLS、client_secret_jwt、RFC 9101 请求对象 | RFC 6749/6750/7009/7523/7636/7662/8414/8628/8693/8705/8707/9068/9101/9126/9207/9449 |
| `auth/protocol/oidc` | OpenID Provider、Discovery、UserInfo、动态注册、登出、会话管理、RP、JARM | OpenID Connect Core 1.0、Discovery 1.0、Registration 1.0、RP-Initiated/Front/Back-Channel Logout、Session Management、JARM |
| `auth/crypto/xmlsig` | XML C14N、XMLDSig、XML Encryption、SM2/SM3/SM4 | W3C C14N 1.0/1.1、XMLDSig 1.1、XML Encryption 1.1、GM/T |
| `auth/protocol/saml` | SAML 2.0 IdP/SP、Metadata、SSO/SLO、POST/Redirect/Artifact 绑定、SOAP 1.2、ARS failover、OneTimeUse 重放存储 | SAML 2.0 Core/Profiles/Bindings/Metadata |
| `auth/directory/ldap` | 纯 Go LDAP v3 客户端、过滤器、分页、StartTLS、SASL（PLAIN/EXTERNAL/SCRAM/GSS-SPNEGO NTLMv2/GSSAPI Kerberos）、连接池健康探测、AD 辅助 | RFC 4511/4515/2696/2891/3062/4120/4532/4752/5802/7677、AD 兼容 |
| `auth/directory/ntlm` | NTLMSSP Type 1/2/3、NTLMv2/LMv2、完整 SPNEGO、mechListMIC、SIGN/SEAL、AV pairs、channel binding、Acceptor | MS-NLMP、RFC 4178 |
| `auth/mfa/webauthn` | WebAuthn Level 2/3、Passkeys、CBOR/COSE、attestation、SafetyNet/AndroidKey/TPM 策略、TPM EK activation、计数器策略与信任根 | W3C WebAuthn L2/L3、RFC 8949、TPM 2.0 |
| `auth/directory/scim` | SCIM 2.0 服务端/客户端、过滤、PATCH、Bulk（原子回滚）、ETag、两阶段口令预配 | RFC 7643/7644 |
| `auth/mfa/otp` | HOTP/TOTP、otpauth URI、恢复码、重放保护、Steam Guard | RFC 4226/6238 |
| `auth/authz/rbac` | RBAC + ABAC 策略引擎、角色继承、条件、组合算法、中间件 | 无单独 RFC；模型对齐 NIST RBAC/ABAC |
| `auth/protocol/cas` | CAS 1.0/2.0/3.0 服务端与客户端、TGT/ST/PGT/PT、代理链路、3.0 JSON 视图、后端/前端单点登出、LogoutRequest XML 签名 | Apereo CAS Protocol 1.0/2.0/3.0 |
| `auth/protocol/wsfed` | WS-Federation 被动请求方配置、RP/STS、SAML 1.1/2.0 令牌 | WS-Federation 1.2、WS-Trust 1.3 |
| `auth/protocol/kerberos` | Kerberos V5 客户端/Acceptor、GSSAPI/SPNEGO、keytab、AES128/256-CTS-HMAC-SHA1-96、RC4-HMAC、通道绑定 | RFC 4120/3961/3962/4121/4178/4752/4757 |
| `auth/protocol/federation` | 社交/企业登录经纪、账号关联、JIT 预配、中外提供方预设 | OAuth 2.0/OIDC + 各提供方 API |
| `auth/keymgmt/kms` | 自研 KMS：密钥生命周期、版本/轮换、信封加密、签名、REST API | NIST SP 800-57、JOSE/JWK、GM/T |
| `auth/keymgmt/kmip` | KMIP TTLV 编解码、客户端/服务端、1.4/2.0 版本化负载、JWK 扩展、密钥与对象全生命周期 | OASIS KMIP 1.4/2.0、RFC 7517 |
| `auth/protocol/radius` | RADIUS 客户端/relay-proxy/Access/Accounting 服务端、PAP/CHAP/MS-CHAPv2/EAP-MD5/EAP-MSCHAPv2/EAP-TLS/TTLS/PEAP、Message-Authenticator、RFC 5176 CoA/Disconnect | RFC 2865/2866/2868/2869/3579/3748/5216/5281/5176/6613/6614 |
| `auth/identity/cn` | 大陆手机号、居民身份证、统一社会信用代码、银行卡校验与脱敏、实名认证/短信 OTP 接口 | GB 11643-1999、GB 32100-2015、工信部号段 |

## 快速开始（ydx/router 原生入口）

```go
import (
    "github.com/shibingli/ydx/auth"
    "github.com/shibingli/ydx/auth/protocol/oidc"
    "github.com/shibingli/ydx/auth/protocol/oauth2"
    "github.com/shibingli/ydx/router"
)

stores := auth.NewMemoryStores()
hasher, _ := auth.NewArgon2idHasher(auth.DefaultArgon2idConfig())
svc, _ := auth.New(auth.Config{Stores: stores, Passwords: hasher})

r := router.New()
r.Use(svc.Sessions().Middleware(auth.SessionMiddlewareOptions{RequireSession: true}))

oauthServer, _ := oauth2.NewServer(oauth2.ServerConfig{
    Issuer:  "https://auth.example.com",
    Clients: oauth2.NewMemoryClientStore( /* ... */ ),
    Store:   oauth2.NewMemoryStore(),
    Scopes:  oauth2.DefaultScopes(),
    Authenticator: oauth2.AuthenticatorFunc(func(ctx context.Context, w http.ResponseWriter, req *http.Request, ar *oauth2.AuthorizationRequest) (*auth.Principal, error) {
        // 从 svc 的会话中解析主体；未登录返回 oauth2.ErrLoginRequired。
        return nil, oauth2.ErrLoginRequired
    }),
})
provider, _ := oidc.NewProvider(oidc.ProviderConfig{OAuth: oauthServer, EnableLogout: true})

oauthServer.Register(r)
provider.Register(r)
```

原生 `net/http` 使用同一实现：

```go
mux := http.NewServeMux()
mux.Handle("/", oauthServer.HTTPHandler())
handler := svc.Sessions().HTTPMiddleware(auth.SessionMiddlewareOptions{RequireSession: false})(mux)
```

`auth` 下每个协议服务器的处理器同时具有 `router.HandlerFuncRaw` 与 `http.HandlerFunc` 形状，
因此 `r.HandleRaw(method, path, server.Token)` 可直接挂载，无需适配层；`Register` 只是把一组
端点一次性挂好。

## 统一 SSO 组合

`auth.Service` + `auth.SessionManager` 是各协议的**唯一会话事实来源**；OIDC、SAML 2.0、CAS、
WS-Federation、LDAP/AD 与联邦登录都委托同一个服务完成认证、会话创建、撤销与审计。典型组合：

```go
svc, _ := auth.New(auth.Config{Stores: stores})
r := router.New()

oauthServer.Register(r)          // OAuth 2.1 / OIDC 令牌与授权端点
oidcProvider.Register(r)         // Discovery / JWKS / UserInfo / Logout
samlSP.Register(r, "/sso")       // SAML 2.0 SP
samlIdP.Register(r, "/idp")      // SAML 2.0 IdP
casServer.Register(r, "/cas")    // CAS 1.0/2.0/3.0
wsfedSTS.Register(r, "/wsfed")   // WS-Federation / ADFS
```

所有服务器的 `Authenticator` 都从 `svc` 的会话或登录流程取得主体；会话 Cookie 由
`SessionManager.Middleware` 统一解析。登出时调用 `svc.Sessions().RevokeUser` 即可让所有协议
同时失效（各协议适配器会按需发送 SAML SLO、OIDC Back-Channel Logout 或 CAS 票据清理）。

## 中国特色能力

- `auth/identity/cn`：大陆手机号规范化/号段校验/运营商识别/脱敏，居民身份证 18 位（及 15 位升级）校验、
  出生日期/性别/年龄、统一社会信用代码 MOD 31 校验、银行卡 Luhn、中文姓名与邮箱脱敏、实名认证
  与短信验证码接口。
- `auth/protocol/federation`：微信开放平台/公众号、支付宝、钉钉、飞书、企业微信、QQ、微博、百度、Gitee
  预设，以及 Google、Microsoft Entra ID、GitHub、Apple、Facebook、GitLab、Okta、Auth0、Keycloak。
- `auth/crypto/xmlsig`：XMLDSig/XML Encryption 的 SM2-with-SM3、SM3 摘要、SM4-CBC/GCM 与 SM2 密钥传输，
  用于国密改造后的 SAML/政务对接。
- `auth/directory/ldap`：Active Directory 的 UPN/sAMAccountName/NT4 登录、嵌套组
  `LDAP_MATCHING_RULE_IN_CHAIN`、`userAccountControl`/密码过期/锁定状态解析、DNS SRV 域控发现。
- `auth/protocol/saml`：SAML 2.0 中文 NameID/属性配置、SHA-1 兼容开关（默认关闭）、常见 IdP 的
  clock skew 与 RelayState 兼容处理。

## 安全与运维要点

- 会话 Cookie 默认 `HttpOnly` + `SameSite=Lax`；生产必须开启 `Secure`。
- 授权码默认强制 PKCE（S256）；`plain` 仅显式开启。刷新令牌默认一次性轮换，检测到重放会撤销
  整个令牌家族。
- 访问令牌默认不透明并只存 SHA-256 哈希；JWT 访问令牌使用 RFC 9068 `at+jwt`，并保留撤销记录。
- 密码默认 Argon2id；兼容 bcrypt、scrypt、PBKDF2-SHA256/512，登录成功后自动重哈希。
- 所有审计事件不包含口令、令牌、密钥或完整请求体。
- `UseOIDC` 提供方必须在授权码令牌响应中返回 `id_token`（OIDC Core 3.1.3.3），且 UserInfo 的
  非空 `sub` 必须与已校验 ID 令牌的 `sub` 一致；联邦错误不包含令牌、客户端密钥或提供方响应体。
- 认证/授权拒绝会终止路由链：`RequireAccess`/`RequirePermission` 与 RBAC 中间件在 401/403 时
  Abort；会话只对可登录用户有效，禁用/锁定用户的既有会话失效。MFA 密码阶段挑战一次性、绑定用户，
  并受同一锁定计数约束。
- 口令哈希参数有硬上限（PBKDF2 100k–10M 次；Argon2 内存 ≤256 MiB、time ≤64、threads ≤32；
  scrypt logN ≤20、r ≤32、p ≤16、内存 ≤256 MiB），bcrypt 成本 ≥10；登录重哈希保留
  `PasswordChangedAt`，不会延长口令有效期。
- JWT 默认最大 1 MiB；JWKS 端点始终只发布公开材料并省略对称密钥；`RSA1_5` 必须显式
  `AllowRSA1_5`。OIDC 登出令牌要求 `typ=logout+jwt`，iat 使用 Provider 时钟；可选
  `LogoutReplayStore`/`MemoryLogoutReplayStore` 防 jti 重放（默认关闭）。RFC 9101
  `request`/`request_uri` 与 JARM 已实现；`request_uri` 仅 HTTPS（回环例外）、不跟随重定向、
  防 SSRF、限制大小并可配置单次使用。
- SCIM 请求体上限 4 MiB、bulk 载荷 1 MiB、客户端响应 16 MiB；Bulk 默认非事务，bulkId 只解析完整
  字符串值或完整路径段。`Options.BulkAtomic` 启用逆序补偿回滚（撤销日志上限
  `BulkMaxUndoBytes`），并发 ETag 冲突返回 409，回滚失败返回通用 500 明细且不回滚外部副作用。
  LDAP 过滤器深度上限 64，分页搜索上限 10000 页（`ErrPagingLimit`）。
- RADIUS 响应在请求带 Message-Authenticator 时必须带有效 MA；CoA/Disconnect 使用 3799 端口，
  按 RFC 5176 原样重传。NAS 侧 `DynamicServer` 校验 Request/Message-Authenticator、支持 ACK/NAK
  与 Error-Cause，并用进程内重复请求缓存应答重传。未实现 Access/Accounting 服务端与中继/代理；
  重复缓存单进程，跨实例需共享实现。OTP 重放键默认为密钥 SHA-256 指纹，共享密钥场景使用
  `WithReplayKey`。
- CAS 服务 URL 必须为绝对 http(s) 且无 userinfo；1.0 也执行 renew；`X-Forwarded-Proto` 仅接受
  http/https，边缘必须剥离客户端自带的该头。WebAuthn 默认严格签名计数器，可配置
  `CounterAllowBackupEligibleReset`（仅 BE=1 且 BS=1 时允许回退）或 `CounterAllowAny`；BE 标志
  仍与存储凭据比对。SafetyNet/Android Key 支持配置信任根与自定义 verifier，未配置根时
  `TrustVerified=false`；ECDAA 按 WebAuthn L3 已移除，不实现。
- WS-Fed JWT 签发器必须返回实际到期时间，否则响应需带 `Lifetime.Expires`；内存请求存储仅单进程。
  KMS 静态加密在配置 `RootKey`/`Passphrase`/自定义 `Wrapper` 时启用，`RequireAtRestEncryption`
  可强制要求保护且不会静默生成临时密钥；未配置时按传入材料存储，部署方负责磁盘加密。
  Federation 的 OIDC Discovery 支持 TTL/抖动/最小-最大寿命与 stale-while-revalidate，刷新为请求
  触发（无后台 goroutine）；自定义 `Provider.Adapter` 会绕过内置刷新策略。
- XML 解析接受 UTF-8 BOM，但拒绝 DTD/内部实体与指令；解析边界为 64 MiB、深度 256、节点 100 万。
  XMLDSig 的 RSA-PSS 参数摘要同样受允许列表约束；`xml:base` 修正仅在 inclusive C14N 1.1 下执行，
  排他规范化由方法 URI 决定。SAML HTTP-Redirect 登出消息带签名时必须通过 `RedirectVerifier`，
  未配置校验器会拒绝；仅签名模式由 `RequireSignedLogout`/`WantLogoutRequestsSigned` 控制。
- 多实例部署必须把 `oauth2.Store`、`auth.SessionStore`、`auth.TokenStore`、OTP 重放保护、
  OIDC/SCIM/RBAC 的状态替换为共享实现；内存实现仅用于单进程、测试与嵌入式场景。
- `auth/identity/cn` 只做结构与校验位验证；真实身份核验必须通过 `RealNameVerifier` 调用合规供应商。
  实名与短信的默认 HTTP 客户端拒绝跟随重定向（3xx 按失败处理），避免把 API Key 等静态凭据头转发到
  其它主机；确需重定向的调用方必须显式传入自定义 `http.Client`。

## 依赖

- `golang.org/x/crypto`：bcrypt、scrypt、Argon2id 口令 KDF（仅密码哈希，不是认证框架）。
- `github.com/shibingli/ydx/guomi`：SM2/SM3/SM4 国密算法。
- `github.com/golang-jwt/jwt/v5`：仅用于 `auth/token/jwt/interop_test.go` 的双向互操作测试，
  不出现在任何运行时代码路径，也不被二进制引用。
- 其余仅依赖 ydx 自有模块（`errs`、`json`、`base64`、`xml`、`router`、`log`、`jwt` 已迁入
  `auth/token/jwt`）。`auth` 依赖已发布的 `ydx/json` v0.1.17（修复原生解码器字符串 arena
  越界 panic 与 fast-struct 解码计划缓存污染）。

## KMS 与协议签名

`auth/keymgmt/kms` 管理密钥生命周期、版本、轮换和信封加密，并提供 `ExportKey` 的
JWK/PKCS#8/PKIX 导出策略；OIDC 的 `SigningKey`、SAML 的 `XMLDSigSigner` 与 JWT 的
`JWTAccessTokenIssuer` 都可以使用从 KMS 导出的受控密钥。生产环境建议由 KMS 托管根密钥，
应用只持有短期数据密钥；KMIP 服务端可把同一 `Store` 暴露给外部密钥管理系统。

## 已知边界

- **Kerberos/GSSAPI** 未内置：纯 Go 下实现 Kerberos 与 GSSAPI 需要完整的票据/加密/ASN.1 栈；
  AD 场景可使用 `auth/directory/ldap` 的 **NTLMv2（SASL GSS-SPNEGO/NTLM，支持
  tls-server-end-point channel binding）**，或 LDAP/LDAPS/StartTLS + SASL PLAIN/EXTERNAL/SCRAM。
  真正的 Kerberos SSO 仍需外部 GSSAPI 实现。
- **OIDC 请求对象（RFC 9101）与 JARM** 已实现；request/request_uri 缓存与登出重放存储为进程内
  实现，多实例需替换为共享实现；JARM 响应 TTL 固定 5 分钟；动态注册会拒绝 `alg=none` 与不安全
  request_uri，但不预先校验任意 `request_object_signing_alg`/`authorization_signed_response_alg`
  是否与提供方密钥能力匹配（在请求/签名时失败）。PAR、DPoP、mTLS、前后端登出、会话管理均已实现。
- **SAML 的 XML 签名/加密** 由 `auth/crypto/xmlsig` 通过 `saml.XMLDSigSigner`/`saml.XMLDSigVerifier`
  注入；未注入时只能用于测试或明确接受未签名断言的兼容场景。Artifact 绑定支持 SOAP 1.1 ARS、
  302 `SAMLart` 交付、TTL 与单次使用；无 SOAP 1.2、ARS failover 或跨端点重试，多实例 IdP 需
  配置共享的 20 字节 `ArtifactSourceID` 与共享 `ArtifactStore`。
- **KMS/KMIP** 默认提供内存存储；生产应替换为持久化 `Store`，KMIP 以 TLS/mTLS 为默认传输，
  客户端通过 `kmip.DialContext` + `kmip.Client` 串行调用类型化操作。KMIP 服务端按请求头选择
  1.4/2.0 负载，`Discover Versions` 通告 `[2.0, 1.4]`；2.0 已覆盖 Create、Create Key Pair、
  Register、Get、Get Attributes、Get Attribute List、Activate、Revoke、Destroy、Locate、
  Derive Key、Encrypt/Decrypt、Sign/Signature Verify、MAC/MAC Verify、Wrap/Unwrap、Query、
  Discover Versions 与 Check 的属性结构，无安全 2.0 表示的操作或标签返回 `ErrUnsupported`。
  JWK 以厂商扩展 `KeyFormatJWK = 0x80000001`（JSON 置于 Key Material）支持 oct/RSA/EC
  P-256/384/521/Ed25519/X25519，并与 Raw/Transparent/PKCS#1/PKCS#8/X.509/SEC1 双向转换；
  SM2 无法表示为 JWK，仍需使用 Transparent/原始格式。`Export` 操作未实现，`Get` 即导出路径；
  2.0 Get 不支持按属性名筛选（请用 Get Attributes），2.0 Get Attributes/Get Attribute List
  拒绝厂商属性引用，2.0 Template 对象不支持；X25519 映射为 ECDH，私钥须以 PKCS#8 导入，
  未提供 X25519 密钥对生成。`Destroy` 保留墓碑，后续 `Get` 返回 Illegal Operation 但不保留
  密钥材料。Client 不自动重连，传输错误后需重新拨号；`AllowPlaintext` 仅用于测试；
  Batch Undo 通过快照回滚，内存与复制成本随批大小增长。
- **CAS** 已实现 3.0 JSON 视图与后端 SLO（SessionIndex 精确撤销、并行回传 `logoutRequest`）；
  未实现前端浏览器 SLO 重定向，LogoutRequest 不做 XML 签名校验（依赖不可猜测的 SessionIndex
  与网络边界），`NotOnOrAfter` 只为幂等性解析不强制；默认 SessionRegistry 仅单进程。
- 所有内存实现（`auth.NewMemoryStores`、`oauth2.NewMemoryStore`、`saml.NewMemoryStore`、
  `rbac.NewMemoryStore`、`scim.NewMemoryStore`、`cas.NewMemoryTicketStore`、`kms`/`kmip`
  内存存储、OTP 重放保护）仅适用于单进程；多实例请实现共享存储接口。

## 第二轮审计行为变更（v0.1.1）

以下变更为对齐协议与收紧密封边界，升级时需检查调用方：

- **JWT/JOSE**：拒绝非规范 base64url、转义拼写的 `crit`/`b64` 头部与 RSA < 2048 位密钥；
  JWK 的 `use`/`key_ops` 参与签名、验签、加密、解密授权；`KeySet.Handler` 默认不发布
  `oct` 对称密钥，可信内部分发需显式 `HandlerWithOptions{IncludeSymmetricKeys: true}`；
  `Verify`/`Decrypt` 默认限制 1 MiB 输入，大载荷需调高 `MaxTokenSize`。
- **OAuth2/OIDC**：`Server.Endpoint(p)` 与 `Provider.Endpoint(p)` 现接受未加前缀的路径并
  自动应用 PathPrefix，禁止 `Endpoint(Path(p))` 嵌套；`client_secret_jwt` 在注册与认证时
  明确拒绝；Back-Channel Logout 接收端必须配置 `BackchannelLogoutClientID`，未配置时失败关闭。
- **SAML/WS-Fed**：多个 AudienceRestriction 必须全部匹配；配置 `SPResolver` 时 ACS 以元数据
  为准，未注册的请求 URL 被拒绝；HTTP-Redirect SLO 以查询签名满足签名策略，POST 仍需 XML 签名。
- **OTP/WebAuthn/RBAC**：HOTP 拒绝计数器回退并保持单调；CBOR binary16 不再静默舍入；Android Key
  attestation 接受规范 EXPLICIT DER；`LoadSnapshot` 对 Engine 方法原子化，经 `Store()` 直接
  写入仍绕过引擎锁。
- **LDAP/SCIM**：连接池重复 Put 为 no-op；SortControl 与 ExtensibleMatch 使用 RFC 要求的隐式
  原始 BOOLEAN；SCRAM 拒绝重复 server-first 属性；PUT/PATCH `/Me` 应用 attributes 投影。
- **CAS/RADIUS**：SSO 签发的 ST 不再继承 TGT 的 renew；CAS 2.0/3.0 空 user 被拒绝；RADIUS UDP
  静默丢弃无效 Response Authenticator 并继续等待合法应答，流传输返回 `ErrAuthenticator` 并
  关闭连接；Vendor-Id 0 的 VSA 被拒绝。
- **KMS/KMIP**：导入非对称材料校验公私钥配对；KMIP 拒绝重复标量标签与重复 ProtocolVersion
  字段，读取前校验根标签，只读 Batch 不再取全 Store 快照；其余见各包文档。

## 第三轮边界修复行为变更（v0.1.2）

本轮补齐可落地的协议边界；新增能力均为显式配置，安全默认失败关闭：

- **JWT/JOSE**：新增 `ValidateIssuedAt`/`RequireIssuedAt`、`Issuers`/`Audiences`、JWS
  General/Flattened JSON 序列化、detached payload、ECDSA low-S 选项。JWE 仍为 compact-only，
  b64=false 继续拒绝；仅 protected 头部可携带 `alg`。
- **OAuth2/OIDC**：Front-Channel Logout 接收端需配置 `FrontchannelLogoutClientID`，否则 500；
  新增第三方 OP 的 `BackchannelLogoutIssuer`/`BackchannelLogoutKeySet`/`BackchannelLogoutJWKSURI`/
  `BackchannelLogoutKeyResolver`；mTLS 客户端必须有 subject DN 或 SAN 绑定，自签名证书校验
  有效期；`request_uri` 单次使用记录上限 4096。
- **SAML/WS-Fed**：`OneTimeUse` 默认要求 `AssertionReplayStore`（否则失败关闭，可用
  `AllowOneTimeUseWithoutReplayStore` 显式放行）；强制 `SessionNotOnOrAfter`；Artifact
  Resolution 支持 SOAP 1.2、多端点 failover 与总超时。WS-Fed 的 `RequireSigned` 必须有
  `SignatureVerifier`，签名断言不可验证时拒绝，并固定 issuer；状态码缺失不再视为成功。
- **CAS**：登记前端登出 URL 后浏览器登出渲染前端 SLO 页面（默认最多 10 个服务）；入站
  LogoutRequest 支持 XML 签名校验，`RequireSignedLogoutRequest` 打开时失败关闭。
- **RADIUS**：UDP 上结构畸形、Identifier 不匹配、Response Authenticator/Message-Authenticator
  错误的报文全部静默丢弃并等待；流传输仍立即失败并关闭连接。新增 UDP/TCP/TLS `AccessServer`
  与 `AccountingServer`（PAP/CHAP、MA、并发/尺寸/关闭控制）；relay 与完整 EAP 状态机仍不在范围。
- **SCIM/LDAP**：写请求默认要求 `application/scim+json` 或 `application/json`（415，可用
  `AllowAnyContentType` 放宽）；新增口令预检与失败补偿（版本条件写）；LDAP 连接池可选空闲探测
  （默认关闭）；`RequireSASLPlainTLS` 可强制 SASL PLAIN 仅 TLS。
- **OTP/WebAuthn/RBAC**：新增 `SafetyNetPolicy` 与 `AndroidKeyPolicy`；RBAC 快照装载失败会
  恢复旧状态，恢复失败返回 `ErrSnapshotRestore`；`Validator.ValidateHOTP` 拒绝计数器回退。
- **KMS/KMIP**：REST 新增 `AllowedOrigins`/`AllowedHosts`/`RequireSameOrigin`/
  `CookieAuth`/`CSRFCheck`；静态加密新写入使用版本化 `KMSM2`（随机盐、参数入包，旧 `KMSM1`
  仍可解）；`DeriveKey` 仅允许对称密钥；KMIP 实现 1.4 `Export`，协议版本仅接受 1.4/2.0，
  客户端断线后惰性重连且不重放失败请求；Batch Undo 仍为完整快照（已在文档说明原因）。
- **核心 auth/CN**：`RotateAfter` 在两种 HTTP 入口自动轮换；`NewManagedMemoryStores` 提供
  周期清理；`RequireEmailVerification` 下联邦未验证邮箱新用户置为 `UserPending`；
  `PasswordPolicy` 支持逐字段默认；`Config.RequireMFAToken` 可关闭旧空 MFAToken 路径；
  identity/cn 默认客户端仅跟随同源/HTTPS 升级重定向，响应字段超限与解码错误不再回显原文。

## 第四轮完整性补全（v0.1.3）

本轮以“不留半成品”为标准补齐此前列出的全部硬边界：

- **Kerberos V5 + GSSAPI/SPNEGO**：新增 `auth/protocol/kerberos`，实现 AS/TGS/AP 交换、
  AES128/256-CTS-HMAC-SHA1-96、RC4-HMAC、MIT keytab、SRV/TXT KDC 发现、GSSAPI 初始上下文、
  AP-REP 双向认证、通道绑定、RFC 4121 Wrap/Unwrap/MIC 与 Acceptor；LDAP 新增
  `BindSASLGSSAPI` 与 `Config.GSSAPI`，支持 SPNEGO/raw Kerberos、authzID、通道绑定与重连重放。
  已通过真实 MIT KDC 互操作测试（`-tags interopkdc`）。
- **JOSE**：JWE General/Flattened JSON（多接收方、AAD、zip）、JWS 多签名签发、RFC 7797
  `b64=false` 全部实现；compact 仍为默认。
- **OAuth2/OIDC**：RFC 9449 DPoP nonce 全流程与 `cnf.jkt` 绑定；`client_secret_jwt` 在部署方
  提供 `ClientSecretResolver` 后可完整认证并参与动态注册；Front-Channel Logout 支持 sid/sub
  会话回调；内存状态周期清理。
- **NTLM**：完整 SPNEGO 状态机、mechListMIC、服务端 Acceptor、NTLMSSP SIGN/SEAL
  （RC4 + HMAC-MD5、序列号、双向密钥派生）；LDAP SASL NTLM 使用新状态机并校验 mechListMIC。
- **RADIUS**：relay/proxy（Access/Accounting、Proxy-State、MS-MPPE 重加密、循环检测）、
  可复用 Access/Accounting 服务端（UDP/TCP/TLS）、MS-CHAPv2 服务端、EAP-MD5/EAP-MSCHAPv2/
  EAP-TLS/EAP-TTLS/PEAPv0、Accounting Message-Authenticator 与重复抑制。
- **SAML/SCIM**：SAML 重放窗口可配置、SOAP 1.2 Artifact Resolution、多端点 failover；
  SCIM 两阶段 `PasswordProvisioner`（Begin/Commit/Rollback）与创建失败显式回滚错误。
- **WebAuthn**：TPM 2.0 EK credential activation 完整实现（自研 TPM2 编解码、MakeCredential/
  ActivateCredential、Linux `/dev/tpmrm0`、Windows TBS、软件 TPM 测试、WebAuthn 注册集成）；
  自定义校验器不能再绕过 SafetyNet/AndroidKey/TPM 策略。
- **KMS/KMIP**：KMIP Batch Undo 改为按受影响对象的事务化逆操作日志（含 Destroy 材料恢复）；
  KMS 版本化 `KMSM2` 包装、REST 安全、DeriveKey 对称限制；KMIP Export、版本策略与惰性重连。
- **多实例共享存储**：新增独立模块 `github.com/shibingli/ydx/authstore`，为 auth 根包与
  oauth2/oidc/saml/cas/scim/rbac/kms/kmip/wsfed/otp/webauthn 的全部 Store/Registry/Replay/
  Challenge/State 接口提供 Redis 实现（Lua 原子性、Cluster 哈希槽、miniredis 多实例测试）。

## 与主流实现的对比

`benchmarks/auth` 对 JOSE/JWS、JWE、OTP、RBAC、LDAP 过滤器与 XMLDSig 做主流程同进程对比，
并通过互操作测试验证 JWT（golang-jwt）、JWS/JWE（go-jose、jwx）、OIDC（coreos/go-oidc）、
XMLDSig（goxmldsig）、TOTP（pquerna/otp）、RBAC（casbin）与 LDAP 过滤器（go-ldap）的双向兼容。
当前结果：HS256 JWS 签发/验签、RBAC、LDAP 过滤器与 XMLDSig 验签均快于或持平主流实现，
ES256 签发/验签同一量级且分配更少；JWT ES256 解析已从落后优化到最快。完整数字与口径见
[`benchmarks/auth/README.md`](../benchmarks/auth/README.md) 与
[`benchmarks/jwt/README.md`](../benchmarks/jwt/README.md)。

## 测试

```bash
cd auth
GOWORK=off go build ./...
GOWORK=off go vet ./...
GOWORK=off CGO_ENABLED=1 CC=clang go test ./... -race
```

`auth v0.1.0` 依赖的 `ydx/json v0.1.17` 已随本仓标签发布，可直接使用默认 `GOPROXY` 构建；
开发期联调尚未发布的兄弟模块时，才需要在仓库外临时 `go.work` 或文件代理。

外部协议一致性测试使用 RFC/W3C/OpenID 官方测试向量与本地 mock 服务器；不访问真实第三方网络。
