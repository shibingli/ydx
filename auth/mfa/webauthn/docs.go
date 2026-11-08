// Package webauthn implements a WebAuthn Level 2/3 relying party with passkey support.
// | Package webauthn 实现支持通行密钥的 WebAuthn Level 2/3 依赖方。
//
// The package covers registration and authentication ceremonies, CBOR (RFC 8949) and COSE
// (RFC 9052) decoding, authenticator and client data validation, attestation statement verification
// for the none, packed, fido-u2f, android-key, android-safetynet, tpm and apple formats, single-use
// challenge storage, a configurable sign-counter policy and an auth.MFAVerifier adapter. | 本包覆盖
// 注册与认证流程、CBOR（RFC 8949）与 COSE（RFC 9052）解码、认证器与客户端数据校验、none、packed、
// fido-u2f、android-key、android-safetynet、tpm 与 apple 格式的认证声明校验、一次性挑战存储、可配置
// 的签名计数器策略以及 auth.MFAVerifier 适配器。
//
// # Ceremony flow | 流程
//
// BeginRegistration, BeginLogin and BeginDiscoverableLogin return navigator-compatible options plus a
// Ceremony value. Persist that Ceremony in the user's session and pass it back to the matching Finish
// method. Every Finish call consumes the challenge before verification, so a failed assertion cannot
// be replayed and a captured challenge cannot be used twice. | BeginRegistration、BeginLogin 与
// BeginDiscoverableLogin 返回与 navigator 兼容的选项以及 Ceremony 值。把该 Ceremony 存入用户会话，
// 并传给对应的 Finish 方法。每个 Finish 调用在校验前消费挑战，因此失败的断言无法重放，被截获的
// 挑战也不能使用两次。
//
// The challenge is random, single use and bounded by Config.Timeout. The ceremony records the RP ID,
// accepted origins, user verification policy, offered algorithms, credential exclusions and the
// cross-origin and token-binding policy, so a later configuration change cannot weaken an in-flight
// ceremony. | 挑战随机、单次使用并受 Config.Timeout 限制。流程记录 RP ID、允许来源、用户验证策略、
// 提供的算法、凭据排除项以及跨来源与令牌绑定策略，因此后续配置变更不会削弱进行中的流程。
//
// # YD router | YD 路由
//
// The package exposes no HTTP handlers of its own; handlers are thin functions over Service. The
// YD router form is | 本包不自带 HTTP 处理器；处理器是 Service 之上的薄封装。YD 路由形式为
//
//	r.HandleFunc(http.MethodPost, "/webauthn/register/begin", func(c *router.Context) error {
//		options, ceremony, err := service.BeginRegistration(c.Request.Context(), user, webauthn.RegistrationOptions{})
//		if err != nil {
//			return err
//		}
//		session.Set("webauthn_ceremony", ceremony)
//		return c.JSON(http.StatusOK, options)
//	})
//
//	r.HandleFunc(http.MethodPost, "/webauthn/register/finish", func(c *router.Context) error {
//		var ceremony webauthn.Ceremony
//		if err := session.Get("webauthn_ceremony", &ceremony); err != nil {
//			return err
//		}
//		var response webauthn.CredentialCreationResponse
//		if err := c.BindJSON(&response); err != nil {
//			return err
//		}
//		credential, err := service.FinishRegistration(c.Request.Context(), &ceremony, &response)
//		if err != nil {
//			return err
//		}
//		return c.JSON(http.StatusCreated, credential)
//	})
//
// Native net/http | 原生 net/http：
//
//	mux.HandleFunc("POST /webauthn/login/begin", func(w http.ResponseWriter, r *http.Request) {
//		options, ceremony, err := service.BeginLogin(r.Context(), user, webauthn.LoginOptions{})
//		if err != nil {
//			http.Error(w, err.Error(), http.StatusBadRequest)
//			return
//		}
//		session.Set("webauthn_ceremony", ceremony)
//		w.Header().Set("Content-Type", "application/json")
//		_ = json.NewEncoder(w).Encode(options)
//	})
//
//	mux.HandleFunc("POST /webauthn/login/finish", func(w http.ResponseWriter, r *http.Request) {
//		var ceremony webauthn.Ceremony
//		if err := session.Get("webauthn_ceremony", &ceremony); err != nil {
//			http.Error(w, err.Error(), http.StatusBadRequest)
//			return
//		}
//		var response webauthn.CredentialAssertionResponse
//		if err := json.NewDecoder(r.Body).Decode(&response); err != nil {
//			http.Error(w, err.Error(), http.StatusBadRequest)
//			return
//		}
//		credential, err := service.FinishLogin(r.Context(), &ceremony, &response)
//		if err != nil {
//			http.Error(w, err.Error(), http.StatusUnauthorized)
//			return
//		}
//		_ = credential
//		w.WriteHeader(http.StatusNoContent)
//	})
//
// # Second factor adapter | 第二因素适配器
//
// Verifier implements auth.MFAVerifier and reads the same CredentialData layout that
// AuthCredentialStore writes: | Verifier 实现 auth.MFAVerifier，读取 AuthCredentialStore 写入的同一
// CredentialData 布局：
//
//	store, _ := webauthn.NewAuthCredentialStore(stores.Credentials)
//	service, _ := webauthn.New(webauthn.Config{
//		RPDisplayName:   "Example",
//		RPID:            "example.com",
//		RPOrigins:       []string{"https://example.com"},
//		CredentialStore: store,
//	})
//	verifier, _ := webauthn.NewVerifier(service)
//	authService.RegisterMFAVerifier(auth.CredentialWebAuthn, verifier)
//
// Verify consumes a challenge produced by BeginLogin or BeginDiscoverableLogin and updates
// credential.Data["signCount"] in place; auth.Service persists the record after success. | Verify
// 消费 BeginLogin 或 BeginDiscoverableLogin 产生的挑战，并就地更新 credential.Data["signCount"]；
// auth.Service 会在成功后持久化记录。
//
// # Counter policy | 计数器策略
//
// Config.CounterPolicy defaults to CounterStrict: a stored non-zero counter must strictly increase.
// CounterAllowBackupEligibleReset additionally accepts a non-increase when the authenticator reports
// BE=1 and BS=1, which lets restore-synced passkeys resume after a legitimate counter reset while
// still rejecting regressions for non-backup credentials. CounterAllowAny accepts any reported value
// and is intended only for environments that cannot store counters. A stored counter of zero always
// accepts the next assertion. The BS flag is persisted through the optional BackupStateUpdater
// interface when the credential store implements it; the built-in memory and auth stores do. |
// Config.CounterPolicy 默认为 CounterStrict：已存的非零计数器必须严格递增。
// CounterAllowBackupEligibleReset 额外接受认证器报告 BE=1 与 BS=1 时的非递增，使恢复同步的通行密钥
// 在合法计数器重置后继续工作，同时仍拒绝非备份凭据的回退。CounterAllowAny 接受任意报告值，只适用于
// 无法存储计数器的环境。已存计数器为零时始终接受下一次断言。当凭据存储实现可选的 BackupStateUpdater
// 接口时持久化 BS 标志；内置的内存存储与 auth 存储均已实现。
//
// # Attestation | 认证声明
//
// Formats none, packed, fido-u2f, android-key, android-safetynet, tpm and apple are verified.
// Signatures are always checked against the credential key or attestation certificate. X.509 chains
// are chained only to caller-supplied anchors: Config.AttestationRoots / AttestationOptions.Roots is
// the generic pool, while SafetyNetRoots and AndroidKeyRoots override it for their format. With no
// configured pool the chain is parsed and reported in TrustPath but TrustVerified stays false; this
// package never uses the system root store and never performs network requests. SafetyNetVerifier and
// AndroidKeyVerifier may replace the built-in checks; when configured roots are also present they
// still gate TrustVerified, and a custom AndroidKeyVerifier reports its own TrustVerified value. |
// 支持校验 none、packed、fido-u2f、android-key、android-safetynet、tpm 与 apple 格式。签名始终
// 针对凭据密钥或认证证书校验。X.509 链只建到调用方提供的信任锚：Config.AttestationRoots /
// AttestationOptions.Roots 是通用信任池，SafetyNetRoots 与 AndroidKeyRoots 按格式覆盖它。未配置信任池
// 时仅解析链并写入 TrustPath，TrustVerified 保持 false；本包从不使用系统根存储，也从不发起网络请求。
// SafetyNetVerifier 与 AndroidKeyVerifier 可替换内置校验；若同时配置了信任锚，TrustVerified 仍受其
// 约束，自定义 AndroidKeyVerifier 则报告自身的 TrustVerified 值。
//
// android-safetynet and android-key attestations also bind the APK package when
// Config.AndroidPackageName or ClientData.AndroidPackageName is set. Neither format carries a
// hostname, so RP ID and origin binding come from the verified client data rather than the
// attestation statement. | 当设置 Config.AndroidPackageName 或 ClientData.AndroidPackageName 时，
// android-safetynet 与 android-key 认证声明还会绑定 APK 包名。两种格式都不携带主机名，因此 RP ID 与
// 来源绑定来自已校验的客户端数据，而不是认证声明。
//
// SafetyNetPolicy tightens the built-in android-safetynet path: it can require basicIntegrity,
// pin the apkCertificateDigestSha256 values, restrict evaluationType and ver, and widen or narrow
// the timestamp window. The mandatory ctsProfileMatch, nonce and signature checks remain in force.
// AndroidKeyPolicy tightens the built-in android-key path: it can require a verified boot state,
// enforce OS version and patch-level minimums, restrict key size and EC curves, allowlist declared
// digest algorithms, pin the attestationApplicationId signature digests, and opt into
// allApplications. Declared keySize and ecCurve values are cross-checked against the certificate
// public key. Both policies apply only to the built-in verification paths; a custom SafetyNetVerifier
// or AndroidKeyVerifier replaces those paths and owns the corresponding checks. | SafetyNetPolicy
// 收紧内置 android-safetynet 路径：可要求 basicIntegrity、固定 apkCertificateDigestSha256、限制
// evaluationType 与 ver，并放宽或收窄时间戳窗口；强制的 ctsProfileMatch、nonce 与签名校验仍然生效。
// AndroidKeyPolicy 收紧内置 android-key 路径：可要求已验证的启动状态、强制 OS 版本与补丁级别下限、
// 限制密钥位数与 EC 曲线、允许声明摘要算法、固定 attestationApplicationId 签名摘要，并选择启用
// allApplications。声明的 keySize 与 ecCurve 会与证书公钥交叉校验。两种策略仅作用于内置校验路径；
// 自定义 SafetyNetVerifier 或 AndroidKeyVerifier 会替换该路径并自行负责对应校验。
//
// TPM verification covers TPMS_ATTEST, pubArea, extraData, the AIK certificate profile and the
// attestation signature, but it does not perform EK credential activation: that protocol needs a
// TPM transport and a challenge/response exchange with the TPM, neither of which exists in a
// WebAuthn attestation object. Callers that require EK credential activation must implement it out
// of band and must not treat TrustVerified as proof of it. | TPM 校验覆盖 TPMS_ATTEST、pubArea、
// extraData、AIK 证书配置与认证签名，但不执行 EK 凭据激活：该协议需要 TPM 传输通道以及与 TPM 的
// 挑战应答交换，二者都不存在于 WebAuthn 认证声明对象中。需要 EK 凭据激活的调用方必须在带外实现，
// 且不得把 TrustVerified 当作其证明。
//
// ECDAA is intentionally unsupported. WebAuthn Level 3 removed the ecdaa attestation format, so the
// package reports it as an unsupported format instead of implementing a superseded algorithm. |
// ECDAA 有意不支持。WebAuthn Level 3 已移除 ecdaa 认证声明格式，因此本包将其报告为不支持的格式，而
// 非实现已被取代的算法。
//
// # Extensions | 扩展
//
// The package understands credProtect, credProps and the FIDO AAGUID certificate extension. It
// models hmac-secret and uvm client extension inputs but does not verify hmac-secret outputs; callers
// that need hmac-secret must validate the returned salts against their own policy. | 本包理解
// credProtect、credProps 与 FIDO AAGUID 证书扩展。它建模 hmac-secret 与 uvm 客户端扩展输入，但不
// 校验 hmac-secret 输出；需要 hmac-secret 的调用方必须按自身策略校验返回的盐值。
//
// # Security notes | 安全说明
//
// Challenges come from crypto/rand, comparisons of challenges, user handles and token binding IDs are
// constant time, and malformed CBOR never panics. Sign-count handling follows Config.CounterPolicy:
// strict by default, with backup-eligible resets accepted only under the opt-in policy and only when
// the authenticator reports BE=1 and BS=1; a stored zero accepts the next assertion. Error messages
// and logs never contain credential private material. The package uses no reflection on request
// paths, no cgo and no dependency outside ydx/errs, ydx/json, ydx/base64 and the auth types. | 挑战来自
// crypto/rand，挑战、用户句柄与令牌绑定标识的比较均为常量时间，非法 CBOR 永不 panic。签名计数器按
// Config.CounterPolicy 处理：默认严格；仅在选择加入的策略下，且认证器报告 BE=1 与 BS=1 时才接受
// 备份资格重置；已存计数器为零时接受下一次断言。错误消息与日志绝不包含凭据私有材料。本包在请求路径
// 上不使用反射、不使用 cgo，且除 ydx/errs、ydx/json、ydx/base64 与 auth 类型外不引入依赖。
package webauthn
