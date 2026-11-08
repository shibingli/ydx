// Package webauthn implements a WebAuthn Level 2/3 relying party with passkey support.
// | Package webauthn 实现支持通行密钥的 WebAuthn Level 2/3 依赖方。
//
// The package covers registration and authentication ceremonies, CBOR (RFC 8949) and COSE
// (RFC 9052) decoding, authenticator and client data validation, attestation statement verification
// for the none, packed, fido-u2f, android-key, android-safetynet, tpm and apple formats, optional TPM
// endorsement-key credential activation, single-use challenge storage, a configurable sign-counter
// policy and an auth.MFAVerifier adapter. | 本包覆盖注册与认证流程、CBOR（RFC 8949）与 COSE
// （RFC 9052）解码、认证器与客户端数据校验、none、packed、fido-u2f、android-key、
// android-safetynet、tpm 与 apple 格式的认证声明校验、可选的 TPM 背书密钥凭据激活、一次性挑战存储、
// 可配置的签名计数器策略以及 auth.MFAVerifier 适配器。
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
// AndroidKeyVerifier add checks before the built-in path: when SafetyNetPolicy or AndroidKeyPolicy is
// non-zero it is still applied after the custom verifier returns, so configured policy cannot be
// silently disabled. With a zero-value policy a custom verifier retains its baseline behavior; when
// configured roots are also present they still gate TrustVerified, and a custom AndroidKeyVerifier
// reports its own TrustVerified value. |
// 支持校验 none、packed、fido-u2f、android-key、android-safetynet、tpm 与 apple 格式。签名始终
// 针对凭据密钥或认证证书校验。X.509 链只建到调用方提供的信任锚：Config.AttestationRoots /
// AttestationOptions.Roots 是通用信任池，SafetyNetRoots 与 AndroidKeyRoots 按格式覆盖它。未配置信任池
// 时仅解析链并写入 TrustPath，TrustVerified 保持 false；本包从不使用系统根存储，也从不发起网络请求。
// SafetyNetVerifier 与 AndroidKeyVerifier 在内置路径之前增加校验：SafetyNetPolicy 或
// AndroidKeyPolicy 非零时，自定义校验器返回后仍会执行，因此已配置策略不能被静默关闭。策略为零值时
// 自定义校验器保持基线行为；若同时配置了信任锚，TrustVerified 仍受其约束，自定义
// AndroidKeyVerifier 则报告自身的 TrustVerified 值。
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
// public key. A non-zero SafetyNetPolicy or AndroidKeyPolicy is enforced on the built-in path and
// re-applied after a custom verifier, so a custom SafetyNetVerifier or AndroidKeyVerifier can add
// checks but cannot disable configured policy; a non-zero SafetyNetPolicy also re-runs the mandatory
// nonce and signature checks. The zero-value policy preserves the baseline custom-verifier behavior. |
// SafetyNetPolicy 收紧内置 android-safetynet 路径：可要求 basicIntegrity、固定
// apkCertificateDigestSha256、限制 evaluationType 与 ver，并放宽或收窄时间戳窗口；强制的
// ctsProfileMatch、nonce 与签名校验仍然生效。AndroidKeyPolicy 收紧内置 android-key 路径：可要求
// 已验证的启动状态、强制 OS 版本与补丁级别下限、限制密钥位数与 EC 曲线、允许声明摘要算法、固定
// attestationApplicationId 签名摘要，并选择启用 allApplications。声明的 keySize 与 ecCurve 会与证书
// 公钥交叉校验。非零 SafetyNetPolicy 或 AndroidKeyPolicy 在内置路径生效，并在自定义校验器之后再次
// 执行，因此自定义 SafetyNetVerifier 或 AndroidKeyVerifier 只能增加校验，不能关闭已配置策略；非零
// SafetyNetPolicy 还会重新执行强制的 nonce 与签名校验。策略为零值时保持自定义校验器的基线行为。
//
// TPM verification covers TPMS_ATTEST, pubArea, extraData, the AIK certificate profile and the
// attestation signature. Optional endorsement-key credential activation is described below. | TPM
// 校验覆盖 TPMS_ATTEST、pubArea、extraData、AIK 证书配置与认证签名。可选的背书密钥凭据激活见下文。
//
// # TPM EK activation | TPM EK 激活
//
// Config.TPMEKActivation enables TPM endorsement-key credential activation and is nil by default, so
// the default registration path is unchanged. Service.BeginTPMEKActivation accepts the EK certificate
// chain, raw EK and AK TPMT_PUBLIC areas and the authenticator AAGUID, then returns a single-use,
// expiring challenge carrying the TPM2B_ID_OBJECT and TPM2B_ENCRYPTED_SECRET parameter contents for
// TPM2_ActivateCredential. The authenticator runs TPM2_ActivateCredential and returns its certInfo as
// TPMEKActivationEvidence in CredentialCreationResponse.TPMEKActivation; FinishRegistration consumes
// the challenge and verifies the proof. FinishTPMEKActivation exposes the same finish step directly,
// and VerifyEKActivation verifies a complete evidence set out of band. | Config.TPMEKActivation 启用
// TPM 背书密钥凭据激活，默认为 nil，因此默认注册路径不变。Service.BeginTPMEKActivation 接收 EK 证书
// 链、原始 EK 与 AK TPMT_PUBLIC 区域以及认证器 AAGUID，返回一次性、有期限的挑战，携带传给
// TPM2_ActivateCredential 的 TPM2B_ID_OBJECT 与 TPM2B_ENCRYPTED_SECRET 参数内容。认证器执行
// TPM2_ActivateCredential，并把 certInfo 作为 TPMEKActivationEvidence 放入
// CredentialCreationResponse.TPMEKActivation 返回；FinishRegistration 消费挑战并校验证明。
// FinishTPMEKActivation 直接提供同一完成步骤，VerifyEKActivation 可带外校验完整证据集。
//
// Activation validates the EK certificate profile (X.509 v3, valid at verification time, non-CA,
// usable key usage, the TCG EK EKU when an EKU extension is present, a minimum RSA modulus or a
// supported ECC curve, and an optional TCG manufacturer directoryName), the optional vendor chain to
// EKRoots or Config.AttestationRoots, the AAGUID and manufacturer allowlists, and the TPM
// cryptographic proof binding the credential to the AK Name. Registration additionally requires the
// activation AK public key to match the AIK certificate in the attestation trust path and the
// challenge AAGUID to match the registration AAGUID. Built-in checks always run before
// TPMEKActivationConfig.Verifier, so a custom verifier can only add constraints. With
// RequiredForTPMAttestation a tpm attestation without evidence is rejected, while evidence attached
// to any other format is rejected. A nil Config.TPMEKActivation ignores evidence. | 激活校验 EK 证书
// 配置（X.509 v3、校验时有效、非 CA、可用的密钥用途、存在 EKU 扩展时要求 TCG EK EKU、最小 RSA 模数
// 或受支持的 ECC 曲线、可选的 TCG 制造商 directoryName）、到 EKRoots 或 Config.AttestationRoots 的
// 可选厂商链、AAGUID 与制造商允许列表，以及把凭据绑定到 AK Name 的 TPM 密码学证明。注册还要求激活
// AK 公钥与认证声明信任路径中的 AIK 证书一致，挑战 AAGUID 与注册 AAGUID 一致。内置校验始终在
// TPMEKActivationConfig.Verifier 之前执行，因此自定义校验器只能增加约束。启用
// RequiredForTPMAttestation 时，无证据的 tpm 认证声明会被拒绝；证据附加到其它格式也会被拒绝。
// Config.TPMEKActivation 为 nil 时忽略证据。
//
// OpenTPM returns a raw TPM 2.0 transport for callers that execute the commands themselves: Linux
// uses /dev/tpmrm0 with a /dev/tpm0 fallback, Windows uses TPM Base Services, and other platforms
// return ErrUnsupported. A missing device or service returns ErrTPMUnavailable. Execute serializes
// concurrent commands, honors context cancellation and deadlines with ErrTPMTimeout, and Close is
// idempotent. | OpenTPM 为自行执行命令的调用方返回原始 TPM 2.0 传输：Linux 使用 /dev/tpmrm0 并回退
// 到 /dev/tpm0，Windows 使用 TPM Base Services，其它平台返回 ErrUnsupported。设备或服务缺失返回
// ErrTPMUnavailable。Execute 串行化并发命令、遵守上下文取消与期限并返回 ErrTPMTimeout，Close 幂等。
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
// paths and no cgo. Apart from the standard library and auth types, runtime dependencies are
// ydx/errs, ydx/json and ydx/base64, plus golang.org/x/sys for the Linux and Windows TPM transports;
// the software TPM used by tests is unexported and test-only. | 挑战来自 crypto/rand，挑战、用户句柄与
// 令牌绑定标识的比较均为常量时间，非法 CBOR 永不 panic。签名计数器按 Config.CounterPolicy 处理：默认
// 严格；仅在选择加入的策略下，且认证器报告 BE=1 与 BS=1 时才接受备份资格重置；已存计数器为零时接受
// 下一次断言。错误消息与日志绝不包含凭据私有材料。本包在请求路径上不使用反射、不使用 cgo。除标准库与
// auth 类型外，运行时依赖为 ydx/errs、ydx/json 与 ydx/base64，Linux 与 Windows TPM 传输另用
// golang.org/x/sys；测试所用软件 TPM 不导出且仅用于测试。
package webauthn
