package webauthn

import "github.com/shibingli/ydx/errs"

// The declared sentinels of this package. | 本包的哨兵错误声明。
//
// Every failure path returns one of them directly or through errs.Detail / errs.Wrap, so callers
// can classify errors with errors.Is instead of matching message text. | 所有失败路径都直接返回其中
// 之一，或经由 errs.Detail / errs.Wrap 包装，因此调用方可以用 errors.Is 分类错误而无需匹配文案。
var (
	// ErrInvalidConfig reports a missing or contradictory service configuration. | ErrInvalidConfig 表示服务配置缺失或互相矛盾。
	ErrInvalidConfig = errs.New("webauthn: invalid configuration | webauthn：配置非法")
	// ErrInvalidRequest reports malformed caller input. | ErrInvalidRequest 表示调用方输入非法。
	ErrInvalidRequest = errs.New("webauthn: invalid request | webauthn：请求非法")
	// ErrInvalidCredential reports a malformed stored credential record. | ErrInvalidCredential 表示存储的凭据记录非法。
	ErrInvalidCredential = errs.New("webauthn: invalid credential | webauthn：凭据记录非法")
	// ErrCredentialNotFound reports an unknown credential identifier. | ErrCredentialNotFound 表示凭据标识不存在。
	ErrCredentialNotFound = errs.New("webauthn: credential not found | webauthn：凭据不存在")
	// ErrCredentialExists reports a duplicate credential identifier. | ErrCredentialExists 表示凭据标识重复。
	ErrCredentialExists = errs.New("webauthn: credential already exists | webauthn：凭据已存在")
	// ErrCredentialIDMismatch reports a response whose rawId differs from the signed credential ID. | ErrCredentialIDMismatch 表示响应的 rawId 与签名的凭据 ID 不一致。
	ErrCredentialIDMismatch = errs.New("webauthn: credential ID mismatch | webauthn：凭据 ID 不匹配")
	// ErrCredentialDisabled reports a credential excluded from authentication. | ErrCredentialDisabled 表示凭据已被排除在认证之外。
	ErrCredentialDisabled = errs.New("webauthn: credential disabled | webauthn：凭据已禁用")
	// ErrInvalidClientData reports malformed or inconsistent client data JSON. | ErrInvalidClientData 表示客户端数据 JSON 非法或不一致。
	ErrInvalidClientData = errs.New("webauthn: invalid client data | webauthn：客户端数据无效")
	// ErrChallengeMismatch reports client data signed over a different challenge. | ErrChallengeMismatch 表示客户端数据签名的挑战不一致。
	ErrChallengeMismatch = errs.New("webauthn: challenge mismatch | webauthn：挑战不匹配")
	// ErrChallengeNotFound reports an unknown or already consumed challenge. | ErrChallengeNotFound 表示挑战不存在或已被消费。
	ErrChallengeNotFound = errs.New("webauthn: challenge not found or already used | webauthn：挑战不存在或已使用")
	// ErrChallengeExpired reports a challenge past its lifetime. | ErrChallengeExpired 表示挑战已超过生命周期。
	ErrChallengeExpired = errs.New("webauthn: challenge expired | webauthn：挑战已过期")
	// ErrChallengeGeneration reports a failure of the random source. | ErrChallengeGeneration 表示随机源生成挑战失败。
	ErrChallengeGeneration = errs.New("webauthn: challenge generation failed | webauthn：挑战生成失败")
	// ErrCeremonyMismatch reports a ceremony of the wrong type or owner. | ErrCeremonyMismatch 表示流程类型或归属不匹配。
	ErrCeremonyMismatch = errs.New("webauthn: ceremony mismatch | webauthn：流程不匹配")
	// ErrOriginMismatch reports client data from an origin outside RPOrigins. | ErrOriginMismatch 表示客户端数据来源不在 RPOrigins 内。
	ErrOriginMismatch = errs.New("webauthn: origin mismatch | webauthn：来源不匹配")
	// ErrRPIDMismatch reports an authenticator data hash for another RP ID. | ErrRPIDMismatch 表示认证器数据哈希对应其他 RP ID。
	ErrRPIDMismatch = errs.New("webauthn: RP ID mismatch | webauthn：RP ID 不匹配")
	// ErrUserPresenceRequired reports a missing user presence flag. | ErrUserPresenceRequired 表示缺少用户在场标志。
	ErrUserPresenceRequired = errs.New("webauthn: user presence required | webauthn：需要用户在场")
	// ErrUserVerificationRequired reports a missing user verification flag under the required policy. | ErrUserVerificationRequired 表示在 required 策略下缺少用户验证标志。
	ErrUserVerificationRequired = errs.New("webauthn: user verification required | webauthn：需要用户验证")
	// ErrUserHandleMismatch reports a user handle that does not belong to the credential or ceremony. | ErrUserHandleMismatch 表示用户句柄与凭据或流程不匹配。
	ErrUserHandleMismatch = errs.New("webauthn: user handle mismatch | webauthn：用户句柄不匹配")
	// ErrTokenBindingMismatch reports a token binding status or ID that cannot be accepted. | ErrTokenBindingMismatch 表示令牌绑定状态或 ID 不可接受。
	ErrTokenBindingMismatch = errs.New("webauthn: token binding mismatch | webauthn：令牌绑定不匹配")
	// ErrSignatureInvalid reports an assertion or attestation signature that did not verify. | ErrSignatureInvalid 表示断言或认证声明签名未通过校验。
	ErrSignatureInvalid = errs.New("webauthn: invalid signature | webauthn：签名无效")
	// ErrCloneDetected reports an authenticator sign count that did not increase. | ErrCloneDetected 表示认证器签名计数器未递增。
	ErrCloneDetected = errs.New("webauthn: authenticator sign count did not increase | webauthn：认证器签名计数器未递增")
	// ErrBackupEligibilityMismatch reports a credential whose backup eligibility flag changed. | ErrBackupEligibilityMismatch 表示凭据的备份资格标志发生变化。
	ErrBackupEligibilityMismatch = errs.New("webauthn: backup eligibility flag changed | webauthn：备份资格标志发生变化")
	// ErrInvalidAuthenticatorData reports malformed authenticator data. | ErrInvalidAuthenticatorData 表示认证器数据非法。
	ErrInvalidAuthenticatorData = errs.New("webauthn: invalid authenticator data | webauthn：认证器数据无效")
	// ErrInvalidCOSEKey reports a malformed COSE public key. | ErrInvalidCOSEKey 表示 COSE 公钥非法。
	ErrInvalidCOSEKey = errs.New("webauthn: invalid COSE key | webauthn：COSE 公钥无效")
	// ErrUnsupportedKey reports an unsupported key type, curve or parameter combination. | ErrUnsupportedKey 表示不支持的密钥类型、曲线或参数组合。
	ErrUnsupportedKey = errs.New("webauthn: unsupported key type or curve | webauthn：不支持的密钥类型或曲线")
	// ErrUnsupportedAlgorithm reports an unsupported signature algorithm. | ErrUnsupportedAlgorithm 表示不支持的签名算法。
	ErrUnsupportedAlgorithm = errs.New("webauthn: unsupported algorithm | webauthn：不支持的算法")
	// ErrAlgorithmMismatch reports an algorithm that differs from the credential key algorithm. | ErrAlgorithmMismatch 表示算法与凭据密钥算法不一致。
	ErrAlgorithmMismatch = errs.New("webauthn: algorithm mismatch | webauthn：算法不匹配")
	// ErrInvalidAttestation reports a malformed or inconsistent attestation statement. | ErrInvalidAttestation 表示认证声明非法或不一致。
	ErrInvalidAttestation = errs.New("webauthn: invalid attestation | webauthn：认证声明无效")
	// ErrUnsupportedAttestation reports an attestation format this package does not implement. | ErrUnsupportedAttestation 表示本包未实现的认证声明格式。
	ErrUnsupportedAttestation = errs.New("webauthn: unsupported attestation format | webauthn：不支持的认证声明格式")
	// ErrUntrustedAttestation reports an attestation chain that cannot be verified against the supplied roots. | ErrUntrustedAttestation 表示认证链无法用调用方提供的根证书验证。
	ErrUntrustedAttestation = errs.New("webauthn: attestation chain is not trusted | webauthn：认证声明证书链不受信任")
	// ErrInvalidCBOR reports malformed CBOR input. | ErrInvalidCBOR 表示 CBOR 输入非法。
	ErrInvalidCBOR = errs.New("webauthn: malformed CBOR | webauthn：CBOR 格式非法")
	// ErrCBORLimit reports a CBOR value that exceeds the configured depth or size limit. | ErrCBORLimit 表示 CBOR 值超过配置的深度或大小限制。
	ErrCBORLimit = errs.New("webauthn: CBOR limit exceeded | webauthn：超出 CBOR 限制")
	// ErrResidentKeyRequired reports a discoverable-credential requirement the client did not meet. | ErrResidentKeyRequired 表示客户端未满足可发现凭据要求。
	ErrResidentKeyRequired = errs.New("webauthn: resident key required | webauthn：需要常驻密钥")
	// ErrNotSupported reports an operation the active backend does not implement. | ErrNotSupported 表示当前后端不支持该操作。
	ErrNotSupported = errs.New("webauthn: operation not supported | webauthn：操作不支持")
	// ErrTPMUnavailable reports that no TPM device or platform TPM service is available. |
	// ErrTPMUnavailable 表示没有可用的 TPM 设备或平台 TPM 服务。
	ErrTPMUnavailable = errs.New("webauthn: TPM unavailable | webauthn：TPM 不可用")
	// ErrUnsupported reports a capability unavailable on the current platform; it is an alias of
	// ErrNotSupported so errors.Is matches either name. | ErrUnsupported 表示当前平台不具备的能力；它是
	// ErrNotSupported 的别名，因此 errors.Is 用任一名称都能匹配。
	ErrUnsupported = ErrNotSupported
	// ErrTPMTransport reports a platform TPM transport failure such as a write or ioctl error. |
	// ErrTPMTransport 表示写入或 ioctl 等平台 TPM 传输失败。
	ErrTPMTransport = errs.New("webauthn: TPM transport failure | webauthn：TPM 传输失败")
	// ErrTPMTimeout reports that a TPM command exceeded its deadline. | ErrTPMTimeout 表示 TPM 命令超过期限。
	ErrTPMTimeout = errs.New("webauthn: TPM command timed out | webauthn：TPM 命令超时")
	// ErrTPMCommand reports a TPM error response code. | ErrTPMCommand 表示 TPM 错误响应码。
	ErrTPMCommand = errs.New("webauthn: TPM command failed | webauthn：TPM 命令失败")
	// ErrTPMStructure reports a malformed, truncated or oversized TPM 2.0 structure. |
	// ErrTPMStructure 表示 TPM 2.0 结构非法、被截断或超长。
	ErrTPMStructure = errs.New("webauthn: invalid TPM 2.0 structure | webauthn：TPM 2.0 结构非法")
	// ErrEKActivation reports a rejected TPM endorsement-key credential activation. |
	// ErrEKActivation 表示 TPM 背书密钥凭据激活被拒绝。
	ErrEKActivation = errs.New("webauthn: TPM EK credential activation failed | webauthn：TPM EK 凭据激活失败")
	// ErrEKCertificate reports an unacceptable endorsement-key certificate or chain. |
	// ErrEKCertificate 表示背书密钥证书或证书链不可接受。
	ErrEKCertificate = errs.New("webauthn: invalid TPM endorsement-key certificate | webauthn：TPM 背书密钥证书非法")
)
