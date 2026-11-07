package kms

import "github.com/shibingli/ydx/errs"

// The declared sentinels of the kms package. | kms 包声明的哨兵错误。
//
// Every failure path returns one of them directly or through errs.Detail / errs.Wrap, so callers
// can classify errors with errors.Is without matching message text. Error messages never contain
// key material, plaintext, passphrases or wrapped DEKs. | 所有失败路径都直接返回其中之一，或经由
// errs.Detail / errs.Wrap 包装，因此调用方可用 errors.Is 分类错误而无需匹配文案。错误文案绝不
// 包含密钥材料、明文、口令或已包装 DEK。
var (
	// ErrInvalidConfig reports a missing or contradictory service configuration. | ErrInvalidConfig 表示服务配置缺失或相互矛盾。
	ErrInvalidConfig = errs.New("kms: invalid configuration | kms：配置非法")
	// ErrInvalidRequest reports malformed caller input. | ErrInvalidRequest 表示调用方输入非法。
	ErrInvalidRequest = errs.New("kms: invalid request | kms：请求非法")
	// ErrNotFound reports an unknown key identifier. | ErrNotFound 表示密钥标识不存在。
	ErrNotFound = errs.New("kms: key not found | kms：密钥不存在")
	// ErrKeyExists reports a duplicate key identifier. | ErrKeyExists 表示密钥标识重复。
	ErrKeyExists = errs.New("kms: key already exists | kms：密钥已存在")
	// ErrAliasExists reports an alias already bound to another key. | ErrAliasExists 表示别名已绑定到其它密钥。
	ErrAliasExists = errs.New("kms: alias already exists | kms：别名已存在")
	// ErrAliasNotFound reports an unknown alias. | ErrAliasNotFound 表示别名不存在。
	ErrAliasNotFound = errs.New("kms: alias not found | kms：别名不存在")
	// ErrConflict reports an optimistic-concurrency conflict on a key revision. | ErrConflict 表示密钥修订号的乐观并发冲突。
	ErrConflict = errs.New("kms: optimistic concurrency conflict | kms：乐观并发冲突")
	// ErrInvalidState reports an illegal key lifecycle transition. | ErrInvalidState 表示非法的密钥生命周期转换。
	ErrInvalidState = errs.New("kms: invalid key state transition | kms：密钥状态转换非法")
	// ErrKeyNotUsable reports a cryptographic operation against a key whose state forbids it. | ErrKeyNotUsable 表示密钥当前状态禁止该密码操作。
	ErrKeyNotUsable = errs.New("kms: key is not usable in its current state | kms：密钥在当前状态不可用")
	// ErrUsageNotAllowed reports an operation outside the key usage mask. | ErrUsageNotAllowed 表示操作超出了密钥用途掩码。
	ErrUsageNotAllowed = errs.New("kms: key usage does not permit this operation | kms：密钥用途不允许该操作")
	// ErrInvalidKeyType reports a key type that cannot perform the requested operation. | ErrInvalidKeyType 表示密钥类型无法执行所请求的操作。
	ErrInvalidKeyType = errs.New("kms: invalid key type for this operation | kms：该操作不支持此密钥类型")
	// ErrInvalidKeySize reports an unsupported or weak key size. | ErrInvalidKeySize 表示密钥长度不受支持或过弱。
	ErrInvalidKeySize = errs.New("kms: invalid or weak key size | kms：密钥长度非法或过弱")
	// ErrInvalidMaterial reports missing, malformed or mismatched key material. | ErrInvalidMaterial 表示密钥材料缺失、格式错误或与类型不匹配。
	ErrInvalidMaterial = errs.New("kms: invalid key material | kms：密钥材料非法")
	// ErrInvalidCiphertext reports a malformed, truncated or tampered ciphertext envelope. | ErrInvalidCiphertext 表示密文封装格式错误、被截断或被篡改。
	ErrInvalidCiphertext = errs.New("kms: invalid ciphertext | kms：密文非法")
	// ErrAuthentication reports a failed authenticated-encryption or signature check. | ErrAuthentication 表示认证加密或签名校验失败。
	ErrAuthentication = errs.New("kms: authentication failed | kms：认证失败")
	// ErrExportDenied reports a key export refused by policy. | ErrExportDenied 表示密钥导出被策略拒绝。
	ErrExportDenied = errs.New("kms: key export denied | kms：密钥导出被拒绝")
	// ErrNotSupported reports an operation the key type or deployment does not support. | ErrNotSupported 表示密钥类型或部署不支持该操作。
	ErrNotSupported = errs.New("kms: operation not supported | kms：不支持该操作")
	// ErrNonceReuse reports a repeated nonce detected before encryption. | ErrNonceReuse 表示加密前检测到 nonce 重复。
	ErrNonceReuse = errs.New("kms: nonce reuse detected | kms：检测到 nonce 重用")
	// ErrRandomSource reports a failure while reading cryptographically secure randomness. | ErrRandomSource 表示读取密码学安全随机数失败。
	ErrRandomSource = errs.New("kms: random source failure | kms：随机源失败")
	// ErrVersionNotFound reports an unknown key version. | ErrVersionNotFound 表示密钥版本不存在。
	ErrVersionNotFound = errs.New("kms: key version not found | kms：密钥版本不存在")
	// ErrVersionExists reports a duplicate key version. | ErrVersionExists 表示密钥版本重复。
	ErrVersionExists = errs.New("kms: key version already exists | kms：密钥版本已存在")
	// ErrStoreUnavailable reports a backend persistence failure. | ErrStoreUnavailable 表示后端持久化故障。
	ErrStoreUnavailable = errs.New("kms: store unavailable | kms：存储不可用")
	// ErrUnauthorized reports a missing or invalid authentication context. | ErrUnauthorized 表示缺少或无效的认证上下文。
	ErrUnauthorized = errs.New("kms: unauthorized | kms：未认证")
	// ErrForbidden reports an authenticated caller without the required permission. | ErrForbidden 表示调用方已认证但缺少所需权限。
	ErrForbidden = errs.New("kms: forbidden | kms：禁止访问")
)
