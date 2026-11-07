package xmlsig

import "github.com/shibingli/ydx/errs"

// Sentinel errors returned by this package. Wrap checks with errors.Is. | 本包返回的哨兵错误。
// 请使用 errors.Is 判定。
var (
	// ErrInvalidXML reports malformed or namespace-ill-formed XML input. | ErrInvalidXML 表示
	// XML 输入格式错误或命名空间不良构。
	ErrInvalidXML = errs.New("xmlsig: invalid XML | xmlsig：XML 非法")
	// ErrUnsupported reports an algorithm, transform or key type that is not implemented. |
	// ErrUnsupported 表示未实现的算法、变换或密钥类型。
	ErrUnsupported = errs.New("xmlsig: unsupported feature | xmlsig：不支持的特性")
	// ErrMalformed reports a structurally invalid Signature or EncryptedData element. |
	// ErrMalformed 表示 Signature 或 EncryptedData 元素结构非法。
	ErrMalformed = errs.New("xmlsig: malformed XML security element | xmlsig：XML 安全元素结构非法")
	// ErrNoSignature reports that no Signature element was found. | ErrNoSignature 表示未找到
	// Signature 元素。
	ErrNoSignature = errs.New("xmlsig: signature not found | xmlsig：未找到签名")
	// ErrMultipleSignatures reports ambiguous signature selection. | ErrMultipleSignatures 表示
	// 签名选择存在歧义。
	ErrMultipleSignatures = errs.New("xmlsig: multiple signatures | xmlsig：存在多个签名")
	// ErrDuplicateID reports duplicate or ambiguous identifier attributes. | ErrDuplicateID 表示
	// 标识属性重复或存在歧义。
	ErrDuplicateID = errs.New("xmlsig: duplicate ID | xmlsig：ID 重复")
	// ErrReference reports an invalid, external or unresolvable reference. | ErrReference 表示
	// 引用非法、指向外部或无法解析。
	ErrReference = errs.New("xmlsig: invalid reference | xmlsig：引用非法")
	// ErrReferenceMismatch reports that a reference does not cover the expected element. |
	// ErrReferenceMismatch 表示引用未覆盖预期元素。
	ErrReferenceMismatch = errs.New("xmlsig: reference does not match the verified element | xmlsig：引用与被校验元素不匹配")
	// ErrDigestMismatch reports that a computed digest differs from DigestValue. | ErrDigestMismatch
	// 表示计算出的摘要与 DigestValue 不一致。
	ErrDigestMismatch = errs.New("xmlsig: digest mismatch | xmlsig：摘要不匹配")
	// ErrSignatureInvalid reports that SignatureValue did not verify. | ErrSignatureInvalid 表示
	// SignatureValue 校验失败。
	ErrSignatureInvalid = errs.New("xmlsig: signature verification failed | xmlsig：签名校验失败")
	// ErrUnsigned reports that a signature has no references. | ErrUnsigned 表示签名不含引用。
	ErrUnsigned = errs.New("xmlsig: no verified reference | xmlsig：没有已验证的引用")
	// ErrAlgorithmNotAllowed reports an algorithm excluded by the caller's allowlist. |
	// ErrAlgorithmNotAllowed 表示算法被调用方的允许列表排除。
	ErrAlgorithmNotAllowed = errs.New("xmlsig: algorithm not allowed | xmlsig：算法不被允许")
	// ErrKeyRequired reports missing key material. | ErrKeyRequired 表示缺少密钥材料。
	ErrKeyRequired = errs.New("xmlsig: key material required | xmlsig：缺少密钥材料")
	// ErrKeyMismatch reports a key that does not fit the algorithm or the certificate. |
	// ErrKeyMismatch 表示密钥与算法或证书不匹配。
	ErrKeyMismatch = errs.New("xmlsig: key does not match the algorithm | xmlsig：密钥与算法不匹配")
	// ErrUntrustedKey reports an embedded key without caller-supplied trust material. |
	// ErrUntrustedKey 表示内嵌密钥缺少调用方提供的信任材料。
	ErrUntrustedKey = errs.New("xmlsig: untrusted embedded key | xmlsig：内嵌密钥不可信")
	// ErrCertificateInvalid reports certificate validity, usage or chain failures. |
	// ErrCertificateInvalid 表示证书有效期、用途或证书链校验失败。
	ErrCertificateInvalid = errs.New("xmlsig: certificate validation failed | xmlsig：证书校验失败")
	// ErrEncrypt reports an encryption failure. | ErrEncrypt 表示加密失败。
	ErrEncrypt = errs.New("xmlsig: encryption failed | xmlsig：加密失败")
	// ErrDecrypt reports a decryption or integrity failure. All causes share one error to avoid
	// padding or authentication oracles. | ErrDecrypt 表示解密或完整性校验失败。所有原因共用同一
	// 错误，以避免填充或认证预言。
	ErrDecrypt = errs.New("xmlsig: decryption failed | xmlsig：解密失败")
	// ErrLimit reports that a configured size limit was exceeded. | ErrLimit 表示超出配置的大小
	// 限制。
	ErrLimit = errs.New("xmlsig: size limit exceeded | xmlsig：超出大小限制")
	// ErrInvalidOption reports an invalid option combination. | ErrInvalidOption 表示选项组合非法。
	ErrInvalidOption = errs.New("xmlsig: invalid option | xmlsig：选项非法")
)
