package kms

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"

	"github.com/shibingli/ydx/errs"
)

// DataKey is a generated data encryption key. | DataKey 是生成的数据加密密钥。
type DataKey struct {
	// Plaintext is the raw DEK. Callers must zero it after use. | Plaintext 是原始 DEK。调用方用完后必须清零。
	Plaintext []byte `json:"plaintext"`
	// Wrapped is the KMSW-wrapped DEK, safe to persist alongside the ciphertext. | Wrapped 是 KMSW
	// 包装的 DEK，可安全地随密文一起保存。
	Wrapped []byte `json:"wrapped"`
	// KeyID is the wrapping key identifier. | KeyID 是包装密钥标识。
	KeyID string `json:"keyId"`
	// KeyVersion is the wrapping key version. | KeyVersion 是包装密钥版本。
	KeyVersion uint32 `json:"keyVersion"`
}

// WrapKey wraps material under the current version of the key named by id. | WrapKey 用 id 对应密钥
// 的当前版本包装 material。
//
// The wrapping key must be symmetric and permit UsageWrapKey. The output is a KMSW blob that binds
// the wrapping key identifier, version and optional associated data. The operation is audited. | 包装
// 密钥必须为对称密钥并允许 UsageWrapKey。输出为 KMSW 数据块，绑定包装密钥标识、版本与可选关联
// 数据。该操作会写入审计。
func (s *Service) WrapKey(ctx context.Context, id string, material, aad []byte) ([]byte, error) {
	if len(material) == 0 {
		err := errs.Detail(ErrInvalidRequest, "empty key material | 密钥材料为空")
		s.fail(ctx, OperationWrapKey, id, 0, err)
		return nil, err
	}
	key, err := s.loadResolvedKey(ctx, id)
	if err != nil {
		s.fail(ctx, OperationWrapKey, id, 0, err)
		return nil, err
	}
	defer key.eraseMaterial()
	version := key.Version
	if err := authorizeUse(key, key.CurrentVersion(), UsageWrapKey); err != nil {
		s.fail(ctx, OperationWrapKey, key.ID, version, err)
		return nil, err
	}
	wrapped, err := s.wrapMaterialForKey(ctx, key, version, material, aad)
	if err != nil {
		s.fail(ctx, OperationWrapKey, key.ID, version, err)
		return nil, err
	}
	s.succeed(ctx, OperationWrapKey, key.ID, version, map[string]string{"type": string(key.Type), "bytes": strconvUint32(uint32(len(material)))})
	return wrapped, nil
}

// UnwrapKey unwraps a KMSW blob produced by WrapKey or GenerateDataKey. | UnwrapKey 解包 WrapKey 或
// GenerateDataKey 产生的 KMSW 数据块。
//
// The blob names the version that wrapped it, so deactivated versions remain usable for unwrapping
// legacy data. A malformed blob returns ErrInvalidCiphertext; tampering returns
// ErrAuthentication. The operation is audited. | 数据块指明包装它的版本，因此已停用版本仍可解包历史
// 数据。格式错误返回 ErrInvalidCiphertext；篡改返回 ErrAuthentication。该操作会写入审计。
func (s *Service) UnwrapKey(ctx context.Context, id string, wrapped, aad []byte) ([]byte, error) {
	parsed, err := parseCipherEnvelope(wrappedMagic, wrapped)
	if err != nil {
		s.fail(ctx, OperationUnwrapKey, id, 0, err)
		return nil, err
	}
	key, err := s.loadResolvedKey(ctx, id)
	if err != nil {
		s.fail(ctx, OperationUnwrapKey, id, parsed.version, err)
		return nil, err
	}
	defer key.eraseMaterial()
	if key.ID != parsed.keyID {
		err := errs.Detail(ErrInvalidCiphertext, "wrapped key names %[1]q, not %[2]q | 包装密钥指定的为 %[1]q，而非 %[2]q", parsed.keyID, key.ID)
		s.fail(ctx, OperationUnwrapKey, key.ID, parsed.version, err)
		return nil, err
	}
	version := key.VersionAt(parsed.version)
	if version == nil {
		err := errs.Detail(ErrVersionNotFound, "key %[1]q version %[2]d | 密钥 %[1]q 版本 %[2]d", key.ID, parsed.version)
		s.fail(ctx, OperationUnwrapKey, key.ID, parsed.version, err)
		return nil, err
	}
	if err := authorizeUse(key, version, UsageUnwrapKey); err != nil {
		s.fail(ctx, OperationUnwrapKey, key.ID, parsed.version, err)
		return nil, err
	}
	plain, err := s.unwrapMaterialForKey(ctx, key, parsed.version, wrapped, aad)
	if err != nil {
		s.fail(ctx, OperationUnwrapKey, key.ID, parsed.version, err)
		return nil, err
	}
	s.succeed(ctx, OperationUnwrapKey, key.ID, parsed.version, map[string]string{"type": string(key.Type), "bytes": strconvUint32(uint32(len(plain)))})
	return plain, nil
}

// GenerateDataKey creates a random DEK and returns both its plaintext and its wrapped form. | GenerateDataKey
// 生成随机 DEK，并返回其明文与包装形式。
//
// length 0 means 32 bytes; the service MaxDataKeyLength caps the output. The wrapping key must permit
// UsageGenerateDataKey. The operation is audited; the plaintext is never logged. | length 为 0 表示
// 32 字节；服务 MaxDataKeyLength 限制输出上限。包装密钥必须允许 UsageGenerateDataKey。该操作会
// 写入审计；明文绝不写入日志。
func (s *Service) GenerateDataKey(ctx context.Context, id string, length int, aad []byte) (*DataKey, error) {
	if length == 0 {
		length = 32
	}
	if err := s.validateDerivedLength(length); err != nil {
		s.fail(ctx, OperationGenerateDataKey, id, 0, err)
		return nil, err
	}
	key, err := s.loadResolvedKey(ctx, id)
	if err != nil {
		s.fail(ctx, OperationGenerateDataKey, id, 0, err)
		return nil, err
	}
	defer key.eraseMaterial()
	version := key.Version
	if err := authorizeUse(key, key.CurrentVersion(), UsageGenerateDataKey); err != nil {
		s.fail(ctx, OperationGenerateDataKey, key.ID, version, err)
		return nil, err
	}
	dek, err := randomBytes(length)
	if err != nil {
		s.fail(ctx, OperationGenerateDataKey, key.ID, version, err)
		return nil, err
	}
	wrapped, err := s.wrapMaterialForKey(ctx, key, version, dek, aad)
	if err != nil {
		zeroBytes(dek)
		s.fail(ctx, OperationGenerateDataKey, key.ID, version, err)
		return nil, err
	}
	s.succeed(ctx, OperationGenerateDataKey, key.ID, version, map[string]string{"type": string(key.Type), "bytes": strconvUint32(uint32(length))})
	return &DataKey{Plaintext: dek, Wrapped: wrapped, KeyID: key.ID, KeyVersion: version}, nil
}

// DeriveKey derives length bytes with HKDF-SHA256 from the current version of the key named by id. | DeriveKey
// 用 HKDF-SHA256 从 id 对应密钥的当前版本派生 length 字节。
//
// info is domain separation between uses. The key must permit UsageDeriveKey. length 0 means 32
// bytes; MaxDataKeyLength caps the output. The operation is audited. | info 用于用途域分离。密钥
// 必须允许 UsageDeriveKey。length 为 0 表示 32 字节；MaxDataKeyLength 限制输出上限。该操作会写入审计。
func (s *Service) DeriveKey(ctx context.Context, id string, length int, info string, salt []byte) ([]byte, error) {
	if length == 0 {
		length = 32
	}
	if err := s.validateDerivedLength(length); err != nil {
		s.fail(ctx, OperationDeriveKey, id, 0, err)
		return nil, err
	}
	key, err := s.loadResolvedKey(ctx, id)
	if err != nil {
		s.fail(ctx, OperationDeriveKey, id, 0, err)
		return nil, err
	}
	defer key.eraseMaterial()
	version := key.Version
	if err := authorizeUse(key, key.CurrentVersion(), UsageDeriveKey); err != nil {
		s.fail(ctx, OperationDeriveKey, key.ID, version, err)
		return nil, err
	}
	material := materialForVersion(key, version)
	if len(material) == 0 {
		err := errs.Detail(ErrInvalidMaterial, "current version has no material | 当前版本没有材料")
		s.fail(ctx, OperationDeriveKey, key.ID, version, err)
		return nil, err
	}
	secret := append([]byte(nil), material...)
	defer zeroBytes(secret)
	out, err := hkdf.Key(sha256.New, secret, salt, info, length)
	if err != nil {
		s.fail(ctx, OperationDeriveKey, key.ID, version, err)
		return nil, errs.WrapDetail(err, ErrInvalidRequest, "HKDF derivation failed | HKDF 派生失败")
	}
	s.succeed(ctx, OperationDeriveKey, key.ID, version, map[string]string{"type": string(key.Type), "bytes": strconvUint32(uint32(length))})
	return out, nil
}

// wrapMaterialForKey seals material under one version of key. | wrapMaterialForKey 在 key 的某个版本下密封 material。
func (s *Service) wrapMaterialForKey(ctx context.Context, key *Key, version uint32, material, aad []byte) ([]byte, error) {
	alg, keyBytes, err := cipherAlgorithmForKey(key, version)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(keyBytes)
	nonce, err := s.newNonce(key.ID, version)
	if err != nil {
		return nil, err
	}
	header := buildCipherHeader(wrappedMagic, alg, key.ID, version, nonce)
	fullAAD := make([]byte, 0, len(header)+len(aad))
	fullAAD = append(fullAAD, header...)
	fullAAD = append(fullAAD, aad...)
	sealed, err := sealAEAD(alg, keyBytes, nonce, material, fullAAD)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(header)+len(sealed))
	out = append(out, header...)
	out = append(out, sealed...)
	return out, nil
}

// unwrapMaterialForKey opens a KMSW blob under one version of key. | unwrapMaterialForKey 在 key 的
// 某个版本下解包 KMSW 数据块。
func (s *Service) unwrapMaterialForKey(ctx context.Context, key *Key, version uint32, wrapped, aad []byte) ([]byte, error) {
	parsed, err := parseCipherEnvelope(wrappedMagic, wrapped)
	if err != nil {
		return nil, err
	}
	if parsed.keyID != key.ID || parsed.version != version {
		return nil, errs.Detail(ErrInvalidCiphertext, "wrapped key metadata mismatch | 包装密钥元数据不匹配")
	}
	alg, keyBytes, err := cipherAlgorithmForKey(key, version)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(keyBytes)
	if parsed.alg != alg {
		return nil, errs.Detail(ErrInvalidCiphertext, "wrapped key algorithm mismatch | 包装密钥算法不匹配")
	}
	fullAAD := make([]byte, 0, parsed.headerLen+len(aad))
	fullAAD = append(fullAAD, wrapped[:parsed.headerLen]...)
	fullAAD = append(fullAAD, aad...)
	return openAEAD(alg, keyBytes, parsed.nonce, parsed.ciphertext, fullAAD)
}

// validateDerivedLength checks a requested output length. | validateDerivedLength 校验请求的输出长度。
func (s *Service) validateDerivedLength(length int) error {
	if length <= 0 || length > s.maxDataKeyLength {
		return errs.Detail(ErrInvalidRequest, "length %[1]d outside 1..%[2]d | 长度 %[1]d 超出 1..%[2]d", length, s.maxDataKeyLength)
	}
	return nil
}
