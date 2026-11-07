package kms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/guomi"
	"golang.org/x/crypto/chacha20poly1305"
)

// cipherAlgorithm encodes the AEAD construction inside a ciphertext header. | cipherAlgorithm 在
// 密文头部编码 AEAD 构造。
type cipherAlgorithm byte

// The AEAD identifiers of the wire format. Values are stable and may not be reused. | 线格式的
// AEAD 标识。取值稳定，不得复用。
const (
	// algAES128GCM identifies AES-128-GCM. | algAES128GCM 标识 AES-128-GCM。
	algAES128GCM cipherAlgorithm = 1
	// algAES192GCM identifies AES-192-GCM. | algAES192GCM 标识 AES-192-GCM。
	algAES192GCM cipherAlgorithm = 2
	// algAES256GCM identifies AES-256-GCM. | algAES256GCM 标识 AES-256-GCM。
	algAES256GCM cipherAlgorithm = 3
	// algChaCha20Poly1305 identifies ChaCha20-Poly1305. | algChaCha20Poly1305 标识 ChaCha20-Poly1305。
	algChaCha20Poly1305 cipherAlgorithm = 4
	// algSM4GCM identifies SM4-GCM. | algSM4GCM 标识 SM4-GCM。
	algSM4GCM cipherAlgorithm = 5
)

// cipherAlgorithmLabel returns a stable exporter label for alg. | cipherAlgorithmLabel 返回 alg 的稳定标签。
func cipherAlgorithmLabel(alg cipherAlgorithm) string {
	switch alg {
	case algAES128GCM:
		return "AES-128-GCM"
	case algAES192GCM:
		return "AES-192-GCM"
	case algAES256GCM:
		return "AES-256-GCM"
	case algChaCha20Poly1305:
		return "ChaCha20-Poly1305"
	case algSM4GCM:
		return "SM4-GCM"
	default:
		return "unknown"
	}
}

// cipherAlgorithmForKey derives the AEAD identifier and a private copy of the key material for a
// key and version. | cipherAlgorithmForKey 为密钥与版本推导 AEAD 标识和密钥材料的私有副本。
//
// The caller must zero the returned material after use. | 调用方用完后必须清零返回的材料。
func cipherAlgorithmForKey(key *Key, version uint32) (cipherAlgorithm, []byte, error) {
	if key == nil {
		return 0, nil, ErrNotFound
	}
	material := materialForVersion(key, version)
	if len(material) == 0 {
		return 0, nil, errs.Detail(ErrInvalidMaterial, "version %[1]d has no material | 版本 %[1]d 没有材料", version)
	}
	out := append([]byte(nil), material...)
	switch key.Type {
	case KeyTypeAES:
		switch len(out) {
		case 16:
			return algAES128GCM, out, nil
		case 24:
			return algAES192GCM, out, nil
		case 32:
			return algAES256GCM, out, nil
		default:
			zeroBytes(out)
			return 0, nil, errs.Detail(ErrInvalidKeySize, "AES material is %[1]d bytes | AES 材料为 %[1]d 字节", len(out))
		}
	case KeyTypeChaCha20:
		if len(out) != chacha20poly1305.KeySize {
			zeroBytes(out)
			return 0, nil, errs.Detail(ErrInvalidKeySize, "ChaCha20 material is %[1]d bytes | ChaCha20 材料为 %[1]d 字节", len(out))
		}
		return algChaCha20Poly1305, out, nil
	case KeyTypeSM4:
		if len(out) != guomi.SM4KeySize {
			zeroBytes(out)
			return 0, nil, errs.Detail(ErrInvalidKeySize, "SM4 material is %[1]d bytes | SM4 材料为 %[1]d 字节", len(out))
		}
		return algSM4GCM, out, nil
	default:
		zeroBytes(out)
		return 0, nil, errs.Detail(ErrInvalidKeyType, "type %[1]q cannot encrypt | 类型 %[1]q 无法加密", key.Type)
	}
}

// sealAEAD encrypts plaintext with alg and a fresh 96-bit nonce already chosen by the caller. | sealAEAD
// 用 alg 与调用方已选定的 96 位新 nonce 加密 plaintext。
func sealAEAD(alg cipherAlgorithm, key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(nonce) != gcmNonceSize {
		return nil, errs.Detail(ErrInvalidMaterial, "AEAD nonce must be %[1]d bytes | AEAD nonce 必须为 %[1]d 字节", gcmNonceSize)
	}
	switch alg {
	case algAES128GCM, algAES192GCM, algAES256GCM:
		aead, err := newAESGCM(key)
		if err != nil {
			return nil, err
		}
		return aead.Seal(nil, nonce, plaintext, aad), nil
	case algChaCha20Poly1305:
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidMaterial, "build ChaCha20-Poly1305 | 构建 ChaCha20-Poly1305")
		}
		return aead.Seal(nil, nonce, plaintext, aad), nil
	case algSM4GCM:
		out, err := guomi.SealGCM(key, nonce, plaintext, aad)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidMaterial, "SM4-GCM seal | SM4-GCM 加密")
		}
		return out, nil
	default:
		return nil, errs.Detail(ErrNotSupported, "AEAD algorithm %[1]d | AEAD 算法 %[1]d", alg)
	}
}

// openAEAD decrypts ciphertext with alg. Authentication failures wrap ErrAuthentication. | openAEAD
// 用 alg 解密 ciphertext。认证失败会包装 ErrAuthentication。
func openAEAD(alg cipherAlgorithm, key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != gcmNonceSize {
		return nil, errs.Detail(ErrInvalidMaterial, "AEAD nonce must be %[1]d bytes | AEAD nonce 必须为 %[1]d 字节", gcmNonceSize)
	}
	switch alg {
	case algAES128GCM, algAES192GCM, algAES256GCM:
		aead, err := newAESGCM(key)
		if err != nil {
			return nil, err
		}
		plain, err := aead.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrAuthentication, "AES-GCM authentication failed | AES-GCM 认证失败")
		}
		return plain, nil
	case algChaCha20Poly1305:
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidMaterial, "build ChaCha20-Poly1305 | 构建 ChaCha20-Poly1305")
		}
		plain, err := aead.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrAuthentication, "ChaCha20-Poly1305 authentication failed | ChaCha20-Poly1305 认证失败")
		}
		return plain, nil
	case algSM4GCM:
		plain, err := guomi.OpenGCM(key, nonce, ciphertext, aad)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrAuthentication, "SM4-GCM authentication failed | SM4-GCM 认证失败")
		}
		return plain, nil
	default:
		return nil, errs.Detail(ErrNotSupported, "AEAD algorithm %[1]d | AEAD 算法 %[1]d", alg)
	}
}

// newAESGCM builds an AES-GCM instance for a 16-, 24- or 32-byte key. | newAESGCM 为 16、24 或 32
// 字节密钥构建 AES-GCM 实例。
func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidMaterial, "build AES cipher | 构建 AES 密码")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidMaterial, "build AES-GCM | 构建 AES-GCM")
	}
	return aead, nil
}

// newNonce returns a fresh, never-before-used nonce for keyID/version. | newNonce 为 keyID/version
// 返回从未使用过的新 nonce。
func (s *Service) newNonce(keyID string, version uint32) ([]byte, error) {
	for attempt := 0; attempt < 16; attempt++ {
		nonce, err := randomBytes(gcmNonceSize)
		if err != nil {
			return nil, err
		}
		if s.rememberNonce(keyID, version, nonce) {
			return nonce, nil
		}
	}
	return nil, ErrNonceReuse
}

// Encrypt encrypts plaintext with the current version of the key named by id. | Encrypt 用 id 对应
// 密钥的当前版本加密 plaintext。
//
// The output is a self-describing KMS1 envelope: the key identifier and version are authenticated
// and carried in the clear, so Decrypt can select the right version after rotation. aad is optional
// associated data authenticated with the ciphertext. | 输出是自描述 KMS1 信封：密钥标识与版本在
// 明文头中携带并受认证，因此轮换后 Decrypt 仍能选择正确版本。aad 是随密文认证的可选关联数据。
func (s *Service) Encrypt(ctx context.Context, id string, plaintext, aad []byte) ([]byte, error) {
	key, err := s.loadResolvedKey(ctx, id)
	if err != nil {
		s.fail(ctx, OperationEncrypt, id, 0, err)
		return nil, err
	}
	defer key.eraseMaterial()
	version := key.Version
	if err := authorizeUse(key, key.CurrentVersion(), UsageEncrypt); err != nil {
		s.fail(ctx, OperationEncrypt, key.ID, version, err)
		return nil, err
	}
	alg, material, err := cipherAlgorithmForKey(key, version)
	if err != nil {
		s.fail(ctx, OperationEncrypt, key.ID, version, err)
		return nil, err
	}
	defer zeroBytes(material)
	nonce, err := s.newNonce(key.ID, version)
	if err != nil {
		s.fail(ctx, OperationEncrypt, key.ID, version, err)
		return nil, err
	}
	header := buildCipherHeader(cipherMagic, alg, key.ID, version, nonce)
	fullAAD := make([]byte, 0, len(header)+len(aad))
	fullAAD = append(fullAAD, header...)
	fullAAD = append(fullAAD, aad...)
	sealed, err := sealAEAD(alg, material, nonce, plaintext, fullAAD)
	if err != nil {
		s.fail(ctx, OperationEncrypt, key.ID, version, err)
		return nil, err
	}
	out := make([]byte, 0, len(header)+len(sealed))
	out = append(out, header...)
	out = append(out, sealed...)
	s.succeed(ctx, OperationEncrypt, key.ID, version, map[string]string{"type": string(key.Type), "algorithm": cipherAlgorithmLabel(alg)})
	return out, nil
}

// Decrypt decrypts a KMS1 envelope produced by Encrypt. | Decrypt 解密 Encrypt 产生的 KMS1 信封。
//
// id may be the key identifier or alias and must resolve to the key named inside the envelope;
// a mismatch returns ErrInvalidCiphertext. Corrupted or tampered ciphertext returns
// ErrAuthentication. The operation is audited. | id 可为密钥标识或别名，且必须解析为信封内命名
// 的密钥；不匹配返回 ErrInvalidCiphertext。损坏或被篡改的密文返回 ErrAuthentication。该操作会
// 写入审计。
func (s *Service) Decrypt(ctx context.Context, id string, ciphertext, aad []byte) ([]byte, error) {
	envelope, err := parseCipherEnvelope(cipherMagic, ciphertext)
	if err != nil {
		s.fail(ctx, OperationDecrypt, id, 0, err)
		return nil, err
	}
	key, err := s.loadResolvedKey(ctx, id)
	if err != nil {
		s.fail(ctx, OperationDecrypt, id, envelope.version, err)
		return nil, err
	}
	defer key.eraseMaterial()
	if key.ID != envelope.keyID {
		err := errs.Detail(ErrInvalidCiphertext, "envelope names key %[1]q, not %[2]q | 信封指定的密钥为 %[1]q，而非 %[2]q", envelope.keyID, key.ID)
		s.fail(ctx, OperationDecrypt, key.ID, envelope.version, err)
		return nil, err
	}
	version := key.VersionAt(envelope.version)
	if version == nil {
		err := errs.Detail(ErrVersionNotFound, "key %[1]q version %[2]d | 密钥 %[1]q 版本 %[2]d", key.ID, envelope.version)
		s.fail(ctx, OperationDecrypt, key.ID, envelope.version, err)
		return nil, err
	}
	if err := authorizeUse(key, version, UsageDecrypt); err != nil {
		s.fail(ctx, OperationDecrypt, key.ID, envelope.version, err)
		return nil, err
	}
	alg, material, err := cipherAlgorithmForKey(key, envelope.version)
	if err != nil {
		s.fail(ctx, OperationDecrypt, key.ID, envelope.version, err)
		return nil, err
	}
	defer zeroBytes(material)
	if alg != envelope.alg {
		err := errs.Detail(ErrInvalidCiphertext, "envelope algorithm %[1]s, key algorithm %[2]s | 信封算法 %[1]s，密钥算法 %[2]s", cipherAlgorithmLabel(envelope.alg), cipherAlgorithmLabel(alg))
		s.fail(ctx, OperationDecrypt, key.ID, envelope.version, err)
		return nil, err
	}
	fullAAD := make([]byte, 0, envelope.headerLen+len(aad))
	fullAAD = append(fullAAD, ciphertext[:envelope.headerLen]...)
	fullAAD = append(fullAAD, aad...)
	plain, err := openAEAD(alg, material, envelope.nonce, envelope.ciphertext, fullAAD)
	if err != nil {
		s.fail(ctx, OperationDecrypt, key.ID, envelope.version, err)
		return nil, err
	}
	s.succeed(ctx, OperationDecrypt, key.ID, envelope.version, map[string]string{"type": string(key.Type), "algorithm": cipherAlgorithmLabel(alg)})
	return plain, nil
}
