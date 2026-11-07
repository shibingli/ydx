package kmip

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"hash"
	"io"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/guomi"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// ecdsaSign returns an ASN.1 DER encoded ECDSA signature. | ecdsaSign 返回 ASN.1 DER 编码的 ECDSA 签名。
func ecdsaSign(private *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	sig, err := ecdsa.SignASN1(rand.Reader, private, digest)
	if err != nil {
		return nil, errs.Wrap(err, ErrCryptographic)
	}
	return sig, nil
}

// ecdsaVerify reports whether the ASN.1 DER signature is valid. | ecdsaVerify 报告 ASN.1 DER 签名是否有效。
func ecdsaVerify(public *ecdsa.PublicKey, digest, signature []byte) bool {
	return ecdsa.VerifyASN1(public, digest, signature)
}

// hashFactory returns the constructor and identifier of a hashing algorithm. | hashFactory 返回哈希算法的构造函数与标识。
func hashFactory(algorithm HashingAlgorithm) (func() hash.Hash, crypto.Hash, error) {
	switch algorithm {
	case HashingAlgorithmSHA1:
		return sha1.New, crypto.SHA1, nil
	case HashingAlgorithmSHA224:
		return sha256.New224, crypto.SHA224, nil
	case HashingAlgorithmSHA256, 0:
		return sha256.New, crypto.SHA256, nil
	case HashingAlgorithmSHA384:
		return sha512.New384, crypto.SHA384, nil
	case HashingAlgorithmSHA512:
		return sha512.New, crypto.SHA512, nil
	case HashingAlgorithmSHA512_224:
		return sha512.New512_224, crypto.SHA512_224, nil
	case HashingAlgorithmSHA512_256:
		return sha512.New512_256, crypto.SHA512_256, nil
	case HashingAlgorithmSM3:
		return guomi.New, 0, nil
	default:
		return nil, 0, errs.Detail(ErrUnsupported, "unsupported hashing algorithm 0x%08X | 不支持的哈希算法 0x%08X", uint32(algorithm), uint32(algorithm))
	}
}

// digestData returns the supplied digest or hashes data with the requested algorithm. | digestData 返回提供的摘要，或使用请求的算法哈希 data。
func digestData(algorithm HashingAlgorithm, data, digested []byte) ([]byte, crypto.Hash, error) {
	factory, id, err := hashFactory(algorithm)
	if err != nil {
		return nil, 0, err
	}
	if digested != nil {
		return digested, id, nil
	}
	h := factory()
	_, _ = h.Write(data)
	return h.Sum(nil), id, nil
}

// signatureHash selects the hash for a signature request. | signatureHash 为签名请求选择哈希。
func signatureHash(p CryptographicParameters, algorithm CryptographicAlgorithm) (HashingAlgorithm, error) {
	if p.HashingAlgorithm != 0 {
		return p.HashingAlgorithm, nil
	}
	switch p.DigitalSignatureAlgorithm {
	case DigitalSignatureRSAPKCS1SHA256, DigitalSignatureECDSASHA256:
		return HashingAlgorithmSHA256, nil
	case DigitalSignatureRSAPKCS1SHA384, DigitalSignatureECDSASHA384:
		return HashingAlgorithmSHA384, nil
	case DigitalSignatureRSAPKCS1SHA512, DigitalSignatureECDSASHA512:
		return HashingAlgorithmSHA512, nil
	case DigitalSignatureRSAPSS:
		return HashingAlgorithmSHA256, nil
	case DigitalSignatureEd25519, DigitalSignatureSM2SM3:
		return 0, nil
	}
	switch algorithm {
	case AlgorithmEd25519, AlgorithmSM2:
		return 0, nil
	default:
		return HashingAlgorithmSHA256, nil
	}
}

// createBlockCipher builds an AES or SM4 block cipher from a parsed key. | createBlockCipher 从已解析密钥构造 AES 或 SM4 分组密码。
func createBlockCipher(key *parsedKey) (cipher.Block, []byte, error) {
	if len(key.symmetric) == 0 {
		return nil, nil, errs.Detail(ErrCryptographic, "key is not a symmetric key | 密钥不是对称密钥")
	}
	switch key.algorithm {
	case AlgorithmAES:
		block, err := aes.NewCipher(key.symmetric)
		if err != nil {
			return nil, nil, errs.Wrap(err, ErrCryptographic)
		}
		return block, key.symmetric, nil
	case AlgorithmSM4:
		block, err := guomi.NewCipher(key.symmetric)
		if err != nil {
			return nil, nil, errs.Wrap(err, ErrCryptographic)
		}
		return block, key.symmetric, nil
	default:
		return nil, nil, errs.Detail(ErrUnsupported, "algorithm %s is not a block cipher | 算法 %s 不是分组密码", key.algorithm, key.algorithm)
	}
}

// maxGCMNonceLength bounds an externally supplied GCM nonce length so a single wire field cannot request an
// unbounded allocation. | maxGCMNonceLength 限制外部提供的 GCM nonce 长度，避免单个线上字段请求无界分配。
const maxGCMNonceLength = 1024

// gcmNonceLength validates and defaults the configured GCM nonce length. | gcmNonceLength 校验并补全配置的 GCM nonce 长度。
func gcmNonceLength(configured int) (int, error) {
	nonceLen := configured
	if nonceLen == 0 {
		nonceLen = 12
	}
	if nonceLen < 0 || nonceLen > maxGCMNonceLength {
		return 0, errs.Detail(ErrInvalidRequest, "invalid GCM nonce length %d | GCM nonce 长度 %d 非法", configured, configured)
	}
	return nonceLen, nil
}

// newGCM builds a GCM AEAD with the requested nonce and tag sizes. | newGCM 使用请求的 nonce 与标签长度构造 GCM AEAD。
func newGCM(block cipher.Block, nonceLen, tagLen int) (cipher.AEAD, error) {
	if nonceLen == 0 {
		nonceLen = 12
	}
	if tagLen == 0 {
		tagLen = 16
	}
	if nonceLen == 12 {
		if tagLen == 16 {
			return cipher.NewGCM(block)
		}
		return cipher.NewGCMWithTagSize(block, tagLen)
	}
	if tagLen != 16 {
		return nil, errs.Detail(ErrUnsupported, "custom GCM nonce and tag lengths cannot be combined | 不能同时自定义 GCM nonce 与标签长度")
	}
	return cipher.NewGCMWithNonceSize(block, nonceLen)
}

// pkcs7Pad appends PKCS#7 padding. | pkcs7Pad 追加 PKCS#7 填充。
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+padding)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(padding)
	}
	return out
}

// pkcs7Unpad removes and validates PKCS#7 padding. | pkcs7Unpad 移除并校验 PKCS#7 填充。
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errs.Detail(ErrCryptographic, "invalid padded data length | 填充数据长度非法")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > blockSize || padding > len(data) {
		return nil, errs.Detail(ErrCryptographic, "invalid PKCS#7 padding | PKCS#7 填充非法")
	}
	for _, b := range data[len(data)-padding:] {
		if int(b) != padding {
			return nil, errs.Detail(ErrCryptographic, "invalid PKCS#7 padding | PKCS#7 填充非法")
		}
	}
	return data[:len(data)-padding], nil
}

// encryptKeyBlock encrypts data with a key block and cryptographic parameters. | encryptKeyBlock 使用密钥块与密码参数加密 data。
//
// It returns the ciphertext, the IV used and, for AEAD modes, the authentication tag. | 返回密文、使用的 IV，以及 AEAD 模式的认证标签。
func encryptKeyBlock(kb KeyBlock, params CryptographicParameters, data, iv, aad []byte) ([]byte, []byte, []byte, error) {
	key, err := parseKeyBlock(kb)
	if err != nil {
		return nil, nil, nil, err
	}
	defer key.zeroize()
	switch key.algorithm {
	case AlgorithmAES, AlgorithmSM4:
		block, _, err := createBlockCipher(key)
		if err != nil {
			return nil, nil, nil, err
		}
		mode := params.BlockCipherMode
		if mode == 0 {
			mode = BlockCipherModeGCM
		}
		switch mode {
		case BlockCipherModeGCM:
			nonceLen, err := gcmNonceLength(params.IVLength)
			if err != nil {
				return nil, nil, nil, err
			}
			if len(iv) == 0 {
				iv = make([]byte, nonceLen)
				if _, err := rand.Read(iv); err != nil {
					return nil, nil, nil, errs.Wrap(err, ErrCryptographic)
				}
			}
			if len(iv) != nonceLen {
				return nil, nil, nil, errs.Detail(ErrInvalidRequest, "GCM IV length %d does not match %d | GCM IV 长度 %d 与 %d 不一致", len(iv), nonceLen, len(iv), nonceLen)
			}
			aead, err := newGCM(block, nonceLen, params.TagLength)
			if err != nil {
				return nil, nil, nil, errs.Wrap(err, ErrCryptographic)
			}
			full := aead.Seal(nil, iv, data, aad)
			tagLen := params.TagLength
			if tagLen == 0 {
				tagLen = 16
			}
			if len(full) < tagLen {
				return nil, nil, nil, errs.Detail(ErrCryptographic, "AEAD output is shorter than its tag | AEAD 输出短于标签")
			}
			split := len(full) - tagLen
			return full[:split], iv, full[split:], nil
		case BlockCipherModeCBC:
			if len(iv) == 0 {
				iv = make([]byte, block.BlockSize())
				if _, err := rand.Read(iv); err != nil {
					return nil, nil, nil, errs.Wrap(err, ErrCryptographic)
				}
			}
			if len(iv) != block.BlockSize() {
				return nil, nil, nil, errs.Detail(ErrInvalidRequest, "CBC IV length %d does not match %d | CBC IV 长度 %d 与 %d 不一致", len(iv), block.BlockSize(), len(iv), block.BlockSize())
			}
			plain := data
			var padded []byte
			switch params.PaddingMethod {
			case 0, PaddingMethodPKCS5:
				padded = pkcs7Pad(data, block.BlockSize())
				plain = padded
			case PaddingMethodNone:
				if len(data)%block.BlockSize() != 0 {
					return nil, nil, nil, errs.Detail(ErrInvalidRequest, "data length is not a multiple of the block size | 数据长度不是分组长度的倍数")
				}
			default:
				return nil, nil, nil, errs.Detail(ErrUnsupported, "unsupported CBC padding method 0x%08X | 不支持的 CBC 填充方法 0x%08X", uint32(params.PaddingMethod), uint32(params.PaddingMethod))
			}
			out := make([]byte, len(plain))
			cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
			zeroize(padded)
			return out, iv, nil, nil
		case BlockCipherModeCTR:
			if len(iv) == 0 {
				iv = make([]byte, block.BlockSize())
				if _, err := rand.Read(iv); err != nil {
					return nil, nil, nil, errs.Wrap(err, ErrCryptographic)
				}
			}
			if len(iv) != block.BlockSize() {
				return nil, nil, nil, errs.Detail(ErrInvalidRequest, "CTR IV length %d does not match %d | CTR IV 长度 %d 与 %d 不一致", len(iv), block.BlockSize(), len(iv), block.BlockSize())
			}
			out := make([]byte, len(data))
			cipher.NewCTR(block, iv).XORKeyStream(out, data)
			return out, iv, nil, nil
		case BlockCipherModeCFB:
			if len(iv) == 0 {
				iv = make([]byte, block.BlockSize())
				if _, err := rand.Read(iv); err != nil {
					return nil, nil, nil, errs.Wrap(err, ErrCryptographic)
				}
			}
			if len(iv) != block.BlockSize() {
				return nil, nil, nil, errs.Detail(ErrInvalidRequest, "CFB IV length %d does not match %d | CFB IV 长度 %d 与 %d 不一致", len(iv), block.BlockSize(), len(iv), block.BlockSize())
			}
			out := make([]byte, len(data))
			// KMIP 1.4 requires CFB; the standard library deprecates it but it remains the interoperable
			// primitive for this mode. | KMIP 1.4 要求 CFB；标准库已弃用，但它仍是该模式的互操作原语。
			cipher.NewCFBEncrypter(block, iv).XORKeyStream(out, data) //nolint:staticcheck // KMIP requires CFB.
			return out, iv, nil, nil
		case BlockCipherModeOFB:
			if len(iv) == 0 {
				iv = make([]byte, block.BlockSize())
				if _, err := rand.Read(iv); err != nil {
					return nil, nil, nil, errs.Wrap(err, ErrCryptographic)
				}
			}
			if len(iv) != block.BlockSize() {
				return nil, nil, nil, errs.Detail(ErrInvalidRequest, "OFB IV length %d does not match %d | OFB IV 长度 %d 与 %d 不一致", len(iv), block.BlockSize(), len(iv), block.BlockSize())
			}
			out := make([]byte, len(data))
			// KMIP 1.4 requires OFB; the standard library deprecates it but it remains the interoperable
			// primitive for this mode. | KMIP 1.4 要求 OFB；标准库已弃用，但它仍是该模式的互操作原语。
			cipher.NewOFB(block, iv).XORKeyStream(out, data) //nolint:staticcheck // KMIP requires OFB.
			return out, iv, nil, nil
		default:
			return nil, nil, nil, errs.Detail(ErrUnsupported, "unsupported block cipher mode 0x%08X | 不支持的分组密码模式 0x%08X", uint32(mode), uint32(mode))
		}
	case AlgorithmRSA:
		if key.rsaPublic == nil {
			return nil, nil, nil, errs.Detail(ErrCryptographic, "RSA encryption requires a public key | RSA 加密需要公钥")
		}
		switch params.PaddingMethod {
		case PaddingMethodPKCS1V15:
			// PKCS#1 v1.5 encryption is retained only because KMIP RSA key transport uses it; OAEP is the
			// default. The algorithm allowlist above restricts this path to RSA keys. | 保留 PKCS#1 v1.5
			// 加密仅因 KMIP RSA 密钥传输需要；默认使用 OAEP。上面的算法白名单把该路径限制为 RSA 密钥。
			out, err := rsa.EncryptPKCS1v15(rand.Reader, key.rsaPublic, data) //nolint:staticcheck // KMIP RSA key transport requires PKCS#1 v1.5.
			if err != nil {
				return nil, nil, nil, errs.Wrap(err, ErrCryptographic)
			}
			return out, nil, nil, nil
		case 0, PaddingMethodOAEP:
			hashAlg := params.HashingAlgorithm
			if hashAlg == 0 {
				hashAlg = HashingAlgorithmSHA256
			}
			factory, _, err := hashFactory(hashAlg)
			if err != nil {
				return nil, nil, nil, err
			}
			out, err := rsa.EncryptOAEP(factory(), rand.Reader, key.rsaPublic, data, nil)
			if err != nil {
				return nil, nil, nil, errs.Wrap(err, ErrCryptographic)
			}
			return out, nil, nil, nil
		default:
			return nil, nil, nil, errs.Detail(ErrUnsupported, "unsupported RSA padding method 0x%08X | 不支持的 RSA 填充方法 0x%08X", uint32(params.PaddingMethod), uint32(params.PaddingMethod))
		}
	default:
		return nil, nil, nil, errs.Detail(ErrUnsupported, "algorithm %s does not support encryption | 算法 %s 不支持加密", key.algorithm, key.algorithm)
	}
}

// decryptKeyBlock decrypts data with a key block and cryptographic parameters. | decryptKeyBlock 使用密钥块与密码参数解密 data。
func decryptKeyBlock(kb KeyBlock, params CryptographicParameters, data, iv, tag, aad []byte) ([]byte, error) {
	key, err := parseKeyBlock(kb)
	if err != nil {
		return nil, err
	}
	defer key.zeroize()
	switch key.algorithm {
	case AlgorithmAES, AlgorithmSM4:
		block, _, err := createBlockCipher(key)
		if err != nil {
			return nil, err
		}
		mode := params.BlockCipherMode
		if mode == 0 {
			mode = BlockCipherModeGCM
		}
		switch mode {
		case BlockCipherModeGCM:
			nonceLen, err := gcmNonceLength(params.IVLength)
			if err != nil {
				return nil, err
			}
			if len(iv) != nonceLen {
				return nil, errs.Detail(ErrInvalidRequest, "GCM IV length %d does not match %d | GCM IV 长度 %d 与 %d 不一致", len(iv), nonceLen, len(iv), nonceLen)
			}
			aead, err := newGCM(block, nonceLen, params.TagLength)
			if err != nil {
				return nil, errs.Wrap(err, ErrCryptographic)
			}
			full := make([]byte, 0, len(data)+len(tag))
			full = append(full, data...)
			full = append(full, tag...)
			out, err := aead.Open(nil, iv, full, aad)
			if err != nil {
				return nil, errs.Wrap(err, ErrCryptographic)
			}
			return out, nil
		case BlockCipherModeCBC:
			if len(iv) != block.BlockSize() {
				return nil, errs.Detail(ErrInvalidRequest, "CBC IV length %d does not match %d | CBC IV 长度 %d 与 %d 不一致", len(iv), block.BlockSize(), len(iv), block.BlockSize())
			}
			if len(data) == 0 || len(data)%block.BlockSize() != 0 {
				return nil, errs.Detail(ErrCryptographic, "CBC ciphertext length is not a multiple of the block size | CBC 密文长度不是分组长度的倍数")
			}
			out := make([]byte, len(data))
			cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
			switch params.PaddingMethod {
			case 0, PaddingMethodPKCS5:
				return pkcs7Unpad(out, block.BlockSize())
			case PaddingMethodNone:
				return out, nil
			default:
				return nil, errs.Detail(ErrUnsupported, "unsupported CBC padding method 0x%08X | 不支持的 CBC 填充方法 0x%08X", uint32(params.PaddingMethod), uint32(params.PaddingMethod))
			}
		case BlockCipherModeCTR:
			if len(iv) != block.BlockSize() {
				return nil, errs.Detail(ErrInvalidRequest, "CTR IV length %d does not match %d | CTR IV 长度 %d 与 %d 不一致", len(iv), block.BlockSize(), len(iv), block.BlockSize())
			}
			out := make([]byte, len(data))
			cipher.NewCTR(block, iv).XORKeyStream(out, data)
			return out, nil
		case BlockCipherModeCFB:
			if len(iv) != block.BlockSize() {
				return nil, errs.Detail(ErrInvalidRequest, "CFB IV length %d does not match %d | CFB IV 长度 %d 与 %d 不一致", len(iv), block.BlockSize(), len(iv), block.BlockSize())
			}
			out := make([]byte, len(data))
			// KMIP 1.4 requires CFB; see the encryption path. | KMIP 1.4 要求 CFB；参见加密路径。
			cipher.NewCFBDecrypter(block, iv).XORKeyStream(out, data) //nolint:staticcheck // KMIP requires CFB.
			return out, nil
		case BlockCipherModeOFB:
			if len(iv) != block.BlockSize() {
				return nil, errs.Detail(ErrInvalidRequest, "OFB IV length %d does not match %d | OFB IV 长度 %d 与 %d 不一致", len(iv), block.BlockSize(), len(iv), block.BlockSize())
			}
			out := make([]byte, len(data))
			// KMIP 1.4 requires OFB; the standard library deprecates it but it remains the interoperable
			// primitive for this mode. | KMIP 1.4 要求 OFB；标准库已弃用，但它仍是该模式的互操作原语。
			cipher.NewOFB(block, iv).XORKeyStream(out, data) //nolint:staticcheck // KMIP requires OFB.
			return out, nil
		default:
			return nil, errs.Detail(ErrUnsupported, "unsupported block cipher mode 0x%08X | 不支持的分组密码模式 0x%08X", uint32(mode), uint32(mode))
		}
	case AlgorithmRSA:
		if key.rsaPrivate == nil {
			return nil, errs.Detail(ErrCryptographic, "RSA decryption requires a private key | RSA 解密需要私钥")
		}
		switch params.PaddingMethod {
		case PaddingMethodPKCS1V15:
			// PKCS#1 v1.5 decryption is retained for KMIP RSA key transport compatibility. Padding errors
			// are reported uniformly as ErrCryptographic and never echo plaintext. | 保留 PKCS#1 v1.5
			// 解密以兼容 KMIP RSA 密钥传输。填充错误统一报告为 ErrCryptographic，绝不回显明文。
			out, err := rsa.DecryptPKCS1v15(rand.Reader, key.rsaPrivate, data) //nolint:staticcheck // KMIP RSA key transport requires PKCS#1 v1.5.
			if err != nil {
				return nil, errs.Wrap(err, ErrCryptographic)
			}
			return out, nil
		case 0, PaddingMethodOAEP:
			hashAlg := params.HashingAlgorithm
			if hashAlg == 0 {
				hashAlg = HashingAlgorithmSHA256
			}
			factory, _, err := hashFactory(hashAlg)
			if err != nil {
				return nil, err
			}
			out, err := rsa.DecryptOAEP(factory(), rand.Reader, key.rsaPrivate, data, nil)
			if err != nil {
				return nil, errs.Wrap(err, ErrCryptographic)
			}
			return out, nil
		default:
			return nil, errs.Detail(ErrUnsupported, "unsupported RSA padding method 0x%08X | 不支持的 RSA 填充方法 0x%08X", uint32(params.PaddingMethod), uint32(params.PaddingMethod))
		}
	default:
		return nil, errs.Detail(ErrUnsupported, "algorithm %s does not support decryption | 算法 %s 不支持解密", key.algorithm, key.algorithm)
	}
}

// signKeyBlock signs data or a supplied digest with a key block. | signKeyBlock 使用密钥块签名 data 或提供的摘要。
func signKeyBlock(kb KeyBlock, params CryptographicParameters, data, digested []byte) ([]byte, error) {
	key, err := parseKeyBlock(kb)
	if err != nil {
		return nil, err
	}
	defer key.zeroize()
	switch key.algorithm {
	case AlgorithmRSA:
		if key.rsaPrivate == nil {
			return nil, errs.Detail(ErrCryptographic, "RSA signing requires a private key | RSA 签名需要私钥")
		}
		hashAlg, err := signatureHash(params, key.algorithm)
		if err != nil {
			return nil, err
		}
		digest, hashID, err := digestData(hashAlg, data, digested)
		if err != nil {
			return nil, err
		}
		if params.DigitalSignatureAlgorithm == DigitalSignatureRSAPSS {
			opts := &rsa.PSSOptions{Hash: hashID, SaltLength: params.SaltLength}
			if opts.SaltLength == 0 {
				opts.SaltLength = rsa.PSSSaltLengthEqualsHash
			}
			sig, err := rsa.SignPSS(rand.Reader, key.rsaPrivate, hashID, digest, opts)
			if err != nil {
				return nil, errs.Wrap(err, ErrCryptographic)
			}
			return sig, nil
		}
		sig, err := rsa.SignPKCS1v15(rand.Reader, key.rsaPrivate, hashID, digest)
		if err != nil {
			return nil, errs.Wrap(err, ErrCryptographic)
		}
		return sig, nil
	case AlgorithmECDSA, AlgorithmEC:
		if key.ecPrivate == nil {
			return nil, errs.Detail(ErrCryptographic, "ECDSA signing requires a private key | ECDSA 签名需要私钥")
		}
		hashAlg, err := signatureHash(params, key.algorithm)
		if err != nil {
			return nil, err
		}
		digest, _, err := digestData(hashAlg, data, digested)
		if err != nil {
			return nil, err
		}
		sig, err := ecdsaSign(key.ecPrivate, digest)
		if err != nil {
			return nil, err
		}
		return sig, nil
	case AlgorithmEd25519:
		if key.edPrivate == nil {
			return nil, errs.Detail(ErrCryptographic, "Ed25519 signing requires a private key | Ed25519 签名需要私钥")
		}
		if digested != nil {
			return nil, errs.Detail(ErrUnsupported, "Ed25519 does not accept pre-hashed data | Ed25519 不接受预哈希数据")
		}
		return ed25519.Sign(key.edPrivate, data), nil
	case AlgorithmSM2:
		if key.sm2Private == nil {
			return nil, errs.Detail(ErrCryptographic, "SM2 signing requires a private key | SM2 签名需要私钥")
		}
		if digested != nil {
			return nil, errs.Detail(ErrUnsupported, "SM2 does not accept pre-hashed data | SM2 不接受预哈希数据")
		}
		sig, err := guomi.Sign(key.sm2Private, data)
		if err != nil {
			return nil, errs.Wrap(err, ErrCryptographic)
		}
		return sig, nil
	default:
		return nil, errs.Detail(ErrUnsupported, "algorithm %s does not support signing | 算法 %s 不支持签名", key.algorithm, key.algorithm)
	}
}

// verifyKeyBlock verifies a signature over data or a supplied digest. | verifyKeyBlock 验证 data 或提供的摘要上的签名。
func verifyKeyBlock(kb KeyBlock, params CryptographicParameters, data, digested, signature []byte) (bool, error) {
	key, err := parseKeyBlock(kb)
	if err != nil {
		return false, err
	}
	defer key.zeroize()
	switch key.algorithm {
	case AlgorithmRSA:
		if key.rsaPublic == nil {
			return false, errs.Detail(ErrCryptographic, "RSA verification requires a public key | RSA 验签需要公钥")
		}
		hashAlg, err := signatureHash(params, key.algorithm)
		if err != nil {
			return false, err
		}
		digest, hashID, err := digestData(hashAlg, data, digested)
		if err != nil {
			return false, err
		}
		if params.DigitalSignatureAlgorithm == DigitalSignatureRSAPSS {
			opts := &rsa.PSSOptions{Hash: hashID, SaltLength: params.SaltLength}
			if opts.SaltLength == 0 {
				opts.SaltLength = rsa.PSSSaltLengthAuto
			}
			if err := rsa.VerifyPSS(key.rsaPublic, hashID, digest, signature, opts); err != nil {
				return false, nil
			}
			return true, nil
		}
		if err := rsa.VerifyPKCS1v15(key.rsaPublic, hashID, digest, signature); err != nil {
			return false, nil
		}
		return true, nil
	case AlgorithmECDSA, AlgorithmEC:
		if key.ecPublic == nil {
			return false, errs.Detail(ErrCryptographic, "ECDSA verification requires a public key | ECDSA 验签需要公钥")
		}
		hashAlg, err := signatureHash(params, key.algorithm)
		if err != nil {
			return false, err
		}
		digest, _, err := digestData(hashAlg, data, digested)
		if err != nil {
			return false, err
		}
		return ecdsaVerify(key.ecPublic, digest, signature), nil
	case AlgorithmEd25519:
		if key.edPublic == nil {
			return false, errs.Detail(ErrCryptographic, "Ed25519 verification requires a public key | Ed25519 验签需要公钥")
		}
		if digested != nil {
			return false, errs.Detail(ErrUnsupported, "Ed25519 does not accept pre-hashed data | Ed25519 不接受预哈希数据")
		}
		return ed25519.Verify(key.edPublic, data, signature), nil
	case AlgorithmSM2:
		if key.sm2Public == nil {
			return false, errs.Detail(ErrCryptographic, "SM2 verification requires a public key | SM2 验签需要公钥")
		}
		if digested != nil {
			return false, errs.Detail(ErrUnsupported, "SM2 does not accept pre-hashed data | SM2 不接受预哈希数据")
		}
		ok, err := guomi.Verify(key.sm2Public, data, signature)
		if err != nil {
			return false, errs.Wrap(err, ErrCryptographic)
		}
		return ok, nil
	default:
		return false, errs.Detail(ErrUnsupported, "algorithm %s does not support verification | 算法 %s 不支持验签", key.algorithm, key.algorithm)
	}
}

// macHash selects the hash used by MAC and MAC Verify. | macHash 选择 MAC 与 MAC Verify 使用的哈希。
func macHash(algorithm CryptographicAlgorithm, p CryptographicParameters) (HashingAlgorithm, error) {
	if p.HashingAlgorithm != 0 {
		return p.HashingAlgorithm, nil
	}
	switch algorithm {
	case AlgorithmHMACSHA1:
		return HashingAlgorithmSHA1, nil
	case AlgorithmHMACSHA224:
		return HashingAlgorithmSHA224, nil
	case AlgorithmHMACSHA256:
		return HashingAlgorithmSHA256, nil
	case AlgorithmHMACSHA384:
		return HashingAlgorithmSHA384, nil
	case AlgorithmHMACSHA512:
		return HashingAlgorithmSHA512, nil
	case AlgorithmSM3:
		return HashingAlgorithmSM3, nil
	case AlgorithmAES, AlgorithmSM4:
		return HashingAlgorithmSHA256, nil
	default:
		return 0, errs.Detail(ErrUnsupported, "algorithm %s does not support MAC | 算法 %s 不支持 MAC", algorithm, algorithm)
	}
}

// macKeyBlock computes a MAC with a symmetric key block. | macKeyBlock 使用对称密钥块计算 MAC。
func macKeyBlock(kb KeyBlock, params CryptographicParameters, data []byte) ([]byte, error) {
	key, err := parseKeyBlock(kb)
	if err != nil {
		return nil, err
	}
	defer key.zeroize()
	if key.symmetric == nil {
		return nil, errs.Detail(ErrCryptographic, "MAC requires a symmetric key | MAC 需要对称密钥")
	}
	hashAlg, err := macHash(key.algorithm, params)
	if err != nil {
		return nil, err
	}
	if hashAlg == HashingAlgorithmSM3 {
		sum := guomi.HMAC(key.symmetric, data)
		return sum[:], nil
	}
	factory, _, err := hashFactory(hashAlg)
	if err != nil {
		return nil, err
	}
	h := hmac.New(factory, key.symmetric)
	_, _ = h.Write(data)
	return h.Sum(nil), nil
}

// macVerifyKeyBlock verifies a MAC in constant time. | macVerifyKeyBlock 以常量时间验证 MAC。
func macVerifyKeyBlock(kb KeyBlock, params CryptographicParameters, data, expected []byte) (bool, error) {
	actual, err := macKeyBlock(kb, params, data)
	if err != nil {
		return false, err
	}
	if len(actual) != len(expected) {
		zeroize(actual)
		return false, nil
	}
	equal := subtle.ConstantTimeCompare(actual, expected) == 1
	zeroize(actual)
	return equal, nil
}

// deriveKeyBlock derives a symmetric key from one input key block. | deriveKeyBlock 从一个输入密钥块派生对称密钥。
//
// HKDF and PBKDF2 are supported. The requested algorithm defaults to AES and the length defaults to 256 bits.
// | 支持 HKDF 与 PBKDF2；请求算法默认 AES，长度默认 256 位。
func deriveKeyBlock(keys []KeyBlock, method DerivationMethod, params DerivationParameters, algorithm CryptographicAlgorithm, lengthBits int) (KeyBlock, error) {
	if len(keys) != 1 {
		return KeyBlock{}, errs.Detail(ErrInvalidRequest, "key derivation requires exactly one key, got %d | 密钥派生需要恰好一个密钥，实际 %d", len(keys), len(keys))
	}
	if algorithm == 0 {
		algorithm = AlgorithmAES
	}
	if lengthBits == 0 {
		lengthBits = 256
	}
	if lengthBits <= 0 || lengthBits%8 != 0 || lengthBits > 4096 {
		return KeyBlock{}, errs.Detail(ErrInvalidRequest, "invalid derived key length %d | 派生密钥长度 %d 非法", lengthBits, lengthBits)
	}
	key, err := parseKeyBlock(keys[0])
	if err != nil {
		return KeyBlock{}, err
	}
	defer key.zeroize()
	if key.symmetric == nil {
		return KeyBlock{}, errs.Detail(ErrCryptographic, "key derivation requires a symmetric input key | 密钥派生需要对称输入密钥")
	}
	hashAlg := HashingAlgorithmSHA256
	if params.CryptographicParameters != nil && params.CryptographicParameters.HashingAlgorithm != 0 {
		hashAlg = params.CryptographicParameters.HashingAlgorithm
	}
	factory, _, err := hashFactory(hashAlg)
	if err != nil {
		return KeyBlock{}, err
	}
	length := lengthBits / 8
	out := make([]byte, length)
	switch method {
	case DerivationMethodHKDF:
		reader := hkdf.New(factory, key.symmetric, params.Salt, params.DerivationData)
		if _, err := io.ReadFull(reader, out); err != nil {
			return KeyBlock{}, errs.Wrap(err, ErrCryptographic)
		}
	case DerivationMethodPBKDF2:
		iterations := params.IterationCount
		if iterations <= 0 {
			iterations = 10000
		}
		salt := params.Salt
		if len(salt) == 0 {
			return KeyBlock{}, errs.Detail(ErrInvalidRequest, "PBKDF2 requires a salt | PBKDF2 需要盐值")
		}
		derived := pbkdf2.Key(key.symmetric, salt, iterations, length, factory)
		copy(out, derived)
		zeroize(derived)
	default:
		return KeyBlock{}, errs.Detail(ErrUnsupported, "unsupported derivation method 0x%08X | 不支持的派生方法 0x%08X", uint32(method), uint32(method))
	}
	return KeyBlock{
		Format:    KeyFormatRaw,
		Algorithm: algorithm,
		Length:    lengthBits,
		Value:     NewRawKeyValue(out),
	}, nil
}

// wrapKeyBlock wraps a key block with another key block according to a wrapping specification. | wrapKeyBlock 按封装规格使用另一个密钥块封装密钥块。
func wrapKeyBlock(kb KeyBlock, wrappingKey KeyBlock, spec KeyWrappingSpecification) (KeyBlock, error) {
	method := spec.WrappingMethod
	if method == 0 {
		method = WrappingMethodEncrypt
	}
	if method != WrappingMethodEncrypt {
		return KeyBlock{}, errs.Detail(ErrUnsupported, "only the Encrypt wrapping method is supported | 仅支持 Encrypt 封装方法")
	}
	if spec.EncryptionKeyInformation == nil {
		return KeyBlock{}, errs.Detail(ErrInvalidRequest, "wrapping specification has no encryption key | 封装规格没有加密密钥")
	}
	material, err := keyMaterialBytes(kb)
	if err != nil {
		return KeyBlock{}, err
	}
	params := CryptographicParameters{}
	if spec.EncryptionKeyInformation.CryptographicParameters != nil {
		params = *spec.EncryptionKeyInformation.CryptographicParameters
	}
	if params.BlockCipherMode == 0 {
		params.BlockCipherMode = BlockCipherModeGCM
	}
	ciphertext, iv, tag, err := encryptKeyBlock(wrappingKey, params, material, nil, nil)
	if err != nil {
		return KeyBlock{}, err
	}
	wrapped := KeyBlock{
		Format:    kb.Format,
		Algorithm: kb.Algorithm,
		Length:    kb.Length,
		Value:     KeyValue{Material: NewByteString(TagKeyMaterial, ciphertext)},
		Wrapping: &KeyWrappingData{
			WrappingMethod:           method,
			EncryptionKeyInformation: spec.EncryptionKeyInformation,
			IVCounterNonce:           iv,
			MACSignature:             tag,
			EncodingOption:           spec.EncodingOption,
		},
	}
	return wrapped, nil
}

// unwrapKeyBlock unwraps a key block with the wrapping key block. | unwrapKeyBlock 使用封装密钥块解封密钥块。
func unwrapKeyBlock(kb KeyBlock, wrappingKey KeyBlock) (KeyBlock, error) {
	if kb.Wrapping == nil {
		return KeyBlock{}, errs.Detail(ErrInvalidRequest, "key block is not wrapped | 密钥块未封装")
	}
	if kb.Wrapping.WrappingMethod != WrappingMethodEncrypt {
		return KeyBlock{}, errs.Detail(ErrUnsupported, "only the Encrypt wrapping method is supported | 仅支持 Encrypt 封装方法")
	}
	if kb.Wrapping.EncryptionKeyInformation == nil {
		return KeyBlock{}, errs.Detail(ErrInvalidRequest, "wrapped key block has no encryption key information | 已封装密钥块没有加密密钥信息")
	}
	material, err := keyMaterialBytes(kb)
	if err != nil {
		return KeyBlock{}, err
	}
	params := CryptographicParameters{}
	if kb.Wrapping.EncryptionKeyInformation.CryptographicParameters != nil {
		params = *kb.Wrapping.EncryptionKeyInformation.CryptographicParameters
	}
	if params.BlockCipherMode == 0 {
		params.BlockCipherMode = BlockCipherModeGCM
	}
	plain, err := decryptKeyBlock(wrappingKey, params, material, kb.Wrapping.IVCounterNonce, kb.Wrapping.MACSignature, nil)
	if err != nil {
		return KeyBlock{}, err
	}
	unwrapped := KeyBlock{
		Format:    kb.Format,
		Algorithm: kb.Algorithm,
		Length:    kb.Length,
		Value:     KeyValue{},
	}
	switch kb.Format {
	case KeyFormatTransparentSymmetricKey, KeyFormatTransparentRSAPrivateKey, KeyFormatTransparentRSAPublicKey,
		KeyFormatTransparentECPrivateKey, KeyFormatTransparentECPublicKey:
		item, err := Decode(plain)
		if err != nil {
			return KeyBlock{}, err
		}
		unwrapped.Value.Material = item
	default:
		unwrapped.Value.Material = NewByteString(TagKeyMaterial, plain)
	}
	unwrapped.Value.Attributes = CloneAttributes(kb.Value.Attributes)
	return unwrapped, nil
}

// randomBytes returns cryptographically random bytes. | randomBytes 返回密码学随机字节。
func randomBytes(n int) ([]byte, error) {
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		return nil, errs.Wrap(err, ErrCryptographic)
	}
	return out, nil
}
