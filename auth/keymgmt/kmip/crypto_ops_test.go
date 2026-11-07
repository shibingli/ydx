package kmip

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"errors"
	"testing"
)

// TestHashHelpers covers hash selection, digesting and signature hash inference. |
// TestHashHelpers 覆盖哈希选择、摘要计算与签名哈希推断。
func TestHashHelpers(t *testing.T) {
	hashes := []struct {
		algorithm HashingAlgorithm
		id        uint32
		size      int
	}{
		{HashingAlgorithmSHA1, 3, 20},
		{HashingAlgorithmSHA224, 4, 28},
		{HashingAlgorithmSHA256, 5, 32},
		{0, 5, 32},
		{HashingAlgorithmSHA384, 6, 48},
		{HashingAlgorithmSHA512, 7, 64},
		{HashingAlgorithmSHA512_224, 14, 28},
		{HashingAlgorithmSHA512_256, 15, 32},
		{HashingAlgorithmSM3, 0, 32},
	}
	for _, testCase := range hashes {
		factory, id, err := hashFactory(testCase.algorithm)
		if err != nil {
			t.Fatalf("hashFactory(0x%08X): %v | 哈希工厂失败：%v", uint32(testCase.algorithm), err, err)
		}
		if uint32(id) != testCase.id {
			t.Fatalf("hashFactory(0x%08X) id = %d, want %d | 哈希标识 = %d，期望 %d", uint32(testCase.algorithm), id, testCase.id, id, testCase.id)
		}
		h := factory()
		_, _ = h.Write([]byte("data"))
		if got := len(h.Sum(nil)); got != testCase.size {
			t.Fatalf("hashFactory(0x%08X) size = %d, want %d | 哈希长度 = %d，期望 %d", uint32(testCase.algorithm), got, testCase.size, got, testCase.size)
		}
	}
	if _, _, err := hashFactory(HashingAlgorithm(0xFFFF)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported hash error = %v | 不支持哈希错误 = %v", err, err)
	}

	digest, id, err := digestData(HashingAlgorithmSHA256, []byte("data"), nil)
	if err != nil {
		t.Fatalf("digestData: %v | 摘要计算失败：%v", err, err)
	}
	want := sha256.Sum256([]byte("data"))
	if !bytes.Equal(digest, want[:]) || id != 5 {
		t.Fatalf("digestData = %x/%d | 摘要结果 = %x/%d", digest, id, digest, id)
	}
	supplied := []byte{9, 8, 7}
	digest, _, err = digestData(HashingAlgorithmSHA512, []byte("ignored"), supplied)
	if err != nil || !bytes.Equal(digest, supplied) {
		t.Fatalf("supplied digest = %x, %v | 提供的摘要 = %x，%v", digest, err, digest, err)
	}
	if _, _, err := digestData(HashingAlgorithm(0xFFFF), nil, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported digest error = %v | 不支持摘要错误 = %v", err, err)
	}

	signatureHashes := []struct {
		params    CryptographicParameters
		algorithm CryptographicAlgorithm
		want      HashingAlgorithm
	}{
		{CryptographicParameters{HashingAlgorithm: HashingAlgorithmSHA224}, AlgorithmRSA, HashingAlgorithmSHA224},
		{CryptographicParameters{DigitalSignatureAlgorithm: DigitalSignatureRSAPKCS1SHA256}, AlgorithmRSA, HashingAlgorithmSHA256},
		{CryptographicParameters{DigitalSignatureAlgorithm: DigitalSignatureECDSASHA256}, AlgorithmECDSA, HashingAlgorithmSHA256},
		{CryptographicParameters{DigitalSignatureAlgorithm: DigitalSignatureRSAPKCS1SHA384}, AlgorithmRSA, HashingAlgorithmSHA384},
		{CryptographicParameters{DigitalSignatureAlgorithm: DigitalSignatureECDSASHA384}, AlgorithmECDSA, HashingAlgorithmSHA384},
		{CryptographicParameters{DigitalSignatureAlgorithm: DigitalSignatureRSAPKCS1SHA512}, AlgorithmRSA, HashingAlgorithmSHA512},
		{CryptographicParameters{DigitalSignatureAlgorithm: DigitalSignatureECDSASHA512}, AlgorithmECDSA, HashingAlgorithmSHA512},
		{CryptographicParameters{DigitalSignatureAlgorithm: DigitalSignatureRSAPSS}, AlgorithmRSA, HashingAlgorithmSHA256},
		{CryptographicParameters{DigitalSignatureAlgorithm: DigitalSignatureEd25519}, AlgorithmEd25519, 0},
		{CryptographicParameters{DigitalSignatureAlgorithm: DigitalSignatureSM2SM3}, AlgorithmSM2, 0},
		{CryptographicParameters{}, AlgorithmEd25519, 0},
		{CryptographicParameters{}, AlgorithmSM2, 0},
		{CryptographicParameters{}, AlgorithmRSA, HashingAlgorithmSHA256},
	}
	for _, testCase := range signatureHashes {
		got, err := signatureHash(testCase.params, testCase.algorithm)
		if err != nil || got != testCase.want {
			t.Fatalf("signatureHash(%+v, %s) = 0x%08X, %v | 签名哈希 = 0x%08X，%v", testCase.params, testCase.algorithm, uint32(got), err, uint32(got), err)
		}
	}
}

// TestPKCS7Padding covers padding and unpadding edge cases. | TestPKCS7Padding 覆盖填充与去填充边界。
func TestPKCS7Padding(t *testing.T) {
	for _, length := range []int{0, 1, 5, 15, 16, 17, 32} {
		data := bytes.Repeat([]byte{0xA5}, length)
		padded := pkcs7Pad(data, 16)
		if len(padded)%16 != 0 || len(padded) <= len(data) {
			t.Fatalf("pad(%d) produced length %d | 填充(%d) 产生长度 %d", length, len(padded), length, len(padded))
		}
		padding := int(padded[len(padded)-1])
		if padding < 1 || padding > 16 {
			t.Fatalf("pad(%d) padding byte = %d | 填充字节 = %d", length, padding, padding)
		}
		unpadded, err := pkcs7Unpad(padded, 16)
		if err != nil || !bytes.Equal(unpadded, data) {
			t.Fatalf("unpad(pad(%d)) = %x, %v | 去填充结果 = %x，%v", length, unpadded, err, unpadded, err)
		}
	}
	errorCases := [][]byte{
		{},
		bytes.Repeat([]byte{1}, 15),
		append(bytes.Repeat([]byte{1}, 15), 0),
		append(bytes.Repeat([]byte{1}, 14), 17),
		append(bytes.Repeat([]byte{1}, 13), 3, 2),
		append(bytes.Repeat([]byte{1}, 14), 2),
	}
	for _, data := range errorCases {
		if _, err := pkcs7Unpad(data, 16); !errors.Is(err, ErrCryptographic) {
			t.Fatalf("unpad(%x) error = %v | 去填充错误 = %v", data, err, err)
		}
	}
}

// TestNewGCMVariants covers nonce and tag size handling. | TestNewGCMVariants 覆盖 nonce 与标签长度处理。
func TestNewGCMVariants(t *testing.T) {
	block, err := aes.NewCipher(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	aead, err := newGCM(block, 0, 0)
	if err != nil || aead.NonceSize() != 12 || aead.Overhead() != 16 {
		t.Fatalf("default GCM = %d/%d, %v | 默认 GCM = %d/%d，%v", aead.NonceSize(), aead.Overhead(), err, aead.NonceSize(), aead.Overhead(), err)
	}
	aead, err = newGCM(block, 12, 12)
	if err != nil || aead.Overhead() != 12 {
		t.Fatalf("12-byte tag GCM overhead = %d, %v | 12 字节标签 GCM 开销 = %d，%v", aead.Overhead(), err, aead.Overhead(), err)
	}
	aead, err = newGCM(block, 16, 16)
	if err != nil || aead.NonceSize() != 16 {
		t.Fatalf("16-byte nonce GCM = %d, %v | 16 字节 nonce GCM = %d，%v", aead.NonceSize(), err, aead.NonceSize(), err)
	}
	if _, err := newGCM(block, 16, 12); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("combined custom sizes error = %v | 组合自定义长度错误 = %v", err, err)
	}
	for _, sizes := range [][2]int{{12, 8}, {12, 20}, {0, 8}, {-1, 16}} {
		if _, err := newGCM(block, sizes[0], sizes[1]); err == nil {
			t.Fatalf("newGCM(%d, %d) accepted invalid sizes | newGCM(%d, %d) 接受了非法长度", sizes[0], sizes[1], sizes[0], sizes[1])
		}
	}
}

// TestGCMNonceLengthValidation guards against negative and unbounded nonce lengths. |
// TestGCMNonceLengthValidation 防止负数与无界 nonce 长度。
func TestGCMNonceLengthValidation(t *testing.T) {
	cases := []struct {
		configured int
		want       int
		wantErr    bool
	}{
		{0, 12, false},
		{12, 12, false},
		{16, 16, false},
		{maxGCMNonceLength, maxGCMNonceLength, false},
		{-1, 0, true},
		{maxGCMNonceLength + 1, 0, true},
	}
	for _, testCase := range cases {
		got, err := gcmNonceLength(testCase.configured)
		if testCase.wantErr {
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("gcmNonceLength(%d) error = %v | 长度校验错误 = %v", testCase.configured, err, err)
			}
			continue
		}
		if err != nil || got != testCase.want {
			t.Fatalf("gcmNonceLength(%d) = %d, %v | 长度校验 = %d，%v", testCase.configured, got, err, got, err)
		}
	}
}

// TestBlockCipherModes covers every supported symmetric mode and error path. |
// TestBlockCipherModes 覆盖所有支持的对称模式与错误路径。
func TestBlockCipherModes(t *testing.T) {
	aesKey := rawKeyBlock(AlgorithmAES, bytes.Repeat([]byte{0x11}, 32))
	sm4Key := rawKeyBlock(AlgorithmSM4, bytes.Repeat([]byte{0x22}, 16))
	data := []byte("the quick brown fox jumps over the lazy dog")

	for _, testCase := range []struct {
		name string
		key  KeyBlock
	}{
		{"AES", aesKey},
		{"SM4", sm4Key},
	} {
		t.Run(testCase.name+" GCM default", func(t *testing.T) {
			ciphertext, iv, tag, err := encryptKeyBlock(testCase.key, CryptographicParameters{}, data, nil, nil)
			if err != nil {
				t.Fatalf("encrypt: %v | 加密失败：%v", err, err)
			}
			if len(iv) != 12 || len(tag) != 16 || len(ciphertext) != len(data) {
				t.Fatalf("GCM outputs = %d/%d/%d | GCM 输出 = %d/%d/%d", len(ciphertext), len(iv), len(tag), len(ciphertext), len(iv), len(tag))
			}
			plain, err := decryptKeyBlock(testCase.key, CryptographicParameters{}, ciphertext, iv, tag, nil)
			if err != nil || !bytes.Equal(plain, data) {
				t.Fatalf("decrypt = %q, %v | 解密 = %q，%v", plain, err, plain, err)
			}
			tampered := append([]byte(nil), tag...)
			tampered[0] ^= 0xFF
			if _, err := decryptKeyBlock(testCase.key, CryptographicParameters{}, ciphertext, iv, tampered, nil); !errors.Is(err, ErrCryptographic) {
				t.Fatalf("tampered tag error = %v | 篡改标签错误 = %v", err, err)
			}
		})

		t.Run(testCase.name+" GCM nonce 16", func(t *testing.T) {
			params := CryptographicParameters{IVLength: 16}
			iv := bytes.Repeat([]byte{3}, 16)
			ciphertext, gotIV, tag, err := encryptKeyBlock(testCase.key, params, data, iv, []byte("aad"))
			if err != nil {
				t.Fatalf("encrypt: %v | 加密失败：%v", err, err)
			}
			if !bytes.Equal(gotIV, iv) {
				t.Fatalf("IV changed to %x | IV 变为 %x", gotIV, gotIV)
			}
			plain, err := decryptKeyBlock(testCase.key, params, ciphertext, iv, tag, []byte("aad"))
			if err != nil || !bytes.Equal(plain, data) {
				t.Fatalf("decrypt with AAD = %q, %v | 带 AAD 解密 = %q，%v", plain, err, plain, err)
			}
			if _, err := decryptKeyBlock(testCase.key, params, ciphertext, iv, tag, []byte("other")); !errors.Is(err, ErrCryptographic) {
				t.Fatalf("wrong AAD error = %v | 错误 AAD 错误 = %v", err, err)
			}
		})

		t.Run(testCase.name+" GCM tag 12", func(t *testing.T) {
			params := CryptographicParameters{TagLength: 12}
			ciphertext, iv, tag, err := encryptKeyBlock(testCase.key, params, data, nil, nil)
			if err != nil || len(tag) != 12 {
				t.Fatalf("encrypt tag = %d, %v | 加密标签 = %d，%v", len(tag), err, len(tag), err)
			}
			plain, err := decryptKeyBlock(testCase.key, params, ciphertext, iv, tag, nil)
			if err != nil || !bytes.Equal(plain, data) {
				t.Fatalf("decrypt = %q, %v | 解密 = %q，%v", plain, err, plain, err)
			}
		})

		t.Run(testCase.name+" CBC default", func(t *testing.T) {
			params := CryptographicParameters{BlockCipherMode: BlockCipherModeCBC}
			ciphertext, iv, tag, err := encryptKeyBlock(testCase.key, params, []byte("short"), nil, nil)
			if err != nil {
				t.Fatalf("encrypt: %v | 加密失败：%v", err, err)
			}
			if len(ciphertext) != 16 || len(iv) != 16 || tag != nil {
				t.Fatalf("CBC outputs = %d/%d/%v | CBC 输出 = %d/%d/%v", len(ciphertext), len(iv), tag, len(ciphertext), len(iv), tag)
			}
			plain, err := decryptKeyBlock(testCase.key, params, ciphertext, iv, nil, nil)
			if err != nil || !bytes.Equal(plain, []byte("short")) {
				t.Fatalf("decrypt = %q, %v | 解密 = %q，%v", plain, err, plain, err)
			}
		})

		t.Run(testCase.name+" CBC none", func(t *testing.T) {
			params := CryptographicParameters{BlockCipherMode: BlockCipherModeCBC, PaddingMethod: PaddingMethodNone}
			ciphertext, iv, _, err := encryptKeyBlock(testCase.key, params, data[:16], nil, nil)
			if err != nil {
				t.Fatalf("encrypt: %v | 加密失败：%v", err, err)
			}
			plain, err := decryptKeyBlock(testCase.key, params, ciphertext, iv, nil, nil)
			if err != nil || !bytes.Equal(plain, data[:16]) {
				t.Fatalf("decrypt = %q, %v | 解密 = %q，%v", plain, err, plain, err)
			}
			if _, _, _, err := encryptKeyBlock(testCase.key, params, data, nil, nil); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("misaligned CBC none error = %v | 非对齐 CBC 无填充错误 = %v", err, err)
			}
			badPadding := params
			badPadding.PaddingMethod = PaddingMethodOAEP
			if _, _, _, err := encryptKeyBlock(testCase.key, badPadding, data[:16], nil, nil); !errors.Is(err, ErrUnsupported) {
				t.Fatalf("unsupported CBC padding error = %v | 不支持 CBC 填充错误 = %v", err, err)
			}
		})

		for _, mode := range []struct {
			name string
			mode BlockCipherMode
		}{
			{"CTR", BlockCipherModeCTR},
			{"CFB", BlockCipherModeCFB},
			{"OFB", BlockCipherModeOFB},
		} {
			t.Run(testCase.name+" "+mode.name, func(t *testing.T) {
				params := CryptographicParameters{BlockCipherMode: mode.mode}
				ciphertext, iv, tag, err := encryptKeyBlock(testCase.key, params, data, nil, nil)
				if err != nil {
					t.Fatalf("encrypt: %v | 加密失败：%v", err, err)
				}
				if len(iv) != 16 || tag != nil || len(ciphertext) != len(data) {
					t.Fatalf("mode outputs = %d/%d | 模式输出 = %d/%d", len(iv), len(ciphertext), len(iv), len(ciphertext))
				}
				plain, err := decryptKeyBlock(testCase.key, params, ciphertext, iv, nil, nil)
				if err != nil || !bytes.Equal(plain, data) {
					t.Fatalf("decrypt = %q, %v | 解密 = %q，%v", plain, err, plain, err)
				}
				if _, err := decryptKeyBlock(testCase.key, params, ciphertext, iv[:8], nil, nil); !errors.Is(err, ErrInvalidRequest) {
					t.Fatalf("short IV error = %v | 过短 IV 错误 = %v", err, err)
				}
			})
		}
	}

	if _, _, _, err := encryptKeyBlock(aesKey, CryptographicParameters{BlockCipherMode: BlockCipherModeECB}, data, nil, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ECB error = %v | ECB 错误 = %v", err, err)
	}
	if _, _, _, err := encryptKeyBlock(aesKey, CryptographicParameters{IVLength: -1}, data, nil, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("negative nonce error = %v | 负 nonce 错误 = %v", err, err)
	}
	if _, _, _, err := encryptKeyBlock(aesKey, CryptographicParameters{IVLength: maxGCMNonceLength + 1}, data, nil, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("oversized nonce error = %v | 过大 nonce 错误 = %v", err, err)
	}
	if _, _, _, err := encryptKeyBlock(aesKey, CryptographicParameters{}, data, []byte("short"), nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("short GCM IV error = %v | 过短 GCM IV 错误 = %v", err, err)
	}
	if _, _, _, err := encryptKeyBlock(aesKey, CryptographicParameters{TagLength: 8}, data, nil, nil); err == nil {
		t.Fatal("8-byte GCM tag accepted | 8 字节 GCM 标签被接受")
	}
	if _, _, _, err := encryptKeyBlock(aesKey, CryptographicParameters{IVLength: 16, TagLength: 12}, data, nil, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("combined GCM sizes error = %v | 组合 GCM 长度错误 = %v", err, err)
	}

	shortAES := rawKeyBlock(AlgorithmAES, bytes.Repeat([]byte{1}, 10))
	if _, _, _, err := encryptKeyBlock(shortAES, CryptographicParameters{}, data, nil, nil); !errors.Is(err, ErrCryptographic) {
		t.Fatalf("short AES key error = %v | 过短 AES 密钥错误 = %v", err, err)
	}
	shortSM4 := rawKeyBlock(AlgorithmSM4, bytes.Repeat([]byte{1}, 10))
	if _, _, _, err := encryptKeyBlock(shortSM4, CryptographicParameters{}, data, nil, nil); !errors.Is(err, ErrCryptographic) {
		t.Fatalf("short SM4 key error = %v | 过短 SM4 密钥错误 = %v", err, err)
	}
	if _, _, _, err := encryptKeyBlock(rawKeyBlock(AlgorithmHMACSHA256, bytes.Repeat([]byte{1}, 32)), CryptographicParameters{}, data, nil, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("HMAC encryption error = %v | HMAC 加密错误 = %v", err, err)
	}
	if _, err := decryptKeyBlock(rawKeyBlock(AlgorithmHMACSHA256, bytes.Repeat([]byte{1}, 32)), CryptographicParameters{}, data, nil, nil, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("HMAC decryption error = %v | HMAC 解密错误 = %v", err, err)
	}
}

// TestCreateBlockCipherErrors covers block cipher construction failures. | TestCreateBlockCipherErrors
// 覆盖分组密码构造失败。
func TestCreateBlockCipherErrors(t *testing.T) {
	if _, _, err := createBlockCipher(&parsedKey{}); !errors.Is(err, ErrCryptographic) {
		t.Fatalf("empty key error = %v | 空密钥错误 = %v", err, err)
	}
	if _, _, err := createBlockCipher(&parsedKey{symmetric: bytes.Repeat([]byte{1}, 16), algorithm: AlgorithmRSA}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("RSA block cipher error = %v | RSA 分组密码错误 = %v", err, err)
	}
	if _, _, err := createBlockCipher(&parsedKey{symmetric: bytes.Repeat([]byte{1}, 10), algorithm: AlgorithmAES}); !errors.Is(err, ErrCryptographic) {
		t.Fatalf("bad AES length error = %v | 非法 AES 长度错误 = %v", err, err)
	}
	if _, _, err := createBlockCipher(&parsedKey{symmetric: bytes.Repeat([]byte{1}, 10), algorithm: AlgorithmSM4}); !errors.Is(err, ErrCryptographic) {
		t.Fatalf("bad SM4 length error = %v | 非法 SM4 长度错误 = %v", err, err)
	}
}

// TestRSAEncryptDecrypt covers RSA key transport with PKCS#1 v1.5 and OAEP. |
// TestRSAEncryptDecrypt 覆盖 PKCS#1 v1.5 与 OAEP 的 RSA 密钥传输。
func TestRSAEncryptDecrypt(t *testing.T) {
	private, public := mustKeyPair(t, AlgorithmRSA, 2048)
	data := []byte("transport me")

	pkcs1 := CryptographicParameters{PaddingMethod: PaddingMethodPKCS1V15}
	ciphertext, iv, tag, err := encryptKeyBlock(public, pkcs1, data, nil, nil)
	if err != nil || len(iv) != 0 || len(tag) != 0 {
		t.Fatalf("PKCS1 encrypt = %d/%d, %v | PKCS1 加密 = %d/%d，%v", len(iv), len(tag), err, len(iv), len(tag), err)
	}
	plain, err := decryptKeyBlock(private, pkcs1, ciphertext, nil, nil, nil)
	if err != nil || !bytes.Equal(plain, data) {
		t.Fatalf("PKCS1 decrypt = %q, %v | PKCS1 解密 = %q，%v", plain, err, plain, err)
	}
	if _, err := decryptKeyBlock(public, pkcs1, ciphertext, nil, nil, nil); !errors.Is(err, ErrCryptographic) {
		t.Fatalf("PKCS1 decrypt with public key error = %v | 公钥 PKCS1 解密错误 = %v", err, err)
	}
	if _, err := decryptKeyBlock(private, pkcs1, []byte("junk"), nil, nil, nil); !errors.Is(err, ErrCryptographic) {
		t.Fatalf("PKCS1 junk ciphertext error = %v | PKCS1 垃圾密文错误 = %v", err, err)
	}

	oaep := CryptographicParameters{}
	ciphertext, _, _, err = encryptKeyBlock(public, oaep, data, nil, nil)
	if err != nil {
		t.Fatalf("OAEP encrypt: %v | OAEP 加密失败：%v", err, err)
	}
	plain, err = decryptKeyBlock(private, oaep, ciphertext, nil, nil, nil)
	if err != nil || !bytes.Equal(plain, data) {
		t.Fatalf("OAEP decrypt = %q, %v | OAEP 解密 = %q，%v", plain, err, plain, err)
	}
	if _, err := decryptKeyBlock(private, CryptographicParameters{HashingAlgorithm: HashingAlgorithmSHA1}, ciphertext, nil, nil, nil); !errors.Is(err, ErrCryptographic) {
		t.Fatalf("OAEP wrong hash error = %v | OAEP 错误哈希错误 = %v", err, err)
	}

	oaepSHA1 := CryptographicParameters{HashingAlgorithm: HashingAlgorithmSHA1}
	ciphertext, _, _, err = encryptKeyBlock(public, oaepSHA1, data, nil, nil)
	if err != nil {
		t.Fatalf("OAEP SHA1 encrypt: %v | OAEP SHA1 加密失败：%v", err, err)
	}
	plain, err = decryptKeyBlock(private, oaepSHA1, ciphertext, nil, nil, nil)
	if err != nil || !bytes.Equal(plain, data) {
		t.Fatalf("OAEP SHA1 decrypt = %q, %v | OAEP SHA1 解密 = %q，%v", plain, err, plain, err)
	}
	if _, _, _, err := encryptKeyBlock(public, CryptographicParameters{HashingAlgorithm: HashingAlgorithm(0xFFFF)}, data, nil, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("OAEP unsupported hash error = %v | OAEP 不支持哈希错误 = %v", err, err)
	}
	if _, _, _, err := encryptKeyBlock(public, CryptographicParameters{PaddingMethod: PaddingMethodPKCS5}, data, nil, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported RSA padding error = %v | 不支持 RSA 填充错误 = %v", err, err)
	}
	if _, err := decryptKeyBlock(private, CryptographicParameters{PaddingMethod: PaddingMethodPKCS5}, ciphertext, nil, nil, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported RSA decrypt padding error = %v | 不支持 RSA 解密填充错误 = %v", err, err)
	}
	if _, _, _, err := encryptKeyBlock(public, oaep, bytes.Repeat([]byte{1}, 500), nil, nil); !errors.Is(err, ErrCryptographic) {
		t.Fatalf("oversized OAEP plaintext error = %v | 过大 OAEP 明文错误 = %v", err, err)
	}

	ecPrivate, _ := mustKeyPair(t, AlgorithmECDSA, 256)
	if _, _, _, err := encryptKeyBlock(ecPrivate, CryptographicParameters{}, data, nil, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ECDSA encryption error = %v | ECDSA 加密错误 = %v", err, err)
	}
	if _, err := decryptKeyBlock(ecPrivate, CryptographicParameters{}, data, nil, nil, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ECDSA decryption error = %v | ECDSA 解密错误 = %v", err, err)
	}
}

// TestSignVerify covers RSA, ECDSA, Ed25519 and SM2 signatures. | TestSignVerify 覆盖 RSA、ECDSA、Ed25519 与 SM2 签名。
func TestSignVerify(t *testing.T) {
	data := []byte("sign me")
	tampered := []byte("sign me!")

	t.Run("RSA PKCS1", func(t *testing.T) {
		private, public := mustKeyPair(t, AlgorithmRSA, 2048)
		params := CryptographicParameters{DigitalSignatureAlgorithm: DigitalSignatureRSAPKCS1SHA256}
		signature, err := signKeyBlock(private, params, data, nil)
		if err != nil {
			t.Fatalf("sign: %v | 签名失败：%v", err, err)
		}
		if ok, err := verifyKeyBlock(public, params, data, nil, signature); err != nil || !ok {
			t.Fatalf("verify = %v, %v | 验签 = %v，%v", ok, err, ok, err)
		}
		if ok, err := verifyKeyBlock(public, params, tampered, nil, signature); err != nil || ok {
			t.Fatalf("tampered verify = %v, %v | 篡改验签 = %v，%v", ok, err, ok, err)
		}
		broken := append([]byte(nil), signature...)
		broken[0] ^= 0xFF
		if ok, err := verifyKeyBlock(public, params, data, nil, broken); err != nil || ok {
			t.Fatalf("broken signature verify = %v, %v | 损坏签名验签 = %v，%v", ok, err, ok, err)
		}
		digest := sha256.Sum256(data)
		digestSignature, err := signKeyBlock(private, params, nil, digest[:])
		if err != nil {
			t.Fatalf("sign digest: %v | 摘要签名失败：%v", err, err)
		}
		if ok, err := verifyKeyBlock(public, params, nil, digest[:], digestSignature); err != nil || !ok {
			t.Fatalf("digest verify = %v, %v | 摘要验签 = %v，%v", ok, err, ok, err)
		}
		if _, err := signKeyBlock(public, params, data, nil); !errors.Is(err, ErrCryptographic) {
			t.Fatalf("public-only sign error = %v | 仅公钥签名错误 = %v", err, err)
		}
		if _, err := signKeyBlock(private, CryptographicParameters{HashingAlgorithm: HashingAlgorithm(0xFFFF)}, data, nil); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unsupported sign hash error = %v | 不支持签名哈希错误 = %v", err, err)
		}
		if _, err := verifyKeyBlock(public, CryptographicParameters{HashingAlgorithm: HashingAlgorithm(0xFFFF)}, data, nil, signature); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unsupported verify hash error = %v | 不支持验签哈希错误 = %v", err, err)
		}
	})

	t.Run("RSA PSS", func(t *testing.T) {
		private, public := mustKeyPair(t, AlgorithmRSA, 2048)
		params := CryptographicParameters{DigitalSignatureAlgorithm: DigitalSignatureRSAPSS}
		signature, err := signKeyBlock(private, params, data, nil)
		if err != nil {
			t.Fatalf("PSS sign: %v | PSS 签名失败：%v", err, err)
		}
		verifyParams := params
		verifyParams.SaltLength = 32
		if ok, err := verifyKeyBlock(public, verifyParams, data, nil, signature); err != nil || !ok {
			t.Fatalf("PSS verify = %v, %v | PSS 验签 = %v，%v", ok, err, ok, err)
		}
		if ok, err := verifyKeyBlock(public, params, tampered, nil, signature); err != nil || ok {
			t.Fatalf("PSS tampered verify = %v, %v | PSS 篡改验签 = %v，%v", ok, err, ok, err)
		}
	})

	t.Run("RSA SHA384", func(t *testing.T) {
		private, public := mustKeyPair(t, AlgorithmRSA, 2048)
		params := CryptographicParameters{HashingAlgorithm: HashingAlgorithmSHA384}
		signature, err := signKeyBlock(private, params, data, nil)
		if err != nil {
			t.Fatalf("SHA384 sign: %v | SHA384 签名失败：%v", err, err)
		}
		if ok, err := verifyKeyBlock(public, params, data, nil, signature); err != nil || !ok {
			t.Fatalf("SHA384 verify = %v, %v | SHA384 验签 = %v，%v", ok, err, ok, err)
		}
	})

	t.Run("ECDSA", func(t *testing.T) {
		private, public := mustKeyPair(t, AlgorithmECDSA, 256)
		params := CryptographicParameters{DigitalSignatureAlgorithm: DigitalSignatureECDSASHA256}
		signature, err := signKeyBlock(private, params, data, nil)
		if err != nil {
			t.Fatalf("sign: %v | 签名失败：%v", err, err)
		}
		if ok, err := verifyKeyBlock(public, params, data, nil, signature); err != nil || !ok {
			t.Fatalf("verify = %v, %v | 验签 = %v，%v", ok, err, ok, err)
		}
		if ok, err := verifyKeyBlock(public, params, tampered, nil, signature); err != nil || ok {
			t.Fatalf("tampered verify = %v, %v | 篡改验签 = %v，%v", ok, err, ok, err)
		}
		if ok, err := verifyKeyBlock(public, params, data, nil, []byte("junk")); err != nil || ok {
			t.Fatalf("junk signature verify = %v, %v | 垃圾签名验签 = %v，%v", ok, err, ok, err)
		}
		if _, err := signKeyBlock(public, params, data, nil); !errors.Is(err, ErrCryptographic) {
			t.Fatalf("public-only sign error = %v | 仅公钥签名错误 = %v", err, err)
		}
		digest := sha256.Sum256(data)
		signature, err = signKeyBlock(private, CryptographicParameters{HashingAlgorithm: HashingAlgorithmSHA256}, nil, digest[:])
		if err != nil {
			t.Fatalf("digest sign: %v | 摘要签名失败：%v", err, err)
		}
		if ok, err := verifyKeyBlock(public, CryptographicParameters{HashingAlgorithm: HashingAlgorithmSHA256}, nil, digest[:], signature); err != nil || !ok {
			t.Fatalf("digest verify = %v, %v | 摘要验签 = %v，%v", ok, err, ok, err)
		}
		otherPrivate, _ := mustKeyPair(t, AlgorithmECDSA, 256)
		otherSignature, err := signKeyBlock(otherPrivate, params, data, nil)
		if err != nil {
			t.Fatalf("other sign: %v | 其他签名失败：%v", err, err)
		}
		if ok, err := verifyKeyBlock(public, params, data, nil, otherSignature); err != nil || ok {
			t.Fatalf("wrong-key verify = %v, %v | 错误密钥验签 = %v，%v", ok, err, ok, err)
		}
	})

	t.Run("Ed25519", func(t *testing.T) {
		private, public := mustKeyPair(t, AlgorithmEd25519, 256)
		params := CryptographicParameters{DigitalSignatureAlgorithm: DigitalSignatureEd25519}
		signature, err := signKeyBlock(private, params, data, nil)
		if err != nil {
			t.Fatalf("sign: %v | 签名失败：%v", err, err)
		}
		if ok, err := verifyKeyBlock(public, params, data, nil, signature); err != nil || !ok {
			t.Fatalf("verify = %v, %v | 验签 = %v，%v", ok, err, ok, err)
		}
		if ok, err := verifyKeyBlock(public, params, tampered, nil, signature); err != nil || ok {
			t.Fatalf("tampered verify = %v, %v | 篡改验签 = %v，%v", ok, err, ok, err)
		}
		if _, err := signKeyBlock(private, params, nil, []byte{1}); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("prehashed sign error = %v | 预哈希签名错误 = %v", err, err)
		}
		if _, err := verifyKeyBlock(public, params, nil, []byte{1}, signature); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("prehashed verify error = %v | 预哈希验签错误 = %v", err, err)
		}
		if _, err := signKeyBlock(public, params, data, nil); !errors.Is(err, ErrCryptographic) {
			t.Fatalf("public-only sign error = %v | 仅公钥签名错误 = %v", err, err)
		}
	})

	t.Run("SM2", func(t *testing.T) {
		private, public := mustKeyPair(t, AlgorithmSM2, 256)
		params := CryptographicParameters{DigitalSignatureAlgorithm: DigitalSignatureSM2SM3}
		signature, err := signKeyBlock(private, params, data, nil)
		if err != nil {
			t.Fatalf("sign: %v | 签名失败：%v", err, err)
		}
		if ok, err := verifyKeyBlock(public, params, data, nil, signature); err != nil || !ok {
			t.Fatalf("verify = %v, %v | 验签 = %v，%v", ok, err, ok, err)
		}
		if ok, _ := verifyKeyBlock(public, params, tampered, nil, signature); ok {
			t.Fatal("tampered SM2 signature verified | 篡改的 SM2 签名通过验签")
		}
		if _, err := signKeyBlock(private, params, nil, []byte{1}); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("prehashed sign error = %v | 预哈希签名错误 = %v", err, err)
		}
		if _, err := verifyKeyBlock(public, params, nil, []byte{1}, signature); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("prehashed verify error = %v | 预哈希验签错误 = %v", err, err)
		}
		if _, err := signKeyBlock(public, params, data, nil); !errors.Is(err, ErrCryptographic) {
			t.Fatalf("public-only sign error = %v | 仅公钥签名错误 = %v", err, err)
		}
	})

	aesKey := rawKeyBlock(AlgorithmAES, bytes.Repeat([]byte{1}, 32))
	if _, err := signKeyBlock(aesKey, CryptographicParameters{}, data, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("AES sign error = %v | AES 签名错误 = %v", err, err)
	}
	if _, err := verifyKeyBlock(aesKey, CryptographicParameters{}, data, nil, []byte("x")); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("AES verify error = %v | AES 验签错误 = %v", err, err)
	}
}

// TestMAC covers MAC generation, verification and constant-time length handling. |
// TestMAC 覆盖 MAC 生成、验证与常量时间长度处理。
func TestMAC(t *testing.T) {
	data := []byte("authenticate me")
	aesKey := rawKeyBlock(AlgorithmAES, bytes.Repeat([]byte{0x33}, 32))

	for _, testCase := range []struct {
		name   string
		key    KeyBlock
		params CryptographicParameters
		size   int
	}{
		{"AES default", aesKey, CryptographicParameters{}, 32},
		{"HMAC-SHA1", rawKeyBlock(AlgorithmHMACSHA1, bytes.Repeat([]byte{1}, 32)), CryptographicParameters{}, 20},
		{"HMAC-SHA224", rawKeyBlock(AlgorithmHMACSHA224, bytes.Repeat([]byte{1}, 32)), CryptographicParameters{}, 28},
		{"HMAC-SHA256", rawKeyBlock(AlgorithmHMACSHA256, bytes.Repeat([]byte{1}, 32)), CryptographicParameters{}, 32},
		{"HMAC-SHA384", rawKeyBlock(AlgorithmHMACSHA384, bytes.Repeat([]byte{1}, 32)), CryptographicParameters{}, 48},
		{"HMAC-SHA512", rawKeyBlock(AlgorithmHMACSHA512, bytes.Repeat([]byte{1}, 32)), CryptographicParameters{}, 64},
		{"AES explicit SHA512", aesKey, CryptographicParameters{HashingAlgorithm: HashingAlgorithmSHA512}, 64},
		{"AES explicit SM3", aesKey, CryptographicParameters{HashingAlgorithm: HashingAlgorithmSM3}, 32},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			first, err := macKeyBlock(testCase.key, testCase.params, data)
			if err != nil {
				t.Fatalf("mac: %v | MAC 失败：%v", err, err)
			}
			if len(first) != testCase.size {
				t.Fatalf("MAC length = %d, want %d | MAC 长度 = %d，期望 %d", len(first), testCase.size, len(first), testCase.size)
			}
			second, err := macKeyBlock(testCase.key, testCase.params, data)
			if err != nil || !bytes.Equal(first, second) {
				t.Fatalf("MAC is not deterministic: %v | MAC 不确定：%v", err, err)
			}
			if ok, err := macVerifyKeyBlock(testCase.key, testCase.params, data, first); err != nil || !ok {
				t.Fatalf("verify = %v, %v | 验证 = %v，%v", ok, err, ok, err)
			}
			if ok, err := macVerifyKeyBlock(testCase.key, testCase.params, []byte("other"), first); err != nil || ok {
				t.Fatalf("wrong data verify = %v, %v | 错误数据验证 = %v，%v", ok, err, ok, err)
			}
			if ok, err := macVerifyKeyBlock(testCase.key, testCase.params, data, first[:len(first)-1]); err != nil || ok {
				t.Fatalf("short MAC verify = %v, %v | 过短 MAC 验证 = %v，%v", ok, err, ok, err)
			}
			tampered := append([]byte(nil), first...)
			tampered[0] ^= 0xFF
			if ok, err := macVerifyKeyBlock(testCase.key, testCase.params, data, tampered); err != nil || ok {
				t.Fatalf("tampered MAC verify = %v, %v | 篡改 MAC 验证 = %v，%v", ok, err, ok, err)
			}
		})
	}

	if _, err := macKeyBlock(rawKeyBlock(AlgorithmAES, bytes.Repeat([]byte{1}, 32)), CryptographicParameters{HashingAlgorithm: HashingAlgorithm(0xFFFF)}, data); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported MAC hash error = %v | 不支持 MAC 哈希错误 = %v", err, err)
	}
	private, _ := mustKeyPair(t, AlgorithmRSA, 2048)
	if _, err := macKeyBlock(private, CryptographicParameters{}, data); !errors.Is(err, ErrCryptographic) {
		t.Fatalf("RSA MAC error = %v | RSA MAC 错误 = %v", err, err)
	}
	if _, err := macVerifyKeyBlock(private, CryptographicParameters{}, data, []byte("x")); !errors.Is(err, ErrCryptographic) {
		t.Fatalf("RSA MAC verify error = %v | RSA MAC 验证错误 = %v", err, err)
	}
	if got, err := macHash(AlgorithmSM3, CryptographicParameters{}); err != nil || got != HashingAlgorithmSM3 {
		t.Fatalf("SM3 MAC hash = 0x%08X, %v | SM3 MAC 哈希 = 0x%08X，%v", uint32(got), err, uint32(got), err)
	}
	if _, err := macHash(AlgorithmECDSA, CryptographicParameters{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ECDSA MAC hash error = %v | ECDSA MAC 哈希错误 = %v", err, err)
	}
}

// TestDeriveKeyBlock covers HKDF and PBKDF2 derivation. | TestDeriveKeyBlock 覆盖 HKDF 与 PBKDF2 派生。
func TestDeriveKeyBlock(t *testing.T) {
	input := rawKeyBlock(AlgorithmAES, bytes.Repeat([]byte{0x55}, 32))
	params := DerivationParameters{Salt: []byte("salt"), DerivationData: []byte("context")}

	first, err := deriveKeyBlock([]KeyBlock{input}, DerivationMethodHKDF, params, 0, 0)
	if err != nil {
		t.Fatalf("HKDF default: %v | HKDF 默认失败：%v", err, err)
	}
	if first.Format != KeyFormatRaw || first.Algorithm != AlgorithmAES || first.Length != 256 || len(first.Value.Material.Value) != 32 {
		t.Fatalf("HKDF default block = %s/%s/%d/%d | HKDF 默认块 = %s/%s/%d/%d",
			first.Format, first.Algorithm, first.Length, len(first.Value.Material.Value),
			first.Format, first.Algorithm, first.Length, len(first.Value.Material.Value))
	}
	second, err := deriveKeyBlock([]KeyBlock{input}, DerivationMethodHKDF, params, 0, 0)
	if err != nil || !bytes.Equal(first.Value.Material.Value, second.Value.Material.Value) {
		t.Fatalf("HKDF is not deterministic: %v | HKDF 不确定：%v", err, err)
	}
	other, err := deriveKeyBlock([]KeyBlock{input}, DerivationMethodHKDF, DerivationParameters{Salt: []byte("other")}, 0, 0)
	if err != nil || bytes.Equal(first.Value.Material.Value, other.Value.Material.Value) {
		t.Fatalf("HKDF ignored the salt: %v | HKDF 忽略了盐值：%v", err, err)
	}
	p384, err := deriveKeyBlock([]KeyBlock{input}, DerivationMethodHKDF, DerivationParameters{
		CryptographicParameters: &CryptographicParameters{HashingAlgorithm: HashingAlgorithmSHA384},
	}, AlgorithmSM4, 384)
	if err != nil {
		t.Fatalf("HKDF SHA384: %v | HKDF SHA384 失败：%v", err, err)
	}
	if p384.Algorithm != AlgorithmSM4 || p384.Length != 384 || len(p384.Value.Material.Value) != 48 {
		t.Fatalf("HKDF SHA384 block = %s/%d/%d | HKDF SHA384 块 = %s/%d/%d", p384.Algorithm, p384.Length, len(p384.Value.Material.Value), p384.Algorithm, p384.Length, len(p384.Value.Material.Value))
	}

	pbkdf2Params := DerivationParameters{Salt: []byte("salt"), IterationCount: 1000}
	derived, err := deriveKeyBlock([]KeyBlock{input}, DerivationMethodPBKDF2, pbkdf2Params, AlgorithmAES, 128)
	if err != nil || derived.Length != 128 || len(derived.Value.Material.Value) != 16 {
		t.Fatalf("PBKDF2 = %d/%d, %v | PBKDF2 = %d/%d，%v", derived.Length, len(derived.Value.Material.Value), err, derived.Length, len(derived.Value.Material.Value), err)
	}
	again, err := deriveKeyBlock([]KeyBlock{input}, DerivationMethodPBKDF2, pbkdf2Params, AlgorithmAES, 128)
	if err != nil || !bytes.Equal(derived.Value.Material.Value, again.Value.Material.Value) {
		t.Fatalf("PBKDF2 is not deterministic: %v | PBKDF2 不确定：%v", err, err)
	}
	defaultIterations, err := deriveKeyBlock([]KeyBlock{input}, DerivationMethodPBKDF2, DerivationParameters{Salt: []byte("salt")}, 0, 0)
	if err != nil || defaultIterations.Length != 256 {
		t.Fatalf("PBKDF2 default iterations = %v | PBKDF2 默认迭代 = %v", err, err)
	}

	errorCases := []struct {
		name   string
		keys   []KeyBlock
		method DerivationMethod
		params DerivationParameters
		bits   int
		want   error
	}{
		{"no keys", nil, DerivationMethodHKDF, params, 256, ErrInvalidRequest},
		{"two keys", []KeyBlock{input, input}, DerivationMethodHKDF, params, 256, ErrInvalidRequest},
		{"unsupported method", []KeyBlock{input}, DerivationMethod(0xFFFF), params, 256, ErrUnsupported},
		{"PBKDF2 without salt", []KeyBlock{input}, DerivationMethodPBKDF2, DerivationParameters{}, 256, ErrInvalidRequest},
		{"negative length", []KeyBlock{input}, DerivationMethodHKDF, params, -8, ErrInvalidRequest},
		{"unaligned length", []KeyBlock{input}, DerivationMethodHKDF, params, 12, ErrInvalidRequest},
		{"oversized length", []KeyBlock{input}, DerivationMethodHKDF, params, 5000, ErrInvalidRequest},
		{"unsupported hash", []KeyBlock{input}, DerivationMethodHKDF, DerivationParameters{CryptographicParameters: &CryptographicParameters{HashingAlgorithm: HashingAlgorithm(0xFFFF)}}, 256, ErrUnsupported},
	}
	for _, testCase := range errorCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := deriveKeyBlock(testCase.keys, testCase.method, testCase.params, 0, testCase.bits); !errors.Is(err, testCase.want) {
				t.Fatalf("error = %v, want %v | 错误 = %v，期望 %v", err, testCase.want, err, testCase.want)
			}
		})
	}
	private, _ := mustKeyPair(t, AlgorithmRSA, 2048)
	if _, err := deriveKeyBlock([]KeyBlock{private}, DerivationMethodHKDF, params, 0, 256); !errors.Is(err, ErrCryptographic) {
		t.Fatalf("RSA derivation error = %v | RSA 派生错误 = %v", err, err)
	}
	if _, err := deriveKeyBlock([]KeyBlock{rawKeyBlock(AlgorithmAES, []byte("junk"))}, DerivationMethodHKDF, params, 0, 256); err != nil {
		t.Fatalf("short symmetric input should derive: %v | 短对称输入应可派生：%v", err, err)
	}
}

// TestWrapUnwrapKeyBlock covers key wrapping with symmetric and RSA wrapping keys. |
// TestWrapUnwrapKeyBlock 覆盖使用对称与 RSA 封装密钥的密钥封装。
func TestWrapUnwrapKeyBlock(t *testing.T) {
	wrappingKey := rawKeyBlock(AlgorithmAES, bytes.Repeat([]byte{0x44}, 32))
	target := rawKeyBlock(AlgorithmAES, bytes.Repeat([]byte{0x66}, 32))
	target.Value.Attributes = AttributeList{NewTextAttribute(AttributeComment, "wrapped")}
	spec := KeyWrappingSpecification{
		WrappingMethod:           WrappingMethodEncrypt,
		EncryptionKeyInformation: &EncryptionKeyInformation{UniqueIdentifier: "wrapping-key"},
		EncodingOption:           EncodingOptionTTLVEncoding,
	}
	wrapped, err := wrapKeyBlock(target, wrappingKey, spec)
	if err != nil {
		t.Fatalf("wrap: %v | 封装失败：%v", err, err)
	}
	if wrapped.Wrapping == nil || wrapped.Wrapping.WrappingMethod != WrappingMethodEncrypt ||
		wrapped.Wrapping.EncryptionKeyInformation == nil || len(wrapped.Wrapping.IVCounterNonce) != 12 ||
		len(wrapped.Wrapping.MACSignature) != 16 || wrapped.Wrapping.EncodingOption != EncodingOptionTTLVEncoding {
		t.Fatalf("wrapping data = %+v | 封装数据 = %+v", wrapped.Wrapping, wrapped.Wrapping)
	}
	wrappedWithAttributes := wrapped
	wrappedWithAttributes.Value.Attributes = CloneAttributes(target.Value.Attributes)
	unwrapped, err := unwrapKeyBlock(wrappedWithAttributes, wrappingKey)
	if err != nil {
		t.Fatalf("unwrap: %v | 解封失败：%v", err, err)
	}
	if !bytes.Equal(unwrapped.Value.Material.Value, target.Value.Material.Value) {
		t.Fatalf("unwrapped material = %x | 解封材料 = %x", unwrapped.Value.Material.Value, unwrapped.Value.Material.Value)
	}
	if len(unwrapped.Value.Attributes) != 1 || unwrapped.Value.Attributes[0].Name != AttributeComment {
		t.Fatalf("unwrapped attributes = %+v | 解封属性 = %+v", unwrapped.Value.Attributes, unwrapped.Value.Attributes)
	}

	cbcSpec := spec
	cbcSpec.EncryptionKeyInformation = &EncryptionKeyInformation{
		UniqueIdentifier:        "wrapping-key",
		CryptographicParameters: &CryptographicParameters{BlockCipherMode: BlockCipherModeCBC, PaddingMethod: PaddingMethodPKCS5},
	}
	cbcWrapped, err := wrapKeyBlock(target, wrappingKey, cbcSpec)
	if err != nil {
		t.Fatalf("CBC wrap: %v | CBC 封装失败：%v", err, err)
	}
	cbcUnwrapped, err := unwrapKeyBlock(cbcWrapped, wrappingKey)
	if err != nil || !bytes.Equal(cbcUnwrapped.Value.Material.Value, target.Value.Material.Value) {
		t.Fatalf("CBC unwrap = %x, %v | CBC 解封 = %x，%v", cbcUnwrapped.Value.Material.Value, err, cbcUnwrapped.Value.Material.Value, err)
	}

	transparentTarget := KeyBlock{
		Format:    KeyFormatTransparentSymmetricKey,
		Algorithm: AlgorithmAES,
		Length:    256,
		Value:     KeyValue{Material: TransparentSymmetricKey{Key: bytes.Repeat([]byte{0x77}, 32)}.Item()},
	}
	transparentWrapped, err := wrapKeyBlock(transparentTarget, wrappingKey, spec)
	if err != nil {
		t.Fatalf("transparent wrap: %v | 透明封装失败：%v", err, err)
	}
	transparentUnwrapped, err := unwrapKeyBlock(transparentWrapped, wrappingKey)
	if err != nil {
		t.Fatalf("transparent unwrap: %v | 透明解封失败：%v", err, err)
	}
	parsed := mustParseKeyBlock(t, transparentUnwrapped)
	if !bytes.Equal(parsed.symmetric, bytes.Repeat([]byte{0x77}, 32)) {
		t.Fatal("transparent unwrap lost the key material | 透明解封丢失密钥材料")
	}

	rsaPrivate, rsaPublic := mustKeyPair(t, AlgorithmRSA, 2048)
	rsaWrapped, err := wrapKeyBlock(target, rsaPublic, KeyWrappingSpecification{
		EncryptionKeyInformation: &EncryptionKeyInformation{UniqueIdentifier: "rsa-key"},
	})
	if err != nil {
		t.Fatalf("RSA wrap: %v | RSA 封装失败：%v", err, err)
	}
	rsaUnwrapped, err := unwrapKeyBlock(rsaWrapped, rsaPrivate)
	if err != nil || !bytes.Equal(rsaUnwrapped.Value.Material.Value, target.Value.Material.Value) {
		t.Fatalf("RSA unwrap = %x, %v | RSA 解封 = %x，%v", rsaUnwrapped.Value.Material.Value, err, rsaUnwrapped.Value.Material.Value, err)
	}

	if _, err := wrapKeyBlock(target, wrappingKey, KeyWrappingSpecification{
		WrappingMethod:           WrappingMethodEncryptThenMACSign,
		EncryptionKeyInformation: &EncryptionKeyInformation{UniqueIdentifier: "wrapping-key"},
	}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported wrapping method error = %v | 不支持封装方法错误 = %v", err, err)
	}
	if _, err := wrapKeyBlock(target, wrappingKey, KeyWrappingSpecification{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("missing wrapping key error = %v | 缺少封装密钥错误 = %v", err, err)
	}
	if _, err := unwrapKeyBlock(target, wrappingKey); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unwrap not wrapped error = %v | 解封未封装密钥错误 = %v", err, err)
	}
	badMethod := wrapped
	badMethod.Wrapping = &KeyWrappingData{WrappingMethod: WrappingMethodEncryptThenMACSign, EncryptionKeyInformation: spec.EncryptionKeyInformation}
	if _, err := unwrapKeyBlock(badMethod, wrappingKey); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unwrap unsupported method error = %v | 解封不支持方法错误 = %v", err, err)
	}
	badEKI := wrapped
	badEKI.Wrapping = &KeyWrappingData{WrappingMethod: WrappingMethodEncrypt}
	if _, err := unwrapKeyBlock(badEKI, wrappingKey); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unwrap missing EKI error = %v | 解封缺少 EKI 错误 = %v", err, err)
	}
	wrongKey := rawKeyBlock(AlgorithmAES, bytes.Repeat([]byte{0x88}, 32))
	if _, err := unwrapKeyBlock(wrapped, wrongKey); !errors.Is(err, ErrCryptographic) {
		t.Fatalf("unwrap wrong key error = %v | 解封错误密钥错误 = %v", err, err)
	}
}

// TestRandomBytes covers the random byte helper. | TestRandomBytes 覆盖随机字节辅助函数。
func TestRandomBytes(t *testing.T) {
	first, err := randomBytes(16)
	if err != nil || len(first) != 16 {
		t.Fatalf("randomBytes(16) = %d, %v | 随机字节 = %d，%v", len(first), err, len(first), err)
	}
	second, err := randomBytes(16)
	if err != nil || bytes.Equal(first, second) {
		t.Fatalf("randomBytes produced repeated output: %v | 随机字节重复：%v", err, err)
	}
	empty, err := randomBytes(0)
	if err != nil || len(empty) != 0 {
		t.Fatalf("randomBytes(0) = %d, %v | 随机字节(0) = %d，%v", len(empty), err, len(empty), err)
	}
}
