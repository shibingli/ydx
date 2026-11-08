package webauthn

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"math/big"

	"github.com/shibingli/ydx/errs"
)

// TPM credential-protection labels. | TPM 凭据保护标签。
var (
	// tpmLabelIdentity is the credential seed protection label. | tpmLabelIdentity 是凭据种子保护标签。
	tpmLabelIdentity = []byte("IDENTITY")
	// tpmLabelStorage is the symmetric key derivation label. | tpmLabelStorage 是对称密钥派生标签。
	tpmLabelStorage = []byte("STORAGE")
	// tpmLabelIntegrity is the integrity HMAC key derivation label. | tpmLabelIntegrity 是完整性 HMAC
	// 密钥派生标签。
	tpmLabelIntegrity = []byte("INTEGRITY")
)

// TPMMakeCredentialResult is the output of the client side of TPM2_MakeCredential. |
// TPMMakeCredentialResult 是 TPM2_MakeCredential 客户端侧的输出。
type TPMMakeCredentialResult struct {
	// CredentialBlob is the TPM2B_ID_OBJECT command parameter. | CredentialBlob 是 TPM2B_ID_OBJECT
	// 命令参数。
	CredentialBlob TPM2BIDObject
	// Secret is the TPM2B_ENCRYPTED_SECRET command parameter. | Secret 是 TPM2B_ENCRYPTED_SECRET
	// 命令参数。
	Secret TPM2BEncryptedSecret
}

// MakeCredential implements the client side of TPM2_MakeCredential. | MakeCredential 实现
// TPM2_MakeCredential 的客户端侧。
//
// ek is the endorsement key public area, akName the TPM Name of the attestation key, and credential
// the secret to protect (at most one nameAlg digest). The returned blob and secret are exactly the
// two parameters of TPM2_MakeCredential. The RSA seed is generated from crypto/rand; ECC seeds are
// derived from an ephemeral ECDH key as the specification requires. Use MakeCredentialWithSeed for a
// deterministic RSA test vector. | ek 是背书密钥公钥区域，akName 是认证密钥的 TPM Name，credential
// 是要保护的秘密（不超过一个 nameAlg 摘要）。返回的 blob 与 secret 正是 TPM2_MakeCredential 的两个
// 参数。RSA 种子来自 crypto/rand；ECC 种子按规范由临时 ECDH 密钥派生。确定性 RSA 测试向量使用
// MakeCredentialWithSeed。
func MakeCredential(ek *TPMTPublic, akName TPM2BName, credential []byte) (*TPMMakeCredentialResult, error) {
	if err := ek.Validate(); err != nil {
		return nil, err
	}
	var seed []byte
	if ek.Type == TPMAlgRSA {
		hash, ok := TPMHash(ek.NameAlg)
		if !ok {
			return nil, errs.Detail(ErrUnsupportedAlgorithm, "endorsement key name algorithm %#04x | 背书密钥名称算法 %#04x",
				ek.NameAlg, ek.NameAlg)
		}
		seed = make([]byte, hash.Size())
		if err := tpmRandom(seed); err != nil {
			return nil, err
		}
	}
	return MakeCredentialWithSeed(ek, akName, credential, seed)
}

// MakeCredentialWithSeed is MakeCredential with a caller-supplied RSA seed. |
// MakeCredentialWithSeed 是使用调用方提供 RSA 种子的 MakeCredential。
//
// For an RSA endorsement key the seed must be exactly one nameAlg digest and must come from a
// cryptographically secure random source in production. ECC endorsement keys take the seed from the
// ephemeral ECDH exchange defined by TPM 2.0 Part 3, so seed must be empty for them; a non-empty seed
// is rejected with ErrEKActivation instead of being silently ignored. | 对 RSA 背书密钥，种子必须
// 恰好为一个 nameAlg 摘要，生产环境必须来自密码学安全随机源。ECC 背书密钥的种子由 TPM 2.0 第三部分
// 定义的临时 ECDH 交换产生，因此必须为空；非空种子会以 ErrEKActivation 拒绝，而不是被静默忽略。
func MakeCredentialWithSeed(ek *TPMTPublic, akName TPM2BName, credential, seed []byte) (*TPMMakeCredentialResult, error) {
	if err := ek.Validate(); err != nil {
		return nil, err
	}
	if !ek.IsRestrictedDecrypt() {
		return nil, errs.Detail(ErrEKActivation, "endorsement key lacks restricted decrypt attributes | 背书密钥缺少 restricted decrypt 属性")
	}
	if err := akName.Validate(); err != nil {
		return nil, err
	}
	hash, ok := TPMHash(ek.NameAlg)
	if !ok {
		return nil, errs.Detail(ErrUnsupportedAlgorithm, "endorsement key name algorithm %#04x | 背书密钥名称算法 %#04x",
			ek.NameAlg, ek.NameAlg)
	}
	digestSize := hash.Size()
	if len(credential) > digestSize {
		return nil, errs.Detail(ErrEKActivation, "credential is %d bytes, limit %d | 凭据为 %d 字节，上限 %d",
			len(credential), digestSize, len(credential), digestSize)
	}
	storageBits, err := ek.StorageSymmetric()
	if err != nil {
		return nil, err
	}
	secret, effectiveSeed, err := encryptCredentialSeed(ek, hash, seed)
	if err != nil {
		return nil, err
	}
	blob, err := protectCredential(hash, effectiveSeed, akName.Name, credential, storageBits)
	if err != nil {
		return nil, err
	}
	return &TPMMakeCredentialResult{CredentialBlob: blob, Secret: secret}, nil
}

// encryptCredentialSeed builds TPM2B_ENCRYPTED_SECRET and returns the seed that protects the
// credential. | encryptCredentialSeed 构建 TPM2B_ENCRYPTED_SECRET，并返回保护凭据所用的种子。
func encryptCredentialSeed(ek *TPMTPublic, hash crypto.Hash, seed []byte) (TPM2BEncryptedSecret, []byte, error) {
	switch ek.Type {
	case TPMAlgRSA:
		if len(seed) != hash.Size() {
			return TPM2BEncryptedSecret{}, nil, errs.Detail(ErrEKActivation, "credential seed is %d bytes, name algorithm needs %d | 凭据种子为 %d 字节，名称算法需要 %d",
				len(seed), hash.Size(), len(seed), hash.Size())
		}
		public, err := ek.PublicKey()
		if err != nil {
			return TPM2BEncryptedSecret{}, nil, err
		}
		rsaPublic, ok := public.(*rsa.PublicKey)
		if !ok {
			return TPM2BEncryptedSecret{}, nil, errs.Detail(ErrEKActivation, "endorsement key is not an RSA key | 背书密钥不是 RSA 密钥")
		}
		ciphertext, err := rsa.EncryptOAEP(hash.New(), rand.Reader, rsaPublic, seed, tpmIdentityLabel())
		if err != nil {
			return TPM2BEncryptedSecret{}, nil, errs.WrapDetail(err, ErrEKActivation, "RSA-OAEP credential seed encryption failed | RSA-OAEP 凭据种子加密失败")
		}
		return TPM2BEncryptedSecret{Buffer: ciphertext}, seed, nil
	case TPMAlgECC:
		if len(seed) != 0 {
			return TPM2BEncryptedSecret{}, nil, errs.Detail(ErrEKActivation, "ECC endorsement keys derive the seed from ECDH; seed must be empty | ECC 背书密钥从 ECDH 派生种子；种子必须为空")
		}
		curve, err := tpmECDHCurve(ek.CurveID)
		if err != nil {
			return TPM2BEncryptedSecret{}, nil, err
		}
		fieldSize, err := tpmECCFieldSize(ek.CurveID)
		if err != nil {
			return TPM2BEncryptedSecret{}, nil, err
		}
		ekX := leftPadBytes(ek.ECCPoint.X, fieldSize)
		ekY := leftPadBytes(ek.ECCPoint.Y, fieldSize)
		point := make([]byte, 0, 1+2*fieldSize)
		point = append(point, 0x04)
		point = append(point, ekX...)
		point = append(point, ekY...)
		ekPublic, err := curve.NewPublicKey(point)
		if err != nil {
			return TPM2BEncryptedSecret{}, nil, errs.WrapDetail(err, ErrEKActivation, "endorsement key ECC point is invalid | 背书密钥 ECC 点非法")
		}
		ephemeral, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return TPM2BEncryptedSecret{}, nil, errs.WrapDetail(err, ErrChallengeGeneration, "ephemeral ECC key generation failed | 临时 ECC 密钥生成失败")
		}
		shared, err := ephemeral.ECDH(ekPublic)
		if err != nil {
			return TPM2BEncryptedSecret{}, nil, errs.WrapDetail(err, ErrEKActivation, "ECDH shared secret computation failed | ECDH 共享秘密计算失败")
		}
		ephemeralPoint := ephemeral.PublicKey().Bytes()
		if len(ephemeralPoint) != 1+2*fieldSize || ephemeralPoint[0] != 0x04 {
			return TPM2BEncryptedSecret{}, nil, errs.Detail(ErrEKActivation, "ephemeral ECC public point has %d bytes | 临时 ECC 公钥点有 %d 字节",
				len(ephemeralPoint), len(ephemeralPoint))
		}
		ephemeralX := ephemeralPoint[1 : 1+fieldSize]
		ephemeralY := ephemeralPoint[1+fieldSize:]
		derivedSeed, err := KDFe(hash, shared, tpmLabelIdentity, ephemeralX, ekX, hash.Size()*8)
		if err != nil {
			return TPM2BEncryptedSecret{}, nil, err
		}
		if len(derivedSeed) != hash.Size() {
			return TPM2BEncryptedSecret{}, nil, errs.Detail(ErrEKActivation, "KDFe produced %d bytes, need %d | KDFe 产生 %d 字节，需要 %d",
				len(derivedSeed), hash.Size(), len(derivedSeed), hash.Size())
		}
		pointSecret, err := (TPMSEccPoint{X: ephemeralX, Y: ephemeralY}).Marshal()
		if err != nil {
			return TPM2BEncryptedSecret{}, nil, err
		}
		return TPM2BEncryptedSecret{Buffer: pointSecret}, derivedSeed, nil
	default:
		return TPM2BEncryptedSecret{}, nil, errs.Detail(ErrUnsupportedKey, "unsupported endorsement key type %#04x | 不支持的背书密钥类型 %#04x",
			ek.Type, ek.Type)
	}
}

// protectCredential builds the TPM2B_ID_OBJECT for a seed and credential. | protectCredential 为种子与
// 凭据构建 TPM2B_ID_OBJECT。
//
// The encrypted plaintext is the marshaled TPM2B_DIGEST credential (a two-byte size followed by the
// digest); encIdentity carries its own TPM2B size prefix in the outer structure. | 加密明文是已编码的
// TPM2B_DIGEST 凭据（两字节长度后跟摘要）；encIdentity 在外层结构中自带 TPM2B 长度前缀。
func protectCredential(hash crypto.Hash, seed, akName, credential []byte, storageBits int) (TPM2BIDObject, error) {
	digestSize := hash.Size()
	symmetricKey, err := KDFa(hash, seed, tpmLabelStorage, akName, nil, storageBits)
	if err != nil {
		return TPM2BIDObject{}, err
	}
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return TPM2BIDObject{}, errs.WrapDetail(err, ErrEKActivation, "AES credential key is invalid | AES 凭据密钥非法")
	}
	plaintext := make([]byte, 2, 2+len(credential))
	plaintext[0] = byte(len(credential) >> 8)
	plaintext[1] = byte(len(credential))
	plaintext = append(plaintext, credential...)
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCFBEncrypter(block, make([]byte, aes.BlockSize)).XORKeyStream(ciphertext, plaintext)
	integrityKey, err := KDFa(hash, seed, tpmLabelIntegrity, nil, nil, digestSize*8)
	if err != nil {
		return TPM2BIDObject{}, err
	}
	mac := hmac.New(hash.New, integrityKey)
	_, _ = mac.Write(ciphertext)
	_, _ = mac.Write(akName)
	integrity := mac.Sum(nil)
	blob := make([]byte, 0, 2+len(integrity)+2+len(ciphertext))
	blob = tpm2AppendU16(blob, uint16(len(integrity)))
	blob = append(blob, integrity...)
	blob = tpm2AppendU16(blob, uint16(len(ciphertext)))
	blob = append(blob, ciphertext...)
	return TPM2BIDObject{Buffer: blob}, nil
}

// ActivateCredential implements the TPM side of TPM2_ActivateCredential in software. |
// ActivateCredential 以软件实现 TPM2_ActivateCredential 的 TPM 侧。
//
// ek is the endorsement key public area, ekPrivate its private key (*rsa.PrivateKey,
// *ecdsa.PrivateKey or *ecdh.PrivateKey), akName the Name of the activated attestation key, and the
// two blobs are the TPM2_MakeCredential parameters. The returned credential is the recovered
// plaintext; an integrity mismatch returns ErrEKActivation, while malformed structures return
// ErrTPMStructure. This function is the reference implementation used by the simulator and by
// interoperability tests; real deployments let the physical TPM execute TPM2_ActivateCredential. |
// ek 是背书密钥公钥区域，ekPrivate 是其私钥（*rsa.PrivateKey、*ecdsa.PrivateKey 或
// *ecdh.PrivateKey），akName 是被激活认证密钥的 Name，两个 blob 是 TPM2_MakeCredential 参数。返回的
// credential 是恢复的明文；完整性不匹配返回 ErrEKActivation，结构非法返回 ErrTPMStructure。本函数是
// 模拟器与互操作测试使用的参考实现；真实部署由物理 TPM 执行 TPM2_ActivateCredential。
func ActivateCredential(ek *TPMTPublic, ekPrivate crypto.PrivateKey, akName TPM2BName, blob TPM2BIDObject, secret TPM2BEncryptedSecret) ([]byte, error) {
	if err := ek.Validate(); err != nil {
		return nil, err
	}
	if !ek.IsRestrictedDecrypt() {
		return nil, errs.Detail(ErrEKActivation, "endorsement key lacks restricted decrypt attributes | 背书密钥缺少 restricted decrypt 属性")
	}
	if err := akName.Validate(); err != nil {
		return nil, err
	}
	hash, ok := TPMHash(ek.NameAlg)
	if !ok {
		return nil, errs.Detail(ErrUnsupportedAlgorithm, "endorsement key name algorithm %#04x | 背书密钥名称算法 %#04x",
			ek.NameAlg, ek.NameAlg)
	}
	digestSize := hash.Size()
	seed, err := recoverCredentialSeed(ek, ekPrivate, hash, secret)
	if err != nil {
		return nil, err
	}
	if len(seed) != digestSize {
		return nil, errs.Detail(ErrEKActivation, "recovered seed is %d bytes, need %d | 恢复的种子为 %d 字节，需要 %d",
			len(seed), digestSize, len(seed), digestSize)
	}
	integrity, ciphertext, err := parseIDObject(blob)
	if err != nil {
		return nil, err
	}
	if len(integrity) != digestSize {
		return nil, errs.Detail(ErrEKActivation, "credential integrity HMAC is %d bytes, need %d | 凭据完整性 HMAC 为 %d 字节，需要 %d",
			len(integrity), digestSize, len(integrity), digestSize)
	}
	integrityKey, err := KDFa(hash, seed, tpmLabelIntegrity, nil, nil, digestSize*8)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(hash.New, integrityKey)
	_, _ = mac.Write(ciphertext)
	_, _ = mac.Write(akName.Name)
	if !constantTimeEqual(mac.Sum(nil), integrity) {
		return nil, errs.Detail(ErrEKActivation, "credential integrity HMAC does not match | 凭据完整性 HMAC 不匹配")
	}
	storageBits, err := ek.StorageSymmetric()
	if err != nil {
		return nil, err
	}
	symmetricKey, err := KDFa(hash, seed, tpmLabelStorage, akName.Name, nil, storageBits)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrEKActivation, "AES credential key is invalid | AES 凭据密钥非法")
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCFBDecrypter(block, make([]byte, aes.BlockSize)).XORKeyStream(plaintext, ciphertext)
	if len(plaintext) < 2 {
		return nil, errs.Detail(ErrTPMStructure, "credential plaintext is %d bytes | 凭据明文为 %d 字节", len(plaintext), len(plaintext))
	}
	credentialSize := int(plaintext[0])<<8 | int(plaintext[1])
	if credentialSize != len(plaintext)-2 {
		return nil, errs.Detail(ErrTPMStructure, "credential size field is %d, plaintext holds %d | 凭据长度字段为 %d，明文包含 %d",
			credentialSize, len(plaintext)-2, credentialSize, len(plaintext)-2)
	}
	if credentialSize > digestSize {
		return nil, errs.Detail(ErrEKActivation, "credential is %d bytes, limit %d | 凭据为 %d 字节，上限 %d",
			credentialSize, digestSize, credentialSize, digestSize)
	}
	return append([]byte(nil), plaintext[2:]...), nil
}

// VerifyActivationCertInfo checks a TPM2_ActivateCredential certInfo value. | VerifyActivationCertInfo
// 校验 TPM2_ActivateCredential 的 certInfo 值。
//
// The attestation must be a TPM_ST_ATTEST_CERTIFY structure whose extraData equals the expected
// credential and whose attested Name equals akName. Any mismatch returns ErrEKActivation; malformed
// structures return ErrTPMStructure. | 认证必须是 TPM_ST_ATTEST_CERTIFY 结构，extraData 等于预期凭据，
// 且受认证 Name 等于 akName。任何不匹配返回 ErrEKActivation；结构非法返回 ErrTPMStructure。
func VerifyActivationCertInfo(certInfo TPM2BAttest, expectedCredential []byte, akName TPM2BName) error {
	attest, err := ParseTPMSAttest(certInfo.Buffer)
	if err != nil {
		return err
	}
	if err := akName.Validate(); err != nil {
		return err
	}
	if !constantTimeEqual(attest.ExtraData, expectedCredential) {
		return errs.Detail(ErrEKActivation, "credential activation extraData does not match | 凭据激活 extraData 不匹配")
	}
	if !constantTimeEqual(attest.Name, akName.Name) {
		return errs.Detail(ErrEKActivation, "credential activation attested Name does not match | 凭据激活受认证 Name 不匹配")
	}
	return nil
}

// parseIDObject splits a TPM2B_ID_OBJECT into its integrity HMAC and ciphertext. | parseIDObject 把
// TPM2B_ID_OBJECT 拆分为完整性 HMAC 与密文。
func parseIDObject(blob TPM2BIDObject) ([]byte, []byte, error) {
	r := &tpm2Reader{data: blob.Buffer}
	integritySize, err := r.u16()
	if err != nil {
		return nil, nil, err
	}
	if integritySize == 0 || integritySize > 64 {
		return nil, nil, errs.Detail(ErrTPMStructure, "credential integrity HMAC is %d bytes | 凭据完整性 HMAC 为 %d 字节",
			integritySize, integritySize)
	}
	integrity, err := r.bytes(int(integritySize))
	if err != nil {
		return nil, nil, err
	}
	cipherSize, err := r.u16()
	if err != nil {
		return nil, nil, err
	}
	if cipherSize < 2 {
		return nil, nil, errs.Detail(ErrTPMStructure, "credential ciphertext is %d bytes | 凭据密文为 %d 字节",
			cipherSize, cipherSize)
	}
	ciphertext, err := r.bytes(int(cipherSize))
	if err != nil {
		return nil, nil, err
	}
	if !r.done() {
		return nil, nil, errs.Detail(ErrTPMStructure, "credential ID object has %d trailing bytes | 凭据 ID 对象有 %d 个多余字节",
			r.remaining(), r.remaining())
	}
	return append([]byte(nil), integrity...), append([]byte(nil), ciphertext...), nil
}

// recoverCredentialSeed decrypts or derives the credential seed from TPM2B_ENCRYPTED_SECRET. |
// recoverCredentialSeed 从 TPM2B_ENCRYPTED_SECRET 解密或派生凭据种子。
func recoverCredentialSeed(ek *TPMTPublic, ekPrivate crypto.PrivateKey, hash crypto.Hash, secret TPM2BEncryptedSecret) ([]byte, error) {
	switch ek.Type {
	case TPMAlgRSA:
		privateKey, ok := ekPrivate.(*rsa.PrivateKey)
		if !ok || privateKey == nil {
			return nil, errs.Detail(ErrEKActivation, "endorsement private key is not RSA | 背书私钥不是 RSA")
		}
		if err := rsaMatchesPublic(privateKey, ek); err != nil {
			return nil, err
		}
		seed, err := rsa.DecryptOAEP(hash.New(), rand.Reader, privateKey, secret.Buffer, tpmIdentityLabel())
		if err != nil {
			return nil, errs.WrapDetail(err, ErrEKActivation, "RSA-OAEP credential seed decryption failed | RSA-OAEP 凭据种子解密失败")
		}
		return seed, nil
	case TPMAlgECC:
		fieldSize, err := tpmECCFieldSize(ek.CurveID)
		if err != nil {
			return nil, err
		}
		r := &tpm2Reader{data: secret.Buffer}
		ephemeral, err := parseTPMSEccPoint(r)
		if err != nil {
			return nil, err
		}
		if !r.done() {
			return nil, errs.Detail(ErrTPMStructure, "ECC encrypted secret has %d trailing bytes | ECC 加密秘密有 %d 个多余字节",
				r.remaining(), r.remaining())
		}
		curve, err := tpmECDHCurve(ek.CurveID)
		if err != nil {
			return nil, err
		}
		paddedX := leftPadBytes(ephemeral.X, fieldSize)
		paddedY := leftPadBytes(ephemeral.Y, fieldSize)
		point := make([]byte, 0, 1+2*fieldSize)
		point = append(point, 0x04)
		point = append(point, paddedX...)
		point = append(point, paddedY...)
		ephemeralPublic, err := curve.NewPublicKey(point)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrEKActivation, "ephemeral ECC point is invalid | 临时 ECC 点非法")
		}
		privateKey, err := ecdhPrivateKey(curve, fieldSize, ekPrivate, ek)
		if err != nil {
			return nil, err
		}
		shared, err := privateKey.ECDH(ephemeralPublic)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrEKActivation, "ECDH shared secret computation failed | ECDH 共享秘密计算失败")
		}
		ekX := leftPadBytes(ek.ECCPoint.X, fieldSize)
		return KDFe(hash, shared, tpmLabelIdentity, paddedX, ekX, hash.Size()*8)
	default:
		return nil, errs.Detail(ErrUnsupportedKey, "unsupported endorsement key type %#04x | 不支持的背书密钥类型 %#04x",
			ek.Type, ek.Type)
	}
}

// ecdhPrivateKey converts the accepted ECC private-key representations to crypto/ecdh. |
// ecdhPrivateKey 把接受的 ECC 私钥表示转换为 crypto/ecdh。
func ecdhPrivateKey(curve ecdh.Curve, fieldSize int, ekPrivate crypto.PrivateKey, ek *TPMTPublic) (*ecdh.PrivateKey, error) {
	var scalar []byte
	switch key := ekPrivate.(type) {
	case *ecdh.PrivateKey:
		if key == nil {
			return nil, errs.Detail(ErrEKActivation, "endorsement private key is nil | 背书私钥为空")
		}
		publicBytes := key.PublicKey().Bytes()
		expected := leftPadBytes(ek.ECCPoint.X, fieldSize)
		if len(publicBytes) != 1+2*fieldSize || !constantTimeEqual(publicBytes[1:1+fieldSize], expected) {
			return nil, errs.Detail(ErrEKActivation, "endorsement private key does not match the public area | 背书私钥与公钥区域不匹配")
		}
		return key, nil
	case *ecdsa.PrivateKey:
		if key == nil || key.D == nil {
			return nil, errs.Detail(ErrEKActivation, "endorsement private key is nil | 背书私钥为空")
		}
		scalar = key.D.FillBytes(make([]byte, fieldSize))
	default:
		return nil, errs.Detail(ErrEKActivation, "endorsement private key type %T is not ECDH | 背书私钥类型 %T 不是 ECDH", ekPrivate, ekPrivate)
	}
	privateKey, err := curve.NewPrivateKey(scalar)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrEKActivation, "endorsement ECC private key is invalid | 背书 ECC 私钥非法")
	}
	publicBytes := privateKey.PublicKey().Bytes()
	expectedX := leftPadBytes(ek.ECCPoint.X, fieldSize)
	expectedY := leftPadBytes(ek.ECCPoint.Y, fieldSize)
	if len(publicBytes) != 1+2*fieldSize || !constantTimeEqual(publicBytes[1:1+fieldSize], expectedX) ||
		!constantTimeEqual(publicBytes[1+fieldSize:], expectedY) {
		return nil, errs.Detail(ErrEKActivation, "endorsement private key does not match the public area | 背书私钥与公钥区域不匹配")
	}
	return privateKey, nil
}

// rsaMatchesPublic checks that an RSA private key belongs to the public area. | rsaMatchesPublic 检查
// RSA 私钥是否属于公钥区域。
func rsaMatchesPublic(privateKey *rsa.PrivateKey, ek *TPMTPublic) error {
	modulus := new(big.Int).SetBytes(ek.RSAModulus)
	if privateKey.N == nil || privateKey.N.Cmp(modulus) != 0 {
		return errs.Detail(ErrEKActivation, "endorsement private key does not match the public modulus | 背书私钥与公钥模数不匹配")
	}
	exponent := int(ek.Exponent)
	if exponent == 0 {
		exponent = tpmDefaultExponent
	}
	if privateKey.E != exponent {
		return errs.Detail(ErrEKActivation, "endorsement private key does not match the public exponent | 背书私钥与公钥指数不匹配")
	}
	return nil
}

// tpmECDHCurve maps a TPM curve identifier to crypto/ecdh. | tpmECDHCurve 把 TPM 曲线标识映射为
// crypto/ecdh。
func tpmECDHCurve(id uint16) (ecdh.Curve, error) {
	switch id {
	case TPMEccNISTP256:
		return ecdh.P256(), nil
	case TPMEccNISTP384:
		return ecdh.P384(), nil
	case TPMEccNISTP521:
		return ecdh.P521(), nil
	default:
		return nil, errs.Detail(ErrUnsupportedKey, "unsupported TPM ECC curve %#04x | 不支持的 TPM ECC 曲线 %#04x", id, id)
	}
}

// tpmIdentityLabel returns the OAEP label required by TPM2_MakeCredential. | tpmIdentityLabel 返回
// TPM2_MakeCredential 要求的 OAEP 标签。
func tpmIdentityLabel() []byte {
	label := make([]byte, 0, len(tpmLabelIdentity)+1)
	label = append(label, tpmLabelIdentity...)
	label = append(label, 0)
	return label
}

// leftPadBytes returns value left-padded with zeros to size bytes. | leftPadBytes 返回左侧补零到 size
// 字节的 value。
func leftPadBytes(value []byte, size int) []byte {
	if len(value) >= size {
		return value
	}
	out := make([]byte, size)
	copy(out[size-len(value):], value)
	return out
}
