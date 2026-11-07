package jose

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"io"

	"github.com/shibingli/ydx/errs"
)

// DefaultJWEMaxDecompressedSize is the default plaintext limit for a DEF-compressed JWE. | DefaultJWEMaxDecompressedSize
// 是 DEF 压缩 JWE 的默认明文上限。
const DefaultJWEMaxDecompressedSize = 32 << 20

// encParams describes the content-encryption algorithm. | encParams 描述内容加密算法。
type encParams struct {
	hash   crypto.Hash
	cekLen int
	tagLen int
	cbc    bool
}

// encParamsFor returns the parameters of a supported enc algorithm. | encParamsFor 返回受支持
// enc 算法的参数。
func encParamsFor(enc string) (encParams, bool) {
	switch enc {
	case "A128CBC-HS256":
		return encParams{cekLen: 32, tagLen: 16, hash: crypto.SHA256, cbc: true}, true
	case "A192CBC-HS384":
		return encParams{cekLen: 48, tagLen: 24, hash: crypto.SHA384, cbc: true}, true
	case "A256CBC-HS512":
		return encParams{cekLen: 64, tagLen: 32, hash: crypto.SHA512, cbc: true}, true
	case "A128GCM":
		return encParams{cekLen: 16, tagLen: 16}, true
	case "A192GCM":
		return encParams{cekLen: 24, tagLen: 16}, true
	case "A256GCM":
		return encParams{cekLen: 32, tagLen: 16}, true
	}
	return encParams{}, false
}

// supportedEnc reports whether enc is implemented. | supportedEnc 报告 enc 是否已实现。
func supportedEnc(enc string) bool {
	_, ok := encParamsFor(enc)
	return ok
}

// randomBytes returns n cryptographically random bytes. | randomBytes 返回 n 个加密安全随机字节。
func randomBytes(n int) ([]byte, error) {
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidKey, "random bytes | 随机字节")
	}
	return out, nil
}

// sealContent encrypts plaintext under cek for enc. | sealContent 使用 cek 按 enc 加密 plaintext。
func sealContent(enc string, cek, aad, plaintext []byte) (iv, ciphertext, tag []byte, err error) {
	p, ok := encParamsFor(enc)
	if !ok {
		return nil, nil, nil, errs.Detail(ErrUnsupportedEnc, "enc=%[1]q | enc=%[1]q", enc)
	}
	if len(cek) != p.cekLen {
		return nil, nil, nil, errs.Detail(ErrWeakKey, "enc=%[1]s needs a %[2]d-byte CEK | enc=%[1]s 需要 %[2]d 字节 CEK", enc, p.cekLen)
	}
	if p.cbc {
		macKey := cek[:p.cekLen/2]
		encKey := cek[p.cekLen/2:]
		iv, err = randomBytes(aes.BlockSize)
		if err != nil {
			return nil, nil, nil, err
		}
		block, err := aes.NewCipher(encKey)
		if err != nil {
			return nil, nil, nil, errs.WrapDetail(err, ErrInvalidKey, "AES | AES")
		}
		padded := pkcs7Pad(plaintext, aes.BlockSize)
		ciphertext = make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
		tag = cbcTag(p.hash, macKey, aad, iv, ciphertext, p.tagLen)
		return iv, ciphertext, tag, nil
	}
	iv, err = randomBytes(12)
	if err != nil {
		return nil, nil, nil, err
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, nil, nil, errs.WrapDetail(err, ErrInvalidKey, "AES | AES")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, errs.WrapDetail(err, ErrInvalidKey, "AES-GCM | AES-GCM")
	}
	sealed := aead.Seal(nil, iv, plaintext, aad)
	cut := len(sealed) - p.tagLen
	return iv, sealed[:cut], sealed[cut:], nil
}

// openContent authenticates and decrypts a JWE content segment. | openContent 认证并解密 JWE
// 内容段。
func openContent(enc string, cek, aad, iv, ciphertext, tag []byte) ([]byte, error) {
	p, ok := encParamsFor(enc)
	if !ok {
		return nil, errs.Detail(ErrUnsupportedEnc, "enc=%[1]q | enc=%[1]q", enc)
	}
	if len(cek) != p.cekLen {
		return nil, errs.Detail(ErrWeakKey, "enc=%[1]s needs a %[2]d-byte CEK | enc=%[1]s 需要 %[2]d 字节 CEK", enc, p.cekLen)
	}
	if p.cbc {
		if len(iv) != aes.BlockSize || len(tag) != p.tagLen || len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
			return nil, errs.Detail(ErrDecryptionFailed, "invalid CBC segment lengths | CBC 段长度非法")
		}
		macKey := cek[:p.cekLen/2]
		encKey := cek[p.cekLen/2:]
		expected := cbcTag(p.hash, macKey, aad, iv, ciphertext, p.tagLen)
		if subtle.ConstantTimeCompare(expected, tag) != 1 {
			return nil, errs.Detail(ErrDecryptionFailed, "CBC authentication tag mismatch | CBC 认证标签不匹配")
		}
		block, err := aes.NewCipher(encKey)
		if err != nil {
			return nil, errs.Detail(ErrDecryptionFailed, "AES key | AES 密钥")
		}
		padded := make([]byte, len(ciphertext))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(padded, ciphertext)
		plaintext, err := pkcs7Unpad(padded, aes.BlockSize)
		if err != nil {
			return nil, err
		}
		return plaintext, nil
	}
	if len(iv) != 12 || len(tag) != p.tagLen {
		return nil, errs.Detail(ErrDecryptionFailed, "invalid GCM segment lengths | GCM 段长度非法")
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, errs.Detail(ErrDecryptionFailed, "AES key | AES 密钥")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errs.Detail(ErrDecryptionFailed, "AES-GCM | AES-GCM")
	}
	sealed := make([]byte, 0, len(ciphertext)+len(tag))
	sealed = append(sealed, ciphertext...)
	sealed = append(sealed, tag...)
	plaintext, err := aead.Open(nil, iv, sealed, aad)
	if err != nil {
		return nil, errs.Detail(ErrDecryptionFailed, "GCM authentication failed | GCM 认证失败")
	}
	return plaintext, nil
}

// cbcTag computes the truncated HMAC tag of a CBC-HS JWE. | cbcTag 计算 CBC-HS JWE 的截断 HMAC 标签。
func cbcTag(h crypto.Hash, macKey, aad, iv, ciphertext []byte, tagLen int) []byte {
	mac := hmac.New(h.New, macKey)
	_, _ = mac.Write(aad)
	_, _ = mac.Write(iv)
	_, _ = mac.Write(ciphertext)
	var al [8]byte
	binary.BigEndian.PutUint64(al[:], uint64(len(aad))*8)
	_, _ = mac.Write(al[:])
	return mac.Sum(nil)[:tagLen]
}

// pkcs7Pad appends PKCS#7 padding to data. | pkcs7Pad 为 data 追加 PKCS#7 填充。
func pkcs7Pad(data []byte, blockSize int) []byte {
	n := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+n)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(n)
	}
	return out
}

// pkcs7Unpad removes and validates PKCS#7 padding. | pkcs7Unpad 移除并校验 PKCS#7 填充。
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errs.Detail(ErrDecryptionFailed, "invalid padded length | 填充后长度非法")
	}
	n := int(data[len(data)-1])
	if n == 0 || n > blockSize || n > len(data) {
		return nil, errs.Detail(ErrDecryptionFailed, "invalid padding | 填充非法")
	}
	var mismatch byte
	for _, b := range data[len(data)-n:] {
		mismatch |= b ^ byte(n)
	}
	if mismatch != 0 {
		return nil, errs.Detail(ErrDecryptionFailed, "invalid padding | 填充非法")
	}
	return data[:len(data)-n], nil
}

// deflate compresses data with raw DEFLATE. | deflate 使用原始 DEFLATE 压缩 data。
func deflate(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidConfig, "DEFLATE writer | DEFLATE 写入器")
	}
	if _, err := w.Write(data); err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidConfig, "DEFLATE write | DEFLATE 写入")
	}
	if err := w.Close(); err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidConfig, "DEFLATE close | DEFLATE 关闭")
	}
	return buf.Bytes(), nil
}

// inflate decompresses raw DEFLATE data, refusing output above limit. | inflate 解压原始 DEFLATE
// 数据，并拒绝超过 limit 的输出。
func inflate(data []byte, limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = DefaultJWEMaxDecompressedSize
	}
	r := flate.NewReader(bytes.NewReader(data))
	defer func() { _ = r.Close() }()
	out, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, errs.Detail(ErrDecryptionFailed, "DEFLATE decode failed | DEFLATE 解码失败")
	}
	if int64(len(out)) > limit {
		return nil, errs.Detail(ErrDecompressionLimit, "limit %[1]d bytes | 上限 %[1]d 字节", limit)
	}
	return out, nil
}

// aesKeyWrap wraps cek with kek per RFC 3394. | aesKeyWrap 按 RFC 3394 使用 kek 包装 cek。
func aesKeyWrap(kek, cek []byte) ([]byte, error) {
	switch len(kek) {
	case 16, 24, 32:
	default:
		return nil, errs.Detail(ErrWeakKey, "AES-KW key is %[1]d bytes | AES-KW 密钥为 %[1]d 字节", len(kek))
	}
	if len(cek) < 16 || len(cek)%8 != 0 {
		return nil, errs.Detail(ErrInvalidKey, "AES-KW data is %[1]d bytes | AES-KW 数据为 %[1]d 字节", len(cek))
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidKey, "AES-KW cipher | AES-KW 密码")
	}
	n := len(cek) / 8
	a := [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	r := append([]byte(nil), cek...)
	buf := make([]byte, 16)
	for j := 0; j < 6; j++ {
		for i := 1; i <= n; i++ {
			copy(buf[:8], a[:])
			copy(buf[8:], r[(i-1)*8:i*8])
			block.Encrypt(buf, buf)
			t := uint64(n*j + i)
			binary.BigEndian.PutUint64(a[:], binary.BigEndian.Uint64(buf[:8])^t)
			copy(r[(i-1)*8:i*8], buf[8:])
		}
	}
	out := make([]byte, 8+len(r))
	copy(out[:8], a[:])
	copy(out[8:], r)
	return out, nil
}

// aesKeyUnwrap unwraps data with kek per RFC 3394 and verifies the IV. | aesKeyUnwrap 按 RFC 3394
// 使用 kek 解包 data，并校验 IV。
func aesKeyUnwrap(kek, data []byte) ([]byte, error) {
	switch len(kek) {
	case 16, 24, 32:
	default:
		return nil, errs.Detail(ErrWeakKey, "AES-KW key is %[1]d bytes | AES-KW 密钥为 %[1]d 字节", len(kek))
	}
	if len(data) < 24 || (len(data)-8)%8 != 0 {
		return nil, errs.Detail(ErrDecryptionFailed, "AES-KW data is %[1]d bytes | AES-KW 数据为 %[1]d 字节", len(data))
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, errs.Detail(ErrDecryptionFailed, "AES-KW cipher | AES-KW 密码")
	}
	n := (len(data) - 8) / 8
	r := append([]byte(nil), data[8:]...)
	var a [8]byte
	copy(a[:], data[:8])
	buf := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n*j + i)
			binary.BigEndian.PutUint64(buf[:8], binary.BigEndian.Uint64(a[:])^t)
			copy(buf[8:], r[(i-1)*8:i*8])
			block.Decrypt(buf, buf)
			copy(a[:], buf[:8])
			copy(r[(i-1)*8:i*8], buf[8:])
		}
	}
	constIV := [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	if subtle.ConstantTimeCompare(a[:], constIV[:]) != 1 {
		return nil, errs.Detail(ErrDecryptionFailed, "AES-KW integrity check failed | AES-KW 完整性校验失败")
	}
	return r, nil
}

// appendLengthPrefixed appends b with a four-byte big-endian length prefix. | appendLengthPrefixed
// 以四字节大端长度前缀追加 b。
func appendLengthPrefixed(dst, b []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	dst = append(dst, l[:]...)
	return append(dst, b...)
}

// concatKDF derives keyLen bytes from z per the NIST Concatenation KDF with SHA-256. | concatKDF
// 使用 SHA-256 按 NIST 拼接 KDF 从 z 派生 keyLen 字节。
func concatKDF(z, algorithmID, apu, apv []byte, keyLen int) ([]byte, error) {
	if keyLen <= 0 || keyLen > 1<<16 {
		return nil, errs.Detail(ErrInvalidConfig, "invalid KDF key length %[1]d | 非法 KDF 密钥长度 %[1]d", keyLen)
	}
	other := make([]byte, 0, 16+len(algorithmID)+len(apu)+len(apv))
	other = appendLengthPrefixed(other, algorithmID)
	other = appendLengthPrefixed(other, apu)
	other = appendLengthPrefixed(other, apv)
	var supp [4]byte
	binary.BigEndian.PutUint32(supp[:], uint32(keyLen*8))
	other = append(other, supp[:]...)

	out := make([]byte, 0, keyLen+sha256.Size)
	var counter [4]byte
	for i := uint32(1); len(out) < keyLen; i++ {
		binary.BigEndian.PutUint32(counter[:], i)
		h := sha256.New()
		_, _ = h.Write(counter[:])
		_, _ = h.Write(z)
		_, _ = h.Write(other)
		out = append(out, h.Sum(nil)...)
	}
	return out[:keyLen], nil
}

// ecdhCurveFor returns the ECDH curve named by a JWK crv. | ecdhCurveFor 返回 JWK crv 指定的
// ECDH 曲线。
func ecdhCurveFor(crv string) (ecdh.Curve, error) {
	switch crv {
	case CurveP256:
		return ecdh.P256(), nil
	case CurveP384:
		return ecdh.P384(), nil
	case CurveP521:
		return ecdh.P521(), nil
	case CurveX25519:
		return ecdh.X25519(), nil
	default:
		return nil, errs.Detail(ErrInvalidKey, "unsupported ECDH crv=%[1]q | 不支持的 ECDH crv=%[1]q", crv)
	}
}

// ecdhPublicOf returns the ECDH public key of k. | ecdhPublicOf 返回 k 的 ECDH 公钥。
func ecdhPublicOf(k *Key) (*ecdh.PublicKey, error) {
	if k == nil {
		return nil, ErrInvalidKey
	}
	switch k.Kty {
	case KeyTypeEC:
		raw, err := k.PublicKey()
		if err != nil {
			return nil, err
		}
		pub, ok := raw.(*ecdsa.PublicKey)
		if !ok {
			return nil, errs.Detail(ErrKeyTypeMismatch, "not an ECDSA key | 不是 ECDSA 密钥")
		}
		out, err := pub.ECDH()
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidKey, "ECDH public key | ECDH 公钥")
		}
		return out, nil
	case KeyTypeOKP:
		if k.Crv != CurveX25519 {
			return nil, errs.Detail(ErrKeyTypeMismatch, "OKP crv=%[1]q is not X25519 | OKP crv=%[1]q 不是 X25519", k.Crv)
		}
		raw, err := k.PublicKey()
		if err != nil {
			return nil, err
		}
		pub, ok := raw.(*ecdh.PublicKey)
		if !ok {
			return nil, errs.Detail(ErrKeyTypeMismatch, "not an X25519 key | 不是 X25519 密钥")
		}
		return pub, nil
	}
	return nil, errs.Detail(ErrKeyTypeMismatch, "kty=%[1]q cannot do ECDH | kty=%[1]q 无法执行 ECDH", k.Kty)
}

// ecdhPrivateOf returns the ECDH private key of k. | ecdhPrivateOf 返回 k 的 ECDH 私钥。
func ecdhPrivateOf(k *Key) (*ecdh.PrivateKey, error) {
	if k == nil {
		return nil, ErrInvalidKey
	}
	switch k.Kty {
	case KeyTypeEC:
		raw, err := k.PrivateKey()
		if err != nil {
			return nil, err
		}
		priv, ok := raw.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errs.Detail(ErrKeyTypeMismatch, "not an ECDSA key | 不是 ECDSA 密钥")
		}
		out, err := priv.ECDH()
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidKey, "ECDH private key | ECDH 私钥")
		}
		return out, nil
	case KeyTypeOKP:
		if k.Crv != CurveX25519 {
			return nil, errs.Detail(ErrKeyTypeMismatch, "OKP crv=%[1]q is not X25519 | OKP crv=%[1]q 不是 X25519", k.Crv)
		}
		raw, err := k.PrivateKey()
		if err != nil {
			return nil, err
		}
		priv, ok := raw.(*ecdh.PrivateKey)
		if !ok {
			return nil, errs.Detail(ErrKeyTypeMismatch, "not an X25519 key | 不是 X25519 密钥")
		}
		return priv, nil
	}
	return nil, errs.Detail(ErrKeyTypeMismatch, "kty=%[1]q cannot do ECDH | kty=%[1]q 无法执行 ECDH", k.Kty)
}

// ephemeralPublicJWK converts an ephemeral ECDH public key into a public JWK. | ephemeralPublicJWK
// 把临时 ECDH 公钥转换为公开 JWK。
func ephemeralPublicJWK(crv string, pub *ecdh.PublicKey) (*Key, error) {
	if pub == nil {
		return nil, ErrInvalidKey
	}
	if crv == CurveX25519 {
		return &Key{Kty: KeyTypeOKP, Crv: CurveX25519, X: b64(pub.Bytes())}, nil
	}
	curve, err := ecCurve(crv)
	if err != nil {
		return nil, err
	}
	size := (curve.Params().BitSize + 7) / 8
	raw := pub.Bytes()
	if len(raw) != 1+2*size || raw[0] != 4 {
		return nil, errs.Detail(ErrInvalidKey, "unexpected ECDH public encoding | 意外的 ECDH 公钥编码")
	}
	return &Key{
		Kty: KeyTypeEC,
		Crv: crv,
		X:   b64(raw[1 : 1+size]),
		Y:   b64(raw[1+size:]),
	}, nil
}

// ecdhSharedForEncrypt generates an ephemeral key and derives the ECDH shared secret. | ecdhSharedForEncrypt
// 生成临时密钥并派生 ECDH 共享密钥。
func ecdhSharedForEncrypt(recipient *Key) ([]byte, *Key, error) {
	curve, err := ecdhCurveFor(recipient.Crv)
	if err != nil {
		return nil, nil, err
	}
	pub, err := ecdhPublicOf(recipient)
	if err != nil {
		return nil, nil, err
	}
	ephemeral, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, errs.WrapDetail(err, ErrInvalidKey, "ephemeral ECDH key | 临时 ECDH 密钥")
	}
	shared, err := ephemeral.ECDH(pub)
	if err != nil {
		return nil, nil, errs.Detail(ErrInvalidKey, "ECDH agreement failed | ECDH 协商失败")
	}
	epk, err := ephemeralPublicJWK(recipient.Crv, ephemeral.PublicKey())
	if err != nil {
		return nil, nil, err
	}
	return shared, epk, nil
}

// ecdhSharedForDecrypt derives the ECDH shared secret from the recipient private key and the
// ephemeral public JWK. | ecdhSharedForDecrypt 使用接收方私钥与临时公钥 JWK 派生 ECDH 共享密钥。
func ecdhSharedForDecrypt(recipient, epk *Key) ([]byte, error) {
	if epk == nil {
		return nil, errs.Detail(ErrInvalidHeader, "ECDH-ES requires epk | ECDH-ES 需要 epk")
	}
	if recipient.Crv != epk.Crv {
		return nil, errs.Detail(ErrDecryptionFailed, "epk crv=%[1]q does not match key crv=%[2]q | epk crv=%[1]q 与密钥 crv=%[2]q 不匹配", epk.Crv, recipient.Crv)
	}
	pub, err := ecdhPublicOf(epk)
	if err != nil {
		return nil, err
	}
	priv, err := ecdhPrivateOf(recipient)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, errs.Detail(ErrDecryptionFailed, "ECDH agreement failed | ECDH 协商失败")
	}
	return shared, nil
}
