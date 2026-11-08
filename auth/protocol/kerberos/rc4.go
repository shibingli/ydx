package kerberos

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"unicode/utf16"

	"golang.org/x/crypto/md4"

	"github.com/shibingli/ydx/errs"
)

// rc4ConfounderSize is the RFC 4757 confounder size in bytes. | rc4ConfounderSize 是
// RFC 4757 混淆值字节数。
const rc4ConfounderSize = 8

// rc4ChecksumSize is the full RFC 4757 checksum size in bytes. | rc4ChecksumSize 是
// RFC 4757 完整校验和字节数。
const rc4ChecksumSize = 16

// rc4Usage translates a Kerberos key usage to the Microsoft T number used by
// rc4-hmac. | rc4Usage 把 Kerberos 密钥用途转换为 rc4-hmac 使用的 Microsoft T 号。
func rc4Usage(usage uint32) uint32 {
	switch usage {
	case 3, 9:
		return 8
	case 23:
		return 13
	default:
		return usage
	}
}

// rc4UsageBytes encodes a translated usage as a little-endian 32-bit value. | rc4UsageBytes
// 把转换后的用途编码为小端 32 位值。
func rc4UsageBytes(usage uint32) []byte {
	raw := make([]byte, 4)
	binary.LittleEndian.PutUint32(raw, rc4Usage(usage))
	return raw
}

// rc4HMAC returns HMAC-MD5 keyed by key. | rc4HMAC 返回以 key 为密钥的 HMAC-MD5。
func rc4HMAC(key, data []byte) []byte {
	mac := hmac.New(md5.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

// rc4StringToKey derives an rc4-hmac key from a password per RFC 4757. | rc4StringToKey
// 按 RFC 4757 从口令派生 rc4-hmac 密钥。
func rc4StringToKey(password string) ([]byte, error) {
	units := utf16.Encode([]rune(password))
	raw := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(raw[i*2:], unit)
	}
	hasher := md4.New()
	_, _ = hasher.Write(raw)
	return hasher.Sum(nil), nil
}

// rc4Checksum computes the RFC 4757 keyed checksum of data. | rc4Checksum 计算 RFC 4757
// 对 data 的带密钥校验和。
func rc4Checksum(key []byte, usage uint32, data []byte) []byte {
	signingKey := rc4HMAC(key, append([]byte("signaturekey"), 0))
	prefix := rc4UsageBytes(usage)
	digest := md5.New()
	_, _ = digest.Write(prefix)
	_, _ = digest.Write(data)
	return rc4HMAC(signingKey, digest.Sum(nil))
}

// rc4EncryptMessage encrypts plaintext with rc4-hmac. A nil confounder makes the
// function draw one from crypto/rand. | rc4EncryptMessage 用 rc4-hmac 加密 plaintext。
// confounder 为空时从 crypto/rand 获取。
func rc4EncryptMessage(key []byte, usage uint32, plaintext, confounder []byte) ([]byte, error) {
	if len(confounder) == 0 {
		confounder = make([]byte, rc4ConfounderSize)
		if _, err := rand.Read(confounder); err != nil {
			return nil, errs.WrapDetail(err, ErrRandom, "RC4 confounder generation failed | RC4 混淆值生成失败")
		}
	}
	if len(confounder) != rc4ConfounderSize {
		return nil, errs.Detail(ErrInvalidConfig, "RC4 confounder is %d bytes, want %d | RC4 混淆值为 %d 字节，期望 %d",
			len(confounder), rc4ConfounderSize, len(confounder), rc4ConfounderSize)
	}
	usageBytes := rc4UsageBytes(usage)
	k2 := rc4HMAC(key, usageBytes)
	toEncrypt := make([]byte, 0, len(confounder)+len(plaintext))
	toEncrypt = append(toEncrypt, confounder...)
	toEncrypt = append(toEncrypt, plaintext...)
	checksum := rc4HMAC(k2, toEncrypt)
	k3 := rc4HMAC(k2, checksum)
	stream, err := rc4.NewCipher(k3)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrDecrypt, "RC4 key rejected | RC4 密钥被拒绝")
	}
	encrypted := make([]byte, len(toEncrypt))
	stream.XORKeyStream(encrypted, toEncrypt)
	out := make([]byte, 0, rc4ChecksumSize+len(encrypted))
	out = append(out, checksum...)
	out = append(out, encrypted...)
	return out, nil
}

// rc4DecryptMessage decrypts and verifies an rc4-hmac message. | rc4DecryptMessage 解密
// 并校验 rc4-hmac 消息。
func rc4DecryptMessage(key []byte, usage uint32, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < rc4ChecksumSize+rc4ConfounderSize {
		return nil, errs.Detail(ErrDecrypt, "RC4 ciphertext is %d bytes, minimum %d | RC4 密文为 %d 字节，至少 %d",
			len(ciphertext), rc4ChecksumSize+rc4ConfounderSize, len(ciphertext), rc4ChecksumSize+rc4ConfounderSize)
	}
	checksum := ciphertext[:rc4ChecksumSize]
	body := ciphertext[rc4ChecksumSize:]
	k2 := rc4HMAC(key, rc4UsageBytes(usage))
	k3 := rc4HMAC(k2, checksum)
	stream, err := rc4.NewCipher(k3)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrDecrypt, "RC4 key rejected | RC4 密钥被拒绝")
	}
	plain := make([]byte, len(body))
	stream.XORKeyStream(plain, body)
	if !hmac.Equal(rc4HMAC(k2, plain), checksum) {
		return nil, errs.Detail(ErrChecksumMismatch, "RC4 integrity checksum mismatch | RC4 完整性校验和不匹配")
	}
	return plain[rc4ConfounderSize:], nil
}
