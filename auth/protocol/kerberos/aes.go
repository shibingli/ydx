package kerberos

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"

	"github.com/shibingli/ydx/errs"
)

// aesBlockSize is the AES block size in bytes. | aesBlockSize 是 AES 块字节数。
const aesBlockSize = 16

// aesConfounderSize is the RFC 3962 confounder size in bytes. | aesConfounderSize 是
// RFC 3962 混淆值字节数。
const aesConfounderSize = 16

// hmacSHA1Size is the truncated HMAC-SHA1-96 size in bytes. | hmacSHA1Size 是截断的
// HMAC-SHA1-96 字节数。
const hmacSHA1Size = 12

// aesEncryptBlock encrypts one block with AES in ECB mode. | aesEncryptBlock 用 AES ECB
// 模式加密一个块。
func aesEncryptBlock(key, block []byte) []byte {
	if len(block) != aesBlockSize {
		return nil
	}
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	out := make([]byte, aesBlockSize)
	blockCipher.Encrypt(out, block)
	return out
}

// hmacSHA1Truncated returns the first 12 bytes of HMAC-SHA1. | hmacSHA1Truncated 返回
// HMAC-SHA1 的前 12 字节。
func hmacSHA1Truncated(key, data []byte) []byte {
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)[:hmacSHA1Size]
}

// aesCTSEncrypt applies RFC 3962 AES ciphertext stealing with a zero IV. One block
// or less is zero padded to a full block. | aesCTSEncrypt 以零 IV 应用 RFC 3962 AES
// 密文窃取。一个块或更短会零填充到完整块。
func aesCTSEncrypt(key, plaintext []byte) ([]byte, error) {
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidConfig, "AES key rejected | AES 密钥被拒绝")
	}
	if len(plaintext) <= aesBlockSize {
		padded := make([]byte, aesBlockSize)
		copy(padded, plaintext)
		out := make([]byte, aesBlockSize)
		blockCipher.Encrypt(out, padded)
		return out, nil
	}
	blocks := (len(plaintext) + aesBlockSize - 1) / aesBlockSize
	padded := make([]byte, blocks*aesBlockSize)
	copy(padded, plaintext)
	ciphertext := make([]byte, blocks*aesBlockSize)
	var previous, mixed [aesBlockSize]byte
	for i := 0; i < blocks; i++ {
		for j := 0; j < aesBlockSize; j++ {
			mixed[j] = padded[i*aesBlockSize+j] ^ previous[j]
		}
		blockCipher.Encrypt(ciphertext[i*aesBlockSize:], mixed[:])
		copy(previous[:], ciphertext[i*aesBlockSize:(i+1)*aesBlockSize])
	}
	if len(plaintext)%aesBlockSize == 0 {
		last := (blocks - 1) * aesBlockSize
		before := (blocks - 2) * aesBlockSize
		var swap [aesBlockSize]byte
		copy(swap[:], ciphertext[before:])
		copy(ciphertext[before:], ciphertext[last:])
		copy(ciphertext[last:], swap[:])
		return ciphertext, nil
	}
	stolen := len(plaintext) % aesBlockSize
	out := make([]byte, 0, len(plaintext))
	out = append(out, ciphertext[:(blocks-2)*aesBlockSize]...)
	out = append(out, ciphertext[(blocks-1)*aesBlockSize:]...)
	out = append(out, ciphertext[(blocks-2)*aesBlockSize:(blocks-2)*aesBlockSize+stolen]...)
	return out, nil
}

// aesCTSDecrypt reverses RFC 3962 AES ciphertext stealing with a zero IV. | aesCTSDecrypt
// 以零 IV 逆向 RFC 3962 AES 密文窃取。
func aesCTSDecrypt(key, ciphertext []byte) ([]byte, error) {
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidConfig, "AES key rejected | AES 密钥被拒绝")
	}
	if len(ciphertext) == 0 {
		return nil, errs.Detail(ErrDecrypt, "empty AES ciphertext | AES 密文为空")
	}
	if len(ciphertext) <= aesBlockSize {
		padded := make([]byte, aesBlockSize)
		copy(padded, ciphertext)
		out := make([]byte, aesBlockSize)
		blockCipher.Decrypt(out, padded)
		return out, nil
	}
	blocks := (len(ciphertext) + aesBlockSize - 1) / aesBlockSize
	stolen := len(ciphertext) - aesBlockSize*(blocks-1)
	var previous, plain [aesBlockSize]byte
	out := make([]byte, 0, len(ciphertext))
	if stolen == aesBlockSize {
		ordered := make([]byte, len(ciphertext))
		copy(ordered, ciphertext[:(blocks-2)*aesBlockSize])
		copy(ordered[(blocks-2)*aesBlockSize:], ciphertext[(blocks-1)*aesBlockSize:])
		copy(ordered[(blocks-1)*aesBlockSize:], ciphertext[(blocks-2)*aesBlockSize:(blocks-1)*aesBlockSize])
		for i := 0; i < blocks; i++ {
			blockCipher.Decrypt(plain[:], ordered[i*aesBlockSize:(i+1)*aesBlockSize])
			for j := 0; j < aesBlockSize; j++ {
				plain[j] ^= previous[j]
			}
			out = append(out, plain[:]...)
			copy(previous[:], ordered[i*aesBlockSize:(i+1)*aesBlockSize])
		}
		return out, nil
	}
	for i := 0; i < blocks-2; i++ {
		blockCipher.Decrypt(plain[:], ciphertext[i*aesBlockSize:(i+1)*aesBlockSize])
		for j := 0; j < aesBlockSize; j++ {
			plain[j] ^= previous[j]
		}
		out = append(out, plain[:]...)
		copy(previous[:], ciphertext[i*aesBlockSize:(i+1)*aesBlockSize])
	}
	lastFull := ciphertext[(blocks-2)*aesBlockSize : (blocks-1)*aesBlockSize]
	stolenTail := ciphertext[(blocks-1)*aesBlockSize:]
	var lastDecrypted [aesBlockSize]byte
	blockCipher.Decrypt(lastDecrypted[:], lastFull)
	lastBlock := make([]byte, aesBlockSize)
	copy(lastBlock, stolenTail)
	copy(lastBlock[stolen:], lastDecrypted[stolen:])
	blockCipher.Decrypt(plain[:], lastBlock)
	for j := 0; j < aesBlockSize; j++ {
		plain[j] ^= previous[j]
	}
	out = append(out, plain[:]...)
	final := make([]byte, aesBlockSize)
	for j := 0; j < aesBlockSize; j++ {
		final[j] = lastDecrypted[j] ^ lastBlock[j]
	}
	out = append(out, final[:stolen]...)
	return out, nil
}

// aesEncryptMessage encrypts a message with the RFC 3962 profile. | aesEncryptMessage
// 用 RFC 3962 配置加密消息。
func aesEncryptMessage(key []byte, usage uint32, plaintext []byte) ([]byte, error) {
	confounder := make([]byte, aesConfounderSize)
	if _, err := rand.Read(confounder); err != nil {
		return nil, errs.WrapDetail(err, ErrRandom, "AES confounder generation failed | AES 混淆值生成失败")
	}
	encryptionKey := deriveKeyUsage(key, usage, 0xAA)
	integrityKey := deriveKeyUsage(key, usage, 0x55)
	if encryptionKey == nil || integrityKey == nil {
		return nil, errs.Detail(ErrDecrypt, "AES usage key derivation failed | AES 用途密钥派生失败")
	}
	plain := make([]byte, 0, len(confounder)+len(plaintext))
	plain = append(plain, confounder...)
	plain = append(plain, plaintext...)
	ciphertext, err := aesCTSEncrypt(encryptionKey, plain)
	if err != nil {
		return nil, err
	}
	return append(ciphertext, hmacSHA1Truncated(integrityKey, plain)...), nil
}

// aesDecryptMessage decrypts and verifies an RFC 3962 message. | aesDecryptMessage 解密
// 并校验 RFC 3962 消息。
func aesDecryptMessage(key []byte, usage uint32, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < aesConfounderSize+hmacSHA1Size {
		return nil, errs.Detail(ErrDecrypt, "AES ciphertext is %d bytes, minimum %d | AES 密文为 %d 字节，至少 %d",
			len(ciphertext), aesConfounderSize+hmacSHA1Size, len(ciphertext), aesConfounderSize+hmacSHA1Size)
	}
	body := ciphertext[:len(ciphertext)-hmacSHA1Size]
	tag := ciphertext[len(ciphertext)-hmacSHA1Size:]
	encryptionKey := deriveKeyUsage(key, usage, 0xAA)
	integrityKey := deriveKeyUsage(key, usage, 0x55)
	if encryptionKey == nil || integrityKey == nil {
		return nil, errs.Detail(ErrDecrypt, "AES usage key derivation failed | AES 用途密钥派生失败")
	}
	plain, err := aesCTSDecrypt(encryptionKey, body)
	if err != nil {
		return nil, err
	}
	if len(plain) < aesConfounderSize {
		return nil, errs.Detail(ErrDecrypt, "AES plaintext is %d bytes, minimum %d | AES 明文为 %d 字节，至少 %d",
			len(plain), aesConfounderSize, len(plain), aesConfounderSize)
	}
	if !hmac.Equal(hmacSHA1Truncated(integrityKey, plain), tag) {
		return nil, errs.Detail(ErrChecksumMismatch, "AES integrity tag mismatch | AES 完整性标签不匹配")
	}
	return plain[aesConfounderSize:], nil
}

// aesCTSCipher exposes the block cipher for tests that need ECB operations. | aesCTSCipher
// 为需要 ECB 运算的测试暴露块密码。
func aesCTSCipher(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}
