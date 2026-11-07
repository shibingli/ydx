package radius

import (
	"crypto/md5"
	"crypto/subtle"

	"github.com/shibingli/ydx/errs"
)

// EncryptUserPassword hides a password with the RFC 2865 section 5.2 PAP algorithm. | EncryptUserPassword
// 使用 RFC 2865 第 5.2 节的 PAP 算法隐藏口令。
//
// The password is zero-padded to a multiple of 16 octets and XORed with MD5 digests chained from
// the shared secret and the Request Authenticator. The returned ciphertext is 16 to 128 octets.
// The caller's password slice is not modified. | 口令以零填充到 16 字节的整数倍，并与由共享密钥和
// Request Authenticator 链式生成的 MD5 摘要异或。返回的密文为 16 到 128 字节。调用方的口令切片
// 不会被修改。
func EncryptUserPassword(secret, requestAuthenticator, password []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errs.Detail(ErrInvalidRequest, "shared secret is required")
	}
	if len(requestAuthenticator) != 16 {
		return nil, errs.Detail(ErrInvalidRequest, "request authenticator length %d must be 16", len(requestAuthenticator))
	}
	if len(password) > 128 {
		return nil, errs.Detail(ErrInvalidRequest, "password length %d exceeds 128", len(password))
	}
	length := ((len(password) + 15) / 16) * 16
	if length == 0 {
		length = 16
	}
	padded := make([]byte, length)
	copy(padded, password)
	out := make([]byte, length)
	defer zeroBytes(padded)
	// Reuse one buffer for the secret and chaining value, then zero it before returning. |
	// 复用同一缓冲区保存密钥与链值，并在返回前清零。
	digestInput := make([]byte, len(secret)+16)
	defer zeroBytes(digestInput)
	previous := requestAuthenticator
	for offset := 0; offset < length; offset += 16 {
		copy(digestInput, secret)
		copy(digestInput[len(secret):], previous)
		digest := md5.Sum(digestInput)
		for i := 0; i < 16; i++ {
			out[offset+i] = padded[offset+i] ^ digest[i]
		}
		previous = out[offset : offset+16]
	}
	return out, nil
}

// DecryptUserPassword reverses EncryptUserPassword. | DecryptUserPassword 逆转 EncryptUserPassword。
//
// Trailing zero octets used as padding are removed from the returned plaintext. | 返回的明文会去除
// 用于填充的尾部零字节。
func DecryptUserPassword(secret, requestAuthenticator, encrypted []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errs.Detail(ErrInvalidRequest, "shared secret is required")
	}
	if len(requestAuthenticator) != 16 {
		return nil, errs.Detail(ErrInvalidRequest, "request authenticator length %d must be 16", len(requestAuthenticator))
	}
	if len(encrypted) < 16 || len(encrypted) > 128 || len(encrypted)%16 != 0 {
		return nil, errs.Detail(ErrInvalidRequest, "password ciphertext length %d must be a multiple of 16 in [16,128]", len(encrypted))
	}
	plain := make([]byte, len(encrypted))
	// Reuse one buffer for the secret and chaining value, then zero it before returning. |
	// 复用同一缓冲区保存密钥与链值，并在返回前清零。
	digestInput := make([]byte, len(secret)+16)
	defer zeroBytes(digestInput)
	previous := requestAuthenticator
	for offset := 0; offset < len(encrypted); offset += 16 {
		copy(digestInput, secret)
		copy(digestInput[len(secret):], previous)
		digest := md5.Sum(digestInput)
		for i := 0; i < 16; i++ {
			plain[offset+i] = encrypted[offset+i] ^ digest[i]
		}
		previous = encrypted[offset : offset+16]
	}
	end := len(plain)
	for end > 0 && plain[end-1] == 0 {
		end--
	}
	return plain[:end], nil
}

// VerifyUserPassword reports whether encrypted hides password for the given secret and Request
// Authenticator. The comparison is constant time. | VerifyUserPassword 报告 encrypted 在给定密钥与
// Request Authenticator 下是否隐藏 password。比较为常量时间。
func VerifyUserPassword(secret, requestAuthenticator, encrypted, password []byte) bool {
	plain, err := DecryptUserPassword(secret, requestAuthenticator, encrypted)
	if err != nil {
		return false
	}
	defer zeroBytes(plain)
	return constantTimeEqual(plain, password)
}

// CHAPResponse computes the RFC 2865 section 2.2 CHAP response
// MD5(Identifier || Password || Challenge). | CHAPResponse 计算 RFC 2865 第 2.2 节的 CHAP 响应
// MD5(Identifier || Password || Challenge)。
func CHAPResponse(ident uint8, password, challenge []byte) [16]byte {
	input := make([]byte, 0, 1+len(password)+len(challenge))
	input = append(input, ident)
	input = append(input, password...)
	input = append(input, challenge...)
	sum := md5.Sum(input)
	zeroBytes(input)
	return sum
}

// VerifyCHAPResponse reports whether response matches the CHAP computation for ident, password
// and challenge. The comparison is constant time. | VerifyCHAPResponse 报告 response 是否与
// ident、password 与 challenge 的 CHAP 计算匹配。比较为常量时间。
func VerifyCHAPResponse(ident uint8, password, challenge, response []byte) bool {
	if len(response) != 16 {
		return false
	}
	expected := CHAPResponse(ident, password, challenge)
	return constantTimeEqual(expected[:], response)
}

// constantTimeEqual compares two byte slices in constant time. | constantTimeEqual 以常量时间比较两个字节切片。
func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
