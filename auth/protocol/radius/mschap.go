package radius

import (
	"crypto/des"
	"crypto/sha1"
	"encoding/binary"
	"math/bits"
	"unicode/utf16"

	"github.com/shibingli/ydx/errs"
	"golang.org/x/crypto/md4"
)

// msCHAPv2ResponseLength is the RADIUS MS-CHAP2-Response value length (RFC 2548 section 2.3.2). |
// msCHAPv2ResponseLength 是 RADIUS MS-CHAP2-Response 值长度（RFC 2548 第 2.3.2 节）。
const msCHAPv2ResponseLength = 50

// MSCHAPv2Response computes the 50-octet RADIUS MS-CHAP2-Response value defined by RFC 2548
// section 2.3.2 and RFC 2759. | MSCHAPv2Response 计算 RFC 2548 第 2.3.2 节与 RFC 2759 定义的
// 50 字节 RADIUS MS-CHAP2-Response 值。
//
// The value is Ident(1) || Flags(1) || Peer-Challenge(16) || Reserved(8) || NT-Response(24). The
// authenticator and peer challenges must each be 16 octets. | 该值为 Ident(1) || Flags(1) ||
// Peer-Challenge(16) || Reserved(8) || NT-Response(24)。认证符挑战与对端挑战均必须为 16 字节。
func MSCHAPv2Response(userName, password string, authenticatorChallenge, peerChallenge []byte, ident uint8) ([]byte, error) {
	if len(authenticatorChallenge) != 16 {
		return nil, errs.Detail(ErrInvalidRequest, "MS-CHAPv2 authenticator challenge length %d must be 16", len(authenticatorChallenge))
	}
	if len(peerChallenge) != 16 {
		return nil, errs.Detail(ErrInvalidRequest, "MS-CHAPv2 peer challenge length %d must be 16", len(peerChallenge))
	}
	challenge := msCHAPv2ChallengeHash(userName, authenticatorChallenge, peerChallenge)
	response := msCHAPv2NTResponse(password, challenge)
	out := make([]byte, msCHAPv2ResponseLength)
	out[0] = ident
	// out[1] is the one-octet Flags field and must be zero; the Reserved field is zero as well.
	copy(out[2:18], peerChallenge)
	copy(out[26:50], response[:])
	return out, nil
}

// VerifyMSCHAPv2Response reports whether response is a valid RADIUS MS-CHAP2-Response for the
// user, password and authenticator challenge. The NT-Response comparison is constant time. |
// VerifyMSCHAPv2Response 报告 response 是否为 user、password 与认证符挑战的合法 RADIUS
// MS-CHAP2-Response。NT-Response 比较为常量时间。
func VerifyMSCHAPv2Response(userName, password string, authenticatorChallenge, response []byte) (bool, error) {
	if len(response) != msCHAPv2ResponseLength {
		return false, errs.Detail(ErrInvalidAttribute, "MS-CHAP2-Response length %d must be %d", len(response), msCHAPv2ResponseLength)
	}
	if len(authenticatorChallenge) != 16 {
		return false, errs.Detail(ErrInvalidAttribute, "MS-CHAPv2 authenticator challenge length %d must be 16", len(authenticatorChallenge))
	}
	ident := response[0]
	peerChallenge := response[2:18]
	expected, err := MSCHAPv2Response(userName, password, authenticatorChallenge, peerChallenge, ident)
	if err != nil {
		return false, err
	}
	defer zeroBytes(expected)
	return constantTimeEqual(expected[26:50], response[26:50]), nil
}

// msCHAPv2ChallengeHash implements ChallengeHash from RFC 2759 section 8.2. | msCHAPv2ChallengeHash
// 实现 RFC 2759 第 8.2 节的 ChallengeHash。
func msCHAPv2ChallengeHash(userName string, authenticatorChallenge, peerChallenge []byte) []byte {
	h := sha1.New()
	h.Write(peerChallenge)
	h.Write(authenticatorChallenge)
	h.Write([]byte(userName))
	sum := h.Sum(nil)
	return sum[:8]
}

// msCHAPv2NTResponse implements ChallengeResponse of RFC 2759 section 8.5: the 16-octet
// PasswordHash is zero-padded to 21 octets and split into three 7-octet DES keys, each encrypting
// the same 8-octet challenge. | msCHAPv2NTResponse 实现 RFC 2759 第 8.5 节的 ChallengeResponse：
// 16 字节 PasswordHash 补零到 21 字节并拆成三个 7 字节 DES 密钥，各自加密同一个 8 字节挑战。
func msCHAPv2NTResponse(password string, challenge []byte) [24]byte {
	passwordHash := ntPasswordHash(password)
	defer zeroBytes(passwordHash[:])
	return desEncryptL(passwordHash[:], challenge)
}

// ntPasswordHash implements NT-PasswordHash: MD4 over the UTF-16LE password. | ntPasswordHash 实现
// NT-PasswordHash：对 UTF-16LE 口令做 MD4。
func ntPasswordHash(password string) [16]byte {
	encoded := utf16LE(password)
	defer zeroBytes(encoded)
	return md4Sum(encoded)
}

// md4Sum returns the MD4 digest of data. MD4 is required by RFC 2759 for the
// MS-CHAPv2 NT-PasswordHash and is not used anywhere else; golang.org/x/crypto/md4
// is deprecated as a general-purpose hash, not as this protocol primitive. |
// md4Sum 返回 data 的 MD4 摘要。RFC 2759 要求用 MD4 计算 MS-CHAPv2 的 NT-PasswordHash，
// 本包不在其它地方使用它；golang.org/x/crypto/md4 的弃用针对通用哈希用途，而非该协议原语。
func md4Sum(data []byte) [16]byte {
	h := md4.New()
	h.Write(data)
	var sum [16]byte
	h.Sum(sum[:0])
	return sum
}

// utf16LE encodes s as UTF-16 little endian. | utf16LE 将 s 编码为 UTF-16 小端。
func utf16LE(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(out[i*2:], unit)
	}
	return out
}

// desEncryptL implements the RFC 2759 DESL function. | desEncryptL 实现 RFC 2759 的 DESL 函数。
func desEncryptL(key, data []byte) [24]byte {
	var out [24]byte
	var expanded [21]byte
	copy(expanded[:], key)
	for block := 0; block < 3; block++ {
		var desKey [8]byte
		expandDESKey(expanded[block*7:(block+1)*7], desKey[:])
		cipher, err := des.NewCipher(desKey[:])
		if err != nil {
			// des.NewCipher only rejects keys whose length is not eight; desKey is always eight.
			// | des.NewCipher 只拒绝长度不为 8 的密钥；desKey 恒为 8 字节。
			continue
		}
		cipher.Encrypt(out[block*8:(block+1)*8], data)
	}
	zeroBytes(expanded[:])
	return out
}

// expandDESKey expands seven octets to an eight-octet DES key with odd parity. | expandDESKey 将
// 7 字节扩展为带奇校验的 8 字节 DES 密钥。
func expandDESKey(in, out []byte) {
	out[0] = in[0] & 0xfe
	out[1] = ((in[0] << 7) | (in[1] >> 1)) & 0xfe
	out[2] = ((in[1] << 6) | (in[2] >> 2)) & 0xfe
	out[3] = ((in[2] << 5) | (in[3] >> 3)) & 0xfe
	out[4] = ((in[3] << 4) | (in[4] >> 4)) & 0xfe
	out[5] = ((in[4] << 3) | (in[5] >> 5)) & 0xfe
	out[6] = ((in[5] << 2) | (in[6] >> 6)) & 0xfe
	out[7] = (in[6] << 1) & 0xfe
	for i := range out {
		if bits.OnesCount8(out[i])%2 == 0 {
			out[i] |= 1
		}
	}
}
