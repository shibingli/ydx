package ntlm

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/subtle"
	"encoding/binary"
	"strings"
	"time"

	"golang.org/x/crypto/md4"

	"github.com/shibingli/ydx/errs"
)

// md4Size is the MD4 digest size used by NTLM hash derivation. | md4Size 是 NTLM
// 哈希派生使用的 MD4 摘要大小。
const md4Size = 16

// channelBindingPrefix is the RFC 5929 tls-server-end-point label mixed into the
// GSS channel-binding hash. | channelBindingPrefix 是混入 GSS 通道绑定哈希的 RFC 5929
// tls-server-end-point 标签。
var channelBindingPrefix = []byte("tls-server-end-point:")

// ntHash returns MD4(UTF-16LE(password)), the NTLM password hash. The result is
// never logged. | ntHash 返回 MD4(UTF-16LE(password))，即 NTLM 口令哈希。结果绝不记录日志。
func ntHash(password string) []byte {
	hasher := md4.New()
	_, _ = hasher.Write(utf16LE(password))
	return hasher.Sum(nil)
}

// NTLMv2Hash derives the NTLMv2 response key
// HMAC-MD5(MD4(UTF-16LE(password)), UTF-16LE(Uppercase(username)+domain)). The
// user name is uppercased with Unicode-aware case mapping while the domain is
// used verbatim, as MS-NLMP 3.3.2 requires. The result is never logged. |
// NTLMv2Hash 派生 NTLMv2 响应密钥
// HMAC-MD5(MD4(UTF-16LE(password)), UTF-16LE(Uppercase(username)+domain))。
// 按 MS-NLMP 3.3.2 要求，用户名使用 Unicode 大小写映射转为大写，域原样使用。结果绝不记录日志。
func NTLMv2Hash(password, username, domain string) []byte {
	identity := strings.ToUpper(username) + domain
	mac := hmac.New(md5.New, ntHash(password))
	_, _ = mac.Write(utf16LE(identity))
	return mac.Sum(nil)
}

// V2Response is the NTLMv2 challenge-response material. | V2Response 是 NTLMv2
// 挑战响应材料。
type V2Response struct {
	// NTProofStr is HMAC-MD5(ResponseKeyNT, ServerChallenge||Temp). | NTProofStr 是
	// HMAC-MD5(ResponseKeyNT, ServerChallenge||Temp)。
	NTProofStr []byte
	// NTResponse is NTProofStr followed by Temp. | NTResponse 是 NTProofStr 后接 Temp。
	NTResponse []byte
	// LMv2Response is HMAC-MD5(ResponseKeyNT, ServerChallenge||ClientChallenge)
	// followed by ClientChallenge. | LMv2Response 是
	// HMAC-MD5(ResponseKeyNT, ServerChallenge||ClientChallenge) 后接 ClientChallenge。
	LMv2Response []byte
	// SessionBaseKey is HMAC-MD5(ResponseKeyNT, NTProofStr). | SessionBaseKey 是
	// HMAC-MD5(ResponseKeyNT, NTProofStr)。
	SessionBaseKey []byte
}

// ComputeNTLMv2Response derives the NTLMv2 responses defined by MS-NLMP 3.3.2.
// responseKey must be a 16-byte NTLMv2Hash result, both challenges must be eight
// bytes, and targetInfo must be the wire AV pair sequence including its
// AVEndOfList terminator. A zero time.Time produces a zero FILETIME, which is
// useful for test vectors; callers normally pass the server timestamp. | ComputeNTLMv2Response
// 按 MS-NLMP 3.3.2 派生 NTLMv2 响应。responseKey 必须是 16 字节 NTLMv2Hash 结果，
// 两个挑战必须为八字节，targetInfo 必须是包含 AVEndOfList 终止符的线格式 AV 对序列。
// time.Time 零值产生零 FILETIME，便于测试向量使用；调用方通常传入服务端时间戳。
func ComputeNTLMv2Response(responseKey, serverChallenge, clientChallenge []byte, timestamp time.Time, targetInfo []byte) (*V2Response, error) {
	if len(responseKey) != md4Size {
		return nil, errs.Detail(ErrCredentials, "response key is %d bytes, want %d | 响应密钥为 %d 字节，期望 %d", len(responseKey), md4Size, len(responseKey), md4Size)
	}
	if len(serverChallenge) != 8 {
		return nil, errs.Detail(ErrChallenge, "server challenge is %d bytes, want 8 | 服务端挑战为 %d 字节，期望 8", len(serverChallenge), len(serverChallenge))
	}
	if len(clientChallenge) != 8 {
		return nil, errs.Detail(ErrCredentials, "client challenge is %d bytes, want 8 | 客户端挑战为 %d 字节，期望 8", len(clientChallenge), len(clientChallenge))
	}
	if len(targetInfo) > 0xffff-48 {
		return nil, errs.Detail(ErrTargetInfo, "target info is too large: %d bytes | 目标信息过大：%d 字节", len(targetInfo), len(targetInfo))
	}
	temp := make([]byte, 0, 28+len(targetInfo)+4)
	temp = append(temp, 1, 1, 0, 0)
	temp = append(temp, 0, 0, 0, 0)
	var filetime [8]byte
	binary.LittleEndian.PutUint64(filetime[:], filetimeFromTime(timestamp))
	temp = append(temp, filetime[:]...)
	temp = append(temp, clientChallenge...)
	temp = append(temp, 0, 0, 0, 0)
	temp = append(temp, targetInfo...)
	temp = append(temp, 0, 0, 0, 0)
	proofInput := make([]byte, 0, len(serverChallenge)+len(temp))
	proofInput = append(proofInput, serverChallenge...)
	proofInput = append(proofInput, temp...)
	proof := hmacMD5(responseKey, proofInput)
	ntResponse := make([]byte, 0, len(proof)+len(temp))
	ntResponse = append(ntResponse, proof...)
	ntResponse = append(ntResponse, temp...)
	lmInput := make([]byte, 0, len(serverChallenge)+len(clientChallenge))
	lmInput = append(lmInput, serverChallenge...)
	lmInput = append(lmInput, clientChallenge...)
	lmHash := hmacMD5(responseKey, lmInput)
	lmResponse := make([]byte, 0, len(lmHash)+len(clientChallenge))
	lmResponse = append(lmResponse, lmHash...)
	lmResponse = append(lmResponse, clientChallenge...)
	return &V2Response{
		NTProofStr:     proof,
		NTResponse:     ntResponse,
		LMv2Response:   lmResponse,
		SessionBaseKey: hmacMD5(responseKey, proof),
	}, nil
}

// ChannelBindingHash computes the GSS channel-binding value
// MD5(0x00*16 || "tls-server-end-point:" || serverEndpointHash), where
// serverEndpointHash is the certificate digest produced by RFC 5929
// tls-server-end-point. | ChannelBindingHash 计算 GSS 通道绑定值
// MD5(0x00*16 || "tls-server-end-point:" || serverEndpointHash)，其中
// serverEndpointHash 是 RFC 5929 tls-server-end-point 产生的证书摘要。
func ChannelBindingHash(serverEndpointHash []byte) ([]byte, error) {
	if len(serverEndpointHash) == 0 {
		return nil, errs.Detail(ErrChannelBindings, "server endpoint hash is empty | 服务端端点哈希为空")
	}
	hasher := md5.New()
	var zeros [16]byte
	_, _ = hasher.Write(zeros[:])
	_, _ = hasher.Write(channelBindingPrefix)
	_, _ = hasher.Write(serverEndpointHash)
	return hasher.Sum(nil), nil
}

// hmacMD5 returns HMAC-MD5(key, data). | hmacMD5 返回 HMAC-MD5(key, data)。
func hmacMD5(key, data []byte) []byte {
	mac := hmac.New(md5.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

// constantTimeEqual compares two octet strings without leaking their first
// differing position. | constantTimeEqual 比较两个八位组字符串，不泄露首个不同位置。
func constantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// utf16LE encodes value as UTF-16LE without a byte-order mark. | utf16LE 把 value
// 编码为无字节序标记的 UTF-16LE。
func utf16LE(value string) []byte {
	return encodeString(value, true)
}
