package ntlm

import (
	"crypto/des"
	"crypto/md5"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// lmMagic is the fixed LM hash plaintext from MS-NLMP 3.3.1. | lmMagic 是 MS-NLMP
// 3.3.1 定义的固定 LM 哈希明文。
var lmMagic = []byte("KGS!@#$%")

// lmHash returns the legacy LAN Manager password hash. The password is
// uppercased, truncated to 14 bytes and split into two 7-byte DES keys. Bytes
// are taken as-is because this client does not know the OEM code page; Active
// Directory deployments with non-ASCII legacy passwords require an explicit
// OEM-encoded password. | lmHash 返回旧式 LAN Manager 口令哈希。口令转为大写、截断为
// 14 字节并拆成两个 7 字节 DES 密钥。由于本客户端不知道 OEM 代码页，字节按原样使用；
// 使用非 ASCII 旧式口令的 Active Directory 部署需要显式提供 OEM 编码口令。
func lmHash(password string) ([]byte, error) {
	upper := strings.ToUpper(password)
	if len(upper) > 14 {
		upper = upper[:14]
	}
	padded := make([]byte, 14)
	copy(padded, upper)
	first, err := desEncrypt(desKey(padded[:7]), lmMagic)
	if err != nil {
		return nil, err
	}
	second, err := desEncrypt(desKey(padded[7:14]), lmMagic)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 16)
	out = append(out, first...)
	out = append(out, second...)
	return out, nil
}

// ntlmV1Response computes the 24-byte NTLMv1 response DESL(21-byte hash,
// serverChallenge). | ntlmV1Response 计算 24 字节 NTLMv1 响应
// DESL(21-byte hash, serverChallenge)。
func ntlmV1Response(passwordHash, serverChallenge []byte) ([]byte, error) {
	if len(passwordHash) != 16 {
		return nil, errs.Detail(ErrCredentials, "NTLMv1 password hash is %d bytes, want 16 | NTLMv1 口令哈希为 %d 字节，期望 16", len(passwordHash), len(passwordHash))
	}
	if len(serverChallenge) != 8 {
		return nil, errs.Detail(ErrChallenge, "server challenge is %d bytes, want 8 | 服务端挑战为 %d 字节，期望 8", len(serverChallenge), len(serverChallenge))
	}
	padded := make([]byte, 21)
	copy(padded, passwordHash)
	out := make([]byte, 0, 24)
	for index := 0; index < 3; index++ {
		block, err := desEncrypt(desKey(padded[index*7:index*7+7]), serverChallenge)
		if err != nil {
			return nil, err
		}
		out = append(out, block...)
	}
	return out, nil
}

// ntlm2SessionResponse computes the NTLM2 session NT and LM responses. The
// session hash is the first eight bytes of MD5(ServerChallenge[:4] ||
// ClientChallenge); the NT response encrypts the 21-byte NT hash with it and
// the LM response is ClientChallenge followed by 16 zero bytes. | ntlm2SessionResponse
// 计算 NTLM2 会话 NT 与 LM 响应。会话哈希是 MD5(ServerChallenge[:4] ||
// ClientChallenge) 的前八字节；NT 响应用它加密 21 字节 NT 哈希，LM 响应是
// ClientChallenge 后接 16 个零字节。
func ntlm2SessionResponse(passwordHash, serverChallenge, clientChallenge []byte) (ntResponse, lmResponse []byte, err error) {
	if len(passwordHash) != 16 {
		return nil, nil, errs.Detail(ErrCredentials, "NTLM2 password hash is %d bytes, want 16 | NTLM2 口令哈希为 %d 字节，期望 16", len(passwordHash), len(passwordHash))
	}
	if len(serverChallenge) != 8 {
		return nil, nil, errs.Detail(ErrChallenge, "server challenge is %d bytes, want 8 | 服务端挑战为 %d 字节，期望 8", len(serverChallenge), len(serverChallenge))
	}
	if len(clientChallenge) != 8 {
		return nil, nil, errs.Detail(ErrCredentials, "client challenge is %d bytes, want 8 | 客户端挑战为 %d 字节，期望 8", len(clientChallenge), len(clientChallenge))
	}
	hasher := md5.New()
	_, _ = hasher.Write(serverChallenge[:4])
	_, _ = hasher.Write(clientChallenge)
	sum := hasher.Sum(nil)
	ntResponse, err = ntlmV1Response(passwordHash, sum[:8])
	if err != nil {
		return nil, nil, err
	}
	lmResponse = make([]byte, 0, 24)
	lmResponse = append(lmResponse, clientChallenge...)
	lmResponse = append(lmResponse, make([]byte, 16)...)
	return ntResponse, lmResponse, nil
}

// desKey expands a 7-byte NTLM key into an 8-byte DES key. Desired parity bits
// are ignored by DES and left zero. | desKey 把 7 字节 NTLM 密钥扩展为 8 字节 DES
// 密钥。DES 忽略校验位，本函数将其留零。
func desKey(key7 []byte) []byte {
	return []byte{
		key7[0],
		key7[0]<<7 | key7[1]>>1,
		key7[1]<<6 | key7[2]>>2,
		key7[2]<<5 | key7[3]>>3,
		key7[3]<<4 | key7[4]>>4,
		key7[4]<<3 | key7[5]>>5,
		key7[5]<<2 | key7[6]>>6,
		key7[6] << 1,
	}
}

// desEncrypt encrypts one block with DES. | desEncrypt 使用 DES 加密一个分组。
func desEncrypt(key, block []byte) ([]byte, error) {
	if len(key) != 8 || len(block) != des.BlockSize {
		return nil, errs.Detail(ErrCredentials, "DES key or block has invalid size | DES 密钥或分组大小非法")
	}
	cipher, err := des.NewCipher(key)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrCredentials, "DES key setup failed | DES 密钥初始化失败")
	}
	out := make([]byte, des.BlockSize)
	cipher.Encrypt(out, block)
	return out, nil
}
