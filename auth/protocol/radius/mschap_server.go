package radius

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// MSCHAPv2FailureReason classifies an MS-CHAPv2 authentication failure. | MSCHAPv2FailureReason
// 对 MS-CHAPv2 认证失败进行分类。
//
// The numeric error codes are the values carried in the E= field of MS-CHAP-Error. They are useful
// both for RADIUS MS-CHAP-Error attributes and for EAP-MSCHAPv2 Failure messages. | 数字错误码是
// MS-CHAP-Error 的 E= 字段所携带的值，既用于 RADIUS MS-CHAP-Error 属性，也用于 EAP-MSCHAPv2
// Failure 消息。
type MSCHAPv2FailureReason uint16

// MS-CHAPv2 failure reason values. | MS-CHAPv2 失败原因值。
const (
	// MSCHAPv2FailureNone reports success. | MSCHAPv2FailureNone 表示成功。
	MSCHAPv2FailureNone MSCHAPv2FailureReason = 0
	// MSCHAPv2FailureMalformed reports a malformed challenge or response. | MSCHAPv2FailureMalformed 表示挑战或响应格式非法。
	MSCHAPv2FailureMalformed MSCHAPv2FailureReason = 1
	// MSCHAPv2FailureUnknownUser reports an unknown user. | MSCHAPv2FailureUnknownUser 表示未知用户。
	MSCHAPv2FailureUnknownUser MSCHAPv2FailureReason = 2
	// MSCHAPv2FailureBadPassword reports an incorrect password. | MSCHAPv2FailureBadPassword 表示口令错误。
	MSCHAPv2FailureBadPassword MSCHAPv2FailureReason = 3
	// MSCHAPv2FailureChallengeMismatch reports a challenge or identifier mismatch. | MSCHAPv2FailureChallengeMismatch 表示挑战或标识符不匹配。
	MSCHAPv2FailureChallengeMismatch MSCHAPv2FailureReason = 4
	// MSCHAPv2FailureRestrictedHours is ERROR_RESTRICTED_LOGON_HOURS (646). | MSCHAPv2FailureRestrictedHours 是 ERROR_RESTRICTED_LOGON_HOURS（646）。
	MSCHAPv2FailureRestrictedHours MSCHAPv2FailureReason = 646
	// MSCHAPv2FailureAccountDisabled is ERROR_ACCT_DISABLED (647). | MSCHAPv2FailureAccountDisabled 是 ERROR_ACCT_DISABLED（647）。
	MSCHAPv2FailureAccountDisabled MSCHAPv2FailureReason = 647
	// MSCHAPv2FailurePasswordExpired is ERROR_PASSWD_EXPIRED (648). | MSCHAPv2FailurePasswordExpired 是 ERROR_PASSWD_EXPIRED（648）。
	MSCHAPv2FailurePasswordExpired MSCHAPv2FailureReason = 648
	// MSCHAPv2FailureNoDialinPermission is ERROR_NO_DIALIN_PERMISSION (649). | MSCHAPv2FailureNoDialinPermission 是 ERROR_NO_DIALIN_PERMISSION（649）。
	MSCHAPv2FailureNoDialinPermission MSCHAPv2FailureReason = 649
	// MSCHAPv2FailureAuthentication is ERROR_AUTHENTICATION_FAILURE (691). | MSCHAPv2FailureAuthentication 是 ERROR_AUTHENTICATION_FAILURE（691）。
	MSCHAPv2FailureAuthentication MSCHAPv2FailureReason = 691
	// MSCHAPv2FailureChangingPassword is ERROR_CHANGING_PASSWORD (709). | MSCHAPv2FailureChangingPassword 是 ERROR_CHANGING_PASSWORD（709）。
	MSCHAPv2FailureChangingPassword MSCHAPv2FailureReason = 709
)

// ErrorCode returns the RFC 2759 E= value for the reason. | ErrorCode 返回该原因对应的 RFC 2759 E= 值。
func (r MSCHAPv2FailureReason) ErrorCode() int {
	switch r {
	case MSCHAPv2FailureNone:
		return 0
	case MSCHAPv2FailureMalformed, MSCHAPv2FailureUnknownUser, MSCHAPv2FailureBadPassword, MSCHAPv2FailureChallengeMismatch:
		return 691
	default:
		return int(r)
	}
}

// RetryAllowed reports whether the peer may retry authentication. | RetryAllowed 报告对端是否可重试认证。
func (r MSCHAPv2FailureReason) RetryAllowed() bool {
	switch r {
	case MSCHAPv2FailureNone, MSCHAPv2FailurePasswordExpired, MSCHAPv2FailureChangingPassword:
		return true
	default:
		return false
	}
}

// String returns the English failure name. | String 返回英文失败原因名称。
func (r MSCHAPv2FailureReason) String() string {
	switch r {
	case MSCHAPv2FailureNone:
		return "success"
	case MSCHAPv2FailureMalformed:
		return "malformed response"
	case MSCHAPv2FailureUnknownUser:
		return "unknown user"
	case MSCHAPv2FailureBadPassword:
		return "authentication failure"
	case MSCHAPv2FailureChallengeMismatch:
		return "challenge mismatch"
	case MSCHAPv2FailureRestrictedHours:
		return "restricted logon hours"
	case MSCHAPv2FailureAccountDisabled:
		return "account disabled"
	case MSCHAPv2FailurePasswordExpired:
		return "password expired"
	case MSCHAPv2FailureNoDialinPermission:
		return "no dial-in permission"
	case MSCHAPv2FailureAuthentication:
		return "authentication failure"
	case MSCHAPv2FailureChangingPassword:
		return "password change required"
	default:
		return "unknown failure"
	}
}

// MSCHAPError builds an RFC 2759 MS-CHAP-Error value. | MSCHAPError 构建 RFC 2759 的 MS-CHAP-Error 值。
//
// The value is "E=<code> R=<0|1> C=<32 hex> V=3 M=<message>". challenge is the 16-octet
// authenticator challenge sent to the peer. The returned value is suitable for the RADIUS
// MS-CHAP-Error vendor attribute and for the EAP-MSCHAPv2 Failure message. | 该值为
// "E=<code> R=<0|1> C=<32 hex> V=3 M=<message>"。challenge 是发送给对端的 16 字节认证符挑战。
// 返回值可用于 RADIUS MS-CHAP-Error 厂商属性与 EAP-MSCHAPv2 Failure 消息。
func MSCHAPError(reason MSCHAPv2FailureReason, challenge []byte, message string) (string, error) {
	if len(challenge) != 16 {
		return "", errs.Detail(ErrInvalidRequest, "MS-CHAPv2 challenge length %d must be 16", len(challenge))
	}
	retry := 0
	if reason.RetryAllowed() {
		retry = 1
	}
	if message == "" {
		message = reason.String()
	}
	return "E=" + decimal(uint64(reason.ErrorCode())) + " R=" + decimal(uint64(retry)) +
		" C=" + strings.ToUpper(hex.EncodeToString(challenge)) + " V=3 M=" + message, nil
}

// decimal formats an unsigned integer without importing strconv in protocol paths. | decimal 在不引入
// strconv 的情况下格式化无符号整数。
func decimal(value uint64) string {
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	index := len(buf)
	for value > 0 {
		index--
		buf[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buf[index:])
}

// MSCHAPv2ServerResult is the outcome of a server-side MS-CHAPv2 verification. | MSCHAPv2ServerResult
// 是服务端 MS-CHAPv2 校验的结果。
//
// AuthenticatorResponse is the 42-octet "S=" followed by 40 uppercase hexadecimal digits that the
// server returns in MS-CHAP2-Success or EAP-MSCHAPv2 Success. MPPESendKey and MPPERecvKey are the
// server-direction RFC 3079 keys, or nil when the password was wrong. Failure is
// MSCHAPv2FailureNone on success and the classified failure otherwise. | AuthenticatorResponse 是服务器
// 在 MS-CHAP2-Success 或 EAP-MSCHAPv2 Success 中返回的 42 字节值，即 "S=" 加 40 个大写十六进制
// 数字。MPPESendKey 与 MPPERecvKey 是服务器方向的 RFC 3079 密钥，口令错误时为 nil。成功时
// Failure 为 MSCHAPv2FailureNone，否则为分类后的失败原因。
type MSCHAPv2ServerResult struct {
	// AuthenticatorResponse is the 42-octet MS-CHAP2-Success string. | AuthenticatorResponse 是 42 字节的 MS-CHAP2-Success 字符串。
	AuthenticatorResponse []byte
	// MPPESendKey is the 16-octet server-to-peer MPPE key. | MPPESendKey 是 16 字节的服务器到对端 MPPE 密钥。
	MPPESendKey []byte
	// MPPERecvKey is the 16-octet peer-to-server MPPE key. | MPPERecvKey 是 16 字节的对端到服务器 MPPE 密钥。
	MPPERecvKey []byte
	// Failure classifies the verification result. | Failure 对校验结果分类。
	Failure MSCHAPv2FailureReason
}

// Succeeded reports whether verification succeeded. | Succeeded 报告校验是否成功。
func (r *MSCHAPv2ServerResult) Succeeded() bool {
	return r != nil && r.Failure == MSCHAPv2FailureNone
}

// NTPasswordHash returns the RFC 2759 NT password hash (UTF-16LE then MD4). | NTPasswordHash 返回
// RFC 2759 的 NT 口令哈希（UTF-16LE 后做 MD4）。
func NTPasswordHash(password string) [16]byte {
	return ntPasswordHash(password)
}

// GenerateMSCHAPv2Challenge returns a cryptographically random 16-octet authenticator challenge. |
// GenerateMSCHAPv2Challenge 返回加密安全的 16 字节认证符挑战。
func GenerateMSCHAPv2Challenge() ([16]byte, error) {
	var challenge [16]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return challenge, errs.Wrap(err, ErrInternal)
	}
	return challenge, nil
}

// VerifyMSCHAPv2Server verifies a RADIUS-format 50-octet MS-CHAP2-Response for a user and password.
// | VerifyMSCHAPv2Server 校验用户与口令对应的 RADIUS 格式 50 字节 MS-CHAP2-Response。
//
// The response layout is Ident(1) || Flags(1) || Peer-Challenge(16) || Reserved(8) ||
// NT-Response(24), as generated by MSCHAPv2Response. A nil error means the response was structurally
// valid and the returned result classifies success or password failure. Malformed lengths return an
// error wrapping ErrInvalidAttribute. | 响应布局为 Ident(1) || Flags(1) || Peer-Challenge(16) ||
// Reserved(8) || NT-Response(24)，与 MSCHAPv2Response 生成的一致。nil 错误表示响应结构合法，
// 返回结果给出成功或口令失败分类。长度非法返回包装 ErrInvalidAttribute 的错误。
func VerifyMSCHAPv2Server(userName, password string, authenticatorChallenge, response []byte) (*MSCHAPv2ServerResult, error) {
	if len(authenticatorChallenge) != 16 {
		return nil, errs.Detail(ErrInvalidAttribute, "MS-CHAPv2 authenticator challenge length %d must be 16", len(authenticatorChallenge))
	}
	if len(response) != msCHAPv2ResponseLength {
		return nil, errs.Detail(ErrInvalidAttribute, "MS-CHAP2-Response length %d must be %d", len(response), msCHAPv2ResponseLength)
	}
	if response[1] != 0 {
		return &MSCHAPv2ServerResult{Failure: MSCHAPv2FailureMalformed}, nil
	}
	var reserved [8]byte
	if subtle.ConstantTimeCompare(reserved[:], response[18:26]) != 1 {
		return &MSCHAPv2ServerResult{Failure: MSCHAPv2FailureMalformed}, nil
	}
	expected, err := MSCHAPv2Response(userName, password, authenticatorChallenge, response[2:18], response[0])
	if err != nil {
		return nil, err
	}
	defer zeroBytes(expected)
	if !constantTimeEqual(expected[26:50], response[26:50]) {
		return &MSCHAPv2ServerResult{Failure: MSCHAPv2FailureBadPassword}, nil
	}
	success, err := MSCHAPv2AuthenticatorResponse(userName, password, authenticatorChallenge, response)
	if err != nil {
		return nil, err
	}
	sendKey, recvKey, err := MSCHAPv2MPPEKeys(password, response)
	if err != nil {
		zeroBytes(success)
		return nil, err
	}
	return &MSCHAPv2ServerResult{
		AuthenticatorResponse: success,
		MPPESendKey:           sendKey,
		MPPERecvKey:           recvKey,
		Failure:               MSCHAPv2FailureNone,
	}, nil
}

// MSCHAPv2AuthenticatorResponse computes the RFC 2759 42-octet AuthenticatorResponse for a valid
// RADIUS-format MS-CHAP2-Response. | MSCHAPv2AuthenticatorResponse 为合法的 RADIUS 格式
// MS-CHAP2-Response 计算 RFC 2759 的 42 字节 AuthenticatorResponse。
//
// The response argument must be 50 octets and must contain the same fields accepted by
// VerifyMSCHAPv2Server. The result is "S=" followed by 40 uppercase hexadecimal digits. | response
// 参数必须为 50 字节，并包含 VerifyMSCHAPv2Server 接受的字段。结果为 "S=" 加 40 个大写十六进制
// 数字。
func MSCHAPv2AuthenticatorResponse(userName, password string, authenticatorChallenge, response []byte) ([]byte, error) {
	if len(authenticatorChallenge) != 16 {
		return nil, errs.Detail(ErrInvalidAttribute, "MS-CHAPv2 authenticator challenge length %d must be 16", len(authenticatorChallenge))
	}
	if len(response) != msCHAPv2ResponseLength {
		return nil, errs.Detail(ErrInvalidAttribute, "MS-CHAP2-Response length %d must be %d", len(response), msCHAPv2ResponseLength)
	}
	passwordHash := ntPasswordHash(password)
	defer zeroBytes(passwordHash[:])
	passwordHashHash := md4Sum(passwordHash[:])
	ntResponse := response[26:50]
	digest := sha1.New()
	digest.Write(passwordHashHash[:])
	digest.Write(ntResponse)
	digest.Write([]byte("Magic server to client signing constant"))
	digestSum := digest.Sum(nil)
	defer zeroBytes(digestSum)
	challenge := msCHAPv2ChallengeHash(userName, authenticatorChallenge, response[2:18])
	sign := sha1.New()
	sign.Write(digestSum)
	sign.Write(challenge)
	sign.Write([]byte("Pad to make it do more than one iteration"))
	signSum := sign.Sum(nil)
	defer zeroBytes(signSum)
	out := make([]byte, 42)
	out[0] = 'S'
	out[1] = '='
	hex.Encode(out[2:], signSum)
	for i := 2; i < len(out); i++ {
		if out[i] >= 'a' && out[i] <= 'f' {
			out[i] -= 'a' - 'A'
		}
	}
	return out, nil
}

// MSCHAPv2SuccessValue returns the 43-octet RADIUS MS-CHAP2-Success value: Ident followed by the
// 42-octet AuthenticatorResponse. | MSCHAPv2SuccessValue 返回 43 字节的 RADIUS MS-CHAP2-Success
// 值：Ident 后跟 42 字节 AuthenticatorResponse。
func MSCHAPv2SuccessValue(ident uint8, userName, password string, authenticatorChallenge, response []byte) ([]byte, error) {
	authenticatorResponse, err := MSCHAPv2AuthenticatorResponse(userName, password, authenticatorChallenge, response)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1+len(authenticatorResponse))
	out[0] = ident
	copy(out[1:], authenticatorResponse)
	zeroBytes(authenticatorResponse)
	return out, nil
}

// MSCHAPv2MPPEKeys derives the RFC 3079 16-octet server send and receive MPPE keys. | MSCHAPv2MPPEKeys
// 派生 RFC 3079 的 16 字节服务器发送与接收 MPPE 密钥。
//
// The response must be a RADIUS-format 50-octet MS-CHAP2-Response; its NT-Response is the RFC 3079
// key seed. The peer's keys are the reverse directions. | response 必须为 RADIUS 格式的 50 字节
// MS-CHAP2-Response；其 NT-Response 是 RFC 3079 的密钥种子。对端的密钥方向相反。
func MSCHAPv2MPPEKeys(password string, response []byte) (sendKey, recvKey []byte, err error) {
	if len(response) != msCHAPv2ResponseLength {
		return nil, nil, errs.Detail(ErrInvalidAttribute, "MS-CHAP2-Response length %d must be %d", len(response), msCHAPv2ResponseLength)
	}
	passwordHash := ntPasswordHash(password)
	defer zeroBytes(passwordHash[:])
	passwordHashHash := md4Sum(passwordHash[:])
	ntResponse := response[26:50]
	masterInput := make([]byte, 0, 16+24+27)
	masterInput = append(masterInput, passwordHashHash[:]...)
	masterInput = append(masterInput, ntResponse...)
	masterInput = append(masterInput, []byte("This is the MPPE Master Key")...)
	masterSum := sha1.Sum(masterInput)
	zeroBytes(masterInput)
	masterKey := masterSum[:16]
	defer zeroBytes(masterKey)
	serverSend := asymmetricStartKey(masterKey, true)
	serverRecv := asymmetricStartKey(masterKey, false)
	return serverSend, serverRecv, nil
}

// asymmetricStartKey implements the RFC 3079 GetAsymmetricStartKey for 128-bit keys. When send is
// true the input uses a zero pad followed by an 0xF2 pad, and the reverse order otherwise. |
// asymmetricStartKey 实现 RFC 3079 面向 128 位密钥的 GetAsymmetricStartKey。send 为真时输入使用零
// 填充后接 0xF2 填充，否则顺序相反。
func asymmetricStartKey(masterKey []byte, send bool) []byte {
	const padLength = 40
	zeros := make([]byte, padLength)
	f2 := bytes.Repeat([]byte{0xf2}, padLength)
	input := make([]byte, 0, len(masterKey)+padLength+1+padLength)
	input = append(input, masterKey...)
	if send {
		input = append(input, zeros...)
		input = append(input, 0)
		input = append(input, f2...)
	} else {
		input = append(input, f2...)
		input = append(input, 0)
		input = append(input, zeros...)
	}
	sum := sha1.Sum(input)
	zeroBytes(input)
	key := make([]byte, 16)
	copy(key, sum[:16])
	zeroBytes(sum[:])
	return key
}

// EncryptMSMPPEKey hides an MPPE key with the RFC 2548 MS-MPPE-Send-Key/Recv-Key algorithm. |
// EncryptMSMPPEKey 用 RFC 2548 的 MS-MPPE-Send-Key/Recv-Key 算法隐藏 MPPE 密钥。
//
// The returned value is Salt(2) || Ciphertext and is suitable for the value of a Microsoft vendor
// attribute. The caller must use a distinct random salt for every key in one Access-Accept; this
// function generates one automatically. | 返回值为 Salt(2) || Ciphertext，可作为 Microsoft 厂商
// 属性的值。同一 Access-Accept 中每个密钥必须使用不同随机盐；本函数会自动生成。
func EncryptMSMPPEKey(secret, requestAuthenticator, key []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errs.Detail(ErrInvalidRequest, "shared secret is required")
	}
	if len(requestAuthenticator) != 16 {
		return nil, errs.Detail(ErrInvalidRequest, "request authenticator length %d must be 16", len(requestAuthenticator))
	}
	if len(key) == 0 || len(key) > 32 {
		return nil, errs.Detail(ErrInvalidRequest, "MPPE key length %d must be in [1,32]", len(key))
	}
	plain := make([]byte, 1+len(key))
	plain[0] = byte(len(key))
	copy(plain[1:], key)
	if remainder := len(plain) % 16; remainder != 0 {
		plain = append(plain, make([]byte, 16-remainder)...)
	}
	salt := make([]byte, 2)
	if _, err := rand.Read(salt); err != nil {
		zeroBytes(plain)
		return nil, errs.Wrap(err, ErrInternal)
	}
	salt[0] |= 0x80
	out := make([]byte, 2+len(plain))
	copy(out, salt)
	digestInput := make([]byte, 0, len(secret)+16+2)
	digestInput = append(digestInput, secret...)
	digestInput = append(digestInput, requestAuthenticator...)
	digestInput = append(digestInput, salt...)
	first := md5.Sum(digestInput)
	zeroBytes(digestInput)
	for i := 0; i < 16; i++ {
		out[2+i] = plain[i] ^ first[i]
	}
	for offset := 16; offset < len(plain); offset += 16 {
		chainInput := make([]byte, len(secret)+16)
		copy(chainInput, secret)
		copy(chainInput[len(secret):], out[2+offset-16:2+offset])
		next := md5.Sum(chainInput)
		zeroBytes(chainInput)
		for i := 0; i < 16; i++ {
			out[2+offset+i] = plain[offset+i] ^ next[i]
		}
	}
	zeroBytes(plain)
	return out, nil
}

// DecryptMSMPPEKey reverses EncryptMSMPPEKey. | DecryptMSMPPEKey 逆转 EncryptMSMPPEKey。
func DecryptMSMPPEKey(secret, requestAuthenticator, encrypted []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errs.Detail(ErrInvalidRequest, "shared secret is required")
	}
	if len(requestAuthenticator) != 16 {
		return nil, errs.Detail(ErrInvalidRequest, "request authenticator length %d must be 16", len(requestAuthenticator))
	}
	if len(encrypted) < 18 || (len(encrypted)-2)%16 != 0 {
		return nil, errs.Detail(ErrInvalidAttribute, "encrypted MPPE key length %d is invalid", len(encrypted))
	}
	salt := encrypted[:2]
	ciphertext := encrypted[2:]
	plain := make([]byte, len(ciphertext))
	digestInput := make([]byte, 0, len(secret)+16+2)
	digestInput = append(digestInput, secret...)
	digestInput = append(digestInput, requestAuthenticator...)
	digestInput = append(digestInput, salt...)
	first := md5.Sum(digestInput)
	zeroBytes(digestInput)
	for i := 0; i < 16; i++ {
		plain[i] = ciphertext[i] ^ first[i]
	}
	for offset := 16; offset < len(ciphertext); offset += 16 {
		chainInput := make([]byte, len(secret)+16)
		copy(chainInput, secret)
		copy(chainInput[len(secret):], ciphertext[offset-16:offset])
		next := md5.Sum(chainInput)
		zeroBytes(chainInput)
		for i := 0; i < 16; i++ {
			plain[offset+i] = ciphertext[offset+i] ^ next[i]
		}
	}
	length := int(plain[0])
	if length == 0 || length > len(plain)-1 {
		zeroBytes(plain)
		return nil, errs.Detail(ErrInvalidAttribute, "decrypted MPPE key length %d is invalid", length)
	}
	key := append([]byte(nil), plain[1:1+length]...)
	zeroBytes(plain)
	return key, nil
}

// MSCHAPv2ServerConfig configures a stateful server-side MS-CHAPv2 challenge responder. |
// MSCHAPv2ServerConfig 配置有状态的服务端 MS-CHAPv2 挑战响应器。
type MSCHAPv2ServerConfig struct {
	// Lookup resolves the user password. It is required. | Lookup 解析用户口令，必填。
	Lookup EAPPasswordLookup
	// Timeout bounds a challenge's lifetime; zero selects DefaultMSCHAPv2ChallengeTimeout. |
	// Timeout 约束挑战的有效期；零值选择 DefaultMSCHAPv2ChallengeTimeout。
	Timeout time.Duration
	// MaxChallenges is the maximum number of outstanding challenges; zero selects 4096. |
	// MaxChallenges 是未完成挑战的最大数量；零值选择 4096。
	MaxChallenges int
}

// DefaultMSCHAPv2ChallengeTimeout is the default lifetime of a server-issued MS-CHAPv2 challenge. |
// DefaultMSCHAPv2ChallengeTimeout 是服务器签发 MS-CHAPv2 挑战的默认有效期。
const DefaultMSCHAPv2ChallengeTimeout = 30 * time.Second

// MSCHAPv2Challenge is one server-issued challenge and its opaque RADIUS State value. |
// MSCHAPv2Challenge 是服务器签发的一次挑战及其不透明 RADIUS State 值。
type MSCHAPv2Challenge struct {
	// Expires is the challenge expiry time. | Expires 是挑战到期时间。
	Expires time.Time
	// UserName is the user the challenge was issued to. | UserName 是挑战签发的用户名。
	UserName string
	// Challenge is the 16-octet MS-CHAP-Challenge value. | Challenge 是 16 字节的 MS-CHAP-Challenge 值。
	Challenge []byte
	// State is the opaque State attribute the AccessServer sends to the client. | State 是 AccessServer
	// 发送给客户端的不透明 State 属性。
	State []byte
}

// MSCHAPv2Server issues and verifies stateful MS-CHAPv2 challenges. It is safe for concurrent use. |
// MSCHAPv2Server 签发并校验有状态的 MS-CHAPv2 挑战，可并发使用。
type MSCHAPv2Server struct {
	lookup    EAPPasswordLookup
	timeout   time.Duration
	maxChalls int

	mu     sync.Mutex
	states map[string]mschapv2ChallengeState
	closed bool
}

// mschapv2ChallengeState is the internal challenge record. | mschapv2ChallengeState 是内部挑战记录。
type mschapv2ChallengeState struct {
	expires   time.Time
	userName  string
	challenge [16]byte
}

// NewMSCHAPv2Server validates config and returns a challenge responder. | NewMSCHAPv2Server 校验
// config 并返回挑战响应器。
func NewMSCHAPv2Server(config MSCHAPv2ServerConfig) (*MSCHAPv2Server, error) {
	if config.Lookup == nil {
		return nil, errs.Detail(ErrInvalidConfig, "MS-CHAPv2 password lookup is required")
	}
	if config.Timeout < 0 {
		return nil, errs.Detail(ErrInvalidConfig, "MS-CHAPv2 timeout must not be negative")
	}
	if config.Timeout == 0 {
		config.Timeout = DefaultMSCHAPv2ChallengeTimeout
	}
	if config.MaxChallenges < 0 {
		return nil, errs.Detail(ErrInvalidConfig, "MS-CHAPv2 max challenges must not be negative")
	}
	if config.MaxChallenges == 0 {
		config.MaxChallenges = 4096
	}
	return &MSCHAPv2Server{
		lookup:    config.Lookup,
		timeout:   config.Timeout,
		maxChalls: config.MaxChallenges,
		states:    make(map[string]mschapv2ChallengeState),
	}, nil
}

// IssueChallenge creates a challenge for userName and returns its opaque State value. | IssueChallenge
// 为 userName 创建挑战并返回其不透明 State 值。
func (s *MSCHAPv2Server) IssueChallenge(ctx context.Context, userName string) (*MSCHAPv2Challenge, error) {
	if s == nil {
		return nil, errs.Detail(ErrInvalidConfig, "MS-CHAPv2 server is nil")
	}
	if userName == "" {
		return nil, errs.Detail(ErrInvalidRequest, "user name is required")
	}
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	challenge, err := GenerateMSCHAPv2Challenge()
	if err != nil {
		return nil, err
	}
	state := make([]byte, 32)
	if _, err := rand.Read(state); err != nil {
		return nil, errs.Wrap(err, ErrInternal)
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrServerClosed
	}
	s.pruneLocked(now)
	if len(s.states) >= s.maxChalls {
		return nil, errs.Detail(ErrInvalidRequest, "too many outstanding MS-CHAPv2 challenges")
	}
	s.states[string(state)] = mschapv2ChallengeState{
		expires:   now.Add(s.timeout),
		userName:  userName,
		challenge: challenge,
	}
	return &MSCHAPv2Challenge{
		Expires:   now.Add(s.timeout),
		UserName:  userName,
		Challenge: append([]byte(nil), challenge[:]...),
		State:     state,
	}, nil
}

// VerifyResponse looks up the password and verifies a RADIUS-format MS-CHAP2-Response against the
// challenge bound to state. | VerifyResponse 查找口令并依据 state 绑定的挑战校验 RADIUS 格式的
// MS-CHAP2-Response。
//
// A returned result with Failure=MSCHAPv2FailureNone carries AuthenticatorResponse and MPPE keys.
// Unknown, expired or already consumed states return ErrEAPState; malformed responses return an
// ErrInvalidAttribute detail. The challenge argument may be nil or must equal the issued challenge.
// | Failure=MSCHAPv2FailureNone 的结果携带 AuthenticatorResponse 与 MPPE 密钥。未知、过期或已使用
// 的 state 返回 ErrEAPState；格式非法的响应返回 ErrInvalidAttribute 细节。challenge 可为 nil，或必须
// 等于签发的挑战。
func (s *MSCHAPv2Server) VerifyResponse(ctx context.Context, userName string, state, challenge, response []byte) (*MSCHAPv2ServerResult, error) {
	if s == nil {
		return nil, errs.Detail(ErrInvalidConfig, "MS-CHAPv2 server is nil")
	}
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	now := time.Now()
	s.mu.Lock()
	record, ok := s.states[string(state)]
	if ok && now.After(record.expires) {
		delete(s.states, string(state))
		ok = false
	}
	if !ok {
		s.mu.Unlock()
		return nil, errs.Detail(ErrEAPState, "unknown or expired MS-CHAPv2 state")
	}
	if userName != "" && record.userName != userName {
		s.mu.Unlock()
		return &MSCHAPv2ServerResult{Failure: MSCHAPv2FailureUnknownUser}, nil
	}
	if len(challenge) != 0 && !constantTimeEqual(challenge, record.challenge[:]) {
		s.mu.Unlock()
		return &MSCHAPv2ServerResult{Failure: MSCHAPv2FailureChallengeMismatch}, nil
	}
	// Claim the state while holding the lock so concurrent replays cannot verify the same
	// challenge twice. | 持锁认领状态，防止并发重放对同一挑战完成两次校验。
	delete(s.states, string(state))
	s.mu.Unlock()
	password, err := lookupEAPPassword(ctx, s.lookup, record.userName)
	if err != nil {
		if isUnknownUser(err) {
			return &MSCHAPv2ServerResult{Failure: MSCHAPv2FailureUnknownUser}, nil
		}
		return nil, err
	}
	defer zeroBytes(password)
	return VerifyMSCHAPv2Server(record.userName, string(password), record.challenge[:], response)
}

// Close discards every outstanding challenge and rejects further use. | Close 丢弃全部未完成挑战并拒绝后续使用。
func (s *MSCHAPv2Server) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	for state := range s.states {
		delete(s.states, state)
	}
	return nil
}

// pruneLocked removes expired records. The caller must hold s.mu. | pruneLocked 删除过期记录。调用方必须持有 s.mu。
func (s *MSCHAPv2Server) pruneLocked(now time.Time) {
	for state, record := range s.states {
		if now.After(record.expires) {
			delete(s.states, state)
		}
	}
}

// ctxErr returns the context error wrapped as an ErrCanceled or ErrTimeout sentinel. | ctxErr 将上下文
// 错误包装为 ErrCanceled 或 ErrTimeout 哨兵。
func ctxErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return contextError(err)
	}
	return nil
}

// isUnknownUser reports whether err classifies as an unknown-user lookup. | isUnknownUser 报告 err
// 是否分类为未知用户查找失败。
func isUnknownUser(err error) bool {
	return err != nil && strings.Contains(err.Error(), ErrEAPUnknownUser.Error())
}

// binaryUint32 is a small helper used by EAP framing. | binaryUint32 是 EAP 分帧使用的小助手。
func binaryUint32(value uint32) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, value)
	return out
}
