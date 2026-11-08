package ntlm

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"sync"

	"github.com/shibingli/ydx/errs"
)

// sessionKeySize is the size in bytes of an NTLMSSP exported session key. |
// sessionKeySize 是 NTLMSSP 导出会话密钥的字节大小。
const sessionKeySize = md4Size

// messageSignatureSize is the size in bytes of an NTLMSSP message signature. |
// messageSignatureSize 是 NTLMSSP 消息签名的字节大小。
const messageSignatureSize = 16

// checksumSize is the size in bytes of the checksum inside an NTLMSSP message
// signature. | checksumSize 是 NTLMSSP 消息签名中校验和的字节大小。
const checksumSize = 8

// messageSignatureVersion is the only NTLMSSP message signature version this
// package accepts. | messageSignatureVersion 是本包唯一接受的 NTLMSSP 消息签名版本。
const messageSignatureVersion uint32 = 1

// maxSequenceNumber is the largest NTLMSSP message sequence number. |
// maxSequenceNumber 是 NTLMSSP 消息序列号的最大值。
const maxSequenceNumber = uint64(^uint32(0))

// The null-terminated ASCII magic constants defined by MS-NLMP 3.4.2 for
// signing and sealing key derivation. | MS-NLMP 3.4.2 为签名与密封密钥派生定义的
// 以 NUL 结尾的 ASCII 魔术常量。
const (
	clientSigningMagic = "session key to client-to-server signing key magic constant"
	serverSigningMagic = "session key to server-to-client signing key magic constant"
	clientSealingMagic = "session key to client-to-server sealing key magic constant"
	serverSealingMagic = "session key to server-to-client sealing key magic constant"
)

// Role identifies which peer owns a SecuritySession. | Role 标识 SecuritySession
// 所属的对端。
type Role uint8

const (
	// RoleClient is the NTLMSSP initiator. | RoleClient 是 NTLMSSP 发起方。
	RoleClient Role = iota
	// RoleServer is the NTLMSSP acceptor. | RoleServer 是 NTLMSSP 接受方。
	RoleServer
)

// String returns a stable name for the role. | String 返回角色的稳定名称。
func (r Role) String() string {
	switch r {
	case RoleClient:
		return "client"
	case RoleServer:
		return "server"
	default:
		return "unknown"
	}
}

// SessionKeys holds the four directional NTLMSSP signing and sealing keys. They
// are keying material: callers must protect them and zero them with Wipe when no
// longer needed. | SessionKeys 保存四个方向性的 NTLMSSP 签名与密封密钥。它们是密钥
// 材料：调用方必须保护它们，并在不再需要时使用 Wipe 清零。
type SessionKeys struct {
	// ClientSigningKey signs client-to-server messages. | ClientSigningKey 对
	// 客户端到服务端消息签名。
	ClientSigningKey []byte
	// ServerSigningKey signs server-to-client messages. | ServerSigningKey 对
	// 服务端到客户端消息签名。
	ServerSigningKey []byte
	// ClientSealingKey seals client-to-server messages. | ClientSealingKey 密封
	// 客户端到服务端消息。
	ClientSealingKey []byte
	// ServerSealingKey seals server-to-client messages. | ServerSealingKey 密封
	// 服务端到客户端消息。
	ServerSealingKey []byte
}

// Wipe zeroes every derived key. | Wipe 清零所有派生密钥。
func (k *SessionKeys) Wipe() {
	if k == nil {
		return
	}
	wipe(k.ClientSigningKey)
	wipe(k.ServerSigningKey)
	wipe(k.ClientSealingKey)
	wipe(k.ServerSealingKey)
	k.ClientSigningKey = nil
	k.ServerSigningKey = nil
	k.ClientSealingKey = nil
	k.ServerSealingKey = nil
}

// DeriveSessionKeys derives the four directional NTLMSSP signing and sealing
// keys defined by MS-NLMP 3.4.2 from a 16-byte exported session key and the
// negotiated flags. Extended session security is required because MS-NLMP 3.4.5.2
// defines no signing keys without it. The 128-bit flag selects the full exported
// key for sealing key derivation, Flag56 selects its first seven bytes, and the
// default selects its first five bytes. | DeriveSessionKeys 按 MS-NLMP 3.4.2 从
// 16 字节导出会话密钥与协商标志派生四个方向性的 NTLMSSP 签名与密封密钥。必须启用扩展
// 会话安全，因为 MS-NLMP 3.4.5.2 在未启用时不定义签名密钥。Flag128 选择完整导出密钥
// 派生密封密钥，Flag56 选择前七字节，默认选择前五字节。
func DeriveSessionKeys(exportedSessionKey []byte, flags NegotiateFlags) (*SessionKeys, error) {
	if len(exportedSessionKey) != sessionKeySize {
		return nil, errs.Detail(ErrSessionSecurity, "exported session key is %d bytes, want %d | 导出会话密钥为 %d 字节，期望 %d", len(exportedSessionKey), sessionKeySize, len(exportedSessionKey), sessionKeySize)
	}
	if !flags.Has(FlagExtendedSessionSecurity) {
		return nil, errs.Detail(ErrSessionSecurity, "extended session security is required for signing keys | 签名密钥需要扩展会话安全")
	}
	sealingMaterial := exportedSessionKey[:5]
	switch {
	case flags.Has(Flag128):
		sealingMaterial = exportedSessionKey
	case flags.Has(Flag56):
		sealingMaterial = exportedSessionKey[:7]
	}
	return &SessionKeys{
		ClientSigningKey: deriveSessionKey(exportedSessionKey, clientSigningMagic),
		ServerSigningKey: deriveSessionKey(exportedSessionKey, serverSigningMagic),
		ClientSealingKey: deriveSessionKey(sealingMaterial, clientSealingMagic),
		ServerSealingKey: deriveSessionKey(sealingMaterial, serverSealingMagic),
	}, nil
}

// deriveSessionKey returns MD5(material || magic || 0x00). | deriveSessionKey 返回
// MD5(material || magic || 0x00)。
func deriveSessionKey(material []byte, magic string) []byte {
	hasher := md5.New()
	_, _ = hasher.Write(material)
	_, _ = hasher.Write([]byte(magic))
	_, _ = hasher.Write([]byte{0})
	return hasher.Sum(nil)
}

// rc4SessionKey applies RC4 with key to data. NTLMv2 uses it to encrypt and
// decrypt the exported session key carried by the Type 3 message. |
// rc4SessionKey 使用 key 对 data 应用 RC4。NTLMv2 用它加密与解密 Type 3 消息携带的
// 导出会话密钥。
func rc4SessionKey(key, data []byte) ([]byte, error) {
	if len(key) != sessionKeySize {
		return nil, errs.Detail(ErrSessionSecurity, "RC4 key is %d bytes, want %d | RC4 密钥为 %d 字节，期望 %d", len(key), sessionKeySize, len(key), sessionKeySize)
	}
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrSessionSecurity, "cannot initialize RC4 | 无法初始化 RC4")
	}
	result := make([]byte, len(data))
	cipher.XORKeyStream(result, data)
	*cipher = rc4.Cipher{}
	return result, nil
}

// SecuritySession applies the connection-oriented NTLMSSP message signing and
// sealing algorithms defined by MS-NLMP 3.4.3 and 3.4.4. One RC4 cipher persists
// per direction across messages, sequence numbers start at zero, and messages
// must be received in order. A SecuritySession is safe for concurrent use. A
// checksum or sequence failure is fail closed: the session is wiped and closed.
// | SecuritySession 应用 MS-NLMP 3.4.3 与 3.4.4 定义的面向连接 NTLMSSP 消息签名与
// 密封算法。每个方向跨消息保持一个 RC4 密码状态，序列号从零开始，消息必须按序接收。
// SecuritySession 可安全并发使用。校验和或序列号失败会失败关闭：会话被清零并关闭。
type SecuritySession struct {
	keys *SessionKeys

	sendCipher *rc4.Cipher
	recvCipher *rc4.Cipher

	sendSigningKey []byte
	recvSigningKey []byte
	sendSealingKey []byte
	recvSealingKey []byte
	sendSequence   uint64
	recvSequence   uint64
	mu             sync.Mutex

	flags NegotiateFlags

	role   Role
	closed bool
}

// NewSecuritySession derives signing and sealing state from an exported session
// key and the negotiated flags. Exactly one of RoleClient and RoleServer must be
// supplied. The negotiated flags must contain FlagExtendedSessionSecurity and
// FlagSign; FlagSeal requires FlagSign. | NewSecuritySession 从导出会话密钥与协商
// 标志派生签名与密封状态。必须提供 RoleClient 与 RoleServer 之一。协商标志必须包含
// FlagExtendedSessionSecurity 与 FlagSign；FlagSeal 需要 FlagSign。
func NewSecuritySession(role Role, exportedSessionKey []byte, flags NegotiateFlags) (*SecuritySession, error) {
	if role != RoleClient && role != RoleServer {
		return nil, errs.Detail(ErrSessionSecurity, "role %d is invalid | 角色 %d 非法", role, role)
	}
	sign := flags.Has(FlagSign)
	seal := flags.Has(FlagSeal)
	if !sign && !seal {
		return nil, errs.Detail(ErrSessionSecurity, "message signing and sealing were not negotiated | 未协商消息签名或密封")
	}
	if seal && !sign {
		return nil, errs.Detail(ErrSessionSecurity, "message sealing requires message signing | 消息密封需要消息签名")
	}
	keys, err := DeriveSessionKeys(exportedSessionKey, flags)
	if err != nil {
		return nil, err
	}
	var sendSigningKey, recvSigningKey, sendSealingKey, recvSealingKey []byte
	switch role {
	case RoleClient:
		sendSigningKey = keys.ClientSigningKey
		recvSigningKey = keys.ServerSigningKey
		sendSealingKey = keys.ClientSealingKey
		recvSealingKey = keys.ServerSealingKey
	case RoleServer:
		sendSigningKey = keys.ServerSigningKey
		recvSigningKey = keys.ClientSigningKey
		sendSealingKey = keys.ServerSealingKey
		recvSealingKey = keys.ClientSealingKey
	}
	sendCipher, err := rc4.NewCipher(sendSealingKey)
	if err != nil {
		keys.Wipe()
		return nil, errs.WrapDetail(err, ErrSessionSecurity, "cannot initialize the send RC4 state | 无法初始化发送 RC4 状态")
	}
	recvCipher, err := rc4.NewCipher(recvSealingKey)
	if err != nil {
		*sendCipher = rc4.Cipher{}
		keys.Wipe()
		return nil, errs.WrapDetail(err, ErrSessionSecurity, "cannot initialize the receive RC4 state | 无法初始化接收 RC4 状态")
	}
	return &SecuritySession{
		role:           role,
		flags:          flags,
		keys:           keys,
		sendSigningKey: sendSigningKey,
		recvSigningKey: recvSigningKey,
		sendSealingKey: sendSealingKey,
		recvSealingKey: recvSealingKey,
		sendCipher:     sendCipher,
		recvCipher:     recvCipher,
	}, nil
}

// Role returns the peer that owns the session. | Role 返回拥有该会话的对端。
func (s *SecuritySession) Role() Role {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.role
}

// Flags returns the negotiated flags the session was built from. | Flags 返回构建
// 会话时使用的协商标志。
func (s *SecuritySession) Flags() NegotiateFlags {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flags
}

// Closed reports whether the session has been closed or failed closed. | Closed
// 报告会话是否已关闭或失败关闭。
func (s *SecuritySession) Closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// Sign returns the 16-byte MS-NLMP message signature for message and advances the
// send sequence: client-to-server for RoleClient and server-to-client for
// RoleServer. It requires negotiated FlagSign. | Sign 返回 message 的 16 字节 MS-NLMP
// 消息签名并推进发送序列号：RoleClient 为客户端到服务端，RoleServer 为服务端到客户端。它
// 要求已协商 FlagSign。
func (s *SecuritySession) Sign(message []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.readyLocked(FlagSign, ErrSigningNotNegotiated); err != nil {
		return nil, err
	}
	sequence, err := s.nextSendSequenceLocked()
	if err != nil {
		return nil, err
	}
	checksum := computeSigningChecksum(s.sendSigningKey, sequence, message)
	if s.flags.Has(FlagKeyExchange) {
		s.sendCipher.XORKeyStream(checksum, checksum)
	}
	signature := make([]byte, messageSignatureSize)
	binary.LittleEndian.PutUint32(signature[0:4], messageSignatureVersion)
	copy(signature[4:12], checksum)
	binary.LittleEndian.PutUint32(signature[12:16], sequence)
	return signature, nil
}

// Verify checks a 16-byte MS-NLMP message signature for message in constant time
// and advances the receive sequence: server-to-client for RoleClient and
// client-to-server for RoleServer. It requires negotiated FlagSign. A wrong
// version, sequence number or checksum fails closed and wipes the session. |
// Verify 以常量时间校验 message 的 16 字节 MS-NLMP 消息签名并推进接收序列号：
// RoleClient 为服务端到客户端，RoleServer 为客户端到服务端。它要求已协商 FlagSign。版本、
// 序列号或校验和错误会失败关闭并清零会话。
func (s *SecuritySession) Verify(message, signature []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.readyLocked(FlagSign, ErrSigningNotNegotiated); err != nil {
		return err
	}
	if len(signature) != messageSignatureSize {
		s.failLocked()
		return errs.Detail(ErrSignature, "message signature is %d bytes, want %d | 消息签名为 %d 字节，期望 %d", len(signature), messageSignatureSize, len(signature), messageSignatureSize)
	}
	if version := binary.LittleEndian.Uint32(signature[0:4]); version != messageSignatureVersion {
		s.failLocked()
		return errs.Detail(ErrSignature, "message signature version %d is not supported | 不支持消息签名版本 %d", version, version)
	}
	sequence := binary.LittleEndian.Uint32(signature[12:16])
	if err := s.checkReceiveSequenceLocked(sequence); err != nil {
		return err
	}
	checksum := append([]byte(nil), signature[4:12]...)
	if s.flags.Has(FlagKeyExchange) {
		s.recvCipher.XORKeyStream(checksum, checksum)
	}
	expected := computeSigningChecksum(s.recvSigningKey, sequence, message)
	if !constantTimeEqual(checksum, expected) {
		s.failLocked()
		return errs.Detail(ErrSignature, "message checksum does not match | 消息校验和不匹配")
	}
	s.recvSequence++
	return nil
}

// Seal encrypts message with RC4 and returns ciphertext followed by the 16-byte
// MS-NLMP message signature. The send direction is client-to-server for
// RoleClient and server-to-client for RoleServer. It advances the send sequence
// and requires negotiated FlagSeal and FlagSign. | Seal 使用 RC4 加密 message，返回
// 密文后接 16 字节 MS-NLMP 消息签名。发送方向在 RoleClient 下为客户端到服务端，在
// RoleServer 下为服务端到客户端。它推进发送序列号并要求已协商 FlagSeal 与 FlagSign。
func (s *SecuritySession) Seal(message []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.readyLocked(FlagSeal, ErrSealingNotNegotiated); err != nil {
		return nil, err
	}
	sequence, err := s.nextSendSequenceLocked()
	if err != nil {
		return nil, err
	}
	sealed := make([]byte, len(message)+messageSignatureSize)
	s.sendCipher.XORKeyStream(sealed[:len(message)], message)
	checksum := computeSigningChecksum(s.sendSigningKey, sequence, message)
	if s.flags.Has(FlagKeyExchange) {
		s.sendCipher.XORKeyStream(checksum, checksum)
	}
	signature := sealed[len(message):]
	binary.LittleEndian.PutUint32(signature[0:4], messageSignatureVersion)
	copy(signature[4:12], checksum)
	binary.LittleEndian.PutUint32(signature[12:16], sequence)
	return sealed, nil
}

// Unseal decrypts a sealed message and verifies its trailing signature in
// constant time. The receive direction is server-to-client for RoleClient and
// client-to-server for RoleServer. It advances the receive sequence and requires
// negotiated FlagSeal and FlagSign. A wrong version, sequence number or checksum
// fails closed and wipes the session. | Unseal 解密密封消息并以常量时间校验其尾部签名。
// 接收方向在 RoleClient 下为服务端到客户端，在 RoleServer 下为客户端到服务端。它推进接收
// 序列号并要求已协商 FlagSeal 与 FlagSign。版本、序列号或校验和错误会失败关闭并清零会话。
func (s *SecuritySession) Unseal(sealed []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.readyLocked(FlagSeal, ErrSealingNotNegotiated); err != nil {
		return nil, err
	}
	if len(sealed) < messageSignatureSize {
		s.failLocked()
		return nil, errs.Detail(ErrSignature, "sealed message is %d bytes, want at least %d | 密封消息为 %d 字节，至少需要 %d", len(sealed), messageSignatureSize, len(sealed), messageSignatureSize)
	}
	signature := sealed[len(sealed)-messageSignatureSize:]
	if version := binary.LittleEndian.Uint32(signature[0:4]); version != messageSignatureVersion {
		s.failLocked()
		return nil, errs.Detail(ErrSignature, "message signature version %d is not supported | 不支持消息签名版本 %d", version, version)
	}
	sequence := binary.LittleEndian.Uint32(signature[12:16])
	if err := s.checkReceiveSequenceLocked(sequence); err != nil {
		return nil, err
	}
	message := make([]byte, len(sealed)-messageSignatureSize)
	s.recvCipher.XORKeyStream(message, sealed[:len(message)])
	checksum := append([]byte(nil), signature[4:12]...)
	if s.flags.Has(FlagKeyExchange) {
		s.recvCipher.XORKeyStream(checksum, checksum)
	}
	expected := computeSigningChecksum(s.recvSigningKey, sequence, message)
	if !constantTimeEqual(checksum, expected) {
		s.failLocked()
		return nil, errs.Detail(ErrSignature, "message checksum does not match | 消息校验和不匹配")
	}
	s.recvSequence++
	return message, nil
}

// Close wipes the derived keys and RC4 state. Close is idempotent and makes all
// later signing or sealing calls fail closed. | Close 清零派生密钥与 RC4 状态。Close
// 可重复调用，并使后续签名或密封调用失败关闭。
func (s *SecuritySession) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked()
	return nil
}

// readyLocked validates session state and the required negotiated flag. |
// readyLocked 校验会话状态与所需协商标志。
func (s *SecuritySession) readyLocked(required NegotiateFlags, missing error) error {
	if s.closed {
		return errs.Detail(ErrSessionSecurity, "security session is closed | 安全会话已关闭")
	}
	if !s.flags.Has(required) {
		return errs.Detail(missing, "negotiated flags do not include the required capability | 协商标志缺少所需能力")
	}
	return nil
}

// nextSendSequenceLocked returns the next send sequence number and advances the
// counter. Sequence exhaustion fails closed. | nextSendSequenceLocked 返回下一个
// 发送序列号并推进计数器。序列号耗尽会失败关闭。
func (s *SecuritySession) nextSendSequenceLocked() (uint32, error) {
	if s.sendSequence > maxSequenceNumber {
		s.failLocked()
		return 0, errs.Detail(ErrSequence, "send sequence is exhausted | 发送序列号已耗尽")
	}
	sequence := uint32(s.sendSequence)
	s.sendSequence++
	return sequence, nil
}

// checkReceiveSequenceLocked requires sequence to equal the next receive
// sequence. A mismatch fails closed. | checkReceiveSequenceLocked 要求 sequence
// 等于下一个接收序列号。不匹配会失败关闭。
func (s *SecuritySession) checkReceiveSequenceLocked(sequence uint32) error {
	if s.recvSequence > maxSequenceNumber {
		s.failLocked()
		return errs.Detail(ErrSequence, "receive sequence is exhausted | 接收序列号已耗尽")
	}
	expected := uint32(s.recvSequence)
	if sequence != expected {
		s.failLocked()
		return errs.Detail(ErrSequence, "message sequence %d does not match expected %d | 消息序列号 %d 与期望 %d 不匹配", sequence, expected, sequence, expected)
	}
	return nil
}

// failLocked wipes the session after a security failure. | failLocked 在安全失败后
// 清零会话。
func (s *SecuritySession) failLocked() {
	s.closeLocked()
}

// closeLocked wipes keys, cipher state and sequence counters. | closeLocked 清零
// 密钥、密码状态与序列号计数器。
func (s *SecuritySession) closeLocked() {
	if s.closed {
		return
	}
	s.closed = true
	if s.sendCipher != nil {
		*s.sendCipher = rc4.Cipher{}
		s.sendCipher = nil
	}
	if s.recvCipher != nil {
		*s.recvCipher = rc4.Cipher{}
		s.recvCipher = nil
	}
	if s.keys != nil {
		s.keys.Wipe()
		s.keys = nil
	}
	s.sendSigningKey = nil
	s.recvSigningKey = nil
	s.sendSealingKey = nil
	s.recvSealingKey = nil
	s.sendSequence = 0
	s.recvSequence = 0
}

// computeSigningChecksum returns the first eight bytes of
// HMAC-MD5(signingKey, LE32(sequence) || message). | computeSigningChecksum 返回
// HMAC-MD5(signingKey, LE32(sequence) || message) 的前八字节。
func computeSigningChecksum(signingKey []byte, sequence uint32, message []byte) []byte {
	mac := hmac.New(md5.New, signingKey)
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], sequence)
	_, _ = mac.Write(encoded[:])
	_, _ = mac.Write(message)
	sum := mac.Sum(nil)
	return sum[:checksumSize]
}
