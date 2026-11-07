package ntlm

import (
	"encoding/binary"

	"github.com/shibingli/ydx/errs"
)

// challengeBaseHeader is the Type 2 header size without a version field. |
// challengeBaseHeader 是不含版本字段的 Type 2 头部大小。
const challengeBaseHeader = 8 + 4 + 4 + 8 + 8 + securityBufferSize + securityBufferSize

// ChallengeMessage is an NTLMSSP Type 2 CHALLENGE_MESSAGE. | ChallengeMessage 是
// NTLMSSP Type 2 CHALLENGE_MESSAGE。
type ChallengeMessage struct {
	// Flags is the server negotiate-flag set. | Flags 是服务端协商标志集。
	Flags NegotiateFlags
	// ServerChallenge is the eight-byte server nonce. | ServerChallenge 是八字节服务端随机数。
	ServerChallenge [8]byte
	// TargetName is the optional target name. | TargetName 是可选的目标名称。
	TargetName string
	// TargetInfo holds the parsed AV pairs. | TargetInfo 保存解析后的 AV 对。
	TargetInfo TargetInfo
	// Version is present when Flags contains FlagVersion. | 当 Flags 包含 FlagVersion
	// 时存在。
	Version *Version
}

// Encode serializes the Type 2 message. It exists for servers, test fixtures and
// protocol tooling; production clients only decode challenges. | Encode 序列化
// Type 2 消息。它供服务端、测试夹具与协议工具使用；生产客户端只解码挑战。
func (m *ChallengeMessage) Encode() ([]byte, error) {
	if m == nil {
		return nil, errs.Detail(ErrMessage, "challenge message is nil | 挑战消息为空")
	}
	if !m.Flags.Has(FlagUnicode) && !m.Flags.Has(FlagOEM) {
		return nil, errs.Detail(ErrMessage, "challenge flags select neither Unicode nor OEM | 挑战标志未选择 Unicode 或 OEM")
	}
	unicode := m.Flags.Has(FlagUnicode)
	targetName := encodeString(m.TargetName, unicode)
	if err := checkFieldSize("target name", targetName); err != nil {
		return nil, err
	}
	info := m.TargetInfo
	if info != nil {
		if err := info.Validate(); err != nil {
			return nil, err
		}
	}
	targetInfo, err := info.Encode()
	if err != nil {
		return nil, err
	}
	header := challengeBaseHeader
	version := effectiveVersion(m.Flags, m.Version)
	if version != nil {
		header += versionSize
	}
	message := make([]byte, header, header+len(targetName)+len(targetInfo))
	copy(message[:signatureSize], Signature)
	binary.LittleEndian.PutUint32(message[8:12], uint32(MessageTypeChallenge))
	binary.LittleEndian.PutUint32(message[12:16], uint32(m.Flags))
	copy(message[16:24], m.ServerChallenge[:])
	offset := uint32(header)
	targetNameBuffer := securityBuffer{length: uint16(len(targetName)), maxLength: uint16(len(targetName))}
	if len(targetName) > 0 {
		targetNameBuffer.offset = offset
		offset += uint32(len(targetName))
	}
	targetInfoBuffer := securityBuffer{length: uint16(len(targetInfo)), maxLength: uint16(len(targetInfo))}
	if len(targetInfo) > 0 {
		targetInfoBuffer.offset = offset
	}
	putSecurityBuffer(message, 32, targetNameBuffer)
	putSecurityBuffer(message, 40, targetInfoBuffer)
	if version != nil {
		copy(message[48:], encodeVersion(nil, *version))
	}
	message = append(message, targetName...)
	message = append(message, targetInfo...)
	return message, nil
}

// DecodeChallenge parses a Type 2 message. | DecodeChallenge 解析 Type 2 消息。
func DecodeChallenge(data []byte) (*ChallengeMessage, error) {
	if err := checkMessage(data, MessageTypeChallenge); err != nil {
		return nil, err
	}
	if len(data) < challengeBaseHeader {
		return nil, errs.Detail(ErrMessage, "challenge message is truncated | 挑战消息被截断")
	}
	message := &ChallengeMessage{Flags: NegotiateFlags(binary.LittleEndian.Uint32(data[12:16]))}
	copy(message.ServerChallenge[:], data[16:24])
	targetNameBuffer, err := decodeSecurityBuffer(data, 32)
	if err != nil {
		return nil, err
	}
	targetInfoBuffer, err := decodeSecurityBuffer(data, 40)
	if err != nil {
		return nil, err
	}
	header := challengeBaseHeader
	if message.Flags.Has(FlagVersion) {
		version, err := decodeVersion(data, challengeBaseHeader)
		if err != nil {
			return nil, err
		}
		message.Version = &version
		header += versionSize
	}
	unicode := message.Flags.Has(FlagUnicode)
	targetName, err := targetNameBuffer.value(data, header)
	if err != nil {
		return nil, err
	}
	if message.TargetName, err = takeString(targetName, unicode); err != nil {
		return nil, err
	}
	targetInfo, err := targetInfoBuffer.value(data, header)
	if err != nil {
		return nil, err
	}
	if len(targetInfo) > 0 {
		if message.TargetInfo, err = ParseTargetInfo(targetInfo); err != nil {
			return nil, err
		}
	}
	return message, nil
}
