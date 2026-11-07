package ntlm

import (
	"encoding/binary"

	"github.com/shibingli/ydx/errs"
)

// authenticateBaseHeader is the Type 3 header size without version or MIC. |
// authenticateBaseHeader 是不含版本或 MIC 的 Type 3 头部大小。
const authenticateBaseHeader = 8 + 4 + 6*securityBufferSize + 4

// AuthenticateMessage is an NTLMSSP Type 3 AUTHENTICATE_MESSAGE. | AuthenticateMessage
// 是 NTLMSSP Type 3 AUTHENTICATE_MESSAGE。
type AuthenticateMessage struct {
	// LMResponse is the LM challenge response field. | LMResponse 是 LM 挑战响应字段。
	LMResponse []byte
	// NTResponse is the NT challenge response field. | NTResponse 是 NT 挑战响应字段。
	NTResponse []byte
	// Domain is the authentication domain. | Domain 是认证域。
	Domain string
	// Username is the authentication user name. | Username 是认证用户名。
	Username string
	// Workstation is the client workstation name. | Workstation 是客户端工作站名称。
	Workstation string
	// SessionKey is the encrypted random session key, unused by this client. |
	// SessionKey 是加密的随机会话密钥，本客户端不使用。
	SessionKey []byte
	// Flags is the negotiated flag set. | Flags 是协商标志集。
	Flags NegotiateFlags
	// Version is present when Flags contains FlagVersion. | 当 Flags 包含 FlagVersion
	// 时存在。
	Version *Version
	// MIC is the optional 16-byte message integrity code. A non-nil value must be
	// exactly 16 bytes. | MIC 是可选的 16 字节消息完整性代码。非 nil 值必须恰好 16 字节。
	MIC []byte
}

// Encode serializes the Type 3 message. When MIC is non-nil the message reserves
// the MIC field but writes the caller-provided bytes, so computing a MIC is a
// three-step operation: encode with a zeroed MIC, hash the encoded bytes, then
// set MIC and encode again. | Encode 序列化 Type 3 消息。当 MIC 非 nil 时消息保留 MIC
// 字段但写入调用方提供的字节，因此计算 MIC 需要三步：以零 MIC 编码、对编码字节做哈希、
// 再设置 MIC 并重新编码。
func (m *AuthenticateMessage) Encode() ([]byte, error) {
	if m == nil {
		return nil, errs.Detail(ErrMessage, "authenticate message is nil | 认证消息为空")
	}
	if !m.Flags.Has(FlagUnicode) && !m.Flags.Has(FlagOEM) {
		return nil, errs.Detail(ErrMessage, "authenticate flags select neither Unicode nor OEM | 认证标志未选择 Unicode 或 OEM")
	}
	if m.MIC != nil && len(m.MIC) != micSize {
		return nil, errs.Detail(ErrMessage, "MIC is %d bytes, want %d | MIC 为 %d 字节，期望 %d", len(m.MIC), micSize, len(m.MIC), micSize)
	}
	unicode := m.Flags.Has(FlagUnicode)
	domain := encodeString(m.Domain, unicode)
	username := encodeString(m.Username, unicode)
	workstation := encodeString(m.Workstation, unicode)
	fields := []struct {
		name  string
		value []byte
	}{
		{name: "LM response", value: m.LMResponse},
		{name: "NT response", value: m.NTResponse},
		{name: "domain", value: domain},
		{name: "user name", value: username},
		{name: "workstation", value: workstation},
		{name: "session key", value: m.SessionKey},
	}
	for _, field := range fields {
		if err := checkFieldSize(field.name, field.value); err != nil {
			return nil, err
		}
	}
	header := authenticateBaseHeader
	version := effectiveVersion(m.Flags, m.Version)
	if version != nil {
		header += versionSize
	}
	micOffset := -1
	if m.MIC != nil {
		micOffset = header
		header += micSize
	}
	total := header
	for _, field := range fields {
		total += len(field.value)
	}
	message := make([]byte, header, total)
	copy(message[:signatureSize], Signature)
	binary.LittleEndian.PutUint32(message[8:12], uint32(MessageTypeAuthenticate))
	offset := uint32(header)
	for index, field := range fields {
		buffer := securityBuffer{length: uint16(len(field.value)), maxLength: uint16(len(field.value))}
		if len(field.value) > 0 {
			buffer.offset = offset
			offset += uint32(len(field.value))
		}
		putSecurityBuffer(message, 12+index*securityBufferSize, buffer)
	}
	binary.LittleEndian.PutUint32(message[60:64], uint32(m.Flags))
	if version != nil {
		copy(message[64:], encodeVersion(nil, *version))
	}
	if micOffset >= 0 {
		copy(message[micOffset:micOffset+micSize], m.MIC)
	}
	for _, field := range fields {
		message = append(message, field.value...)
	}
	return message, nil
}

// DecodeAuthenticate parses a Type 3 message. MIC presence is inferred from the
// payload offsets: when every non-empty field starts at or after the header plus
// 16 bytes, the intervening bytes are treated as the MIC. | DecodeAuthenticate
// 解析 Type 3 消息。MIC 是否存在由载荷偏移推断：当所有非空字段都从头部加 16 字节之后
// 开始时，中间字节被视为 MIC。
func DecodeAuthenticate(data []byte) (*AuthenticateMessage, error) {
	if err := checkMessage(data, MessageTypeAuthenticate); err != nil {
		return nil, err
	}
	if len(data) < authenticateBaseHeader {
		return nil, errs.Detail(ErrMessage, "authenticate message is truncated | 认证消息被截断")
	}
	message := &AuthenticateMessage{Flags: NegotiateFlags(binary.LittleEndian.Uint32(data[60:64]))}
	buffers := make([]securityBuffer, 6)
	for index := range buffers {
		buffer, err := decodeSecurityBuffer(data, 12+index*securityBufferSize)
		if err != nil {
			return nil, err
		}
		buffers[index] = buffer
	}
	header := authenticateBaseHeader
	if message.Flags.Has(FlagVersion) {
		version, err := decodeVersion(data, authenticateBaseHeader)
		if err != nil {
			return nil, err
		}
		message.Version = &version
		header += versionSize
	}
	minimumOffset := len(data)
	for _, buffer := range buffers {
		if buffer.length > 0 && int(buffer.offset) < minimumOffset {
			minimumOffset = int(buffer.offset)
		}
	}
	if len(data) >= header+micSize && minimumOffset >= header+micSize {
		message.MIC = make([]byte, micSize)
		copy(message.MIC, data[header:header+micSize])
	}
	unicode := message.Flags.Has(FlagUnicode)
	values := make([][]byte, len(buffers))
	for index, buffer := range buffers {
		value, err := buffer.value(data, header)
		if err != nil {
			return nil, err
		}
		values[index] = value
	}
	message.LMResponse = values[0]
	message.NTResponse = values[1]
	domain, err := takeString(values[2], unicode)
	if err != nil {
		return nil, err
	}
	message.Domain = domain
	username, err := takeString(values[3], unicode)
	if err != nil {
		return nil, err
	}
	message.Username = username
	workstation, err := takeString(values[4], unicode)
	if err != nil {
		return nil, err
	}
	message.Workstation = workstation
	message.SessionKey = values[5]
	return message, nil
}
