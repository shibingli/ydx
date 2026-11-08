package ntlm

import (
	"encoding/binary"
	"unicode/utf16"

	"github.com/shibingli/ydx/errs"
)

// Fixed wire sizes from MS-NLMP 2.2.1. | MS-NLMP 2.2.1 定义的固定线格式大小。
const (
	signatureSize      = 8
	messageTypeSize    = 4
	versionSize        = 8
	securityBufferSize = 8
	micSize            = 16
)

// securityBuffer is one MS-NLMP SECURITY_BUFFER field: length, allocated length
// and payload offset. | securityBuffer 是一个 MS-NLMP SECURITY_BUFFER 字段：长度、
// 分配长度与载荷偏移。
type securityBuffer struct {
	length    uint16
	maxLength uint16
	offset    uint32
}

// putSecurityBuffer writes the eight-byte field at offset. | putSecurityBuffer 在
// offset 处写入八字节字段。
func putSecurityBuffer(dst []byte, offset int, buffer securityBuffer) {
	binary.LittleEndian.PutUint16(dst[offset:offset+2], buffer.length)
	binary.LittleEndian.PutUint16(dst[offset+2:offset+4], buffer.maxLength)
	binary.LittleEndian.PutUint32(dst[offset+4:offset+8], buffer.offset)
}

// decodeSecurityBuffer reads one eight-byte field at offset. | decodeSecurityBuffer
// 在 offset 处读取一个八字节字段。
func decodeSecurityBuffer(data []byte, offset int) (securityBuffer, error) {
	if offset < 0 || offset+securityBufferSize > len(data) {
		return securityBuffer{}, errs.Detail(ErrMessage, "security buffer is truncated | 安全缓冲区被截断")
	}
	return securityBuffer{
		length:    binary.LittleEndian.Uint16(data[offset : offset+2]),
		maxLength: binary.LittleEndian.Uint16(data[offset+2 : offset+4]),
		offset:    binary.LittleEndian.Uint32(data[offset+4 : offset+8]),
	}, nil
}

// value resolves a security buffer against data and copies the payload. header
// is the fixed message header size; a non-empty payload must follow it. | value
// 基于 data 解析安全缓冲区并复制载荷。header 是固定消息头大小；非空载荷必须位于其后。
func (b securityBuffer) value(data []byte, header int) ([]byte, error) {
	if b.length == 0 {
		return nil, nil
	}
	if b.maxLength < b.length {
		return nil, errs.Detail(ErrMessage, "security buffer length %d exceeds maximum %d | 安全缓冲区长度 %d 超过上限 %d", b.length, b.maxLength, b.length, b.maxLength)
	}
	start := uint64(b.offset)
	end := start + uint64(b.length)
	if start < uint64(header) || end > uint64(len(data)) {
		return nil, errs.Detail(ErrMessage, "security buffer range [%d,%d) is outside the message | 安全缓冲区范围 [%d,%d) 超出消息", start, end, start, end)
	}
	out := make([]byte, b.length)
	copy(out, data[start:end])
	return out, nil
}

// takeString decodes a string field using the negotiated character set. | takeString
// 使用协商的字符集解码字符串字段。
func takeString(data []byte, unicode bool) (string, error) {
	if !unicode {
		return string(data), nil
	}
	if len(data)%2 != 0 {
		return "", errs.Detail(ErrMessage, "UTF-16LE string has odd length %d | UTF-16LE 字符串长度为奇数 %d", len(data), len(data))
	}
	units := make([]uint16, len(data)/2)
	for index := range units {
		units[index] = binary.LittleEndian.Uint16(data[index*2 : index*2+2])
	}
	return string(utf16.Decode(units)), nil
}

// encodeString encodes a string field using the negotiated character set. OEM
// strings are written as raw UTF-8 bytes because the OEM code page is not known
// to this client; Active Directory always negotiates Unicode. | encodeString 使用
// 协商的字符集编码字符串字段。由于本客户端不知道 OEM 代码页，OEM 字符串按原始 UTF-8
// 字节写入；Active Directory 总是协商 Unicode。
func encodeString(value string, unicode bool) []byte {
	if !unicode {
		return []byte(value)
	}
	units := utf16.Encode([]rune(value))
	out := make([]byte, len(units)*2)
	for index, unit := range units {
		binary.LittleEndian.PutUint16(out[index*2:index*2+2], unit)
	}
	return out
}

// checkMessage verifies the signature and message type. | checkMessage 校验签名与消息
// 类型。
func checkMessage(data []byte, want MessageType) error {
	if len(data) < signatureSize+messageTypeSize {
		return errs.Detail(ErrMessage, "message is shorter than its signature | 消息短于签名")
	}
	if string(data[:signatureSize]) != Signature {
		return errs.Detail(ErrMessage, "NTLMSSP signature mismatch | NTLMSSP 签名不匹配")
	}
	got := MessageType(binary.LittleEndian.Uint32(data[signatureSize : signatureSize+messageTypeSize]))
	if got != want {
		return errs.Detail(ErrMessage, "message type %d, want %d | 消息类型 %d，期望 %d", got, want, got, want)
	}
	return nil
}

// encodeVersion appends the eight-byte version field. | encodeVersion 追加八字节版本
// 字段。
func encodeVersion(dst []byte, version Version) []byte {
	return append(dst,
		version.Major,
		version.Minor,
		byte(version.Build),
		byte(version.Build>>8),
		0, 0, 0,
		version.Revision,
	)
}

// decodeVersion reads the eight-byte version field at offset. | decodeVersion 在
// offset 处读取八字节版本字段。
func decodeVersion(data []byte, offset int) (Version, error) {
	if offset < 0 || offset+versionSize > len(data) {
		return Version{}, errs.Detail(ErrMessage, "version field is truncated | 版本字段被截断")
	}
	return Version{
		Major:    data[offset],
		Minor:    data[offset+1],
		Build:    binary.LittleEndian.Uint16(data[offset+2 : offset+4]),
		Revision: data[offset+7],
	}, nil
}

// effectiveVersion returns the message version or the client default when the
// version flag is set. | effectiveVersion 在版本标志置位时返回消息版本或客户端默认版本。
func effectiveVersion(flags NegotiateFlags, version *Version) *Version {
	if !flags.Has(FlagVersion) {
		return nil
	}
	if version != nil {
		copied := *version
		return &copied
	}
	fallback := DefaultVersion()
	return &fallback
}

// NegotiateMessage is an NTLMSSP Type 1 NEGOTIATE_MESSAGE. | NegotiateMessage 是
// NTLMSSP Type 1 NEGOTIATE_MESSAGE。
type NegotiateMessage struct {
	// Version is encoded when Flags contains FlagVersion. A nil value selects
	// DefaultVersion. | 当 Flags 包含 FlagVersion 时编码；nil 选择 DefaultVersion。
	Version *Version
	// Domain is the optional domain name. | Domain 是可选的域名。
	Domain string
	// Workstation is the optional workstation name. | Workstation 是可选的工作站名称。
	Workstation string
	// Flags is the advertised negotiate-flag set. | Flags 是声明的协商标志集。
	Flags NegotiateFlags
}

// Encode serializes the Type 1 message. | Encode 序列化 Type 1 消息。
func (m *NegotiateMessage) Encode() ([]byte, error) {
	if m == nil {
		return nil, errs.Detail(ErrMessage, "negotiate message is nil | 协商消息为空")
	}
	if !m.Flags.Has(FlagUnicode) && !m.Flags.Has(FlagOEM) {
		return nil, errs.Detail(ErrMessage, "negotiate flags select neither Unicode nor OEM | 协商标志未选择 Unicode 或 OEM")
	}
	unicode := m.Flags.Has(FlagUnicode)
	domain := encodeString(m.Domain, unicode)
	workstation := encodeString(m.Workstation, unicode)
	if err := checkFieldSize("domain", domain); err != nil {
		return nil, err
	}
	if err := checkFieldSize("workstation", workstation); err != nil {
		return nil, err
	}
	header := 8 + 4 + 4 + securityBufferSize + securityBufferSize
	version := effectiveVersion(m.Flags, m.Version)
	if version != nil {
		header += versionSize
	}
	message := make([]byte, header, header+len(domain)+len(workstation))
	copy(message[:signatureSize], Signature)
	binary.LittleEndian.PutUint32(message[8:12], uint32(MessageTypeNegotiate))
	binary.LittleEndian.PutUint32(message[12:16], uint32(m.Flags))
	offset := uint32(header)
	domainBuffer := securityBuffer{length: uint16(len(domain)), maxLength: uint16(len(domain))}
	if len(domain) > 0 {
		domainBuffer.offset = offset
		offset += uint32(len(domain))
	}
	workstationBuffer := securityBuffer{length: uint16(len(workstation)), maxLength: uint16(len(workstation))}
	if len(workstation) > 0 {
		workstationBuffer.offset = offset
	}
	putSecurityBuffer(message, 16, domainBuffer)
	putSecurityBuffer(message, 24, workstationBuffer)
	if version != nil {
		copy(message[32:], encodeVersion(nil, *version))
	}
	message = append(message, domain...)
	message = append(message, workstation...)
	return message, nil
}

// DecodeNegotiate parses a Type 1 message. | DecodeNegotiate 解析 Type 1 消息。
func DecodeNegotiate(data []byte) (*NegotiateMessage, error) {
	if err := checkMessage(data, MessageTypeNegotiate); err != nil {
		return nil, err
	}
	const baseHeader = 8 + 4 + 4 + securityBufferSize + securityBufferSize
	if len(data) < baseHeader {
		return nil, errs.Detail(ErrMessage, "negotiate message is truncated | 协商消息被截断")
	}
	message := &NegotiateMessage{Flags: NegotiateFlags(binary.LittleEndian.Uint32(data[12:16]))}
	domainBuffer, err := decodeSecurityBuffer(data, 16)
	if err != nil {
		return nil, err
	}
	workstationBuffer, err := decodeSecurityBuffer(data, 24)
	if err != nil {
		return nil, err
	}
	header := baseHeader
	if message.Flags.Has(FlagVersion) {
		version, err := decodeVersion(data, baseHeader)
		if err != nil {
			return nil, err
		}
		message.Version = &version
		header += versionSize
	}
	unicode := message.Flags.Has(FlagUnicode)
	domain, err := domainBuffer.value(data, header)
	if err != nil {
		return nil, err
	}
	if message.Domain, err = takeString(domain, unicode); err != nil {
		return nil, err
	}
	workstation, err := workstationBuffer.value(data, header)
	if err != nil {
		return nil, err
	}
	if message.Workstation, err = takeString(workstation, unicode); err != nil {
		return nil, err
	}
	return message, nil
}

// checkFieldSize rejects payload fields that do not fit a security buffer. |
// checkFieldSize 拒绝无法放入安全缓冲区的载荷字段。
func checkFieldSize(name string, value []byte) error {
	if len(value) > 0xffff {
		return errs.Detail(ErrMessage, "%s field is %d bytes, maximum is 65535 | %s 字段为 %d 字节，上限为 65535", name, len(value), name, len(value))
	}
	return nil
}
