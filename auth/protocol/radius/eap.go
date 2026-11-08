package radius

import (
	"context"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// EAPCode is the one-octet EAP packet code defined by RFC 3748 section 4. | EAPCode 是 RFC 3748
// 第 4 节定义的一字节 EAP 报文类型码。
type EAPCode uint8

// EAP packet codes. | EAP 报文类型码。
const (
	// EAPCodeRequest is an authenticator-to-peer Request. | EAPCodeRequest 是认证器到对端的 Request。
	EAPCodeRequest EAPCode = 1
	// EAPCodeResponse is a peer-to-authenticator Response. | EAPCodeResponse 是对端到认证器的 Response。
	EAPCodeResponse EAPCode = 2
	// EAPCodeSuccess reports successful authentication. | EAPCodeSuccess 表示认证成功。
	EAPCodeSuccess EAPCode = 3
	// EAPCodeFailure reports failed authentication. | EAPCodeFailure 表示认证失败。
	EAPCodeFailure EAPCode = 4
)

// EAPType is the EAP authentication method or special Request/Response type. | EAPType 是 EAP 认证
// 方法或特殊 Request/Response 类型。
type EAPType uint8

// EAP methods and special types. | EAP 方法与特殊类型。
const (
	// EAPTypeIdentity is the EAP Identity method. | EAPTypeIdentity 是 EAP Identity 方法。
	EAPTypeIdentity EAPType = 1
	// EAPTypeNotification is the EAP Notification method. | EAPTypeNotification 是 EAP Notification 方法。
	EAPTypeNotification EAPType = 2
	// EAPTypeNak is the legacy EAP Nak response. | EAPTypeNak 是传统 EAP Nak 响应。
	EAPTypeNak EAPType = 3
	// EAPTypeMD5 is EAP-MD5 (RFC 3748 section 5.4). | EAPTypeMD5 是 EAP-MD5（RFC 3748 第 5.4 节）。
	EAPTypeMD5 EAPType = 4
	// EAPTypeTLS is EAP-TLS (RFC 5216). | EAPTypeTLS 是 EAP-TLS（RFC 5216）。
	EAPTypeTLS EAPType = 13
	// EAPTypeTTLS is EAP-TTLS (RFC 5281). | EAPTypeTTLS 是 EAP-TTLS（RFC 5281）。
	EAPTypeTTLS EAPType = 21
	// EAPTypePEAP is PEAP version 0. | EAPTypePEAP 是 PEAP 版本 0。
	EAPTypePEAP EAPType = 25
	// EAPTypeMSCHAPv2 is EAP-MSCHAPv2 (RFC 2759 / draft-kamath-pppext-eap-mschapv2). |
	// EAPTypeMSCHAPv2 是 EAP-MSCHAPv2（RFC 2759 / draft-kamath-pppext-eap-mschapv2）。
	EAPTypeMSCHAPv2 EAPType = 26
	// EAPTypeExpanded is the Expanded Type method. | EAPTypeExpanded 是 Expanded Type 方法。
	EAPTypeExpanded EAPType = 254
)

// EAP packet limits. | EAP 报文限制。
const (
	// EAPHeaderLength is the EAP Code/Identifier/Length header size. | EAPHeaderLength 是 EAP
	// Code/Identifier/Length 头部长度。
	EAPHeaderLength = 4
	// MaxEAPPacketLength is the largest EAP packet length representable by the 16-bit Length field. |
	// MaxEAPPacketLength 是 16 位 Length 字段可表示的最大 EAP 报文长度。
	MaxEAPPacketLength = 65535
)

// EAPPacket is a decoded EAP packet. | EAPPacket 是已解码的 EAP 报文。
//
// Code, Identifier and Length are the fixed header. Type and Data are present for Request and
// Response packets; Success and Failure have neither. MarshalBinary derives Length from Type and
// Data, and UnmarshalBinary validates that the declared length matches the available bytes. | Code、
// Identifier 与 Length 构成固定头部。Request 与 Response 携带 Type 与 Data；Success 与 Failure
// 两者皆无。MarshalBinary 由 Type 与 Data 推导 Length，UnmarshalBinary 校验声明长度与可用字节一致。
type EAPPacket struct {
	// Data is the method data following Type. | Data 是 Type 之后的方法数据。
	Data []byte
	// Code is the EAP code. | Code 是 EAP 类型码。
	Code EAPCode
	// Identifier matches Requests with Responses and is echoed in Success and Failure. | Identifier
	// 用于匹配 Request 与 Response，并在 Success 与 Failure 中回显。
	Identifier uint8
	// Type is the method or special type for Request and Response packets. | Type 是 Request 与
	// Response 报文的方法或特殊类型。
	Type EAPType
	// Length is the declared packet length. MarshalBinary recomputes it. | Length 是声明的报文长度。
	// MarshalBinary 会重新计算它。
	Length uint16
}

// MarshalBinary encodes p to its RFC 3748 wire form. | MarshalBinary 将 p 编码为 RFC 3748 线格式。
func (p *EAPPacket) MarshalBinary() ([]byte, error) {
	if p == nil {
		return nil, errs.Detail(ErrInvalidPacket, "nil EAP packet")
	}
	if p.Code < EAPCodeRequest || p.Code > EAPCodeFailure {
		return nil, errs.Detail(ErrInvalidPacket, "EAP code %d is invalid", uint8(p.Code))
	}
	switch p.Code {
	case EAPCodeSuccess, EAPCodeFailure:
		if len(p.Data) != 0 {
			return nil, errs.Detail(ErrInvalidPacket, "EAP Success and Failure must not carry data")
		}
		return []byte{byte(p.Code), p.Identifier, 0, EAPHeaderLength}, nil
	default:
		if p.Type == 0 {
			return nil, errs.Detail(ErrInvalidPacket, "EAP Request and Response require a type")
		}
		length := EAPHeaderLength + 1 + len(p.Data)
		if length > MaxEAPPacketLength {
			return nil, errs.Detail(ErrInvalidPacket, "EAP packet length %d exceeds %d", length, MaxEAPPacketLength)
		}
		out := make([]byte, length)
		out[0] = byte(p.Code)
		out[1] = p.Identifier
		out[2] = byte(length >> 8)
		out[3] = byte(length)
		out[4] = byte(p.Type)
		copy(out[5:], p.Data)
		return out, nil
	}
}

// UnmarshalBinary decodes data into p. | UnmarshalBinary 从 data 解码到 p。
func (p *EAPPacket) UnmarshalBinary(data []byte) error {
	parsed, err := ParseEAPPacket(data)
	if err != nil {
		return err
	}
	*p = *parsed
	return nil
}

// ParseEAPPacket decodes and validates an EAP packet. | ParseEAPPacket 解码并校验 EAP 报文。
//
// The whole slice must be exactly one EAP packet: the declared Length must equal len(data), because
// RADIUS reassembly, not EAP, removes trailing padding. | 切片必须恰好包含一个 EAP 报文：声明 Length
// 必须等于 len(data)，因为去除尾部填充由 RADIUS 重组而非 EAP 完成。
func ParseEAPPacket(data []byte) (*EAPPacket, error) {
	if len(data) < EAPHeaderLength {
		return nil, errs.Detail(ErrInvalidPacket, "EAP packet length %d is below %d", len(data), EAPHeaderLength)
	}
	code := EAPCode(data[0])
	if code < EAPCodeRequest || code > EAPCodeFailure {
		return nil, errs.Detail(ErrInvalidPacket, "EAP code %d is invalid", uint8(code))
	}
	length := int(data[2])<<8 | int(data[3])
	if length != len(data) {
		return nil, errs.Detail(ErrInvalidPacket, "EAP declared length %d does not match received %d", length, len(data))
	}
	if length < EAPHeaderLength {
		return nil, errs.Detail(ErrInvalidPacket, "EAP length %d is below %d", length, EAPHeaderLength)
	}
	packet := &EAPPacket{
		Code:       code,
		Identifier: data[1],
		Length:     uint16(length),
	}
	if code == EAPCodeSuccess || code == EAPCodeFailure {
		if length != EAPHeaderLength {
			return nil, errs.Detail(ErrInvalidPacket, "EAP Success and Failure length %d must be %d", length, EAPHeaderLength)
		}
		return packet, nil
	}
	if length < EAPHeaderLength+1 {
		return nil, errs.Detail(ErrInvalidPacket, "EAP Request or Response length %d lacks a type", length)
	}
	packet.Type = EAPType(data[4])
	if packet.Type == 0 {
		return nil, errs.Detail(ErrInvalidPacket, "EAP Request or Response type 0 is reserved")
	}
	packet.Data = append([]byte(nil), data[5:]...)
	return packet, nil
}

// EAPPasswordLookup resolves a user password for EAP-MD5, EAP-MSCHAPv2 and inner EAP-TTLS or PEAP
// authentication. | EAPPasswordLookup 为 EAP-MD5、EAP-MSCHAPv2 以及 EAP-TTLS 或 PEAP 内部认证解析
// 用户口令。
//
// The returned slice is copied when necessary and zeroed by the caller after verification. Returning
// an error wrapping ErrEAPUnknownUser lets the EAP server emit the standard unknown-user failure
// without exposing lookup details. A lookup must be safe for concurrent use and should honor ctx. |
// 返回的切片在必要时会被复制，并在校验后由调用方清零。返回包装 ErrEAPUnknownUser 的错误可让 EAP
// 服务器发出标准未知用户失败而不泄露查找细节。查找必须可并发使用，并应响应 ctx。
type EAPPasswordLookup func(ctx context.Context, userName string) ([]byte, error)

// lookupEAPPassword invokes a password lookup and validates its result. | lookupEAPPassword 调用口令
// 查找并校验结果。
func lookupEAPPassword(ctx context.Context, lookup EAPPasswordLookup, userName string) ([]byte, error) {
	if lookup == nil {
		return nil, errs.Detail(ErrInvalidConfig, "EAP password lookup is required")
	}
	if strings.TrimSpace(userName) == "" {
		return nil, errs.Detail(ErrEAPUnknownUser, "empty user name")
	}
	password, err := lookup(ctx, userName)
	if err != nil {
		return nil, err
	}
	if password == nil {
		return nil, errs.Detail(ErrEAPUnknownUser, "no password for user %q", userName)
	}
	return append([]byte(nil), password...), nil
}

// SplitEAPMessage splits a complete EAP packet into values suitable for consecutive EAP-Message
// attributes. | SplitEAPMessage 将完整 EAP 报文拆分为适合连续 EAP-Message 属性的值。
//
// Every returned fragment is at most MaxAttributeValueLength octets. Concatenating the fragments in
// order reconstructs message exactly. maxFragment may lower the size for transports with a smaller
// MTU; it must be in [1,MaxAttributeValueLength]. | 每个返回片段最多 MaxAttributeValueLength 字节；
// 按序拼接可精确还原 message。maxFragment 可为更小 MTU 的传输调低大小；必须位于
// [1,MaxAttributeValueLength]。
func SplitEAPMessage(message []byte, maxFragment int) ([][]byte, error) {
	if len(message) == 0 {
		return nil, errs.Detail(ErrInvalidRequest, "EAP message must not be empty")
	}
	if len(message) > MaxEAPPacketLength {
		return nil, errs.Detail(ErrInvalidRequest, "EAP message length %d exceeds %d", len(message), MaxEAPPacketLength)
	}
	if maxFragment == 0 {
		maxFragment = MaxAttributeValueLength
	}
	if maxFragment < 1 || maxFragment > MaxAttributeValueLength {
		return nil, errs.Detail(ErrInvalidRequest, "EAP fragment size %d must be in [1,%d]", maxFragment, MaxAttributeValueLength)
	}
	fragments := make([][]byte, 0, (len(message)+maxFragment-1)/maxFragment)
	for offset := 0; offset < len(message); offset += maxFragment {
		end := offset + maxFragment
		if end > len(message) {
			end = len(message)
		}
		fragments = append(fragments, append([]byte(nil), message[offset:end]...))
	}
	return fragments, nil
}

// AppendEAPMessage appends message as one or more EAP-Message attributes. | AppendEAPMessage 将 message
// 追加为一个或多个 EAP-Message 属性。
//
// The fragments are appended in order; RADIUS reassembly concatenates their values. An invalid
// message or nil attributes returns ErrInvalidRequest. | 片段按序追加；RADIUS 重组会拼接它们的值。
// 非法 message 或 nil 属性返回 ErrInvalidRequest。
func AppendEAPMessage(attributes *Attributes, message []byte) error {
	if attributes == nil {
		return errs.Detail(ErrInvalidRequest, "attributes are nil")
	}
	fragments, err := SplitEAPMessage(message, MaxAttributeValueLength)
	if err != nil {
		return err
	}
	for _, fragment := range fragments {
		attributes.Add(AttrEAPMessage, fragment)
	}
	return nil
}

// ReassembleEAPMessages concatenates every EAP-Message attribute in wire order. | ReassembleEAPMessages
// 按线序拼接全部 EAP-Message 属性。
//
// It returns ErrInvalidRequest when no EAP-Message is present and ErrInvalidPacket when the combined
// length exceeds the EAP 16-bit limit. | 不存在 EAP-Message 时返回 ErrInvalidRequest；合并长度超过
// EAP 16 位上限时返回 ErrInvalidPacket。
func ReassembleEAPMessages(attributes Attributes) ([]byte, error) {
	values := attributes.GetAll(AttrEAPMessage)
	if len(values) == 0 {
		return nil, errs.Detail(ErrInvalidRequest, "no EAP-Message attribute")
	}
	total := 0
	for _, value := range values {
		total += len(value.Value)
	}
	if total > MaxEAPPacketLength {
		return nil, errs.Detail(ErrInvalidPacket, "reassembled EAP length %d exceeds %d", total, MaxEAPPacketLength)
	}
	out := make([]byte, 0, total)
	for _, value := range values {
		out = append(out, value.Value...)
	}
	return out, nil
}

// EAPResponseIdentity returns the identity carried by an EAP-Response/Identity packet, or an error
// when packet is another code or type. | EAPResponseIdentity 返回 EAP-Response/Identity 携带的身份，
// packet 为其它类型码或类型时返回错误。
func EAPResponseIdentity(packet *EAPPacket) (string, error) {
	if packet == nil {
		return "", errs.Detail(ErrInvalidRequest, "EAP packet is nil")
	}
	if packet.Code != EAPCodeResponse || packet.Type != EAPTypeIdentity {
		return "", errs.Detail(ErrInvalidRequest, "EAP packet is not a Response/Identity")
	}
	identity := strings.TrimSpace(string(packet.Data))
	if identity == "" {
		return "", errs.Detail(ErrInvalidRequest, "EAP identity is empty")
	}
	return identity, nil
}

// newEAPRequest builds a Request packet. | newEAPRequest 构建 Request 报文。
func newEAPRequest(identifier uint8, method EAPType, data []byte) *EAPPacket {
	return &EAPPacket{Code: EAPCodeRequest, Identifier: identifier, Type: method, Data: append([]byte(nil), data...)}
}

// newEAPResponse builds a Response packet. | newEAPResponse 构建 Response 报文。
func newEAPResponse(identifier uint8, method EAPType, data []byte) *EAPPacket {
	return &EAPPacket{Code: EAPCodeResponse, Identifier: identifier, Type: method, Data: append([]byte(nil), data...)}
}

// newEAPSuccess builds an EAP Success packet. | newEAPSuccess 构建 EAP Success 报文。
func newEAPSuccess(identifier uint8) *EAPPacket {
	return &EAPPacket{Code: EAPCodeSuccess, Identifier: identifier}
}

// newEAPFailure builds an EAP Failure packet. | newEAPFailure 构建 EAP Failure 报文。
func newEAPFailure(identifier uint8) *EAPPacket {
	return &EAPPacket{Code: EAPCodeFailure, Identifier: identifier}
}

// marshalEAPPacket encodes packet and returns its bytes. | marshalEAPPacket 编码 packet 并返回字节。
func marshalEAPPacket(packet *EAPPacket) ([]byte, error) {
	return packet.MarshalBinary()
}
