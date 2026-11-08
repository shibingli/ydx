package radius

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"

	"github.com/shibingli/ydx/errs"
)

// responseAuthenticator computes MD5(Code || Identifier || Length || Request Authenticator ||
// Attributes || Secret) over raw, substituting requestAuthenticator in the header. | responseAuthenticator
// 在 raw 上计算 MD5(Code || Identifier || Length || Request Authenticator || Attributes || Secret)，
// 并在头部替换为 requestAuthenticator。
func responseAuthenticator(raw, secret []byte, requestAuthenticator [16]byte) ([16]byte, error) {
	length, err := packetLength(raw)
	if err != nil {
		return [16]byte{}, err
	}
	buf := make([]byte, length)
	copy(buf, raw[:length])
	copy(buf[4:HeaderLength], requestAuthenticator[:])
	h := md5.New()
	h.Write(buf)
	h.Write(secret)
	var sum [16]byte
	h.Sum(sum[:0])
	return sum, nil
}

// applyResponseAuthenticator signs raw in place for a server response. The caller must place the
// Request Authenticator in the header and must have filled any Message-Authenticator value first. |
// applyResponseAuthenticator 就地签名服务器响应。调用方必须已将 Request Authenticator 放入头部，
// 并已先填入任何 Message-Authenticator 值。
func applyResponseAuthenticator(raw, secret []byte) error {
	length, err := packetLength(raw)
	if err != nil {
		return err
	}
	h := md5.New()
	h.Write(raw[:length])
	h.Write(secret)
	var sum [16]byte
	h.Sum(sum[:0])
	copy(raw[4:HeaderLength], sum[:])
	return nil
}

// verifyResponseAuthenticator checks a received response against its Request Authenticator. | verifyResponseAuthenticator
// 使用对应的 Request Authenticator 校验收到的响应。
func verifyResponseAuthenticator(raw, secret []byte, requestAuthenticator [16]byte) error {
	if len(raw) < HeaderLength {
		return errs.Detail(ErrInvalidResponse, "response length %d is below %d", len(raw), HeaderLength)
	}
	var received [16]byte
	copy(received[:], raw[4:HeaderLength])
	expected, err := responseAuthenticator(raw, secret, requestAuthenticator)
	if err != nil {
		return err
	}
	if !constantTimeEqual(received[:], expected[:]) {
		return errs.Detail(ErrAuthenticator, "response authenticator mismatch for code %d identifier %d", raw[0], raw[1])
	}
	return nil
}

// accountingRequestAuthenticator computes the RFC 2866 Request Authenticator over raw, whose
// authenticator field is ignored and treated as sixteen zero octets. | accountingRequestAuthenticator
// 在 raw 上计算 RFC 2866 Request Authenticator，其认证符字段被忽略并按 16 个零字节处理。
func accountingRequestAuthenticator(raw, secret []byte) ([16]byte, error) {
	length, err := packetLength(raw)
	if err != nil {
		return [16]byte{}, err
	}
	buf := make([]byte, length)
	copy(buf, raw[:length])
	for i := 4; i < HeaderLength; i++ {
		buf[i] = 0
	}
	h := md5.New()
	h.Write(buf)
	h.Write(secret)
	var sum [16]byte
	h.Sum(sum[:0])
	return sum, nil
}

// verifyAccountingRequestAuthenticator checks an Accounting-Request authenticator. | verifyAccountingRequestAuthenticator
// 校验 Accounting-Request 认证符。
func verifyAccountingRequestAuthenticator(raw, secret []byte) error {
	if len(raw) < HeaderLength {
		return errs.Detail(ErrInvalidPacket, "request length %d is below %d", len(raw), HeaderLength)
	}
	expected, err := accountingRequestAuthenticator(raw, secret)
	if err != nil {
		return err
	}
	var received [16]byte
	copy(received[:], raw[4:HeaderLength])
	if !constantTimeEqual(received[:], expected[:]) {
		return errs.Detail(ErrAuthenticator, "accounting request authenticator mismatch")
	}
	return nil
}

// signMessageAuthenticator fills the single Message-Authenticator attribute of raw in place. The
// authenticator field must already contain the Request Authenticator. | signMessageAuthenticator
// 就地填入 raw 中唯一的 Message-Authenticator 属性。认证符字段必须已包含 Request Authenticator。
func signMessageAuthenticator(raw, secret []byte, requestAuthenticator [16]byte) error {
	offsets, err := messageAuthenticatorOffsets(raw)
	if err != nil {
		return err
	}
	if len(offsets) != 1 {
		return errs.Detail(ErrMessageAuthenticator, "expected one Message-Authenticator, found %d", len(offsets))
	}
	sum, err := computeMessageAuthenticator(raw, secret, requestAuthenticator, offsets)
	if err != nil {
		return err
	}
	copy(raw[offsets[0]:offsets[0]+16], sum[:])
	return nil
}

// signDynamicRequest fills the RFC 5176 Request Authenticator of a CoA-Request or
// Disconnect-Request in place. When messageAuthenticator is true the raw packet must already carry
// one zeroed Message-Authenticator attribute, which is signed first because RFC 5176 section 3.4
// inserts it before the Request Authenticator is calculated. The packet must be marshaled with a
// zero Authenticator field. | signDynamicRequest 就地填入 CoA-Request 或 Disconnect-Request 的
// RFC 5176 Request Authenticator。当 messageAuthenticator 为真时，原始报文必须已携带一个置零的
// Message-Authenticator 属性；由于 RFC 5176 第 3.4 节要求先插入它再计算 Request Authenticator，
// 因此先对其签名。报文必须以全零 Authenticator 字段编码。
func signDynamicRequest(raw, secret []byte, messageAuthenticator bool) ([16]byte, error) {
	var requestAuthenticator [16]byte
	if messageAuthenticator {
		offsets, err := messageAuthenticatorOffsets(raw)
		if err != nil {
			return requestAuthenticator, err
		}
		if len(offsets) != 1 {
			return requestAuthenticator, errs.Detail(ErrMessageAuthenticator, "expected one Message-Authenticator, found %d", len(offsets))
		}
		sum, err := computeMessageAuthenticator(raw, secret, requestAuthenticator, offsets)
		if err != nil {
			return requestAuthenticator, err
		}
		copy(raw[offsets[0]:offsets[0]+16], sum[:])
	}
	authenticator, err := accountingRequestAuthenticator(raw, secret)
	if err != nil {
		return requestAuthenticator, err
	}
	copy(raw[4:HeaderLength], authenticator[:])
	return authenticator, nil
}

// verifyMessageAuthenticatorRaw validates the Message-Authenticator of raw. It reports whether the
// attribute is present and, when present, whether it matches. | verifyMessageAuthenticatorRaw 校验
// raw 的 Message-Authenticator。它报告属性是否存在，以及存在时是否匹配。
func verifyMessageAuthenticatorRaw(raw, secret []byte, requestAuthenticator [16]byte) (present, valid bool, err error) {
	offsets, err := messageAuthenticatorOffsets(raw)
	if err != nil {
		return false, false, err
	}
	if len(offsets) == 0 {
		return false, false, nil
	}
	var received [16]byte
	copy(received[:], raw[offsets[0]:offsets[0]+16])
	expected, err := computeMessageAuthenticator(raw, secret, requestAuthenticator, offsets)
	if err != nil {
		return true, false, err
	}
	return true, constantTimeEqual(received[:], expected[:]), nil
}

// verifyRequiredResponseMessageAuthenticator enforces the RFC 3579 section 3.2 and RFC 5176
// section 3.4 rule that a response must carry a valid Message-Authenticator when the request carried
// one. A missing or mismatching value returns an error wrapping ErrMessageAuthenticator, which UDP
// read paths silently discard while stream transports fail the attempt and close the connection. |
// verifyRequiredResponseMessageAuthenticator 强制执行 RFC 3579 第 3.2 节与 RFC 5176 第 3.4 节的
// 规则：请求携带 Message-Authenticator 时，响应必须携带合法值。缺失或不匹配会返回包装
// ErrMessageAuthenticator 的错误；UDP 读取路径会静默丢弃该候选，流传输则让本次尝试失败并关闭连接。
func verifyRequiredResponseMessageAuthenticator(raw, secret []byte, requestAuthenticator [16]byte) error {
	present, valid, err := verifyMessageAuthenticatorRaw(raw, secret, requestAuthenticator)
	if err != nil {
		return errs.Wrap(err, ErrInvalidResponse)
	}
	if !present {
		return errs.Detail(ErrMessageAuthenticator, "response lacks the required Message-Authenticator")
	}
	if !valid {
		return errs.Detail(ErrMessageAuthenticator, "response Message-Authenticator mismatch")
	}
	return nil
}

// computeMessageAuthenticator returns HMAC-MD5 over raw with the Request Authenticator in the
// header and every Message-Authenticator value zeroed. | computeMessageAuthenticator 返回 raw 的
// HMAC-MD5：头部使用 Request Authenticator，所有 Message-Authenticator 值置零。
func computeMessageAuthenticator(raw, secret []byte, requestAuthenticator [16]byte, offsets []int) ([16]byte, error) {
	length, err := packetLength(raw)
	if err != nil {
		return [16]byte{}, err
	}
	buf := make([]byte, length)
	copy(buf, raw[:length])
	copy(buf[4:HeaderLength], requestAuthenticator[:])
	for _, offset := range offsets {
		for i := 0; i < 16; i++ {
			buf[offset+i] = 0
		}
	}
	h := hmac.New(md5.New, secret)
	h.Write(buf)
	var sum [16]byte
	h.Sum(sum[:0])
	return sum, nil
}

// messageAuthenticatorOffsets returns the value offsets of Message-Authenticator attributes. | messageAuthenticatorOffsets
// 返回 Message-Authenticator 属性的值偏移。
func messageAuthenticatorOffsets(raw []byte) ([]int, error) {
	length, err := packetLength(raw)
	if err != nil {
		return nil, err
	}
	var offsets []int
	for offset := HeaderLength; offset < length; {
		if length-offset < 2 {
			return nil, errs.Detail(ErrInvalidAttribute, "truncated attribute header at offset %d", offset)
		}
		t := AttributeType(raw[offset])
		attributeLength := int(raw[offset+1])
		if t == 0 {
			return nil, errs.Detail(ErrInvalidAttribute, "attribute type 0 is reserved")
		}
		if attributeLength < 2 || attributeLength > length-offset {
			return nil, errs.Detail(ErrInvalidAttribute, "attribute %d has invalid length %d", uint8(t), attributeLength)
		}
		if t == AttrMessageAuthenticator {
			if attributeLength != 18 {
				return nil, errs.Detail(ErrInvalidAttribute, "Message-Authenticator length %d must be 18", attributeLength)
			}
			offsets = append(offsets, offset+2)
			if len(offsets) > 1 {
				return nil, errs.Detail(ErrInvalidAttribute, "duplicate Message-Authenticator attribute")
			}
		}
		offset += attributeLength
	}
	return offsets, nil
}

// packetLength validates the header length field of a raw packet and returns it. | packetLength
// 校验原始报文的头部长度字段并返回它。
func packetLength(raw []byte) (int, error) {
	if len(raw) < HeaderLength {
		return 0, errs.Detail(ErrInvalidPacket, "packet length %d is below %d", len(raw), HeaderLength)
	}
	length := int(binary.BigEndian.Uint16(raw[2:4]))
	if length < HeaderLength {
		return 0, errs.Detail(ErrInvalidPacket, "declared length %d is below %d", length, HeaderLength)
	}
	if length > MaxPacketLength {
		return 0, errs.Detail(ErrInvalidPacket, "declared length %d exceeds %d", length, MaxPacketLength)
	}
	if length > len(raw) {
		return 0, errs.Detail(ErrInvalidPacket, "declared length %d exceeds received %d", length, len(raw))
	}
	return length, nil
}
