package kerberos

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/subtle"
	"encoding/binary"

	"github.com/shibingli/ydx/errs"
)

// gssMessageContext holds the key and sequence state of one established GSS
// context. | gssMessageContext 保存一个已建立 GSS 上下文的密钥与序列状态。
type gssMessageContext struct {
	key            EncryptionKey
	sendAcceptor   bool
	acceptorSubkey bool
	sendSeq        uint64
	recvSeq        uint64
}

// wrap produces an RFC 4121 WRAP token, or an RFC 1964/4757 token for
// rc4-hmac. | wrap 生成 RFC 4121 WRAP 令牌；rc4-hmac 使用 RFC 1964/4757 令牌。
func (m *gssMessageContext) wrap(data []byte, confidential bool) ([]byte, error) {
	if m == nil {
		return nil, errs.Detail(ErrGSSAPI, "nil GSS context | GSS 上下文为空")
	}
	if m.key.KeyType == ETypeRC4HMAC {
		return m.wrapLegacy(data, confidential)
	}
	usage := gssSealingUsage(m.sendAcceptor)
	flags := byte(0)
	if m.sendAcceptor {
		flags |= gssTokenFlagSentByAcceptor
	}
	if m.acceptorSubkey {
		flags |= gssTokenFlagAcceptorSubkey
	}
	sequence := m.sendSeq
	if confidential {
		flags |= gssTokenFlagSealed
		filler := gssWrapFiller(len(data))
		innerHeader := gssWrapHeader(flags, uint16(filler), 0, sequence)
		plaintext := make([]byte, 0, len(data)+filler+len(innerHeader))
		plaintext = append(plaintext, data...)
		for i := 0; i < filler; i++ {
			plaintext = append(plaintext, 0xFF)
		}
		plaintext = append(plaintext, innerHeader...)
		ciphertext, err := EncryptMessage(m.key.KeyType, m.key.KeyValue, usage, plaintext)
		if err != nil {
			return nil, err
		}
		token := make([]byte, 0, 16+len(ciphertext))
		token = append(token, gssWrapHeader(flags, uint16(filler), 0, sequence)...)
		token = append(token, ciphertext...)
		m.sendSeq++
		return token, nil
	}
	zeroHeader := gssWrapHeader(flags, 0, 0, sequence)
	checksum, err := ChecksumMessage(m.key.KeyType, m.key.KeyValue, usage, append(append([]byte(nil), data...), zeroHeader...))
	if err != nil {
		return nil, err
	}
	token := make([]byte, 0, 16+len(data)+len(checksum))
	token = append(token, gssWrapHeader(flags, uint16(len(checksum)), 0, sequence)...)
	token = append(token, data...)
	token = append(token, checksum...)
	m.sendSeq++
	return token, nil
}

// unwrap verifies and opens an RFC 4121 WRAP token, or the legacy form for
// rc4-hmac. It reports whether the payload was confidential. | unwrap 校验并解包
// RFC 4121 WRAP 令牌，rc4-hmac 使用传统格式。它报告载荷是否受机密性保护。
func (m *gssMessageContext) unwrap(token []byte) ([]byte, bool, error) {
	if m == nil {
		return nil, false, errs.Detail(ErrGSSAPI, "nil GSS context | GSS 上下文为空")
	}
	if m.key.KeyType == ETypeRC4HMAC {
		return m.unwrapLegacy(token)
	}
	if len(token) < 16 {
		return nil, false, errs.Detail(ErrGSSAPI, "WRAP token is %d bytes, minimum 16 | WRAP 令牌为 %d 字节，至少 16", len(token), len(token))
	}
	if binary.BigEndian.Uint16(token) != gssTokenWrap {
		return nil, false, errs.Detail(ErrGSSAPI, "unexpected WRAP TOK_ID 0x%04x | 意外的 WRAP TOK_ID 0x%04x",
			binary.BigEndian.Uint16(token), binary.BigEndian.Uint16(token))
	}
	flags := token[2]
	if err := m.checkPeerFlags(flags, m.acceptorSubkey); err != nil {
		return nil, false, err
	}
	if token[3] != 0xFF {
		return nil, false, errs.Detail(ErrGSSAPI, "invalid WRAP filler 0x%02x | 非法 WRAP 填充值 0x%02x", token[3], token[3])
	}
	ec := binary.BigEndian.Uint16(token[4:6])
	rrc := binary.BigEndian.Uint16(token[6:8])
	sequence := binary.BigEndian.Uint64(token[8:16])
	body := rotateLeft(token[16:], int(rrc))
	sealed := flags&gssTokenFlagSealed != 0
	var headerForChecksum []byte
	usage := gssSealingUsage(!m.sendAcceptor)
	if sealed {
		plaintext, err := DecryptMessage(m.key.KeyType, m.key.KeyValue, usage, body)
		if err != nil {
			return nil, false, err
		}
		if len(plaintext) < 16 || len(plaintext) < int(ec)+16 {
			return nil, false, errs.Detail(ErrGSSAPI, "confidential WRAP plaintext is %d bytes | 机密 WRAP 明文为 %d 字节", len(plaintext), len(plaintext))
		}
		innerHeader := plaintext[len(plaintext)-16:]
		headerForChecksum = gssWrapHeader(flags, ec, 0, sequence)
		if subtle.ConstantTimeCompare(innerHeader, headerForChecksum) != 1 {
			return nil, false, errs.Detail(ErrBadIntegrity, "confidential WRAP header copy mismatch | 机密 WRAP 头副本不匹配")
		}
		filler := int(ec)
		dataEnd := len(plaintext) - 16 - filler
		if dataEnd < 0 {
			return nil, false, errs.Detail(ErrGSSAPI, "confidential WRAP filler %d exceeds plaintext | 机密 WRAP 填充 %d 超过明文长度", filler, filler)
		}
		for _, b := range plaintext[dataEnd : len(plaintext)-16] {
			if b != 0xFF {
				return nil, false, errs.Detail(ErrGSSAPI, "confidential WRAP filler is not 0xFF | 机密 WRAP 填充不是 0xFF")
			}
		}
		if err := m.acceptSequence(sequence); err != nil {
			return nil, false, err
		}
		return append([]byte(nil), plaintext[:dataEnd]...), true, nil
	}
	if int(ec) == 0 || int(ec) > len(body) {
		return nil, false, errs.Detail(ErrGSSAPI, "WRAP checksum length %d does not fit %d bytes | WRAP 校验和长度 %d 不适合 %d 字节", ec, ec, len(body), len(body))
	}
	data := body[:len(body)-int(ec)]
	checksum := body[len(body)-int(ec):]
	headerForChecksum = gssWrapHeader(flags, 0, 0, sequence)
	expected, err := ChecksumMessage(m.key.KeyType, m.key.KeyValue, usage, append(append([]byte(nil), data...), headerForChecksum...))
	if err != nil {
		return nil, false, err
	}
	if subtle.ConstantTimeCompare(expected, checksum) != 1 {
		return nil, false, errs.Detail(ErrBadIntegrity, "WRAP checksum mismatch | WRAP 校验和不匹配")
	}
	if err := m.acceptSequence(sequence); err != nil {
		return nil, false, err
	}
	return append([]byte(nil), data...), false, nil
}

// mic produces an RFC 4121 MIC token, or the legacy form for rc4-hmac. | mic 生成
// RFC 4121 MIC 令牌；rc4-hmac 使用传统格式。
func (m *gssMessageContext) mic(data []byte) ([]byte, error) {
	if m == nil {
		return nil, errs.Detail(ErrGSSAPI, "nil GSS context | GSS 上下文为空")
	}
	if m.key.KeyType == ETypeRC4HMAC {
		return m.micLegacy(data)
	}
	flags := byte(0)
	if m.sendAcceptor {
		flags |= gssTokenFlagSentByAcceptor
	}
	if m.acceptorSubkey {
		flags |= gssTokenFlagAcceptorSubkey
	}
	sequence := m.sendSeq
	header := []byte{gssTokenMIC >> 8, gssTokenMIC & 0xFF, flags, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint64(header[8:], sequence)
	checksum, err := ChecksumMessage(m.key.KeyType, m.key.KeyValue, gssMICUsage(m.sendAcceptor), append(append([]byte(nil), data...), header...))
	if err != nil {
		return nil, err
	}
	token := make([]byte, 0, len(header)+len(checksum))
	token = append(token, header...)
	token = append(token, checksum...)
	m.sendSeq++
	return token, nil
}

// verifyMIC verifies an RFC 4121 MIC token, or the legacy form for rc4-hmac. |
// verifyMIC 校验 RFC 4121 MIC 令牌，rc4-hmac 使用传统格式。
func (m *gssMessageContext) verifyMIC(data, token []byte) error {
	if m == nil {
		return errs.Detail(ErrGSSAPI, "nil GSS context | GSS 上下文为空")
	}
	if m.key.KeyType == ETypeRC4HMAC {
		return m.verifyMICLegacy(data, token)
	}
	if len(token) < 16 {
		return errs.Detail(ErrGSSAPI, "MIC token is %d bytes, minimum 16 | MIC 令牌为 %d 字节，至少 16", len(token), len(token))
	}
	if binary.BigEndian.Uint16(token) != gssTokenMIC {
		return errs.Detail(ErrGSSAPI, "unexpected MIC TOK_ID 0x%04x | 意外的 MIC TOK_ID 0x%04x",
			binary.BigEndian.Uint16(token), binary.BigEndian.Uint16(token))
	}
	flags := token[2]
	if err := m.checkPeerFlags(flags, m.acceptorSubkey); err != nil {
		return err
	}
	for i := 3; i < 8; i++ {
		if token[i] != 0xFF {
			return errs.Detail(ErrGSSAPI, "invalid MIC filler | 非法 MIC 填充")
		}
	}
	sequence := binary.BigEndian.Uint64(token[8:16])
	header := append([]byte(nil), token[:16]...)
	expected, err := ChecksumMessage(m.key.KeyType, m.key.KeyValue, gssMICUsage(!m.sendAcceptor), append(append([]byte(nil), data...), header...))
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(expected, token[16:]) != 1 {
		return errs.Detail(ErrBadIntegrity, "MIC checksum mismatch | MIC 校验和不匹配")
	}
	return m.acceptSequence(sequence)
}

// checkPeerFlags validates direction and subkey flags of an incoming token. |
// checkPeerFlags 校验入站令牌的方向与子密钥标志。
func (m *gssMessageContext) checkPeerFlags(flags byte, expectAcceptorSubkey bool) error {
	sentByAcceptor := flags&gssTokenFlagSentByAcceptor != 0
	if sentByAcceptor == m.sendAcceptor {
		return errs.Detail(ErrGSSAPI, "token direction flag does not match the peer | 令牌方向标志与对端不匹配")
	}
	acceptorSubkey := flags&gssTokenFlagAcceptorSubkey != 0
	if acceptorSubkey != expectAcceptorSubkey {
		return errs.Detail(ErrGSSAPI, "token subkey flag does not match the selected key | 令牌子密钥标志与所选密钥不匹配")
	}
	return nil
}

// acceptSequence validates and advances the incoming sequence number. | acceptSequence
// 校验并推进入站序列号。
func (m *gssMessageContext) acceptSequence(sequence uint64) error {
	if sequence < m.recvSeq {
		return errs.Detail(ErrSequence, "GSS sequence %d is older than expected %d | GSS 序列 %d 早于期望值 %d",
			sequence, m.recvSeq, sequence, m.recvSeq)
	}
	m.recvSeq = sequence + 1
	return nil
}

// gssWrapHeader builds the 16-byte RFC 4121 WRAP token header. | gssWrapHeader 构建
// 16 字节 RFC 4121 WRAP 令牌头。
func gssWrapHeader(flags byte, ec, rrc uint16, sequence uint64) []byte {
	header := make([]byte, 16)
	binary.BigEndian.PutUint16(header, gssTokenWrap)
	header[2] = flags
	header[3] = 0xFF
	binary.BigEndian.PutUint16(header[4:6], ec)
	binary.BigEndian.PutUint16(header[6:8], rrc)
	binary.BigEndian.PutUint64(header[8:16], sequence)
	return header
}

// gssWrapFiller returns the number of confidentiality filler octets required
// for an AES CTS ciphertext to have no residue. | gssWrapFiller 返回使 AES CTS 密文
// 无残留所需的机密性填充字节数。
func gssWrapFiller(size int) int {
	if remainder := size % aesBlockSize; remainder != 0 {
		return aesBlockSize - remainder
	}
	return 0
}

// rotateRight rotates data right by shift octets. | rotateRight 把 data 右旋 shift 字节。
func rotateRight(data []byte, shift int) []byte {
	if len(data) == 0 {
		return data
	}
	shift %= len(data)
	if shift == 0 {
		return data
	}
	out := make([]byte, len(data))
	copy(out[shift:], data[:len(data)-shift])
	copy(out[:shift], data[len(data)-shift:])
	return out
}

// rotateLeft rotates data left by shift octets. | rotateLeft 把 data 左旋 shift 字节。
func rotateLeft(data []byte, shift int) []byte {
	if len(data) == 0 {
		return data
	}
	shift %= len(data)
	if shift == 0 {
		return data
	}
	out := make([]byte, len(data))
	copy(out[:len(data)-shift], data[shift:])
	copy(out[len(data)-shift:], data[:shift])
	return out
}

// legacyMICHeader is the RFC 1964/4757 MIC header. | legacyMICHeader 是 RFC 1964/4757
// MIC 头。
var legacyMICHeader = []byte{0x01, 0x01, 0x11, 0x00, 0xFF, 0xFF, 0xFF, 0xFF}

// legacyWrapHeaderPrefix is the RFC 1964/4757 WRAP header prefix published before
// the seal algorithm. | legacyWrapHeaderPrefix 是 RFC 1964/4757 WRAP 头中密封算法之前
// 的前缀。
var legacyWrapHeaderPrefix = []byte{0x02, 0x01, 0x11, 0x00}

// legacySealNone and legacySealRC4 are the RFC 1964/4757 SEAL_ALG values. |
// legacySealNone 与 legacySealRC4 是 RFC 1964/4757 的 SEAL_ALG 值。
const (
	legacySealNone = 0xFFFF
	legacySealRC4  = 0x1000
)

// micLegacy produces an RFC 4757 MIC token. | micLegacy 生成 RFC 4757 MIC 令牌。
func (m *gssMessageContext) micLegacy(data []byte) ([]byte, error) {
	sequence := m.sendSeq
	checksum := rc4Checksum(m.key.KeyValue, 15, append(append([]byte(nil), legacyMICHeader...), data...))[:8]
	encryptedSequence := legacyEncryptSequence(m.key.KeyValue, checksum, sequence, m.sendAcceptor)
	token := make([]byte, 0, 8+8+len(checksum))
	token = append(token, legacyMICHeader...)
	token = append(token, encryptedSequence...)
	token = append(token, checksum...)
	m.sendSeq++
	return token, nil
}

// verifyMICLegacy verifies an RFC 4757 MIC token. | verifyMICLegacy 校验 RFC 4757 MIC 令牌。
func (m *gssMessageContext) verifyMICLegacy(data, token []byte) error {
	if len(token) < 24 {
		return errs.Detail(ErrGSSAPI, "legacy MIC token is %d bytes, minimum 24 | 传统 MIC 令牌为 %d 字节，至少 24", len(token), len(token))
	}
	if subtle.ConstantTimeCompare(token[:8], legacyMICHeader) != 1 {
		return errs.Detail(ErrGSSAPI, "invalid legacy MIC header | 非法传统 MIC 头")
	}
	checksum := token[16:24]
	sequence, err := legacyDecryptSequence(m.key.KeyValue, checksum, token[8:16], !m.sendAcceptor)
	if err != nil {
		return err
	}
	expected := rc4Checksum(m.key.KeyValue, 15, append(append([]byte(nil), legacyMICHeader...), data...))[:8]
	if subtle.ConstantTimeCompare(expected, checksum) != 1 {
		return errs.Detail(ErrBadIntegrity, "legacy MIC checksum mismatch | 传统 MIC 校验和不匹配")
	}
	return m.acceptSequence(sequence)
}

// wrapLegacy produces an RFC 4757 WRAP token. | wrapLegacy 生成 RFC 4757 WRAP 令牌。
func (m *gssMessageContext) wrapLegacy(data []byte, confidential bool) ([]byte, error) {
	sequence := m.sendSeq
	sealAlgorithm := uint16(legacySealNone)
	if confidential {
		sealAlgorithm = legacySealRC4
	}
	header := make([]byte, 8)
	copy(header, legacyWrapHeaderPrefix)
	binary.BigEndian.PutUint16(header[4:6], sealAlgorithm)
	header[6], header[7] = 0xFF, 0xFF
	confounder := make([]byte, rc4ConfounderSize)
	if _, err := rand.Read(confounder); err != nil {
		return nil, errs.WrapDetail(err, ErrRandom, "GSS confounder generation failed | GSS 混淆值生成失败")
	}
	padded := make([]byte, 0, len(data)+1)
	padded = append(padded, data...)
	padded = append(padded, 1)
	first := md5.New()
	_, _ = first.Write(rc4UsageBytes(15))
	_, _ = first.Write(header)
	_, _ = first.Write(confounder)
	second := md5.New()
	_, _ = second.Write(padded)
	signingKey := rc4HMAC(m.key.KeyValue, append([]byte("signaturekey"), 0))
	mac := hmac.New(md5.New, signingKey)
	_, _ = mac.Write(first.Sum(nil))
	_, _ = mac.Write(second.Sum(nil))
	checksum := mac.Sum(nil)[:8]
	encryptedSequence := legacyEncryptSequence(m.key.KeyValue, checksum, sequence, m.sendAcceptor)
	body := make([]byte, 0, len(confounder)+len(padded))
	if confidential {
		keystream := legacyDataKey(m.key.KeyValue, uint32(sequence))
		encrypted := make([]byte, len(confounder)+len(padded))
		stream, err := rc4.NewCipher(keystream)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrGSSAPI, "RC4 data key rejected | RC4 数据密钥被拒绝")
		}
		stream.XORKeyStream(encrypted, append(append([]byte(nil), confounder...), padded...))
		body = append(body, encrypted...)
	} else {
		body = append(body, confounder...)
		body = append(body, padded...)
	}
	token := make([]byte, 0, len(header)+8+len(checksum)+len(body))
	token = append(token, header...)
	token = append(token, encryptedSequence...)
	token = append(token, checksum...)
	token = append(token, body...)
	m.sendSeq++
	return token, nil
}

// unwrapLegacy verifies and opens an RFC 4757 WRAP token. | unwrapLegacy 校验并解包
// RFC 4757 WRAP 令牌。
func (m *gssMessageContext) unwrapLegacy(token []byte) ([]byte, bool, error) {
	if len(token) < 24+rc4ConfounderSize+1 {
		return nil, false, errs.Detail(ErrGSSAPI, "legacy WRAP token is %d bytes, too short | 传统 WRAP 令牌为 %d 字节，过短", len(token), len(token))
	}
	if subtle.ConstantTimeCompare(token[:4], legacyWrapHeaderPrefix) != 1 {
		return nil, false, errs.Detail(ErrGSSAPI, "invalid legacy WRAP header | 非法传统 WRAP 头")
	}
	sealAlgorithm := binary.BigEndian.Uint16(token[4:6])
	confidential := false
	switch sealAlgorithm {
	case legacySealNone:
	case legacySealRC4:
		confidential = true
	default:
		return nil, false, errs.Detail(ErrGSSAPI, "unsupported legacy SEAL_ALG 0x%04x | 不支持的传统 SEAL_ALG 0x%04x", sealAlgorithm, sealAlgorithm)
	}
	if token[6] != 0xFF || token[7] != 0xFF {
		return nil, false, errs.Detail(ErrGSSAPI, "invalid legacy WRAP filler | 非法传统 WRAP 填充")
	}
	checksum := token[16:24]
	sequence, err := legacyDecryptSequence(m.key.KeyValue, checksum, token[8:16], !m.sendAcceptor)
	if err != nil {
		return nil, false, err
	}
	body := token[24:]
	var confounder, padded []byte
	if confidential {
		keystream := legacyDataKey(m.key.KeyValue, uint32(sequence))
		plain := make([]byte, len(body))
		stream, err := rc4.NewCipher(keystream)
		if err != nil {
			return nil, false, errs.WrapDetail(err, ErrGSSAPI, "RC4 data key rejected | RC4 数据密钥被拒绝")
		}
		stream.XORKeyStream(plain, body)
		body = plain
	}
	confounder = body[:rc4ConfounderSize]
	padded = body[rc4ConfounderSize:]
	// The checksum covers the plaintext header, confounder and padded data. |
	// 校验和覆盖明文头、混淆值与填充后的数据。
	first := md5.New()
	_, _ = first.Write(rc4UsageBytes(15))
	_, _ = first.Write(token[:8])
	_, _ = first.Write(confounder)
	second := md5.New()
	_, _ = second.Write(padded)
	signingKey := rc4HMAC(m.key.KeyValue, append([]byte("signaturekey"), 0))
	mac := hmac.New(md5.New, signingKey)
	_, _ = mac.Write(first.Sum(nil))
	_, _ = mac.Write(second.Sum(nil))
	if subtle.ConstantTimeCompare(mac.Sum(nil)[:8], checksum) != 1 {
		return nil, false, errs.Detail(ErrBadIntegrity, "legacy WRAP checksum mismatch | 传统 WRAP 校验和不匹配")
	}
	if len(padded) == 0 {
		return nil, false, errs.Detail(ErrGSSAPI, "legacy WRAP payload is empty | 传统 WRAP 载荷为空")
	}
	padding := int(padded[len(padded)-1])
	if padding < 1 || padding > 8 || padding > len(padded) {
		return nil, false, errs.Detail(ErrGSSAPI, "invalid legacy WRAP padding %d | 非法传统 WRAP 填充 %d", padding, padding)
	}
	for _, b := range padded[len(padded)-padding:] {
		if int(b) != padding {
			return nil, false, errs.Detail(ErrGSSAPI, "inconsistent legacy WRAP padding | 传统 WRAP 填充不一致")
		}
	}
	if err := m.acceptSequence(sequence); err != nil {
		return nil, false, err
	}
	return append([]byte(nil), padded[:len(padded)-padding]...), confidential, nil
}

// legacyEncryptSequence encrypts an RFC 4757 SND_SEQ field. | legacyEncryptSequence 加密
// RFC 4757 SND_SEQ 字段。
func legacyEncryptSequence(key, checksum []byte, sequence uint64, sentByAcceptor bool) []byte {
	plain := make([]byte, 8)
	binary.BigEndian.PutUint32(plain[:4], uint32(sequence))
	copy(plain[4:], gssDirectionBytes(sentByAcceptor))
	keystream := legacySequenceKey(key, checksum)
	encrypted := make([]byte, 8)
	stream, err := rc4.NewCipher(keystream)
	if err != nil {
		return make([]byte, 8)
	}
	stream.XORKeyStream(encrypted, plain)
	return encrypted
}

// legacyDecryptSequence decrypts and validates an RFC 4757 SND_SEQ field. |
// legacyDecryptSequence 解密并校验 RFC 4757 SND_SEQ 字段。
func legacyDecryptSequence(key, checksum, encrypted []byte, expectAcceptor bool) (uint64, error) {
	if len(encrypted) != 8 || len(checksum) < 8 {
		return 0, errs.Detail(ErrGSSAPI, "legacy SND_SEQ is malformed | 传统 SND_SEQ 格式非法")
	}
	keystream := legacySequenceKey(key, checksum)
	plain := make([]byte, 8)
	stream, err := rc4.NewCipher(keystream)
	if err != nil {
		return 0, errs.WrapDetail(err, ErrGSSAPI, "RC4 sequence key rejected | RC4 序列密钥被拒绝")
	}
	stream.XORKeyStream(plain, encrypted)
	expected := gssDirectionBytes(expectAcceptor)
	if subtle.ConstantTimeCompare(plain[4:], expected) != 1 {
		return 0, errs.Detail(ErrGSSAPI, "legacy token direction does not match the peer | 传统令牌方向与对端不匹配")
	}
	return uint64(binary.BigEndian.Uint32(plain[:4])), nil
}

// legacySequenceKey derives the RFC 4757 Kseq key. | legacySequenceKey 派生 RFC 4757
// Kseq 密钥。
func legacySequenceKey(key, checksum []byte) []byte {
	base := rc4HMAC(key, rc4UsageBytes(0))
	return rc4HMAC(base, checksum[:8])
}

// legacyDataKey derives the RFC 4757 Kcrypt key for a sequence number. |
// legacyDataKey 为序列号派生 RFC 4757 Kcrypt 密钥。
func legacyDataKey(key []byte, sequence uint32) []byte {
	local := make([]byte, len(key))
	for i := range key {
		local[i] = key[i] ^ 0xF0
	}
	raw := make([]byte, 4)
	binary.LittleEndian.PutUint32(raw, sequence)
	base := rc4HMAC(local, rc4UsageBytes(0))
	return rc4HMAC(base, raw)
}
