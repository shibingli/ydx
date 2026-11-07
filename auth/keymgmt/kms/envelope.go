package kms

import (
	"bytes"
	"context"
	"encoding/binary"

	"github.com/shibingli/ydx/errs"
)

// The wire-format magics. | 线格式魔数。
var (
	// cipherMagic prefixes direct ciphertext produced by Encrypt. | cipherMagic 是 Encrypt 产生的直接密文前缀。
	cipherMagic = []byte("KMS1")
	// wrappedMagic prefixes key material wrapped by WrapKey and GenerateDataKey. | wrappedMagic 是 WrapKey 与 GenerateDataKey 包装密钥材料的前缀。
	wrappedMagic = []byte("KMSW")
	// envelopeMagic prefixes Envelope.MarshalBinary output. | envelopeMagic 是 Envelope.MarshalBinary 输出前缀。
	envelopeMagic = []byte("KMSE")
)

// cipherFormatVersion is the binary format version of KMS1, KMSW and KMSE. | cipherFormatVersion 是
// KMS1、KMSW 与 KMSE 的二进制格式版本。
const cipherFormatVersion byte = 1

// envelopeContext separates envelope DEK wrapping from plain key wrapping. | envelopeContext 把信封
// DEK 包装与普通密钥包装区分开。
const envelopeContext = "ydx/kms/envelope/v1"

// buildCipherHeader builds a KMS1/KMSW header. | buildCipherHeader 构建 KMS1/KMSW 头部。
//
// Layout: magic[4] | format version[1] | algorithm[1] | key ID length[2, big endian] | key ID |
// key version[4, big endian] | nonce length[1] | nonce. The ciphertext follows the header. | 布局：
// 魔数[4] | 格式版本[1] | 算法[1] | 密钥 ID 长度[2，大端] | 密钥 ID | 密钥版本[4，大端] |
// nonce 长度[1] | nonce。密文紧跟头部。
func buildCipherHeader(magic []byte, alg cipherAlgorithm, keyID string, version uint32, nonce []byte) []byte {
	out := make([]byte, 0, len(magic)+1+1+2+len(keyID)+4+1+len(nonce))
	out = append(out, magic...)
	out = append(out, cipherFormatVersion)
	out = append(out, byte(alg))
	var scratch [4]byte
	binary.BigEndian.PutUint16(scratch[:2], uint16(len(keyID)))
	out = append(out, scratch[:2]...)
	out = append(out, keyID...)
	binary.BigEndian.PutUint32(scratch[:], version)
	out = append(out, scratch[:]...)
	out = append(out, byte(len(nonce)))
	out = append(out, nonce...)
	return out
}

// cipherEnvelope is a parsed KMS1/KMSW header. | cipherEnvelope 是解析后的 KMS1/KMSW 头部。
type cipherEnvelope struct {
	// alg is the AEAD algorithm. | alg 是 AEAD 算法。
	alg cipherAlgorithm
	// keyID is the key identifier carried in the header. | keyID 是头部携带的密钥标识。
	keyID string
	// version is the key version carried in the header. | version 是头部携带的密钥版本。
	version uint32
	// nonce is the AEAD nonce. | nonce 是 AEAD nonce。
	nonce []byte
	// ciphertext is the sealed body. | ciphertext 是密封后的主体。
	ciphertext []byte
	// headerLen is the number of leading header bytes. | headerLen 是前导头部字节数。
	headerLen int
}

// parseCipherEnvelope parses and validates a KMS1/KMSW header. | parseCipherEnvelope 解析并校验
// KMS1/KMSW 头部。
func parseCipherEnvelope(magic []byte, data []byte) (*cipherEnvelope, error) {
	const fixed = 4 + 1 + 1 + 2 + 4 + 1
	invalid := func(reason string) error {
		return errs.Detail(ErrInvalidCiphertext, "%[1]s | %[1]s", reason)
	}
	if len(data) < fixed || !bytes.HasPrefix(data, magic) {
		return nil, invalid("bad magic or truncated header | 魔数错误或头部被截断")
	}
	pos := len(magic)
	format := data[pos]
	pos++
	if format != cipherFormatVersion {
		return nil, invalid("unsupported ciphertext format version | 不支持的密文格式版本")
	}
	alg := cipherAlgorithm(data[pos])
	pos++
	if cipherAlgorithmLabel(alg) == "unknown" {
		return nil, invalid("unknown AEAD algorithm | 未知 AEAD 算法")
	}
	keyIDLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if keyIDLen == 0 || keyIDLen > maxKeyIDLength || pos+keyIDLen+4+1 > len(data) {
		return nil, invalid("invalid key id length | 密钥 ID 长度非法")
	}
	keyID := string(data[pos : pos+keyIDLen])
	pos += keyIDLen
	version := binary.BigEndian.Uint32(data[pos : pos+4])
	pos += 4
	nonceLen := int(data[pos])
	pos++
	if nonceLen != gcmNonceSize || pos+nonceLen > len(data) {
		return nil, invalid("invalid nonce length | nonce 长度非法")
	}
	nonce := data[pos : pos+nonceLen]
	pos += nonceLen
	body := data[pos:]
	if len(body) < 16 {
		return nil, invalid("truncated ciphertext | 密文被截断")
	}
	return &cipherEnvelope{alg: alg, keyID: keyID, version: version, nonce: nonce, ciphertext: body, headerLen: pos}, nil
}

// Envelope is a data encryption envelope: a random 256-bit DEK encrypted under a managed key, plus
// the payload encrypted with that DEK. | Envelope 是数据加密信封：在受管密钥下加密的 256 位随机
// DEK，以及用该 DEK 加密的负载。
type Envelope struct {
	// KeyID is the wrapping key identifier. | KeyID 是包装密钥标识。
	KeyID string `json:"keyId"`
	// KeyVersion is the wrapping key version. | KeyVersion 是包装密钥版本。
	KeyVersion uint32 `json:"keyVersion"`
	// WrappedKey is the KMSW-wrapped DEK. | WrappedKey 是 KMSW 包装的 DEK。
	WrappedKey []byte `json:"wrappedKey"`
	// Nonce is the 96-bit AES-GCM nonce of the payload. | Nonce 是负载的 96 位 AES-GCM nonce。
	Nonce []byte `json:"nonce"`
	// Ciphertext is the payload ciphertext including its tag. | Ciphertext 是包含标签的负载密文。
	Ciphertext []byte `json:"ciphertext"`
}

// Clone returns a deep copy of e. | Clone 返回 e 的深拷贝。
func (e *Envelope) Clone() *Envelope {
	if e == nil {
		return nil
	}
	c := *e
	c.WrappedKey = append([]byte(nil), e.WrappedKey...)
	c.Nonce = append([]byte(nil), e.Nonce...)
	c.Ciphertext = append([]byte(nil), e.Ciphertext...)
	return &c
}

// buildHeader returns the KMSE header used as AEAD associated data. | buildHeader 返回作为 AEAD
// 关联数据的 KMSE 头部。
//
// Layout: magic[4] | format version[1] | key ID length[2, big endian] | key ID | key version[4, big
// endian] | wrapped key length[2, big endian] | wrapped key | nonce length[1] | nonce. | 布局：
// 魔数[4] | 格式版本[1] | 密钥 ID 长度[2，大端] | 密钥 ID | 密钥版本[4，大端] | 包装密钥长度
// [2，大端] | 包装密钥 | nonce 长度[1] | nonce。
func (e *Envelope) buildHeader() []byte {
	out := make([]byte, 0, len(envelopeMagic)+1+2+len(e.KeyID)+4+2+len(e.WrappedKey)+1+len(e.Nonce))
	out = append(out, envelopeMagic...)
	out = append(out, cipherFormatVersion)
	var scratch [4]byte
	binary.BigEndian.PutUint16(scratch[:2], uint16(len(e.KeyID)))
	out = append(out, scratch[:2]...)
	out = append(out, e.KeyID...)
	binary.BigEndian.PutUint32(scratch[:], e.KeyVersion)
	out = append(out, scratch[:]...)
	binary.BigEndian.PutUint16(scratch[:2], uint16(len(e.WrappedKey)))
	out = append(out, scratch[:2]...)
	out = append(out, e.WrappedKey...)
	out = append(out, byte(len(e.Nonce)))
	out = append(out, e.Nonce...)
	return out
}

// Validate checks the envelope field sizes. | Validate 校验信封字段长度。
func (e *Envelope) Validate() error {
	if e == nil {
		return errs.Detail(ErrInvalidRequest, "nil envelope | 信封为空")
	}
	if e.KeyID == "" || len(e.KeyID) > maxKeyIDLength {
		return errs.Detail(ErrInvalidRequest, "invalid envelope key id | 信封密钥 ID 非法")
	}
	if len(e.WrappedKey) == 0 || len(e.WrappedKey) > 65535 {
		return errs.Detail(ErrInvalidRequest, "invalid wrapped key length | 包装密钥长度非法")
	}
	if len(e.Nonce) != gcmNonceSize {
		return errs.Detail(ErrInvalidRequest, "invalid envelope nonce length | 信封 nonce 长度非法")
	}
	if len(e.Ciphertext) < 16 {
		return errs.Detail(ErrInvalidRequest, "invalid envelope ciphertext length | 信封密文长度非法")
	}
	return nil
}

// MarshalBinary encodes the envelope as a KMSE blob. | MarshalBinary 把信封编码为 KMSE 数据块。
func (e *Envelope) MarshalBinary() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	header := e.buildHeader()
	out := make([]byte, 0, len(header)+len(e.Ciphertext))
	out = append(out, header...)
	out = append(out, e.Ciphertext...)
	return out, nil
}

// ParseEnvelope decodes a KMSE blob produced by Envelope.MarshalBinary. | ParseEnvelope 解码
// Envelope.MarshalBinary 产生的 KMSE 数据块。
func ParseEnvelope(data []byte) (*Envelope, error) {
	const fixed = 4 + 1 + 2 + 4 + 2 + 1
	invalid := func(reason string) error {
		return errs.Detail(ErrInvalidCiphertext, "%[1]s | %[1]s", reason)
	}
	if len(data) < fixed || !bytes.HasPrefix(data, envelopeMagic) {
		return nil, invalid("bad envelope magic or truncated header | 信封魔数错误或头部被截断")
	}
	pos := len(envelopeMagic)
	if data[pos] != cipherFormatVersion {
		return nil, invalid("unsupported envelope format version | 不支持的信封格式版本")
	}
	pos++
	keyIDLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if keyIDLen == 0 || keyIDLen > maxKeyIDLength || pos+keyIDLen+4+2+1 > len(data) {
		return nil, invalid("invalid envelope key id length | 信封密钥 ID 长度非法")
	}
	keyID := string(data[pos : pos+keyIDLen])
	pos += keyIDLen
	version := binary.BigEndian.Uint32(data[pos : pos+4])
	pos += 4
	wrappedLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if wrappedLen == 0 || pos+wrappedLen+1 > len(data) {
		return nil, invalid("invalid wrapped key length | 包装密钥长度非法")
	}
	wrapped := data[pos : pos+wrappedLen]
	pos += wrappedLen
	nonceLen := int(data[pos])
	pos++
	if nonceLen != gcmNonceSize || pos+nonceLen > len(data) {
		return nil, invalid("invalid envelope nonce length | 信封 nonce 长度非法")
	}
	nonce := data[pos : pos+nonceLen]
	pos += nonceLen
	ciphertext := data[pos:]
	if len(ciphertext) < 16 {
		return nil, invalid("truncated envelope ciphertext | 信封密文被截断")
	}
	env := &Envelope{
		KeyID:      keyID,
		KeyVersion: version,
		WrappedKey: append([]byte(nil), wrapped...),
		Nonce:      append([]byte(nil), nonce...),
		Ciphertext: append([]byte(nil), ciphertext...),
	}
	return env, nil
}

// EncryptEnvelope generates a random 256-bit DEK, wraps it under the current version of the key
// named by id, and encrypts plaintext with AES-256-GCM. | EncryptEnvelope 生成 256 位随机 DEK，在
// id 对应密钥的当前版本下包装它，并用 AES-256-GCM 加密 plaintext。
//
// This is the recommended mode for bulk data: only the small DEK touches the managed key, and the
// key can rotate without re-encrypting the payload. aad is authenticated with both layers. | 这是
// 批量数据的推荐模式：只有小型 DEK 接触受管密钥，密钥轮换无需重加密负载。aad 在两层都会认证。
func (s *Service) EncryptEnvelope(ctx context.Context, id string, plaintext, aad []byte) (*Envelope, error) {
	key, err := s.loadResolvedKey(ctx, id)
	if err != nil {
		s.fail(ctx, OperationEncrypt, id, 0, err)
		return nil, err
	}
	defer key.eraseMaterial()
	version := key.Version
	if err := authorizeUse(key, key.CurrentVersion(), UsageEncrypt); err != nil {
		s.fail(ctx, OperationEncrypt, key.ID, version, err)
		return nil, err
	}
	dek, err := randomBytes(32)
	if err != nil {
		s.fail(ctx, OperationEncrypt, key.ID, version, err)
		return nil, err
	}
	defer zeroBytes(dek)
	wrapped, err := s.wrapMaterialForKey(ctx, key, version, dek, envelopeWrapAAD(envelopeContext, aad))
	if err != nil {
		s.fail(ctx, OperationEncrypt, key.ID, version, err)
		return nil, err
	}
	nonce, err := s.newNonce(key.ID, version)
	if err != nil {
		s.fail(ctx, OperationEncrypt, key.ID, version, err)
		return nil, err
	}
	env := &Envelope{KeyID: key.ID, KeyVersion: version, WrappedKey: wrapped, Nonce: nonce}
	header := env.buildHeader()
	fullAAD := make([]byte, 0, len(header)+len(aad))
	fullAAD = append(fullAAD, header...)
	fullAAD = append(fullAAD, aad...)
	sealed, err := sealAEAD(algAES256GCM, dek, nonce, plaintext, fullAAD)
	if err != nil {
		s.fail(ctx, OperationEncrypt, key.ID, version, err)
		return nil, err
	}
	env.Ciphertext = sealed
	s.succeed(ctx, OperationEncrypt, key.ID, version, map[string]string{"type": string(key.Type), "algorithm": "AES-256-GCM", "mode": "envelope"})
	return env, nil
}

// DecryptEnvelope decrypts an envelope produced by EncryptEnvelope. | DecryptEnvelope 解密
// EncryptEnvelope 产生的信封。
//
// The KEK version named inside the envelope is used, subject to its lifecycle state. | 使用信封内
// 指定的 KEK 版本，并受其生命周期状态约束。
func (s *Service) DecryptEnvelope(ctx context.Context, envelope *Envelope, aad []byte) ([]byte, error) {
	if envelope == nil {
		err := errs.Detail(ErrInvalidRequest, "nil envelope | 信封为空")
		s.fail(ctx, OperationDecrypt, "", 0, err)
		return nil, err
	}
	key, err := s.loadResolvedKey(ctx, envelope.KeyID)
	if err != nil {
		s.fail(ctx, OperationDecrypt, envelope.KeyID, envelope.KeyVersion, err)
		return nil, err
	}
	defer key.eraseMaterial()
	if key.ID != envelope.KeyID {
		err := errs.Detail(ErrInvalidCiphertext, "envelope names key %[1]q, not %[2]q | 信封指定的密钥为 %[1]q，而非 %[2]q", envelope.KeyID, key.ID)
		s.fail(ctx, OperationDecrypt, key.ID, envelope.KeyVersion, err)
		return nil, err
	}
	version := key.VersionAt(envelope.KeyVersion)
	if version == nil {
		err := errs.Detail(ErrVersionNotFound, "key %[1]q version %[2]d | 密钥 %[1]q 版本 %[2]d", key.ID, envelope.KeyVersion)
		s.fail(ctx, OperationDecrypt, key.ID, envelope.KeyVersion, err)
		return nil, err
	}
	if err := authorizeUse(key, version, UsageDecrypt); err != nil {
		s.fail(ctx, OperationDecrypt, key.ID, envelope.KeyVersion, err)
		return nil, err
	}
	if len(envelope.Nonce) != gcmNonceSize || len(envelope.Ciphertext) < 16 {
		err := errs.Detail(ErrInvalidCiphertext, "invalid envelope nonce or ciphertext | 信封 nonce 或密文非法")
		s.fail(ctx, OperationDecrypt, key.ID, envelope.KeyVersion, err)
		return nil, err
	}
	dek, err := s.unwrapMaterialForKey(ctx, key, envelope.KeyVersion, envelope.WrappedKey, envelopeWrapAAD(envelopeContext, aad))
	if err != nil {
		s.fail(ctx, OperationDecrypt, key.ID, envelope.KeyVersion, err)
		return nil, err
	}
	defer zeroBytes(dek)
	header := envelope.buildHeader()
	fullAAD := make([]byte, 0, len(header)+len(aad))
	fullAAD = append(fullAAD, header...)
	fullAAD = append(fullAAD, aad...)
	plain, err := openAEAD(algAES256GCM, dek, envelope.Nonce, envelope.Ciphertext, fullAAD)
	if err != nil {
		s.fail(ctx, OperationDecrypt, key.ID, envelope.KeyVersion, err)
		return nil, err
	}
	s.succeed(ctx, OperationDecrypt, key.ID, envelope.KeyVersion, map[string]string{"type": string(key.Type), "algorithm": "AES-256-GCM", "mode": "envelope"})
	return plain, nil
}

// envelopeWrapAAD binds the DEK wrapping to its purpose and the caller's associated data. | envelopeWrapAAD
// 把 DEK 包装绑定到用途与调用方关联数据。
func envelopeWrapAAD(context string, aad []byte) []byte {
	out := make([]byte, 0, len(context)+1+len(aad))
	out = append(out, context...)
	out = append(out, 0)
	out = append(out, aad...)
	return out
}
