package kms

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"strconv"

	"github.com/shibingli/ydx/errs"
	"golang.org/x/crypto/pbkdf2"
)

// Wrapper encrypts and authenticates private key material at rest. | Wrapper 静态加密并认证私钥材料。
//
// Implementations must be deterministic in the metadata they authenticate: the same keyID and
// version passed to Wrap must be passed to Unwrap. | 实现必须对其认证的元数据保持一致：Wrap 与
// Unwrap 必须收到相同的 keyID 与 version。
type Wrapper interface {
	// Wrap encrypts material for keyID and version. | Wrap 为 keyID 与 version 加密 material。
	Wrap(ctx context.Context, keyID string, version uint32, material []byte) ([]byte, error)
	// Unwrap decrypts material produced by Wrap. | Unwrap 解密 Wrap 产生的 material。
	Unwrap(ctx context.Context, keyID string, version uint32, wrapped []byte) ([]byte, error)
}

// atRestMagic identifies the current versioned at-rest format. | atRestMagic 标识当前带版本信息的
// 静态材料格式。
//
// Layout: magic | KDF (1) | iterations (4, big endian) | key length (2, big endian) |
// salt length (1) | salt | nonce (12) | ciphertext and tag. The whole header except magic is
// authenticated as additional data, so editing a KDF parameter makes Unwrap fail. | 布局：
// 魔数 | KDF（1）| 迭代次数（4，大端）| 密钥长度（2，大端）| 盐长度（1）| 盐 | nonce（12）|
// 密文与标签。除魔数外的整个头部都作为附加数据认证，因此修改 KDF 参数会使 Unwrap 失败。
var atRestMagic = []byte("KMSM2")

// legacyAtRestMagic identifies the first at-rest format, which stored no KDF parameters. | legacyAtRestMagic
// 标识首个静态材料格式，该格式不保存 KDF 参数。
var legacyAtRestMagic = []byte("KMSM1")

// atRestKDF identifies the key derivation used by the versioned at-rest format. | atRestKDF 标识
// 带版本静态格式使用的密钥派生方式。
type atRestKDF byte

const (
	// atRestKDFDirect uses the configured root key bytes directly. | atRestKDFDirect 直接使用配置的根密钥字节。
	atRestKDFDirect atRestKDF = 0
	// atRestKDFPBKDF2 stretches the configured passphrase with PBKDF2-HMAC-SHA256. | atRestKDFPBKDF2
	// 使用 PBKDF2-HMAC-SHA256 拉伸配置的口令。
	atRestKDFPBKDF2 atRestKDF = 1
)

const (
	// pbkdf2Iterations is the PBKDF2 work factor for passphrase-derived at-rest keys. | pbkdf2Iterations
	// 是口令派生静态密钥的 PBKDF2 工作因子。
	pbkdf2Iterations = 210_000
	// atRestSaltSize is the random salt length written by passphrase wrappers. | atRestSaltSize 是
	// 口令包装器写入的随机盐长度。
	atRestSaltSize = 16
	// atRestMaxSaltSize caps accepted salt lengths. | atRestMaxSaltSize 限制可接受的盐长度。
	atRestMaxSaltSize = 32
	// atRestMinIterations is the smallest accepted PBKDF2 work factor. | atRestMinIterations 是可
	// 接受的最小 PBKDF2 工作因子。
	atRestMinIterations = 10_000
	// atRestMaxIterations is the largest accepted PBKDF2 work factor. | atRestMaxIterations 是可
	// 接受的最大 PBKDF2 工作因子。
	atRestMaxIterations = 10_000_000
	// legacyAtRestSalt is the fixed salt of the KMSM1 format. | legacyAtRestSalt 是 KMSM1 格式的固定盐。
	legacyAtRestSalt = "ydx/kms/at-rest/v1"
	// atRestFixedHeaderSize is the header size before the salt. | atRestFixedHeaderSize 是盐之前的头部长度。
	atRestFixedHeaderSize = 5 + 1 + 4 + 2 + 1
)

// atRestWrapper wraps material with AES-GCM under a root key or passphrase. | atRestWrapper 在根密钥
// 或口令下用 AES-GCM 包装材料。
type atRestWrapper struct {
	// aead is the AES-GCM instance built from a direct root key; nil for passphrase wrappers. | aead
	// 是由直接根密钥构建的 AES-GCM 实例；口令包装器为 nil。
	aead cipher.AEAD
	// passphrase is a private copy used for per-wrap PBKDF2 derivation. | passphrase 是用于每次
	// 包装时 PBKDF2 派生的私有副本。
	passphrase []byte
	// keyLen is the direct root key length in bytes. | keyLen 是直接根密钥的字节长度。
	keyLen int
}

// newAtRestWrapper builds the default at-rest wrapper. | newAtRestWrapper 构建默认静态包装器。
//
// It returns (nil, nil) when neither a root key nor a passphrase is configured. The root key may be
// 16, 24 or 32 bytes; a passphrase is stretched with PBKDF2-HMAC-SHA256 using a fresh random salt
// for every Wrap call, and the parameters are stored in the wrapped material. At-rest wrapping
// always uses AES-GCM even when the root key is labelled SM4 or ChaCha20. | 未配置根密钥与口令时
// 返回 (nil, nil)。根密钥可为 16、24 或 32 字节；口令在每次 Wrap 时使用新的随机盐经
// PBKDF2-HMAC-SHA256 拉伸，参数保存在包装材料中。即使根密钥标注为 SM4 或 ChaCha20，静态包装
// 始终使用 AES-GCM。
func newAtRestWrapper(root *Key, passphrase string) (Wrapper, error) {
	if root == nil && passphrase == "" {
		return nil, nil
	}
	if root != nil {
		if root.Material == nil {
			return nil, errs.Detail(ErrInvalidConfig, "root key has no material | 根密钥没有材料")
		}
		keyBytes := append([]byte(nil), root.Material...)
		defer zeroBytes(keyBytes)
		switch len(keyBytes) {
		case 16, 24, 32:
		default:
			return nil, errs.Detail(ErrInvalidConfig, "at-rest key must be 16, 24 or 32 bytes, got %[1]d | 静态密钥必须为 16、24 或 32 字节，实际 %[1]d", len(keyBytes))
		}
		block, err := aes.NewCipher(keyBytes)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidConfig)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidConfig)
		}
		return &atRestWrapper{aead: aead, keyLen: len(keyBytes)}, nil
	}
	return &atRestWrapper{passphrase: []byte(passphrase)}, nil
}

// configured reports whether the wrapper can encrypt and decrypt material. | configured 报告包装器
// 是否可加解密材料。
func (w *atRestWrapper) configured() bool {
	return w != nil && (w.aead != nil || len(w.passphrase) > 0)
}

// Wrap encrypts material with a fresh salt and nonce and metadata-bound AAD. | Wrap 使用新盐、新
// nonce 与绑定元数据的 AAD 加密材料。
func (w *atRestWrapper) Wrap(_ context.Context, keyID string, version uint32, material []byte) ([]byte, error) {
	if !w.configured() {
		return nil, ErrInvalidConfig
	}
	if len(material) == 0 {
		return nil, nil
	}
	kdf := atRestKDFDirect
	var (
		salt       []byte
		iterations uint32
		keyLen     = w.keyLen
		aead       cipher.AEAD
	)
	if w.aead != nil {
		aead = w.aead
	} else {
		kdf = atRestKDFPBKDF2
		iterations = pbkdf2Iterations
		keyLen = 32
		var err error
		salt, err = randomBytes(atRestSaltSize)
		if err != nil {
			return nil, err
		}
		derived, err := deriveAtRestAEAD(w.passphrase, salt, iterations, keyLen)
		if err != nil {
			return nil, err
		}
		aead = derived
	}
	header := appendAtRestHeader(nil, kdf, iterations, keyLen, salt)
	nonce, err := randomBytes(gcmNonceSize)
	if err != nil {
		return nil, err
	}
	aad := append(atRestAAD(keyID, version), header...)
	out := make([]byte, 0, len(header)+len(nonce)+len(material)+aead.Overhead())
	out = append(out, header...)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, material, aad)
	return out, nil
}

// Unwrap decrypts material produced by Wrap, including the legacy KMSM1 format. | Unwrap 解密 Wrap
// 产生的材料，包括旧版 KMSM1 格式。
func (w *atRestWrapper) Unwrap(_ context.Context, keyID string, version uint32, wrapped []byte) ([]byte, error) {
	if !w.configured() {
		return nil, ErrInvalidConfig
	}
	if bytes.HasPrefix(wrapped, legacyAtRestMagic) {
		return w.unwrapLegacy(keyID, version, wrapped)
	}
	if !bytes.HasPrefix(wrapped, atRestMagic) {
		return nil, errs.Detail(ErrInvalidMaterial, "missing at-rest material magic | 缺少静态材料魔数")
	}
	params, err := parseAtRestHeader(wrapped)
	if err != nil {
		return nil, err
	}
	aead, err := w.aeadForParams(params)
	if err != nil {
		return nil, err
	}
	aad := append(atRestAAD(keyID, version), params.header...)
	plain, err := aead.Open(nil, params.nonce, params.ciphertext, aad)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidMaterial, "at-rest unwrap failed | 静态解包失败")
	}
	return plain, nil
}

// atRestParams is a parsed versioned at-rest header. | atRestParams 是解析后的带版本静态头部。
type atRestParams struct {
	// kdf is the key derivation identifier. | kdf 是密钥派生标识。
	kdf atRestKDF
	// iterations is the PBKDF2 work factor, zero for direct keys. | iterations 是 PBKDF2 工作因子，
	// 直接密钥为零。
	iterations uint32
	// keyLen is the derived key length in bytes. | keyLen 是派生密钥的字节长度。
	keyLen int
	// salt is the PBKDF2 salt. | salt 是 PBKDF2 盐。
	salt []byte
	// header is the exact authenticated header bytes. | header 是参与认证的精确头部字节。
	header []byte
	// nonce is the AES-GCM nonce. | nonce 是 AES-GCM nonce。
	nonce []byte
	// ciphertext is the sealed material including the tag. | ciphertext 是包含标签的密封材料。
	ciphertext []byte
}

// parseAtRestHeader parses and validates a versioned at-rest header. | parseAtRestHeader 解析并校验
// 带版本静态头部。
func parseAtRestHeader(wrapped []byte) (atRestParams, error) {
	if len(wrapped) < atRestFixedHeaderSize {
		return atRestParams{}, errs.Detail(ErrInvalidMaterial, "truncated at-rest header | 静态头部被截断")
	}
	if !bytes.Equal(wrapped[:len(atRestMagic)], atRestMagic) {
		return atRestParams{}, errs.Detail(ErrInvalidMaterial, "missing at-rest material magic | 缺少静态材料魔数")
	}
	rest := wrapped[len(atRestMagic):]
	params := atRestParams{
		kdf:        atRestKDF(rest[0]),
		iterations: binary.BigEndian.Uint32(rest[1:5]),
		keyLen:     int(binary.BigEndian.Uint16(rest[5:7])),
	}
	saltLen := int(rest[7])
	if saltLen > atRestMaxSaltSize {
		return atRestParams{}, errs.Detail(ErrInvalidMaterial, "invalid at-rest salt length %[1]d | 静态盐长度 %[1]d 非法", saltLen)
	}
	headerLen := atRestFixedHeaderSize + saltLen
	if len(wrapped) < headerLen {
		return atRestParams{}, errs.Detail(ErrInvalidMaterial, "truncated at-rest salt | 静态盐被截断")
	}
	params.salt = rest[8 : 8+saltLen]
	params.header = wrapped[:headerLen]
	switch params.keyLen {
	case 16, 24, 32:
	default:
		return atRestParams{}, errs.Detail(ErrInvalidMaterial, "invalid at-rest key length %[1]d | 静态密钥长度 %[1]d 非法", params.keyLen)
	}
	switch params.kdf {
	case atRestKDFDirect:
		if params.iterations != 0 || saltLen != 0 {
			return atRestParams{}, errs.Detail(ErrInvalidMaterial, "direct at-rest key carries KDF parameters | 直接静态密钥携带了 KDF 参数")
		}
	case atRestKDFPBKDF2:
		if saltLen == 0 {
			return atRestParams{}, errs.Detail(ErrInvalidMaterial, "passphrase at-rest key has no salt | 口令静态密钥缺少盐")
		}
		if params.iterations < atRestMinIterations || params.iterations > atRestMaxIterations {
			return atRestParams{}, errs.Detail(ErrInvalidMaterial, "PBKDF2 iterations %[1]d outside %[2]d..%[3]d | PBKDF2 迭代次数 %[1]d 超出 %[2]d..%[3]d", params.iterations, atRestMinIterations, atRestMaxIterations)
		}
	default:
		return atRestParams{}, errs.Detail(ErrInvalidMaterial, "unknown at-rest KDF %[1]d | 未知静态 KDF %[1]d", params.kdf)
	}
	body := wrapped[headerLen:]
	if len(body) < gcmNonceSize {
		return atRestParams{}, errs.Detail(ErrInvalidMaterial, "truncated at-rest nonce | 静态 nonce 被截断")
	}
	params.nonce = body[:gcmNonceSize]
	params.ciphertext = body[gcmNonceSize:]
	if len(params.ciphertext) == 0 {
		return atRestParams{}, errs.Detail(ErrInvalidMaterial, "truncated wrapped material | 包装材料被截断")
	}
	return params, nil
}

// aeadForParams returns the AEAD selected by the header parameters. | aeadForParams 返回头部参数
// 选定的 AEAD。
func (w *atRestWrapper) aeadForParams(params atRestParams) (cipher.AEAD, error) {
	switch params.kdf {
	case atRestKDFDirect:
		if w.aead == nil {
			return nil, errs.Detail(ErrInvalidMaterial, "material needs a root key, not a passphrase | 材料需要根密钥而非口令")
		}
		if params.keyLen != w.keyLen {
			return nil, errs.Detail(ErrInvalidMaterial, "at-rest key length mismatch | 静态密钥长度不匹配")
		}
		return w.aead, nil
	case atRestKDFPBKDF2:
		if len(w.passphrase) == 0 {
			return nil, errs.Detail(ErrInvalidMaterial, "material needs a passphrase, not a root key | 材料需要口令而非根密钥")
		}
		return deriveAtRestAEAD(w.passphrase, params.salt, params.iterations, params.keyLen)
	default:
		return nil, errs.Detail(ErrInvalidMaterial, "unknown at-rest KDF %[1]d | 未知静态 KDF %[1]d", params.kdf)
	}
}

// deriveAtRestAEAD derives an AES-GCM instance with PBKDF2-HMAC-SHA256. | deriveAtRestAEAD 用
// PBKDF2-HMAC-SHA256 派生 AES-GCM 实例。
func deriveAtRestAEAD(passphrase, salt []byte, iterations uint32, keyLen int) (cipher.AEAD, error) {
	key := pbkdf2.Key(passphrase, salt, int(iterations), keyLen, sha256.New)
	defer zeroBytes(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidConfig)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidConfig)
	}
	return aead, nil
}

// unwrapLegacy decrypts the first at-rest format, which used a fixed salt and no header. | unwrapLegacy
// 解密首个静态格式，该格式使用固定盐且没有头部。
func (w *atRestWrapper) unwrapLegacy(keyID string, version uint32, wrapped []byte) ([]byte, error) {
	rest := wrapped[len(legacyAtRestMagic):]
	if len(rest) < gcmNonceSize {
		return nil, errs.Detail(ErrInvalidMaterial, "truncated wrapped material | 包装材料被截断")
	}
	aead := w.aead
	if aead == nil {
		derived, err := deriveAtRestAEAD(w.passphrase, []byte(legacyAtRestSalt), pbkdf2Iterations, 32)
		if err != nil {
			return nil, err
		}
		aead = derived
	}
	nonce := rest[:gcmNonceSize]
	if len(rest) == gcmNonceSize {
		return nil, errs.Detail(ErrInvalidMaterial, "truncated wrapped material | 包装材料被截断")
	}
	plain, err := aead.Open(nil, nonce, rest[gcmNonceSize:], atRestAAD(keyID, version))
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidMaterial, "at-rest unwrap failed | 静态解包失败")
	}
	return plain, nil
}

// appendAtRestHeader builds the authenticated versioned header. | appendAtRestHeader 构建参与认证的
// 带版本头部。
func appendAtRestHeader(dst []byte, kdf atRestKDF, iterations uint32, keyLen int, salt []byte) []byte {
	dst = append(dst, atRestMagic...)
	dst = append(dst, byte(kdf))
	dst = binary.BigEndian.AppendUint32(dst, iterations)
	dst = binary.BigEndian.AppendUint16(dst, uint16(keyLen))
	dst = append(dst, byte(len(salt)))
	dst = append(dst, salt...)
	return dst
}

// atRestAAD builds the metadata the at-rest wrapper authenticates. | atRestAAD 构建静态包装器认证的元数据。
func atRestAAD(keyID string, version uint32) []byte {
	out := make([]byte, 0, len(keyID)+16)
	out = append(out, "ydx/kms/at-rest/meta/v1"...)
	out = append(out, 0)
	out = append(out, keyID...)
	out = append(out, 0)
	out = strconv.AppendUint(out, uint64(version), 10)
	return out
}

// isAtRestMaterial reports whether material uses a known at-rest wrapping format. | isAtRestMaterial
// 报告材料是否使用已知的静态包装格式。
func isAtRestMaterial(material []byte) bool {
	return bytes.HasPrefix(material, atRestMagic) || bytes.HasPrefix(material, legacyAtRestMagic)
}

// Rewrap decrypts wrapped with from and encrypts the plaintext with to under the same metadata. | Rewrap
// 用 from 解密 wrapped，并在相同元数据下用 to 加密明文。
//
// It is the building block for passphrase rotation: the returned blob uses the target wrapper's
// current format and parameters. Both wrappers must be non-nil. | 它是口令轮换的构建块：返回的数据块
// 使用目标包装器的当前格式与参数。两个包装器都必须非 nil。
func Rewrap(ctx context.Context, from, to Wrapper, keyID string, version uint32, wrapped []byte) ([]byte, error) {
	if from == nil || to == nil {
		return nil, errs.Detail(ErrInvalidConfig, "both source and target wrappers are required | 必须提供源与目标包装器")
	}
	if len(wrapped) == 0 {
		return nil, nil
	}
	plain, err := from.Unwrap(ctx, keyID, version, wrapped)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(plain)
	out, err := to.Wrap(ctx, keyID, version, plain)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// wrapperChain writes with primary and reads with primary or fallback. | wrapperChain 用 primary
// 写入，并用 primary 或 fallback 读取。
type wrapperChain struct {
	// primary encrypts new material. | primary 加密新材料。
	primary Wrapper
	// fallback decrypts material written before rotation. | fallback 解密轮换前写入的材料。
	fallback Wrapper
}

// Wrap encrypts with the primary wrapper. | Wrap 用主包装器加密。
func (c *wrapperChain) Wrap(ctx context.Context, keyID string, version uint32, material []byte) ([]byte, error) {
	return c.primary.Wrap(ctx, keyID, version, material)
}

// Unwrap tries the primary wrapper and then the fallback. | Unwrap 先尝试主包装器，再尝试回退包装器。
func (c *wrapperChain) Unwrap(ctx context.Context, keyID string, version uint32, wrapped []byte) ([]byte, error) {
	out, err := c.primary.Unwrap(ctx, keyID, version, wrapped)
	if err == nil {
		return out, nil
	}
	fallback, fallbackErr := c.fallback.Unwrap(ctx, keyID, version, wrapped)
	if fallbackErr == nil {
		return fallback, nil
	}
	return nil, errs.WrapDetail(err, ErrInvalidMaterial, "no at-rest wrapper could unwrap material | 没有静态包装器可解包材料")
}

// RewrapAtRest re-encrypts every wrapped key and version with next and installs next as the service
// wrapper. | RewrapAtRest 用 next 重新加密每个已包装的密钥与版本，并把 next 安装为服务包装器。
//
// It returns the number of keys updated. Wrapped material written before the call remains readable
// through a fallback when an update fails partway: the service then keeps both wrappers installed.
// On success only next remains. Material that is not at-rest wrapped is left untouched. The service
// must already have a wrapper; otherwise ErrInvalidConfig is returned. | 它返回更新的密钥数量。
// 若更新中途失败，调用前写入的包装材料仍可通过回退包装器读取：服务会同时保留两个包装器。
// 全部成功后只保留 next。未做静态包装的材料保持不变。服务必须已有包装器，否则返回
// ErrInvalidConfig。
func (s *Service) RewrapAtRest(ctx context.Context, next Wrapper) (int, error) {
	if s == nil || s.store == nil {
		return 0, ErrStoreUnavailable
	}
	if next == nil {
		return 0, errs.Detail(ErrInvalidConfig, "target wrapper is required | 必须提供目标包装器")
	}
	s.wrapperMu.Lock()
	defer s.wrapperMu.Unlock()
	if s.wrapper == nil {
		return 0, errs.Detail(ErrInvalidConfig, "no current at-rest wrapper to rotate from | 没有可轮换的当前静态包装器")
	}
	keys, err := s.store.ListKeys(ctx, KeyFilter{})
	if err != nil {
		return 0, err
	}
	updated := 0
	previous := s.wrapper
	// Install the chain before touching records so a partial rewrite stays readable. | 在改写记录前
	// 安装链式包装器，保证部分改写后仍可读取。
	s.wrapper = &wrapperChain{primary: next, fallback: previous}
	for _, key := range keys {
		if key == nil {
			continue
		}
		changed := false
		version := key.Version
		if version == 0 {
			version = 1
		}
		if len(key.Material) > 0 && isAtRestMaterial(key.Material) {
			rewrapped, err := Rewrap(ctx, previous, next, key.ID, version, key.Material)
			if err != nil {
				return updated, err
			}
			zeroBytes(key.Material)
			key.Material = rewrapped
			changed = true
		}
		for _, item := range key.Versions {
			if item == nil || len(item.Material) == 0 || !isAtRestMaterial(item.Material) {
				continue
			}
			rewrapped, err := Rewrap(ctx, previous, next, key.ID, item.Version, item.Material)
			if err != nil {
				return updated, err
			}
			zeroBytes(item.Material)
			item.Material = rewrapped
			changed = true
		}
		if !changed {
			continue
		}
		if err := s.store.UpdateKey(ctx, key); err != nil {
			return updated, err
		}
		updated++
	}
	s.wrapper = next
	return updated, nil
}

// persistKey returns a copy of key with private material wrapped for storage. | persistKey 返回私钥
// 材料已包装、可供存储的 key 副本。
func (s *Service) persistKey(ctx context.Context, key *Key) (_ *Key, err error) {
	if key == nil {
		return nil, ErrNotFound
	}
	stored := key.Clone()
	defer func() {
		if err != nil {
			stored.eraseMaterial()
		}
	}()
	s.wrapperMu.RLock()
	wrapper := s.wrapper
	s.wrapperMu.RUnlock()
	if wrapper == nil {
		return stored, nil
	}
	version := stored.Version
	if version == 0 {
		version = 1
	}
	if len(stored.Material) > 0 {
		wrapped, err := wrapper.Wrap(ctx, stored.ID, version, stored.Material)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidMaterial, "wrap key material | 包装密钥材料")
		}
		zeroBytes(stored.Material)
		stored.Material = wrapped
	}
	for _, item := range stored.Versions {
		if item == nil || len(item.Material) == 0 {
			continue
		}
		wrapped, err := wrapper.Wrap(ctx, stored.ID, item.Version, item.Material)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidMaterial, "wrap version material | 包装版本材料")
		}
		zeroBytes(item.Material)
		item.Material = wrapped
	}
	return stored, nil
}

// loadKey returns a copy of key with private material unwrapped. | loadKey 返回私钥材料已解包的 key 副本。
func (s *Service) loadKey(ctx context.Context, key *Key) (_ *Key, err error) {
	if key == nil {
		return nil, ErrNotFound
	}
	loaded := key.Clone()
	defer func() {
		if err != nil {
			loaded.eraseMaterial()
		}
	}()
	s.wrapperMu.RLock()
	wrapper := s.wrapper
	s.wrapperMu.RUnlock()
	if wrapper == nil {
		if isAtRestMaterial(loaded.Material) {
			return nil, errs.Detail(ErrInvalidConfig, "material is wrapped but no wrapper is configured | 材料已包装但未配置包装器")
		}
		return loaded, nil
	}
	if len(loaded.Material) > 0 {
		version := loaded.Version
		if version == 0 {
			version = 1
		}
		plain, err := wrapper.Unwrap(ctx, loaded.ID, version, loaded.Material)
		if err != nil {
			return nil, err
		}
		zeroBytes(loaded.Material)
		loaded.Material = plain
	}
	for _, item := range loaded.Versions {
		if item == nil || len(item.Material) == 0 {
			continue
		}
		plain, err := wrapper.Unwrap(ctx, loaded.ID, item.Version, item.Material)
		if err != nil {
			return nil, err
		}
		zeroBytes(item.Material)
		item.Material = plain
	}
	return loaded, nil
}

// materialForVersion returns the material for a specific version. | materialForVersion 返回指定版本的材料。
func materialForVersion(key *Key, version uint32) []byte {
	if key == nil {
		return nil
	}
	if item := key.VersionAt(version); item != nil && len(item.Material) > 0 {
		return item.Material
	}
	if version == key.Version {
		return key.Material
	}
	return nil
}
