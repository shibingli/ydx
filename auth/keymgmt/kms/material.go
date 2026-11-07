package kms

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
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

// atRestMagic identifies material wrapped by atRestWrapper. | atRestMagic 标识由 atRestWrapper 包装的材料。
var atRestMagic = []byte("KMSM1")

// pbkdf2Iterations is the PBKDF2 work factor for passphrase-derived at-rest keys. | pbkdf2Iterations
// 是口令派生静态密钥的 PBKDF2 工作因子。
const pbkdf2Iterations = 210_000

// atRestWrapper wraps material with AES-GCM under a root key. | atRestWrapper 在根密钥下用 AES-GCM 包装材料。
type atRestWrapper struct {
	// aead is the AES-GCM instance built from the root key. | aead 是由根密钥构建的 AES-GCM 实例。
	aead cipher.AEAD
}

// newAtRestWrapper builds the default at-rest wrapper. | newAtRestWrapper 构建默认静态包装器。
//
// It returns (nil, nil) when neither a root key nor a passphrase is configured. The root key may be
// 16, 24 or 32 bytes; a passphrase is stretched to 32 bytes with PBKDF2-HMAC-SHA256. At-rest
// wrapping always uses AES-GCM even when the root key is labelled SM4 or ChaCha20. | 未配置根密钥
// 与口令时返回 (nil, nil)。根密钥可为 16、24 或 32 字节；口令经 PBKDF2-HMAC-SHA256 拉伸为 32
// 字节。即使根密钥标注为 SM4 或 ChaCha20，静态包装始终使用 AES-GCM。
func newAtRestWrapper(root *Key, passphrase string) (Wrapper, error) {
	var keyBytes []byte
	switch {
	case root != nil:
		if root.Material == nil {
			return nil, errs.Detail(ErrInvalidConfig, "root key has no material | 根密钥没有材料")
		}
		keyBytes = append([]byte(nil), root.Material...)
	case passphrase != "":
		keyBytes = pbkdf2.Key([]byte(passphrase), []byte("ydx/kms/at-rest/v1"), pbkdf2Iterations, 32, sha256.New)
	default:
		return nil, nil
	}
	switch len(keyBytes) {
	case 16, 24, 32:
	default:
		zeroBytes(keyBytes)
		return nil, errs.Detail(ErrInvalidConfig, "at-rest key must be 16, 24 or 32 bytes, got %[1]d | 静态密钥必须为 16、24 或 32 字节，实际 %[1]d", len(keyBytes))
	}
	block, err := aes.NewCipher(keyBytes)
	zeroBytes(keyBytes)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidConfig)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidConfig)
	}
	return &atRestWrapper{aead: aead}, nil
}

// Wrap encrypts material with a fresh nonce and metadata-bound AAD. | Wrap 使用新 nonce 与绑定元数据的 AAD 加密材料。
func (w *atRestWrapper) Wrap(_ context.Context, keyID string, version uint32, material []byte) ([]byte, error) {
	if w == nil || w.aead == nil {
		return nil, ErrInvalidConfig
	}
	if len(material) == 0 {
		return nil, nil
	}
	nonce, err := randomBytes(gcmNonceSize)
	if err != nil {
		return nil, err
	}
	aad := atRestAAD(keyID, version)
	out := make([]byte, 0, len(atRestMagic)+len(nonce)+len(material)+w.aead.Overhead())
	out = append(out, atRestMagic...)
	out = append(out, nonce...)
	out = w.aead.Seal(out, nonce, material, aad)
	return out, nil
}

// Unwrap decrypts material produced by Wrap. | Unwrap 解密 Wrap 产生的材料。
func (w *atRestWrapper) Unwrap(_ context.Context, keyID string, version uint32, wrapped []byte) ([]byte, error) {
	if w == nil || w.aead == nil {
		return nil, ErrInvalidConfig
	}
	if !bytes.HasPrefix(wrapped, atRestMagic) {
		return nil, errs.Detail(ErrInvalidMaterial, "missing at-rest material magic | 缺少静态材料魔数")
	}
	rest := wrapped[len(atRestMagic):]
	if len(rest) < gcmNonceSize+w.aead.Overhead() {
		return nil, errs.Detail(ErrInvalidMaterial, "truncated wrapped material | 包装材料被截断")
	}
	nonce := rest[:gcmNonceSize]
	plain, err := w.aead.Open(nil, nonce, rest[gcmNonceSize:], atRestAAD(keyID, version))
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidMaterial, "at-rest unwrap failed | 静态解包失败")
	}
	return plain, nil
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
	if s.wrapper == nil {
		return stored, nil
	}
	version := stored.Version
	if version == 0 {
		version = 1
	}
	if len(stored.Material) > 0 {
		wrapped, err := s.wrapper.Wrap(ctx, stored.ID, version, stored.Material)
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
		wrapped, err := s.wrapper.Wrap(ctx, stored.ID, item.Version, item.Material)
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
	if s.wrapper == nil {
		if bytes.HasPrefix(loaded.Material, atRestMagic) {
			return nil, errs.Detail(ErrInvalidConfig, "material is wrapped but no wrapper is configured | 材料已包装但未配置包装器")
		}
		return loaded, nil
	}
	if len(loaded.Material) > 0 {
		version := loaded.Version
		if version == 0 {
			version = 1
		}
		plain, err := s.wrapper.Unwrap(ctx, loaded.ID, version, loaded.Material)
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
		plain, err := s.wrapper.Unwrap(ctx, loaded.ID, item.Version, item.Material)
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
