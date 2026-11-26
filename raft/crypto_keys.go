package raft

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"sync"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/guomi"
	"golang.org/x/crypto/chacha20poly1305"
)

// keyMaterial is one deep-copied master key and its lazily derived context
// AEADs. | keyMaterial 是一个深拷贝的主密钥及其按用途惰性派生的 AEAD。
type keyMaterial struct {
	aead   map[string]cipher.AEAD
	master []byte
	mu     sync.Mutex
	id     uint32
	suite  EncryptionSuite
}

// keyRing is an immutable map of master keys plus the active write key. |
// keyRing 是不可变的主密钥映射及活动写密钥。
type keyRing struct {
	keys  map[uint32]*keyMaterial
	order []uint32
}

// newKeyRing validates and deep-copies master keys. Zero activeID selects the
// smallest key ID. | newKeyRing 校验并深拷贝主密钥；activeID 为零时选择最小密钥 ID。
func newKeyRing(keys []EncryptionKey, activeID uint32) (*keyRing, *keyMaterial, error) {
	if len(keys) == 0 {
		return nil, nil, errs.Detail(ErrInvalidKey, "key ring is empty | 密钥环为空")
	}
	ring := &keyRing{keys: make(map[uint32]*keyMaterial, len(keys))}
	for _, key := range keys {
		if key.ID == 0 {
			return nil, nil, errs.Detail(ErrInvalidKey, "key ID 0 is reserved for plaintext | 密钥 ID 0 保留给明文")
		}
		if _, ok := ring.keys[key.ID]; ok {
			return nil, nil, errs.Detail(ErrInvalidKey, "duplicate key ID %[1]d | 重复密钥 ID %[1]d", key.ID)
		}
		if !key.Suite.valid() {
			return nil, nil, errs.Detail(ErrInvalidKey, "unknown suite %[1]d for key %[2]d | 密钥 %[2]d 的套件 %[1]d 未知",
				key.Suite, key.ID)
		}
		want := key.Suite.keySize()
		if len(key.Bytes) != want {
			return nil, nil, errs.Detail(ErrInvalidKey,
				"key %[1]d has %[2]d bytes, want %[3]d | 密钥 %[1]d 有 %[2]d 字节，期望 %[3]d",
				key.ID, len(key.Bytes), want)
		}
		material := &keyMaterial{
			id:     key.ID,
			suite:  key.Suite,
			master: append([]byte(nil), key.Bytes...),
			aead:   make(map[string]cipher.AEAD, 2),
		}
		ring.keys[key.ID] = material
		ring.order = append(ring.order, key.ID)
	}
	// Keys arrive in caller order; sort IDs so zero ActiveKeyID is deterministic.
	// | 密钥按调用方顺序传入；排序 ID 使零 ActiveKeyID 的选择确定。
	for i := 1; i < len(ring.order); i++ {
		for j := i; j > 0 && ring.order[j] < ring.order[j-1]; j-- {
			ring.order[j], ring.order[j-1] = ring.order[j-1], ring.order[j]
		}
	}
	if activeID == 0 {
		activeID = ring.order[0]
	}
	active, ok := ring.keys[activeID]
	if !ok {
		return nil, nil, errs.Detail(ErrKeyNotFound, "active key ID %[1]d is not in the ring | 活动密钥 ID %[1]d 不在密钥环中", activeID)
	}
	return ring, active, nil
}

// contextAEAD returns the AEAD derived for one domain-separated context. The
// derivation is cached because context keys never rotate. | contextAEAD 返回某个
// 用途隔离上下文派生出的 AEAD；上下文密钥不会轮换，因此结果会被缓存。
func (k *keyMaterial) contextAEAD(info string) (cipher.AEAD, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if aead, ok := k.aead[info]; ok {
		return aead, nil
	}
	key, err := hkdf.Key(sha256.New, k.master, nil, info, k.suite.keySize())
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidKey, "derive %s key %d | 派生 %s 密钥 %d 失败", info, k.id, info, k.id)
	}
	aead, err := newAEAD(k.suite, key)
	zero(key)
	if err != nil {
		return nil, err
	}
	k.aead[info] = aead
	return aead, nil
}

// deriveAEAD derives a per-stream or per-file AEAD with an explicit salt. |
// deriveAEAD 使用显式 salt 派生每个流或每个文件专用的 AEAD。
func (k *keyMaterial) deriveAEAD(salt []byte, info string) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, k.master, salt, info, k.suite.keySize())
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidKey, "derive %s key %d | 派生 %s 密钥 %d 失败", info, k.id, info, k.id)
	}
	aead, err := newAEAD(k.suite, key)
	zero(key)
	if err != nil {
		return nil, err
	}
	return aead, nil
}

// newAEAD builds the AEAD for one suite. | newAEAD 为一种套件构建 AEAD。
func newAEAD(suite EncryptionSuite, key []byte) (cipher.AEAD, error) {
	switch suite {
	case EncryptionAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidKey)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidKey)
		}
		return aead, nil
	case EncryptionChaCha20Poly1305:
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidKey)
		}
		return aead, nil
	case EncryptionSM4GCM:
		aead, err := guomi.NewGCM(key)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidKey)
		}
		return aead, nil
	default:
		return nil, errs.Detail(ErrInvalidKey, "unknown suite %d | 未知套件 %d", suite, suite)
	}
}

// zero clears a byte slice. | zero 清零字节切片。
func zero(p []byte) {
	for i := range p {
		p[i] = 0
	}
}
