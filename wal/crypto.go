package wal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"sort"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/guomi"
)

// Suite selects a record encryption algorithm. | Suite 选择记录加密算法。
type Suite uint8

const (
	// SuiteAESGCM is AES-256-GCM, the default international suite. | SuiteAESGCM 是默认的国际套件 AES-256-GCM。
	SuiteAESGCM Suite = iota
	// SuiteSM4GCM is SM4-GCM, the Chinese national suite. | SuiteSM4GCM 是国密套件 SM4-GCM。
	SuiteSM4GCM
)

// Key is one master key in a KeyRing. | Key 是 KeyRing 中的一个主密钥。
type Key struct {
	ID    uint32
	Suite Suite
	Bytes []byte
}

// KeyRing is an immutable set of master keys. | KeyRing 是不可变的主密钥集合。
type KeyRing struct {
	suggested uint32
	keys      map[uint32]*keyMaterial
	order     []uint32
}

// keyMaterial is one deep-copied master key. | keyMaterial 是一个深拷贝的主密钥。
type keyMaterial struct {
	id     uint32
	suite  Suite
	master []byte
}

// NewKeyRing validates and deep-copies master keys. The suggestedActiveID is
// used only for an empty WAL; zero selects the smallest key ID. | NewKeyRing
// 校验并深拷贝主密钥；suggestedActiveID 仅用于空 WAL，0 表示选择最小密钥 ID。
func NewKeyRing(suggestedActiveID uint32, keys ...Key) (*KeyRing, error) {
	if len(keys) == 0 {
		return nil, errs.Detail(ErrInvalidKey, "key ring is empty | 密钥环为空")
	}
	r := &KeyRing{keys: make(map[uint32]*keyMaterial, len(keys))}
	for _, k := range keys {
		if k.ID == 0 {
			return nil, errs.Detail(ErrInvalidKey, "key ID 0 is reserved for plaintext | 密钥 ID 0 保留给明文")
		}
		if _, ok := r.keys[k.ID]; ok {
			return nil, errs.Detail(ErrInvalidKey, "duplicate key ID %[1]d | 重复密钥 ID %[1]d", k.ID)
		}
		if k.Suite > SuiteSM4GCM {
			return nil, errs.Detail(ErrInvalidKey, "unknown suite %[1]d for key %[2]d | 密钥 %[2]d 的套件 %[1]d 未知", k.Suite, k.ID)
		}
		want := 32
		if k.Suite == SuiteSM4GCM {
			want = guomi.SM4KeySize
		}
		if len(k.Bytes) != want {
			return nil, errs.Detail(ErrInvalidKey, "key %[1]d has %[2]d bytes, want %[3]d | 密钥 %[1]d 有 %[2]d 字节，期望 %[3]d",
				k.ID, len(k.Bytes), want)
		}
		r.keys[k.ID] = &keyMaterial{id: k.ID, suite: k.Suite, master: append([]byte(nil), k.Bytes...)}
		r.order = append(r.order, k.ID)
	}
	sort.Slice(r.order, func(i, j int) bool { return r.order[i] < r.order[j] })
	if suggestedActiveID == 0 {
		suggestedActiveID = r.order[0]
	} else if _, ok := r.keys[suggestedActiveID]; !ok {
		return nil, errs.Detail(ErrInvalidKey, "suggested key ID %[1]d is not in the ring | 建议密钥 ID %[1]d 不在密钥环中", suggestedActiveID)
	}
	r.suggested = suggestedActiveID
	return r, nil
}

// SuggestedActiveID returns the key ID suggested for an empty WAL. | SuggestedActiveID
// 返回空 WAL 使用的建议密钥 ID。
func (r *KeyRing) SuggestedActiveID() uint32 {
	if r == nil {
		return 0
	}
	return r.suggested
}

// has reports whether the ring contains id. | has 返回密钥环是否包含 id。
func (r *KeyRing) has(id uint32) bool {
	_, ok := r.keys[id]
	return ok
}

// boundKey holds per-WAL derived material. | boundKey 保存每个 WAL 派生的密钥材料。
type boundKey struct {
	id    uint32
	suite Suite
	key   []byte
	aead  cipher.AEAD
	kcv   uint64
}

// boundRing holds keys derived with one WAL ID. | boundRing 保存以某个 WAL ID 派生的一组密钥。
type boundRing struct {
	keys map[uint32]*boundKey
}

// bind derives per-WAL data keys with HKDF-SHA256. | bind 使用 HKDF-SHA256 派生每个 WAL 的数据密钥。
func (r *KeyRing) bind(walID [16]byte) (*boundRing, error) {
	if r == nil {
		return nil, errs.Detail(ErrInvalidKey, "nil key ring | 密钥环为 nil")
	}
	br := &boundRing{keys: make(map[uint32]*boundKey, len(r.keys))}
	for id, km := range r.keys {
		keyLen := 32
		if km.suite == SuiteSM4GCM {
			keyLen = guomi.SM4KeySize
		}
		dataKey, err := hkdf.Key(sha256.New, km.master, walID[:], "ydx/wal/record", keyLen)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidKey, "derive key %d | 派生密钥 %d 失败", id, id)
		}
		aead, err := newAEAD(km.suite, dataKey)
		if err != nil {
			zero(dataKey)
			return nil, err
		}
		kcvKey, err := hkdf.Key(sha256.New, km.master, walID[:], "ydx/wal/kcv", keyLen)
		if err != nil {
			zero(dataKey)
			return nil, errs.WrapDetail(err, ErrInvalidKey, "derive KCV key %d | 派生 KCV 密钥 %d 失败", id, id)
		}
		kcvAEAD, err := newAEAD(km.suite, kcvKey)
		if err != nil {
			zero(dataKey)
			zero(kcvKey)
			return nil, err
		}
		kcv := computeKCV(kcvAEAD)
		zero(kcvKey)
		br.keys[id] = &boundKey{id: id, suite: km.suite, key: dataKey, aead: aead, kcv: kcv}
	}
	return br, nil
}

// close zeroes derived key material. | close 清零派生密钥材料。
func (b *boundRing) close() {
	if b == nil {
		return
	}
	for _, k := range b.keys {
		zero(k.key)
		k.key = nil
		k.aead = nil
	}
	b.keys = nil
}

// key returns a derived key. | key 返回派生密钥。
func (b *boundRing) key(id uint32) (*boundKey, error) {
	k, ok := b.keys[id]
	if !ok {
		return nil, errs.Detail(ErrKeyNotFound, "key ID %[1]d is not in the ring | 密钥 ID %[1]d 不在密钥环中", id)
	}
	return k, nil
}

// newAEAD builds a GCM AEAD for one suite. | newAEAD 为一种套件构建 GCM AEAD。
func newAEAD(suite Suite, key []byte) (cipher.AEAD, error) {
	switch suite {
	case SuiteAESGCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidKey)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidKey)
		}
		return aead, nil
	case SuiteSM4GCM:
		aead, err := guomi.NewGCM(key)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidKey)
		}
		return aead, nil
	default:
		return nil, errs.Detail(ErrInvalidKey, "unknown suite %[1]d | 未知套件 %[1]d", suite)
	}
}

// diskCipher maps an API suite to the on-disk cipher byte. | diskCipher 把 API 套件映射为磁盘 cipher 值。
func diskCipher(suite Suite) byte {
	if suite == SuiteSM4GCM {
		return cipherSM4GCM
	}
	return cipherAESGCM
}

// suiteFromCipher maps a disk cipher byte to an API suite. | suiteFromCipher 把磁盘 cipher 值映射为 API 套件。
func suiteFromCipher(c byte) (Suite, bool) {
	switch c {
	case cipherAESGCM:
		return SuiteAESGCM, true
	case cipherSM4GCM:
		return SuiteSM4GCM, true
	default:
		return 0, false
	}
}

// kcvPlain and kcvNonce are the fixed KCV inputs. | kcvPlain 与 kcvNonce 是固定的 KCV 输入。
var (
	kcvPlain = []byte("YDXWALKCV01!")
	kcvNonce = make([]byte, nonceSize)
)

// computeKCV returns the first 8 ciphertext bytes of the fixed KCV seal. The
// AEAD is built from the dedicated HKDF info "ydx/wal/kcv", so its nonce space
// is disjoint from record encryption. The plaintext is the 12 ASCII bytes
// "YDXWALKCV01!", the nonce is 12 zero bytes, and the AAD is empty. | computeKCV
// 返回固定 KCV 加密结果的前 8 个密文字节。AEAD 使用专用 HKDF info
// "ydx/wal/kcv" 派生，nonce 空间与记录加密不相交。明文为 12 字节 ASCII
// "YDXWALKCV01!"，nonce 为 12 个零字节，AAD 为空。
func computeKCV(aead cipher.AEAD) uint64 {
	sealed := aead.Seal(nil, kcvNonce, kcvPlain, nil)
	return binary.LittleEndian.Uint64(sealed[:8])
}

// nonceGen produces salt||counter nonces for one WAL instance. | nonceGen 为一个 WAL 实例生成 salt||counter nonce。
type nonceGen struct {
	salt    [8]byte
	counter uint32
	ready   bool
}

// newNonceGen creates a random salt. | newNonceGen 创建随机 salt。
func newNonceGen() (*nonceGen, error) {
	g := &nonceGen{}
	if _, err := rand.Read(g.salt[:]); err != nil {
		return nil, errs.Wrap(err, ErrRandomSource)
	}
	g.ready = true
	return g, nil
}

// next returns the next 12-byte nonce. When the 32-bit counter wraps, a fresh
// salt is generated before continuing. | next 返回下一个 12 字节 nonce；32 位
// 计数器回绕时先重新生成 salt 再继续。
func (g *nonceGen) next() ([12]byte, error) {
	var out [12]byte
	if !g.ready {
		if _, err := rand.Read(g.salt[:]); err != nil {
			return out, errs.Wrap(err, ErrRandomSource)
		}
		g.counter = 0
		g.ready = true
	}
	if g.counter == math.MaxUint32 {
		if _, err := rand.Read(g.salt[:]); err != nil {
			return out, errs.Wrap(err, ErrRandomSource)
		}
		g.counter = 0
	}
	copy(out[:8], g.salt[:])
	binary.BigEndian.PutUint32(out[8:], g.counter)
	g.counter++
	return out, nil
}

// cryptoRandRead fills p from crypto/rand. | cryptoRandRead 用 crypto/rand 填充 p。
func cryptoRandRead(p []byte) (int, error) { return rand.Read(p) }

// zero clears a byte slice. | zero 清零字节切片。
func zero(p []byte) {
	for i := range p {
		p[i] = 0
	}
}
