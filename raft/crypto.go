package raft

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/guomi"
	"github.com/shibingli/ydx/wal"
)

const (
	// encryptionEnvelopeMagic prefixes one-shot ciphertexts. | encryptionEnvelopeMagic
	// 是一次性密文的前缀魔数。
	encryptionEnvelopeMagic = "YDRENC01"
	// encryptionEnvelopeVersion is the current one-shot envelope version. |
	// encryptionEnvelopeVersion 是当前一次性信封版本。
	encryptionEnvelopeVersion = byte(1)
	// encryptionHeaderSize is magic, version, key ID, suite and nonce. |
	// encryptionHeaderSize 是魔数、版本、密钥 ID、套件与 nonce 的长度。
	encryptionHeaderSize = 8 + 1 + 4 + 1 + encryptionNonceSize
	// encryptionNonceSize matches the GCM and ChaCha20-Poly1305 nonce size. |
	// encryptionNonceSize 与 GCM 和 ChaCha20-Poly1305 的 nonce 长度一致。
	encryptionNonceSize = 12
	// encryptionTagSize is the AEAD tag overhead for every supported suite. |
	// encryptionTagSize 是所有受支持套件的 AEAD 标签开销。
	encryptionTagSize = 16
	// defaultEncryptionChunkSize is the plaintext block sealed by each streaming
	// chunk. | defaultEncryptionChunkSize 是每个流式分块封装的明文字节数。
	defaultEncryptionChunkSize = 64 << 10
	// maxEncryptionChunkSize bounds the allocation requested by a chunk header.
	// | maxEncryptionChunkSize 限制分块头部可请求的分配大小。
	maxEncryptionChunkSize = 16 << 20

	// infoOneShot, infoStream, infoSnapshot and infoHardState domain-separate
	// keys derived from one master key. | infoOneShot、infoStream、infoSnapshot
	// 与 infoHardState 用不同用途隔离同一主密钥派生出的密钥。
	infoOneShot   = "ydx/raft/oneshot"
	infoStream    = "ydx/raft/stream"
	infoSnapshot  = "ydx/raft/snapshot"
	infoHardState = "ydx/raft/hardstate"
)

// EncryptionSuite selects an AEAD algorithm for data at rest. The numeric values
// are part of the snapshot and hard-state file formats and must not change.
// | EncryptionSuite 选择静态数据使用的 AEAD 算法；数值属于快照与硬状态文件格式，
// 不得修改。
type EncryptionSuite uint8

const (
	// EncryptionAES256GCM is AES-256-GCM, the default international suite. |
	// EncryptionAES256GCM 是默认的国际套件 AES-256-GCM。
	EncryptionAES256GCM EncryptionSuite = iota
	// EncryptionChaCha20Poly1305 is ChaCha20-Poly1305, an international suite
	// useful on platforms without AES hardware acceleration. It is available to
	// Encryptor and to snapshots/hard state, but not to the WAL, whose record
	// encryption supports only AES-256-GCM and SM4-GCM. | EncryptionChaCha20Poly1305
	// 是国际套件 ChaCha20-Poly1305，适合没有 AES 硬件加速的平台。它可用于
	// Encryptor 以及快照/硬状态，但 WAL 记录加密只支持 AES-256-GCM 与 SM4-GCM。
	EncryptionChaCha20Poly1305
	// EncryptionSM4GCM is SM4-GCM (GB/T 32907-2016), the Chinese national suite.
	// | EncryptionSM4GCM 是国密套件 SM4-GCM（GB/T 32907-2016）。
	EncryptionSM4GCM
)

// String returns the canonical suite name. | String 返回套件的规范名称。
func (s EncryptionSuite) String() string {
	switch s {
	case EncryptionAES256GCM:
		return "AES-256-GCM"
	case EncryptionChaCha20Poly1305:
		return "ChaCha20-Poly1305"
	case EncryptionSM4GCM:
		return "SM4-GCM"
	default:
		return "unknown"
	}
}

// keySize returns the required master key length. | keySize 返回要求的主密钥长度。
func (s EncryptionSuite) keySize() int {
	if s == EncryptionSM4GCM {
		return guomi.SM4KeySize
	}
	return 32
}

// valid reports whether the suite is known. | valid 报告套件是否已知。
func (s EncryptionSuite) valid() bool {
	return s <= EncryptionSM4GCM
}

// walSuite maps a suite onto the ydx/wal record encryption suite. Only AES and
// SM4 are supported by the WAL. | walSuite 把套件映射为 ydx/wal 记录加密套件；
// WAL 仅支持 AES 与 SM4。
func (s EncryptionSuite) walSuite() (wal.Suite, bool) {
	switch s {
	case EncryptionAES256GCM:
		return wal.SuiteAESGCM, true
	case EncryptionSM4GCM:
		return wal.SuiteSM4GCM, true
	default:
		return 0, false
	}
}

// EncryptionKey is one master key in an EncryptionOptions ring. Bytes is copied
// when the ring is built, so callers may release or wipe their slice afterwards.
// | EncryptionKey 是 EncryptionOptions 密钥环中的一个主密钥。构建密钥环时会深拷贝
// Bytes，调用方随后可释放或清零自己的切片。
type EncryptionKey struct {
	// Bytes is the raw key: 32 bytes for AES-256-GCM and ChaCha20-Poly1305,
	// 16 bytes for SM4-GCM. | Bytes 是原始密钥：AES-256-GCM 与 ChaCha20-Poly1305
	// 为 32 字节，SM4-GCM 为 16 字节。
	Bytes []byte
	// ID identifies the key in file headers and WAL records; zero is reserved
	// for plaintext. | ID 在文件头与 WAL 记录中标识密钥；零保留给明文。
	ID uint32
	// Suite selects the AEAD algorithm for this key. | Suite 选择该密钥的 AEAD 算法。
	Suite EncryptionSuite
}

// EncryptionTargets is a bit set selecting which durable artifacts FileStorage
// encrypts. Combine targets with |. | EncryptionTargets 是选择 FileStorage 加密哪些
// 持久化数据的位集合，可用 | 组合。
type EncryptionTargets uint8

const (
	// EncryptWAL encrypts ydx/wal record payloads. | EncryptWAL 加密 ydx/wal 记录负载。
	EncryptWAL EncryptionTargets = 1 << iota
	// EncryptSnapshots encrypts snapshot image files. | EncryptSnapshots 加密快照镜像文件。
	EncryptSnapshots
	// EncryptHardState encrypts the dedicated HARDSTATE file. | EncryptHardState
	// 加密独立 HARDSTATE 文件。
	EncryptHardState
	// EncryptAll enables every target. | EncryptAll 启用全部加密目标。
	EncryptAll = EncryptWAL | EncryptSnapshots | EncryptHardState
)

// EncryptionOptions configures data-at-rest encryption for FileStorage and the
// reusable Encryptor. Empty Keys disables encryption. When Keys is non-empty and
// Targets is zero, all targets are encrypted. | EncryptionOptions 配置 FileStorage
// 的静态数据加密以及可复用的 Encryptor。Keys 为空表示关闭加密；Keys 非空且
// Targets 为零时加密全部目标。
type EncryptionOptions struct {
	// Keys is the master key ring. At least one key is required to enable
	// encryption. | Keys 是主密钥环；启用加密时至少需要一个密钥。
	Keys []EncryptionKey
	// ChunkSize is the plaintext bytes sealed by one streaming or snapshot
	// chunk. Zero uses 64 KiB; the maximum is 16 MiB. | ChunkSize 是单个流式或快照
	// 分块封装的明文字节数；零表示 64 KiB，上限 16 MiB。
	ChunkSize int
	// ActiveKeyID selects the key used for new snapshots and HARDSTATE, and the
	// initial key for an empty WAL. An existing encrypted WAL keeps its persisted
	// active key; use FileStorage.SetActiveEncryptionKey to rotate it. Zero
	// selects the smallest key ID. Decryption accepts every key in the ring, so
	// rotation only needs the old and new keys present. | ActiveKeyID 选择新快照与
	// HARDSTATE 使用的密钥，以及空 WAL 的初始密钥。既有加密 WAL 保持其已持久化的
	// 活动密钥；轮换它请使用 FileStorage.SetActiveEncryptionKey。零表示最小密钥 ID。
	// 解密接受密钥环中的任意密钥，因此轮换只需同时保留新旧密钥。
	ActiveKeyID uint32
	// Targets selects encrypted artifacts for FileStorage. NewEncryptor ignores
	// this field. | Targets 选择 FileStorage 加密的目标；NewEncryptor 忽略该字段。
	Targets EncryptionTargets
	// AllowPlaintextWAL permits opening an existing non-empty plaintext WAL while
	// a key ring is configured. The WAL keeps its persisted plaintext policy;
	// enabling encryption on existing data requires a fresh WAL directory. |
	// AllowPlaintextWAL 允许在配置密钥环时打开已有的非空明文 WAL。WAL 保持其已
	// 持久化的明文策略；要在已有数据上启用加密，必须使用新的 WAL 目录。
	AllowPlaintextWAL bool
	// AllowPlaintextFiles permits reading existing plaintext snapshot and
	// HARDSTATE files while the corresponding encryption target is enabled. It is
	// a migration switch; leave it false in encrypted deployments so a plaintext
	// downgrade cannot replace an authenticated file. | AllowPlaintextFiles 允许在
	// 对应加密目标启用时读取既有明文快照与 HARDSTATE。它是迁移开关；加密部署应保持
	// false，避免明文文件被用于降级替换。
	AllowPlaintextFiles bool
}

// Encryptor is an immutable key ring for one-shot and streaming AEAD. It is safe
// for concurrent use. | Encryptor 是用于一次性与流式 AEAD 的不可变密钥环，可安全
// 并发使用。
type Encryptor struct {
	ring      *keyRing
	active    *keyMaterial
	chunkSize int
}

// NewEncryptor validates keys and builds a cipher for one-shot and streaming
// encryption. Keys are deep-copied. Storage-only options (Targets,
// AllowPlaintextWAL and AllowPlaintextFiles) are ignored. | NewEncryptor 校验密钥
// 并构建用于一次性与流式加密的加密器；密钥会被深拷贝。仅存储使用的选项
// （Targets、AllowPlaintextWAL 与 AllowPlaintextFiles）会被忽略。
func NewEncryptor(opts EncryptionOptions) (*Encryptor, error) {
	ring, active, err := newKeyRing(opts.Keys, opts.ActiveKeyID)
	if err != nil {
		return nil, err
	}
	chunkSize, err := encryptionChunkSize(opts.ChunkSize)
	if err != nil {
		return nil, err
	}
	return &Encryptor{ring: ring, active: active, chunkSize: chunkSize}, nil
}

// ActiveKeyID returns the key used for new ciphertexts. | ActiveKeyID 返回新密文
// 使用的密钥。
func (e *Encryptor) ActiveKeyID() uint32 {
	if e == nil || e.active == nil {
		return 0
	}
	return e.active.id
}

// ActiveSuite returns the suite used for new ciphertexts. | ActiveSuite 返回新密文
// 使用的套件。
func (e *Encryptor) ActiveSuite() EncryptionSuite {
	if e == nil || e.active == nil {
		return 0
	}
	return e.active.suite
}

// ChunkSize returns the plaintext bytes per streaming chunk. | ChunkSize 返回每个
// 流式分块的明文字节数。
func (e *Encryptor) ChunkSize() int {
	if e == nil {
		return 0
	}
	return e.chunkSize
}

// WithActiveKey returns an Encryptor sharing this key ring but using id for new
// ciphertexts. It enables rotation without rebuilding the ring; the receiver is
// unchanged. | WithActiveKey 返回共享当前密钥环、但使用 id 生成新密文的 Encryptor，
// 无需重建密钥环即可轮换；接收者本身不变。
func (e *Encryptor) WithActiveKey(id uint32) (*Encryptor, error) {
	if e == nil || e.ring == nil {
		return nil, errs.Detail(ErrInvalidKey, "nil encryptor | 加密器为空")
	}
	key, ok := e.ring.keys[id]
	if !ok {
		return nil, errs.Detail(ErrKeyNotFound, "key ID %[1]d is not in the ring | 密钥 ID %[1]d 不在密钥环中", id)
	}
	return &Encryptor{ring: e.ring, active: key, chunkSize: e.chunkSize}, nil
}

// Encrypt seals plaintext and prepends a self-describing envelope holding the
// magic, version, key ID, suite and nonce. aad is authenticated but not stored.
// dst is appended to and must not overlap plaintext. | Encrypt 加密 plaintext 并
// 前置自描述信封，包含魔数、版本、密钥 ID、套件与 nonce；aad 只参与认证、不存储。
// 结果追加到 dst，且 dst 不得与 plaintext 重叠。
func (e *Encryptor) Encrypt(dst, plaintext, aad []byte) ([]byte, error) {
	if e == nil || e.active == nil {
		return nil, errs.Detail(ErrInvalidKey, "nil encryptor | 加密器为空")
	}
	aead, err := e.active.contextAEAD(infoOneShot)
	if err != nil {
		return nil, err
	}
	var header [encryptionHeaderSize]byte
	copy(header[:8], encryptionEnvelopeMagic)
	header[8] = encryptionEnvelopeVersion
	binary.LittleEndian.PutUint32(header[9:13], e.active.id)
	header[13] = byte(e.active.suite)
	if _, err := rand.Read(header[14:]); err != nil {
		return nil, errs.Wrap(err, ErrRandom)
	}
	bound := bindAAD(header[:], aad)
	return aead.Seal(append(dst, header[:]...), header[14:], plaintext, bound), nil
}

// Decrypt opens an envelope produced by Encrypt. The key is selected by the
// envelope's key ID, so any key still in the ring can decrypt old data. dst is
// appended to and must not overlap ciphertext. | Decrypt 解密 Encrypt 生成的信封。
// 密钥由信封中的密钥 ID 选择，因此密钥环中保留的任意旧密钥都能解密旧数据。结果追加
// 到 dst，且 dst 不得与 ciphertext 重叠。
func (e *Encryptor) Decrypt(dst, ciphertext, aad []byte) ([]byte, error) {
	if e == nil || e.ring == nil {
		return nil, errs.Detail(ErrInvalidKey, "nil encryptor | 加密器为空")
	}
	if len(ciphertext) < encryptionHeaderSize+encryptionTagSize {
		return nil, errs.Detail(ErrAuth, "ciphertext too short | 密文过短")
	}
	header := ciphertext[:encryptionHeaderSize]
	if string(header[:8]) != encryptionEnvelopeMagic {
		return nil, errs.Detail(ErrAuth, "bad envelope magic | 信封魔数错误")
	}
	if header[8] != encryptionEnvelopeVersion {
		return nil, errs.Detail(ErrAuth, "unsupported envelope version %d | 信封版本 %d 不受支持", header[8], header[8])
	}
	keyID := binary.LittleEndian.Uint32(header[9:13])
	suite := EncryptionSuite(header[13])
	if !suite.valid() {
		return nil, errs.Detail(ErrAuth, "unknown suite %d | 未知套件 %d", header[13], header[13])
	}
	key, ok := e.ring.keys[keyID]
	if !ok {
		return nil, errs.Detail(ErrKeyNotFound, "key ID %[1]d is not in the ring | 密钥 ID %[1]d 不在密钥环中", keyID)
	}
	if key.suite != suite {
		return nil, errs.Detail(ErrAuth,
			"key %d suite %s does not match envelope suite %s | 密钥 %d 套件 %s 与信封套件 %s 不匹配",
			keyID, key.suite, suite, keyID, key.suite, suite)
	}
	aead, err := key.contextAEAD(infoOneShot)
	if err != nil {
		return nil, err
	}
	bound := bindAAD(header, aad)
	plain, err := aead.Open(dst, header[14:], ciphertext[encryptionHeaderSize:], bound)
	if err != nil {
		return nil, errs.Wrap(err, ErrAuth)
	}
	return plain, nil
}

// encryptionChunkSize normalizes and validates a configured chunk size. |
// encryptionChunkSize 规范化并校验配置的分块大小。
func encryptionChunkSize(size int) (int, error) {
	if size == 0 {
		return defaultEncryptionChunkSize, nil
	}
	if size < 0 || size > maxEncryptionChunkSize {
		return 0, errs.Detail(ErrInvalidConfig,
			"encryption chunk size %d outside 1..%d | 加密分块大小 %d 超出 1..%d",
			size, maxEncryptionChunkSize, size, maxEncryptionChunkSize)
	}
	return size, nil
}

// bindAAD concatenates the envelope header and caller additional data. |
// bindAAD 拼接信封头部与调用方附加数据。
func bindAAD(header, aad []byte) []byte {
	bound := make([]byte, 0, len(header)+len(aad))
	bound = append(bound, header...)
	return append(bound, aad...)
}
