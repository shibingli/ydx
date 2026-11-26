package raft

import (
	"sync/atomic"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/wal"
)

// dataCipher is the immutable FileStorage encryption policy plus the mutable
// active key used for new artifacts. | dataCipher 是 FileStorage 的不可变加密策略
// 以及用于新产物的可变活动密钥。
type dataCipher struct {
	ring                *keyRing
	walRing             *wal.KeyRing
	active              atomic.Pointer[keyMaterial]
	chunkSize           int
	targets             EncryptionTargets
	allowPlaintextWAL   bool
	allowPlaintextFiles bool
}

// newDataCipher validates FileStorage encryption options. It returns nil when
// encryption is disabled. | newDataCipher 校验 FileStorage 加密选项；加密关闭时
// 返回 nil。
func newDataCipher(opts EncryptionOptions) (*dataCipher, error) {
	if len(opts.Keys) == 0 {
		if opts.Targets != 0 || opts.ActiveKeyID != 0 {
			return nil, errs.Detail(ErrInvalidConfig,
				"encryption targets or active key require keys | 加密目标或活动密钥需要配置密钥")
		}
		return nil, nil
	}
	if opts.Targets&^EncryptAll != 0 {
		return nil, errs.Detail(ErrInvalidConfig, "unknown encryption targets %d | 未知加密目标 %d", opts.Targets, opts.Targets)
	}
	targets := opts.Targets
	if targets == 0 {
		targets = EncryptAll
	}
	ring, active, err := newKeyRing(opts.Keys, opts.ActiveKeyID)
	if err != nil {
		return nil, err
	}
	chunkSize, err := encryptionChunkSize(opts.ChunkSize)
	if err != nil {
		return nil, err
	}
	cipher := &dataCipher{
		ring:                ring,
		targets:             targets,
		chunkSize:           chunkSize,
		allowPlaintextWAL:   opts.AllowPlaintextWAL,
		allowPlaintextFiles: opts.AllowPlaintextFiles,
	}
	cipher.active.Store(active)
	if targets&EncryptWAL != 0 {
		walKeys := make([]wal.Key, 0, len(ring.order))
		for _, id := range ring.order {
			key := ring.keys[id]
			suite, ok := key.suite.walSuite()
			if !ok {
				return nil, errs.Detail(ErrInvalidKey,
					"WAL encryption supports only AES-256-GCM and SM4-GCM, key %d uses %s | WAL 加密仅支持 AES-256-GCM 与 SM4-GCM，密钥 %d 使用 %s",
					key.id, key.suite, key.id, key.suite)
			}
			walKeys = append(walKeys, wal.Key{ID: key.id, Suite: suite, Bytes: key.master})
		}
		walRing, err := wal.NewKeyRing(active.id, walKeys...)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidKey)
		}
		cipher.walRing = walRing
	}
	return cipher, nil
}

// encrypts reports whether a target is enabled. | encrypts 报告某个目标是否启用。
func (c *dataCipher) encrypts(target EncryptionTargets) bool {
	return c != nil && c.targets&target != 0
}

// activeKey returns the current write key. | activeKey 返回当前写密钥。
func (c *dataCipher) activeKey() *keyMaterial {
	if c == nil {
		return nil
	}
	return c.active.Load()
}

// setActiveKey switches the write key for new snapshots and hard state. |
// setActiveKey 切换新快照与硬状态使用的写密钥。
func (c *dataCipher) setActiveKey(key *keyMaterial) {
	c.active.Store(key)
}

// SetActiveEncryptionKey switches the key used for new WAL records, snapshot
// files and HARDSTATE. The key must exist in the configured ring and, when WAL
// encryption is enabled, must use AES-256-GCM or SM4-GCM. Old artifacts remain
// readable while their key stays in the ring. A WAL still running under the
// AllowPlaintextWAL migration policy cannot rotate and returns ErrInvalidConfig.
// | SetActiveEncryptionKey 切换新 WAL 记录、快照文件与 HARDSTATE 使用的密钥。密钥
// 必须存在于已配置的密钥环中；启用 WAL 加密时必须使用 AES-256-GCM 或 SM4-GCM。
// 只要旧密钥仍留在环中，旧数据仍可读取。仍处于 AllowPlaintextWAL 迁移策略的明文
// WAL 无法轮换，会返回 ErrInvalidConfig。
func (s *FileStorage) SetActiveEncryptionKey(id uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStopped
	}
	cipher := s.cipher
	if cipher == nil {
		return errs.Detail(ErrInvalidConfig, "encryption is not configured | 未配置加密")
	}
	key, ok := cipher.ring.keys[id]
	if !ok {
		return errs.Detail(ErrKeyNotFound, "key ID %[1]d is not in the ring | 密钥 ID %[1]d 不在密钥环中", id)
	}
	if cipher.walRing != nil {
		if _, ok := key.suite.walSuite(); !ok {
			return errs.Detail(ErrInvalidKey,
				"WAL encryption supports only AES-256-GCM and SM4-GCM | WAL 加密仅支持 AES-256-GCM 与 SM4-GCM")
		}
		if !s.loaded {
			if _, err := s.loadLocked(); err != nil {
				return err
			}
		}
		if err := s.wlog.setActiveKey(id); err != nil {
			return err
		}
	}
	cipher.setActiveKey(key)
	return nil
}
