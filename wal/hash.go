package wal

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"sync"

	"github.com/shibingli/ydx/guomi"
)

// hashState pools one reusable digest state per algorithm. | hashState 按算法池化可复用的摘要状态。
var (
	sha256Pool = sync.Pool{New: func() any { return sha256.New() }}
	sm3Pool    = sync.Pool{New: func() any { return guomi.New() }}
)

// digestKeyData returns the 32-byte digest of key || data using alg. This
// unframed form is persisted by dedup references, write keys, and transaction
// controls; do not change it without a format version. Callers that need to
// distinguish field splits must use digestRecordContent. | digestKeyData 使用
// alg 计算 key || data 的 32 字节摘要。该无框架形式被去重引用、写键与事务控制
// 持久化，不得在无格式版本的情况下修改；需要区分字段切分的调用方必须使用
// digestRecordContent。
func digestKeyData(alg HashAlgorithm, key, data []byte) [32]byte {
	return digestParts(alg, key, data)
}

// digestRecordContent hashes len(key) || key || len(data) || data so that
// different key/data splits of the same concatenation do not collide. It is
// used only for the in-memory idempotency window. | digestRecordContent 对
// len(key) || key || len(data) || data 做摘要，使相同拼接的不同字段切分不会
// 碰撞；仅用于内存幂等窗口。
func digestRecordContent(alg HashAlgorithm, key, data []byte) [32]byte {
	var hdr [16]byte
	binary.LittleEndian.PutUint64(hdr[0:], uint64(len(key)))
	binary.LittleEndian.PutUint64(hdr[8:], uint64(len(data)))
	return digestParts(alg, hdr[:], key, data)
}

// digestParts hashes parts in order. | digestParts 按顺序摘要各分片。
func digestParts(alg HashAlgorithm, parts ...[]byte) [32]byte {
	var h hash.Hash
	switch alg {
	case HashSM3:
		h = sm3Pool.Get().(hash.Hash)
	default:
		h = sha256Pool.Get().(hash.Hash)
	}
	h.Reset()
	for _, p := range parts {
		if len(p) > 0 {
			_, _ = h.Write(p)
		}
	}
	var out [32]byte
	sum := h.Sum(out[:0])
	if len(sum) >= 32 {
		copy(out[:], sum[:32])
	}
	h.Reset()
	if alg == HashSM3 {
		sm3Pool.Put(h)
	} else {
		sha256Pool.Put(h)
	}
	return out
}

// hashName returns the stable algorithm name. | hashName 返回稳定的算法名称。
func hashName(alg HashAlgorithm) string {
	if alg == HashSM3 {
		return "SM3"
	}
	return "SHA-256"
}
