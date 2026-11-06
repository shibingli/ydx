package wal

import (
	"crypto/sha256"
	"hash"
	"sync"

	"github.com/shibingli/ydx/guomi"
)

// hashState pools one reusable digest state per algorithm. | hashState 按算法池化可复用的摘要状态。
var (
	sha256Pool = sync.Pool{New: func() any { return sha256.New() }}
	sm3Pool    = sync.Pool{New: func() any { return guomi.New() }}
)

// digestKeyData returns the 32-byte digest of key || data using alg. | digestKeyData
// 使用 alg 计算 key || data 的 32 字节摘要。
func digestKeyData(alg HashAlgorithm, key, data []byte) [32]byte {
	var h hash.Hash
	switch alg {
	case HashSM3:
		h = sm3Pool.Get().(hash.Hash)
	default:
		h = sha256Pool.Get().(hash.Hash)
	}
	h.Reset()
	if len(key) > 0 {
		_, _ = h.Write(key)
	}
	if len(data) > 0 {
		_, _ = h.Write(data)
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
