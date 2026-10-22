package buffpool

import (
	"sync"
	"unsafe"
)

// tierSizes is the ascending list of pool size classes. | tierSizes 是池的尺寸分级，
// 按升序排列。
var tierSizes = [...]int{
	1 << 10,   // 1 KiB | 1 KiB
	4 << 10,   // 4 KiB | 4 KiB
	16 << 10,  // 16 KiB | 16 KiB
	64 << 10,  // 64 KiB | 64 KiB
	256 << 10, // 256 KiB | 256 KiB
}

// MaxSize is the largest capacity the pool retains. | MaxSize 是池保留的最大容量。
// A Put with a larger capacity drops the buffer. | Put 传入更大容量时直接丢弃该缓冲。
const MaxSize = 256 << 10

// pools holds one sync.Pool per size class. | pools 为每个尺寸分级持有一个 sync.Pool。
//
// Items are *byte pointers to the first byte of a class-sized block rather than
// slice headers: putting a []byte into an interface would heap-allocate a copy
// of the slice header, while a one-word pointer boxes allocation-free. | 池中存放的
// 是指向该分级内存块首字节的 *byte，而不是切片头：把 []byte 放进接口会为切片头的
// 副本做一次堆分配，而单字指针装箱不会分配。
var pools [len(tierSizes)]sync.Pool

// Get returns a zero-length slice with capacity of at least n. | Get 返回长度为零、
// 容量不小于 n 的切片。
//
// The smallest size class that fits n is used; n <= 0 selects the smallest class
// and n > MaxSize allocates an exactly sized buffer outside the pool. | 选用能容纳 n
// 的最小分级；n <= 0 选择最小分级，n > MaxSize 则在池外分配恰好大小的缓冲。
// The contents are not guaranteed to be zero. | 内容不保证为零值。
func Get(n int) []byte {
	if i := classForSize(n); i >= 0 {
		if v := pools[i].Get(); v != nil {
			return unsafe.Slice(v.(*byte), tierSizes[i])[:0]
		}
		return make([]byte, tierSizes[i])[:0]
	}
	return make([]byte, n)[:0]
}

// Put returns a buffer to the pool. | Put 把缓冲归还到池中。
//
// The buffer is pooled only when its capacity is exactly one of the size classes;
// oversized or oddly sized buffers are dropped. The caller must not use p after
// Put. | 仅当容量恰好等于某一分级时才会归还；超大或非分级容量的缓冲一律丢弃。
// 调用方在 Put 之后不得继续使用 p。
func Put(p []byte) {
	i := classForCapacity(cap(p))
	if i < 0 {
		return
	}
	// A one-word interior pointer keeps the block alive without boxing a slice header.
	// | 单字内部指针即可保活内存块，且无需装箱切片头。
	pools[i].Put(&p[:tierSizes[i]][0])
}

// classForSize returns the index of the smallest class holding at least n bytes,
// or -1 when n exceeds MaxSize. | classForSize 返回容量不小于 n 的最小分级下标；
// n 超过 MaxSize 时返回 -1。
func classForSize(n int) int {
	if n <= 0 {
		return 0
	}
	for i, size := range tierSizes {
		if n <= size {
			return i
		}
	}
	return -1
}

// classForCapacity returns the index of the class whose size equals capacity,
// or -1 when no class matches. | classForCapacity 返回尺寸恰好等于 capacity 的分级
// 下标；没有匹配时返回 -1。
func classForCapacity(capacity int) int {
	for i, size := range tierSizes {
		if capacity == size {
			return i
		}
	}
	return -1
}
