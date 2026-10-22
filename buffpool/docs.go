// Package bufpool provides a size-classed pool of reusable byte buffers.
// | Package bufpool 提供按尺寸分级复用的字节缓冲池。
//
// Buffers are grouped into fixed size classes, one sync.Pool per class, so a
// request for a few hundred bytes never occupies a quarter-megabyte block and
// a large response never forces small allocations to follow it. | 缓冲按固定尺寸
// 分级，每级一个 sync.Pool；因此几百字节的请求不会占用 256 KiB 的大块，大响应也
// 不会迫使小分配跟随它迁移。
//
// Get returns a slice whose length is zero and whose capacity is at least the
// requested size, so appending within that capacity never reallocates. | Get 返回
// 长度为 0、容量不小于请求值的切片，因此在该容量内 append 不会再次分配。
//
// The contents of a returned buffer are NOT guaranteed to be zero. A caller
// that handles secrets, or that otherwise relies on a zero-filled buffer, must
// clear it explicitly before use. | 返回缓冲的内容**不保证为零值**。处理敏感数据或
// 以零值缓冲为前提的调用方必须在使用前自行清零。
//
// Put accepts a buffer only when its capacity is exactly one of the size
// classes and never exceeds MaxSize; everything else is dropped instead of
// pooled, so one oversized request cannot inflate the pool's retained memory.
// | Put 只接纳容量恰好等于某一分级且不超过 MaxSize 的缓冲，其余一律丢弃而不归还，
// 避免个别超大请求把池的常驻内存撑大。
//
// A buffer passed to Put must not be used afterwards: ownership returns to the
// pool and the same memory may be handed out to another goroutine. | 传给 Put 的
// 缓冲此后不得继续使用：所有权已归还池，同一块内存可能被交给其它 goroutine。
//
// Typical usage | 典型用法：
//
//	buf := bufpool.Get(4096)
//	defer bufpool.Put(buf)
package bufpool
