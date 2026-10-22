// Package cachex is the framework's two-level cache. | Package cachex 是框架的二级缓存。
//
// A Manager owns one first-level cache shared by every namespace and, optionally, one
// remote store (Redis). Cache values are serialized into byte envelopes in L1 as well as
// in L2, which keeps the two levels byte-identical and keeps long-lived Go object graphs
// out of the heap: a cache holding hundreds of megabytes adds almost nothing for the
// garbage collector to scan. | Manager 拥有一个由所有命名空间共享的一级缓存，以及可选的
// 远端存储（Redis）。缓存值在一级与二级中都以字节信封保存，使两层字节完全一致，也让长生命
// 周期的 Go 对象图远离堆：即使缓存持有数百兆字节，垃圾回收器需要扫描的对象也几乎不增加。
//
// Consistency model: | 一致性模型：
//
//   - Writes go to L2 first, then update L1 and publish an invalidation event. Every
//     node deletes its L1 entry when the event arrives. | 写入先到 L2，再更新 L1 并发布
//     失效事件；每个节点在事件到达时删除自己的 L1 条目。
//   - Every L2 entry carries a monotonically increasing version. Read-through loads use
//     a compare-and-set write-back, so a slow loader can never overwrite a newer write.
//     | 每个 L2 条目携带单调递增的版本号；读透加载用 CAS 回填，因此慢加载永远无法覆盖
//     更新的写入。
//   - An L1 entry lives at most Lease, even when its value lives longer. A lost Pub/Sub
//     message therefore bounds staleness by Lease, and a reconnect flushes L1 entirely.
//     | L1 条目最长只存活 Lease；丢失的 Pub/Sub 消息因此把陈旧窗口限制在 Lease 内，
//     重连则会整体清空 L1。
//
// Zero copy: Raw.View and Raw.GetOrLoadView hand the stored bytes to a callback without
// copying them out of the ring; typed caches decode inside that callback. | 零拷贝：
// Raw.View 与 Raw.GetOrLoadView 把已存字节直接交给回调，不再从环形缓冲区复制；泛型缓存
// 就在回调内完成解码。
//
// It is not a distributed lock, not a database, and it does not silently hide L2 write
// failures; callers choose the read failure policy with FailOpen. | 它不是分布式锁、不是
// 数据库，也不静默隐藏 L2 写失败；读失败策略由调用方通过 FailOpen 选择。
//
// Typical usage | 典型用法：
//
//	mgr, err := cachex.NewManager(cachex.WithOptions(o))
//	if err != nil {
//		return err
//	}
//	raw, err := mgr.Raw("users")
//	if err != nil {
//		return err
//	}
//	_ = raw
package cachex
