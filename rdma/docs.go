// Package rdma is a zero-copy, batch-first RDMA transport for Linux built on
// libibverbs through purego. It requires no cgo: the library is loaded at
// runtime, and builds without the rdma tag compile a stub that returns
// ErrUnsupported. | rdma 包是基于 libibverbs、经 purego 调用的零拷贝、批量优先
// Linux RDMA 传输库。它不需要 cgo：运行时加载共享库；没有 rdma 构建标签时编译
// 桩实现并返回 ErrUnsupported。
//
// # 功能 | Features
//
//   - RC、UC、UD 队列对，PD、CQ、SRQ、AH、注册内存区与内存池 | RC, UC and UD
//     queue pairs, PD, CQ, SRQ, AH, registered memory regions and pools
//   - SEND/RECV、RDMA WRITE/READ、WRITE_WITH_IMM、比较交换与取加原子操作 |
//     SEND/RECV, RDMA WRITE/READ, WRITE_WITH_IMM, compare-and-swap and
//     fetch-and-add atomics
//   - RoCE v1、RoCE v2 与原生 InfiniBand；默认自动选择可路由的 RoCE v2 GID |
//     RoCE v1, RoCE v2 and native InfiniBand; routable RoCE v2 GIDs by default
//   - 批量提交与批量轮询：一次调用提交整条工作请求链，一次调用取回多个完成事件 |
//     Batch posting and polling: one call posts a work request chain, one call
//     reaps several completions
//   - 预注册大页内存池、零拷贝发送、零拷贝接收与批量回收 | Pre-registered huge
//     page pools, zero-copy send, zero-copy receive and batch recycling
//   - 直接调用 ibv_context_ops 热路径函数指针，不经 libibverbs 的 inline 包装 |
//     Hot paths call ibv_context_ops function pointers directly, without the
//     libibverbs inline wrappers
//   - 可通过 Config.VerbsLibrary 指定任意发行版的 libibverbs 路径 | Config.
//     VerbsLibrary selects any distribution's libibverbs path
//
// # 构建 | Build
//
// 默认构建（无 rdma 标签）为纯 Go 桩实现。真实 RDMA 需要 Linux、64 位架构与
// rdma 构建标签；运行时必须有 libibverbs： | The default build (no rdma tag) is
// a pure Go stub. Real RDMA needs Linux, a 64-bit architecture, the rdma build
// tag and libibverbs at run time:
//
//	GOWORK=off CGO_ENABLED=0 go build -tags rdma ./...
//
// libibverbs 的查找顺序为可移植 soname "libibverbs.so.1"、"libibverbs.so"，
// 然后是 Debian/Ubuntu、RHEL/Fedora、SUSE 与 Mellanox OFED 的常见路径。可用
// Config.VerbsLibrary 显式覆盖。 | libibverbs is searched by the portable
// sonames "libibverbs.so.1" and "libibverbs.so", then by the common paths of
// Debian/Ubuntu, RHEL/Fedora, SUSE and Mellanox OFED. Config.VerbsLibrary
// overrides the search.
//
// # 快速开始：零拷贝消息连接 | Quick start: zero-copy message connection
//
// 服务端： | Server:
//
//	cfg := rdma.DefaultConnConfig()
//	ln, err := rdma.Listen("192.168.2.2:2030", cfg)
//	if err != nil {
//		return err
//	}
//	defer ln.Close()
//	conn, err := ln.Accept()
//	if err != nil {
//		return err
//	}
//	defer conn.Close()
//	for {
//		buf, n, err := conn.RecvBuffer()
//		if err != nil {
//			return err
//		}
//		process(buf.Bytes()[:n])
//		if err := conn.Release(buf); err != nil {
//			return err
//		}
//	}
//
// 客户端： | Client:
//
//	conn, err := rdma.Dial("192.168.2.2:2030", cfg)
//	if err != nil {
//		return err
//	}
//	defer conn.Close()
//	buf, err := conn.Alloc(len(msg))
//	if err != nil {
//		return err
//	}
//	copy(buf.Bytes(), msg)
//	return conn.SendBuffer(buf, len(msg))
//
// Send/Recv 是复制便利接口；Alloc/SendBuffer 与 RecvBuffer/Release 走零拷贝
// 路径。SendBatch/SendBatchBuffers 与 RecvBuffers/ReleaseBatch 批量提交与回收。
// 一个 Conn 不得被多个协程同时使用，每个工作协程使用独立 Conn。 | Send/Recv
// are copying conveniences; Alloc/SendBuffer and RecvBuffer/Release are the
// zero-copy path. SendBatch/SendBatchBuffers and RecvBuffers/ReleaseBatch batch
// posting and recycling. A Conn must not be shared by goroutines; use one Conn
// per worker.
//
// # 底层 verbs | Low-level verbs
//
//	cfg := rdma.DefaultConfig()
//	dev, err := rdma.Open(cfg)
//	if err != nil {
//		return err
//	}
//	defer dev.Close()
//	pool, err := dev.NewPool(rdma.PoolConfig{Slots: 1024, SlotSize: 4096})
//	if err != nil {
//		return err
//	}
//	defer pool.Close()
//	cq, err := dev.NewCQ(2048)
//	if err != nil {
//		return err
//	}
//	defer cq.Close()
//	qp, err := dev.NewQP(rdma.DefaultQPConfig(cq))
//	if err != nil {
//		return err
//	}
//	defer qp.Close()
//	local := qp.LocalInfo(0x1234)
//	// 与对端交换 ConnectInfo（TCP、配置文件或任意控制通道）| exchange
//	// ConnectInfo with the peer over TCP or any control channel
//	if err := qp.Connect(local, remote); err != nil {
//		return err
//	}
//	buf, _ := pool.Acquire()
//	_, err = qp.PostRecv([]rdma.RecvWR{{
//		WRID: 1, Addr: buf.Addr(), Length: uint32(buf.Len()), LKey: buf.LKey(),
//	}})
//
// # 性能建议 | Performance notes
//
//   - 热路径使用忙轮询；Conn 的 RecvBuffer/Alloc 在无进展时先自旋 4096 次再
//     让出处理器。对最低延迟，调用 runtime.LockOSThread 并用 taskset 固定核心 |
//     Hot paths busy-poll; Conn spins 4096 times before yielding. For the
//     lowest latency, call runtime.LockOSThread and pin the core with taskset
//   - 每连接使用独立 Conn，发送用 SendBatchBuffers，接收用 RecvBuffers 与
//     ReleaseBatch | use one Conn per connection, send with SendBatchBuffers and
//     receive with RecvBuffers/ReleaseBatch
//   - NewMR/NewPool 优先申请 2 MiB 大页，失败时回退透明大页；部署时可预留
//     vm.nr_hugepages | NewMR/NewPool prefer 2 MiB huge pages and fall back to
//     transparent huge pages; reserve vm.nr_hugepages in deployment
//   - 路径 MTU 取端口活动 MTU 与对端 MTU 的较小值；提高交换机与网卡 MTU 后
//     需要整条路径支持，否则会出现 retry-exceeded | the path MTU is the
//     smaller of the local active MTU and the peer MTU; raising it requires
//     jumbo frame support on the whole path, otherwise sends fail with
//     retry-exceeded
//   - 原子操作取回的原始值由设备按网络字节序写回本地缓冲区；使用
//     encoding/binary.BigEndian 读取 | atomic fetch results are written back
//     in network byte order; read them with encoding/binary.BigEndian
//
// # 并发与生命周期 | Concurrency and lifetime
//
// Device 拥有 PD；CQ、QP、MR、Pool 必须在 Device.Close 之前关闭。QP 的投递与
// Poll 不应并发调用。Conn 的热路径是单协程模型。 | A Device owns its PD; CQ,
// QP, MR and Pool must be closed before Device.Close. QP posting and polling
// must not be called concurrently. Conn's hot path is single-goroutine.
//
// # 错误 | Errors
//
// 所有可判定错误均为 errs 哨兵，调用方使用 errors.Is 判定，例如
// ErrUnsupported、ErrInvalidConfig、ErrNoDevice、ErrNoGID、ErrQueueFull、
// ErrTimeout、ErrConnReset 与 ErrHandshake。 | All matchable errors are errs
// sentinels; use errors.Is with ErrUnsupported, ErrInvalidConfig, ErrNoDevice,
// ErrNoGID, ErrQueueFull, ErrTimeout, ErrConnReset and ErrHandshake.
package rdma
