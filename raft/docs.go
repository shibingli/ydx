// Package raft implements a high-throughput, strongly consistent Raft replica
// with a single-group Node core and a multi-group NodeHost, durable WAL
// storage, snapshots, joint-consensus membership changes, linearizable reads,
// and pluggable TCP, HTTP and RDMA transports. | Package raft 实现高吞吐、强一致的
// Raft 副本，包含单组 Node 核心与多组 NodeHost、持久化 WAL、快照、联合共识成员变更、
// 线性一致读，以及可插拔的 TCP、HTTP 与 RDMA 传输。
//
// # Consistency | 一致性
//
// A successful Propose has been committed by a majority and applied locally.
// ReadIndex returns a committed index that is linearizable with the call; use
// WaitApplied or Barrier before reading the state machine. The leader serves a
// read from its lease only after committing an entry in its current term;
// otherwise it confirms leadership with a heartbeat quorum. Followers forward
// ReadIndex to the leader and wait for their own apply loop. | 成功的 Propose 已被
// 多数派提交并在本地应用。ReadIndex 返回与调用线性一致的已提交索引；读取状态机前
// 使用 WaitApplied 或 Barrier。领导者只有在已提交当前任期日志项后才用租约服务读；
// 否则通过心跳法定人数确认领导权。跟随者将 ReadIndex 转发给领导者，并等待本地应用
// 循环追上。
//
// # Quick start | 快速开始
//
// A single-node node with memory storage is useful for tests: | 单节点内存存储示例：
//
//	fsm := &myFSM{}
//	store := raft.NewMemStorage()
//	node, err := raft.New(raft.Config{
//		ID: 1, Storage: store, FSM: fsm,
//	})
//	if err != nil { /* handle */ }
//	defer node.Close()
//
//	res, err := node.Propose(ctx, []byte("set key=value"))
//
// A three-node TCP cluster uses NewTCPTransport and the same Config.Peers on
// every node: | 三节点 TCP 集群在每个节点使用 NewTCPTransport 与相同的 Config.Peers：
//
//	tr, err := raft.NewTCPTransport(raft.TCPTransportOptions{
//		ListenAddr: "192.168.2.2:22102",
//	})
//	peers := []raft.Peer{
//		{ID: 1, Addr: "192.168.2.2:22102"},
//		{ID: 2, Addr: "192.168.2.3:22102"},
//		{ID: 3, Addr: "192.168.2.4:22102"},
//	}
//	node, err := raft.New(raft.Config{
//		ID: 1, Peers: peers, Storage: store, FSM: fsm, Transport: tr,
//	})
//
// # HTTP transport | HTTP 传输
//
// The YD router is the first-class entry point. HTTPTransport.Handler returns a
// standard http.Handler, and its ServeHTTP method value is directly assignable
// to router.HandlerFuncRaw, so no adapter module or extra dependency is needed:
// mounting shares the router's middleware chain, authentication and
// observability. The same handler also works with net/http. | YD 路由是一等入口。
// HTTPTransport.Handler 返回标准 http.Handler，其 ServeHTTP 方法值可直接赋给
// router.HandlerFuncRaw，因此无需适配模块或额外依赖：挂载后共享路由器的中间件链、
// 认证与可观测性；同一个处理器也适用于原生 net/http。
//
//	tr, _ := raft.NewHTTPTransport(raft.HTTPTransportOptions{
//		ID: 1, Path: "/raft/message", SharedSecret: secret,
//	})
//
//	// YD router: same underlying func type, no raft/ydrouter package | YD 路由：
//	// 底层函数类型相同，无需 raft/ydrouter 包
//	r := router.New()
//	r.HandleRaw(http.MethodPost, "/raft/message", tr.Handler().ServeHTTP)
//
//	// plain net/http compatibility | 原生 net/http 兼容
//	http.Handle("/raft/message", tr.Handler())
//
// Peers then use base URLs such as "http://192.168.2.2:23102". Set
// SharedSecret for HMAC-SHA256 authentication and put TLS in front of the
// server for confidentiality. | 此时 Peers 使用 "http://192.168.2.2:23102" 这类
// 基础 URL。设置 SharedSecret 启用 HMAC-SHA256 认证，并在服务器前使用 TLS 提供
// 保密性。
//
// # Security and limits | 安全与上限
//
// Inbound messages are not authenticated by default. Every multi-node deployment
// must configure TLS and/or SharedSecret (at least 16 bytes); use both for
// encryption plus frame integrity. RDMA needs HMAC plus IPsec/MACsec for
// confidentiality. TCP MaxFrameBytes and HTTP MaxBodyBytes must exceed the
// largest encoded snapshot unless chunking is enabled. Config.SnapshotChunkBytes
// transfers large images as ack-gated MsgSnapChunk messages, removing the
// transport frame limit; the receiver still reassembles the whole image, so the
// protocol cap of 256 MiB remains. Chunk messages are an opt-in extension and
// require every peer to support them. Without chunking, a leader logs an
// explicit error when a snapshot cannot fit instead of retrying silently. |
// 入站消息默认不认证。所有多节点部署必须配置 TLS 和/或至少 16 字节的
// SharedSecret；两者同时使用可同时获得加密与帧完整性。RDMA 需要 HMAC 与
// IPsec/MACsec 才能保密。TCP MaxFrameBytes 与 HTTP MaxBodyBytes 必须大于最大快照
// 的编码大小，除非启用分块。Config.SnapshotChunkBytes 通过逐块确认的
// MsgSnapChunk 传输大镜像，解除传输帧上限；接收端仍会重组完整镜像，因此协议上限
// 256 MiB 仍然有效。分块消息是显式扩展，要求所有对端支持。未启用分块时，快照无法
// 放下会让领导者记录明确错误，而不是静默重试。
//
// Committed entries are applied only after the local WAL persist completes, so a
// crash cannot expose effects of an entry that was never durable locally. WAL
// group commit keeps the encoding contiguous even when append retries overlap.
// FileStorage keeps term/vote/commit in a dedicated HARDSTATE file; recovery
// merges it with the WAL hard state. A follower can therefore vote while a large
// snapshot image is being written, instead of leaving the group leaderless until
// the snapshot fsync finishes. | 已提交日志项只会在本地 WAL 持久化完成后应用，因此
// 崩溃不会暴露本地从未持久化日志项的副作用。即使追加重试重叠，WAL 组提交仍保持
// 编码区间连续。FileStorage 将 term/vote/commit 保存在独立的 HARDSTATE 文件中，
// 恢复时与 WAL 硬状态合并；跟随者因此能在大型快照镜像写入期间应答选票，而不是让
// 组一直无 leader 到快照 fsync 结束。
//
// # Snapshots | 快照
//
// FileStorage writes local images outside the WAL persist goroutine and records
// a small marker afterwards; the marker can share one WAL record and fsync with
// following entries. An FSM may implement StreamingFSM to write the image
// directly to a temporary file instead of materializing a full []byte. Large
// images with Config.SnapshotChunkBytes enabled are sent as bounded, ack-gated
// chunks and read from the file on demand; small snapshots keep a memory copy so
// a single MsgSnap does not touch the filesystem on the event loop.
// FileStorageOptions.SnapshotChecksum can select CRC32C-only images for very
// large states, and SnapshotDir can place images on a separate volume. |
// FileStorage 在 WAL persist 协程之外写入本地镜像，随后记录小型标记；标记可与
// 后续日志项共享一条 WAL 记录和一次 fsync。FSM 可实现 StreamingFSM，将镜像直接
// 写入临时文件，而不在内存中生成完整 []byte。启用 Config.SnapshotChunkBytes 后，
// 大镜像以有界、逐块确认的消息发送并按需从文件读取；小快照保留内存副本，避免单条
// MsgSnap 在事件循环上访问文件系统。FileStorageOptions.SnapshotChecksum 可为超大
// 状态选择仅 CRC32C 镜像，SnapshotDir 可把镜像放到独立卷。
//
// # RDMA transport | RDMA 传输
//
// Real RDMA is an optional build on Linux/amd64 or Linux/arm64 with -tags rdma.
// It uses ydx/rdma, which loads libibverbs through purego at run time and does
// not require cgo; libibverbs.so.1 must be installed. The default pure-Go stub
// returns ErrUnsupported when RDMA is requested. Frames larger than one
// registered slot are chunked, so snapshots and large batches do not need
// oversized slot registrations. | 真实 RDMA 是 Linux/amd64 或 Linux/arm64 下的
// 可选构建，使用 -tags rdma。它依赖 ydx/rdma，经 purego 在运行时加载
// libibverbs，不需要 cgo；系统需安装 libibverbs.so.1。默认纯 Go 桩在请求 RDMA
// 时返回 ErrUnsupported。大于一个注册槽位的帧会被分块，因此快照与大日志批次无需
// 注册超大槽位。
//
//	cfg.RDMA = true
//	cfg.RDMAOptions = raft.RDMATransportOptions{
//		ListenAddr: "192.168.2.2:22102",
//	}
//
// Build with: | 构建命令：
//
//	CGO_ENABLED=0 go build -tags rdma ./...
//
// An explicit Config.Transport always wins over Config.RDMA. RDMA is reliable,
// not encrypted; use IPsec/MACsec or the TLS-enabled TCP/HTTP transports for
// confidentiality. SharedSecret adds frame-level HMAC authentication. | 显式
// Config.Transport 优先于 Config.RDMA。RDMA 提供可靠传输但不加密；保密性请使用
// IPsec/MACsec 或启用 TLS 的 TCP/HTTP 传输。SharedSecret 增加帧级 HMAC 认证。
//
// # Multi-group NodeHost | 多组 NodeHost
//
// NodeHost runs many Raft groups on one member. Groups share the node identity
// and one base transport; messages are multiplexed by GroupID. Each group has
// its own WAL directory, FSM, log, election state, snapshots and apply worker.
// | NodeHost 在一个成员上运行多个 Raft 组。组共享节点身份与一条基础传输；消息按
// GroupID 多路复用。每组拥有独立的 WAL 目录、FSM、日志、选举状态、快照与 apply
// 协程。
//
//	host, err := raft.NewNodeHost(raft.NodeHostConfig{
//		ID:        1,
//		Transport: tcpTransport,
//		Storage:   raft.FileStorageFactory("/data/raft", raft.FileStorageOptions{}),
//		FSM:       func(g raft.GroupID) (raft.FSM, error) { return openFSM(g) },
//	})
//	if err != nil { /* handle */ }
//	defer host.Close()
//	_, err = host.StartGroup(raft.GroupConfig{ID: 10, Peers: peers})
//	res, err := host.Propose(ctx, 10, []byte("set key=value"))
//
// ListGroups scans group-<id> directories for restart recovery. Group IDs must be
// stable and non-zero. | ListGroups 扫描 group-<id> 目录用于重启恢复。组 ID 必须稳定
// 且非零。
//
// # Concurrency and tuning | 并发与调优
//
// Control traffic (elections, heartbeats, leadership transfer and snapshots)
// uses a dedicated high-priority queue, so a saturated replication backlog
// cannot starve the messages that keep the cluster alive. Proposals are
// appended in batches; clients that keep several ProposeAsync calls in flight
// amortize persistence, replication and apply. The intake is lock-striped
// across producers, and a synchronous Propose reuses its Future and proposal
// after completion to keep the hot path allocation-light. PersistBatchDelay
// adds an optional group-commit window for fsync-bound storage; it delays only
// the durable acknowledgement and never blocks the Raft event loop. | 控制流量
// （选举、心跳、领导权转移与快照）使用独立高优先级队列，饱和的复制积压无法饿死维持
// 集群存活的消息。提案按批追加；保持多个 ProposeAsync 在途的客户端可分摊持久化、
// 复制与应用成本。提案入口按生产者锁分片，同步 Propose 在完成后复用 Future 与提案
// 对象，使热路径保持低分配。PersistBatchDelay 为 fsync 主导的存储提供可选组提交
// 窗口；它只延迟持久化确认，绝不阻塞 Raft 事件循环。
//
// # Durability | 持久化
//
// FileStorage writes CRC-checked WAL segments with group commit and atomic
// snapshot files protected by CRC32C and SHA-256. A snapshot file is trusted
// only when a durable WAL marker names it, so a crash between the file write
// and the marker leaves the previous log intact. InstallSnapshot markers reset
// stale log entries; local compaction snapshots keep the valid tail. Local
// compaction also retains up to SnapshotCatchUpEntries covered entries in
// memory so slightly lagging followers can catch up with AppendEntries; that
// window is not recovered after a restart. The storage directory is locked
// against a second writer. | FileStorage 写入带 CRC 校验的 WAL 分段（组提交）以及
// 由 CRC32C 与 SHA-256 保护的原子快照文件。只有持久 WAL 标记引用快照文件时才会
// 信任它，因此文件写入与标记之间的崩溃会保留旧日志。InstallSnapshot 标记会丢弃
// 陈旧日志项；本地压缩快照保留有效尾部，并在内存中额外保留最多
// SnapshotCatchUpEntries 条已覆盖日志，使略落后的跟随者可用 AppendEntries 追上；
// 该窗口重启后不会恢复。存储目录带进程级排他锁。
//
// # State machine contract | 状态机契约
//
// FSM.Apply, FSM.Snapshot and FSM.Restore run on one goroutine in log order.
// Do not call them concurrently. Entry data is owned by the node after Propose;
// Propose copies it, while ProposeOwned transfers ownership. | FSM.Apply、
// FSM.Snapshot 与 FSM.Restore 在单个协程上按日志顺序运行，不得并发调用。Propose
// 后日志项数据归节点所有；Propose 会复制数据，ProposeOwned 转移所有权。
//
// # Membership | 成员变更
//
// AddNode, AddLearner, Promote and RemoveNode use joint consensus and allow one
// change at a time. The changed configuration takes effect when its entry is
// appended; the leader automatically appends the LeaveJoint entry after the
// joint entry commits. Learners receive entries but do not vote. | AddNode、
// AddLearner、Promote 与 RemoveNode 使用联合共识，同一时间只允许一个变更。配置在
// 日志项被追加时生效；联合配置日志项提交后，领导者自动追加 LeaveJoint 日志项。
// 学习者接收日志但不投票。
//
// # Observability and lifecycle | 可观测性与生命周期
//
// Stats returns lock-free counters. Status is assembled by the event loop. Both
// implement MarshalJSON through ydx/json with stable snake_case fields and a
// named state, suitable for admin HTTP APIs. Close stops the node and closes its
// Storage and Transport; callers must not call Close from an event-loop
// callback. | Stats 返回无锁计数器。Status 由事件循环组装。两者都通过 ydx/json
// 实现 MarshalJSON，使用稳定的 snake_case 字段与名称化状态，适合管理 HTTP API。
// Close 停止节点并关闭其 Storage 与 Transport；调用方不得在事件循环回调中调用
// Close。
package raft
