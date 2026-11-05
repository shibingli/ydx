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
// The YD router is the first-class entry point. The raft/ydrouter module mounts
// the transport as a POST route on an existing router, sharing its middleware
// chain, authentication and observability; the same HTTPTransport.Handler is
// also a standard net/http handler for compatibility. | YD 路由是一等入口。
// raft/ydrouter 模块把传输挂载为现有路由器上的 POST 路由，共享中间件链、认证与
// 可观测性；同一个 HTTPTransport.Handler 也是标准 net/http 处理器，用于兼容。
//
//	tr, _ := raft.NewHTTPTransport(raft.HTTPTransportOptions{
//		ID: 1, Path: "/raft/message", SharedSecret: secret,
//	})
//
//	// YD router first | YD 路由优先
//	r := router.New()
//	if err := ydrouter.Mount(r, "/raft/message", tr); err != nil {
//		// handle
//	}
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
// stale log entries; local compaction snapshots keep the valid tail. | FileStorage
// 写入带 CRC 校验的 WAL 分段（组提交）以及由 CRC32C 与 SHA-256 保护的原子快照文件。
// 只有持久 WAL 标记引用快照文件时才会信任它，因此文件写入与标记之间的崩溃会保留旧
// 日志。InstallSnapshot 标记会丢弃陈旧日志项；本地压缩快照保留有效尾部。
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
// Stats returns lock-free counters. Status is assembled by the event loop.
// Close stops the node and closes its Storage and Transport; callers must not
// call Close from an event-loop callback. | Stats 返回无锁计数器。Status 由事件
// 循环组装。Close 停止节点并关闭其 Storage 与 Transport；调用方不得在事件循环回调
// 中调用 Close。
package raft
