package rdma

import (
	"fmt"
	"sync"
	"sync/atomic"
)

// MaxSGE is the largest scatter/gather entry count accepted by one work
// request. Four entries cover the common zero-copy layouts without a second
// allocation per post. | MaxSGE 是单个工作请求接受的最大分散/聚集项数。四项
// 足以覆盖常见零拷贝布局，且每次提交无需二次分配。
const MaxSGE = 4

// QPType selects the transport service of a queue pair. Values match the
// Ibverbs queue pair types. | QPType 选择队列对的传输服务。取值与 Ibverbs
// 队列对类型一致。
type QPType uint32

// Queue pair types. | 队列对类型。
const (
	// QPTypeRC is reliable connected. | QPTypeRC 是可靠连接。
	QPTypeRC QPType = 2
	// QPTypeUC is unreliable connected. | QPTypeUC 是不可靠连接。
	QPTypeUC QPType = 3
	// QPTypeUD is unreliable datagram. | QPTypeUD 是不可靠数据报。
	QPTypeUD QPType = 4
)

// String returns the English queue pair type name. | String 返回队列对类型英文名。
func (t QPType) String() string {
	switch t {
	case QPTypeRC:
		return "RC"
	case QPTypeUC:
		return "UC"
	case QPTypeUD:
		return "UD"
	default:
		return "unknown"
	}
}

// QPState is the queue pair state. Values match Ibverbs. | QPState 是队列对
// 状态，取值与 Ibverbs 一致。
type QPState uint32

// Queue pair states. | 队列对状态。
const (
	// QPStateReset is the reset state. | QPStateReset 是复位状态。
	QPStateReset QPState = 0
	// QPStateInit is the initialised state. | QPStateInit 是初始化状态。
	QPStateInit QPState = 1
	// QPStateRTR is ready to receive. | QPStateRTR 是就绪接收状态。
	QPStateRTR QPState = 2
	// QPStateRTS is ready to send. | QPStateRTS 是就绪发送状态。
	QPStateRTS QPState = 3
	// QPStateSQD is send queue drain. | QPStateSQD 是发送队列排空状态。
	QPStateSQD QPState = 4
	// QPStateSQE is send queue error. | QPStateSQE 是发送队列错误状态。
	QPStateSQE QPState = 5
	// QPStateErr is the error state. | QPStateErr 是错误状态。
	QPStateErr QPState = 6
)

// String returns the English queue pair state name. | String 返回队列对状态英文名。
func (s QPState) String() string {
	switch s {
	case QPStateReset:
		return "reset"
	case QPStateInit:
		return "init"
	case QPStateRTR:
		return "rtr"
	case QPStateRTS:
		return "rts"
	case QPStateSQD:
		return "sqd"
	case QPStateSQE:
		return "sqe"
	case QPStateErr:
		return "err"
	default:
		return "unknown"
	}
}

// SendOpcode selects the work request operation. Values match Ibverbs
// ibv_wr_opcode. | SendOpcode 选择工作请求操作。取值与 Ibverbs
// ibv_wr_opcode 一致。
type SendOpcode uint32

// Work request opcodes. | 工作请求操作码。
const (
	// OpRDMAWrite writes to remote memory without a receive request. |
	// OpRDMAWrite 无需接收请求即可写入远端内存。
	OpRDMAWrite SendOpcode = 0
	// OpRDMAWriteWithImm is OpRDMAWrite with an immediate value. |
	// OpRDMAWriteWithImm 是携带立即数的 OpRDMAWrite。
	OpRDMAWriteWithImm SendOpcode = 1
	// OpSend posts a message consumed by a receive request. | OpSend 提交由
	// 接收请求消费的消息。
	OpSend SendOpcode = 2
	// OpSendWithImm is OpSend with an immediate value. | OpSendWithImm 是携带
	// 立即数的 OpSend。
	OpSendWithImm SendOpcode = 3
	// OpRDMARead reads remote memory. | OpRDMARead 读取远端内存。
	OpRDMARead SendOpcode = 4
	// OpAtomicCmpSwap is a remote compare-and-swap. | OpAtomicCmpSwap 是远端
	// 比较并交换。
	OpAtomicCmpSwap SendOpcode = 5
	// OpAtomicFetchAdd is a remote fetch-and-add. | OpAtomicFetchAdd 是远端
	// 取回并相加。
	OpAtomicFetchAdd SendOpcode = 6
	// OpLocalInv invalidates a local memory region. | OpLocalInv 使本地内存区
	// 失效。
	OpLocalInv SendOpcode = 7
	// OpBindMW binds a memory window. | OpBindMW 绑定内存窗口。
	OpBindMW SendOpcode = 8
	// OpSendWithInv is OpSend with an invalidation. | OpSendWithInv 是携带失效
	// 的 OpSend。
	OpSendWithInv SendOpcode = 9
)

// String returns the English opcode name. | String 返回操作码英文名。
func (o SendOpcode) String() string {
	switch o {
	case OpRDMAWrite:
		return "RDMA_WRITE"
	case OpRDMAWriteWithImm:
		return "RDMA_WRITE_WITH_IMM"
	case OpSend:
		return "SEND"
	case OpSendWithImm:
		return "SEND_WITH_IMM"
	case OpRDMARead:
		return "RDMA_READ"
	case OpAtomicCmpSwap:
		return "ATOMIC_CMP_SWAP"
	case OpAtomicFetchAdd:
		return "ATOMIC_FETCH_ADD"
	case OpLocalInv:
		return "LOCAL_INV"
	case OpBindMW:
		return "BIND_MW"
	case OpSendWithInv:
		return "SEND_WITH_INV"
	default:
		return "unknown"
	}
}

// SendFlags control one work request. Values match Ibverbs ibv_send_flags. |
// SendFlags 控制单个工作请求。取值与 Ibverbs ibv_send_flags 一致。
type SendFlags uint32

// Work request flags. | 工作请求标志。
const (
	// SendFence orders this request after prior RDMA reads. | SendFence 使本
	// 请求排在先前的 RDMA 读之后。
	SendFence SendFlags = 1 << 0
	// SendSignaled requests a completion. With SignalAll queue pairs it is
	// implied. | SendSignaled 请求完成事件；在 SignalAll 队列对上自动隐含。
	SendSignaled SendFlags = 1 << 1
	// SendSolicited requests an immediate ACK. | SendSolicited 请求立即 ACK。
	SendSolicited SendFlags = 1 << 2
	// SendInline places the payload in the work request instead of DMA. |
	// SendInline 将负载放入工作请求而不是 DMA。
	SendInline SendFlags = 1 << 3
)

// SGE is one scatter/gather entry. Its layout matches the provider ABI.
// | SGE 是一个分散/聚集项，布局与提供方 ABI 一致。
type SGE struct {
	// Addr is the local virtual address. | Addr 是本地虚拟地址。
	Addr uintptr
	// Length is the entry length in bytes. | Length 是条目字节长度。
	Length uint32
	// LKey is the local access key. | LKey 是本地访问键。
	LKey uint32
}

// SendWR is one send work request. When NumSGE is zero, Addr, Length and LKey
// form a single SGE. Otherwise SGEs[:NumSGE] is used. The layout matches the
// provider layout, so batches are encoded without a cgo conversion. | SendWR 是一个
// 发送工作请求。NumSGE 为零时由 Addr、Length、LKey 组成单个 SGE；否则使用
// SGEs[:NumSGE]。布局与提供方 ABI 一致，批量提交无需 cgo 转换。
type SendWR struct {
	// WRID is echoed back in the completion. | WRID 会在完成事件中原样返回。
	WRID uint64
	// Addr is the local buffer address. | Addr 是本地缓冲区地址。
	Addr uintptr
	// RemoteAddr is the remote virtual address for RDMA and atomic ops. |
	// RemoteAddr 是 RDMA 与原子操作的远端虚拟地址。
	RemoteAddr uint64
	// CompareAdd is the compare value for compare-and-swap or the addend for
	// fetch-and-add. | CompareAdd 是比较交换的比较值或取加操作的加数。
	CompareAdd uint64
	// Swap is the swap value for compare-and-swap. | Swap 是比较交换的交换值。
	Swap uint64
	// Length is the payload length in bytes. | Length 是负载字节长度。
	Length uint32
	// LKey is the local access key. | LKey 是本地访问键。
	LKey uint32
	// RKey is the remote access key. | RKey 是远端访问键。
	RKey uint32
	// Opcode selects the operation. | Opcode 选择操作。
	Opcode SendOpcode
	// Flags control the request. | Flags 控制请求。
	Flags SendFlags
	// Imm is the immediate value for *_WITH_IMM opcodes. | Imm 是带立即数操作码
	// 的立即数。
	Imm uint32
	// NumSGE selects SGEs[:NumSGE] when non-zero. | NumSGE 非零时选择
	// SGEs[:NumSGE]。
	NumSGE uint32
	// RemoteQPN is the destination queue pair for unreliable datagram sends. |
	// RemoteQPN 是不可靠数据报发送的目标队列对。
	RemoteQPN uint32
	// RemoteQKey is the remote queue key for unreliable datagram sends. |
	// RemoteQKey 是不可靠数据报发送的远端队列键。
	RemoteQKey uint32
	_          uint32
	// SGEs holds up to MaxSGE scatter/gather entries. | SGEs 最多保存 MaxSGE
	// 个分散/聚集项。
	SGEs [MaxSGE]SGE
}

// RecvWR is one receive work request. When NumSGE is zero, Addr, Length and
// LKey form a single SGE. | RecvWR 是一个接收工作请求。NumSGE 为零时由 Addr、
// Length、LKey 组成单个 SGE。
type RecvWR struct {
	// WRID is echoed back in the completion. | WRID 会在完成事件中原样返回。
	WRID uint64
	// Addr is the local buffer address. | Addr 是本地缓冲区地址。
	Addr uintptr
	// Length is the buffer length in bytes. | Length 是缓冲区字节长度。
	Length uint32
	// LKey is the local access key. | LKey 是本地访问键。
	LKey uint32
	// NumSGE selects SGEs[:NumSGE] when non-zero. | NumSGE 非零时选择
	// SGEs[:NumSGE]。
	NumSGE uint32
	_      uint32
	// SGEs holds up to MaxSGE scatter/gather entries. | SGEs 最多保存 MaxSGE
	// 个分散/聚集项。
	SGEs [MaxSGE]SGE
}

// CompletionOpcode is the operation that produced a completion. Values match
// Ibverbs ibv_wc_opcode. | CompletionOpcode 是产生完成事件的操作，取值与
// Ibverbs ibv_wc_opcode 一致。
type CompletionOpcode uint32

// Completion opcodes. | 完成操作码。
const (
	// CompSend is a completed send. | CompSend 是完成的发送。
	CompSend CompletionOpcode = 0
	// CompRDMAWrite is a completed RDMA write. | CompRDMAWrite 是完成的 RDMA 写。
	CompRDMAWrite CompletionOpcode = 1
	// CompRDMARead is a completed RDMA read. | CompRDMARead 是完成的 RDMA 读。
	CompRDMARead CompletionOpcode = 2
	// CompCmpSwap is a completed compare-and-swap. | CompCmpSwap 是完成的比较交换。
	CompCmpSwap CompletionOpcode = 3
	// CompFetchAdd is a completed fetch-and-add. | CompFetchAdd 是完成的取加。
	CompFetchAdd CompletionOpcode = 4
	// CompBindMW is a completed memory window bind. | CompBindMW 是完成的内存窗口绑定。
	CompBindMW CompletionOpcode = 5
	// CompLocalInv is a completed local invalidation. | CompLocalInv 是完成的本地失效。
	CompLocalInv CompletionOpcode = 6
	// CompTSO is a completed TCP segmentation offload. | CompTSO 是完成的 TCP
	// 分段卸载。
	CompTSO CompletionOpcode = 7
	// CompFlush is a completed flush. | CompFlush 是完成的刷新。
	CompFlush CompletionOpcode = 8
	// CompAtomicWrite is a completed atomic write. | CompAtomicWrite 是完成的
	// 原子写。
	CompAtomicWrite CompletionOpcode = 9
	// CompRecv is a completed receive. | CompRecv 是完成的接收。
	CompRecv CompletionOpcode = 1 << 7
	// CompRecvRDMAWithImm is a receive completed by RDMA write with immediate.
	// | CompRecvRDMAWithImm 是由带立即数 RDMA 写完成的接收。
	CompRecvRDMAWithImm CompletionOpcode = 1<<7 + 1
)

// IsRecv reports whether the completion consumed a receive request. | IsRecv
// 报告完成事件是否消费了接收请求。
func (o CompletionOpcode) IsRecv() bool { return o&CompRecv != 0 }

// String returns the English completion opcode name. | String 返回完成操作码
// 英文名。
func (o CompletionOpcode) String() string {
	switch o {
	case CompSend:
		return "SEND"
	case CompRDMAWrite:
		return "RDMA_WRITE"
	case CompRDMARead:
		return "RDMA_READ"
	case CompCmpSwap:
		return "COMP_SWAP"
	case CompFetchAdd:
		return "FETCH_ADD"
	case CompBindMW:
		return "BIND_MW"
	case CompLocalInv:
		return "LOCAL_INV"
	case CompTSO:
		return "TSO"
	case CompFlush:
		return "FLUSH"
	case CompAtomicWrite:
		return "ATOMIC_WRITE"
	case CompRecv:
		return "RECV"
	case CompRecvRDMAWithImm:
		return "RECV_RDMA_WITH_IMM"
	default:
		return "unknown"
	}
}

// CompletionStatus is the outcome of a work request. Values match Ibverbs
// ibv_wc_status. | CompletionStatus 是工作请求的结果，取值与 Ibverbs
// ibv_wc_status 一致。
type CompletionStatus uint32

// Completion statuses. | 完成状态。
const (
	// StatusSuccess means the request completed successfully. | StatusSuccess
	// 表示请求成功完成。
	StatusSuccess CompletionStatus = 0
	// StatusLocalLengthErr is a local length error. | StatusLocalLengthErr 是本地长度错误。
	StatusLocalLengthErr CompletionStatus = 1
	// StatusLocalQPOperationErr is a local queue pair operation error. |
	// StatusLocalQPOperationErr 是本地队列对操作错误。
	StatusLocalQPOperationErr CompletionStatus = 2
	// StatusLocalEECOperationErr is a local EEC operation error. |
	// StatusLocalEECOperationErr 是本地 EEC 操作错误。
	StatusLocalEECOperationErr CompletionStatus = 3
	// StatusLocalProtectionErr is a local protection error. |
	// StatusLocalProtectionErr 是本地保护错误。
	StatusLocalProtectionErr CompletionStatus = 4
	// StatusWRFlushErr means the request was flushed. | StatusWRFlushErr 表示
	// 请求被冲刷。
	StatusWRFlushErr CompletionStatus = 5
	// StatusMWBindErr is a memory window bind error. | StatusMWBindErr 是内存
	// 窗口绑定错误。
	StatusMWBindErr CompletionStatus = 6
	// StatusBadResponseErr is a bad response error. | StatusBadResponseErr 是
	// 错误响应。
	StatusBadResponseErr CompletionStatus = 7
	// StatusLocalAccessErr is a local access error. | StatusLocalAccessErr 是
	// 本地访问错误。
	StatusLocalAccessErr CompletionStatus = 8
	// StatusRemoteInvalidRequestErr is a remote invalid request error. |
	// StatusRemoteInvalidRequestErr 是远端非法请求错误。
	StatusRemoteInvalidRequestErr CompletionStatus = 9
	// StatusRemoteAccessErr is a remote access error. | StatusRemoteAccessErr
	// 是远端访问错误。
	StatusRemoteAccessErr CompletionStatus = 10
	// StatusRemoteOperationErr is a remote operation error. |
	// StatusRemoteOperationErr 是远端操作错误。
	StatusRemoteOperationErr CompletionStatus = 11
	// StatusRetryExceededErr means retries were exhausted. |
	// StatusRetryExceededErr 表示重试耗尽。
	StatusRetryExceededErr CompletionStatus = 12
	// StatusRNRRetryExceededErr means receiver-not-ready retries were exhausted.
	// | StatusRNRRetryExceededErr 表示接收端未就绪重试耗尽。
	StatusRNRRetryExceededErr CompletionStatus = 13
	// StatusLocalRDDViolationErr is a local RDD violation. |
	// StatusLocalRDDViolationErr 是本地 RDD 违规。
	StatusLocalRDDViolationErr CompletionStatus = 14
	// StatusRemoteInvalidReadRequestErr is a remote invalid read request. |
	// StatusRemoteInvalidReadRequestErr 是远端非法读请求。
	StatusRemoteInvalidReadRequestErr CompletionStatus = 15
	// StatusRemoteAbortErr is a remote abort. | StatusRemoteAbortErr 是远端中止。
	StatusRemoteAbortErr CompletionStatus = 16
	// StatusInvalidEECNErr is an invalid EECN. | StatusInvalidEECNErr 是非法 EECN。
	StatusInvalidEECNErr CompletionStatus = 17
	// StatusInvalidEECStateErr is an invalid EEC state. |
	// StatusInvalidEECStateErr 是非法 EEC 状态。
	StatusInvalidEECStateErr CompletionStatus = 18
	// StatusFatalErr is a fatal error. | StatusFatalErr 是致命错误。
	StatusFatalErr CompletionStatus = 19
	// StatusResponseTimeoutErr is a response timeout. | StatusResponseTimeoutErr
	// 是响应超时。
	StatusResponseTimeoutErr CompletionStatus = 20
	// StatusGeneralErr is a general error. | StatusGeneralErr 是一般错误。
	StatusGeneralErr CompletionStatus = 21
)

// String returns the English status name. | String 返回状态英文名。
func (s CompletionStatus) String() string {
	switch s {
	case StatusSuccess:
		return "success"
	case StatusLocalLengthErr:
		return "local length error"
	case StatusLocalQPOperationErr:
		return "local QP operation error"
	case StatusLocalEECOperationErr:
		return "local EEC operation error"
	case StatusLocalProtectionErr:
		return "local protection error"
	case StatusWRFlushErr:
		return "work request flush error"
	case StatusMWBindErr:
		return "memory window bind error"
	case StatusBadResponseErr:
		return "bad response error"
	case StatusLocalAccessErr:
		return "local access error"
	case StatusRemoteInvalidRequestErr:
		return "remote invalid request error"
	case StatusRemoteAccessErr:
		return "remote access error"
	case StatusRemoteOperationErr:
		return "remote operation error"
	case StatusRetryExceededErr:
		return "retry exceeded error"
	case StatusRNRRetryExceededErr:
		return "receiver not ready retry exceeded error"
	case StatusFatalErr:
		return "fatal error"
	case StatusResponseTimeoutErr:
		return "response timeout error"
	default:
		return fmt.Sprintf("status(%d)", uint32(s))
	}
}

// Completion is one completion queue entry. Its layout matches the bridge
// structure, so Poll writes completions in place without conversion. | Completion
// 是一个完成队列项。布局与桥接结构一致，Poll 可原地写入而无需转换。
type Completion struct {
	// WRID is the work request identifier supplied by the caller. | WRID 是调用
	// 方提供的工作请求标识。
	WRID uint64
	// Opcode is the completed operation. | Opcode 是完成的操作。
	Opcode CompletionOpcode
	// Status is the completion status. | Status 是完成状态。
	Status CompletionStatus
	// Bytes is the transferred byte count. | Bytes 是传输字节数。
	Bytes uint32
	// QP is the source queue pair number. | QP 是来源队列对号。
	QP uint32
	// Imm is the immediate value for receive-with-immediate completions. |
	// Imm 是带立即数接收完成的立即数。
	Imm uint32
	// VendorErr is the vendor error code. | VendorErr 是厂商错误码。
	VendorErr uint32
}

// IsError reports whether the completion failed. | IsError 报告完成事件是否失败。
func (c Completion) IsError() bool { return c.Status != StatusSuccess }

// QPAttrMask selects which queue pair attributes Modify applies. Values match
// Ibverbs ibv_qp_attr_mask. | QPAttrMask 选择 Modify 应用的队列对属性，取值
// 与 Ibverbs ibv_qp_attr_mask 一致。
type QPAttrMask uint32

// Queue pair attribute masks. | 队列对属性掩码。
const (
	// QPAttrState selects the queue pair state. | QPAttrState 选择队列对状态。
	QPAttrState QPAttrMask = 1 << 0
	// QPAttrCurState selects the current state. | QPAttrCurState 选择当前状态。
	QPAttrCurState QPAttrMask = 1 << 1
	// QPAttrEnSQDAsyncNotify selects send queue drain notification. |
	// QPAttrEnSQDAsyncNotify 选择发送队列排空通知。
	QPAttrEnSQDAsyncNotify QPAttrMask = 1 << 2
	// QPAttrAccessFlags selects remote access permissions. |
	// QPAttrAccessFlags 选择远端访问权限。
	QPAttrAccessFlags QPAttrMask = 1 << 3
	// QPAttrPKeyIndex selects the partition key index. | QPAttrPKeyIndex 选择
	// 分区键索引。
	QPAttrPKeyIndex QPAttrMask = 1 << 4
	// QPAttrPort selects the port number. | QPAttrPort 选择端口号。
	QPAttrPort QPAttrMask = 1 << 5
	// QPAttrQKey selects the QKey. | QPAttrQKey 选择 QKey。
	QPAttrQKey QPAttrMask = 1 << 6
	// QPAttrAV selects the address vector. | QPAttrAV 选择地址向量。
	QPAttrAV QPAttrMask = 1 << 7
	// QPAttrPathMTU selects the path MTU. | QPAttrPathMTU 选择路径 MTU。
	QPAttrPathMTU QPAttrMask = 1 << 8
	// QPAttrTimeout selects the local ACK timeout. | QPAttrTimeout 选择本地
	// ACK 超时。
	QPAttrTimeout QPAttrMask = 1 << 9
	// QPAttrRetryCount selects the transport retry count. |
	// QPAttrRetryCount 选择传输重试次数。
	QPAttrRetryCount QPAttrMask = 1 << 10
	// QPAttrRNRRetry selects the receiver-not-ready retry count. |
	// QPAttrRNRRetry 选择接收端未就绪重试次数。
	QPAttrRNRRetry QPAttrMask = 1 << 11
	// QPAttrRQPSN selects the receive packet sequence number. |
	// QPAttrRQPSN 选择接收报文序列号。
	QPAttrRQPSN QPAttrMask = 1 << 12
	// QPAttrMaxQPRDAtomic selects the outstanding RDMA read count. |
	// QPAttrMaxQPRDAtomic 选择在途 RDMA 读数量。
	QPAttrMaxQPRDAtomic QPAttrMask = 1 << 13
	// QPAttrAltPath selects the alternate path. | QPAttrAltPath 选择备用路径。
	QPAttrAltPath QPAttrMask = 1 << 14
	// QPAttrMinRNRTimer selects the minimum RNR NAK timer. |
	// QPAttrMinRNRTimer 选择最小 RNR NAK 定时器。
	QPAttrMinRNRTimer QPAttrMask = 1 << 15
	// QPAttrSQPSN selects the send packet sequence number. |
	// QPAttrSQPSN 选择发送报文序列号。
	QPAttrSQPSN QPAttrMask = 1 << 16
	// QPAttrMaxDestRDAtomic selects the remote outstanding RDMA read count. |
	// QPAttrMaxDestRDAtomic 选择远端在途 RDMA 读数量。
	QPAttrMaxDestRDAtomic QPAttrMask = 1 << 17
	// QPAttrPathMigState selects the path migration state. |
	// QPAttrPathMigState 选择路径迁移状态。
	QPAttrPathMigState QPAttrMask = 1 << 18
	// QPAttrCap selects capability attributes. | QPAttrCap 选择能力属性。
	QPAttrCap QPAttrMask = 1 << 19
	// QPAttrDestQPN selects the destination queue pair number. |
	// QPAttrDestQPN 选择目标队列对号。
	QPAttrDestQPN QPAttrMask = 1 << 20
	// QPAttrRateLimit selects the rate limit. | QPAttrRateLimit 选择速率限制。
	QPAttrRateLimit QPAttrMask = 1 << 21
)

// AHAttr is the address vector of a remote peer. | AHAttr 是远端对端的地址向量。
type AHAttr struct {
	// IsGlobal requests a global routing header. | IsGlobal 请求全局路由头。
	IsGlobal bool
	// DLID is the destination InfiniBand LID. | DLID 是目标 InfiniBand LID。
	DLID uint16
	// SL is the service level. | SL 是服务等级。
	SL uint8
	// SrcPathBits is the source path bits. | SrcPathBits 是源路径位。
	SrcPathBits uint8
	// StaticRate is the static rate. | StaticRate 是静态速率。
	StaticRate uint8
	// Port is the local port number. | Port 是本地端口号。
	Port uint8
	// GID is the destination global identifier. | GID 是目标全局标识。
	GID [16]byte
	// FlowLabel is the IPv6 flow label. | FlowLabel 是 IPv6 流标签。
	FlowLabel uint32
	// SGIDIndex is the local source GID index. | SGIDIndex 是本地源 GID 索引。
	SGIDIndex uint8
	// HopLimit is the IPv6 hop limit. | HopLimit 是 IPv6 跳数限制。
	HopLimit uint8
	// TrafficClass is the IPv6 traffic class. | TrafficClass 是 IPv6 流量类别。
	TrafficClass uint8
}

// QPAttr carries queue pair attributes for Modify. Zero fields are ignored
// unless their mask bit is set. | QPAttr 携带 Modify 使用的队列对属性。未设置
// 掩码位的零值字段会被忽略。
type QPAttr struct {
	// PathMTU is the path MTU in bytes. | PathMTU 是路径 MTU（字节）。
	PathMTU int
	// AH is the address vector. | AH 是地址向量。
	AH AHAttr
	// Mask selects the fields to apply. | Mask 选择要应用的字段。
	Mask QPAttrMask
	// State is the target state. | State 是目标状态。
	State QPState
	// CurState is the current state. | CurState 是当前状态。
	CurState QPState
	// PathMigState is the path migration state. | PathMigState 是路径迁移状态。
	PathMigState uint32
	// QKey is the queue key. | QKey 是队列键。
	QKey uint32
	// RQPSN is the receive packet sequence number. | RQPSN 是接收报文序列号。
	RQPSN uint32
	// SQPSN is the send packet sequence number. | SQPSN 是发送报文序列号。
	SQPSN uint32
	// DestQPN is the destination queue pair number. | DestQPN 是目标队列对号。
	DestQPN uint32
	// Access is the remote access permission granted to the peer. | Access 是
	// 授予对端的远端访问权限。
	Access Access
	// PKeyIndex is the partition key index. | PKeyIndex 是分区键索引。
	PKeyIndex uint16
	// AltPKeyIndex is the alternate partition key index. | AltPKeyIndex 是
	// 备用分区键索引。
	AltPKeyIndex uint16
	// MaxRDMAtomic is the outstanding RDMA read count. | MaxRDMAtomic 是在途
	// RDMA 读数量。
	MaxRDMAtomic uint8
	// MaxDestRDMAtomic is the remote outstanding RDMA read count. |
	// MaxDestRDMAtomic 是远端在途 RDMA 读数量。
	MaxDestRDMAtomic uint8
	// MinRNRTimer is the minimum RNR NAK timer. | MinRNRTimer 是最小 RNR NAK
	// 定时器。
	MinRNRTimer uint8
	// Port is the local port number. | Port 是本地端口号。
	Port uint8
	// Timeout is the local ACK timeout exponent. | Timeout 是本地 ACK 超时指数。
	Timeout uint8
	// RetryCount is the transport retry count. | RetryCount 是传输重试次数。
	RetryCount uint8
	// RNRRetry is the receiver-not-ready retry count. | RNRRetry 是接收端未就绪
	// 重试次数。
	RNRRetry uint8
}

// ConnectInfo carries the queue pair parameters exchanged before two peers
// become usable. | ConnectInfo 携带两个对端可用前交换的队列对参数。
type ConnectInfo struct {
	// MTU is the path MTU in bytes. | MTU 是路径 MTU（字节）。
	MTU int
	// QPN is the queue pair number. | QPN 是队列对号。
	QPN uint32
	// PSN is the send packet sequence number. | PSN 是发送报文序列号。
	PSN uint32
	// QKey is the unreliable datagram queue key. | QKey 是不可靠数据报队列键。
	QKey uint32
	// LID is the InfiniBand local identifier; zero on RoCE. | LID 是 InfiniBand
	// 本地标识；RoCE 上为零。
	LID uint16
	// GID is the GID used by RDMA-aware transports. | GID 是 RDMA 传输使用的 GID。
	GID [16]byte
}

// QPConfig configures a new queue pair. | QPConfig 配置新队列对。
type QPConfig struct {
	// SendCQ receives send completions. It is required. | SendCQ 接收发送完成
	// 事件，必填。
	SendCQ *CQ
	// RecvCQ receives receive completions. When nil, SendCQ is used. | RecvCQ
	// 接收接收完成事件；为空时使用 SendCQ。
	RecvCQ *CQ
	// SRQ optionally shares a receive queue. | SRQ 可选地共享接收队列。
	SRQ *SRQ
	// MaxSendWR is the send queue depth; zero uses Config.QueueDepth. |
	// MaxSendWR 是发送队列深度；零使用 Config.QueueDepth。
	MaxSendWR int
	// MaxRecvWR is the receive queue depth; zero uses Config.QueueDepth. |
	// MaxRecvWR 是接收队列深度；零使用 Config.QueueDepth。
	MaxRecvWR int
	// MaxSendSGE is the send scatter/gather limit; zero means 1. |
	// MaxSendSGE 是发送分散/聚集上限；零表示 1。
	MaxSendSGE int
	// MaxRecvSGE is the receive scatter/gather limit; zero means 1. |
	// MaxRecvSGE 是接收分散/聚集上限；零表示 1。
	MaxRecvSGE int
	// MaxInline is the inline payload limit; zero uses the device maximum. |
	// MaxInline 是内联负载上限；零使用设备上限。
	MaxInline int
	// Type selects the transport service. Zero means QPTypeRC. | Type 选择传输
	// 服务；零表示 QPTypeRC。
	Type QPType
	// Access is the remote access permission granted to the peer. Zero means
	// AccessDefault; the Conn SEND/RECV path uses AccessLocalWrite. | Access 是
	// 授予对端的远端访问权限；零表示 AccessDefault，Conn 的 SEND/RECV 路径使用
	// AccessLocalWrite。
	Access Access
	// SignalAll requests a completion for every send. | SignalAll 为每次发送
	// 请求完成事件。
	SignalAll bool
}

// DefaultQPConfig returns a reliable connected configuration with the given
// completion queue and full signaling. | DefaultQPConfig 返回使用指定完成队列
// 且全量信号、可靠连接的配置。
func DefaultQPConfig(cq *CQ) QPConfig {
	return QPConfig{Type: QPTypeRC, SendCQ: cq, SignalAll: true}
}

// SRQConfig configures a shared receive queue. | SRQConfig 配置共享接收队列。
type SRQConfig struct {
	// MaxWR is the receive queue depth. | MaxWR 是接收队列深度。
	MaxWR int
	// MaxSGE is the scatter/gather limit. | MaxSGE 是分散/聚集上限。
	MaxSGE int
}

// DeviceAttr reports device capabilities used to validate configurations. |
// DeviceAttr 报告用于校验配置的设备能力。
type DeviceAttr struct {
	// Firmware is the firmware version. | Firmware 是固件版本。
	Firmware string
	// MaxMRSize is the maximum memory region size. | MaxMRSize 是最大内存区大小。
	MaxMRSize uint64
	// MaxQPWR is the maximum queue pair depth. | MaxQPWR 是最大队列对深度。
	MaxQPWR uint32
	// MaxSRQWR is the maximum shared receive queue depth. | MaxSRQWR 是最大共享
	// 接收队列深度。
	MaxSRQWR uint32
	// MaxSGE is the maximum scatter/gather entries per request. | MaxSGE 是
	// 单请求最大分散/聚集项数。
	MaxSGE uint32
	// MaxCQE is the maximum completion queue depth. | MaxCQE 是最大完成队列深度。
	MaxCQE uint32
	// MaxInline is deprecated and always zero. Inline limits are negotiated
	// per queue pair; use QP.MaxInline. | MaxInline 已弃用且始终为零。内联上限
	// 按队列对协商；请使用 QP.MaxInline。
	MaxInline uint32
	// MaxQPRdAtomic is the maximum outstanding RDMA reads. | MaxQPRdAtomic 是
	// 最大在途 RDMA 读数量。
	MaxQPRdAtomic uint32
	// MaxQPInitRdAtomic is the maximum initial outstanding RDMA reads. |
	// MaxQPInitRdAtomic 是最大初始在途 RDMA 读数量。
	MaxQPInitRdAtomic uint32
	// VendorPartID is the vendor part identifier. | VendorPartID 是厂商部件号。
	VendorPartID uint32
}

// PortAttr reports the runtime attributes of one port. | PortAttr 报告一个端口
// 的运行属性。
type PortAttr struct {
	// Port is the one-based port number. | Port 是 1 起始的端口号。
	Port int
	// MaxMTU is the maximum path MTU in bytes. | MaxMTU 是最大路径 MTU（字节）。
	MaxMTU int
	// ActiveMTU is the active path MTU in bytes. | ActiveMTU 是当前路径 MTU（字节）。
	ActiveMTU int
	// GIDTableLen is the GID table length. | GIDTableLen 是 GID 表长度。
	GIDTableLen int
	// LID is the InfiniBand local identifier. | LID 是 InfiniBand 本地标识。
	LID uint16
	// State is the port state. | State 是端口状态。
	State PortState
	// LinkLayer is the link layer. | LinkLayer 是链路层。
	LinkLayer LinkLayer
}

// PoolConfig configures a registered memory pool. | PoolConfig 配置注册内存池。
type PoolConfig struct {
	// Slots is the number of slots. Zero means 1024. | Slots 是槽位数量；零表示 1024。
	Slots int
	// SlotSize is the slot size in bytes. Zero means 4096. | SlotSize 是槽位
	// 字节数；零表示 4096。
	SlotSize int
	// Access is the registered permission set. Zero means AccessDefault. |
	// Access 是注册权限集合；零表示 AccessDefault。
	Access Access
	// HugePages asks for 2 MiB huge pages with a transparent-huge-page
	// fallback. | HugePages 请求 2 MiB 大页，失败时回退透明大页。
	HugePages bool
	// Align is the slot alignment; zero means 64 bytes. | Align 是槽位对齐；
	// 零表示 64 字节。
	Align int
}

// Device is an opened RDMA device with one protection domain. | Device 是已
// 打开并带有一个保护域的 RDMA 设备。
type Device struct {
	closeErr  error
	state     *deviceState
	closeDone chan struct{}
	info      DeviceInfo
	gid       GID
	attr      DeviceAttr
	cfg       Config
	portAttr  PortAttr
	port      int
	children  int
	mu        sync.Mutex
	inlineMax atomic.Int32 // 0 unknown, >0 supported, <0 unsupported | 0 未知，>0 支持，<0 不支持
	closed    atomic.Bool
}

// acquireChild reserves the device for one new child object. | acquireChild 为
// 新子对象占用设备。
func (d *Device) acquireChild() bool {
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state == nil || d.closed.Load() {
		return false
	}
	d.children++
	return true
}

// releaseChild drops one child reservation. | releaseChild 释放一个子对象占用。
func (d *Device) releaseChild() {
	if d == nil {
		return
	}
	d.mu.Lock()
	if d.children > 0 {
		d.children--
	}
	d.mu.Unlock()
}

// CQ is a completion queue. | CQ 是完成队列。
type CQ struct {
	closeErr error
	dev      *Device
	state    *cqState
	depth    int
	closeMu  sync.Mutex
	closed   atomic.Bool
}

// QP is a queue pair. | QP 是队列对。
type QP struct {
	closeErr error
	dev      *Device
	state    *qpState
	closeMu  sync.Mutex
	typ      QPType
	qpn      uint32
	inline   uint32
	access   Access
	closed   atomic.Bool
}

// SRQ is a shared receive queue. | SRQ 是共享接收队列。
type SRQ struct {
	dev      *Device
	state    *srqState
	closeErr error
	closeMu  sync.Mutex
	closed   atomic.Bool
}

// AH is an address handle used by unreliable datagram queue pairs. | AH 是
// 不可靠数据报队列对使用的地址句柄。
type AH struct {
	dev      *Device
	state    *ahState
	closeErr error
	closeMu  sync.Mutex
	closed   atomic.Bool
}
