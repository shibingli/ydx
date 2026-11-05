//go:build linux && rdma && (amd64 || arm64)

package rdma

import "unsafe"

// The structures in this file mirror the stable libibverbs ABI. Field order,
// padding and sizes are verified by abi_linux_test.go against offsets captured
// from the system headers. Do not reorder fields. | 本文件的结构体镜像稳定的
// libibverbs ABI。字段顺序、填充与大小由 abi_linux_test.go 按系统头文件采集
// 的偏移验证。不得重排字段。

// Opaque libibverbs handles. | 不透明的 libibverbs 句柄。
type (
	ibvDevice   struct{}
	ibvContext  struct{}
	ibvPD       struct{}
	ibvCQ       struct{}
	ibvSRQ      struct{}
	ibvAH       struct{}
	ibvCompChan struct{}
)

// ibvSGE mirrors struct ibv_sge. | ibvSGE 对应 struct ibv_sge。
type ibvSGE struct {
	Addr   uint64
	Length uint32
	LKey   uint32
}

// ibvSendWRUnion mirrors the anonymous union in struct ibv_send_wr. For UD the
// first word holds the AH pointer and the second packs remote QPN and QKey. |
// ibvSendWRUnion 对应 struct ibv_send_wr 的匿名联合。UD 发送时首字保存 AH
// 指针，第二字打包远端 QPN 与 QKey。
type ibvSendWRUnion struct {
	// RemoteAddr is wr.rdma.remote_addr or wr.ud.ah. | RemoteAddr 是
	// wr.rdma.remote_addr 或 wr.ud.ah。
	RemoteAddr uint64
	// Field8 is wr.rdma.rkey, wr.atomic.compare_add, or packed UD QPN/QKey.
	// | Field8 是 wr.rdma.rkey、wr.atomic.compare_add 或打包的 UD QPN/QKey。
	Field8 uint64
	// Swap is wr.atomic.swap. | Swap 是 wr.atomic.swap。
	Swap uint64
	// RKey is wr.atomic.rkey. | RKey 是 wr.atomic.rkey。
	RKey uint32
	_    uint32
}

// ibvSendWR mirrors struct ibv_send_wr (128 bytes). | ibvSendWR 对应
// struct ibv_send_wr（128 字节）。
type ibvSendWR struct {
	WRID      uint64
	Next      *ibvSendWR
	SGList    *ibvSGE
	NumSGE    int32
	Opcode    uint32
	SendFlags uint32
	ImmData   uint32
	Union     ibvSendWRUnion
	QPType    uint32
	_         uint32
	Tail      [48]byte
}

// ibvRecvWR mirrors struct ibv_recv_wr (32 bytes). | ibvRecvWR 对应
// struct ibv_recv_wr（32 字节）。
type ibvRecvWR struct {
	WRID   uint64
	Next   *ibvRecvWR
	SGList *ibvSGE
	NumSGE int32
	_      int32
}

// ibvWC mirrors struct ibv_wc (48 bytes). | ibvWC 对应 struct ibv_wc（48 字节）。
type ibvWC struct {
	WRID         uint64
	Status       uint32
	Opcode       uint32
	VendorErr    uint32
	ByteLen      uint32
	ImmData      uint32
	QPNum        uint32
	SrcQP        uint32
	WCFlags      int32
	PKeyIndex    uint16
	SLID         uint16
	SL           uint8
	DLIDPathBits uint8
	_            [2]byte
}

// ibvQPCap mirrors struct ibv_qp_cap. | ibvQPCap 对应 struct ibv_qp_cap。
type ibvQPCap struct {
	MaxSendWR     uint32
	MaxRecvWR     uint32
	MaxSendSGE    uint32
	MaxRecvSGE    uint32
	MaxInlineData uint32
}

// ibvQPInitAttr mirrors struct ibv_qp_init_attr (64 bytes). | ibvQPInitAttr
// 对应 struct ibv_qp_init_attr（64 字节）。
type ibvQPInitAttr struct {
	QPContext unsafe.Pointer
	SendCQ    *ibvCQ
	RecvCQ    *ibvCQ
	SRQ       *ibvSRQ
	Cap       ibvQPCap
	QPType    uint32
	SQSigAll  int32
	_         int32
}

// ibvGlobalRoute mirrors struct ibv_global_route (24 bytes). | ibvGlobalRoute
// 对应 struct ibv_global_route（24 字节）。
type ibvGlobalRoute struct {
	DGID         [16]byte
	FlowLabel    uint32
	SGIDIndex    uint8
	HopLimit     uint8
	TrafficClass uint8
	_            uint8
}

// ibvAHAttr mirrors struct ibv_ah_attr (32 bytes). | ibvAHAttr 对应
// struct ibv_ah_attr（32 字节）。
type ibvAHAttr struct {
	GRH         ibvGlobalRoute
	DLID        uint16
	SL          uint8
	SrcPathBits uint8
	StaticRate  uint8
	IsGlobal    uint8
	PortNum     uint8
	_           uint8
}

// ibvQPAttr mirrors struct ibv_qp_attr (144 bytes). | ibvQPAttr 对应
// struct ibv_qp_attr（144 字节）。
type ibvQPAttr struct {
	QPState          uint32
	CurQPState       uint32
	PathMTU          uint32
	PathMigState     uint32
	QKey             uint32
	RQPSN            uint32
	SQPSN            uint32
	DestQPN          uint32
	QPAccessFlags    uint32
	Cap              ibvQPCap
	AHAttr           ibvAHAttr
	AltAHAttr        ibvAHAttr
	PKeyIndex        uint16
	AltPKeyIndex     uint16
	EnSQDAsyncNotify uint8
	SQDraining       uint8
	MaxRDAtomic      uint8
	MaxDestRDAtomic  uint8
	MinRNRTimer      uint8
	PortNum          uint8
	Timeout          uint8
	RetryCnt         uint8
	RNRRetry         uint8
	AltPortNum       uint8
	AltTimeout       uint8
	_                uint8
	RateLimit        uint32
	_                [4]byte
}

// ibvDeviceAttr mirrors struct ibv_device_attr (232 bytes). | ibvDeviceAttr
// 对应 struct ibv_device_attr（232 字节）。
type ibvDeviceAttr struct {
	FWVer                 [64]byte
	NodeGUID              uint64
	SysImageGUID          uint64
	MaxMRSize             uint64
	PageSizeCap           uint64
	VendorID              uint32
	VendorPartID          uint32
	HWVer                 uint32
	MaxQP                 int32
	MaxQPWR               int32
	DeviceCapFlags        uint32
	MaxSGE                int32
	MaxSGERd              int32
	MaxCQ                 int32
	MaxCQE                int32
	MaxMR                 int32
	MaxPD                 int32
	MaxQPRdAtom           int32
	MaxEERdAtom           int32
	MaxResRdAtom          int32
	MaxQPInitRdAtom       int32
	MaxEEInitRdAtom       int32
	AtomicCap             uint32
	MaxEE                 int32
	MaxRDD                int32
	MaxMW                 int32
	MaxRawIPv6QP          int32
	MaxRawEthyQP          int32
	MaxMcastGrp           int32
	MaxMcastQPAttach      int32
	MaxTotalMcastQPAttach int32
	MaxAH                 int32
	MaxFMR                int32
	MaxMapPerFMR          int32
	MaxSRQ                int32
	MaxSRQWR              int32
	MaxSRQSGE             int32
	MaxPKeys              uint16
	LocalCAAckDelay       uint8
	PhysPortCnt           uint8
	_                     [4]byte
}

// ibvPortAttr mirrors struct ibv_port_attr (56 bytes). | ibvPortAttr 对应
// struct ibv_port_attr（56 字节）。
type ibvPortAttr struct {
	State         uint32
	MaxMTU        uint32
	ActiveMTU     uint32
	GIDTblLen     int32
	PortCapFlags  uint32
	MaxMsgSz      uint32
	BadPKeyCntr   uint32
	QKeyViolCntr  uint32
	PKeyTblLen    uint16
	LID           uint16
	SMLID         uint16
	LMC           uint8
	MaxVLNum      uint8
	SMSL          uint8
	SubnetTimeout uint8
	InitTypeReply uint8
	ActiveWidth   uint8
	ActiveSpeed   uint8
	PhysState     uint8
	LinkLayer     uint8
	Flags         uint8
	PortCapFlags2 uint16
	_             [2]byte
	ActiveSpeedEx uint32
}

// ibvQP mirrors enough of struct ibv_qp to read qp_num. | ibvQP 镜像
// struct ibv_qp 中以读取 qp_num 所需的部分。
type ibvQP struct {
	Context   unsafe.Pointer
	QPContext unsafe.Pointer
	_         [32]byte
	Handle    uint32
	QPNum     uint32
	State     uint32
	QPType    uint32
	_         [96]byte
}

// ibvMR mirrors struct ibv_mr (48 bytes). | ibvMR 对应 struct ibv_mr（48 字节）。
type ibvMR struct {
	Context unsafe.Pointer
	PD      unsafe.Pointer
	Addr    unsafe.Pointer
	Length  uintptr
	Handle  uint32
	LKey    uint32
	RKey    uint32
	_       uint32
}

// ibvSRQAttr mirrors struct ibv_srq_attr. | ibvSRQAttr 对应 struct ibv_srq_attr。
type ibvSRQAttr struct {
	MaxWR    uint32
	MaxSGE   uint32
	SRQLimit uint32
}

// ibvSRQInitAttr mirrors struct ibv_srq_init_attr (24 bytes). | ibvSRQInitAttr
// 对应 struct ibv_srq_init_attr（24 字节）。
type ibvSRQInitAttr struct {
	SRQContext unsafe.Pointer
	Attr       ibvSRQAttr
	_          int32
}

// ibv_context_ops offsets captured from the system headers. | 从系统头文件采集
// 的 ibv_context_ops 偏移。
const (
	ctxOpsOffset  = 8   // struct ibv_context.ops | ibv_context.ops
	opPollCQ      = 88  // ibv_context_ops.poll_cq
	opReqNotifyCQ = 96  // ibv_context_ops.req_notify_cq
	opPostSRQRecv = 160 // ibv_context_ops.post_srq_recv
	opPostSend    = 200 // ibv_context_ops.post_send
	opPostRecv    = 208 // ibv_context_ops.post_recv
)

// ABI size constants used by tests. | 测试使用的 ABI 大小常量。
const (
	abiSendWRSize      = 128
	abiRecvWRSize      = 32
	abiSGESize         = 16
	abiWCSize          = 48
	abiQPInitAttrSize  = 64
	abiAHAttrSize      = 32
	abiQPAttrSize      = 144
	abiDeviceAttrSize  = 232
	abiPortAttrSize    = 56
	abiMRSize          = 48
	abiSRQInitAttrSize = 24
)
