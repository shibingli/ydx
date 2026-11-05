//go:build !linux || !rdma || !(amd64 || arm64)

package rdma

// Supported reports whether this build links libibverbs. | Supported 报告当前
// 构建是否链接了 libibverbs。
func Supported() bool { return false }

// Open is unavailable without the rdma build tag. | 没有 rdma 构建标签时 Open
// 不可用。
func Open(Config) (*Device, error) { return nil, ErrUnsupported }

// Close is unavailable without the rdma build tag. | 没有 rdma 构建标签时 Close
// 不可用。
func (d *Device) Close() error { return ErrUnsupported }

// NewCQ is unavailable without the rdma build tag. | 没有 rdma 构建标签时
// NewCQ 不可用。
func (d *Device) NewCQ(int) (*CQ, error) { return nil, ErrUnsupported }

// NewQP is unavailable without the rdma build tag. | 没有 rdma 构建标签时 NewQP
// 不可用。
func (d *Device) NewQP(QPConfig) (*QP, error) { return nil, ErrUnsupported }

// NewSRQ is unavailable without the rdma build tag. | 没有 rdma 构建标签时
// NewSRQ 不可用。
func (d *Device) NewSRQ(SRQConfig) (*SRQ, error) { return nil, ErrUnsupported }

// NewAH is unavailable without the rdma build tag. | 没有 rdma 构建标签时 NewAH
// 不可用。
func (d *Device) NewAH(AHAttr) (*AH, error) { return nil, ErrUnsupported }

// NewMR is unavailable without the rdma build tag. | 没有 rdma 构建标签时 NewMR
// 不可用。
func (d *Device) NewMR(int, Access) (*MR, error) { return nil, ErrUnsupported }

// RegisterMemory is unavailable without the rdma build tag. | 没有 rdma 构建
// 标签时 RegisterMemory 不可用。
func (d *Device) RegisterMemory([]byte, Access) (*MR, error) { return nil, ErrUnsupported }

// NewPool is unavailable without the rdma build tag. | 没有 rdma 构建标签时
// NewPool 不可用。
func (d *Device) NewPool(PoolConfig) (*Pool, error) { return nil, ErrUnsupported }

// Poll is unavailable without the rdma build tag. | 没有 rdma 构建标签时 Poll
// 不可用。
func (c *CQ) Poll([]Completion) (int, error) { return 0, ErrUnsupported }

// Close is unavailable without the rdma build tag. | 没有 rdma 构建标签时 Close
// 不可用。
func (c *CQ) Close() error { return ErrUnsupported }

// PostSend is unavailable without the rdma build tag. | 没有 rdma 构建标签时
// PostSend 不可用。
func (q *QP) PostSend([]SendWR) (int, error) { return 0, ErrUnsupported }

// PostSendUD is unavailable without the rdma build tag. | 没有 rdma 构建标签时
// PostSendUD 不可用。
func (q *QP) PostSendUD([]SendWR, *AH) (int, error) { return 0, ErrUnsupported }

// PostRecv is unavailable without the rdma build tag. | 没有 rdma 构建标签时
// PostRecv 不可用。
func (q *QP) PostRecv([]RecvWR) (int, error) { return 0, ErrUnsupported }

// Modify is unavailable without the rdma build tag. | 没有 rdma 构建标签时
// Modify 不可用。
func (q *QP) Modify(QPAttr) error { return ErrUnsupported }

// State is unavailable without the rdma build tag. | 没有 rdma 构建标签时 State
// 不可用。
func (q *QP) State() (QPState, error) { return QPStateErr, ErrUnsupported }

// LocalInfo is unavailable without the rdma build tag. | 没有 rdma 构建标签时
// LocalInfo 不可用。
func (q *QP) LocalInfo(uint32) ConnectInfo { return ConnectInfo{} }

// Connect is unavailable without the rdma build tag. | 没有 rdma 构建标签时
// Connect 不可用。
func (q *QP) Connect(ConnectInfo, ConnectInfo) error { return ErrUnsupported }

// Close is unavailable without the rdma build tag. | 没有 rdma 构建标签时 Close
// 不可用。
func (q *QP) Close() error { return ErrUnsupported }

// PostRecv is unavailable without the rdma build tag. | 没有 rdma 构建标签时
// PostRecv 不可用。
func (s *SRQ) PostRecv([]RecvWR) (int, error) { return 0, ErrUnsupported }

// Close is unavailable without the rdma build tag. | 没有 rdma 构建标签时 Close
// 不可用。
func (s *SRQ) Close() error { return ErrUnsupported }

// Close is unavailable without the rdma build tag. | 没有 rdma 构建标签时 Close
// 不可用。
func (a *AH) Close() error { return ErrUnsupported }
