package rdma

import "github.com/shibingli/ydx/errs"

// Package sentinel errors. Callers match them with errors.Is. | 包级哨兵错误，
// 调用方使用 errors.Is 判定。
var (
	// ErrUnsupported reports that this build has no RDMA provider. | ErrUnsupported
	// 表示当前构建没有 RDMA 实现。
	ErrUnsupported = errs.New("rdma: unsupported build, need linux + -tags rdma + libibverbs (no cgo) | rdma: 当前构建不支持，需 linux + -tags rdma + libibverbs（不需要 cgo）")
	// ErrInvalidConfig reports an invalid configuration value. | ErrInvalidConfig
	// 表示配置值非法。
	ErrInvalidConfig = errs.New("rdma: invalid configuration | rdma: 配置非法")
	// ErrNoDevice reports that no matching RDMA device exists. | ErrNoDevice
	// 表示没有匹配的 RDMA 设备。
	ErrNoDevice = errs.New("rdma: no matching RDMA device | rdma: 没有匹配的 RDMA 设备")
	// ErrNoGID reports that no GID matches the requested type or netdev. |
	// ErrNoGID 表示没有匹配类型或网卡的 GID。
	ErrNoGID = errs.New("rdma: no matching GID | rdma: 没有匹配的 GID")
	// ErrInvalidGID reports an unparsable GID address. | ErrInvalidGID 表示 GID
	// 地址无法解析。
	ErrInvalidGID = errs.New("rdma: invalid GID | rdma: GID 非法")
	// ErrClosed reports use of a closed device, queue or connection. | ErrClosed
	// 表示设备、队列或连接已关闭。
	ErrClosed = errs.New("rdma: object is closed | rdma: 对象已关闭")
	// ErrQueueFull reports that no send or receive slot is available. |
	// ErrQueueFull 表示没有可用的发送或接收槽位。
	ErrQueueFull = errs.New("rdma: queue is full | rdma: 队列已满")
	// ErrNoBuffer reports that the registered memory pool is exhausted. |
	// ErrNoBuffer 表示注册内存池已耗尽。
	ErrNoBuffer = errs.New("rdma: buffer pool exhausted | rdma: 缓冲区池已耗尽")
	// ErrTimeout reports that an operation exceeded its deadline. | ErrTimeout
	// 表示操作超时。
	ErrTimeout = errs.New("rdma: operation timed out | rdma: 操作超时")
	// ErrConnReset reports a broken queue pair or completion error. |
	// ErrConnReset 表示队列对断开或完成事件出错。
	ErrConnReset = errs.New("rdma: connection reset | rdma: 连接已重置")
	// ErrMessageTooLarge reports a message larger than one registered slot. |
	// ErrMessageTooLarge 表示消息超过单个注册槽位容量。
	ErrMessageTooLarge = errs.New("rdma: message too large | rdma: 消息过大")
	// ErrRemoteError reports a remote completion with error status. |
	// ErrRemoteError 表示远端完成事件带错误状态。
	ErrRemoteError = errs.New("rdma: remote completion error | rdma: 远端完成错误")
	// ErrHandshake reports a malformed or failed out-of-band parameter
	// exchange. | ErrHandshake 表示带外参数交换格式错误或失败。
	ErrHandshake = errs.New("rdma: handshake failed | rdma: 握手失败")
	// ErrDevice reports a failed device, queue or memory operation. |
	// ErrDevice 表示设备、队列或内存操作失败。
	ErrDevice = errs.New("rdma: device operation failed | rdma: 设备操作失败")
	// ErrNetwork reports a failed TCP listener, dial or control exchange. |
	// ErrNetwork 表示 TCP 监听、拨号或控制交换失败。
	ErrNetwork = errs.New("rdma: network error | rdma: 网络错误")
	// ErrBusy reports that a device still owns live queue pairs, completion
	// queues, shared receive queues, address handles or memory regions. |
	// ErrBusy 表示设备仍拥有活动的队列对、完成队列、共享接收队列、地址句柄或内存区。
	ErrBusy = errs.New("rdma: device has live resources | rdma: 设备仍有活动资源")
)
