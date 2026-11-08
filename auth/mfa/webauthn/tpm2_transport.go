package webauthn

import (
	"context"
	"errors"
	"time"

	"github.com/shibingli/ydx/errs"
)

// DefaultTPMTimeout is the command deadline applied when TPMOptions.Timeout is zero. |
// DefaultTPMTimeout 是 TPMOptions.Timeout 为零时应用的命令期限。
const DefaultTPMTimeout = 30 * time.Second

// TPM is a raw TPM 2.0 command transport. | TPM 是原始 TPM 2.0 命令传输。
//
// Execute sends one complete command wire image and returns one complete response wire image.
// Implementations serialize concurrent commands because a TPM command/response exchange is atomic.
// Execute must return ErrTPMTimeout when a deadline expires, ErrTPMTransport for transport failures,
// and must not retain the command slice after returning. | Execute 发送一个完整命令线上镜像并返回一个
// 完整响应线上镜像。实现会串行化并发命令，因为 TPM 命令/响应交换是原子的。期限到时 Execute 必须返回
// ErrTPMTimeout，传输失败必须返回 ErrTPMTransport，且返回后不得保留 command 切片。
type TPM interface {
	// Execute sends a raw command and returns the raw response. | Execute 发送原始命令并返回原始响应。
	Execute(ctx context.Context, command []byte) ([]byte, error)
	// Close releases the device or platform context; it is idempotent. | Close 释放设备或平台上下文；
	// 它是幂等的。
	Close() error
}

// TPMOptions configures OpenTPM. | TPMOptions 配置 OpenTPM。
type TPMOptions struct {
	// DevicePath overrides the platform device path. On Linux it names a /dev/tpm* node; on Windows
	// it is ignored because TBS is used. Empty selects the platform default. | DevicePath 覆盖平台设备
	// 路径。Linux 上它指定 /dev/tpm* 节点；Windows 上因使用 TBS 而被忽略。空值选择平台默认值。
	DevicePath string
	// Timeout bounds every Execute call. Zero selects DefaultTPMTimeout; a negative value is
	// rejected with ErrInvalidConfig. | Timeout 限制每次 Execute 调用。零值选择 DefaultTPMTimeout；
	// 负值以 ErrInvalidConfig 拒绝。
	Timeout time.Duration
}

// validate checks the options and applies the default timeout. | validate 校验选项并应用默认期限。
func (o TPMOptions) validate() (time.Duration, error) {
	if o.Timeout < 0 {
		return 0, errs.Detail(ErrInvalidConfig, "TPM timeout %s is negative | TPM 期限 %s 为负值", o.Timeout, o.Timeout)
	}
	if o.Timeout == 0 {
		return DefaultTPMTimeout, nil
	}
	return o.Timeout, nil
}

// OpenTPM opens the platform TPM transport. | OpenTPM 打开平台 TPM 传输。
//
// Linux uses /dev/tpmrm0 (falling back to /dev/tpm0 when TPMOptions.DevicePath is empty), Windows uses
// the TPM Base Services raw TPM 2.0 interface, and other platforms return ErrUnsupported. A missing
// device or service is reported as ErrTPMUnavailable. | Linux 使用 /dev/tpmrm0（DevicePath 为空时回退到
// /dev/tpm0），Windows 使用 TPM Base Services 原始 TPM 2.0 接口，其他平台返回 ErrUnsupported。设备或
// 服务缺失报告为 ErrTPMUnavailable。
func OpenTPM(options TPMOptions) (TPM, error) {
	timeout, err := options.validate()
	if err != nil {
		return nil, err
	}
	return openPlatformTPM(options, timeout)
}

// validateTPMCommand checks the command framing before handing it to the transport. | validateTPMCommand
// 在交给传输前检查命令框架。
func validateTPMCommand(command []byte) error {
	if len(command) < 10 {
		return errs.Detail(ErrTPMStructure, "TPM command is %d bytes, header needs 10 | TPM 命令为 %d 字节，头部需要 10",
			len(command), len(command))
	}
	if len(command) > MaxTPM2CommandSize {
		return errs.Detail(ErrTPMStructure, "TPM command is %d bytes, limit %d | TPM 命令为 %d 字节，上限 %d",
			len(command), MaxTPM2CommandSize, len(command), MaxTPM2CommandSize)
	}
	declared := uint32(command[2])<<24 | uint32(command[3])<<16 | uint32(command[4])<<8 | uint32(command[5])
	if declared != uint32(len(command)) {
		return errs.Detail(ErrTPMStructure, "TPM command header size %d differs from %d bytes | TPM 命令头大小 %d 与 %d 字节不一致",
			declared, len(command), declared, len(command))
	}
	return nil
}

// validateTPMResponse checks the response framing returned by a transport. | validateTPMResponse 检查
// 传输返回的响应框架。
func validateTPMResponse(response []byte) error {
	if len(response) < 10 {
		return errs.Detail(ErrTPMTransport, "TPM response is %d bytes, header needs 10 | TPM 响应为 %d 字节，头部需要 10",
			len(response), len(response))
	}
	if len(response) > MaxTPM2CommandSize {
		return errs.Detail(ErrTPMTransport, "TPM response is %d bytes, limit %d | TPM 响应为 %d 字节，上限 %d",
			len(response), MaxTPM2CommandSize, len(response), MaxTPM2CommandSize)
	}
	declared := uint32(response[2])<<24 | uint32(response[3])<<16 | uint32(response[4])<<8 | uint32(response[5])
	if declared != uint32(len(response)) {
		return errs.Detail(ErrTPMTransport, "TPM response header size %d differs from %d bytes | TPM 响应头大小 %d 与 %d 字节不一致",
			declared, len(response), declared, len(response))
	}
	return nil
}

// tpmCommandContext derives a context bounded by the device timeout. | tpmCommandContext 派生受设备期限
// 限制的上下文。
func tpmCommandContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, timeout)
}

// tpmContextError classifies a canceled TPM wait. The wall clock can cross the deadline a few
// microseconds before the context timer fires, so the fallback cause is also classified. |
// tpmContextError 分类被取消的 TPM 等待。墙钟可能比上下文计时器早几微秒越过期限，因此回退原因也会
// 被分类。
func tpmContextError(ctx context.Context, fallback error) error {
	cause := fallback
	if ctx != nil && ctx.Err() != nil {
		cause = ctx.Err()
	}
	switch {
	case errors.Is(cause, context.DeadlineExceeded):
		return errs.WrapDetail(context.DeadlineExceeded, ErrTPMTimeout, "TPM command deadline exceeded | TPM 命令超过期限")
	case errors.Is(cause, context.Canceled):
		return errs.WrapDetail(context.Canceled, ErrTPMTransport, "TPM command canceled | TPM 命令已取消")
	default:
		return fallback
	}
}

// tpmClosedError returns the error for operations on a closed transport. | tpmClosedError 返回已关闭传输上
// 操作使用的错误。
func tpmClosedError() error {
	return errs.Detail(ErrTPMTransport, "TPM transport is closed | TPM 传输已关闭")
}
