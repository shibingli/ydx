//go:build linux

package webauthn

import (
	"context"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
	"golang.org/x/sys/unix"
)

// linuxTPMCandidates are the device nodes tried when TPMOptions.DevicePath is empty. | linuxTPMCandidates
// 是 TPMOptions.DevicePath 为空时尝试的设备节点。
var linuxTPMCandidates = []string{"/dev/tpmrm0", "/dev/tpm0"}

// tpmPollInterval bounds how long a blocked read or write waits before observing context cancellation. |
// tpmPollInterval 限制阻塞读写观察上下文取消前等待的时长。
const tpmPollInterval = 50 * time.Millisecond

// linuxTPM is a Linux character-device TPM transport. | linuxTPM 是 Linux 字符设备 TPM 传输。
type linuxTPM struct {
	mu      sync.Mutex
	fd      int
	timeout time.Duration
	closed  bool
}

// openPlatformTPM opens the Linux TPM device. | openPlatformTPM 打开 Linux TPM 设备。
func openPlatformTPM(options TPMOptions, timeout time.Duration) (TPM, error) {
	candidates := linuxTPMCandidates
	if options.DevicePath != "" {
		candidates = []string{options.DevicePath}
	}
	var lastErr error
	for _, path := range candidates {
		fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err == nil {
			return &linuxTPM{fd: fd, timeout: timeout}, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = unix.ENODEV
	}
	return nil, errs.WrapDetail(lastErr, ErrTPMUnavailable, "no TPM device is available | 没有可用的 TPM 设备")
}

// Execute sends one TPM command and reads one response. | Execute 发送一个 TPM 命令并读取一个响应。
func (d *linuxTPM) Execute(ctx context.Context, command []byte) ([]byte, error) {
	if err := validateTPMCommand(command); err != nil {
		return nil, err
	}
	waitCtx, cancel := tpmCommandContext(ctx, d.timeout)
	defer cancel()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, tpmClosedError()
	}
	if err := waitCtx.Err(); err != nil {
		return nil, tpmContextError(waitCtx, err)
	}
	if err := d.writeAll(waitCtx, command); err != nil {
		return nil, err
	}
	header := make([]byte, 10)
	if err := d.readFull(waitCtx, header); err != nil {
		return nil, err
	}
	size := uint32(header[2])<<24 | uint32(header[3])<<16 | uint32(header[4])<<8 | uint32(header[5])
	if size < 10 || size > MaxTPM2CommandSize {
		return nil, errs.Detail(ErrTPMTransport, "TPM response declares %d bytes | TPM 响应声明 %d 字节", size, size)
	}
	response := make([]byte, int(size))
	copy(response, header)
	if len(response) > len(header) {
		if err := d.readFull(waitCtx, response[len(header):]); err != nil {
			return nil, err
		}
	}
	if err := validateTPMResponse(response); err != nil {
		return nil, err
	}
	return response, nil
}

// Close closes the device node. | Close 关闭设备节点。
func (d *linuxTPM) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	fd := d.fd
	d.fd = -1
	if err := unix.Close(fd); err != nil {
		return errs.WrapDetail(err, ErrTPMTransport, "TPM device close failed | TPM 设备关闭失败")
	}
	return nil
}

// writeAll writes every byte, polling for writability. | writeAll 写入全部字节，并轮询可写状态。
func (d *linuxTPM) writeAll(ctx context.Context, buffer []byte) error {
	for len(buffer) > 0 {
		if err := d.poll(ctx, unix.POLLOUT); err != nil {
			return err
		}
		written, err := unix.Write(d.fd, buffer)
		switch {
		case err == unix.EINTR:
			continue
		case err == unix.EAGAIN || err == unix.EWOULDBLOCK:
			continue
		case err != nil:
			return errs.WrapDetail(err, ErrTPMTransport, "TPM device write failed | TPM 设备写入失败")
		case written <= 0:
			return errs.Detail(ErrTPMTransport, "TPM device write returned no progress | TPM 设备写入无进展")
		}
		buffer = buffer[written:]
	}
	return nil
}

// readFull reads exactly buffer. | readFull 精确读取 buffer。
func (d *linuxTPM) readFull(ctx context.Context, buffer []byte) error {
	for len(buffer) > 0 {
		if err := d.poll(ctx, unix.POLLIN); err != nil {
			return err
		}
		read, err := unix.Read(d.fd, buffer)
		switch {
		case err == unix.EINTR:
			continue
		case err == unix.EAGAIN || err == unix.EWOULDBLOCK:
			continue
		case err != nil:
			return errs.WrapDetail(err, ErrTPMTransport, "TPM device read failed | TPM 设备读取失败")
		case read == 0:
			return errs.Detail(ErrTPMTransport, "TPM device closed during read | TPM 设备在读取期间关闭")
		}
		buffer = buffer[read:]
	}
	return nil
}

// poll waits for the requested event while observing context cancellation. | poll 等待请求的事件，同时
// 观察上下文取消。
func (d *linuxTPM) poll(ctx context.Context, events int16) error {
	for {
		if err := ctx.Err(); err != nil {
			return tpmContextError(ctx, err)
		}
		timeout := tpmPollInterval
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return tpmContextError(ctx, context.DeadlineExceeded)
			}
			if remaining < timeout {
				timeout = remaining
			}
		}
		milliseconds := int(timeout / time.Millisecond)
		if milliseconds < 1 {
			milliseconds = 1
		}
		fds := []unix.PollFd{{Fd: int32(d.fd), Events: events}}
		count, err := unix.Poll(fds, milliseconds)
		switch {
		case err == unix.EINTR:
			continue
		case err != nil:
			return errs.WrapDetail(err, ErrTPMTransport, "TPM device poll failed | TPM 设备轮询失败")
		case count == 0:
			continue
		}
		if fds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return errs.Detail(ErrTPMTransport, "TPM device reported an error while polling | TPM 设备轮询时报告错误")
		}
		if fds[0].Revents&events != 0 {
			return nil
		}
	}
}
