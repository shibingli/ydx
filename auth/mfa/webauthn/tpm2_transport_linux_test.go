//go:build linux

package webauthn

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// newTestLinuxTPM builds a linuxTPM backed by a connected socket pair and returns the peer end. |
// newTestLinuxTPM 构建由已连接套接字对支撑的 linuxTPM，并返回对端。
func newTestLinuxTPM(t *testing.T) (*linuxTPM, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socketpair error = %v", err)
	}
	device := &linuxTPM{fd: fds[0], timeout: 2 * time.Second}
	t.Cleanup(func() {
		_ = device.Close()
		_ = unix.Close(fds[1])
	})
	return device, fds[1]
}

// unixReadFull reads exactly buffer from fd. | unixReadFull 从 fd 精确读取 buffer。
func unixReadFull(fd int, buffer []byte) error {
	for len(buffer) > 0 {
		read, err := unix.Read(fd, buffer)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if read == 0 {
			return unix.ENODATA
		}
		buffer = buffer[read:]
	}
	return nil
}

// unixWriteAll writes every byte to fd. | unixWriteAll 向 fd 写入全部字节。
func unixWriteAll(fd int, buffer []byte) error {
	for len(buffer) > 0 {
		written, err := unix.Write(fd, buffer)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if written <= 0 {
			return unix.ENODATA
		}
		buffer = buffer[written:]
	}
	return nil
}

// TestLinuxTPMExecute checks a complete command/response exchange over the device abstraction. |
// TestLinuxTPMExecute 校验通过设备抽象的完整命令/响应交换。
func TestLinuxTPMExecute(t *testing.T) {
	device, peer := newTestLinuxTPM(t)
	command := testReadPublicCommand()
	response := testTPMResponseImage(nil)
	peerErr := make(chan error, 1)
	go func() {
		buffer := make([]byte, len(command))
		if err := unixReadFull(peer, buffer); err != nil {
			peerErr <- err
			return
		}
		if !bytes.Equal(buffer, command) {
			peerErr <- unix.EINVAL
			return
		}
		peerErr <- unixWriteAll(peer, response)
	}()

	got, err := device.Execute(t.Context(), command)
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}
	if !bytes.Equal(got, response) {
		t.Fatalf("Execute response = %x, want %x", got, response)
	}
	if err := <-peerErr; err != nil {
		t.Fatalf("peer error = %v", err)
	}
	if err := device.Close(); err != nil {
		t.Fatalf("Close error = %v", err)
	}
	if err := device.Close(); err != nil {
		t.Fatalf("second Close error = %v", err)
	}
	if _, err := device.Execute(context.Background(), command); !errors.Is(err, ErrTPMTransport) {
		t.Fatalf("Execute after Close error = %v, want ErrTPMTransport", err)
	}
}

// TestLinuxTPMTimeout checks that an unanswered read is abandoned at the command deadline. |
// TestLinuxTPMTimeout 校验未获应答的读取在命令期限到达时放弃。
func TestLinuxTPMTimeout(t *testing.T) {
	device, _ := newTestLinuxTPM(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := device.Execute(ctx, testReadPublicCommand()); !errors.Is(err, ErrTPMTimeout) {
		t.Fatalf("Execute timeout error = %v, want ErrTPMTimeout", err)
	}
	canceledCtx, canceledCancel := context.WithCancel(context.Background())
	canceledCancel()
	if _, err := device.Execute(canceledCtx, testReadPublicCommand()); !errors.Is(err, ErrTPMTransport) {
		t.Fatalf("Execute cancellation error = %v, want ErrTPMTransport", err)
	}
	if _, err := device.Execute(t.Context(), []byte{0x80}); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("malformed command error = %v, want ErrTPMStructure", err)
	}
}
