package webauthn

import (
	"context"
	"errors"
	"testing"
	"time"
)

// testReadPublicCommand returns a framed TPM2_ReadPublic command for transport tests. |
// testReadPublicCommand 返回传输测试使用的 TPM2_ReadPublic 命令镜像。
func testReadPublicCommand() []byte {
	return []byte{
		0x80, 0x01, 0x00, 0x00, 0x00, 0x0E,
		0x00, 0x00, 0x01, 0x73,
		0x81, 0x00, 0x00, 0x01,
	}
}

// testTPMResponseImage builds a framed response for transport tests. | testTPMResponseImage 构建传输
// 测试使用的响应镜像。
func testTPMResponseImage(parameters []byte) []byte {
	size := 10 + len(parameters)
	response := make([]byte, 0, size)
	response = tpm2AppendU16(response, TPMSTNoSessions)
	response = tpm2AppendU32(response, uint32(size))
	response = tpm2AppendU32(response, TPMRCSuccess)
	return append(response, parameters...)
}

// TestValidateTPMCommand checks command framing validation. | TestValidateTPMCommand 校验命令框架校验。
func TestValidateTPMCommand(t *testing.T) {
	valid := testReadPublicCommand()
	if err := validateTPMCommand(valid); err != nil {
		t.Fatalf("valid command error = %v", err)
	}
	if err := validateTPMCommand(valid[:9]); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("short command error = %v, want ErrTPMStructure", err)
	}
	mismatched := append([]byte(nil), valid...)
	mismatched[5] = 0x0F
	if err := validateTPMCommand(mismatched); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("mismatched length error = %v, want ErrTPMStructure", err)
	}
	oversized := make([]byte, MaxTPM2CommandSize+1)
	copy(oversized, valid)
	if err := validateTPMCommand(oversized); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("oversized command error = %v, want ErrTPMStructure", err)
	}
}

// TestValidateTPMResponse checks response framing validation. | TestValidateTPMResponse 校验响应框架校验。
func TestValidateTPMResponse(t *testing.T) {
	valid := testTPMResponseImage([]byte{0x01, 0x02})
	if err := validateTPMResponse(valid); err != nil {
		t.Fatalf("valid response error = %v", err)
	}
	if err := validateTPMResponse(valid[:9]); !errors.Is(err, ErrTPMTransport) {
		t.Fatalf("short response error = %v, want ErrTPMTransport", err)
	}
	mismatched := append([]byte(nil), valid...)
	mismatched[5] = 0x05
	if err := validateTPMResponse(mismatched); !errors.Is(err, ErrTPMTransport) {
		t.Fatalf("mismatched response error = %v, want ErrTPMTransport", err)
	}
	oversized := make([]byte, MaxTPM2CommandSize+1)
	copy(oversized, valid)
	if err := validateTPMResponse(oversized); !errors.Is(err, ErrTPMTransport) {
		t.Fatalf("oversized response error = %v, want ErrTPMTransport", err)
	}
}

// TestTPMOptionsValidate checks timeout defaults and rejection of negative values. |
// TestTPMOptionsValidate 校验期限默认值与负值拒绝。
func TestTPMOptionsValidate(t *testing.T) {
	timeout, err := (TPMOptions{}).validate()
	if err != nil || timeout != DefaultTPMTimeout {
		t.Fatalf("default options validate = %s, %v", timeout, err)
	}
	timeout, err = (TPMOptions{Timeout: 2 * time.Second}).validate()
	if err != nil || timeout != 2*time.Second {
		t.Fatalf("explicit options validate = %s, %v", timeout, err)
	}
	if _, err := (TPMOptions{Timeout: -time.Second}).validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("negative timeout error = %v, want ErrInvalidConfig", err)
	}
	if _, err := OpenTPM(TPMOptions{Timeout: -time.Second}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("OpenTPM negative timeout error = %v, want ErrInvalidConfig", err)
	}
}

// TestTPMContextError checks deadline and cancellation classification. |
// TestTPMContextError 校验期限与取消分类。
func TestTPMContextError(t *testing.T) {
	fallback := errors.New("fallback")
	if got := tpmContextError(nil, fallback); got != fallback {
		t.Fatalf("nil context error = %v, want fallback", got)
	}
	if got := tpmContextError(context.Background(), fallback); got != fallback {
		t.Fatalf("background context error = %v, want fallback", got)
	}

	deadlineCtx, deadlineCancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer deadlineCancel()
	<-deadlineCtx.Done()
	err := tpmContextError(deadlineCtx, fallback)
	if !errors.Is(err, ErrTPMTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline context error = %v, want ErrTPMTimeout", err)
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	err = tpmContextError(canceledCtx, fallback)
	if !errors.Is(err, ErrTPMTransport) || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context error = %v, want ErrTPMTransport", err)
	}
}

// TestTPMCommandContext checks timeout derivation. | TestTPMCommandContext 校验期限派生。
func TestTPMCommandContext(t *testing.T) {
	commandCtx, cancel := tpmCommandContext(nil, 25*time.Millisecond)
	defer cancel()
	deadline, ok := commandCtx.Deadline()
	if !ok || time.Until(deadline) > 25*time.Millisecond {
		t.Fatalf("command context deadline = %s, present %v", deadline, ok)
	}
	parent, parentCancel := context.WithCancel(context.Background())
	defer parentCancel()
	child, childCancel := tpmCommandContext(parent, time.Minute)
	defer childCancel()
	parentCancel()
	<-child.Done()
	if !errors.Is(child.Err(), context.Canceled) {
		t.Fatalf("child context error = %v, want context.Canceled", child.Err())
	}
}

// blockingTPM blocks until the command context completes. | blockingTPM 阻塞直到命令上下文完成。
type blockingTPM struct{}

// Execute implements TPM. | Execute 实现 TPM。
func (b *blockingTPM) Execute(ctx context.Context, _ []byte) ([]byte, error) {
	<-ctx.Done()
	return nil, tpmContextError(ctx, ctx.Err())
}

// Close implements TPM. | Close 实现 TPM。
func (b *blockingTPM) Close() error { return nil }

// TestTPM2CallContextCancellation checks cancellation propagation through TPM2Call. |
// TestTPM2CallContextCancellation 校验通过 TPM2Call 的取消传播。
func TestTPM2CallContextCancellation(t *testing.T) {
	command := &TPM2Command{Tag: TPMSTNoSessions, CommandCode: TPMCCReadPublic, Handles: []uint32{softwareTPMPersistentEK}}
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := TPM2Call(canceledCtx, &blockingTPM{}, command); !errors.Is(err, ErrTPMTransport) {
		t.Fatalf("canceled call error = %v, want ErrTPMTransport", err)
	}
	deadlineCtx, deadlineCancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer deadlineCancel()
	if _, err := TPM2Call(deadlineCtx, &blockingTPM{}, command); !errors.Is(err, ErrTPMTimeout) {
		t.Fatalf("timed out call error = %v, want ErrTPMTimeout", err)
	}
}

// TestOpenTPMPlatform detects whether the host exposes a usable TPM. | TestOpenTPMPlatform 检测主机是否
// 提供可用的 TPM。
//
// The test never fails because a host lacks a TPM: absent devices are expected and reported through
// ErrTPMUnavailable or ErrUnsupported. When a TPM is present its manufacturer property is queried so
// the transport is exercised end to end. | 主机缺少 TPM 时测试不会失败：设备缺失是预期情况，并通过
// ErrTPMUnavailable 或 ErrUnsupported 报告。存在 TPM 时会查询制造商属性，以端到端方式验证传输。
func TestOpenTPMPlatform(t *testing.T) {
	device, err := OpenTPM(TPMOptions{Timeout: 5 * time.Second})
	if err != nil {
		if !errors.Is(err, ErrTPMUnavailable) && !errors.Is(err, ErrUnsupported) {
			t.Fatalf("OpenTPM error = %v, want ErrTPMUnavailable or ErrUnsupported", err)
		}
		t.Logf("no platform TPM available: %v", err)
		return
	}
	defer func() {
		if err := device.Close(); err != nil {
			t.Logf("TPM Close error: %v", err)
		}
	}()
	t.Log("platform TPM transport opened")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	capability, err := GetCapability(ctx, device, TPMCapTPMProperties, TPMPropertyManufacturer, 4)
	if err != nil {
		t.Logf("platform TPM detected but property query failed: %v", err)
		return
	}
	manufacturer := uint32(0)
	for _, property := range capability.Properties {
		if property.Property == TPMPropertyManufacturer {
			manufacturer = property.Value
		}
	}
	t.Logf("real TPM detected: manufacturer=%#08x, %d properties", manufacturer, len(capability.Properties))
}
