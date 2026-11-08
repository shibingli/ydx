//go:build windows

package webauthn

import (
	"context"
	"sync"
	"time"
	"unsafe"

	"github.com/shibingli/ydx/errs"
	"golang.org/x/sys/windows"
)

// TPM Base Services constants. | TPM Base Services 常量。
const (
	// tbsContextParams2Version is TBS_CONTEXT_PARAMS2.version for Windows 8 and later. |
	// tbsContextParams2Version 是 Windows 8 及以后 TBS_CONTEXT_PARAMS2.version 的值。
	tbsContextParams2Version uint32 = 2
	// tbsContextRequestRaw is TBS_CONTEXT_PARAMS2_REQUEST_RAW. | tbsContextRequestRaw 是
	// TBS_CONTEXT_PARAMS2_REQUEST_RAW。
	tbsContextRequestRaw uint32 = 0x1
	// tbsContextIncludeTPM20 is TBS_CONTEXT_PARAMS2_INCLUDE_TPM20. | tbsContextIncludeTPM20 是
	// TBS_CONTEXT_PARAMS2_INCLUDE_TPM20。
	tbsContextIncludeTPM20 uint32 = 0x4
	// tbsCommandLocalityZero is TBS_COMMAND_LOCALITY_ZERO. | tbsCommandLocalityZero 是
	// TBS_COMMAND_LOCALITY_ZERO。
	tbsCommandLocalityZero uint32 = 0
	// tbsCommandPriorityNormal is TBS_COMMAND_PRIORITY_NORMAL. | tbsCommandPriorityNormal 是
	// TBS_COMMAND_PRIORITY_NORMAL。
	tbsCommandPriorityNormal uint32 = 200
	// tbsSuccess is TBS_SUCCESS. | tbsSuccess 是 TBS_SUCCESS。
	tbsSuccess uint32 = 0
)

// tbsContextParams2 mirrors TBS_CONTEXT_PARAMS2. | tbsContextParams2 对应 TBS_CONTEXT_PARAMS2。
type tbsContextParams2 struct {
	// Version is the structure version, 2 for raw TPM 2.0 contexts. | Version 是结构版本，原始
	// TPM 2.0 上下文为 2。
	Version uint32
	// Flags packs requestRaw, includeTpm12 and includeTpm20 bits. | Flags 打包 requestRaw、
	// includeTpm12 与 includeTpm20 位。
	Flags uint32
}

// tbsProcs holds the TPM Base Services entry points. | tbsProcs 保存 TPM Base Services 入口点。
type tbsProcs struct {
	contextCreate  *windows.LazyProc
	submitCommand  *windows.LazyProc
	cancelCommands *windows.LazyProc
	contextClose   *windows.LazyProc
}

// windowsTPM is a Windows TBS raw TPM 2.0 transport. | windowsTPM 是 Windows TBS 原始 TPM 2.0 传输。
type windowsTPM struct {
	mu      sync.Mutex
	procs   *tbsProcs
	context uintptr
	timeout time.Duration
	closed  bool
}

// loadTBSProcs resolves tbs.dll and every entry point. | loadTBSProcs 解析 tbs.dll 与所有入口点。
func loadTBSProcs() (*tbsProcs, error) {
	dll := windows.NewLazySystemDLL("tbs.dll")
	if err := dll.Load(); err != nil {
		return nil, errs.WrapDetail(err, ErrTPMUnavailable, "TPM Base Services is not available | TPM Base Services 不可用")
	}
	procs := &tbsProcs{
		contextCreate:  dll.NewProc("Tbsi_Context_Create"),
		submitCommand:  dll.NewProc("Tbsip_Submit_Command"),
		cancelCommands: dll.NewProc("Tbsip_Cancel_Commands"),
		contextClose:   dll.NewProc("Tbsip_Context_Close"),
	}
	for name, proc := range map[string]*windows.LazyProc{
		"Tbsi_Context_Create":   procs.contextCreate,
		"Tbsip_Submit_Command":  procs.submitCommand,
		"Tbsip_Cancel_Commands": procs.cancelCommands,
		"Tbsip_Context_Close":   procs.contextClose,
	} {
		if err := proc.Find(); err != nil {
			return nil, errs.WrapDetail(err, ErrTPMUnavailable, "TPM Base Services lacks %s | TPM Base Services 缺少 %s", name, name)
		}
	}
	return procs, nil
}

// openPlatformTPM creates a raw TPM 2.0 TBS context. | openPlatformTPM 创建原始 TPM 2.0 TBS 上下文。
func openPlatformTPM(options TPMOptions, timeout time.Duration) (TPM, error) {
	_ = options
	procs, err := loadTBSProcs()
	if err != nil {
		return nil, err
	}
	params := tbsContextParams2{
		Version: tbsContextParams2Version,
		Flags:   tbsContextRequestRaw | tbsContextIncludeTPM20,
	}
	var handle uintptr
	result, _, _ := procs.contextCreate.Call(
		uintptr(unsafe.Pointer(&params)),
		uintptr(unsafe.Pointer(&handle)),
	)
	if uint32(result) != tbsSuccess {
		return nil, errs.Detail(ErrTPMUnavailable, "TBS raw TPM 2.0 context creation failed with TBS_RESULT %#08x | TBS 原始 TPM 2.0 上下文创建失败，TBS_RESULT %#08x",
			uint32(result), uint32(result))
	}
	if handle == 0 {
		return nil, errs.Detail(ErrTPMUnavailable, "TBS returned an empty TPM context | TBS 返回空 TPM 上下文")
	}
	return &windowsTPM{procs: procs, context: handle, timeout: timeout}, nil
}

// Execute submits one TPM command through TBS. | Execute 通过 TBS 提交一个 TPM 命令。
func (d *windowsTPM) Execute(ctx context.Context, command []byte) ([]byte, error) {
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
	response := make([]byte, MaxTPM2CommandSize)
	resultSize := uint32(len(response))
	done := make(chan uint32, 1)
	go func() {
		result, _, _ := d.procs.submitCommand.Call(
			d.context,
			uintptr(tbsCommandLocalityZero),
			uintptr(tbsCommandPriorityNormal),
			uintptr(unsafe.Pointer(&command[0])),
			uintptr(len(command)),
			uintptr(unsafe.Pointer(&response[0])),
			uintptr(unsafe.Pointer(&resultSize)),
		)
		done <- uint32(result)
	}()
	select {
	case result := <-done:
		if result != tbsSuccess {
			return nil, errs.Detail(ErrTPMTransport, "TBS command submission failed with TBS_RESULT %#08x | TBS 命令提交失败，TBS_RESULT %#08x",
				result, result)
		}
	case <-waitCtx.Done():
		// Tbsip_Cancel_Commands is the only safe way to abandon an in-flight submission: the command
		// and response buffers must stay alive until the system call returns. | Tbsip_Cancel_Commands
		// 是安全放弃在途提交的唯一方式：命令与响应缓冲区必须在系统调用返回后才能释放。
		_, _, _ = d.procs.cancelCommands.Call(d.context)
		<-done
		return nil, tpmContextError(waitCtx, waitCtx.Err())
	}
	if resultSize < 10 || resultSize > MaxTPM2CommandSize {
		return nil, errs.Detail(ErrTPMTransport, "TBS returned a %d byte response | TBS 返回 %d 字节响应", resultSize, resultSize)
	}
	reply := response[:resultSize]
	if err := validateTPMResponse(reply); err != nil {
		return nil, err
	}
	return reply, nil
}

// Close closes the TBS context. | Close 关闭 TBS 上下文。
func (d *windowsTPM) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	result, _, _ := d.procs.contextClose.Call(d.context)
	if uint32(result) != tbsSuccess {
		return errs.Detail(ErrTPMTransport, "TBS context close failed with TBS_RESULT %#08x | TBS 上下文关闭失败，TBS_RESULT %#08x",
			uint32(result), uint32(result))
	}
	return nil
}
