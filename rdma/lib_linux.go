//go:build linux && rdma && (amd64 || arm64)

package rdma

import (
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/shibingli/ydx/errs"
)

// verbsAPI holds the resolved libibverbs entry points. Hot-path ops call the
// context function pointers through purego's system-stack trampoline; control
// calls use purego.SyscallN directly. | verbsAPI 保存解析后的 libibverbs 入口。
// 热路径经 purego 的系统栈跳板调用上下文函数指针；控制面直接使用
// purego.SyscallN。
type verbsAPI struct {
	lib            uintptr
	path           string
	getDeviceList  uintptr
	freeDeviceList uintptr
	getDeviceName  uintptr
	openDevice     uintptr
	closeDevice    uintptr
	queryDevice    uintptr
	queryPort      uintptr
	allocPD        uintptr
	deallocPD      uintptr
	createCQ       uintptr
	destroyCQ      uintptr
	regMR          uintptr
	deregMR        uintptr
	createQP       uintptr
	destroyQP      uintptr
	modifyQP       uintptr
	queryQP        uintptr
	createSRQ      uintptr
	destroySRQ     uintptr
	createAH       uintptr
	destroyAH      uintptr
	errnoLoc       uintptr
}

// defaultVerbsLibraries lists portable sonames first, then distribution
// specific paths for Debian/Ubuntu, RHEL/Fedora, SUSE and Mellanox OFED. |
// defaultVerbsLibraries 先列出可移植 soname，再列出 Debian/Ubuntu、
// RHEL/Fedora、SUSE 与 Mellanox OFED 的发行版路径。
var defaultVerbsLibraries = []string{
	"libibverbs.so.1",
	"libibverbs.so",
	"/usr/lib/x86_64-linux-gnu/libibverbs.so.1",
	"/usr/lib/aarch64-linux-gnu/libibverbs.so.1",
	"/usr/lib64/libibverbs.so.1",
	"/usr/lib/libibverbs.so.1",
	"/usr/local/lib/libibverbs.so.1",
	"/usr/local/lib64/libibverbs.so.1",
}

// verbsResult caches one load attempt. | verbsResult 缓存一次加载结果。
type verbsResult struct {
	api *verbsAPI
	err error
}

var verbsCache sync.Map // path -> verbsResult | 路径到加载结果

// loadVerbs resolves libibverbs for path. An empty path tries each default in
// order; a non-empty path is used exclusively. | loadVerbs 解析 path 对应的
// libibverbs。空路径按顺序尝试每个默认值；非空路径只尝试该路径。
func loadVerbs(path string) (*verbsAPI, error) {
	key := path
	if key == "" {
		key = "<auto>"
	}
	if cached, ok := verbsCache.Load(key); ok {
		r := cached.(verbsResult)
		return r.api, r.err
	}
	var api *verbsAPI
	var err error
	if path != "" {
		api, err = openVerbs(path)
	} else {
		var lastErr error
		for _, candidate := range defaultVerbsLibraries {
			api, err = openVerbs(candidate)
			if err == nil {
				break
			}
			lastErr = err
		}
		if api == nil {
			err = lastErr
		}
	}
	if err != nil {
		verbsCache.Store(key, verbsResult{nil, err})
		return nil, err
	}
	verbsCache.Store(key, verbsResult{api, nil})
	return api, nil
}

// openVerbs loads and resolves one libibverbs path. | openVerbs 加载并解析一个
// libibverbs 路径。
func openVerbs(path string) (*verbsAPI, error) {
	lib, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrUnsupported, "load %s | 加载 %s", path, path)
	}
	api := &verbsAPI{lib: lib, path: path}
	symbols := []struct {
		name string
		out  *uintptr
	}{
		{"ibv_get_device_list", &api.getDeviceList},
		{"ibv_free_device_list", &api.freeDeviceList},
		{"ibv_get_device_name", &api.getDeviceName},
		{"ibv_open_device", &api.openDevice},
		{"ibv_close_device", &api.closeDevice},
		{"ibv_query_device", &api.queryDevice},
		{"ibv_query_port", &api.queryPort},
		{"ibv_alloc_pd", &api.allocPD},
		{"ibv_dealloc_pd", &api.deallocPD},
		{"ibv_create_cq", &api.createCQ},
		{"ibv_destroy_cq", &api.destroyCQ},
		{"ibv_reg_mr", &api.regMR},
		{"ibv_dereg_mr", &api.deregMR},
		{"ibv_create_qp", &api.createQP},
		{"ibv_destroy_qp", &api.destroyQP},
		{"ibv_modify_qp", &api.modifyQP},
		{"ibv_query_qp", &api.queryQP},
		{"ibv_create_srq", &api.createSRQ},
		{"ibv_destroy_srq", &api.destroySRQ},
		{"ibv_create_ah", &api.createAH},
		{"ibv_destroy_ah", &api.destroyAH},
	}
	for _, s := range symbols {
		sym, err := purego.Dlsym(lib, s.name)
		if err != nil {
			_ = purego.Dlclose(lib)
			return nil, errs.WrapDetail(err, ErrUnsupported, "resolve %s | 解析 %s", s.name, s.name)
		}
		*s.out = sym
	}
	// purego clears the errno slot on Linux, so NULL-returning verbs need the
	// thread-local errno read explicitly. Resolve the libc accessor through the
	// already-loaded library; providers link libc. | purego 在 Linux 上会清零 errno
	// 槽位，因此返回 NULL 的 verbs 需要显式读取线程局部 errno。通过已加载的库解析
	// libc 访问器；提供方均链接 libc。
	if sym, err := purego.Dlsym(lib, "__errno_location"); err == nil {
		api.errnoLoc = sym
	} else if libc, lerr := purego.Dlopen("libc.so.6", purego.RTLD_NOW|purego.RTLD_GLOBAL); lerr == nil {
		if sym, serr := purego.Dlsym(libc, "__errno_location"); serr == nil {
			api.errnoLoc = sym
		}
	}
	return api, nil
}

// callControl invokes a NULL-returning control call and captures errno on the
// same OS thread. Locking the thread is required because the C call and the
// __errno_location read must observe the same thread-local errno. | callControl
// 调用返回 NULL 的控制面函数，并在同一 OS 线程读取 errno。必须锁定线程，因为 C
// 调用与 __errno_location 读取必须看到同一个线程局部 errno。
func (v *verbsAPI) callControl(fn uintptr, args ...uintptr) (uintptr, int) {
	if fn == 0 {
		return 0, 5 // EIO
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	r, _, _ := purego.SyscallN(fn, args...)
	if r == 0 && v.errnoLoc != 0 {
		p, _, _ := purego.SyscallN(v.errnoLoc)
		if p != 0 {
			if errno := int(*(*int32)(ptrFromUintptr(p))); errno != 0 {
				return 0, errno
			}
		}
	}
	return r, 0
}

// ptrFromUintptr converts an address returned by libibverbs into a pointer
// without tripping go vet's uintptr heuristic. | ptrFromUintptr 将 libibverbs
// 返回的地址转换为指针，避免触发 go vet 的 uintptr 检查。
func ptrFromUintptr(u uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&u))
}

// errnoOfResult maps a captured thread-local errno to an errno, falling back to
// EIO when the provider did not report one. | errnoOfResult 将捕获的线程局部
// errno 映射为 errno，提供方未报告时回退 EIO。
func errnoOfResult(errno int) int {
	if errno != 0 {
		return errno
	}
	return 5 // EIO
}

// deviceList returns the NULL-terminated device array and its count. |
// deviceList 返回以 NULL 结尾的设备数组及数量。
func (v *verbsAPI) deviceList() (unsafe.Pointer, int32) {
	var n int32
	r, _, _ := purego.SyscallN(v.getDeviceList, uintptr(unsafe.Pointer(&n)))
	return ptrFromUintptr(r), n
}

// freeDeviceList releases a device array. | freeDeviceList 释放设备数组。
func (v *verbsAPI) releaseDeviceList(list unsafe.Pointer) {
	purego.SyscallN(v.freeDeviceList, uintptr(list))
}

// deviceName returns the kernel name of a device. | deviceName 返回设备内核名。
func (v *verbsAPI) deviceName(dev *ibvDevice) string {
	r, _, _ := purego.SyscallN(v.getDeviceName, uintptr(unsafe.Pointer(dev)))
	return goStringZ((*byte)(ptrFromUintptr(r)))
}

// goStringZ converts a NUL-terminated C string. | goStringZ 转换以 NUL 结尾的
// C 字符串。
func goStringZ(p *byte) string {
	if p == nil {
		return ""
	}
	n := 0
	for *(*byte)(unsafe.Add(unsafe.Pointer(p), n)) != 0 {
		n++
	}
	return string(unsafe.Slice(p, n))
}

// openDevice opens one device. | openDevice 打开一个设备。
func (v *verbsAPI) open(dev *ibvDevice) (*ibvContext, int) {
	r, errno := v.callControl(v.openDevice, uintptr(unsafe.Pointer(dev)))
	if r == 0 {
		return nil, errnoOfResult(errno)
	}
	return (*ibvContext)(ptrFromUintptr(r)), 0
}

// closeDevice closes one device context. | closeDevice 关闭一个设备上下文。
func (v *verbsAPI) close(ctx *ibvContext) int {
	r, _, _ := purego.SyscallN(v.closeDevice, uintptr(unsafe.Pointer(ctx)))
	return int(int32(r))
}

// queryDevice fills base device attributes. | queryDevice 填充基础设备属性。
func (v *verbsAPI) queryDev(ctx *ibvContext, out *ibvDeviceAttr) int {
	r, _, _ := purego.SyscallN(v.queryDevice, uintptr(unsafe.Pointer(ctx)), uintptr(unsafe.Pointer(out)))
	return int(int32(r))
}

// queryPort fills port attributes. | queryPort 填充端口属性。
func (v *verbsAPI) queryP(ctx *ibvContext, port uint8, out *ibvPortAttr) int {
	r, _, _ := purego.SyscallN(v.queryPort, uintptr(unsafe.Pointer(ctx)), uintptr(port), uintptr(unsafe.Pointer(out)))
	return int(int32(r))
}

// allocPD allocates a protection domain. | allocPD 分配保护域。
func (v *verbsAPI) allocProtectionDomain(ctx *ibvContext) (*ibvPD, int) {
	r, errno := v.callControl(v.allocPD, uintptr(unsafe.Pointer(ctx)))
	if r == 0 {
		return nil, errnoOfResult(errno)
	}
	return (*ibvPD)(ptrFromUintptr(r)), 0
}

// deallocPD releases a protection domain. | deallocPD 释放保护域。
func (v *verbsAPI) deallocProtectionDomain(pd *ibvPD) int {
	r, _, _ := purego.SyscallN(v.deallocPD, uintptr(unsafe.Pointer(pd)))
	return int(int32(r))
}

// createCQ creates a completion queue. | createCQ 创建完成队列。
func (v *verbsAPI) makeCQ(ctx *ibvContext, depth int32) (*ibvCQ, int) {
	r, errno := v.callControl(v.createCQ, uintptr(unsafe.Pointer(ctx)), uintptr(depth), 0, 0, 0)
	if r == 0 {
		return nil, errnoOfResult(errno)
	}
	return (*ibvCQ)(ptrFromUintptr(r)), 0
}

// destroyCQ destroys a completion queue. | destroyCQ 销毁完成队列。
func (v *verbsAPI) removeCQ(cq *ibvCQ) int {
	r, _, _ := purego.SyscallN(v.destroyCQ, uintptr(unsafe.Pointer(cq)))
	return int(int32(r))
}

// regMR registers memory. | regMR 注册内存。
func (v *verbsAPI) registerMR(pd *ibvPD, addr unsafe.Pointer, length int, access Access) (*ibvMR, int) {
	r, errno := v.callControl(v.regMR,
		uintptr(unsafe.Pointer(pd)), uintptr(addr), uintptr(length), uintptr(access))
	if r == 0 {
		return nil, errnoOfResult(errno)
	}
	return (*ibvMR)(ptrFromUintptr(r)), 0
}

// deregMR deregisters memory. | deregMR 注销内存。
func (v *verbsAPI) deregisterMR(mr *ibvMR) int {
	r, _, _ := purego.SyscallN(v.deregMR, uintptr(unsafe.Pointer(mr)))
	return int(int32(r))
}

// createQP creates a queue pair. | createQP 创建队列对。
func (v *verbsAPI) makeQP(pd *ibvPD, attr *ibvQPInitAttr) (*ibvQP, int) {
	r, errno := v.callControl(v.createQP, uintptr(unsafe.Pointer(pd)), uintptr(unsafe.Pointer(attr)))
	if r == 0 {
		return nil, errnoOfResult(errno)
	}
	return (*ibvQP)(ptrFromUintptr(r)), 0
}

// destroyQP destroys a queue pair. | destroyQP 销毁队列对。
func (v *verbsAPI) removeQP(qp *ibvQP) int {
	r, _, _ := purego.SyscallN(v.destroyQP, uintptr(unsafe.Pointer(qp)))
	return int(int32(r))
}

// modifyQP applies queue pair attributes. | modifyQP 应用队列对属性。
func (v *verbsAPI) modify(qp *ibvQP, attr *ibvQPAttr, mask QPAttrMask) int {
	r, _, _ := purego.SyscallN(v.modifyQP, uintptr(unsafe.Pointer(qp)), uintptr(unsafe.Pointer(attr)), uintptr(mask))
	return int(int32(r))
}

// qpCap reports the provider-granted send and receive queue depths. |
// qpCap 返回提供方实际授予的发送与接收队列深度。
func (v *verbsAPI) qpCap(qp *ibvQP) (int, int, int) {
	var attr ibvQPAttr
	var init ibvQPInitAttr
	r, _, _ := purego.SyscallN(v.queryQP, uintptr(unsafe.Pointer(qp)),
		uintptr(unsafe.Pointer(&attr)), 0, uintptr(unsafe.Pointer(&init)))
	if int(int32(r)) != 0 {
		return 0, 0, int(int32(r))
	}
	return int(attr.Cap.MaxSendWR), int(attr.Cap.MaxRecvWR), 0
}

// queryQPState reads the current queue pair state. | queryQPState 读取当前
// 队列对状态。
func (v *verbsAPI) state(qp *ibvQP) (QPState, int) {
	var attr ibvQPAttr
	var init ibvQPInitAttr
	r, _, _ := purego.SyscallN(v.queryQP, uintptr(unsafe.Pointer(qp)), uintptr(unsafe.Pointer(&attr)),
		uintptr(QPAttrState), uintptr(unsafe.Pointer(&init)))
	if int(int32(r)) != 0 {
		return QPStateErr, int(int32(r))
	}
	return QPState(attr.QPState), 0
}

// opsFn reads one function pointer from the context ops table. | opsFn 从
// 上下文操作表读取一个函数指针。
func opsFn(ctx *ibvContext, off uintptr) uintptr {
	return *(*uintptr)(unsafe.Add(unsafe.Pointer(ctx), ctxOpsOffset+off))
}

// send posts a send work request chain through the provider op. |
// send 通过提供方操作提交发送工作请求链。
func (v *verbsAPI) send(fn uintptr, qp *ibvQP, wr *ibvSendWR) (int, *ibvSendWR) {
	var bad *ibvSendWR
	if fn == 0 {
		return 5, bad
	}
	r := callFn(fn, uintptr(unsafe.Pointer(qp)), uintptr(unsafe.Pointer(wr)),
		uintptr(unsafe.Pointer(&bad)))
	return int(int32(r)), bad
}

// recv posts a receive work request chain through the provider op. |
// recv 通过提供方操作提交接收工作请求链。
func (v *verbsAPI) recv(fn uintptr, qp *ibvQP, wr *ibvRecvWR) (int, *ibvRecvWR) {
	var bad *ibvRecvWR
	if fn == 0 {
		return 5, bad
	}
	r := callFn(fn, uintptr(unsafe.Pointer(qp)), uintptr(unsafe.Pointer(wr)),
		uintptr(unsafe.Pointer(&bad)))
	return int(int32(r)), bad
}

// poll polls the completion queue through the provider op. | poll 通过提供方
// 操作轮询完成队列。
func (v *verbsAPI) poll(fn uintptr, cq *ibvCQ, max int32, wc *ibvWC) int32 {
	if fn == 0 {
		return -5
	}
	return int32(callFn(fn, uintptr(unsafe.Pointer(cq)), uintptr(max), uintptr(unsafe.Pointer(wc))))
}

// createSRQ creates a shared receive queue. | createSRQ 创建共享接收队列。
func (v *verbsAPI) makeSRQ(pd *ibvPD, attr *ibvSRQInitAttr) (*ibvSRQ, int) {
	r, errno := v.callControl(v.createSRQ, uintptr(unsafe.Pointer(pd)), uintptr(unsafe.Pointer(attr)))
	if r == 0 {
		return nil, errnoOfResult(errno)
	}
	return (*ibvSRQ)(ptrFromUintptr(r)), 0
}

// destroySRQ destroys a shared receive queue. | destroySRQ 销毁共享接收队列。
func (v *verbsAPI) removeSRQ(srq *ibvSRQ) int {
	r, _, _ := purego.SyscallN(v.destroySRQ, uintptr(unsafe.Pointer(srq)))
	return int(int32(r))
}

// srqRecv posts a receive chain to a shared receive queue. | srqRecv 向共享
// 接收队列提交接收链。
func (v *verbsAPI) srqRecv(fn uintptr, srq *ibvSRQ, wr *ibvRecvWR) (int, *ibvRecvWR) {
	var bad *ibvRecvWR
	if fn == 0 {
		return 5, bad
	}
	r := callFn(fn, uintptr(unsafe.Pointer(srq)), uintptr(unsafe.Pointer(wr)),
		uintptr(unsafe.Pointer(&bad)))
	return int(int32(r)), bad
}

// createAH creates an address handle. | createAH 创建地址句柄。
func (v *verbsAPI) makeAH(pd *ibvPD, attr *ibvAHAttr) (*ibvAH, int) {
	r, errno := v.callControl(v.createAH, uintptr(unsafe.Pointer(pd)), uintptr(unsafe.Pointer(attr)))
	if r == 0 {
		return nil, errnoOfResult(errno)
	}
	return (*ibvAH)(ptrFromUintptr(r)), 0
}

// destroyAH destroys an address handle. | destroyAH 销毁地址句柄。
func (v *verbsAPI) removeAH(ah *ibvAH) int {
	r, _, _ := purego.SyscallN(v.destroyAH, uintptr(unsafe.Pointer(ah)))
	return int(int32(r))
}
