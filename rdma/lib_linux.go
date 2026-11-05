//go:build linux && rdma && (amd64 || arm64)

package rdma

import (
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/shibingli/ydx/errs"
)

// verbsAPI holds the resolved libibverbs entry points. Calls go straight to
// the function pointers through purego, so no cgo transition is paid. |
// verbsAPI 保存解析后的 libibverbs 入口。调用经 purego 直接到达函数指针，不支付
// cgo 切换开销。
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
			return nil, errs.WrapDetail(err, ErrUnsupported, "resolve %s | 解析 %s", s.name, s.name)
		}
		*s.out = sym
	}
	return api, nil
}

// ptrFromUintptr converts an address returned by libibverbs into a pointer
// without tripping go vet's uintptr heuristic. | ptrFromUintptr 将 libibverbs
// 返回的地址转换为指针，避免触发 go vet 的 uintptr 检查。
func ptrFromUintptr(u uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&u))
}

// errnoOfResult maps the third SyscallN result to an errno, falling back to
// EIO when the provider did not report one. | errnoOfResult 将 SyscallN 的第三
// 个返回值映射为 errno，提供方未报告时回退 EIO。
func errnoOfResult(err uintptr) int {
	if err != 0 {
		return int(err)
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
	r, _, e := purego.SyscallN(v.openDevice, uintptr(unsafe.Pointer(dev)))
	if r == 0 {
		return nil, errnoOfResult(e)
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
	r, _, e := purego.SyscallN(v.allocPD, uintptr(unsafe.Pointer(ctx)))
	if r == 0 {
		return nil, errnoOfResult(e)
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
	r, _, e := purego.SyscallN(v.createCQ, uintptr(unsafe.Pointer(ctx)), uintptr(depth), 0, 0, 0)
	if r == 0 {
		return nil, errnoOfResult(e)
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
	r, _, e := purego.SyscallN(v.regMR, uintptr(unsafe.Pointer(pd)), uintptr(addr), uintptr(length), uintptr(access))
	if r == 0 {
		return nil, errnoOfResult(e)
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
	r, _, e := purego.SyscallN(v.createQP, uintptr(unsafe.Pointer(pd)), uintptr(unsafe.Pointer(attr)))
	if r == 0 {
		return nil, errnoOfResult(e)
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
func (v *verbsAPI) send(ctx *ibvContext, qp *ibvQP, wr *ibvSendWR) (int, *ibvSendWR) {
	fn := opsFn(ctx, opPostSend)
	var bad *ibvSendWR
	if fn == 0 {
		return 5, bad
	}
	r, _, _ := purego.SyscallN(fn, uintptr(unsafe.Pointer(qp)), uintptr(unsafe.Pointer(wr)),
		uintptr(unsafe.Pointer(&bad)))
	return int(int32(r)), bad
}

// recv posts a receive work request chain through the provider op. |
// recv 通过提供方操作提交接收工作请求链。
func (v *verbsAPI) recv(ctx *ibvContext, qp *ibvQP, wr *ibvRecvWR) (int, *ibvRecvWR) {
	fn := opsFn(ctx, opPostRecv)
	var bad *ibvRecvWR
	if fn == 0 {
		return 5, bad
	}
	r, _, _ := purego.SyscallN(fn, uintptr(unsafe.Pointer(qp)), uintptr(unsafe.Pointer(wr)),
		uintptr(unsafe.Pointer(&bad)))
	return int(int32(r)), bad
}

// poll polls the completion queue through the provider op. | poll 通过提供方
// 操作轮询完成队列。
func (v *verbsAPI) poll(ctx *ibvContext, cq *ibvCQ, max int32, wc *ibvWC) int32 {
	fn := opsFn(ctx, opPollCQ)
	if fn == 0 {
		return -5
	}
	r, _, _ := purego.SyscallN(fn, uintptr(unsafe.Pointer(cq)), uintptr(max), uintptr(unsafe.Pointer(wc)))
	return int32(r)
}

// createSRQ creates a shared receive queue. | createSRQ 创建共享接收队列。
func (v *verbsAPI) makeSRQ(pd *ibvPD, attr *ibvSRQInitAttr) (*ibvSRQ, int) {
	r, _, e := purego.SyscallN(v.createSRQ, uintptr(unsafe.Pointer(pd)), uintptr(unsafe.Pointer(attr)))
	if r == 0 {
		return nil, errnoOfResult(e)
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
func (v *verbsAPI) srqRecv(ctx *ibvContext, srq *ibvSRQ, wr *ibvRecvWR) (int, *ibvRecvWR) {
	fn := opsFn(ctx, opPostSRQRecv)
	var bad *ibvRecvWR
	if fn == 0 {
		return 5, bad
	}
	r, _, _ := purego.SyscallN(fn, uintptr(unsafe.Pointer(srq)), uintptr(unsafe.Pointer(wr)),
		uintptr(unsafe.Pointer(&bad)))
	return int(int32(r)), bad
}

// createAH creates an address handle. | createAH 创建地址句柄。
func (v *verbsAPI) makeAH(pd *ibvPD, attr *ibvAHAttr) (*ibvAH, int) {
	r, _, e := purego.SyscallN(v.createAH, uintptr(unsafe.Pointer(pd)), uintptr(unsafe.Pointer(attr)))
	if r == 0 {
		return nil, errnoOfResult(e)
	}
	return (*ibvAH)(ptrFromUintptr(r)), 0
}

// destroyAH destroys an address handle. | destroyAH 销毁地址句柄。
func (v *verbsAPI) removeAH(ah *ibvAH) int {
	r, _, _ := purego.SyscallN(v.destroyAH, uintptr(unsafe.Pointer(ah)))
	return int(int32(r))
}
