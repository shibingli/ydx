//go:build linux && rdma && (amd64 || arm64)

package rdma

import (
	"math"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/shibingli/ydx/errs"
)

const (
	// hugePageSize is the 2 MiB huge page size. | hugePageSize 是 2 MiB 大页大小。
	hugePageSize = 2 << 20
	// mapHuge2MB asks mmap for 2 MiB huge pages (MAP_HUGE_2MB). | mapHuge2MB
	// 请求 mmap 使用 2 MiB 大页（MAP_HUGE_2MB）。
	mapHuge2MB = 21 << 26
)

// Supported reports whether libibverbs can be loaded. | Supported 报告
// libibverbs 是否可加载。
func Supported() bool {
	_, err := loadVerbs("")
	return err == nil
}

// Open opens the configured device, allocates its protection domain and
// selects the GID used for connections. | Open 打开配置的设备、分配保护域并
// 选择连接使用的 GID。
func Open(cfg Config) (*Device, error) {
	api, err := loadVerbs(cfg.VerbsLibrary)
	if err != nil {
		return nil, err
	}
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	devices, err := ListDevices()
	if err != nil {
		return nil, err
	}
	info, port, gid, err := chooseDevice(devices, &cfg)
	if err != nil {
		return nil, err
	}
	list, count := api.deviceList()
	if list == nil {
		return nil, errs.Detail(ErrNoDevice, "libibverbs returned no devices | libibverbs 没有返回设备")
	}
	defer api.releaseDeviceList(list)
	var target *ibvDevice
	for _, dev := range unsafe.Slice((**ibvDevice)(list), int(count)) {
		if dev != nil && api.deviceName(dev) == info.Name {
			target = dev
			break
		}
	}
	if target == nil {
		return nil, errs.Detail(ErrNoDevice, "device %q not visible to libibverbs | libibverbs 看不到设备 %q", info.Name, info.Name)
	}
	ctx, rc := api.open(target)
	if rc != 0 {
		return nil, errnoError("open device "+info.Name, rc)
	}
	pd, rc := api.allocProtectionDomain(ctx)
	if rc != 0 {
		api.close(ctx)
		return nil, errnoError("allocate protection domain", rc)
	}
	d := &Device{
		state: &deviceState{api: api, ctx: ctx, pd: pd},
		cfg:   cfg,
		info:  info,
		gid:   gid,
		port:  port.Port,
	}
	var da ibvDeviceAttr
	if rc := api.queryDev(ctx, &da); rc != 0 {
		d.Close()
		return nil, errnoError("query device", rc)
	}
	d.attr = DeviceAttr{
		MaxQPWR:           uint32(da.MaxQPWR),
		MaxSGE:            uint32(da.MaxSGE),
		MaxCQE:            uint32(da.MaxCQE),
		MaxQPRdAtomic:     uint32(da.MaxQPRdAtom),
		MaxQPInitRdAtomic: uint32(da.MaxQPInitRdAtom),
		MaxMRSize:         da.MaxMRSize,
		VendorPartID:      da.VendorPartID,
		Firmware:          trimNul(da.FWVer[:]),
	}
	var pa ibvPortAttr
	if rc := api.queryP(ctx, uint8(cfg.Port), &pa); rc != 0 {
		d.Close()
		return nil, errnoError("query port", rc)
	}
	d.portAttr = PortAttr{
		Port:        cfg.Port,
		State:       PortState(pa.State),
		MaxMTU:      mtuBytes(pa.MaxMTU),
		ActiveMTU:   mtuBytes(pa.ActiveMTU),
		LID:         pa.LID,
		LinkLayer:   LinkLayer(pa.LinkLayer),
		GIDTableLen: int(pa.GIDTblLen),
	}
	for i := range d.info.Ports {
		if d.info.Ports[i].Port == cfg.Port {
			d.info.Ports[i].ActiveMTU = d.portAttr.ActiveMTU
			d.info.Ports[i].MaxMTU = d.portAttr.MaxMTU
		}
	}
	if cfg.MTU == 0 {
		cfg.MTU = d.portAttr.ActiveMTU
		if cfg.MTU == 0 {
			cfg.MTU = 1024
		}
	}
	if d.portAttr.ActiveMTU > 0 && cfg.MTU > d.portAttr.ActiveMTU {
		d.Close()
		return nil, errs.Detail(ErrInvalidConfig,
			"mtu %d exceeds active mtu %d | MTU %d 超过活动 MTU %d",
			cfg.MTU, d.portAttr.ActiveMTU, cfg.MTU, d.portAttr.ActiveMTU)
	}
	cfg.VerbsLibrary = api.path
	d.cfg = cfg
	return d, nil
}

// trimNul converts a fixed NUL-padded byte array to a string. | trimNul 将
// NUL 填充的定长字节数组转换为字符串。
func trimNul(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// chooseDevice selects a device, port and GID. | chooseDevice 选择设备、端口
// 与 GID。
func chooseDevice(devices []DeviceInfo, cfg *Config) (DeviceInfo, PortInfo, GID, error) {
	pick := func(d DeviceInfo) (PortInfo, GID, bool) {
		p, ok := d.Port(cfg.Port)
		if !ok || !p.Active() {
			return PortInfo{}, GID{}, false
		}
		idx, err := cfg.selectGID(p.GIDs)
		if err != nil {
			return PortInfo{}, GID{}, false
		}
		g, ok := p.GID(idx)
		if !ok {
			return PortInfo{}, GID{}, false
		}
		cfg.GIDIndex = idx
		if cfg.GIDType == GIDTypeUnknown {
			cfg.GIDType = g.Type
		}
		return p, g, true
	}
	if cfg.Device != "" {
		for _, d := range devices {
			if d.Name != cfg.Device {
				continue
			}
			p, g, ok := pick(d)
			if !ok {
				return DeviceInfo{}, PortInfo{}, GID{}, errs.Detail(ErrNoDevice,
					"device %s port %d has no active matching GID | 设备 %s 端口 %d 没有活动的匹配 GID",
					cfg.Device, cfg.Port, cfg.Device, cfg.Port)
			}
			return d, p, g, nil
		}
		return DeviceInfo{}, PortInfo{}, GID{}, errs.Detail(ErrNoDevice,
			"device %q not found | 设备 %q 不存在", cfg.Device, cfg.Device)
	}
	for _, d := range devices {
		if p, g, ok := pick(d); ok {
			return d, p, g, nil
		}
	}
	return DeviceInfo{}, PortInfo{}, GID{}, errs.Detail(ErrNoDevice,
		"no active port with a matching GID | 没有带匹配 GID 的活动端口")
}

// mtuBytes converts an ibv_mtu enum to bytes. | mtuBytes 将 ibv_mtu 枚举转换
// 为字节数。
func mtuBytes(v uint32) int {
	switch v {
	case 1:
		return 256
	case 2:
		return 512
	case 3:
		return 1024
	case 4:
		return 2048
	case 5:
		return 4096
	default:
		return 0
	}
}

// mtuEnum converts bytes to an ibv_mtu enum. | mtuEnum 将字节数转换为
// ibv_mtu 枚举。
func mtuEnum(v int) uint32 {
	switch v {
	case 256:
		return 1
	case 512:
		return 2
	case 2048:
		return 4
	case 4096:
		return 5
	default:
		return 3 // 1024
	}
}

// Close releases the protection domain and device. Queue pairs, completion
// queues, memory regions and pools must be closed first. | Close 释放保护域
// 与设备。必须先关闭队列对、完成队列、内存区与内存池。
func (d *Device) Close() error {
	if d == nil || !d.closed.CompareAndSwap(false, true) {
		return nil
	}
	if d.state == nil {
		return nil
	}
	if d.state.pd != nil {
		d.state.api.deallocProtectionDomain(d.state.pd)
		d.state.pd = nil
	}
	if d.state.ctx != nil {
		d.state.api.close(d.state.ctx)
		d.state.ctx = nil
	}
	return nil
}

// NewCQ creates a completion queue. depth is clamped to the device maximum. |
// NewCQ 创建完成队列；depth 会被限制在设备上限内。
func (d *Device) NewCQ(depth int) (*CQ, error) {
	if d == nil || d.closed.Load() {
		return nil, ErrClosed
	}
	if depth <= 0 {
		depth = d.cfg.CQDepth
	}
	if depth < 2 {
		depth = 2
	}
	if max := int(d.attr.MaxCQE); max > 0 && depth > max {
		depth = max
	}
	cq, rc := d.state.api.makeCQ(d.state.ctx, int32(depth))
	if rc != 0 {
		return nil, errnoError("create completion queue", rc)
	}
	return &CQ{
		dev:   d,
		state: &cqState{cq: cq, scratch: make([]ibvWC, 64)},
		depth: depth,
	}, nil
}

// NewQP creates a queue pair. | NewQP 创建队列对。
func (d *Device) NewQP(cfg QPConfig) (*QP, error) {
	if d == nil || d.closed.Load() {
		return nil, ErrClosed
	}
	if cfg.Type == 0 {
		cfg.Type = QPTypeRC
	}
	if cfg.SendCQ == nil {
		return nil, errs.Detail(ErrInvalidConfig, "send cq is required | 必须提供发送 CQ")
	}
	if cfg.SendCQ.dev != d {
		return nil, errs.Detail(ErrInvalidConfig, "send cq belongs to another device | 发送 CQ 属于其它设备")
	}
	if cfg.RecvCQ == nil {
		cfg.RecvCQ = cfg.SendCQ
	}
	if cfg.RecvCQ.dev != d {
		return nil, errs.Detail(ErrInvalidConfig, "recv cq belongs to another device | 接收 CQ 属于其它设备")
	}
	if cfg.SendCQ.closed.Load() || cfg.RecvCQ.closed.Load() {
		return nil, ErrClosed
	}
	maxSend := cfg.MaxSendWR
	if maxSend <= 0 {
		maxSend = d.cfg.QueueDepth
	}
	maxRecv := cfg.MaxRecvWR
	if maxRecv <= 0 {
		maxRecv = d.cfg.QueueDepth
	}
	if cfg.SRQ != nil {
		maxRecv = 0
	}
	if max := int(d.attr.MaxQPWR); max > 0 {
		if maxSend > max {
			maxSend = max
		}
		if maxRecv > max {
			maxRecv = max
		}
	}
	if maxSend < 1 {
		maxSend = 1
	}
	sendSGE := cfg.MaxSendSGE
	if sendSGE <= 0 {
		sendSGE = 1
	}
	recvSGE := cfg.MaxRecvSGE
	if recvSGE <= 0 {
		recvSGE = 1
	}
	if max := int(d.attr.MaxSGE); max > 0 {
		if sendSGE > max {
			sendSGE = max
		}
		if recvSGE > max {
			recvSGE = max
		}
	}
	if sendSGE > MaxSGE {
		sendSGE = MaxSGE
	}
	if recvSGE > MaxSGE {
		recvSGE = MaxSGE
	}
	inline := cfg.MaxInline
	probe := false
	if inline <= 0 {
		probe = true
		switch hint := int(d.inlineMax.Load()); {
		case hint > 0:
			inline = hint
		case hint < 0:
			inline = 0
		default:
			inline = 64
		}
	}
	q, rc, granted := d.createQP(cfg, maxSend, maxRecv, sendSGE, recvSGE, inline)
	if q == nil && probe && inline > 0 {
		q, rc, granted = d.createQP(cfg, maxSend, maxRecv, sendSGE, recvSGE, 0)
		if q != nil {
			d.inlineMax.Store(-1)
			inline = 0
		}
	}
	if q == nil {
		return nil, errnoError("create queue pair", rc)
	}
	if inline > 0 {
		d.inlineMax.Store(int32(inline))
	}
	st := &qpState{qp: q, scap: maxSend, rcap: maxRecv}
	if maxSend > 0 {
		st.swr = make([]ibvSendWR, maxSend)
		st.ssge = make([]ibvSGE, maxSend*MaxSGE)
	}
	if maxRecv > 0 {
		st.rwr = make([]ibvRecvWR, maxRecv)
		st.rsge = make([]ibvSGE, maxRecv*MaxSGE)
	}
	return &QP{dev: d, state: st, typ: cfg.Type, qpn: q.QPNum, inline: granted}, nil
}

// createQP builds the init attributes and creates one queue pair. | createQP
// 构建初始化属性并创建一个队列对。
func (d *Device) createQP(cfg QPConfig, maxSend, maxRecv, sendSGE, recvSGE, inline int) (*ibvQP, int, uint32) {
	var attr ibvQPInitAttr
	attr.SendCQ = cfg.SendCQ.state.cq
	attr.RecvCQ = cfg.RecvCQ.state.cq
	if cfg.SRQ != nil {
		attr.SRQ = cfg.SRQ.state.srq
	}
	attr.Cap.MaxSendWR = uint32(maxSend)
	attr.Cap.MaxRecvWR = uint32(maxRecv)
	attr.Cap.MaxSendSGE = uint32(sendSGE)
	attr.Cap.MaxRecvSGE = uint32(recvSGE)
	attr.Cap.MaxInlineData = uint32(inline)
	attr.QPType = uint32(cfg.Type)
	if cfg.SignalAll {
		attr.SQSigAll = 1
	}
	q, rc := d.state.api.makeQP(d.state.pd, &attr)
	return q, rc, attr.Cap.MaxInlineData
}

// NewSRQ creates a shared receive queue. | NewSRQ 创建共享接收队列。
func (d *Device) NewSRQ(cfg SRQConfig) (*SRQ, error) {
	if d == nil || d.closed.Load() {
		return nil, ErrClosed
	}
	maxWR := cfg.MaxWR
	if maxWR <= 0 {
		maxWR = d.cfg.QueueDepth
	}
	if max := int(d.attr.MaxQPWR); max > 0 && maxWR > max {
		maxWR = max
	}
	maxSGE := cfg.MaxSGE
	if maxSGE <= 0 {
		maxSGE = 1
	}
	if max := int(d.attr.MaxSGE); max > 0 && maxSGE > max {
		maxSGE = max
	}
	if maxSGE > MaxSGE {
		maxSGE = MaxSGE
	}
	var attr ibvSRQInitAttr
	attr.Attr.MaxWR = uint32(maxWR)
	attr.Attr.MaxSGE = uint32(maxSGE)
	srq, rc := d.state.api.makeSRQ(d.state.pd, &attr)
	if rc != 0 {
		return nil, errnoError("create shared receive queue", rc)
	}
	st := &srqState{srq: srq, cap: maxWR}
	if maxWR > 0 {
		st.rwr = make([]ibvRecvWR, maxWR)
		st.rsge = make([]ibvSGE, maxWR*MaxSGE)
	}
	return &SRQ{dev: d, state: st}, nil
}

// NewAH creates an address handle for unreliable datagram sends. | NewAH 为
// 不可靠数据报发送创建地址句柄。
func (d *Device) NewAH(attr AHAttr) (*AH, error) {
	if d == nil || d.closed.Load() {
		return nil, ErrClosed
	}
	if attr.Port == 0 {
		attr.Port = uint8(d.port)
	}
	var a ibvAHAttr
	a.IsGlobal = boolByte(attr.IsGlobal)
	a.DLID = attr.DLID
	a.SL = attr.SL
	a.SrcPathBits = attr.SrcPathBits
	a.StaticRate = attr.StaticRate
	a.PortNum = attr.Port
	a.GRH.DGID = attr.GID
	a.GRH.FlowLabel = attr.FlowLabel
	a.GRH.SGIDIndex = attr.SGIDIndex
	a.GRH.HopLimit = attr.HopLimit
	a.GRH.TrafficClass = attr.TrafficClass
	ah, rc := d.state.api.makeAH(d.state.pd, &a)
	if rc != 0 {
		return nil, errnoError("create address handle", rc)
	}
	return &AH{state: &ahState{api: d.state.api, ah: ah}}, nil
}

// boolByte converts a bool to the uint8 used by C structures. | boolByte 将
// 布尔值转换为 C 结构使用的 uint8。
func boolByte(v bool) uint8 {
	if v {
		return 1
	}
	return 0
}

// NewMR allocates library-owned memory and registers it with the device. It
// tries 2 MiB huge pages first and falls back to transparent huge pages. |
// NewMR 分配库拥有的内存并将其注册到设备。优先尝试 2 MiB 大页，失败时回退
// 透明大页。
func (d *Device) NewMR(size int, access Access) (*MR, error) {
	if d == nil || d.closed.Load() {
		return nil, ErrClosed
	}
	if size <= 0 {
		return nil, errs.Detail(ErrInvalidConfig, "mr size %d | 内存区大小 %d", size, size)
	}
	if access == 0 {
		access = AccessDefault
	}
	mem, err := allocMem(size, true)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrNoBuffer, "allocate %d bytes | 分配 %d 字节", size, size)
	}
	ptr := unsafe.Pointer(&mem[0])
	mr, rc := d.state.api.registerMR(d.state.pd, ptr, len(mem), access)
	if mr == nil {
		_ = syscall.Munmap(mem)
		return nil, errnoError("register memory region", rc)
	}
	release := func() {
		d.state.api.deregisterMR(mr)
		_ = syscall.Munmap(mem)
	}
	return &MR{
		mem:     mem,
		ptr:     ptr,
		addr:    uintptr(ptr),
		size:    len(mem),
		lkey:    mr.LKey,
		rkey:    mr.RKey,
		access:  access,
		release: release,
	}, nil
}

// allocMem allocates page-backed memory, preferring 2 MiB huge pages. | allocMem
// 分配页后备内存，优先使用 2 MiB 大页。
func allocMem(size int, huge bool) ([]byte, error) {
	if huge {
		aligned := (size + hugePageSize - 1) &^ (hugePageSize - 1)
		mem, err := syscall.Mmap(-1, 0, aligned, syscall.PROT_READ|syscall.PROT_WRITE,
			syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS|syscall.MAP_HUGETLB|mapHuge2MB)
		if err == nil {
			return mem, nil
		}
	}
	mem, err := syscall.Mmap(-1, 0, size, syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		return nil, err
	}
	_ = syscall.Madvise(mem, syscall.MADV_HUGEPAGE)
	return mem, nil
}

// RegisterMemory registers caller-owned memory. The caller must not pass the
// slice to another owner or free it while the region is open. The region pins
// the backing object for its lifetime. Prefer NewMR for DMA buffers. |
// RegisterMemory 注册调用方拥有的内存。内存区打开期间，调用方不得转移或释放
// 该切片。内存区会在生命周期内钉住底层对象。DMA 缓冲区优先使用 NewMR。
func (d *Device) RegisterMemory(buf []byte, access Access) (*MR, error) {
	if d == nil || d.closed.Load() {
		return nil, ErrClosed
	}
	if len(buf) == 0 {
		return nil, errs.Detail(ErrInvalidConfig, "empty buffer | 缓冲区为空")
	}
	if access == 0 {
		access = AccessDefault
	}
	pinner := new(runtime.Pinner)
	pinner.Pin(&buf[0])
	ptr := unsafe.Pointer(&buf[0])
	mr, rc := d.state.api.registerMR(d.state.pd, ptr, len(buf), access)
	if mr == nil {
		pinner.Unpin()
		return nil, errnoError("register memory region", rc)
	}
	release := func() {
		d.state.api.deregisterMR(mr)
		pinner.Unpin()
	}
	return &MR{
		mem:     buf,
		ptr:     ptr,
		addr:    uintptr(ptr),
		size:    len(buf),
		lkey:    mr.LKey,
		rkey:    mr.RKey,
		access:  access,
		release: release,
	}, nil
}

// NewPool allocates a registered arena and splits it into fixed-size slots. |
// NewPool 分配注册内存区并切分为定长槽位。
func (d *Device) NewPool(cfg PoolConfig) (*Pool, error) {
	if cfg.Slots <= 0 {
		cfg.Slots = 1024
	}
	if cfg.SlotSize <= 0 {
		cfg.SlotSize = 4096
	}
	if cfg.Align <= 0 {
		cfg.Align = 64
	}
	if cfg.Access == 0 {
		cfg.Access = AccessDefault
	}
	if cfg.Slots > math.MaxInt/cfg.SlotSize {
		return nil, errs.Detail(ErrInvalidConfig, "pool size overflows | 内存池大小溢出")
	}
	mr, err := d.NewMR(cfg.Slots*cfg.SlotSize, cfg.Access)
	if err != nil {
		return nil, err
	}
	pool, err := newPool(mr, cfg.SlotSize, cfg.Align)
	if err != nil {
		_ = mr.Close()
		return nil, err
	}
	return pool, nil
}
