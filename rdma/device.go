package rdma

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// sysfsRoot is the RDMA sysfs mount point. Tests point it at a fixture. |
// sysfsRoot 是 RDMA sysfs 挂载点；测试将其指向伪造目录。
var sysfsRoot = "/sys/class/infiniband"

// LinkLayer is the physical link layer of one port. | LinkLayer 是端口的物理
// 链路层。
type LinkLayer uint8

const (
	// LinkLayerUnknown is an unrecognised link layer. | LinkLayerUnknown 表示
	// 无法识别的链路层。
	LinkLayerUnknown LinkLayer = iota
	// LinkLayerInfiniBand is a native InfiniBand link. | LinkLayerInfiniBand 是
	// 原生 InfiniBand 链路。
	LinkLayerInfiniBand
	// LinkLayerEthernet is an Ethernet link carrying RoCE. | LinkLayerEthernet
	// 是承载 RoCE 的以太网链路。
	LinkLayerEthernet
)

// String returns the English link layer name. | String 返回链路层英文名。
func (l LinkLayer) String() string {
	switch l {
	case LinkLayerInfiniBand:
		return "InfiniBand"
	case LinkLayerEthernet:
		return "Ethernet"
	default:
		return "unknown"
	}
}

// PortState is the InfiniBand port state reported by sysfs. | PortState 是
// sysfs 报告的 InfiniBand 端口状态。
type PortState uint8

const (
	// PortStateUnknown is an unrecognised state. | PortStateUnknown 表示未知状态。
	PortStateUnknown PortState = iota
	// PortStateDown means the port is down. | PortStateDown 表示端口关闭。
	PortStateDown
	// PortStateInitialize means the port is initialising. | PortStateInitialize
	// 表示端口初始化中。
	PortStateInitialize
	// PortStateArmed means the port is armed. | PortStateArmed 表示端口已就绪。
	PortStateArmed
	// PortStateActive means the port can carry traffic. | PortStateActive 表示
	// 端口可以承载流量。
	PortStateActive
	// PortStateActiveDefer means the port is active with deferred recovery. |
	// PortStateActiveDefer 表示端口活动但延迟恢复。
	PortStateActiveDefer
)

// String returns the English port state name. | String 返回端口状态英文名。
func (s PortState) String() string {
	switch s {
	case PortStateDown:
		return "down"
	case PortStateInitialize:
		return "initialize"
	case PortStateArmed:
		return "armed"
	case PortStateActive:
		return "active"
	case PortStateActiveDefer:
		return "active-defer"
	default:
		return "unknown"
	}
}

// PortInfo describes one device port discovered through sysfs. MTU values are
// filled by Device.Info from ibv_query_port; sysfs alone does not expose them.
// | PortInfo 描述通过 sysfs 发现的一个设备端口。MTU 由 Device.Info 从
// ibv_query_port 填充；sysfs 本身不暴露 MTU。
type PortInfo struct {
	// PhysicalState is the raw sysfs physical state text. | PhysicalState 是
	// sysfs 的物理状态原文。
	PhysicalState string
	// GIDs lists the port GID table ordered by index. | GIDs 按索引顺序列出
	// 端口 GID 表。
	GIDs []GID
	// Port is the one-based port number. | Port 是 1 起始的端口号。
	Port int
	// RateGbps is the negotiated link rate in gigabits per second. | RateGbps 是
	// 协商链路速率（Gb/s）。
	RateGbps uint64
	// ActiveMTU is the current path MTU in bytes; zero until Device.Info runs.
	// | ActiveMTU 是当前路径 MTU（字节）；Device.Info 运行前为零。
	ActiveMTU int
	// MaxMTU is the maximum path MTU in bytes; zero until Device.Info runs. |
	// MaxMTU 是最大路径 MTU（字节）；Device.Info 运行前为零。
	MaxMTU int
	// LID is the InfiniBand local identifier; zero on Ethernet links. | LID 是
	// InfiniBand 本地标识；以太网链路为零。
	LID uint16
	// State is the current port state. | State 是当前端口状态。
	State PortState
	// LinkLayer is the port link layer. | LinkLayer 是端口链路层。
	LinkLayer LinkLayer
}

// Active reports whether the port state can carry traffic. | Active 报告端口
// 状态是否可承载流量。
func (s PortState) Active() bool {
	return s == PortStateActive || s == PortStateActiveDefer
}

// Active reports whether the port can carry traffic. | Active 报告端口是否可
// 承载流量。
func (p PortInfo) Active() bool { return p.State.Active() }

// GID returns the GID with the given table index. | GID 返回指定表索引的 GID。
func (p PortInfo) GID(index int) (GID, bool) {
	for _, g := range p.GIDs {
		if g.Index == index {
			return g, true
		}
	}
	return GID{}, false
}

// DeviceInfo describes one RDMA device discovered through sysfs. | DeviceInfo
// 描述通过 sysfs 发现的一个 RDMA 设备。
type DeviceInfo struct {
	// Name is the kernel device name, for example "mlx5_0". | Name 是内核设备名，
	// 例如 "mlx5_0"。
	Name string
	// Firmware is the firmware version string. | Firmware 是固件版本字符串。
	Firmware string
	// Ports lists the device ports ordered by port number. | Ports 按端口号排序。
	Ports []PortInfo
	// NodeGUID identifies the node. | NodeGUID 标识节点。
	NodeGUID uint64
	// SysImageGUID identifies the system image. | SysImageGUID 标识系统镜像。
	SysImageGUID uint64
}

// Port returns the port with the given number. | Port 返回指定端口号的端口。
func (d DeviceInfo) Port(num int) (PortInfo, bool) {
	for _, p := range d.Ports {
		if p.Port == num {
			return p, true
		}
	}
	return PortInfo{}, false
}

// ListDevices enumerates RDMA devices through sysfs without opening them. It
// returns ErrNoDevice on hosts without RDMA sysfs. | ListDevices 通过 sysfs
// 枚举 RDMA 设备而不打开它们；没有 RDMA sysfs 的主机返回 ErrNoDevice。
func ListDevices() ([]DeviceInfo, error) { return listDevices(sysfsRoot) }

// listDevices enumerates devices below root. | listDevices 枚举 root 下的设备。
func listDevices(root string) ([]DeviceInfo, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrNoDevice, "%s", root)
	}
	devices := make([]DeviceInfo, 0, len(entries))
	var firstErr error
	for _, entry := range entries {
		// /sys/class/infiniband entries are symlinks to device directories;
		// DirEntry.IsDir reports false for them. | /sys/class/infiniband 的
		// 条目是指向设备目录的符号链接，DirEntry.IsDir 对它们返回 false。
		if !entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
			continue
		}
		dev, err := readDevice(filepath.Join(root, entry.Name()), entry.Name())
		if err != nil {
			// One unreadable or partially initialized device must not hide
			// other usable devices. | 单个不可读或未初始化完成的设备不得遮蔽其它
			// 可用设备。
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		devices = append(devices, dev)
	}
	if len(devices) == 0 {
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, errs.Detail(ErrNoDevice, "no devices under %s | %s 下没有设备", root, root)
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].Name < devices[j].Name })
	return devices, nil
}

// readDevice reads one device directory. | readDevice 读取一个设备目录。
func readDevice(dir, name string) (DeviceInfo, error) {
	dev := DeviceInfo{Name: name}
	dev.NodeGUID = parseGUID(readTrim(filepath.Join(dir, "node_guid")))
	dev.SysImageGUID = parseGUID(readTrim(filepath.Join(dir, "sys_image_guid")))
	dev.Firmware = readTrim(filepath.Join(dir, "fw_ver"))
	portDir := filepath.Join(dir, "ports")
	entries, err := os.ReadDir(portDir)
	if err != nil {
		if os.IsNotExist(err) {
			return dev, nil
		}
		return dev, errs.WrapDetail(err, ErrNoDevice, "%s", portDir)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		num, err := strconv.Atoi(entry.Name())
		if err != nil || num <= 0 {
			continue
		}
		dev.Ports = append(dev.Ports, readPort(filepath.Join(portDir, entry.Name()), num))
	}
	sort.Slice(dev.Ports, func(i, j int) bool { return dev.Ports[i].Port < dev.Ports[j].Port })
	return dev, nil
}

// readPort reads one port directory. | readPort 读取一个端口目录。
func readPort(dir string, num int) PortInfo {
	p := PortInfo{Port: num}
	p.State = parsePortState(readTrim(filepath.Join(dir, "state")))
	p.PhysicalState = readTrim(filepath.Join(dir, "phys_state"))
	p.LinkLayer = parseLinkLayer(readTrim(filepath.Join(dir, "link_layer")))
	p.RateGbps = parseRate(readTrim(filepath.Join(dir, "rate")))
	p.LID = parseLID(readTrim(filepath.Join(dir, "lid")))
	p.GIDs = readGIDs(dir, p.LinkLayer)
	return p
}

// readGIDs reads the GID table of one port. | readGIDs 读取一个端口的 GID 表。
func readGIDs(portDir string, link LinkLayer) []GID {
	dir := filepath.Join(portDir, "gids")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	gids := make([]GID, 0, len(entries))
	for _, entry := range entries {
		index, err := strconv.Atoi(entry.Name())
		if err != nil || index < 0 {
			continue
		}
		text := readTrim(filepath.Join(dir, entry.Name()))
		g, err := ParseGID(index, text)
		if err != nil {
			continue
		}
		typeText := readTrim(filepath.Join(portDir, "gid_attrs", "types", entry.Name()))
		g.Type = gidTypeFromSysfs(typeText, link)
		if g.Type == GIDTypeUnknown {
			g.Type = inferGIDType(g, link)
		}
		g.NetDev = readTrim(filepath.Join(portDir, "gid_attrs", "ndevs", entry.Name()))
		gids = append(gids, g)
	}
	sort.Slice(gids, func(i, j int) bool { return gids[i].Index < gids[j].Index })
	return gids
}

// readTrim reads a sysfs attribute and trims surrounding whitespace. It
// returns "" when the file cannot be read. | readTrim 读取 sysfs 属性并去除
// 首尾空白；读取失败返回空串。
func readTrim(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// parseGUID parses "b859:9f03:0001:1150" style GUIDs. | parseGUID 解析
// "b859:9f03:0001:1150" 形式的 GUID。
func parseGUID(s string) uint64 {
	cleaned := strings.ReplaceAll(strings.TrimSpace(s), ":", "")
	if cleaned == "" {
		return 0
	}
	v, err := strconv.ParseUint(cleaned, 16, 64)
	if err != nil {
		return 0
	}
	return v
}

// parsePortState parses "4: ACTIVE" style sysfs states. | parsePortState 解析
// "4: ACTIVE" 形式的 sysfs 状态。
func parsePortState(s string) PortState {
	numText := s
	if i := strings.IndexByte(s, ':'); i >= 0 {
		numText = s[:i]
	}
	n, err := strconv.Atoi(strings.TrimSpace(numText))
	if err != nil {
		return PortStateUnknown
	}
	switch n {
	case 1:
		return PortStateDown
	case 2:
		return PortStateInitialize
	case 3:
		return PortStateArmed
	case 4:
		return PortStateActive
	case 5:
		return PortStateActiveDefer
	default:
		return PortStateUnknown
	}
}

// parseLinkLayer parses the sysfs link layer text. | parseLinkLayer 解析 sysfs
// 链路层文本。
func parseLinkLayer(s string) LinkLayer {
	switch strings.TrimSpace(s) {
	case "Ethernet":
		return LinkLayerEthernet
	case "InfiniBand":
		return LinkLayerInfiniBand
	default:
		return LinkLayerUnknown
	}
}

// parseRate extracts the leading gigabit rate from "100 Gb/sec (4X EDR)". |
// parseRate 从 "100 Gb/sec (4X EDR)" 中提取开头的 Gb/s 速率。
func parseRate(s string) uint64 {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || v <= 0 {
		return 0
	}
	return uint64(v)
}

// parseLID parses a hexadecimal LID such as "0x42". | parseLID 解析 "0x42"
// 形式的十六进制 LID。
func parseLID(s string) uint16 {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 0, 16)
	if err != nil {
		return 0
	}
	return uint16(v)
}
