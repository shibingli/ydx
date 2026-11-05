package rdma

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// writeSysfsFile writes one fake sysfs attribute. | writeSysfsFile 写入一个
// 伪造的 sysfs 属性。
func writeSysfsFile(t *testing.T, path, value string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v | 创建目录失败", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		t.Fatalf("write %s: %v | 写入属性失败", path, err)
	}
}

// buildFakeSysfs creates a two-device sysfs tree mirroring the test cluster. |
// buildFakeSysfs 创建模拟测试集群的双设备 sysfs 目录树。
func buildFakeSysfs(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	dev0 := filepath.Join(root, "mlx5_0")
	writeSysfsFile(t, filepath.Join(dev0, "node_guid"), "b859:9f03:0001:1150\n")
	writeSysfsFile(t, filepath.Join(dev0, "sys_image_guid"), "b859:9f03:0001:1150\n")
	writeSysfsFile(t, filepath.Join(dev0, "fw_ver"), "16.35.4030\n")
	port0 := filepath.Join(dev0, "ports", "1")
	writeSysfsFile(t, filepath.Join(port0, "state"), "4: ACTIVE\n")
	writeSysfsFile(t, filepath.Join(port0, "phys_state"), "5: LinkUp\n")
	writeSysfsFile(t, filepath.Join(port0, "link_layer"), "Ethernet\n")
	writeSysfsFile(t, filepath.Join(port0, "rate"), "100 Gb/sec (4X EDR)\n")
	writeSysfsFile(t, filepath.Join(port0, "lid"), "0x0\n")
	writeSysfsFile(t, filepath.Join(port0, "gids", "0"), "fe80:0000:0000:0000:ba59:9fff:fe01:1150\n")
	writeSysfsFile(t, filepath.Join(port0, "gids", "1"), "fe80:0000:0000:0000:ba59:9fff:fe01:1150\n")
	writeSysfsFile(t, filepath.Join(port0, "gids", "2"), "0000:0000:0000:0000:0000:ffff:c0a8:0202\n")
	writeSysfsFile(t, filepath.Join(port0, "gids", "3"), "0000:0000:0000:0000:0000:ffff:c0a8:0202\n")
	writeSysfsFile(t, filepath.Join(port0, "gid_attrs", "types", "0"), "IB/RoCE v1\n")
	writeSysfsFile(t, filepath.Join(port0, "gid_attrs", "types", "1"), "RoCE v2\n")
	writeSysfsFile(t, filepath.Join(port0, "gid_attrs", "types", "2"), "IB/RoCE v1\n")
	writeSysfsFile(t, filepath.Join(port0, "gid_attrs", "types", "3"), "RoCE v2\n")
	writeSysfsFile(t, filepath.Join(port0, "gid_attrs", "ndevs", "0"), "enp101s0f0np0\n")
	writeSysfsFile(t, filepath.Join(port0, "gid_attrs", "ndevs", "1"), "enp101s0f0np0\n")
	writeSysfsFile(t, filepath.Join(port0, "gid_attrs", "ndevs", "2"), "enp101s0f0np0\n")
	writeSysfsFile(t, filepath.Join(port0, "gid_attrs", "ndevs", "3"), "enp101s0f0np0\n")

	dev1 := filepath.Join(root, "mlx5_1")
	writeSysfsFile(t, filepath.Join(dev1, "node_guid"), "b859:9f03:0001:1151\n")
	writeSysfsFile(t, filepath.Join(dev1, "sys_image_guid"), "b859:9f03:0001:1150\n")
	writeSysfsFile(t, filepath.Join(dev1, "fw_ver"), "16.35.4030\n")
	port1 := filepath.Join(dev1, "ports", "1")
	writeSysfsFile(t, filepath.Join(port1, "state"), "1: DOWN\n")
	writeSysfsFile(t, filepath.Join(port1, "phys_state"), "3: Disabled\n")
	writeSysfsFile(t, filepath.Join(port1, "link_layer"), "InfiniBand\n")
	writeSysfsFile(t, filepath.Join(port1, "rate"), "40 Gb/sec (4X QDR)\n")
	writeSysfsFile(t, filepath.Join(port1, "lid"), "0x42\n")
	return root
}

// TestListDevicesParsesSysfs proves device, port and GID attributes are read
// from the sysfs layout. | TestListDevicesParsesSysfs 证明设备、端口与 GID
// 属性能够从 sysfs 布局中读取。
func TestListDevicesParsesSysfs(t *testing.T) {
	root := buildFakeSysfs(t)
	devices, err := listDevices(root)
	if err != nil {
		t.Fatalf("listDevices = %v | 枚举设备失败", err)
	}
	if len(devices) != 2 {
		t.Fatalf("devices = %d, want 2 | 设备数量应为 2", len(devices))
	}
	if devices[0].Name != "mlx5_0" || devices[1].Name != "mlx5_1" {
		t.Fatalf("names = %q, %q | 设备名不符", devices[0].Name, devices[1].Name)
	}
	d := devices[0]
	if d.NodeGUID != 0xb8599f0300011150 {
		t.Fatalf("NodeGUID = %#x | 节点 GUID 解析错误", d.NodeGUID)
	}
	if d.Firmware != "16.35.4030" {
		t.Fatalf("Firmware = %q | 固件版本解析错误", d.Firmware)
	}
	if len(d.Ports) != 1 {
		t.Fatalf("ports = %d, want 1 | 端口数量应为 1", len(d.Ports))
	}
	p := d.Ports[0]
	if p.State != PortStateActive {
		t.Fatalf("State = %v, want active | 端口状态应为 active", p.State)
	}
	if p.LinkLayer != LinkLayerEthernet {
		t.Fatalf("LinkLayer = %v, want Ethernet | 链路层应为 Ethernet", p.LinkLayer)
	}
	if p.RateGbps != 100 {
		t.Fatalf("RateGbps = %d, want 100 | 速率应为 100", p.RateGbps)
	}
	if len(p.GIDs) != 4 {
		t.Fatalf("GIDs = %d, want 4 | GID 数量应为 4", len(p.GIDs))
	}
	if p.GIDs[3].Type != GIDTypeRoCEv2 {
		t.Fatalf("GID[3].Type = %v, want RoCE v2 | 索引 3 应为 RoCE v2", p.GIDs[3].Type)
	}
	if p.GIDs[3].NetDev != "enp101s0f0np0" {
		t.Fatalf("GID[3].NetDev = %q | GID 网卡解析错误", p.GIDs[3].NetDev)
	}
	if ip, ok := p.GIDs[3].IPv4(); !ok || ip.String() != "192.168.2.2" {
		t.Fatalf("GID[3].IPv4 = %v/%v | RoCE v2 IPv4 地址解析错误", ip, ok)
	}

	down := devices[1]
	if down.Ports[0].State != PortStateDown {
		t.Fatalf("state = %v, want down | 第二设备端口应为 down", down.Ports[0].State)
	}
	if down.Ports[0].LinkLayer != LinkLayerInfiniBand {
		t.Fatalf("link = %v, want InfiniBand | 第二设备链路层应为 InfiniBand", down.Ports[0].LinkLayer)
	}
	if down.Ports[0].LID != 0x42 {
		t.Fatalf("LID = %#x, want 0x42 | LID 解析错误", down.Ports[0].LID)
	}
}

// TestReadGIDsInfersTypeWhenSysfsMissing proves GID types are derived from the
// link layer and address when the kernel does not expose gid_attrs/types, as
// on older or non-Mellanox providers. | TestReadGIDsInfersTypeWhenSysfsMissing
// 证明内核未提供 gid_attrs/types（旧版或非 Mellanox 驱动）时，GID 类型可由
// 链路层与地址推断。
func TestReadGIDsInfersTypeWhenSysfsMissing(t *testing.T) {
	ethPort := filepath.Join(t.TempDir(), "eth0", "ports", "1")
	writeSysfsFile(t, filepath.Join(ethPort, "state"), "4: ACTIVE\n")
	writeSysfsFile(t, filepath.Join(ethPort, "link_layer"), "Ethernet\n")
	writeSysfsFile(t, filepath.Join(ethPort, "gids", "0"), "fe80:0000:0000:0000:ba59:9fff:fe01:1150\n")
	writeSysfsFile(t, filepath.Join(ethPort, "gids", "1"), "0000:0000:0000:0000:0000:ffff:c0a8:0202\n")
	p := readPort(ethPort, 1)
	if len(p.GIDs) != 2 {
		t.Fatalf("ethernet GIDs = %d, want 2 | 以太网 GID 数量应为 2", len(p.GIDs))
	}
	if p.GIDs[0].Type != GIDTypeRoCEv1 {
		t.Fatalf("link-local type = %v, want RoCE v1 | 链路本地 GID 应为 RoCE v1", p.GIDs[0].Type)
	}
	if p.GIDs[1].Type != GIDTypeRoCEv2 {
		t.Fatalf("global type = %v, want RoCE v2 | 全局 GID 应为 RoCE v2", p.GIDs[1].Type)
	}

	ibPort := filepath.Join(t.TempDir(), "ib0", "ports", "1")
	writeSysfsFile(t, filepath.Join(ibPort, "state"), "4: ACTIVE\n")
	writeSysfsFile(t, filepath.Join(ibPort, "link_layer"), "InfiniBand\n")
	writeSysfsFile(t, filepath.Join(ibPort, "gids", "0"), "fe80:0000:0000:0000:0002:c903:00ef:4a3e\n")
	p = readPort(ibPort, 1)
	if len(p.GIDs) != 1 {
		t.Fatalf("IB GIDs = %d, want 1 | IB GID 数量应为 1", len(p.GIDs))
	}
	if p.GIDs[0].Type != GIDTypeInfiniBand {
		t.Fatalf("IB type = %v, want InfiniBand | IB GID 类型应为 InfiniBand", p.GIDs[0].Type)
	}
}

// TestListDevicesMissingRoot proves a host without /sys/class/infiniband
// reports ErrNoDevice. | TestListDevicesMissingRoot 证明没有
// /sys/class/infiniband 的主机会返回 ErrNoDevice。
func TestListDevicesMissingRoot(t *testing.T) {
	_, err := listDevices(filepath.Join(t.TempDir(), "absent"))
	if !errors.Is(err, ErrNoDevice) {
		t.Fatalf("listDevices(absent) = %v, want ErrNoDevice | 缺失目录应返回 ErrNoDevice", err)
	}
}

// TestDeviceInfoPortLookup proves port lookup and active checks. |
// TestDeviceInfoPortLookup 证明端口查找与活动状态判定。
func TestDeviceInfoPortLookup(t *testing.T) {
	devices, err := listDevices(buildFakeSysfs(t))
	if err != nil {
		t.Fatalf("listDevices = %v | 枚举设备失败", err)
	}
	p, ok := devices[0].Port(1)
	if !ok || !p.Active() {
		t.Fatalf("Port(1) = %v/%v, want active | 端口 1 应为活动", p, ok)
	}
	if _, ok := devices[0].Port(2); ok {
		t.Fatal("Port(2) found, want missing | 端口 2 不应存在")
	}
	if devices[1].Ports[0].Active() {
		t.Fatal("mlx5_1 active, want down | mlx5_1 应为 down")
	}
}
