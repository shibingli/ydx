package rdma

// Name returns the kernel device name. | Name 返回内核设备名。
func (d *Device) Name() string {
	if d == nil {
		return ""
	}
	return d.info.Name
}

// Config returns the normalised configuration used to open the device. |
// Config 返回打开设备时使用的规范化配置。
func (d *Device) Config() Config {
	if d == nil {
		return Config{}
	}
	return d.cfg
}

// Info returns the sysfs device description enriched with port MTU values. |
// Info 返回补充端口 MTU 后的 sysfs 设备描述。
func (d *Device) Info() DeviceInfo {
	if d == nil {
		return DeviceInfo{}
	}
	return d.info
}

// GID returns the GID selected for connections. | GID 返回连接选用的 GID。
func (d *Device) GID() GID {
	if d == nil {
		return GID{}
	}
	return d.gid
}

// Port returns the one-based port number. | Port 返回 1 起始的端口号。
func (d *Device) Port() int {
	if d == nil {
		return 0
	}
	return d.port
}

// Attr returns the device capabilities. | Attr 返回设备能力。
func (d *Device) Attr() DeviceAttr {
	if d == nil {
		return DeviceAttr{}
	}
	return d.attr
}

// PortAttr returns the runtime port attributes. | PortAttr 返回端口运行属性。
func (d *Device) PortAttr() PortAttr {
	if d == nil {
		return PortAttr{}
	}
	return d.portAttr
}

// Depth returns the completion queue depth. | Depth 返回完成队列深度。
func (c *CQ) Depth() int {
	if c == nil {
		return 0
	}
	return c.depth
}

// QPN returns the queue pair number. | QPN 返回队列对号。
func (q *QP) QPN() uint32 {
	if q == nil {
		return 0
	}
	return q.qpn
}

// MaxInline returns the inline payload limit granted to the queue pair. |
// MaxInline 返回授予队列对的内联负载上限。
func (q *QP) MaxInline() int {
	if q == nil {
		return 0
	}
	return int(q.inline)
}

// Type returns the queue pair transport service. | Type 返回队列对传输服务。
func (q *QP) Type() QPType {
	if q == nil {
		return 0
	}
	return q.typ
}
