package rdma

// peerAH builds the address handle used to reach a remote queue pair. Native
// InfiniBand peers with a LID use local routing; RoCE and LID-less peers use
// the global routing header. | peerAH 构建用于访问远端队列对的地址句柄。
// 带 LID 的原生 InfiniBand 对端使用本地路由；RoCE 与无 LID 的对端使用全局
// 路由头。
func peerAH(link LinkLayer, cfg *Config, port int, remote ConnectInfo) AHAttr {
	ah := AHAttr{
		IsGlobal:     true,
		GID:          remote.GID,
		DLID:         remote.LID,
		SGIDIndex:    uint8(cfg.GIDIndex),
		HopLimit:     cfg.HopLimit,
		Port:         uint8(port),
		SL:           cfg.ServiceLevel,
		TrafficClass: cfg.TrafficClass,
	}
	if link == LinkLayerInfiniBand && remote.LID != 0 {
		// A LID-addressed InfiniBand peer stays inside the local subnet, so the
		// GRH is unnecessary and would require a routable GID. | 用 LID 寻址的
		// InfiniBand 对端位于本地子网，无需 GRH，也不会要求可路由 GID。
		ah.IsGlobal = false
		ah.GID = [16]byte{}
	}
	if link != LinkLayerInfiniBand {
		// RoCE ignores LIDs; a stale value must not leak into the address handle.
		// | RoCE 忽略 LID，残留值不得进入地址句柄。
		ah.DLID = 0
	}
	return ah
}
