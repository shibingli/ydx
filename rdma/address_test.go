package rdma

import "testing"

// TestPeerAHLocalRoutingForInfiniBand proves an InfiniBand peer with a LID is
// addressed by local routing (DLID, no GRH), while a LID-less IB peer falls
// back to the global routing header. | TestPeerAHLocalRoutingForInfiniBand
// 证明带 LID 的 InfiniBand 对端使用本地路由（DLID、无 GRH），没有 LID 的 IB
// 对端回退到全局路由头。
func TestPeerAHLocalRoutingForInfiniBand(t *testing.T) {
	remote := ConnectInfo{
		QPN: 7, PSN: 11, GID: parseGIDForTest(t, "fe80::1"), LID: 0x42, MTU: 1024,
	}
	cfg := Config{GIDIndex: 3, HopLimit: 64, ServiceLevel: 2, TrafficClass: 5}
	ah := peerAH(LinkLayerInfiniBand, &cfg, 1, remote)
	if ah.IsGlobal {
		t.Fatal("IsGlobal = true, want local routing | 带 LID 的 IB 对端不应使用 GRH")
	}
	if ah.DLID != 0x42 {
		t.Fatalf("DLID = %#x, want 0x42 | DLID 应为远端 LID", ah.DLID)
	}
	if ah.SGIDIndex != 3 || ah.Port != 1 || ah.SL != 2 {
		t.Fatalf("AH = %+v | GID 索引、端口与服务等级不符", ah)
	}

	remote.LID = 0
	ah = peerAH(LinkLayerInfiniBand, &cfg, 1, remote)
	if !ah.IsGlobal {
		t.Fatal("IsGlobal = false, want GRH fallback | 无 LID 的 IB 对端应使用 GRH")
	}
	if ah.GID != remote.GID || ah.HopLimit != 64 || ah.SGIDIndex != 3 {
		t.Fatalf("AH = %+v | GRH 回退字段不符", ah)
	}
}

// TestPeerAHGlobalForRoCE proves Ethernet peers always use the global routing
// header with the configured hop limit and traffic class, even if a stale LID
// is present. | TestPeerAHGlobalForRoCE 证明以太网对端始终使用全局路由头，
// 并带上配置的跳数限制与流量类别，即使残留了 LID。
func TestPeerAHGlobalForRoCE(t *testing.T) {
	remote := ConnectInfo{
		QPN: 9, PSN: 1, GID: parseGIDForTest(t, "::ffff:192.168.2.3"), LID: 0x7, MTU: 1024,
	}
	cfg := Config{GIDIndex: 1, HopLimit: 32, ServiceLevel: 1, TrafficClass: 6}
	ah := peerAH(LinkLayerEthernet, &cfg, 1, remote)
	if !ah.IsGlobal {
		t.Fatal("IsGlobal = false, want GRH | RoCE 对端必须使用 GRH")
	}
	if ah.GID != remote.GID {
		t.Fatalf("GID = %x, want %x | GID 应为远端 GID", ah.GID, remote.GID)
	}
	if ah.HopLimit != 32 || ah.TrafficClass != 6 || ah.SGIDIndex != 1 {
		t.Fatalf("AH = %+v | RoCE 路径字段不符", ah)
	}
	if ah.DLID != 0 {
		t.Fatalf("DLID = %#x, want 0 | RoCE 对端不应携带 DLID", ah.DLID)
	}
}
