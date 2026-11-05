//go:build linux && rdma && (amd64 || arm64)

package rdma

import (
	"testing"
	"unsafe"
)

// TestABISizes proves the Go mirrors have the exact libibverbs sizes. The
// expected values come from a C probe against /usr/include/infiniband/verbs.h.
// | TestABISizes 证明 Go 镜像与 libibverbs 的大小完全一致。期望值来自针对
// /usr/include/infiniband/verbs.h 的 C 探针。
func TestABISizes(t *testing.T) {
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"ibvSGE", unsafe.Sizeof(ibvSGE{}), abiSGESize},
		{"ibvSendWR", unsafe.Sizeof(ibvSendWR{}), abiSendWRSize},
		{"ibvRecvWR", unsafe.Sizeof(ibvRecvWR{}), abiRecvWRSize},
		{"ibvWC", unsafe.Sizeof(ibvWC{}), abiWCSize},
		{"ibvQPInitAttr", unsafe.Sizeof(ibvQPInitAttr{}), abiQPInitAttrSize},
		{"ibvAHAttr", unsafe.Sizeof(ibvAHAttr{}), abiAHAttrSize},
		{"ibvQPAttr", unsafe.Sizeof(ibvQPAttr{}), abiQPAttrSize},
		{"ibvDeviceAttr", unsafe.Sizeof(ibvDeviceAttr{}), abiDeviceAttrSize},
		{"ibvPortAttr", unsafe.Sizeof(ibvPortAttr{}), abiPortAttrSize},
		{"ibvMR", unsafe.Sizeof(ibvMR{}), abiMRSize},
		{"ibvSRQInitAttr", unsafe.Sizeof(ibvSRQInitAttr{}), abiSRQInitAttrSize},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s size = %d, want %d | %s 大小不符", tc.name, tc.got, tc.want, tc.name)
		}
	}
}

// TestABIOffsets proves hot-path field offsets match the C probe. | TestABIOffsets
// 证明热路径字段偏移与 C 探针一致。
func TestABIOffsets(t *testing.T) {
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"send_wr.next", unsafe.Offsetof(ibvSendWR{}.Next), 8},
		{"send_wr.sg_list", unsafe.Offsetof(ibvSendWR{}.SGList), 16},
		{"send_wr.num_sge", unsafe.Offsetof(ibvSendWR{}.NumSGE), 24},
		{"send_wr.opcode", unsafe.Offsetof(ibvSendWR{}.Opcode), 28},
		{"send_wr.send_flags", unsafe.Offsetof(ibvSendWR{}.SendFlags), 32},
		{"send_wr.imm_data", unsafe.Offsetof(ibvSendWR{}.ImmData), 36},
		{"send_wr.wr", unsafe.Offsetof(ibvSendWR{}.Union), 40},
		{"send_wr.wr.rdma.remote_addr", unsafe.Offsetof(ibvSendWR{}.Union) + unsafe.Offsetof(ibvSendWRUnion{}.RemoteAddr), 40},
		{"send_wr.wr.rdma.rkey", unsafe.Offsetof(ibvSendWR{}.Union) + unsafe.Offsetof(ibvSendWRUnion{}.Field8), 48},
		{"send_wr.wr.atomic.compare_add", unsafe.Offsetof(ibvSendWR{}.Union) + unsafe.Offsetof(ibvSendWRUnion{}.Field8), 48},
		{"send_wr.wr.atomic.swap", unsafe.Offsetof(ibvSendWR{}.Union) + unsafe.Offsetof(ibvSendWRUnion{}.Swap), 56},
		{"send_wr.qp_type", unsafe.Offsetof(ibvSendWR{}.QPType), 72},
		{"recv_wr.next", unsafe.Offsetof(ibvRecvWR{}.Next), 8},
		{"recv_wr.sg_list", unsafe.Offsetof(ibvRecvWR{}.SGList), 16},
		{"recv_wr.num_sge", unsafe.Offsetof(ibvRecvWR{}.NumSGE), 24},
		{"wc.status", unsafe.Offsetof(ibvWC{}.Status), 8},
		{"wc.opcode", unsafe.Offsetof(ibvWC{}.Opcode), 12},
		{"wc.imm_data", unsafe.Offsetof(ibvWC{}.ImmData), 24},
		{"wc.qp_num", unsafe.Offsetof(ibvWC{}.QPNum), 28},
		{"qp_init_attr.send_cq", unsafe.Offsetof(ibvQPInitAttr{}.SendCQ), 8},
		{"qp_init_attr.recv_cq", unsafe.Offsetof(ibvQPInitAttr{}.RecvCQ), 16},
		{"qp_init_attr.srq", unsafe.Offsetof(ibvQPInitAttr{}.SRQ), 24},
		{"qp_init_attr.cap", unsafe.Offsetof(ibvQPInitAttr{}.Cap), 32},
		{"qp_init_attr.qp_type", unsafe.Offsetof(ibvQPInitAttr{}.QPType), 52},
		{"qp_init_attr.sq_sig_all", unsafe.Offsetof(ibvQPInitAttr{}.SQSigAll), 56},
		{"ah_attr.grh", unsafe.Offsetof(ibvAHAttr{}.GRH), 0},
		{"ah_attr.grh.flow_label", unsafe.Offsetof(ibvAHAttr{}.GRH.FlowLabel), 16},
		{"ah_attr.dlid", unsafe.Offsetof(ibvAHAttr{}.DLID), 24},
		{"ah_attr.sl", unsafe.Offsetof(ibvAHAttr{}.SL), 26},
		{"ah_attr.is_global", unsafe.Offsetof(ibvAHAttr{}.IsGlobal), 29},
		{"ah_attr.port_num", unsafe.Offsetof(ibvAHAttr{}.PortNum), 30},
		{"qp_attr.path_mtu", unsafe.Offsetof(ibvQPAttr{}.PathMTU), 8},
		{"qp_attr.dest_qp_num", unsafe.Offsetof(ibvQPAttr{}.DestQPN), 28},
		{"qp_attr.qp_access_flags", unsafe.Offsetof(ibvQPAttr{}.QPAccessFlags), 32},
		{"qp_attr.cap", unsafe.Offsetof(ibvQPAttr{}.Cap), 36},
		{"qp_attr.ah_attr", unsafe.Offsetof(ibvQPAttr{}.AHAttr), 56},
		{"qp_attr.alt_ah_attr", unsafe.Offsetof(ibvQPAttr{}.AltAHAttr), 88},
		{"qp_attr.pkey_index", unsafe.Offsetof(ibvQPAttr{}.PKeyIndex), 120},
		{"qp_attr.max_rd_atomic", unsafe.Offsetof(ibvQPAttr{}.MaxRDAtomic), 126},
		{"qp_attr.max_dest_rd_atomic", unsafe.Offsetof(ibvQPAttr{}.MaxDestRDAtomic), 127},
		{"qp_attr.min_rnr_timer", unsafe.Offsetof(ibvQPAttr{}.MinRNRTimer), 128},
		{"qp_attr.port_num", unsafe.Offsetof(ibvQPAttr{}.PortNum), 129},
		{"qp_attr.timeout", unsafe.Offsetof(ibvQPAttr{}.Timeout), 130},
		{"qp_attr.retry_cnt", unsafe.Offsetof(ibvQPAttr{}.RetryCnt), 131},
		{"qp_attr.rnr_retry", unsafe.Offsetof(ibvQPAttr{}.RNRRetry), 132},
		{"qp_attr.rate_limit", unsafe.Offsetof(ibvQPAttr{}.RateLimit), 136},
		{"device_attr.node_guid", unsafe.Offsetof(ibvDeviceAttr{}.NodeGUID), 64},
		{"device_attr.max_mr_size", unsafe.Offsetof(ibvDeviceAttr{}.MaxMRSize), 80},
		{"device_attr.max_qp_wr", unsafe.Offsetof(ibvDeviceAttr{}.MaxQPWR), 112},
		{"device_attr.max_sge", unsafe.Offsetof(ibvDeviceAttr{}.MaxSGE), 120},
		{"device_attr.max_cqe", unsafe.Offsetof(ibvDeviceAttr{}.MaxCQE), 132},
		{"device_attr.max_qp_rd_atom", unsafe.Offsetof(ibvDeviceAttr{}.MaxQPRdAtom), 144},
		{"port_attr.max_mtu", unsafe.Offsetof(ibvPortAttr{}.MaxMTU), 4},
		{"port_attr.active_mtu", unsafe.Offsetof(ibvPortAttr{}.ActiveMTU), 8},
		{"port_attr.lid", unsafe.Offsetof(ibvPortAttr{}.LID), 34},
		{"port_attr.link_layer", unsafe.Offsetof(ibvPortAttr{}.LinkLayer), 46},
		{"qp.qp_num", unsafe.Offsetof(ibvQP{}.QPNum), 52},
		{"mr.lkey", unsafe.Offsetof(ibvMR{}.LKey), 36},
		{"mr.rkey", unsafe.Offsetof(ibvMR{}.RKey), 40},
		{"srq_init_attr.attr", unsafe.Offsetof(ibvSRQInitAttr{}.Attr), 8},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s offset = %d, want %d | %s 偏移不符", tc.name, tc.got, tc.want, tc.name)
		}
	}
}

// TestSupportedOnRDMAHost proves libibverbs loads on the test hosts. |
// TestSupportedOnRDMAHost 证明测试主机可加载 libibverbs。
func TestSupportedOnRDMAHost(t *testing.T) {
	if !Supported() {
		_, err := loadVerbs("")
		t.Fatalf("Supported() = false: %v | 测试主机应支持 RDMA", err)
	}
}
