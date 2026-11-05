package rdma

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

// testQPInfo returns a fully populated QP descriptor. | testQPInfo 返回一个
// 字段完整的 QP 描述。
func testQPInfo(t *testing.T) qpInfo {
	t.Helper()
	gid, err := ParseGID(3, "::ffff:192.168.2.2")
	if err != nil {
		t.Fatalf("ParseGID = %v | GID 解析失败", err)
	}
	return qpInfo{
		QPN:       0x1234,
		PSN:       0xabcdef,
		GID:       gid.Addr,
		LID:       7,
		MTU:       1024,
		MaxInline: 64,
		RKey:      0xdeadbeef,
		Addr:      0x7f0000000000,
		SlotSize:  65536,
		Slots:     512,
	}
}

// TestQPInfoRoundTrip proves the wire format preserves every field. |
// TestQPInfoRoundTrip 证明线格式能完整保留每个字段。
func TestQPInfoRoundTrip(t *testing.T) {
	want := testQPInfo(t)
	var buf bytes.Buffer
	if err := writeQPInfo(&buf, want); err != nil {
		t.Fatalf("writeQPInfo = %v | 编码失败", err)
	}
	if got, wantLen := buf.Len(), qpInfoWireSize; got != wantLen {
		t.Fatalf("wire size = %d, want %d | 线格式长度不符", got, wantLen)
	}
	got, err := readQPInfo(&buf)
	if err != nil {
		t.Fatalf("readQPInfo = %v | 解码失败", err)
	}
	if got != want {
		t.Fatalf("round trip = %+v, want %+v | 往返结果不一致", got, want)
	}
}

// TestReadQPInfoRejectsBadMagic proves a foreign TCP stream is rejected
// instead of misread as QP parameters. | TestReadQPInfoRejectsBadMagic 证明
// 外来 TCP 流会被拒绝而不是误读为 QP 参数。
func TestReadQPInfoRejectsBadMagic(t *testing.T) {
	buf := make([]byte, qpInfoWireSize)
	if _, err := readQPInfo(bytes.NewReader(buf)); !errors.Is(err, ErrHandshake) {
		t.Fatalf("readQPInfo(zero) = %v, want ErrHandshake | 错误魔数应返回 ErrHandshake", err)
	}
}

// TestReadQPInfoRejectsTruncation proves a short stream is rejected. |
// TestReadQPInfoRejectsTruncation 证明短流会被拒绝。
func TestReadQPInfoRejectsTruncation(t *testing.T) {
	var buf bytes.Buffer
	if err := writeQPInfo(&buf, testQPInfo(t)); err != nil {
		t.Fatalf("writeQPInfo = %v | 编码失败", err)
	}
	data := buf.Bytes()
	if _, err := readQPInfo(bytes.NewReader(data[:len(data)-1])); !errors.Is(err, ErrHandshake) {
		t.Fatalf("readQPInfo(truncated) = %v, want ErrHandshake | 截断流应返回 ErrHandshake", err)
	}
}

// TestExchangeQPInfo proves two peers exchange descriptors concurrently over
// a duplex stream. | TestExchangeQPInfo 证明两个对端可在双工流上并发交换描述。
func TestExchangeQPInfo(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	type result struct {
		info qpInfo
		err  error
	}
	serverCh := make(chan result, 1)
	go func() {
		info, err := exchangeQPInfo(server, testQPInfo(t), time.Second)
		serverCh <- result{info, err}
	}()
	wantClient := testQPInfo(t)
	wantClient.QPN++
	got, err := exchangeQPInfo(client, wantClient, time.Second)
	if err != nil {
		t.Fatalf("client exchange = %v | 客户端交换失败", err)
	}
	if got != testQPInfo(t) {
		t.Fatalf("client remote = %+v | 客户端收到的描述不符", got)
	}
	res := <-serverCh
	if res.err != nil {
		t.Fatalf("server exchange = %v | 服务端交换失败", res.err)
	}
	if res.info != wantClient {
		t.Fatalf("server remote = %+v, want %+v | 服务端收到的描述不符", res.info, wantClient)
	}
}
