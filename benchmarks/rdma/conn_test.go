//go:build linux && rdma && (amd64 || arm64)

package rdma

import (
	"bytes"
	"os"
	"runtime"
	"sort"
	"testing"
	"time"

	ydx "github.com/shibingli/ydx/rdma"
)

// benchConnConfig returns a small connection configuration for the latency
// benchmark. | benchConnConfig 返回延迟基准使用的小型连接配置。
func benchConnConfig() ydx.ConnConfig {
	cfg := ydx.DefaultConnConfig()
	cfg.Device = "mlx5_0"
	cfg.Slots = 2
	cfg.SlotSize = 4096
	cfg.HandshakeTimeout = 30 * time.Second
	cfg.SendTimeout = 30 * time.Second
	cfg.RecvTimeout = 30 * time.Second
	return cfg
}

// TestConnCrossHost measures the zero-copy message round trip. | TestConnCrossHost
// 测量零拷贝消息往返延迟。
func TestConnCrossHost(t *testing.T) {
	role := os.Getenv("YDX_RDMA_ROLE")
	addr := os.Getenv("YDX_RDMA_ADDR")
	if role == "" || addr == "" {
		t.Skip("set YDX_RDMA_ROLE and YDX_RDMA_ADDR | 未设置跨主机测试变量")
	}
	cfg := benchConnConfig()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	const rounds = 1000
	switch role {
	case "server":
		ln, err := ydx.Listen(addr, cfg)
		if err != nil {
			t.Fatalf("Listen = %v | 监听失败", err)
		}
		defer ln.Close()
		c, err := ln.Accept()
		if err != nil {
			t.Fatalf("Accept = %v | 接受失败", err)
		}
		defer c.Close()
		t.Logf("server inline=%d slot=%d", c.QP().MaxInline(), cfg.SlotSize)
		var recvNS, sendNS int64
		for i := 0; i < rounds; i++ {
			t0 := time.Now()
			rb, n, rerr := c.RecvBuffer()
			if rerr != nil {
				t.Fatalf("RecvBuffer #%d = %v | 接收失败", i, rerr)
			}
			t1 := time.Now()
			tb, aerr := c.Alloc(n)
			if aerr != nil {
				t.Fatalf("Alloc #%d = %v | 获取发送槽位失败", i, aerr)
			}
			copy(tb.Bytes(), rb.Bytes()[:n])
			_ = c.Release(rb)
			if serr := c.SendBuffer(tb, n); serr != nil {
				t.Fatalf("SendBuffer #%d = %v | 回显失败", i, serr)
			}
			t2 := time.Now()
			recvNS += int64(t1.Sub(t0))
			sendNS += int64(t2.Sub(t1))
		}
		t.Logf("server recv=%v send=%v | 服务端耗时",
			time.Duration(recvNS/rounds), time.Duration(sendNS/rounds))
	case "client":
		c, err := ydx.Dial(addr, cfg)
		if err != nil {
			t.Fatalf("Dial = %v | 拨号失败", err)
		}
		defer c.Close()
		t.Logf("client inline=%d slot=%d", c.QP().MaxInline(), cfg.SlotSize)
		msg := []byte("cross-host payload")
		var sendNS, waitNS int64
		durs := make([]time.Duration, 0, rounds)
		for i := 0; i < rounds; i++ {
			t0 := time.Now()
			b, aerr := c.Alloc(len(msg))
			if aerr != nil {
				t.Fatalf("Alloc #%d = %v | 获取发送槽位失败", i, aerr)
			}
			copy(b.Bytes(), msg)
			if serr := c.SendBuffer(b, len(msg)); serr != nil {
				t.Fatalf("SendBuffer #%d = %v | 发送失败", i, serr)
			}
			t1 := time.Now()
			rb, n, rerr := c.RecvBuffer()
			if rerr != nil {
				t.Fatalf("RecvBuffer #%d = %v | 接收失败", i, rerr)
			}
			t2 := time.Now()
			sendNS += int64(t1.Sub(t0))
			waitNS += int64(t2.Sub(t1))
			durs = append(durs, t2.Sub(t0))
			if !bytes.Equal(rb.Bytes()[:n], msg) {
				t.Fatalf("echo #%d = %q | 回显不符", i, rb.Bytes()[:n])
			}
			if rerr := c.Release(rb); rerr != nil {
				t.Fatalf("Release #%d = %v | 释放失败", i, rerr)
			}
		}
		sort.Slice(durs, func(i, j int) bool { return durs[i] < durs[j] })
		var sum time.Duration
		for _, d := range durs {
			sum += d
		}
		t.Logf("client avg=%v min=%v p50=%v p99=%v max=%v send=%v wait=%v | 客户端往返耗时",
			sum/rounds, durs[0], durs[rounds/2], durs[rounds*99/100], durs[rounds-1],
			time.Duration(sendNS/rounds), time.Duration(waitNS/rounds))
	default:
		t.Fatalf("unknown YDX_RDMA_ROLE %q | 未知角色", role)
	}
}

// TestConnBandwidthCrossHost measures the zero-copy SEND throughput. |
// TestConnBandwidthCrossHost 测量零拷贝 SEND 吞吐。
func TestConnBandwidthCrossHost(t *testing.T) {
	role := os.Getenv("YDX_RDMA_ROLE")
	addr := os.Getenv("YDX_RDMA_ADDR")
	if role == "" || addr == "" {
		t.Skip("set YDX_RDMA_ROLE and YDX_RDMA_ADDR | 未设置跨主机测试变量")
	}
	cfg := ydx.DefaultConnConfig()
	cfg.Device = "mlx5_0"
	cfg.Slots = 1024
	cfg.SlotSize = 4096
	cfg.MaxBatch = 64
	cfg.HandshakeTimeout = 30 * time.Second
	cfg.SendTimeout = 30 * time.Second
	cfg.RecvTimeout = 30 * time.Second
	const rounds = 1000000
	const payload = 4096
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	switch role {
	case "server":
		ln, err := ydx.Listen(addr, cfg)
		if err != nil {
			t.Fatalf("Listen = %v | 监听失败", err)
		}
		defer ln.Close()
		c, err := ln.Accept()
		if err != nil {
			t.Fatalf("Accept = %v | 接受失败", err)
		}
		defer c.Close()
		bufs := make([]*ydx.Buffer, 64)
		lens := make([]int, 64)
		received := 0
		start := time.Now()
		for received < rounds {
			n, rerr := c.RecvBuffers(bufs, lens)
			if rerr != nil {
				t.Fatalf("RecvBuffers = %v | 批量接收失败", rerr)
			}
			if n == 0 {
				continue
			}
			received += n
			if rerr := c.ReleaseBatch(bufs[:n]); rerr != nil {
				t.Fatalf("ReleaseBatch = %v | 批量释放失败", rerr)
			}
		}
		elapsed := time.Since(start)
		bits := float64(rounds) * payload * 8
		t.Logf("server received %d messages in %v: %.1f Gb/s | 服务端吞吐",
			rounds, elapsed, bits/elapsed.Seconds()/1e9)
	case "client":
		c, err := ydx.Dial(addr, cfg)
		if err != nil {
			t.Fatalf("Dial = %v | 拨号失败", err)
		}
		defer c.Close()
		lens := make([]int, 64)
		for i := range lens {
			lens[i] = payload
		}
		sent := 0
		batch := make([]*ydx.Buffer, 64)
		start := time.Now()
		for sent < rounds {
			n := rounds - sent
			if n > len(batch) {
				n = len(batch)
			}
			for i := 0; i < n; i++ {
				b, aerr := c.Alloc(payload)
				if aerr != nil {
					t.Fatalf("Alloc = %v | 获取发送槽位失败", aerr)
				}
				b.Bytes()[0] = byte(sent + i)
				batch[i] = b
			}
			posted, perr := c.SendBatchBuffers(batch[:n], lens[:n])
			if perr != nil {
				t.Fatalf("SendBatchBuffers = %v | 批量发送失败", perr)
			}
			sent += posted
		}
		elapsed := time.Since(start)
		bits := float64(rounds) * payload * 8
		t.Logf("client posted %d messages in %v: %.1f Gb/s | 客户端发送吞吐",
			rounds, elapsed, bits/elapsed.Seconds()/1e9)
		time.Sleep(2 * time.Second)
	default:
		t.Fatalf("unknown YDX_RDMA_ROLE %q | 未知角色", role)
	}
}
