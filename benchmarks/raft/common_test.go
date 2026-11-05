package raft

import (
	"context"
	"encoding/binary"
	"testing"
	"time"
)

// benchmarkSize is the proposal payload size in bytes. | benchmarkSize 是提案负载
// 的字节数。
const benchmarkSize = 64

// proposer is the shared hot-path contract. | proposer 是共享热路径契约。
type proposer interface {
	propose(ctx context.Context, size int) error
}

// payload builds a proposal body with an embedded sequence number. | payload 构建
// 内嵌序号提案体。
func payload(seq uint64, size int) []byte {
	b := make([]byte, size)
	binary.BigEndian.PutUint64(b, seq)
	return b
}

// runSequential runs b.N synchronous proposals. | runSequential 运行 b.N 个同步提案。
func runSequential(b *testing.B, p proposer) {
	b.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := p.propose(ctx, benchmarkSize); err != nil {
			b.Fatalf("propose: %v", err)
		}
	}
}

// runParallel runs b.N proposals from the benchmark's parallel workers. | runParallel
// 从基准并行 worker 运行 b.N 个提案。
func runParallel(b *testing.B, p proposer) {
	b.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := p.propose(ctx, benchmarkSize); err != nil {
				b.Errorf("propose: %v", err)
				return
			}
		}
	})
}

// waitUntil polls a condition with a deadline. | waitUntil 在期限内轮询条件。
func waitUntil(b *testing.B, what string, timeout time.Duration, cond func() bool) {
	b.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	b.Fatalf("timed out waiting for %s", what)
}
