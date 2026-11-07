package wal

import (
	"context"
	"math"
	"testing"
	"time"
)

// TestSizePolicyManualHonorsThresholds verifies that manual values are used
// verbatim. | TestSizePolicyManualHonorsThresholds 验证手动阈值被原样使用。
func TestSizePolicyManualHonorsThresholds(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, WithSizePolicy(SizePolicy{
		Mode:                SizePolicyManual,
		CRCCombineMinBytes:  32 << 10,
		StagingJoinMaxBytes: 16 << 10,
		WriteBufferBytes:    8 << 10,
	}))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer w.Close()
	p := w.EffectiveSizePolicy()
	if p.Mode != SizePolicyManual {
		t.Fatalf("mode = %v, want manual", p.Mode)
	}
	if p.CRCCombineMinBytes != 32<<10 {
		t.Fatalf("crc threshold = %d, want %d", p.CRCCombineMinBytes, 32<<10)
	}
	if p.StagingJoinMaxBytes != 16<<10 {
		t.Fatalf("staging threshold = %d, want %d", p.StagingJoinMaxBytes, 16<<10)
	}
	if p.WriteBufferBytes != 8<<10 {
		t.Fatalf("write buffer = %d, want %d", p.WriteBufferBytes, 8<<10)
	}
}

// TestSizePolicyManualNegativeDisables verifies that negative manual values
// disable the corresponding strategy. | TestSizePolicyManualNegativeDisables 验证
// 负的手动值会关闭对应策略。
func TestSizePolicyManualNegativeDisables(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, WithSizePolicy(SizePolicy{
		Mode:                SizePolicyManual,
		CRCCombineMinBytes:  -1,
		StagingJoinMaxBytes: -1,
		WriteBufferBytes:    0,
	}))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer w.Close()
	if got := w.crcCombineMin(); got != math.MaxInt32 {
		t.Fatalf("crc threshold = %d, want disabled (MaxInt32)", got)
	}
	if got := w.EffectiveSizePolicy().StagingJoinMaxBytes; got != 0 {
		t.Fatalf("staging threshold = %d, want disabled", got)
	}
}

// TestSizePolicyAutoCalibratesWithinBounds verifies that auto mode derives
// thresholds from measured costs and keeps them inside safe bounds. |
// TestSizePolicyAutoCalibratesWithinBounds 验证自动模式根据实测成本推导阈值，并保持
// 在安全边界内。
func TestSizePolicyAutoCalibratesWithinBounds(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, WithSizePolicy(SizePolicy{Mode: SizePolicyAuto}))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer w.Close()
	p := w.EffectiveSizePolicy()
	t.Logf("auto policy: crc=%d staging=%d buffer=%d",
		p.CRCCombineMinBytes, p.StagingJoinMaxBytes, p.WriteBufferBytes)
	if p.CRCCombineMinBytes < minCRCCombineBytes || p.CRCCombineMinBytes > maxCRCCombineBytes {
		t.Fatalf("crc threshold %d outside [%d, %d]",
			p.CRCCombineMinBytes, minCRCCombineBytes, maxCRCCombineBytes)
	}
	if p.StagingJoinMaxBytes < minStagingJoinBytes || p.StagingJoinMaxBytes > maxStagingJoinBytes {
		t.Fatalf("staging threshold %d outside [%d, %d]",
			p.StagingJoinMaxBytes, minStagingJoinBytes, maxStagingJoinBytes)
	}
	if p.WriteBufferBytes != 0 {
		t.Fatalf("write buffer = %d, want disabled by default", p.WriteBufferBytes)
	}
}

// TestSizePolicyAdaptiveBufferTracksBatchSize verifies that the adaptive write
// buffer grows toward twice the observed batch-size p95 and stays bounded. |
// TestSizePolicyAdaptiveBufferTracksBatchSize 验证自适应写缓冲向观测批次大小的 p95
// 两倍增长，并保持有界。
func TestSizePolicyAdaptiveBufferTracksBatchSize(t *testing.T) {
	w, err := Open(t.TempDir(),
		WithSyncPolicy(SyncNever()),
		WithSyncOnRotate(false),
		WithSizePolicy(SizePolicy{Mode: SizePolicyAuto, WriteBufferBytes: -1}),
	)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer w.Close()
	first := w.EffectiveSizePolicy().WriteBufferBytes
	if first < minAdaptiveWriteBuffer || first > maxAdaptiveWriteBuffer {
		t.Fatalf("initial adaptive buffer %d outside bounds", first)
	}
	small := make([]byte, 4<<10)
	ctx := context.Background()
	for i := 0; i < 600; i++ {
		if _, err := w.Append(ctx, Record{Data: small}); err != nil {
			t.Fatalf("append small %d: %v", i, err)
		}
	}
	afterSmall := w.EffectiveSizePolicy().WriteBufferBytes
	if afterSmall < minAdaptiveWriteBuffer || afterSmall > maxAdaptiveWriteBuffer {
		t.Fatalf("buffer after small batches %d outside bounds", afterSmall)
	}
	large := make([]byte, 256<<10)
	for i := 0; i < 600; i++ {
		if _, err := w.Append(ctx, Record{Data: large}); err != nil {
			t.Fatalf("append large %d: %v", i, err)
		}
	}
	afterLarge := w.EffectiveSizePolicy().WriteBufferBytes
	if afterLarge <= afterSmall {
		t.Fatalf("buffer did not grow with batch size: %d -> %d", afterSmall, afterLarge)
	}
	if afterLarge > maxAdaptiveWriteBuffer {
		t.Fatalf("buffer %d exceeds max %d", afterLarge, maxAdaptiveWriteBuffer)
	}
}

// TestSizeHistogramQuantile covers bucket selection for representative sizes. |
// TestSizeHistogramQuantile 覆盖代表性大小下的分桶选择。
func TestSizeHistogramQuantile(t *testing.T) {
	var h sizeHistogram
	for i := 0; i < 95; i++ {
		h.observe(1 << 10)
	}
	for i := 0; i < 5; i++ {
		h.observe(1 << 20)
	}
	if got := h.quantile(0.90); got < 1<<10 || got > 2<<10 {
		t.Fatalf("p90 = %d, want near 1 KiB", got)
	}
	if got := h.quantile(0.99); got < 1<<20 || got > 2<<20 {
		t.Fatalf("p99 = %d, want near 1 MiB", got)
	}
}

// TestStagingPolicyLearnsLatency verifies that the staging threshold grows when
// writes are slow and shrinks when they are fast, within bounds. |
// TestStagingPolicyLearnsLatency 验证写延迟高时暂存阈值增大、延迟低时减小，并保持
// 有界。
func TestStagingPolicyLearnsLatency(t *testing.T) {
	s := newSizePolicyState(SizePolicy{Mode: SizePolicyAuto}, 0)
	slow := 400 * time.Microsecond
	for i := 0; i < 256; i++ {
		s.observeWriteLatency(slow, 2)
	}
	high := s.stagingJoinMax.Load()
	if high <= minStagingJoinBytes || high > maxStagingJoinBytes {
		t.Fatalf("staging threshold after slow writes = %d, outside bounds", high)
	}
	fast := 500 * time.Nanosecond
	for i := 0; i < 4096; i++ {
		s.observeWriteLatency(fast, 2)
	}
	low := s.stagingJoinMax.Load()
	if low < minStagingJoinBytes {
		t.Fatalf("staging threshold after fast writes = %d, below min", low)
	}
	if low >= high {
		t.Fatalf("staging threshold did not shrink: %d -> %d", high, low)
	}
}
