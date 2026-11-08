package zstd

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"

	kzstd "github.com/klauspost/compress/zstd"
)

// codecContract mirrors wal.Codec without importing the wal module. | codecContract
// 在不 import wal 模块的前提下镜像 wal.Codec。
type codecContract interface {
	ID() byte
	Compress(dst, src []byte) ([]byte, error)
	Decompress(dst, src []byte) ([]byte, error)
}

var _ codecContract = New(3)

func roundTrip(t *testing.T, c *Codec, src []byte) []byte {
	t.Helper()
	compressed, err := c.Compress(nil, src)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	dst := make([]byte, len(src))
	out, err := c.Decompress(dst, compressed)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	return out
}

// TestRoundTrip covers levels, sizes, and repetitive data. | 覆盖级别、大小与
// 重复数据。
func TestRoundTrip(t *testing.T) {
	if CodecID != 2 {
		t.Fatalf("CodecID = %d, want 2", CodecID)
	}
	inputs := [][]byte{
		{},
		[]byte("x"),
		bytes.Repeat([]byte("abcd"), 1024),
		bytes.Repeat([]byte("z"), 1<<20),
	}
	for _, level := range []int{-1, 0, 1, 3, 9, 22, 100} {
		c := New(level)
		if c.ID() != CodecID {
			t.Fatalf("ID = %d", c.ID())
		}
		for _, in := range inputs {
			got := roundTrip(t, c, in)
			if !bytes.Equal(got, in) {
				t.Fatalf("level %d: round trip mismatch for %d bytes", level, len(in))
			}
		}
	}
}

// TestCompressRatio verifies that highly repetitive input actually shrinks. |
// 验证高重复输入确实被压缩。
func TestCompressRatio(t *testing.T) {
	c := New(3)
	src := bytes.Repeat([]byte("the quick brown fox "), 4096)
	out, err := c.Compress(nil, src)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) >= len(src)/2 {
		t.Fatalf("compressed %d bytes to %d, expected at least 2x", len(src), len(out))
	}
}

// TestCorruptAndTruncated verifies that bad frames fail without panicking. |
// 验证损坏/截断帧安全失败。
func TestCorruptAndTruncated(t *testing.T) {
	c := New(3)
	src := bytes.Repeat([]byte("corruption"), 256)
	compressed, err := c.Compress(nil, src)
	if err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, len(src))
	if _, err := c.Decompress(dst, compressed[:len(compressed)/2]); err == nil {
		t.Fatal("truncated frame was accepted")
	}
	// The frame magic is the reliable structural corruption check; the wal
	// record CRC covers payload bit rot. | 帧 magic 是可靠的结构损坏检查；
	// wal 记录 CRC 负责覆盖负载位腐。
	bad := append([]byte(nil), compressed...)
	bad[0] ^= 0xFF
	if _, err := c.Decompress(dst, bad); err == nil {
		t.Fatal("corrupt frame was accepted")
	}
	// A valid frame whose plaintext is longer than dst must be rejected. |
	// 明文长于目标缓冲的有效帧必须拒绝。
	short := make([]byte, len(src)-1)
	if _, err := c.Decompress(short, compressed); err == nil {
		t.Fatal("short destination was accepted")
	}
}

// TestDecompressRejectsWindowLargerThanPlaintext verifies that the decoder binds
// its window and memory to the validated plaintext length, so a crafted frame
// cannot force a large window allocation for a small record. | 验证解码器把窗口
// 与内存绑定到已校验的明文长度，使构造帧无法用小记录触发大窗口分配。
func TestDecompressRejectsWindowLargerThanPlaintext(t *testing.T) {
	payload := bytes.Repeat([]byte("window-bound"), 1<<15)
	var framed bytes.Buffer
	enc, err := kzstd.NewWriter(&framed,
		kzstd.WithEncoderConcurrency(1),
		kzstd.WithEncoderLevel(kzstd.SpeedFastest),
		kzstd.WithWindowSize(1<<20),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enc.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}

	c := New(3)
	dst := make([]byte, 0, len(payload))
	_, err = c.Decompress(dst, framed.Bytes())
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v, want ErrCorrupt for a window larger than the declared plaintext", err)
	}
	if !strings.Contains(err.Error(), "window size exceeded") {
		t.Fatalf("err = %v, want the zstd window-size bound to trigger", err)
	}
}

// TestConcurrentCodec verifies the pool is safe under concurrent use. |
// 验证池在并发使用下安全。
func TestConcurrentCodec(t *testing.T) {
	c := New(5)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			src := bytes.Repeat([]byte{byte('a' + id)}, 4096)
			for j := 0; j < 50; j++ {
				compressed, err := c.Compress(nil, src)
				if err != nil {
					t.Errorf("worker %d compress: %v", id, err)
					return
				}
				dst := make([]byte, len(src))
				got, err := c.Decompress(dst, compressed)
				if err != nil {
					t.Errorf("worker %d decompress: %v", id, err)
					return
				}
				if !bytes.Equal(got, src) {
					t.Errorf("worker %d mismatch", id)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

// TestErrorsAreStable verifies sentinel errors survive wrapping. | 验证哨兵错误
// 经过包装后仍可判定。
func TestErrorsAreStable(t *testing.T) {
	c := New(3)
	if _, err := c.Decompress(make([]byte, 4), []byte("not a zstd frame")); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v, want ErrCorrupt", err)
	}
}
