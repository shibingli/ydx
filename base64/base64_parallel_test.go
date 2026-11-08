package base64

import (
	"bytes"
	"errors"
	"runtime"
	"testing"
)

// TestParallelMatchesSerial verifies every encoding variant and worker count
// produces exactly the serial result. | TestParallelMatchesSerial 验证每个编码变体
// 与工作协程数都产生与串行版本完全一致的结果。
func TestParallelMatchesSerial(t *testing.T) {
	variants := map[string]*Encoding{
		"std": StdEncoding, "raw-std": RawStdEncoding,
		"url": URLEncoding, "raw-url": RawURLEncoding,
	}
	sizes := []int{0, 1, 2, 3, 4, 5, 255, 256 << 10, (256 << 10) + 1, (1 << 20) + 7}
	workers := []int{0, 1, 2, 3, 7, runtime.GOMAXPROCS(0)}
	for name, e := range variants {
		for _, n := range sizes {
			src := randomBytes(n)
			want := make([]byte, e.EncodedLen(len(src)))
			e.Encode(want, src)
			for _, w := range workers {
				got := make([]byte, len(want))
				e.encodeParallel(got, src, w)
				if !bytes.Equal(got, want) {
					t.Fatalf("%s/n=%d/workers=%d encode differs | 编码结果不一致", name, n, w)
				}
				dec := make([]byte, e.DecodedLen(len(want)))
				m, err := e.decodeParallel(dec, want, w)
				if err != nil || m != len(src) || !bytes.Equal(dec[:m], src) {
					t.Fatalf("%s/n=%d/workers=%d decode: n=%d err=%v | 解码结果不一致",
						name, n, w, m, err)
				}
			}
		}
	}
}

// checkParallelDecodeError verifies a parallel decode returns exactly the serial partial count,
// error type, error offset and decoded prefix. | checkParallelDecodeError 验证并行解码返回与串行
// 完全一致的部分字节数、错误类型、错误偏移与已解码前缀。
func checkParallelDecodeError(t *testing.T, name string, pos int, e *Encoding, src []byte, workers int) {
	t.Helper()
	wantOut := make([]byte, e.DecodedLen(len(src)))
	wantN, wantErr := e.Decode(wantOut, src)
	gotOut := make([]byte, len(wantOut))
	gotN, gotErr := e.decodeParallel(gotOut, src, workers)
	if (gotErr == nil) != (wantErr == nil) {
		t.Fatalf("%s/pos=%d err=%v, want %v | 并行错误存在性不一致", name, pos, gotErr, wantErr)
	}
	if gotN != wantN {
		t.Fatalf("%s/pos=%d n=%d, want %d | 并行部分字节数不一致", name, pos, gotN, wantN)
	}
	if !bytes.Equal(gotOut[:gotN], wantOut[:wantN]) {
		t.Fatalf("%s/pos=%d decoded prefix differs | 并行已解码前缀不一致", name, pos)
	}
	if wantErr != nil {
		var wantPos, gotPos CorruptInputError
		if !errors.As(wantErr, &wantPos) || !errors.As(gotErr, &gotPos) {
			t.Fatalf("%s/pos=%d err=%v, want CorruptInputError %v | 错误类型不一致", name, pos, gotErr, wantErr)
		}
		if gotPos != wantPos || gotErr.Error() != wantErr.Error() {
			t.Fatalf("%s/pos=%d err=%q, want %q | 并行错误偏移不一致", name, pos, gotErr, wantErr)
		}
		if !errors.Is(gotErr, ErrInvalidData) {
			t.Fatalf("%s/pos=%d err=%v, want ErrInvalidData | 错误缺少 ErrInvalidData", name, pos, gotErr)
		}
	}
}

// TestParallelDecodeErrors verifies invalid data in every chunk region keeps the serial partial
// count and absolute error position, and that short buffers keep the serial error contract. |
// TestParallelDecodeErrors 验证每个分块区域内的非法数据都保持串行部分字节数与绝对错误位置，且
// 短缓冲区保持串行错误语义。
func TestParallelDecodeErrors(t *testing.T) {
	src := randomBytes(300 << 10)
	variants := []struct {
		name string
		e    *Encoding
	}{
		{"std", StdEncoding}, {"raw-std", RawStdEncoding},
		{"url", URLEncoding}, {"raw-url", RawURLEncoding},
	}
	for _, v := range variants {
		enc := make([]byte, v.e.EncodedLen(len(src)))
		v.e.Encode(enc, src)
		positions := []int{0, 1, 4, len(enc) / 4, len(enc) / 2, 3 * len(enc) / 4, len(enc) - 4, len(enc) - 1}
		for _, pos := range positions {
			bad := append([]byte(nil), enc...)
			bad[pos] = '!'
			checkParallelDecodeError(t, v.name, pos, v.e, bad, 3)
		}
		short := make([]byte, v.e.DecodedLen(len(enc))-1)
		if _, err := v.e.decodeParallel(short, enc, 0); !errors.Is(err, ErrShortBuffer) {
			t.Fatalf("%s short buffer error = %v, want ErrShortBuffer | 短缓冲应返回 ErrShortBuffer", v.name, err)
		}
	}
}

// TestParallelDecodePaddingAtChunkBoundary verifies a padding group ending exactly on a non-final
// chunk boundary still reports the trailing-data error at the same absolute offset as the serial
// decoder. | TestParallelDecodePaddingAtChunkBoundary 验证恰好结束于非末尾分块边界的填充组仍以
// 与串行解码器相同的绝对偏移报告填充后残余数据错误。
func TestParallelDecodePaddingAtChunkBoundary(t *testing.T) {
	// Two equal chunks of per*4 characters. The first payload length is 3*per-2 so its padded
	// encoding is exactly 4*per characters and ends in "==". | 两个长度均为 per*4 字符的分块。
	// 第一段载荷长度为 3*per-2，其带填充编码恰好为 4*per 字符并以 "==" 结尾。
	const per = (parallelMinBytes / 8)
	part1 := StdEncoding.EncodeToString(randomBytes(3*per - 2))
	part2 := StdEncoding.EncodeToString(randomBytes(3 * per))
	src := append([]byte(part1), []byte(part2)...)
	if len(src) != 2*4*per || len(part1) != 4*per {
		t.Fatalf("test setup: src=%d part1=%d | 测试数据长度不符合预期", len(src), len(part1))
	}
	checkParallelDecodeError(t, "padding-boundary", len(part1), StdEncoding, src, 2)
}

// TestParallelDecodeCRLFFallsBack verifies line-wrapped input matches the
// serial decoder, which ignores CR/LF. | TestParallelDecodeCRLFFallsBack 验证按行
// 折行的输入与忽略 CR/LF 的串行解码一致。
func TestParallelDecodeCRLFFallsBack(t *testing.T) {
	src := randomBytes(300 << 10)
	enc := StdEncoding.EncodeToString(src)
	var wrapped bytes.Buffer
	for i := 0; i < len(enc); i += 76 {
		end := i + 76
		if end > len(enc) {
			end = len(enc)
		}
		wrapped.WriteString(enc[i:end])
		wrapped.WriteString("\r\n")
	}
	out := make([]byte, StdEncoding.DecodedLen(wrapped.Len()))
	n, err := StdEncoding.decodeParallel(out, wrapped.Bytes(), 0)
	if err != nil || n != len(src) || !bytes.Equal(out[:n], src) {
		t.Fatalf("CRLF decode: n=%d err=%v | CRLF 解码结果不一致", n, err)
	}
}

// TestPlanDecodeChunksRejectsNonAdditiveDecodedLen verifies the parallel decoder
// does not slice past dst when a backend's DecodedLen reserves a per-call
// margin, as cristalhq does. | TestPlanDecodeChunksRejectsNonAdditiveDecodedLen
// 验证后端 DecodedLen 每次调用都预留余量时，并行解码不会越过 dst 切片。
func TestPlanDecodeChunksRejectsNonAdditiveDecodedLen(t *testing.T) {
	const total = 349527
	src := make([]byte, total)
	dst := make([]byte, total*6/8)

	nonAdditive := func(n int) int { return n/4*3 + 1 }
	if _, ok := planDecodeChunks(src, dst, 4, nonAdditive); ok {
		t.Fatal("non-additive DecodedLen must fall back to serial | 非可加 DecodedLen 必须回退串行")
	}

	additive := func(n int) int { return n * 6 / 8 }
	chunks, ok := planDecodeChunks(src, dst, 4, additive)
	if !ok {
		t.Fatal("additive DecodedLen must plan | 可加 DecodedLen 应能分块")
	}
	sum := 0
	for _, c := range chunks {
		sum += len(c.dst)
	}
	if sum != len(dst) {
		t.Fatalf("planned %d decoded bytes, want %d | 规划输出 %d 字节，期望 %d", sum, len(dst), sum, len(dst))
	}
}
