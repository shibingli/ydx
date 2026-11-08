package zstd

import (
	"bytes"
	"io"
	"sync"

	kzstd "github.com/klauspost/compress/zstd"
	"github.com/shibingli/ydx/errs"
)

// CodecID is the on-disk codec identifier reserved for Zstandard. | CodecID 是
// Zstandard 预留的磁盘 codec 标识。
const CodecID byte = 2

// maxDecodedSize mirrors the wal format's 1 GiB hard limit and bounds decoder
// memory against malicious frames. | maxDecodedSize 对应 wal 格式的 1 GiB 硬
// 上限，并限制解码器内存以防御恶意帧。
const maxDecodedSize = 1 << 30

// Sentinel errors returned by the codec. | codec 返回的哨兵错误。
var (
	// ErrCodecUnavailable reports a codec instance that could not be created. |
	// ErrCodecUnavailable 表示 codec 实例创建失败。
	ErrCodecUnavailable = errs.New("zstd: codec unavailable | zstd：编解码器不可用")
	// ErrCorrupt reports a malformed or truncated Zstandard frame. | ErrCorrupt
	// 表示 Zstandard 帧损坏或被截断。
	ErrCorrupt = errs.New("zstd: corrupt frame | zstd：帧损坏")
	// ErrTooShort reports a destination smaller than the declared plaintext. |
	// ErrTooShort 表示目标缓冲小于声明的明文长度。
	ErrTooShort = errs.New("zstd: destination is too short | zstd：目标缓冲过短")
	// ErrTooLarge reports a declared plaintext above 1 GiB. | ErrTooLarge 表示
	// 声明明文超过 1 GiB。
	ErrTooLarge = errs.New("zstd: decoded size exceeds 1 GiB | zstd：解码大小超过 1 GiB")
)

// Codec is a pooled Zstandard encoder/decoder pair. It is safe for concurrent
// use; each pooled instance is used by one goroutine at a time. | Codec 是池化
// 的 Zstandard 编解码器对，并发安全；每个池化实例同一时刻只被一个协程使用。
type Codec struct {
	enc   sync.Pool
	dec   sync.Pool
	level kzstd.EncoderLevel
}

// New returns a Zstandard codec. Levels follow the standard zstd 1..22 scale;
// values outside that range select the default level. | New 返回 Zstandard
// codec。级别使用标准 zstd 1..22；超出范围选择默认级别。
func New(level int) *Codec {
	if level < 1 || level > 22 {
		level = 3
	}
	c := &Codec{level: kzstd.EncoderLevelFromZstd(level)}
	c.enc.New = func() any {
		enc, err := kzstd.NewWriter(nil,
			kzstd.WithEncoderLevel(c.level),
			kzstd.WithEncoderConcurrency(1),
			kzstd.WithEncoderCRC(false),
		)
		if err != nil {
			return nil
		}
		return enc
	}
	c.dec.New = func() any {
		dec, err := kzstd.NewReader(nil,
			kzstd.WithDecoderConcurrency(1),
			kzstd.WithDecoderLowmem(true),
			kzstd.WithDecoderMaxMemory(maxDecodedSize),
		)
		if err != nil {
			return nil
		}
		return dec
	}
	return c
}

// ID returns the on-disk codec identifier. | ID 返回磁盘 codec 标识。
func (c *Codec) ID() byte { return CodecID }

// Compress appends the compressed form of src to dst. | Compress 把 src 的压缩
// 结果追加到 dst。
func (c *Codec) Compress(dst, src []byte) ([]byte, error) {
	enc, _ := c.enc.Get().(*kzstd.Encoder)
	if enc == nil {
		return nil, ErrCodecUnavailable
	}
	out := enc.EncodeAll(src, dst)
	c.enc.Put(enc)
	return out, nil
}

// Decompress writes exactly cap(dst) plaintext bytes into dst. | Decompress 向
// dst 精确写入 cap(dst) 字节明文。
func (c *Codec) Decompress(dst, src []byte) ([]byte, error) {
	expected := cap(dst)
	if expected == 0 {
		expected = len(dst)
	}
	if expected > maxDecodedSize {
		return nil, ErrTooLarge
	}
	if cap(dst) < expected {
		return nil, ErrTooShort
	}
	dec, _ := c.dec.Get().(*kzstd.Decoder)
	if dec == nil {
		return nil, ErrCodecUnavailable
	}
	defer c.dec.Put(dec)
	// Bind decoder memory and window to the already validated plaintext length
	// (with the zstd minimum window) so a hostile frame cannot force a large
	// window allocation for a small record. | 把解码器内存与窗口绑定到已校验的
	// 明文长度（不低于 zstd 最小窗口），防止恶意帧用小记录触发大窗口分配。
	bound := uint64(expected)
	if bound < uint64(kzstd.MinWindowSize) {
		bound = uint64(kzstd.MinWindowSize)
	}
	if err := dec.ResetWithOptions(bytes.NewReader(src),
		kzstd.WithDecoderMaxMemory(bound),
		kzstd.WithDecoderMaxWindow(bound),
	); err != nil {
		return nil, errs.Wrap(err, ErrCorrupt)
	}
	out := dst[:expected]
	if _, err := io.ReadFull(dec, out); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, errs.Detail(ErrCorrupt, "decompressed output is shorter than %[1]d | 解压输出短于 %[1]d", expected)
		}
		return nil, errs.Wrap(err, ErrCorrupt)
	}
	var one [1]byte
	n, err := dec.Read(one[:])
	if n != 0 || err != io.EOF {
		return nil, errs.Detail(ErrCorrupt, "decompressed output is longer than %[1]d | 解压输出长于 %[1]d", expected)
	}
	return out, nil
}
