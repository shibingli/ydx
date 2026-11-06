package wal

import (
	"bytes"
	"compress/flate"
	"fmt"
	"io"
	"sync"

	"github.com/shibingli/ydx/errs"
)

// Codec is one record-level compression algorithm. | Codec 是一种记录级压缩算法。
//
// Compress appends the compressed form of src to dst and returns the result.
// Decompress writes exactly cap(dst) plaintext bytes into dst; it must not
// allocate a larger output buffer. Implementations must be safe for concurrent
// use and must not block, call back into the WAL, or panic. | Compress 把 src
// 的压缩结果追加到 dst 并返回；Decompress 必须把恰好 cap(dst) 字节明文写入
// dst，不得分配更大的输出缓冲。实现必须并发安全、不得阻塞、不得回调 WAL、
// 不得 panic。
type Codec interface {
	ID() byte
	Compress(dst, src []byte) ([]byte, error)
	Decompress(dst, src []byte) ([]byte, error)
}

// Compression configures record-level compression. | Compression 配置记录级压缩。
type Compression struct {
	Active   byte
	Codecs   []Codec
	MinBytes int
}

// enabled reports whether new records should be compressed. | enabled 返回新记录是否应压缩。
func (c Compression) enabled() bool { return c.Active != 0 }

// validate freezes the codec registry and fills defaults. | validate 冻结算法注册表并填充默认值。
func (c *Compression) validate() error {
	if c.MinBytes < 0 {
		return errs.Detail(ErrInvalidOptions, "Compression.MinBytes must not be negative | Compression.MinBytes 不得为负数")
	}
	if c.MinBytes == 0 {
		c.MinBytes = defaultDedupMinBytes
	}
	ids := make(map[byte]struct{}, len(c.Codecs)+1)
	for _, codec := range c.Codecs {
		if codec == nil {
			return errs.Detail(ErrInvalidOptions, "nil compression codec | 压缩算法为 nil")
		}
		id := codec.ID()
		if id == codecNone || id == codecTxnControl || (id >= codecReservedLo && id <= codecReservedHi) {
			return errs.Detail(ErrInvalidOptions, "codec ID %[1]d is reserved | codec ID %[1]d 为保留值", id)
		}
		if _, ok := ids[id]; ok {
			return errs.Detail(ErrInvalidOptions, "duplicate codec ID %[1]d | 重复 codec ID %[1]d", id)
		}
		ids[id] = struct{}{}
	}
	if c.Active != 0 {
		if c.Active == codecTxnControl || (c.Active >= codecReservedLo && c.Active <= codecReservedHi) {
			return errs.Detail(ErrInvalidOptions, "active codec ID %[1]d is reserved | 活动 codec ID %[1]d 为保留值", c.Active)
		}
		if _, ok := ids[c.Active]; !ok {
			if c.Active == codecFlate {
				c.Codecs = append(c.Codecs, FlateCodec(flate.DefaultCompression))
				ids[c.Active] = struct{}{}
			} else {
				return errs.Detail(ErrInvalidOptions, "active codec %[1]d is not registered | 活动 codec %[1]d 未注册", c.Active)
			}
		}
	}
	return nil
}

// lookup returns a registered codec. | lookup 返回已注册的 codec。
func (c Compression) lookup(id byte) (Codec, error) {
	if id == codecNone {
		return nil, nil
	}
	for _, codec := range c.Codecs {
		if codec.ID() == id {
			return codec, nil
		}
	}
	return nil, errs.Detail(ErrCodecMismatch, "codec %[1]d is not registered | codec %[1]d 未注册", id)
}

// codecName returns a diagnostic name. | codecName 返回诊断名称。
func codecName(id byte) string {
	switch id {
	case codecNone:
		return "none"
	case codecFlate:
		return "flate"
	case codecZstd:
		return "zstd"
	case codecTxnControl:
		return "txn-control"
	default:
		return fmt.Sprintf("codec-%d", id)
	}
}

// flateCodec is the built-in stdlib flate codec. | flateCodec 是内置的 stdlib flate 算法。
type flateCodec struct {
	level int
	pool  sync.Pool
}

// FlateCodec returns the built-in flate codec with the given level. Levels
// outside HuffmanOnly..BestCompression select the default level. | FlateCodec
// 返回指定级别的内置 flate 算法；超出 HuffmanOnly..BestCompression 使用默认级别。
func FlateCodec(level int) Codec {
	if level < flate.HuffmanOnly || level > flate.BestCompression {
		level = flate.DefaultCompression
	}
	return &flateCodec{level: level}
}

// ID returns codecFlate. | ID 返回 codecFlate。
func (c *flateCodec) ID() byte { return codecFlate }

// Compress compresses src into dst. | Compress 把 src 压缩进 dst。
func (c *flateCodec) Compress(dst, src []byte) ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(cap(dst))
	w, _ := c.pool.Get().(*flate.Writer)
	if w == nil {
		var err error
		w, err = flate.NewWriter(&buf, c.level)
		if err != nil {
			return nil, errs.Wrap(err, ErrCodecFailure)
		}
	} else {
		w.Reset(&buf)
	}
	if _, err := w.Write(src); err != nil {
		c.pool.Put(w)
		return nil, errs.Wrap(err, ErrCodecFailure)
	}
	if err := w.Close(); err != nil {
		c.pool.Put(w)
		return nil, errs.Wrap(err, ErrCodecFailure)
	}
	c.pool.Put(w)
	return buf.Bytes(), nil
}

// Decompress writes exactly cap(dst) bytes into dst. | Decompress 向 dst 精确写入 cap(dst) 字节。
func (c *flateCodec) Decompress(dst, src []byte) ([]byte, error) {
	expected := cap(dst)
	if expected == 0 {
		expected = len(dst)
	}
	if cap(dst) < expected {
		return nil, errs.Detail(ErrTooShort, "decompression destination capacity %[1]d | 解压目标容量 %[1]d", cap(dst))
	}
	out := dst[:expected]
	r := flate.NewReader(bytes.NewReader(src))
	_, err := io.ReadFull(r, out)
	if err != nil {
		_ = r.Close()
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, errs.Detail(ErrCorrupt, "decompressed output is shorter than %[1]d | 解压输出短于 %[1]d", expected)
		}
		return nil, errs.Wrap(err, ErrCodecFailure)
	}
	var one [1]byte
	if _, err := io.ReadFull(r, one[:]); err != io.EOF {
		_ = r.Close()
		return nil, errs.Detail(ErrCorrupt, "decompressed output is longer than %[1]d | 解压输出长于 %[1]d", expected)
	}
	_ = r.Close()
	return out, nil
}

// safeCompress isolates a user codec panic and converts it into an error. | safeCompress
// 隔离用户 codec 的 panic 并转换为错误。
func safeCompress(codec Codec, dst, src []byte) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			out = nil
			err = errs.Detail(ErrCodecFailure, "codec %[1]d panicked: %[2]v | codec %[1]d 发生 panic：%[2]v", codec.ID(), r)
		}
	}()
	return codec.Compress(dst, src)
}

// safeDecompress isolates a user codec panic and converts it into an error. | safeDecompress
// 隔离用户 codec 的 panic 并转换为错误。
func safeDecompress(codec Codec, dst, src []byte) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			out = nil
			err = errs.Detail(ErrCodecFailure, "codec %[1]d panicked: %[2]v | codec %[1]d 发生 panic：%[2]v", codec.ID(), r)
		}
	}()
	return codec.Decompress(dst, src)
}
