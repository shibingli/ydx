// Package zstd implements the ydx/wal Codec interface with Zstandard.
// | Package zstd 使用 Zstandard 实现 ydx/wal 的 Codec 接口。
//
// The package has no dependency on the wal module: its methods satisfy
// wal.Codec structurally, so this module can be built and tested independently
// of the published wal version. Register it with wal.WithCompression:
// | 本包不依赖 wal 模块：其方法在结构上满足 wal.Codec，因此本模块可以独立于
// 已发布的 wal 版本构建与测试。通过 wal.WithCompression 注册：
//
//	w, err := wal.Open(dir, wal.WithCompression(wal.Compression{
//		Active:  zstd.CodecID,
//		Codecs:  []wal.Codec{zstd.New(3)},
//		MinBytes: 1024,
//	}))
//
// The wal format reserves codec IDs 0..2; Zstandard uses ID 2. The codec pools
// encoders and decoders, bounds decoder memory at the format's 1 GiB hard
// limit, and writes decompressed output only into the caller's buffer. |
// wal 格式保留 codec ID 0..2；Zstandard 使用 ID 2。codec 池化编码器与解码器，
// 解码内存以格式 1 GiB 硬上限为界，解压输出只写入调用方缓冲。
//
// # Native Go usage | 原生 Go 用法
//
//	codec := zstd.New(3)
//	if codec.ID() != zstd.CodecID {
//		panic("codec id mismatch")
//	}
//	compressed, err := codec.Compress(nil, plain)
//	out := make([]byte, len(plain))
//	plain2, err := codec.Decompress(out, compressed)
//
// The Codec is safe for concurrent Compress/Decompress calls. |
// Codec 可安全并发调用 Compress/Decompress。
package zstd
