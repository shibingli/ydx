# ydx/wal/zstd

`ydx/wal` 的 Zstandard 记录级压缩实现（codec ID = 2）。独立 Go 模块，不依赖
`wal` 模块，可在 `wal` 发布前独立构建与测试。

- 模块路径：`github.com/shibingli/ydx/wal/zstd`
- 包名：`zstd`
- 依赖：`github.com/klauspost/compress`（纯 Go、无 cgo）
- 并发：`Codec` 内部池化编码器/解码器，可被 writer 与多个 Reader 并发调用
- 内存边界：解码器 `WithDecoderMaxMemory(1 GiB)`，解压输出只写入调用方缓冲

## 用法

```go
import (
    "github.com/shibingli/ydx/wal"
    "github.com/shibingli/ydx/wal/zstd"
)

w, err := wal.Open(dir, wal.WithCompression(wal.Compression{
    Active:   zstd.CodecID,
    Codecs:   []wal.Codec{zstd.New(3)},
    MinBytes: 1 << 10,
}))
```

`zstd.New(level)` 接受标准 zstd 1..22 级别；超出范围使用默认级别 3。
压缩后不小于原文时，`wal` 自动存原文。读取端必须注册 codec ID 2，否则返回
`wal.ErrCodecMismatch`，不会把“缺少依赖”误判为文件损坏。

## 测试

```bash
GOWORK=off go build ./... && GOWORK=off go vet ./...
GOWORK=off go test ./... -race
```

本模块的测试用结构化接口断言 `wal.Codec` 契约，不 import `wal`，因此 CI 不需要
先发布新的 `wal` 标签。

## 许可证

Apache-2.0。`klauspost/compress` 为 BSD-3-Clause。
