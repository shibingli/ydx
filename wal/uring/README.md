# ydx/wal/uring

`ydx/wal` 的可选 Linux io_uring `IOEngine`。独立 Go 模块，不依赖 `wal` 模块；
其方法在结构上满足 `wal.IOEngine`。

- 模块路径：`github.com/shibingli/ydx/wal/uring`
- 包名：`uring`
- 平台：Linux amd64 / arm64（原始 `io_uring_setup`/`io_uring_enter` + mmap）
- 其它平台：编译为返回 `ErrUnsupported` 的桩
- 依赖：`golang.org/x/sys/unix`、`ydx/errs`；纯 Go、无 cgo、无 liburing
- 默认：**不启用**；`wal` 默认仍是可移植同步引擎

## 用法

```go
if !uring.Supported() {
    log.Fatal("io_uring unavailable")
}
engine, err := uring.New(uring.WithQueueDepth(256))
if err != nil {
    log.Fatal(err)
}
defer engine.Close()

w, err := wal.Open(dir, wal.WithIOEngine(engine))
```

`wal` 的数据写入、显式同步与随机数据读取都会经过该引擎：

- `WriteAt`：`IORING_OP_WRITEV`，`syncData=true` 时追加
  `IORING_OP_FSYNC` + `IORING_FSYNC_DATASYNC`
- `ReadAt`：`IORING_OP_READ`
- `Sync`：`IORING_OP_FSYNC` + `IORING_FSYNC_DATASYNC`

## 语义与边界

- 单 ring 由互斥量保护，所有提交串行化；并发 `ReadAt` 不会并行进入内核。需要
  更高并发时请使用默认引擎或多个 WAL 实例。
- `WithQueueDepth` 默认 256，裁剪到 [2, 4096]；`WithSetupFlags` 可传递额外
  `io_uring_params.flags`（如特权 flag 由调用方自行保证）。
- `Supported()` 只做一次 `io_uring_setup` 探测；容器/seccomp 可能拒绝，返回
  false。
- 引擎不改变 WAL 的持久性、加密、压缩或恢复语义；它只替换位置 I/O 实现。

## 测试

```bash
GOWORK=off go build ./... && GOWORK=off go vet ./...
GOWORK=off go test ./... -race
```

Linux 测试在 `Supported()==false` 时跳过；其它平台运行桩测试。

## 许可证

Apache-2.0。`golang.org/x/sys` 为 BSD-3-Clause。
