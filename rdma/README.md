# ydx/rdma — 纯 Go 零拷贝 RDMA

`github.com/shibingli/ydx/rdma` 是 ydx 的可独立引用 RDMA 传输模块。它通过
[purego](https://github.com/ebitengine/purego) 在运行时加载 `libibverbs`，
**不需要 cgo**，默认构建为纯 Go 桩实现；启用 `-tags rdma` 后获得完整的
RoCE v1/v2 与 InfiniBand 能力。

- 源码：<https://github.com/shibingli/ydx/tree/main/rdma>
- 协议：Apache-2.0
- Go 版本：1.27.4
- 运行时依赖：`libibverbs.so.1`（RDMA 设备驱动，如 `rdma-core` / MLNX OFED）

## 为什么不是 gordma

gordma 是 cgo 封装，每次 `ibv_post_send` / `ibv_poll_cq` 都要承担 cgo 栈切换
开销。本模块把热路径直接落到 `ibv_context_ops` 的函数指针（这也是 libibverbs
inline 包装的实际路径），并用 purego 的 `SyscallN` 调用，避免了 cgo 转换；
所有批量接口一次调用提交整条工作请求链、一次调用取回多个完成事件。

同机同网实测（ConnectX-5 Ex、PCIe x4、MTU 1024、4 KiB 消息）：

| 指标 | ydx/rdma | gordma v0.3.0 | perftest |
|---|---|---|---|
| 往返延迟（p50 / min） | **5.5 µs / 5.4 µs** | 11.0 µs | 2.59 µs（单程；等价往返约 5.18 µs） |
| 4 KiB SEND 带宽 | **55.1 Gb/s** | 32.6 Gb/s | 54.7 Gb/s |

> perftest 的 `t_avg` 对 SEND 按"往返 / 2"报告，本表 ydx/rdma 为完整往返；
> 因此 5.5 µs 往返约等于 perftest 的 2.59 µs 单程值。三台测试机的 PCIe 链路
> 为 x4，带宽上限约 55 Gb/s，100 GbE 链路无法跑满；55.1 Gb/s 已与 perftest
> 原生 C 实现持平。
>
> 表中数据在早期直接汇编跳板版本测得。为避免在 goroutine 小栈上执行提供方 C
> 代码，当前热路径改为 purego 系统栈跳板；固定调用开销略有增加，部署前应在目标
> 硬件复测。

## 性能实现要点

- **内联发送 + 周期性信号**：小于等于 QP 授予的 `max_inline_data` 的消息使用
  `IBV_SEND_INLINE`，`ibv_post_send` 返回后立即回收发送缓冲区；每 `SQ 深度/2`
  条发送周期性请求一次完成事件，确保 mlx5 等提供方能够回收发送队列空间。
  设备内联上限未知时按 `256 → 128 → 64 → 32 → 16 → 0` 逐个探测并缓存授予值。
- **热路径直调**：`ibv_post_send`、`ibv_post_recv`、`ibv_poll_cq`、`ibv_post_srq_recv`
  直接调用 `ibv_context_ops` 函数指针；C 调用统一经 purego 的系统栈跳板完成，
  避免在 goroutine 的小栈上直接执行提供方代码。
- **批量回收**：接收侧使用 `RecvBuffers` + `ReleaseBatch` 批量补给 RQ，避免每条
  消息一次门铃；发送侧 `SendBatchBuffers` 按 `MaxBatch`/队列深度分次门铃提交
  整批，超过发送池时仍会全部提交。
- **原子错误状态与低频时钟检查**：连接错误用原子指针记录；自旋循环每 1024 次
  才读取一次时钟，降低热路径开销。

## 功能

| 能力 | 说明 |
|---|---|
| 队列对 | RC / UC / UD，含 `Connect` 状态机（INIT → RTR → RTS） |
| 完成队列 | 批量 Poll、共享 CQ、SRQ |
| 内存 | 预注册大页内存池、库拥有 MR、调用方内存注册（MR 持有切片，不使用 Pinner） |
| 发送 | SEND / SEND_WITH_IMM / RDMA WRITE / WRITE_WITH_IMM / RDMA READ / 原子操作 |
| 寻址 | RoCE v1、RoCE v2、原生 InfiniBand；默认自动选择 GID（RoCE v2 > RoCE v1 > IB），IB 提供 LID 时使用本地路由 |
| 批量 | `PostSend` / `PostRecv` 一次提交整链；`CQ.Poll` 一次取回多个完成 |
| 零拷贝 | `Alloc` + `SendBuffer`、`RecvBuffer` + `Release`、`SendBatchBuffers`、`RecvBuffers` + `ReleaseBatch` |
| 连接层 | `Listen` / `Dial`：TCP 控制通道交换 QPN/PSN/GID/MTU 与槽位参数，数据面纯 RDMA；不公布远端 RKey |
| 发行版 | 自动查找 `libibverbs.so.1`/`.so` 与 Debian、Ubuntu、RHEL、SUSE、OFED 常见路径；`Config.VerbsLibrary` 可覆盖 |
| 硬件 | 不绑定厂商：按 sysfs 自动发现设备与活动端口；GID 类型缺失时按链路层与地址推断；支持 Mellanox、Broadcom、Intel、Marvell 等标准 ibverbs 提供方 |
| 无 cgo | `CGO_ENABLED=0` 可构建、可运行 |

## 构建

```bash
# 纯 Go 桩（默认，无 rdma 标签）
GOWORK=off CGO_ENABLED=0 go build ./...

# 真实 RDMA（Linux + 64 位 + rdma 标签）
GOWORK=off CGO_ENABLED=0 go build -tags rdma ./...
```

没有 `rdma` 标签时所有入口返回 `ErrUnsupported`；有标签但运行时缺少
`libibverbs` 时 `Supported()` 返回 false，`Open` 返回带路径细节的
`ErrUnsupported`。

## 快速开始：消息连接

```go
cfg := rdma.DefaultConnConfig()

// 服务端
ln, err := rdma.Listen("192.168.2.2:2030", cfg)
if err != nil {
    return err
}
defer ln.Close()
conn, err := ln.Accept()
if err != nil {
    return err
}
defer conn.Close()

// 零拷贝接收
buf, n, err := conn.RecvBuffer()
if err != nil {
    return err
}
process(buf.Bytes()[:n])
_ = conn.Release(buf)
```

```go
// 客户端
conn, err := rdma.Dial("192.168.2.2:2030", cfg)
if err != nil {
    return err
}
defer conn.Close()

buf, err := conn.Alloc(len(msg))
if err != nil {
    return err
}
copy(buf.Bytes(), msg)
return conn.SendBuffer(buf, len(msg))
```

- `Send` / `Recv` 是复制便利接口；`Alloc`/`SendBuffer` 与
  `RecvBuffer`/`Release` 是零拷贝路径。
- `SendBatch` / `SendBatchBuffers` 与 `RecvBuffers` / `ReleaseBatch` 用于吞吐。
- 一个 `Conn` 不得被多个协程同时使用；每个工作协程使用独立 `Conn`。

## 快速开始：底层 verbs

```go
cfg := rdma.DefaultConfig()
dev, err := rdma.Open(cfg)
if err != nil {
    return err
}
defer dev.Close()

pool, err := dev.NewPool(rdma.PoolConfig{Slots: 1024, SlotSize: 4096})
if err != nil {
    return err
}
defer pool.Close()

cq, err := dev.NewCQ(2048)
if err != nil {
    return err
}
defer cq.Close()

qp, err := dev.NewQP(rdma.DefaultQPConfig(cq))
if err != nil {
    return err
}
defer qp.Close()

local := qp.LocalInfo(0x1234)
// 通过任意控制通道与对端交换 ConnectInfo
if err := qp.Connect(local, remote); err != nil {
    return err
}

buf, _ := pool.Acquire()
_, err = qp.PostRecv([]rdma.RecvWR{{
    WRID: 1, Addr: buf.Addr(), Length: uint32(buf.Len()), LKey: buf.LKey(),
}})
```

## 性能建议

- 热路径使用忙轮询。`RecvBuffer`/`Alloc` 在无进展时先自旋 4096 次再让出处理器。
  对最低延迟，调用 `runtime.LockOSThread` 并用 `taskset` 固定核心。
- 每连接独立 `Conn`；吞吐场景用 `SendBatchBuffers` 与 `RecvBuffers`/`ReleaseBatch`。
- `NewMR`/`NewPool` 优先 `MAP_HUGETLB` 2 MiB 大页，失败回退透明大页。部署时
  预留 `vm.nr_hugepages`。
- 路径 MTU 自动取端口活动 MTU 与对端 MTU 的较小值。提高 MTU 需要整条交换路径
  支持 jumbo frame，否则会出现 `retry-exceeded`；本测试集群上 4096 路径 MTU
  不可用，1024 稳定。
- 原子操作取回的原始值由设备按**网络字节序**写回本地缓冲区，使用
  `encoding/binary.BigEndian` 读取；`compare_add`/`swap` 操作数按主机序传入。
- Dev 与 CQ/QP/MR/Pool 的关闭顺序：先 QP，再 CQ/MR/Pool，最后 Device。

## 测试

```bash
# 本机单元测试（无 rdma 标签）
GOWORK=off go test ./...

# 设备集成测试（Linux + rdma 标签 + 真实设备）
GOWORK=off CGO_ENABLED=0 go test -tags rdma ./...

# 跨主机延迟 / 带宽在 benchmarks/rdma 模块中（两台主机分别执行）
cd benchmarks/rdma
YDX_RDMA_ROLE=server YDX_RDMA_ADDR=192.168.2.2:19555 go test -tags rdma -run TestConnCrossHost -v
YDX_RDMA_ROLE=client YDX_RDMA_ADDR=192.168.2.2:19555 go test -tags rdma -run TestConnCrossHost -v
```

`TestConnCrossHost`、`TestConnBandwidthCrossHost` 与 `TestRawLatencyCrossHost`
位于 `benchmarks/rdma`，未设置 `YDX_RDMA_ROLE`/`YDX_RDMA_ADDR` 时自动跳过。
本模块的 `-tags rdma` 集成测试需要真实 RDMA 设备；没有设备时不要使用该标签运行。

集成测试与基准支持以下可选环境变量，用于在任意厂商硬件上指定设备；全部未设置
时自动发现第一个带活动端口的设备，并自动选择最佳 GID：

| 变量 | 作用 |
|---|---|
| `YDX_RDMA_DEVICE` | 设备名，如 `mlx5_0`、`bnxt_re0`、`irdma0` |
| `YDX_RDMA_PORT` | 端口号，默认 1 |
| `YDX_RDMA_NETDEV` | RoCE 网卡名过滤，如 `enp101s0f0np0` |
| `YDX_RDMA_GID_INDEX` | 显式 GID 表索引；默认自动 |
| `YDX_RDMA_GID_TYPE` | `auto`（默认）/ `ib` / `rocev1` / `rocev2` |
| `YDX_RDMA_VERBS` | libibverbs 共享库路径覆盖 |

```bash
GOWORK=off CGO_ENABLED=0 go test -tags rdma ./...
YDX_RDMA_DEVICE=bnxt_re0 GOWORK=off CGO_ENABLED=0 go test -tags rdma ./...
```

## 平台与限制

- 仅 Linux、64 位（amd64/arm64）；其它平台编译桩实现。
- 运行时需要可用的 RDMA 设备与 `libibverbs`；`Supported()` 检查加载结果。
- 未指定 `Config.Device` 时按设备名排序选择第一个带活动端口的设备；同时存在
  IB 与 RoCE 网卡的混合主机应显式设置 `Device`/`NetDev`。
- `MaxSGE` 为 4；更大分散聚集请求需拆分为多个工作请求。
- 单条消息上限为连接配置的 `SlotSize`；大消息请增大 `SlotSize` 或使用 RDMA
  WRITE/READ 直接读写对端注册内存。`Conn.Close` 可与阻塞中的收发并发调用，其余
  数据面方法仍须单协程串行使用；已交给调用方的零拷贝缓冲区必须在 Close 前消费并
  释放。`QP`/`CQ`/`SRQ`/`AH` 的 `Close` 不得与同一对象上的投递或轮询并发调用。
- 握手后发送窗口会按对端公布的接收槽位数收缩，避免在途 SEND 超过对端 RQ。
  接收应用仍须及时 `Release`/`ReleaseBatch`；否则对端会收到 RNR NAK。默认
  `RNRRetry=7` 表示无限重试，长时间不释放会表现为延迟升高或发送超时。
- `Listen`/`Dial` 的 TCP 控制握手不提供认证或加密，控制面参数可被伪造导致拒绝
  服务；数据面内存池仅授予本地写权限，不公布 RKey。不可信网络应使用
  IPsec/MACsec 或受保护的隧道。
- `Device.Close` 在仍有 QP/CQ/SRQ/AH/MR/Pool 时会返回 `ErrBusy`；请按
  QP → CQ/SRQ/AH → MR/Pool → Device 的顺序关闭。
- `Listener.Close` 会关闭所有已接受的 Conn；调用方必须先停止使用这些 Conn 及
  其已取出的零拷贝缓冲区，再关闭监听器。
