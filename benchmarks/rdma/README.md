# benchmarks/rdma — ydx/rdma 跨主机基准

本模块测量 `github.com/shibingli/ydx/rdma` 在真实 RoCE v2 网络上的往返延迟与
SEND 吞吐，并与 gordma v0.3.0、perftest 对照。

## 运行

基准需要两台通过 RDMA 高速网络互联的主机。先在一端运行服务端，再在另一端运行
客户端（两端使用同一测试二进制）：

```bash
# 构建（rdma 模块尚未发布标签时，在仓库外创建临时 go.work）
cat > /tmp/ydx-go.work <<'EOF'
go 1.27.3
use (
    /path/to/ydx/rdma
    /path/to/ydx/benchmarks/rdma
)
EOF
cd /path/to/ydx/benchmarks/rdma
GOWORK=/tmp/ydx-go.work CGO_ENABLED=0 go test -c -tags rdma -o /tmp/rdma-bench.test ./...

# 服务端
YDX_RDMA_ROLE=server YDX_RDMA_ADDR=192.168.2.2:19555 /tmp/rdma-bench.test -test.run TestConnCrossHost -test.v

# 客户端
YDX_RDMA_ROLE=client YDX_RDMA_ADDR=192.168.2.2:19555 /tmp/rdma-bench.test -test.run TestConnCrossHost -test.v
```

可用测试：

| 测试 | 说明 |
|---|---|
| `TestConnCrossHost` | 零拷贝 `Conn` 往返延迟，1000 次，输出 min/avg/p50/p99/max |
| `TestConnBandwidthCrossHost` | 4 KiB 零拷贝 SEND 吞吐，100 万条消息 |
| `TestRawLatencyCrossHost` | 绕过 Conn 的裸 verbs 往返延迟，2000 次 |

未设置 `YDX_RDMA_ROLE`/`YDX_RDMA_ADDR` 时全部跳过。服务端与客户端必须使用同一
端口；建议每个测试使用不同端口以避免残留进程冲突。

## 实测结果

环境：ConnectX-5 Ex、100 GbE、PCIe x4、RoCE v2、GID index 3、路径 MTU 1024、
两台主机经 192.168.2.0/24 直连。

| 指标 | ydx/rdma | gordma v0.3.0 | perftest |
|---|---|---|---|
| 往返延迟 p50 / min | **6.8 µs / 5.7 µs** | 11.0 µs | 2.59 µs（工具报告值） |
| 往返延迟 p99 / max | 8.8–18 µs / 0.15–2 ms | — | — |
| 4 KiB SEND 带宽 | **55.3 Gb/s** | 32.6 Gb/s | 54.7 Gb/s |
| 客户端提交耗时 | 0.52 µs/次 | — | — |

- 三台测试机的 PCIe 链路为 x4，持续带宽上限约 55 Gb/s，因此 100 GbE 链路无法
  跑满；ydx/rdma 已与 perftest 的 C 实现持平，并明显高于 gordma。
- 延迟口径：`TestConnCrossHost` 测量完整往返（客户端 Send 到收到回显），包含
  服务端零拷贝接收、回显发送与网络往返。
- 将网卡 MTU 提高到 4200/9000、路径 MTU 4096 时，本集群出现
  `retry-exceeded`，perftest 同样无法完成；1024 路径 MTU 稳定。提高 MTU 需要
  整条交换路径支持 jumbo frame。

## 说明

- 本模块是基准专用模块，产品模块不得导入。
- `go.mod` 依赖 `github.com/shibingli/ydx/rdma v0.1.0`；标签发布前使用仓库外的
  临时 `go.work` 联调，不提交 `replace`。
