// Package rdma contains cross-host latency and bandwidth benchmarks for
// github.com/shibingli/ydx/rdma. | Package rdma 包含 github.com/shibingli/ydx/rdma
// 的跨主机延迟与带宽基准。
//
// The benchmarks use one server process and one client process on separate
// hosts connected by RoCE v2. Run the same test binary on both sides with
// YDX_RDMA_ROLE=server|client and YDX_RDMA_ADDR=host:port; when the variables
// are unset every test skips. | 基准使用两台主机上的服务端与客户端进程，经
// RoCE v2 互联。在两端运行同一测试二进制，设置 YDX_RDMA_ROLE=server|client
// 与 YDX_RDMA_ADDR=host:port；未设置时所有测试自动跳过。
//
// Measured on ConnectX-5 Ex at 100 GbE with PCIe x4 and path MTU 1024: the
// zero-copy message connection reaches a median round trip of 6.8 µs and a
// 4 KiB SEND throughput of 55.3 Gb/s, compared with gordma v0.3.0 at 11.0 µs
// and 32.6 Gb/s and perftest at 2.59 µs (its reported metric) and 54.7 Gb/s.
// The PCIe x4 link caps sustained bandwidth near 55 Gb/s. | 在 ConnectX-5 Ex、
// 100 GbE、PCIe x4、路径 MTU 1024 上实测：零拷贝消息连接往返中位数 6.8 µs，
// 4 KiB SEND 吞吐 55.3 Gb/s；gordma v0.3.0 为 11.0 µs 与 32.6 Gb/s，perftest
// 为 2.59 µs（工具报告口径）与 54.7 Gb/s。PCIe x4 把持续带宽限制在约 55 Gb/s。
//
// Release gate: the module requires github.com/shibingli/ydx/rdma v0.1.0.
// Until that tag is published, run it through a temporary go.work outside the
// repository that includes both the rdma and benchmarks/rdma modules; never
// commit a replace directive. | 发布门禁：本模块依赖 github.com/shibingli/ydx/rdma
// v0.1.0。在该标签发布之前，请在仓库之外创建临时 go.work，同时纳入 rdma 与
// benchmarks/rdma 两个模块后运行；不得提交 replace。
package rdma
