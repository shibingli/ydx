# ydx/waf vs Coraza 性能与兼容性基准

[`github.com/shibingli/ydx/waf`](../../waf) 是基于自研 SecLang 引擎的 WAF。本模块在同一
`net/http` 请求路径上对比 `ydx/waf v0.1.2` 与 Coraza `v3.8.1`，并验证 OWASP CRS 4.29.0
全量规则下的检测一致性。组件模块本身不依赖 Coraza 或任何基准专用库。

## 环境与方法

| 项 | 值 |
|---|---|
| CPU | Intel Core i9-10980HK，8 核 / 16 线程 |
| 系统 | Windows 11 Pro for Workstations；WSL Ubuntu 24.04 |
| Go | 1.27.3 |
| 规则集 | OWASP CRS 4.29.0 全量规则（严格模式） |
| 对照 | Coraza v3.8.1 |
| 请求路径 | 两个引擎均通过各自的 `net/http` 中间件；响应写入空 `ResponseWriter` |
| 采样 | `-benchtime=1s -count=5`，benchstat 中位数 |

默认使用 [`testdata/rules.conf`](testdata/rules.conf) 中的内嵌规则，便于无外部数据运行测试与
快速基准。设置 `YDX_WAF_CRS_DIR` 后改用完整 CRS 规则。

## 运行

```bash
cd benchmarks/waf

# 内嵌规则：兼容性测试 + 基准
GOWORK=off go test ./...
GOWORK=off go test -run '^$' -bench . -benchmem -count=5

# 完整 OWASP CRS 4.29.0
YDX_WAF_CRS_DIR=/path/to/coreruleset GOWORK=off go test ./...
YDX_WAF_CRS_DIR=/path/to/coreruleset GOWORK=off go test \
  -run '^$' -bench 'Benchmark(BenignGET|AttackGET|BenignPOST|AttackPOST|ParallelBenignGET|SequentialBenignGET|Build)$' \
  -benchmem -count=5 -benchtime=1s

# 汇总
benchstat results/waf-v0.1.2-linux-i9-10980hk.txt
```

Windows PowerShell 设置环境变量：`$env:YDX_WAF_CRS_DIR='E:\coreruleset'`。

## 性能结果（完整 CRS 4.29.0）

`ydx` 列为默认自动并行；`ydx 顺序` 为 `ParallelWorkers: 1`，用于与 Coraza 的单事务执行路径
做同条件对比。绝对值受 CPU 频率、后台负载与 WSL 调度影响，同一机器多次运行有 ±10–20% 波动；
相对倍数稳定在 3–5 倍。

| 场景 | ydx (Windows) | Coraza (Windows) | 倍数 | ydx (Linux) | Coraza (Linux) | 倍数 |
|---|---:|---:|---:|---:|---:|---:|
| 善意 GET | 180.3 µs | 698.9 µs | 3.9× | 222.2 µs | 671.6 µs | 3.0× |
| 善意 GET（顺序） | 216.7 µs | 761.6 µs | 3.5× | 152.1 µs | 613.5 µs | 4.0× |
| SQLi GET | 121.1 µs | 594.8 µs | 4.9× | 113.3 µs | 561.2 µs | 5.0× |
| 善意表单 POST | 205.4 µs | 907.7 µs | 4.4× | 182.9 µs | 840.0 µs | 4.6× |
| SQLi 表单 POST | 137.5 µs | 691.9 µs | 5.0× | 123.3 µs | 666.9 µs | 5.4× |
| 并发善意 GET | 36.16 µs | 150.1 µs | 4.2× | 29.35 µs | 138.1 µs | 4.7× |

### 每请求内存分配

| 场景 | ydx | Coraza | 差异 |
|---|---:|---:|---:|
| 善意 GET | 5.82 KiB / 187 allocs | 174.1 KiB / 2932 allocs | 字节约 30×，分配次数约 15.7× |
| SQLi GET | 7.07 KiB / 140 allocs | 119.3 KiB / 2709 allocs | 字节约 17×，分配次数约 19× |
| 善意 POST | 7.36 KiB / 228 allocs | 255.6 KiB / 3286 allocs | 字节约 35×，分配次数约 14× |
| SQLi POST | 8.33 KiB / 162 allocs | 197.3 KiB / 2915 allocs | 字节约 24×，分配次数约 18× |
| 并发 GET | 5.82 KiB / 187 allocs | 177.0 KiB / 2932 allocs | 字节约 30×，分配次数约 15.7× |

### 规则构建

| 平台 | ydx | Coraza |
|---|---:|---:|
| Windows | 175.0 ms / 100.9 MiB / 1.006M allocs | 138.4 ms / 78.62 MiB / 719.6k allocs |
| Linux | 287.2 ms / 100.8 MiB / 1.006M allocs | 379.6 ms / 78.86 MiB / 721.9k allocs |

构建耗时受文件系统、CPU 频率与后台负载影响较大，两种平台上的排序会反转。`ydx` 的构建分配
约多 28%，主要来自 `regexpx.Warm()` 启动预热；这是启动期一次性成本，用于消除首个请求的 DFA
构建尖峰。稳态请求的 CPU 与内存收益远大于该成本。

## 兼容性结果

完整 CRS 4.29.0 严格模式加载：

- `ydx/waf`：703 个编译规则节点（包含链式子规则）
- Coraza：660 条顶层规则
- 双方均加载同一套 `crs-setup.conf` 与 `rules/*.conf`，无解析错误或跳过

共享载荷集共 59 个：9 个善意请求，50 个攻击请求，覆盖 SQLi、XSS、LFI、RCE、PHP 注入、
RFI、CRLF、Scanner UA、Shellshock、Log4Shell、Java 类加载、XXE、SSTI、表单/JSON/multipart。

| 平台 | 状态码完全一致 | 双方拦截 | 双方放行 | ydx 单独拦截 |
|---|---:|---:|---:|---:|
| Linux | **59/59** | 47 | 12 | 0 |
| Windows | 56/59 | 44 | 12 | 3 |

Windows 的 3 个差异全部是 **ydx 拦截、Coraza 放行**：`lfi-var-log`、`rce-cat`、`rce-bash`。
原因是 Coraza 的 `normalizePath` / `normalizePathWin` 在 Windows 上通过 `filepath.Clean`
把 `/` 转成 `\`，导致 CRS 数据文件中的 `var/log`、`etc/passwd`、`dev/tcp` 特征无法命中；
Linux 上同一批请求完全一致。测试对这三个已知差异显式记录并继续，其他任何差异都会失败。

在集成测试过程中，对比还发现并修复了两个 CRS 兼容问题，已包含在 `waf v0.1.2`：

- 跨阶段 `SecMarker`/`skipAfter` 会错误跳过后续文件的 phase 1 规则，导致 Scanner UA 与
  Shellshock 漏报；
- `@pm`/`@pmFromFile` 未按 ModSecurity/Coraza 语义做大小写不敏感匹配。

## 结果文件

- [`results/waf-v0.1.2-windows-i9-10980hk.txt`](results/waf-v0.1.2-windows-i9-10980hk.txt)
- [`results/waf-v0.1.2-windows-benchstat.txt`](results/waf-v0.1.2-windows-benchstat.txt)
- [`results/waf-v0.1.2-linux-i9-10980hk.txt`](results/waf-v0.1.2-linux-i9-10980hk.txt)
- [`results/waf-v0.1.2-linux-benchstat.txt`](results/waf-v0.1.2-linux-benchstat.txt)
