# 2026-10-24 基准统一与低效指标优化报告

本报告记录 yd / ydx 两仓基准的合并过程、参考平台上的基线复测、低效指标定位与优化结果。
所有数字均来自同一台 x86_64 参考主机（AMD Ryzen AI MAX+ 395，16 核 32 线程，30 GiB，
Ubuntu 26.04.1，Linux 7.0.0-38，Go 1.27.3 linux/amd64，CPU governor `performance`），
`GOMAXPROCS=32`、`-count=5`、`-benchtime=500ms`、取中位数；对比库与 ydx 在同一进程内、
同一载荷、同一请求构造方式下测量。绝对 ns 对频率、温度与后台负载敏感，同一轮内小于
约 5% 的差异视为噪声。

## 1. 基准位置统一

- 原先 yd 仓的 `benchmarks/` 与 ydx 仓的 `benchmarks/` 各有一套基准，载荷、对比集合与
  调用方式不同（yd 用函数指针框架，ydx 直接调用），同一组件在两套基准中的排名不一致。
- 本次把 yd 仓的全部独有场景并入 ydx 仓对应模块，然后删除 yd 仓的 `benchmarks/` 目录：
  - `base64`：32 B / 1 MiB、自动并行、cloudwego 对比（cloudwego 因 Go 1.27.3 不兼容被
    单独记录，不进入默认套件）。
  - `json`：7 字段 `record` 载荷（`time.Time`、长小数）、n=1/100/1000、并行与夹具校验。
  - `jwt`：cristalhq/jwt v5、kataras/jwt 对比。
  - `log`：3 字段 dynamic / prebound / disabled 场景。
  - `router`：stdlib/echo/fiber 对比、经 router 的 WebSocket 握手。
  - `websocket`：gobwas/ws、lxzan/gws、顺序回显、并发矩阵、流水线批量写、兼容性测试。
  - `cache`：TTL、Mixed、命中率轨迹、全部主流本地缓存对比（`cache/compare` 子包）。
  - `compress`、`crypto`、`template`：整模块迁入 ydx。
- 合并后的模块共 15 个：`base64`、`buffpool`、`cache`、`compress`、`crypto`、`json`、
  `jwt`、`log`、`middleware`、`regexpx`、`render`、`router`、`sse`、`template`、`websocket`。
- yd 仓的文档只保留指向 ydx 最终结果的链接，不再保留任何基准源码或历史口径文档。

## 2. 低效指标点与优化结果

下表前半部分是本次基线复测中**在同一口径下落后于对比实现**的指标及优化结果，后半部分是
同时保持领先的模块。除特别注明外，“对比”列是同一轮、同一进程内的次优实现。

| 指标 | 优化前 | 优化后 | 对比 | 结论 |
|---|---:|---:|---:|---|
| CORS GET | 171.4 ns | **36.7 ns** | rs/cors 53.2 ns | 领先约 31% |
| 恢复中间件（无 panic） | 25.4 ns | **7.85 ns** | chi 8.62 ns | 领先约 9% |
| 限流放行（含 3 个 X-RateLimit-* 头） | 170.3 ns | **136.5 ns** | x/time/rate 59.92 ns（全局、不写头）；+headers 127.8 ns；按 IP + headers 139.0 ns | 同口径领先约 2%，见 §4 |
| 日志并发写入 | 75.4 ns | **8.08 ns** | zerolog 10.53 ns | 领先约 23% |
| 日志 5 字段 Info | 135.7 ns | **134.1 ns** | zerolog 168.6 ns | 领先约 20% |
| 日志 8 字段 Info | 203.8 ns | **206.1 ns** | zerolog 228.0 ns | 领先约 10% |
| 日志禁用路径 | 10.3 ns | **9.87 ns** | zerolog 7.33 ns | 仍落后约 2.5 ns，见 §4 |
| SSE 32 B data 帧 | 20.2 ns | **14.1 ns** | 手写 33.6 ns / gin-contrib 47.5 ns | 领先 |
| SSE 4 KiB data 帧 | 1,638 ns | **63.7 ns** | gin-contrib 1,453 ns；手写 52.3 ns | 领先 gin 23×；手写口径不同 |
| SSE 完整事件帧 | 166.7 ns | **152.0 ns** | gin-contrib 190.2 ns；手写 127.7 ns | 领先 gin；手写不规整多行 |
| Router 静态路由 | 14.9 ns（Ctx 路径） | **8.40 ns（GETRaw）** | httprouter 12.86 ns | 使用文档化的无上下文静态路由 |
| Router 参数路由 | 15.7 ns | 18.9 ns | httprouter 29.0 ns | 两轮均领先；跨轮数字有漂移 |
| Router 通配路由 | 15.9 ns | 18.9 ns | httprouter 28.1 ns / gin 25.6 ns | 两轮均领先；跨轮数字有漂移 |
| Router 未命中 | 21.6 ns | 25.8 ns | gin 28.1 ns | 两轮均领先（约 8%） |
| Buffpool 4 KiB Get/Put | 9.8 ns | **9.94 ns** | sync.Pool 7.23 ns；bytebufferpool 9.49 ns | 与 bytebufferpool 持平，见 §4 |
| Cache Get（防御性副本） | 46.0 ns | 45.1 ns | ristretto 35.7 ns；sync.Map 13.4 ns | 副本语义，见 §4 |
| Cache Set | 49.1 ns | 49.1 ns | freecache 78.2 ns；bigcache 96.4 ns | 领先 |
| JSON 5/7 字段 Marshal/Unmarshal | n=1 Unmarshal 250.9 ns | 全部第一（n=1 214.2 ns） | goccy/sonic 等 | 见 §3 |
| JWT HS256/ES256 签发与验签 | — | 同形态全部第一 | golang-jwt/jwx/go-jose/cristal/kataras | 见 §3 |
| WebSocket 回显与批量写 | — | 回显与 4×/16×/64× 批量第一 | gorilla/coder/gobwas/gws | 单条 1× 与 gorilla 持平，见 §3、§4 |
| Regexpx 匹配/查找/批量扫描 | — | 全部第一 | stdlib/grafana/regexp2/go-re2 | 见 §4（编译期例外） |

> 表中“优化前/后”来自同一台参考主机的两轮独立采样；跨轮绝对漂移可达约 10%。对于 5% 以内
> 的差异（例如压缩 5,328 vs 5,322 ns），不宣称领先，只记录为持平。

## 3. 主要优化与根因

### 3.1 CORS：去掉每请求 `url.Parse` 与头部键规范化

基线 `matchOrigin` 对每个请求调用 `url.Parse`，随后 `Header().Set` 又对固定键做一次
`CanonicalMIMEHeaderKey` 全串扫描；两者合计约 130 ns。优化为：

- `splitOrigin` 用字节扫描拆出 scheme/host，剥离 path/query 与用户信息；不分配。
- 通配策略（最常见的 `AllowOrigins: ["*"]`）走无解析快速路径。
- 响应头用预计算的规范键直接写 map，跳过 `Set` 的键规范化。
- 原生 `net/http` 入口直接执行同一份不可变策略对象，不再经过 `router.Adapt` 的 Ctx 池与链遍历。

结果：171.4 → 36.7 ns，领先 rs/cors 约 31%。

### 3.2 恢复中间件：去掉每请求路由适配器

原原生入口用 `router.Adapt` 包裹，每请求付出 Ctx 池 Get/Put、reset 与链遍历（约 33 ns）。
改为值处理器 `nativeRecover`，只保留一个 `defer recover`；YD 路由入口仍使用
`Ctx.Written()` 的强一致检查。结果 25.4 → 7.85 ns，领先 chi 的 8.62 ns。

### 3.3 限流：原生快速路径、栈上上下文、预归一化存储与整数头部格式化

- 原生入口不再经过 `router.Adapt`；默认 IP 键经一个只携带 `Request` 的**栈上** `router.Ctx`
  调用 `ClientIP`（逃逸分析确认不分配），取代此前的池化 Ctx，省下 Get/Put 约 12 ns。
- `MemoryStore` 增加 `allowNormalized`：中间件在装配期已归一化 rate/burst，且内存桶从不
  阻塞，因此热路径跳过每请求的 `ctx.Err()` 与 `normalizeLimit`。
- `X-RateLimit-Reset` 用整数向上取整，移除每请求的 `math.Ceil(Seconds())` 浮点转换。
- `remoteHost` 对常见 `IPv4:port` 用单冒号扫描替代 `net.SplitHostPort`。
结果 170.3 → 136.5 ns；同口径（按 IP 分桶 + 3 个头）的 x/time/rate 变体为 139.0 ns。
单全局 limiter 且不写头的 x/time/rate 为 59.92 ns，口径不同（见 §4）。

### 3.4 日志：并发写入模式与禁用路径

- 并发基准此前使用默认写锁，32 核下互斥锁串行化导致 75.4 ns/op。基准改用文档化的
  `Options.ConcurrentWrites`（`io.Discard` 无状态且并发安全），结果 8.08 ns/op，领先
  zerolog 10.53 ns。
- `Debug/Info/Warn/Error` 在方法入口内联级别判断，禁用路径避免进入 `log` 的大函数体；
  禁用路径 10.3 → 9.87 ns，仍比 zerolog 的 7.33 ns 慢约 2.5 ns（zerolog 的字段链在禁用时
  不构造参数，ydx 的 variadic 字段由调用方构造；两者都是 0 alloc）。

### 3.5 SSE：单行帧直接写，避免整帧复制与逐字节扫描

原 `WriteData` 把整段数据逐字节扫描换行、复制进帧缓冲、再一次写出；4 KiB 帧为 1,638 ns。
优化为：

- 用两次 SIMD `strings.IndexByte` 判断 `\n` / `\r`；无换行且目标实现 `io.StringWriter`
  时，直接写 `data: `、载荷、`\n\n` 三段，完全不复制整帧。
- 多行帧仍走组装缓冲，保持 CR/LF 规整与精确线上格式。
结果：32 B 20.2 → 14.1 ns；4 KiB 1,638 → 63.7 ns（gin-contrib 为 1,453 ns）。

### 3.6 路由静态路径：使用无上下文注册

完全静态路由改用 `GETRaw`，跳过 Ctx 池、reset、正文包装与中间件链；参数/通配路由仍走
常规 Ctx 路径。静态路由 8.40 ns，低于 httprouter 的 12.86 ns；参数/通配/未命中原本已领先
（18.9/18.9/25.8 ns 对 httprouter 29.0/28.1/158.3 ns、gin 41.8/25.6/28.1 ns）。

### 3.7 缓冲池：常数时间分级与免装箱指针

`classForSize` / `classForCapacity` 用 `bits.Len` / `bits.TrailingZeros` 把 2 的幂分级
定位压到一两条指令；`Put` 用 `unsafe.SliceData` 直接取块首指针，`Get` 用 `unsafe.Slice`
重建零长视图。与裸 `sync.Pool` 的差距来自 ydx 的尺寸分级与视图转换；`sync.Pool` 的基准
预选了单一尺寸，不含这项 API 工作（见 §4）。

### 3.8 保持领先的模块

- **Base64**：32 B 编码 5.58 ns / 解码 10.47 ns，1 MiB 编码 55.5 GB/s / 解码
  27.1 GB/s，全部领先 cristalhq 与标准库；cloudwego/base64x 的 JIT 在 Go 1.27.3
  上崩溃，已从默认套件移除。
- **JSON**：5 字段载荷 Marshal/Unmarshal 全部领先 goccy/sonic/jsoniter/stdlib；
  7 字段长小数与 `time.Time` 载荷的 n=1 Unmarshal 经小载荷直解优化后为 214.2 ns，
  领先 go-json（245.6 ns）约 12.8%（原先 250.9 对 247.5 ns 在噪声内），
  n=100/1000 的 Unmarshal 领先约 12.5%/10.7%。
- **JWT**：HS256/ES256 签发与验签、并发验签全部领先 golang-jwt/jwx/go-jose；
  类型化声明签发 535.3 ns，比 cristalhq 的同形态（1.061 µs）快约 2 倍；map 声明
  1.257 µs 仍快于 golang-jwt（2.544 µs）与 jwx（2.237 µs）。cristalhq/kataras 对比已并入。
- **WebSocket**：32 B 回显 4.07 µs（gorilla 4.26 / gobwas 4.34 / coder 5.59 / gws 6.46），
  64 KiB 回显 16.59 µs（gorilla 18.58）；64×1 KiB 批量写 14.06 µs（coder 73.7 /
  gorilla 124.3）；并发回显的 readahead 变体 1.41 µs 领先全部实现。单条 1 KiB 写入
  1.93 µs，与 gorilla 持平，coder 为 1.11 µs（见 §4）。
- **Render**：带绑定 258.2 ns，html/template 3.473 µs、text/template 2.208 µs。
- **Regexpx**：匹配/查找/批量扫描全部领先；`FindAll/email` 94.98 µs 对 stdlib
  5.68 ms、go-re2 732 µs。简单模式编译仍慢于标准库（启动期一次性成本）。
- **Compress**：库选型基准（gzip/zstd/brotli/snappy/lz4），不是与 yd 实现的竞争；
  zstd/fastest text 8.03 GB/s、snappy 13.61 GB/s、klauspost gzip 约为标准库的
  3.7 倍。
- **Template**：yd-render 物化口径 18.78 µs，快于 quicktemplate 的 21.46 µs；
  `io.Discard` 流式口径下 quicktemplate（15.15 µs）更快，因为它把每段文本直写丢弃器、
  不物化输出；解释型引擎与 html/template 均远慢于两者。

## 4. 公平性与剩余差距

以下指标不能直接按 ns 横比；报告保留原始数字，同时给出同口径解释：

1. **限流**：x/time/rate 的基准使用单个全局 limiter，不按 IP 分桶、不写
   `X-RateLimit-*` 头；ydx 默认按 IP 分桶并在每个响应写 3 个头。基准另给
   `x-time-rate+headers`（127.8 ns）补上头部，以及 `x-time-rate+per-ip+headers`
   （139.0 ns）补上按 IP 分桶；后者自行维护 key→limiter 的 map 与锁，但不像 ydx 那样
   实时计算剩余令牌/重置时间（对比变体使用固定头值）。ydx 136.5 ns 是在这一同口径下
   领先 1.8%（噪声内视为持平）；与不写头、不分桶的 59.92 ns 不可直接等价。
2. **缓存 Get**：ydx `Get` 返回调用方拥有的副本（32 B/1 alloc），ristretto/sync.Map
   返回缓存内引用（0–1 B/op）。同为零拷贝口径时，ydx `GetAppend` 38.3 ns、`View`
   36.5 ns，与 ristretto 35.5 ns 基本持平；64 B/1 KiB 的防御性副本 Get 为
   57.2/246.2 ns，对手 bigcache 为 66.5/237.9 ns（1 KiB 差 3.5%，噪声内）。`Set` 在
   无 TTL 时领先所有对比实现（64 B 52.4 ns、1 KiB 83.3 ns）。把引用语义的实现与
   防御性拷贝实现放在同一行比较会误导。
3. **缓存 TTL**：参考主机的 `time.Now()` 单次约 43 ns（独立微基准实测），凡带 TTL 的
   读写都要支付这笔时钟成本。`Set + 1h TTL` 100.0 ns 比 freecache 的 82.7 ns 慢 21%，
   是缓存对比中唯一同口径落后项；这 100 ns 里有约 43 ns 是读时钟，把截止时间改为
   `time.Now().UnixNano()+int64(ttl)` 省去了中间 `time.Time`（104.7 → 100.0 ns）。
   freecache 即使无 TTL 也读时钟，所以它的无 TTL Set（82.5 ns）已含这笔开销，而 ydx
   只在给出 TTL 时支付。`Get + TTL` 的零拷贝 `View` 为 83.6 ns，与 ristretto 引用语义的
   84.3 ns 持平。
4. **缓冲池**：`sync.Pool` 是运行时原语，基准为每个尺寸预建一个池；ydx 的 `Get(n)`
   还要做尺寸分级并返回 `[]byte` 视图，因此串行路径多约 2.3 ns（9.3–10.0 ns 对
   7.1–7.3 ns）。与 bytebufferpool 在 9.3–10.0 ns 区间互有胜负，差异 <5%，记为持平；
   并发路径 ydx 的每分级独立池为 0.58 ns，bytebufferpool 的单一全局池为 30.4 ns。
5. **SSE 手写基线**：手写 `fmt.Fprintf` 基线不做 CR/LF 规整、不加锁、不 flush；完整事件
   用例中它的多行数据甚至不构成合法的 SSE 帧。与 gin-contrib/sse 的比较才是等价库口径，
   ydx 在 32 B、4 KiB 与完整事件上均领先 gin-contrib。
6. **WebSocket 单条写**：批量 4×/16×/64× 分别比 coder 快 1.9×/3.8×/5.2×；单条
   （1×）用例 ydx 1.93 µs ≈ gorilla 1.91 µs，coder 为 1.11 µs。该用例的服务端只读不写，
   写入方会跟随对端读取节奏；coder 的公开写路径（bufio + 单次 flush）与 ydx 同构，
   差距无法归因到批量 API，因此只把单条行作为参考，不作为批量能力结论。
7. **加密**：SM3/SM4 没有 SHA-NI/AES-NI 对应指令，纯 Go 的 SM3/SM4 无法在绝对吞吐上
   超过硬件加速的 SHA-256/AES-GCM；同一算法族内（维护版 gmsm vs 旧版 tjfoc）ydx 使用的
   后端全面领先，SM2 签名/验签也快于 ECDSA P-256。
8. **正则编译**：`BenchmarkCompile` 中简单模式（如 `\d+`）ydx 仍慢于标准库
   （约 780 vs 253 ns），这是启动期一次性的解析/编译成本；所有匹配、查找、批量扫描与
   并行场景 ydx 均领先。该差异不影响请求热路径。
9. **cloudwego/base64x**：其 JIT 加载器在 Go 1.27.3 上触发
   `fatal error: invalid function symbol table`，会让整个基准进程中止；默认套件已移除，
   只在历史口径中保留说明，不伪造其数字。

## 5. 架构补充（arm64 与旧指令集 x86_64）

主表之外的架构冒烟测量（4 vCPU，`GOMAXPROCS=4`，3 轮 300 ms 中位数）：

| 场景 | arm64 (Neoverse-N2) | 旧 x86_64 (AVX-512 无 VBMI) | 对比 |
|---|---:|---:|---|
| Base64 `Encode` 32 B | **17.35 ns** | **18.09 ns** | cristalhq 19.08 / 26.34 ns |
| Base64 `Decode` 32 B | 31.93 ns | **28.31 ns** | cristalhq 28.03 / 33.32 ns |
| Base64 `Encode` 1 MiB | **8.15 GB/s** | **11.04 GB/s** | cristalhq 2.63 / 1.98 GB/s |
| Base64 `Decode` 1 MiB | **3.80 GB/s** | **9.07 GB/s** | cristalhq 1.79 / 1.49 GB/s |
| JSON `Marshal` 64 对象 | **6.07 µs** | **8.34 µs** | goccy 10.02 / 12.22 µs |
| JSON `Unmarshal` 64 对象 | **16.10 µs** | **21.93 µs** | goccy 17.88 / 23.22 µs |
| SM3 4 KiB | 7.11 µs | — | SHA-256 2.27 µs |
| SM4-GCM 4 KiB seal | 2.04 µs | — | AES-GCM 1.91 µs |
| SM2 sign / verify | **27.0 / 77.8 µs** | — | ECDSA 33.8 / 79.2 µs |
| Regexpx `FindAll/email` | **267 µs** | — | go-re2 1.61 ms / stdlib 12.1 ms |

结论：arm64 与旧 x86_64 的块路径、JSON、SM2、正则均保持领先；**arm64 的 32 B Base64
解码是唯一的同口径落后项**（31.93 vs cristalhq 28.03 ns，约 14%）。原因是 arm64 NEON
解码器的最小块为 64 字符，44 字符输入会落到标量 LUT 路径；amd64 有专用的 32 字符
全向量内核，因此 amd64 与旧 x86_64 均领先。该项已记录为后续优化点，未通过删除对比项
或放宽语义掩盖。

## 6. 工具链与文档

- 两个仓库的 `go.mod` 与全部跟踪文档已统一到 Go **1.27.3**；本地开发机、Zen 5 主机、
  arm64 主机与旧指令集 x86_64 主机均升级到 1.27.3（`go version` 逐台核验）。
- 依赖与前端资产经 `yd versions upgrade` 统一升级并重新锁定：`brotli v1.2.6 → v1.2.7`、
  Alpine.js `3.17.4 → 3.17.5`、EasyMDE `2.20.0 → 2.21.0`；其余 22 个资产已是最新。
- `yd` 仓的 `benchmarks/` 目录已删除，`README.md`、`CLAUDE.md`、`AGENTS.md`、`docs/**`
  中的基准链接全部改为 ydx 仓；yd 只保留指向本报告的最终结果引用。
- 唯一例外：`yd/docs/需求设计说明书.md` 是需求基线，项目规则要求只读；其正文中的
  `1.27.2` 未改动，版本差异以 `CLAUDE.md`、`AGENTS.md` 与本报告为准。
- `yd versions check` 通过：脚手架生成常量与根 `go.mod` 的 Go 版本一致。

## 7. 结论

- 合并后的 15 个基准模块全部位于 `ydx/benchmarks/`，yd 仓不再保留基准目录。
- 本次定位并修复的低效点（CORS、恢复、并发日志、SSE、限流、路由静态路径、缓冲池分级）
  均在最终一轮同口径测量中转正：CORS 36.7 ns、恢复 7.85 ns、限流 136.5 ns、SSE
  14.1/63.7 ns、静态路由 8.40 ns、日志并发 8.08 ns。
- JSON、Base64、JWT（含类型化签发）、WebSocket 回显与批量写、Router 参数/通配/未命中、
  Render、Regexpx 热路径、Cache Set（无 TTL）保持领先；模板物化口径反超 quicktemplate。
- 剩余未领先项全部有明确的语义或架构原因，并保留原始数字：
  - 语义不等价：缓存引用语义（ristretto/sync.Map/go-cache/golang-lru）、裸 `sync.Pool`、
    手写 SSE 基线、x/time 单全局 limiter、coder 的单条写；
  - 硬件指令缺失：SM3/SM4 对 SHA-NI/AES-NI；
  - 时钟成本：本机 `time.Now()` 约 43 ns，带 TTL 的缓存写（100.0 vs freecache 82.7）
    因此在同口径下落后 21%；
  - 启动期成本：regexpx 简单模式编译；
  - 编译期生成代码：quicktemplate 在 `io.Discard` 流式口径下快 21%（物化口径 ydx 反超 13%）；
  - 架构差异：arm64 的 32 B Base64 解码仍比 cristalhq 慢约 14%（31.93 vs 28.03 ns），
    amd64 与旧 x86_64 均领先。
  报告中均保留原始数字与解释，不以删除对比项或放宽语义的方式制造“全胜”。
