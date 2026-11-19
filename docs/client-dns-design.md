# ydx/client HTTP DNS 与 DNSSEC 支持设计

日期：2026-11-19
状态：方案复审后待评审
范围：`github.com/shibingli/ydx/client` 及其可选嵌套模块

## 1. 背景与目标

系统 DNS 在部分网络环境中会被污染或劫持。云厂商通常提供 HTTP DNS（JSON/DoH）
和 DNSSEC 能力，用于提升解析结果的完整性与可用性。本设计为 `client` 增加：

- 可插拔的 DNS Resolver 抽象；
- RFC 8484 DNS-over-HTTPS；
- 通用厂商 HTTP DNS 适配；
- 委托型 DNSSEC（验证型 DoH 的 AD 位）与可选本地 DNSSEC 验证；
- 与现有 `AccessPolicy`、拨号 IP 固定、Host 池、健康检查、镜像、SSE、转发路径的统一集成。

目标不是替换系统解析器，而是让使用方可以按域名/规则选择安全解析路径，同时保持
默认行为、兼容性和性能不退化。

## 2. 范围与非目标

### 范围

- 解析 A/AAAA，展开 CNAME；返回 TTL 与安全状态。
- DoH（RFC 8484）、厂商 HTTP DNS JSON、DoT 作为后续可选能力。
- DNSSEC 委托验证与可选本地验证。
- 有界缓存、singleflight、失败策略、指标与日志。
- 与内置 `http.Transport` 的拨号集成；自定义 Transport/代理的安全语义。

### 非目标

- 不实现完整 DNS 递归解析器；Resolver 只做查询与验证。
- 不改变默认系统 DNS 行为。
- 不把云厂商 SDK、`miekg/dns` 或重型框架引入核心模块。
- 不实现 DNS SRV/Consul/Etcd 服务发现。
- 不承诺 DNSSEC 提供保密性；保密性由 DoH/DoT 提供。
- 不实现 ECH/SVCB/HTTPS RR；后续可单独评估。
- 不在核心模块内实现本地 DNSSEC 验证；放在可选模块。
- 不实现任意 DoH 重定向、HTTP 明文 DoH、或自动信任系统代理。

## 3. 威胁模型与信任边界

| 威胁 | 防护 |
|---|---|
| 本地/运营商 DNS 投毒 | DoH/DoT 的 TLS 完整性；DNSSEC |
| 伪造 DNS 响应 | DNSSEC RRSIG/DS 链；DoH 的 TLS + 问题区校验 |
| DoH endpoint 被劫持 | 固定 bootstrap IP + 严格 TLS + SPKI pin |
| 恶意/被攻破的 DoH 解析器 | pin、最小信任、AD 只作为该解析器的断言 |
| DNS rebinding | 解析一次、校验 IP、直接拨号该 IP，不二次解析 |
| 代理绕过本地 DNS 策略 | 严格模式代理失败关闭 |
| 厂商 HTTP DNS 响应伪造 | 厂商签名校验 + TLS；`TransportAuthenticated` 与 DNSSEC 分离 |
| 查询名泄露 | DoH/DoT 加密；日志默认脱敏；ECS 默认关闭 |
| DNSSEC 验证 DoS | 响应大小、算法、NSEC3 迭代、签名验证预算上限 |

信任模型必须明确：

- **DoH 信任**来自 endpoint 的 TLS 证书/固定 pin，而不是 bootstrap IP 本身。
- **委托 DNSSEC** 信任来自“可信验证型 DoH Resolver”的 AD 位；AD 不是密码学证明，
  只是该解析器的断言。必须同时校验 DoH 通道与 pin。
- **本地 DNSSEC** 信任来自配置的根信任锚；信任锚轮换需要单独策略。
- **厂商 HTTP DNS** 的签名只证明响应来自该厂商，不等同于 DNSSEC 验证。

## 4. 方案复审：上一版方案的遗漏与修正

| # | 上一版问题 | 修正 |
|---|---|---|
| 1 | 用一个 `Authenticated` 布尔值同时表示 TLS/厂商签名和 DNSSEC | 拆分为 `TransportAuthenticated` 与 `DNSSECState`（Secure/Insecure/Bogus/Indeterminate） |
| 2 | `RequireAuthenticated` 语义模糊 | 拆分为 `RequireSecureTransport`、`RequireDNSSEC`、`RequireSecureAll` 三种策略 |
| 3 | 未区分“未签名（Insecure）”与“签名错误（Bogus）” | Insecure 按策略可放行，Bogus 严格模式必须失败；默认不把 Bogus 当 Insecure |
| 4 | 全局单一 Resolver 会破坏企业内网/VPN 分裂视图 | 增加按规则/Host/后缀路由；私有域可显式使用系统解析器 |
| 5 | 忽略 hosts 文件、search domain/ndots、`.local`/mDNS | Resolver 路由中增加 hosts 覆盖、搜索域和本地域名绕过策略 |
| 6 | DoH 引导只提 bootstrap IP | 明确 bootstrap 信任边界、禁止递归、固定 SNI/pin、独立代理与连接池 |
| 7 | DoH 响应校验只提事务 ID | DoH 的 ID 可能为 0；以问题区/QR/RCode/Content-Type/大小/CNAME 链为主，ID 仅作辅助 |
| 8 | 未限制 DoH 重定向、Content-Type、响应体大小 | 默认拒绝重定向；强制 2xx + `application/dns-message`；设置响应上限 |
| 9 | 未考虑 HTTP 代理会由代理侧解析目标 | 严格模式默认代理失败关闭；DoH endpoint 代理独立配置 |
| 10 | 解析缓存与 `AccessPolicy` DNS 缓存重复 | 统一到 Resolver 缓存；策略缓存只保留兼容层并最终弃用 |
| 11 | 缓存键未包含 DO/CD/ECS/路由 | 缓存键包含 qname/qtype/qclass/DO/CD/ECS 范围/路由/Resolver 身份 |
| 12 | 未处理 DNS TTL 与长连接存活期不一致 | 文档说明；提供刷新后关闭空闲连接的可选能力 |
| 13 | 本地 DNSSEC 未说明 CD/DO 标志 | 本地验证必须 DO=1、CD=1，自行判断 Bogus；不能依赖递归解析器返回 SERVFAIL |
| 14 | DNSSEC 未定义信任锚轮换、算法策略、DoS 上限 | 增加信任锚配置/轮换策略、算法白名单、响应/迭代/验证预算上限 |
| 15 | 厂商 HTTP DNS 与 DNSSEC 混淆 | 厂商签名只映射到 `TransportAuthenticated`；DNSSEC 状态单独判断 |
| 16 | 未说明明文 HTTP DNS | 明文 HTTP 仅在响应签名校验通过且显式允许时使用；否则拒绝 |
| 17 | 未处理 ECS/geo 答案的缓存作用域 | ECS 默认关闭；启用时缓存键包含 ECS scope；厂商结果按出口/区域隔离 |
| 18 | 未定义 Resolver 生命周期与热更新 | 增加 DNS 策略/凭据/pin/endpoint 的热更新接口与并发安全边界 |
| 19 | 未处理自定义 Transport/自定义 Dialer | 与现有 IP 守卫一致：无法在拨号期解析则构造/更新失败 |
| 20 | 未说明 DNS 错误的用户可见语义 | 增加 DNS 错误哨兵与分类；不把解析失败伪装成普通网络错误 |
| 21 | 未考虑 Happy Eyeballs 与双栈 | 解析结果保留地址顺序/族；拨号层并发/延迟回退，不串行放大延迟 |
| 22 | 未说明查询名隐私与日志 | qname 默认脱敏；ECS 默认关闭；调试日志需显式开启 |
| 23 | 未定义缓存负结果/失败的处理 | NXDOMAIN/NODATA 按 SOA 负缓存；SERVFAIL/超时/Bogus 不进入正缓存 |
| 24 | 未说明模块/依赖边界 | 核心只定义接口；DoH/HTTPDNS/DNSSEC 为可选嵌套模块，复用已有 `x/net` |
| 25 | 未定义严格模式失败与降级 | 明确 Strict/FallbackSystem/Permissive 三档，降级必须显式并有指标 |

## 5. 总体架构

```
                 Client / Rules / Hosts / Forward / SSE / Pipeline
                                      │
                               engine.RoundTrip
                                      │
                            DialPlan（解析一次）
                                      │
                    ┌─────────────────┴──────────────────┐
                    │        DNS Router / Resolver       │
                    │  ├─ per-rule / per-host / suffix   │
                    │  ├─ hosts overlay（可选）           │
                    │  ├─ system resolver（内网/本地）     │
                    │  ├─ DoH resolver                   │
                    │  ├─ vendor HTTP DNS adapter        │
                    │  └─ DNSSEC validator（可选）        │
                    └─────────────────┬──────────────────┘
                                      │
                         DNS 结果 + TTL + 安全状态
                                      │
                         AccessPolicy IP/CIDR 校验
                                      │
                         直接拨号已校验 IP（不二次解析）
                                      │
                         TLS（SNI/证书仍使用逻辑主机名）
```

关键原则：

1. 每次拨号只解析一次；校验后直接拨 IP。
2. DNS 结果必须带安全状态与来源，不能只返回地址列表。
3. 解析路由优先于全局默认；内网/本地域名可绕过 DoH。
4. 安全策略与降级策略分离；严格模式绝不静默回退。
5. DNS 解析器不依赖被解析的目标 Client，避免递归。

## 6. 模块划分

| 模块 | 职责 | 依赖 |
|---|---|---|
| `client` 核心 | Resolver 接口、DNS 路由、Dial 集成、缓存、策略、错误、指标 | 仅现有轻量依赖 |
| `client/doh` | RFC 8484 DoH、bootstrap、pin、endpoint 健康、DoH 缓存 | → `client` |
| `client/httpdns` | 通用厂商 HTTP DNS 适配、签名校验、TTL/JSON 映射 | → `client` |
| `client/dnssec` | 委托 AD 适配与可选本地 DNSSEC 验证 | → `client` |
| `benchmarks/client` | DNS 缓存命中、并发解析、DoH/系统解析对比 | 独立基准模块 |

核心不 import 上述嵌套模块。`DoH` 可使用 `x/net/dns/dnsmessage`（该依赖已存在），
本地 DNSSEC 使用标准库 crypto；不引入 `miekg/dns` 或云厂商 SDK。

## 7. 核心 Resolver 抽象

Resolver 查询结果至少包含：

- `Addrs`：A/AAAA 地址，保留返回顺序与地址族；
- `TTL`：整条 CNAME 链的最小 TTL；
- `CNAMEChain`：用于诊断与缓存边界，长度有上限；
- `DNSSECState`：Secure / Insecure / Bogus / Indeterminate；
- `TransportAuthenticated`：DoH TLS 或厂商签名是否通过；
- `Source`：System / DoH / HTTPDNS / Static；
- `ResolverID`：用于缓存隔离与指标；
- `RCode`：NXDOMAIN、SERVFAIL、REFUSED 等；
- `Cached`、`ResolvedAt`：观测与 TTL 计算；
- `ECSScope`：启用 ECS 时的作用域标识。

错误分类使用包级哨兵并支持 `errors.Is`，至少包含：

- 解析超时、DoH endpoint 不可用、bootstrap 失败；
- NXDOMAIN、NODATA、SERVFAIL；
- DNSSEC Bogus、未认证但要求认证、信任锚/算法不支持；
- 策略拒绝、代理不允许、自定义 Transport 不支持。

Resolver 需要支持 `Close`/`Update` 生命周期，并与 Client 的 `Close` 联动。

## 8. 解析路由与兼容性

### 8.1 路由优先级

1. IP 字面量：直接使用，不查询 DNS（仍走 AccessPolicy）。
2. hosts 覆盖（可选，默认沿用系统行为）。
3. 规则级 Resolver（`Rule` 或 `Host` 覆盖）。
4. 域名后缀/精确路由（内网、`.local`、企业域）。
5. 客户端默认 Resolver。
6. 严格模式下不允许隐式回退到系统 DNS。

### 8.2 必须保留的兼容行为

- **hosts 文件**：DoH 绕过 hosts 文件会造成本地覆盖失效；提供“hosts 优先”或静态覆盖表。
- **search domain / ndots**：短主机名在内网依赖搜索域；DoH 不应破坏；无法支持时显式失败。
- **`.local`/mDNS、NetBIOS**：默认绕过 DoH，交回系统解析器。
- **VPN 分裂视图**：企业内网域名必须可路由到系统/内网 DNS，不能强制 DoH。
- **短名称/相对名称**：与标准库语义保持一致；自定义 Resolver 不自行拼接搜索域，除非显式配置。

### 8.3 规则与 Host 覆盖

允许规则、Host 或域名后缀指定 Resolver。适用场景：

- 公网 API 走 DoH + DNSSEC；
- 内网服务走系统 DNS；
- 特定厂商域名走厂商 HTTP DNS；
- 测试域名走静态 Resolver。

## 9. DoH 设计（RFC 8484）

### endpoint 与引导

- 支持 POST wire-format；可选 GET base64url。
- endpoint 通过固定 bootstrap IP 列表访问，禁止使用待替换的 Resolver 解析自身。
- 使用独立 `http.Transport`：独立连接池、独立代理配置、HTTP/2、连接复用。
- 强制 TLS 校验；支持 RootCAs、SPKI pin、ServerName；默认拒绝 `InsecureSkipVerify`。
- bootstrap 只解决“如何到达 DoH”，信任仍来自 TLS/pin。
- 多个 endpoint 支持故障转移、健康检查和熔断；避免每次查询风暴式重试。

### 协议与响应校验

- 请求/响应使用 `application/dns-message`；
- 默认拒绝重定向；如需允许，仅同源且显式配置；
- 校验 2xx、Content-Type、问题区、QR、RCode、TC、CNAME 链、响应大小；
- DoH 的事务 ID 可能为 0，不能只依赖 ID；问题区匹配更重要；
- 设置响应字节上限、CNAME 链上限、超时与单 endpoint 并发上限；
- 支持 EDNS(0) DO/CD；ECS 默认关闭，启用时写入缓存键；
- 默认使用 DNS padding（RFC 8467）降低长度侧信道。

### 缓存与失败

- DoH 结果进入统一 Resolver 缓存；
- SERVFAIL、超时、bogus、不完整响应不进入正缓存；
- endpoint 失败有短退避与熔断，避免拖慢所有请求；
- 严格模式不回退系统 DNS；回退模式必须显式开启。

## 10. 厂商 HTTP DNS

- 通用适配层负责请求构造、JSON 响应解析、TTL、错误码、签名校验钩子。
- 厂商适配只负责 endpoint、鉴权头、签名算法、字段映射。
- 明文 HTTP 响应必须验签；未验签的响应只在 Permissive 模式可用。
- 凭证不进入日志、错误、Meta、Stats 标签。
- 支持批量查询、配额错误、超时、重试与熔断；批量结果按域名拆分缓存。
- 厂商签名映射为 `TransportAuthenticated`，不自动映射为 DNSSEC Secure。
- ECS/geo 答案按出口/区域隔离缓存；默认不启用 ECS。

## 11. DNSSEC 设计

### 状态模型

- **Secure**：从信任锚到 RRset 的签名链验证通过。
- **Insecure**：存在已证明的未签名委派（无 DS），按策略可放行。
- **Bogus**：应有签名但验证失败（签名、时间、算法、链断裂）。严格模式必须失败。
- **Indeterminate**：无法判断（超时、算法不支持、信任锚缺失）。按策略处理。

### 委托验证（推荐默认）

- 使用可信验证型 DoH Resolver；
- 校验 DoH TLS/pin，读取 AD 位；
- `RequireSecureTransport` 要求 DoH TLS/厂商签名；
- `RequireDNSSEC` 要求 AD=true 或本地验证 Secure/Insecure 符合策略；
- `RequireSecureAll` 要求所有解析结果均为 Secure；Insecure 也失败；
- AD 只是解析器断言，不能脱离 DoH 信任链单独使用。

### 本地验证（可选模块）

- 查询时必须 DO=1、CD=1，自行验证 Bogus，不能依赖递归解析器返回 SERVFAIL；
- 根信任锚内置并可配置；支持信任锚轮换/RFC 5011 策略；
- 验证 DS → DNSKEY → RRSIG 链；
- 支持 RSA/SHA-256、ECDSA P-256/P-384、Ed25519；DS SHA-256/SHA-384；
- 处理规范化 RRset、时间窗口、密钥标志、通配符、CNAME 链、NSEC/NSEC3 否定证明；
- 算法白名单、NSEC3 迭代上限、响应大小上限、签名验证预算；
- 验证结果按 DNSSEC 状态和 TTL 缓存；Bogus 不进入正缓存；
- 未签名委派（Insecure）与验证失败（Bogus）严格区分。

### 策略

- `RequireSecureAll`：所有域名必须 Secure，适合高安全场景，但会拒绝未部署 DNSSEC 的域名；
- `RequireDNSSEC`：Bogus 失败，Insecure 可配置放行；
- `PreferDNSSEC`：尽量验证，失败可按显式回退策略处理；
- 默认不开启 DNSSEC，避免行为突变。

## 12. 缓存设计

- 统一在 Resolver 层，使用分片有界 LRU；
- 键包含：qname（大小写归一）、qtype、qclass、DO、CD、ECS scope、路由/Resolver ID；
- 正缓存 TTL 取 CNAME 链最小值，按 MinTTL/MaxTTL 截断；
- NXDOMAIN/NODATA 使用 SOA 负缓存 TTL；SERVFAIL/超时/Bogus 不缓存为正结果；
- 同一键 singleflight，leader 取消不影响 follower；
- TTL 抖动避免同一时刻过期风暴；
- 缓存条目数、单响应大小、CNAME 链长度、DNSKEY/DS 缓存均有上限；
- 可选 stale-while-revalidate；严格 DNSSEC 模式下默认关闭；
- 现有 `AccessPolicy.DNSCacheTTL` 逐步弃用，避免双重缓存；
- DNS 结果刷新不强制关闭已有长连接；提供显式“关闭空闲连接”能力。

## 13. 拨号与现有能力集成

- 拨号流程：解析 → 安全状态判断 → AccessPolicy IP/CIDR 校验 → 选择地址 → 直接拨 IP；
- Happy Eyeballs：优先 IPv6 时并发/延迟回退，避免串行放大延迟；
- TLS 仍用逻辑主机名做 SNI、证书校验和 pin；
- Host 池、健康检查、重试、重定向、镜像、SSE、Forward 全部复用同一拨号路径；
- IP 字面量不解析，但仍做 AccessPolicy；
- HTTP 代理/SOCKS 代理会由代理侧解析目标：严格 DNS 策略默认失败关闭，除非显式允许远程 DNS；
- 自定义 `http.RoundTripper` 或自定义 `DialContext`/`DialTLSContext` 无法保证拨号期解析：
  构造或更新策略时失败关闭；
- 连接池中的长连接可能继续使用旧 IP；文档说明 TTL 与连接生命周期的差异。

## 14. 失败与降级策略

| 模式 | 行为 |
|---|---|
| Strict | DoH/DNSSEC/签名失败即失败，不回退系统 DNS |
| FallbackSystem | DoH/DNSSEC 不可用时回退系统 DNS，记录指标/日志 |
| Permissive | 允许未认证结果；仅测试/诊断，必须显式开启 |

降级不能静默：必须产生结构化日志与统计；严格模式下代理、自定义 Transport、
bootstrap 失败均失败关闭。

## 15. 并发与性能

- DNS 缓存分片，避免全局锁；
- 同域名并发查询 singleflight；
- DoH endpoint 独立连接池/HTTP2 复用；
- 查询预算、响应大小、CNAME 链、NSEC3 迭代、签名验证预算有上限；
- 不因每次拨号创建无界 goroutine；所有后台任务必须有退出条件；
- 解析结果按地址族保留，支持双栈拨号；
- 基准覆盖系统解析、DoH 缓存命中/未命中、并发解析和解析+拨号端到端。

## 16. 可观测性与隐私

- Stats 增加：DNS 查询、命中、未命中、失败、DNSSEC Bogus、回退次数、平均解析耗时；
- 可选 Hook 观察解析结果，但默认不记录 qname；
- 日志默认脱敏 qname、不含凭证、不含完整响应；
- ECS 默认关闭；启用需显式配置并记录隐私影响；
- 厂商凭证不出现在错误、日志、指标标签中。

## 17. API 与易用性（设计层）

建议新增：

- `WithDNSPolicy(...)`：统一设置 Resolver、严格模式、缓存、超时、代理策略；
- `WithDNSResolver(...)`：快速注入自定义 Resolver；
- Rule/Host 级 Resolver 覆盖或域名后缀路由；
- `UpdateDNS`/`ReloadDNS`：热更新 endpoint、pin、凭证和缓存配置；
- `client/doh.New(...)`、`client/httpdns.New(...)`、`client/dnssec.Wrap(...)`；
- 预置配置：`DNSPolicyStrict`、`DNSPolicyCompat`、`DNSPolicyFallback`。

默认行为保持不变：未配置 DNS 策略时使用系统 Resolver。

## 18. 测试与基准

### 单元/集成

- 本地 `httptest` TLS DoH 服务：正常、畸形、截断、错误 Content-Type、重定向、超大响应；
- bootstrap 失效、TLS/pin 失败、endpoint 故障转移、熔断；
- Resolver 路由：规则/Host/后缀、hosts、search domain、`.local`；
- 缓存 TTL、负缓存、singleflight、并发取消、缓存键隔离；
- 严格/回退/宽松模式；代理失败关闭；自定义 Transport 拒绝；
- DNSSEC：Secure/Insecure/Bogus/Indeterminate、CNAME、通配符、NSEC/NSEC3、算法轮换；
- 本地 DNSSEC 必须验证 CD/DO 标志和 Bogus 数据。

### Fuzz

- DNS wire-format 解析；
- CNAME/NSEC/NSEC3 边界；
- DNSSEC 规范化与签名输入；
- 缓存键和响应大小边界。

### 基准

在 `benchmarks/client` 增加系统解析 vs DoH、缓存命中 vs 未命中、并发解析、
严格 DNSSEC 额外开销；CI 使用 mock DoH，不访问外网。

## 19. 分阶段交付与工作量

| 阶段 | 内容 | 估算 |
|---|---|---|
| P1 | 核心 Resolver 抽象、路由、拨号集成、统一缓存、错误/指标 | 4–6 天 |
| P2 | `client/doh`：RFC 8484、bootstrap、TLS/pin、endpoint 健康、测试 | 5–7 天 |
| P3 | `client/httpdns` 通用适配 + 一个厂商适配 | 3–5 天 |
| P4 | 委托 DNSSEC（AD）与策略 | 2–3 天 |
| P5 | 本地 DNSSEC 验证（可选模块） | 3–5 周 |
| P6 | 硬化、fuzz、基准、文档、CI、发布 | 5–8 天 |

建议先交付 P1–P4；本地 DNSSEC 独立推进。

## 20. 验收标准

- 未配置 DNS 策略时行为与当前完全一致；
- 严格模式不会回退系统 DNS，不会使用代理远程解析；
- DoH endpoint 无法通过被替换的 Resolver 递归解析；
- DNSSEC Bogus 与 Insecure 可区分，严格策略按配置生效；
- AccessPolicy IP 校验与 DNS 结果组合正确，解析后直接拨 IP；
- 自定义 Transport/代理在无法保证时失败关闭；
- 缓存/TTL/负缓存/singleflight 有界且并发安全；
- `GOWORK=off go build/vet/test -race`、`repotest`、基准与 fuzz 通过；
- 新模块满足 `docs.go`/`go.mod`/`go.sum` 与目录命名约束。

## 21. 风险与待决问题

1. 本地 DNSSEC 的算法覆盖、信任锚轮换和 NSEC3 边界复杂度最高，建议独立排期。
2. 严格 `RequireSecureAll` 会拒绝大量未部署 DNSSEC 的域名，默认应采用 `RequireDNSSEC`
   或 `PreferDNSSEC`。
3. 企业 split-horizon/VPN 场景必须提供系统解析器路由，否则 DoH 会破坏内网访问。
4. 厂商 HTTP DNS 的签名/鉴权差异大，核心必须保持厂商无关。
5. DoH 被网络封锁时的回退策略需要产品明确；默认 Strict 会失败。
6. 本地 DNSSEC 与 DoH 的组合需要明确“谁验证、谁断言”，避免双重验证和信任混淆。
7. `x/net/dns/dnsmessage` 已随 `x/net` 存在；若未来移除 `x/net`，需要重新评估依赖。
8. 长连接与 DNS TTL 的生命周期差异需要文档和可选刷新策略。