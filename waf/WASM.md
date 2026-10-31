# ydx/waf WASM 插件 ABI

`waf` 使用纯 Go 的 [wazero](https://wazero.io) 运行时执行 WebAssembly 插件，无 cgo。插件由
`WASMPluginConfig` 加载，编译一次、按需实例化，并在实例池中并发复用。

## 模块要求

- 导入模块名：`ydx_waf`（宿主函数，全部可选调用）。
- 导出内存：`memory`。
- ABI 版本：`ydx_waf_abi_version() -> i32` 必须返回 `1`。
- 事件负载通过导出分配器写入客户内存；因此非空事件要求 `ydx_waf_alloc`。

## 客户导出

| 导出 | 签名 | 说明 |
|---|---|---|
| `ydx_waf_abi_version` | `() -> i32` | 必须返回 `1` |
| `ydx_waf_init` | `(ptr i32, len i32) -> i32` | 可选；`Config` 非空时必需；返回 0 成功 |
| `ydx_waf_on_hook` | `(ptr i32, len i32) -> i32` | 必需；参数是 UTF-8 JSON 事件 |
| `ydx_waf_alloc` | `(size i32) -> i32` | 非空事件必需；返回可写内存偏移 |
| `ydx_waf_free` | `(ptr i32)` | 可选；每次调用后释放事件缓冲 |
| `memory` | memory | 必需 |

`ydx_waf_on_hook` 返回值：

| 值 | 语义 |
|---|---|
| `0` | 继续 |
| `1` | deny（使用 `set_verdict` 设置的状态，否则 403） |
| `2` | drop（关闭连接） |
| `3` | allow（停止后续规则处理） |

也可以调用宿主函数 `set_verdict` 覆盖返回值与状态。

## 宿主函数（导入模块 `ydx_waf`）

| 函数 | 签名 | 说明 |
|---|---|---|
| `log` | `(level i32, ptr i32, len i32)` | level：0 debug、1 info、2 warn、3 error |
| `get_var` | `(namePtr, nameLen, outPtr, outCap) i32` | 读取 TX 变量；返回完整长度，`-1` 失败；`outCap` 不足时写入前缀 |
| `set_var` | `(namePtr, nameLen, valuePtr, valueLen) i32` | 写入 TX 变量；返回 0 |
| `set_verdict` | `(code, status, msgPtr, msgLen) i32` | 设置裁决、HTTP 状态与消息；返回 0 |

变量名与值均为 UTF-8 字节。TX 变量名大小写不敏感。

## 事件 JSON

`ydx_waf_on_hook` 收到的事件示例：

```json
{
  "point": "rule_match",
  "phase": 2,
  "tx_id": "m3k...-1",
  "method": "POST",
  "path": "/login",
  "client_ip": "203.0.113.5",
  "rule_id": 942100,
  "var": "ARGS_POST",
  "key": "username",
  "value": "admin' OR '1'='1",
  "message": "SQL injection",
  "severity": "CRITICAL",
  "tags": ["attack-sqli", "OWASP_CRS"],
  "rule_version": "crs-4.29.0",
  "interruption": null,
  "error": ""
}
```

`point` 取值：`before_phase` `after_phase` `rule_match` `before_interrupt`
`after_interrupt` `reload` `plugin_error` `request_complete`。

插件可通过 `WASMPluginConfig.Points` 只订阅需要的点；为空表示全部。

## 生命周期与隔离

- 模块编译一次；实例按并发需求创建，最多 `MaxInstances` 个（默认 32）。
- 每个实例独立执行 `ydx_waf_init`，可持有实例内状态；不同实例之间不共享内存。
- 单次调用受 `Timeout`（默认 `Options.PluginTimeout`，100ms）约束；启用
  `WithCloseOnContextDone`，超时会终止客户代码并丢弃该实例。
- `MaxMemoryPages` 限制客户内存（默认 256 页 = 16 MiB）。
- trap/超时/非法内存访问：实例丢弃；连续失败 5 次触发熔断，禁用 30 秒。
- `FailClosed=false`（默认）：插件失败只记录并计数，请求继续。
- `FailClosed=true`：插件失败返回 503。
- 宿主不向插件暴露文件系统；插件只能通过 `get_var`/`set_var` 访问 TX 状态与事件元数据。

## 构建示例

### Rust

```toml
[lib]
crate-type = ["cdylib"]
```

```rust
use std::slice;

#[no_mangle]
pub extern "C" fn ydx_waf_abi_version() -> i32 { 1 }

#[no_mangle]
pub extern "C" fn ydx_waf_init(_ptr: *const u8, _len: usize) -> i32 { 0 }

#[no_mangle]
pub extern "C" fn ydx_waf_on_hook(ptr: *const u8, len: usize) -> i32 {
    let event = unsafe { slice::from_raw_parts(ptr, len) };
    // 解析 JSON（建议使用 serde_json），按 point/rule_id 决策。
    let _ = event;
    0
}
```

```bash
cargo build --release --target wasm32-wasip1
```

### TinyGo

```go
//go:export ydx_waf_abi_version
func abiVersion() int32 { return 1 }

//go:export ydx_waf_init
func initPlugin(ptr, size uint32) int32 { return 0 }

//go:export ydx_waf_on_hook
func onHook(ptr, size uint32) int32 { return 0 }
```

```bash
tinygo build -o scoring.wasm -target=wasi .
```

TinyGo 的分配器与 ABI 差异较大时，请显式导出 `ydx_waf_alloc`/`ydx_waf_free` 并确保
`memory` 可导出。

## 安全建议

- 只加载经过签名/校验的模块；插件与规则包使用同一发布流程。
- 生产环境保持 `FailClosed=false` 并监控 `Stats.PluginFailures`，避免插件故障放大为拒服。
- 插件不应在 `on_hook` 中做阻塞 IO；WASI 环境未配置文件系统，网络访问也不可用。
- 对来自插件的日志与消息做长度限制；引擎已对事件值做 1 KiB 截断。
