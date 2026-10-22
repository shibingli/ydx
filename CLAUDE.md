# CLAUDE.md — ydx 项目 AI 助手全局上下文

本文件定义 AI 助手（Claude / 其他编码代理）在 **ydx** 仓库内的全局上下文与硬性约束。
ydx 是 yd 全栈框架的可复用组件仓库；组件源码以本仓库为唯一事实来源，yd 通过版本号依赖本仓库。

## 1. 项目身份

| 项 | 值 |
|---|---|
| 项目名 | ydx（YunDev 可独立引用的 Go 组件集） |
| 归属团队 | YunDev（https://yun-dev.cn 、https://yun-dev.net） |
| 源码仓库 | https://github.com/shibingli/ydx |
| 开源协议 | Apache-2.0（见 `LICENSE`） |
| 主仓 | https://github.com/shibingli/yd |
| Go 版本 | 1.27.2（每个模块 `go 1.27.2`） |

## 2. 仓库结构与命名（强制）

仓库根目录**没有** `go.mod` 与 `go.work`。每个子目录是一个独立 Go 模块，标签形如
`errs/v0.1.0`、`middleware/cors/v0.1.0`。

- **目录名 = 模块路径末段 = 包名**：`ydx/cache` 的包名必须是 `cache`；`ydx/middleware/cors`
  的包名必须是 `cors`。不得出现 `cachex`、`jsonx`、`b64x`、`logx`、`gormx`、`errx`、
  `bufpool`、`ws` 等旧前缀。
- **主文件名 = 包名**：每个带实现代码的包必须有 `<package>.go`（如 `cache/cache.go`）。
  其余文件按职责命名，但不得用旧包前缀。
- **公开路径不含 `internal`**：共享设施放 `middleware/reqlog`，仓库守卫放 `repotest`。
- **每个模块必须包含** `docs.go`、`go.mod`、`go.sum`。`docs.go` 给出包文档，并同时给出
  YD 路由与原生 `net/http`（或原生 Go）两种用法。
- **组件模块不得包含基准**：所有 `Benchmark*` 放 `benchmarks/*` 独立模块；组件模块也不得
  依赖基准专用库。基准模块的包名同样等于目录名。
- 产品模块（31 个）：`errs`、`sysinfo`、`buffpool`、`protocol`、`base64`、`json`、`afs`、
  `config`、`log`、`regexpx`、`router`、`gorm`、`redis`、`asynq`、`cache`、`sse`、`websocket`、
  `render`、`i18n`、`openapi`、`openapi/ydrouter`、`jwt`、`middleware` 及
  `middleware/{accesslog,asyncafter,compress,cors,ratelimit,recovery,requestid,reqlog}`。
- `openapi` 是独立模块：核心只接受 `openapi.Route` 并提供标准 `net/http` 处理器，
  **不得** import `ydx/router`；路由适配（`FromRouter` / `Handler`）只在 `openapi/ydrouter`。
- 基准模块（11 个）：`benchmarks/{base64,buffpool,cache,json,jwt,log,middleware,render,router,sse,websocket}`。
- 守卫模块：`repotest`。

## 3. 依赖与版本（强制）

- ydx 模块**不得** import `github.com/shibingli/yd`；依赖方向只能是 yd → ydx。
- 最终 `go.mod` **不得包含**指向本地路径的 `replace`。开发期需要联调时，在两个仓库之外
  临时创建 `go.work`，不得提交。
- 兄弟 ydx 模块按 `v0.1.0` 的锁步版本引用；发布前用本地标签引导 `go.sum`。
- 外部依赖版本以 yd 根 `go.mod` 为准，不得在迁移或常规修改中擅自升级。
- `repotest` 会扫描本地 `replace`、旧包前缀、yd 依赖、标准库编解码直引、`fmt.Errorf`、
  直接 `panic`、外键、cgo SQLite 与基准位置。

## 4. 代码风格

1. 一个文件一个职责；文件超过约 600 行或承担两类职责即拆分。
2. **错误**：包级用 `errs` 声明哨兵（`errs.New("English | 中文")`）；默认禁止
   `fmt.Errorf`，附加细节用 `errs.Detail`，包装底层错误用 `errs.Wrap` / `errs.WrapDetail`；
   调用方用 `errors.Is` / `errors.As` 判定。**禁止直接 `panic`**，唯一例外是 `recover()`
   块里重新抛出已经发生的 panic。
3. **文档注释**：所有导出符号必须有以符号名开头的 Go doc 注释；注释与日志文案中英文同步，
   英文在前、中文在后，以 ` | ` 分隔。
4. **日志**：统一使用 `ydx/log`（包名 `log`）；禁止标准库 `log`、`fmt.Print*` 作为日志、
   禁止 zap/zerolog/logrus。局部变量与包同名时使用 `logx` 或 `ydlog` **导入别名**，
   不得让变量遮蔽日志包。
5. **JSON / Base64 / 正则**：分别只经 `ydx/json`、`ydx/base64`、`ydx/regexpx`；
   包装层之外禁止直接 `import "encoding/json"`、`"encoding/base64"`、`"regexp"`、
   `"regexp2"`（测试与基准模块可把标准库当对照实现）。
6. **热路径禁止反射**：请求处理、序列化、日志、JWT 验签路径不得使用 `reflect`；
   反射只允许出现在启动期装配与文档 Schema 构建。
7. **零拷贝优先**：优先 `AppendXxx` 与调用方缓冲区，避免不必要的 `string([]byte)` 往返。
8. **并发**：共享状态必须显式加锁或使用 `sync.Pool`/原子操作；每个 `go` 关键路径
   必须能回答「它何时退出」。
9. **格式**：`gofmt` / `go vet ./...` 零告警；导入分组为标准库 / 第三方 / 本项目。
10. **内存对齐**：提交前对改动过的模块运行 `betteralign -apply ./...`（可选工具，
    缺失不得阻塞构建）；重排后测试必须通过。
11. **无 cgo**：默认构建为纯 Go、`CGO_ENABLED=0`；禁止引入 `mattn/go-sqlite3` 等
    cgo 驱动。

## 5. HTTP 双入口

- YD 路由：`router.Middleware`、`router.HandlerFunc`、`router.Adapt`。
- 原生 `net/http`：`router.Adapt(next, mw...)`；各插件提供
  `Middleware(...) func(http.Handler) http.Handler`；`jwt` 提供
  `HTTPMiddleware` / `FromRequest`，`sse` 提供 `HTTPHandler`，
  `websocket` 提供 `HtmxHTTPHandler`。
- 原生适配器只新增入口，不得改变 YD 入口的每请求路径。

## 6. 测试与基准（强制）

- TDD：先写失败测试，再写最小实现；复制迁移的既有组件以原测试为验收。
- 文件名与被测文件同名加 `_test.go`；涉及并发必须 `-race` 通过。
- Windows 上没有 gcc 时用 `CGO_ENABLED=1 CC=clang go test ./... -race`；不得因未指定
  编译器就宣称 `-race` 不可用。
- 每个模块单独验证：

```bash
GOWORK=off go build ./... && GOWORK=off go vet ./...
GOWORK=off CGO_ENABLED=1 CC=clang go test ./... -race
```

- 全仓验证：`scripts/test-all.sh` / `scripts/test-all.ps1`。
- 基准只在 `benchmarks/*` 运行；性能门禁为 benchstat 无统计显著回退、`allocs/op` 不增加。
- 不得通过删除/注释测试、放宽断言、`t.Skip` 让流水线变绿。

## 7. 发布与标签

- 每个模块独立打子目录标签，例如 `errs/v0.1.0`、`middleware/cors/v0.1.0`。
- 发布前必须：所有模块测试通过 → `repotest` 通过 → 打标签 → 推送 `main` 与标签。
- 标签提交中的 `go.sum` 由本地标签引导生成；改动模块内容后必须重新生成并验证各模块，
  不得让兄弟模块解析到旧内容。
- 消费方用版本号引用；不得把本地 `replace` 带入发布。

## 8. 提交纪律（强制）

**一律禁止在提交信息、作者、署名、脚注、PR 描述中出现任何 Claude / Anthropic / AI 助手相关内容**
（包括但不限于 `Claude`、`claude`、`Anthropic`、`noreply@anthropic.com`、
`Generated with Claude Code`、`🤖` 等标记）。

提交信息格式：**中文 Conventional Commits + 固定署名尾行**。

```
<类型>(<范围>): <中文简述>

<可选正文：为什么这么改、影响面、验证方式>

Co-Authored-By: Eric Shi <shibingli@sina.com>
```

- 类型：`feat` `fix` `refactor` `perf` `test` `docs` `chore` `build` `ci` `style`
- 范围：受影响的包名，如 `router`、`log`、`cache`、`middleware`
- 简述：中文，动词开头，不超过 50 字，句末不加句号
- 署名：凡本仓提交，一律使用 `Co-Authored-By: Eric Shi <shibingli@sina.com>`，不得省略

## 9. 安全与数据

- 不得在源码中硬编码任何密钥、口令、Token；测试密钥只能用明显的固定测试值。
- 错误文案与日志不得泄露口令、DSN、主密钥或完整请求体。
- 新增第三方依赖需说明理由与体积影响；能用标准库解决的不引依赖。

## 10. 常用命令

```bash
# 单个模块
GOWORK=off go build ./... && GOWORK=off go vet ./...
GOWORK=off go test ./... -race

# 仓库守卫
cd repotest && GOWORK=off go test ./...

# 全模块
./scripts/test-all.sh          # POSIX
pwsh ./scripts/test-all.ps1    # Windows
```
