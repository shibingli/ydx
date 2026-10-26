# repotest — 仓库级架构守卫

`github.com/shibingli/ydx/repotest` 包含 ydx 多模块工作区的仓库级守卫。它不是运行时库，
而是一组在 CI/发布前执行的测试，用来防止模块结构、依赖方向与代码规范随时间漂移。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/repotest` |
| 包名 | `repotest` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |

## 功能

守卫覆盖以下规则：

- **模块文件完整**：每个模块都带有 `docs.go`、`go.mod` 与 `go.sum`。
- **模块路径与目录一致**：`go.mod` 的 module 路径等于仓库相对目录。
- **包名与目录一致**：包标识符等于目录名。
- **主文件命名**：每个带实现代码的包都有 `<package>.go` 主文件。
- **禁止本地 replace**：`go.mod` 不得包含指向本地路径的 `replace`。
- **禁止 yd 依赖**：ydx 模块不得 import `github.com/shibingli/yd`。
- **禁止标准库编解码/正则直引**：包装层之外不得直接 import `encoding/json`、
  `encoding/base64`、`regexp`、`regexp2`。
- **禁止 `fmt.Errorf`**：`errs` 之外不得使用 `fmt.Errorf`。
- **禁止直接 `panic`**：唯一例外是 `recover()` 块中重新抛出已发生的 panic。
- **禁止外键**：数据库模型不得使用外键约束。
- **禁止 cgo SQLite**：不得引入 `mattn/go-sqlite3` 等 cgo 驱动。
- **基准位置**：所有 `Benchmark*` 必须位于 `benchmarks/*` 独立模块；组件模块不得包含
  基准或依赖基准专用库。

## 特性

- **架构可执行化**：把仓库规范中的硬性约束变成可运行的测试，而不是口头约定。
- **快速失败**：在构建、测试之前发现结构性问题，避免发布后才发现依赖方向错误。
- **多模块感知**：扫描整个工作区，而不是单个 Go 模块。
- **无第三方依赖**：只使用 Go 标准库，守卫本身不引入额外供应链。
- **可本地复现**：在仓库根目录或 `repotest` 目录运行同一组测试。

## 快速开始

`repotest` 会自行向上查找仓库根目录，因此从其模块目录运行即可：

```bash
cd repotest
GOWORK=off go test ./...
```

如果在仓库根目录执行，请使用子 shell 切换目录（根目录没有 `go.mod`）：

```bash
(cd repotest && GOWORK=off go test ./...)
```

建议在以下时机执行：

- 提交前；
- CI 流水线；
- 发布打标签前（与全模块测试一起）；
- 新增模块、移动目录、拆分包之后。

## 典型失败与修复

| 失败 | 修复 |
|---|---|
| `docs.go` / `go.sum` 缺失 | 补齐模块文件并运行 `go mod tidy` |
| module 路径与目录不一致 | 修正 `go.mod` 的 module 行 |
| 包名与目录不一致 | 重命名包标识符（如 `cachex` → `cache`） |
| 缺少 `<package>.go` | 增加与包同名的主文件 |
| 本地 `replace` | 删除；开发期用仓库外的临时 `go.work` |
| import 了 yd | 把共享代码下沉到 ydx，保持 yd → ydx 单向依赖 |
| 直接 import 标准库编解码/正则 | 改用 `ydx/json`、`ydx/base64`、`ydx/regexpx` |
| `fmt.Errorf` / 直接 `panic` | 改用 `errs.Detail` / `errs.Wrap`；panic 只在 recover 中重抛 |
| 组件模块出现 `Benchmark*` | 移到 `benchmarks/*` 独立模块 |

## 应用场景

- **CI 门禁**：在合并前阻止架构违规。
- **发布前检查**：与全模块构建、vet、`-race` 测试一起执行。
- **重构护栏**：移动目录或拆分包后立即验证命名与依赖。
- **新人 onboarding**：用失败信息学习仓库结构约定。

## 性能指标

本模块没有运行时性能指标；它是 CI 工具：

- 执行成本与仓库文件数、模块数成正比，通常在秒级。
- 不参与产品二进制，不增加运行时依赖或内存占用。
- 测试只读文件系统，不修改仓库内容。
- 建议与 `go build`、`go vet`、`go test -race` 一起在流水线中执行。

## 第三方依赖与鸣谢

本模块没有第三方运行时依赖，只使用 Go 标准库。

## 相关模块

- 所有产品模块与基准模块：守卫遍历它们的 `go.mod`、`docs.go` 与源码。
- [`errs`](../errs/README.md)：`fmt.Errorf` 规则的替代方案。
- [`json`](../json/README.md)、[`base64`](../base64/README.md)、
  [`regexpx`](../regexpx/README.md)：标准库直引规则的替代入口。
- [`benchmarks`](../benchmarks/README.md)：基准位置规则的目标目录。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
