# AGENTS.md — ydx 自主 AI Agent 自动化规约

面向在 **ydx** 仓库内自主执行「代码修复 / 功能迭代 / 组件发布」的 AI Agent。本文件定义修改
权限边界、测试自愈流程、发布流程与安全合规检查。与 `CLAUDE.md` 冲突时，以更严格的一条为准。

## 0. 项目定位

- ydx 是 yd 全栈框架的组件仓库，包含产品模块、14 个基准模块与 1 个 `repotest` 守卫模块。
- 组件源码以 ydx 为唯一事实来源；yd 通过 `github.com/shibingli/ydx/* vX.Y.Z` 依赖本仓库。
- 禁止反向依赖：任何 ydx 模块都不得 import `github.com/shibingli/yd`。

## 1. 修改权限边界

**允许直接修改**

- 产品模块目录：`errs/`、`sysinfo/`、`gc/`、`buffpool/`、`protocol/`、`base64/`、`json/`、`afs/`、
  `config/`、`log/`、`regexpx/`、`router/`、`gorm/`、`redis/`、`asynq/`、`cache/`、`sse/`、
  `websocket/`、`nodeid/`、`webtransport/`、`realtime/`、`render/`、`i18n/`、`openapi/`、`jwt/`、
  `captcha/`、`guomi/`、`middleware/` 及其插件子目录。
- 基准模块：`benchmarks/**`。
- 守卫：`repotest/**`。
- 测试与文档：`*_test.go`、`testdata/**`、`README.md`、本文件、`CLAUDE.md`、`docs/**`。
- 仓库脚本：`scripts/**`。

**禁止修改**

- `LICENSE` 的授权条款正文（仅允许更新末尾版权行）。
- 任何模块的 `go.mod` 中加入指向本地路径的 `replace`（发布态）。
- 组件模块中加入 `Benchmark*` 或基准专用依赖。
- 把公开路径改成包含 `internal` 的路径。

**需要人工确认**

- 新增第三方依赖（尤其 cgo、SIMD 或超过 1MB 体积的依赖）。
- 破坏公开 API 的签名变更（提交信息须标注 `BREAKING CHANGE`）。
- 修改模块路径、包名或主文件名（会影响所有下游 import 与标签）。
- 修改已发布标签指向的内容（应发新版本，而不是移动旧标签）。

## 2. 测试自愈流程（Test-and-Fix）

任何修改都必须以如下闭环收尾，**最多 3 轮**；3 轮未收敛则停止并输出诊断报告，不得继续盲改。

```bash
# 1. 受影响模块编译
cd <module>
GOWORK=off go build ./...

# 2. 静态检查
GOWORK=off go vet ./...

# 3. 单元测试（竞态检测）
GOWORK=off CGO_ENABLED=1 CC=clang go test ./... -race
# Windows 上没有 gcc 时用 clang；不得因未指定 CC 就跳过 -race。

# 4. 仓库守卫
cd repotest && GOWORK=off go test ./...

# 5. 全模块（发布前必须）
./scripts/test-all.sh          # POSIX
pwsh ./scripts/test-all.ps1    # Windows
```

自愈规则：

- **不得**通过删除/注释测试、放宽断言、`t.Skip` 来让流水线变绿。
- 修复缺陷时必须**先补一条能复现缺陷的测试**，再修实现。
- 每轮自愈的失败证据（命令 + 原始输出）必须保留在提交信息或 PR 描述中。
- 组件模块与基准模块分开验证；基准用 `-run '^$' -bench . -benchmem`。

## 3. 命名与模块检查清单

提交前逐项确认：

- [ ] 目录名 = 模块路径末段 = 包名。
- [ ] 带实现代码的包存在 `<package>.go` 主文件。
- [ ] 每个模块有 `docs.go`、`go.mod`、`go.sum`。
- [ ] 没有 `errx` / `jsonx` / `b64x` / `logx` / `gormx` / `cachex` / `bufpool` / `ws` 旧前缀。
- [ ] 没有 `github.com/shibingli/yd/...` import。
- [ ] 没有本地 `replace`。
- [ ] 没有 `fmt.Errorf`、直接 `panic`、标准库 `log`。
- [ ] JSON / Base64 / 正则只经包装包。
- [ ] 没有外键、GORM 关联标签、cgo SQLite 驱动。
- [ ] 基准只在 `benchmarks/*`。
- [ ] 注释、日志、错误文案中英文同步。

`repotest` 会自动检查以上大部分规则；仍需人工确认语义与文档。

## 4. 发布流程

1. 全模块 `build` / `vet` / `test -race` 通过。
2. `cd repotest && GOWORK=off go test ./...` 通过。
3. 提交所有源码、`go.mod`、`go.sum`、`docs.go` 与文档。
4. 为每个模块打子目录标签：`<module>/vX.Y.Z`（如 `errs/v0.1.0`）。
5. 推送 `main` 与全部标签：

```bash
git push origin main
git push origin --tags
```

6. 发布后由 yd 主仓按版本号引用；不得在 yd 中保留本地 `replace`。

**go.sum 说明**：多模块仓库同时打锁步标签时，`go.sum` 中的兄弟模块校验和由本地标签引导
生成；模块 zip 包含 `go.sum`，因此标签与校验和更新通常分属相邻提交。消费方使用自己的
`go.sum`，不受影响；本仓库以工作树的全模块测试为准。

## 5. 安全合规检查清单

- [ ] 没有硬编码密钥、口令、Token、私钥。
- [ ] 错误与日志不包含口令、DSN、主密钥、完整请求体。
- [ ] 新增依赖已说明理由与体积影响。
- [ ] 默认 `CGO_ENABLED=0`，没有引入 cgo SQLite 或其它 cgo 依赖。
- [ ] 没有运行时 CDN 引用；资产可离线使用。
- [ ] 没有把用户输入直接拼进 SQL / shell / 模板。
- [ ] 正则扫描走 `regexpx` 的自研线性引擎；需要环视/反向引用时受 `MatchTimeout` 保护。

## 6. 提交纪律（强制）

**禁止在提交信息、作者、署名、脚注、PR 描述中出现任何 Claude / Anthropic / AI 助手相关内容。**

```
<类型>(<范围>): <中文简述>

<可选正文：为什么这么改、影响面、验证方式>

Co-Authored-By: Eric Shi <shibingli@sina.com>
```

- 类型：`feat` `fix` `refactor` `perf` `test` `docs` `chore` `build` `ci` `style`
- 范围：受影响的包名
- 简述：中文，动词开头，不超过 50 字，句末不加句号
- 署名：一律 `Co-Authored-By: Eric Shi <shibingli@sina.com>`，不得省略

## 7. 完成报告

每次任务结束必须给出：

1. 修改的模块与文件；
2. 执行的验证命令与真实结果（通过/失败，不得只写「应该通过」）；
3. 未运行的检查及原因；
4. 对公开 API、版本、标签或下游 yd 的影响；
5. 若做了取舍，写清取舍与代价。
