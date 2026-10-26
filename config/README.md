# config — 多源分层配置引擎

`github.com/shibingli/ydx/config` 实现框架的多源分层配置：命令行参数、环境变量、
配置文件与默认值按固定优先级合并，并支持配置文件热重载。它只负责读取、分层与监视，
不解析业务语义、不校验取值，也不装配子系统。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/config` |
| 包名 | `config` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |
| 默认前缀 | `YD`（`YD_DB_MAXCONN` → `db.maxconn`） |

## 功能

- `Load(Options)`：按「默认值 → `.env` → 配置文件」构建配置实例。
- 配置来源优先级（高 → 低）：显式 pflag > 环境变量（含 `.env`）> 配置文件 > 默认值。
- 支持 `yaml` / `yml` / `toml` / `json`，并按 `config.<ext>` 后 `config.local.<ext>`
  的顺序深合并（local 覆盖 base）。
- `Config` 内嵌 `*viper.Viper`，`Get` / `GetInt` / `GetString` / `Set` 等读取 API 直接可用。
- 强类型读取包装：`GetBool`、`GetInt64`、`GetFloat64`、`GetDuration`、`GetStringSlice`、
  `GetStringMapString`、`IsSet`、`AllKeys`、`AllSettings`、`Unmarshal`、`Sub`。
- `BindFlags`：把命令行标志接入配置层。
- `Watch`：监听配置文件变化并重新加载；`WatchErr` 返回最近一次监视错误。

## 特性

- **命令行默认值不越权**：`BindFlags` 会绑定传入的每个标志，但只有显式传参（`Changed`）
  的标志以最高优先级参与取值；未变更标志的默认值只注入最低优先级的默认层。viper 在取值
  时检查 `HasChanged`，因此未传参的标志不会覆盖环境变量与配置文件，而在 `BindFlags`
  之后才解析的标志仍然生效。
- **动态优先级**：viper 在取值时解析环境变量与标志，因此 `BindFlags` 之后修改标志仍然
  生效。
- **并发安全**：`Config` 的读写包装器用 `RWMutex` 串行化读取与热重载，避免 viper 的
  “concurrent map read and map write”。
- **自主持有 watcher**：`Watch` 直接使用 fsnotify，而不是 `viper.WatchConfig`，从而：
  保留 `config.local` 覆盖、在包内锁下更新映射、监视失败只记录 `WatchErr` 而不
  `os.Exit`。
- **去抖重载**：文件事件后 100 ms 去抖，避免编辑器保存触发多次重载。
- **删除不破坏**：配置文件被整体删除时保留当前内存取值，不做破坏性清空。
- **任意文件系统**：通过 `Options.FS` 支持内存/内嵌文件系统，便于测试与只读镜像。

## 快速开始

```go
package main

import (
	"fmt"

	"github.com/shibingli/ydx/config"
)

func main() {
	cfg, err := config.Load(config.Options{
		Name:       "api",
		ConfigDir:  "./configs",
		ConfigName: "config", // 或 "config.yaml" 锁定扩展名
	})
	if err != nil {
		return
	}

	port := cfg.GetInt("server.port")
	name := cfg.GetString("app.name")
	fmt.Println(port, name)

	cfg.Watch(func(c *config.Config) {
		fmt.Println("reloaded:", c.GetString("app.name"))
	})
	if err := cfg.WatchErr(); err != nil {
		fmt.Println("watch error:", err)
	}
}
```

命令行绑定：

```go
fs := pflag.NewFlagSet("api", pflag.ContinueOnError)
port := fs.Int("port", 8080, "listen port")

if err := cfg.BindFlags(fs, map[string]string{"port": "server.port"}); err != nil {
	return err
}
// 未显式传 --port 时，8080 只进入默认层，环境变量 YD_SERVER_PORT 与配置文件仍然胜出。
```

## 应用场景

- **12-factor 应用**：环境变量覆盖镜像内默认配置，命令行再覆盖环境变量。
- **多环境部署**：`config.yaml` 提供基线，`config.local.yaml` 提供环境差异。
- **CLI 工具**：同一份配置结构同时服务命令行与环境变量。
- **热重载**：日志级别、限流阈值、功能开关等可运行时调整。
- **测试**：用 `afs.NewMem()` 注入内存配置，无需临时文件。

## 性能指标

本模块没有独立基准；成本集中在启动期与低频重载：

- `Load` 读取 `.env` 与配置文件、解析并合并一次；启动期成本由文件大小与格式决定。
- `Get*` 每次读取加一次 `RWMutex` 读锁并查 viper 映射；热路径可按需缓存到局部变量。
- `Watch` 只拥有一个 fsnotify watcher 协程；100 ms 去抖把连续保存合并为一次重载。
- 重载期间读锁与写锁互斥；重载本身不阻塞未发生写入的并发读。
- 没有反射式热路径：`Unmarshal` 只在启动期使用反射。

> 逐请求读取配置不是推荐用法；请在启动期映射为强类型结构或局部变量。

## 第三方依赖与鸣谢

| 依赖 | 版本 | 许可证 | 用途 |
|---|---|---|---|
| [`spf13/viper`](https://github.com/spf13/viper) | v1.21.0 | MIT | 多格式配置解析、分层与取值 |
| [`spf13/pflag`](https://github.com/spf13/pflag) | v1.0.10 | BSD-3-Clause | POSIX/GNU 风格命令行标志 |
| [`fsnotify/fsnotify`](https://github.com/fsnotify/fsnotify) | v1.10.1 | BSD-3-Clause | 配置文件变更监视 |
| [`spf13/afero`](https://github.com/spf13/afero) | v1.15.0 | Apache-2.0 | 可替换文件系统 |

仓库内依赖：`afs`、`errs`。

## 相关模块

- [`nodeid`](../nodeid/README.md)、[`gc`](../gc/README.md)、[`gorm`](../gorm/README.md)、
  [`redis`](../redis/README.md)、[`asynq`](../asynq/README.md)、[`cache`](../cache/README.md)、
  [`realtime`](../realtime/README.md) 等通过各自的 `OptionsFromConfig` 映射本模块实例。
- [`afs`](../afs/README.md)：配置来源文件系统。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
