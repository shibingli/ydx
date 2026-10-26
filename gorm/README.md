# gorm — GORM 装配与方言能力层

`github.com/shibingli/ydx/gorm` 是框架的 GORM 装配层：把配置、日志与连接池收敛为一次
`Open`，并提供跨 MySQL / PostgreSQL / SQLite / 达梦 DM8 的方言能力层。它不定义模型与
业务查询，也不替调用方决定 DSN 之外的重试与降级策略。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/gorm` |
| 包名 | `gorm` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |
| 支持驱动 | `mysql`、`postgres`、`sqlite`、`dm` |

## 功能

- `Open(Options, logger)`：依据 Options（通常来自 `OptionsFromConfig`）选择驱动并打开
  `*gorm.DB`。
- 框架命名策略：表统一带 `yd_` 前缀，派生索引名统一为 `yd_idx_` 形态。
- 连接池：把最大连接数、空闲连接数、连接生命周期等参数落到 `sql.DB`，默认开启预编译
  语句缓存。
- 日志：GORM 日志经 `ydx/log` 输出；慢查询走 `log.SlowQuery`；`ParamsFilter` 屏蔽口令、
  Token 等敏感实参。
- 生命周期：`AutoMigrate`、`Health`、`Close`。
- 方言能力层：`DialectFor` / `DialectOf`、`Upsert`、`UpsertDoNothing`、`JSONExtract`、
  `ILike`、`LockClause`、`Concat`、`Random`、`Features`。
- DSN 预置：`PresetDSN` 补齐驱动常用参数。

## 特性

- **四方言统一**：调用方不必按驱动名分支处理支持情况或拼写差异。
- **纯 Go SQLite**：使用 `glebarez/sqlite`，无 cgo，默认 `CGO_ENABLED=0` 可构建。
- **达梦 DM8**：通过 `godoes/gorm-dameng` 选择 DM8 方言。
- **敏感参数脱敏**：`ParamsFilter` 在日志中隐藏密码、Token 等实参，避免 DSN/凭据泄露。
- **预编译语句缓存**：默认开启，减少重复 SQL 解析与计划生成。
- **错误哨兵**：不支持驱动、方言能力缺失等失败路径返回包级哨兵，可用 `errors.Is` 判定。
- **职责边界清晰**：不管理连接以外的资源（缓存、迁移版本表），不封装业务查询。

## 快速开始

```go
package main

import (
	"context"
	"fmt"

	"github.com/shibingli/ydx/config"
	"github.com/shibingli/ydx/gorm"
	"github.com/shibingli/ydx/log"
)

type User struct {
	ID   uint64 `gorm:"primaryKey"`
	Name string
}

func main() {
	cfg, err := config.Load(config.Options{Name: "api"})
	if err != nil {
		return
	}

	logger := log.New(log.Options{Service: "api"})
	db, err := gorm.Open(gorm.OptionsFromConfig(cfg), logger)
	if err != nil {
		return
	}
	defer func() { _ = gorm.Close(db) }()

	if err := gorm.AutoMigrate(db, &User{}); err != nil {
		return
	}
	if err := gorm.Health(context.Background(), db); err != nil {
		return
	}

	fmt.Println(db.Find(&[]User{}).Error)
}
```

方言能力：

```go
d, err := gorm.DialectFor("postgres")
if err != nil {
	return err
}
if d.Features.Has(gorm.FeatureReturning) {
	// 使用 RETURNING。
}
```

## 应用场景

- **多数据库产品**：同一套模型在 MySQL、PostgreSQL、SQLite 与达梦 DM8 上运行。
- **信创/国产化部署**：达梦 DM8 方言与能力层。
- **测试与边缘部署**：纯 Go SQLite 无需 cgo 与系统库。
- **SaaS 多租户**：统一 `yd_` 前缀与索引命名，便于迁移与审计。
- **可观测性**：慢查询日志与敏感参数脱敏。
- **连接池治理**：把配置中的池参数直接落到 `sql.DB`。

## 性能指标

本模块没有独立基准；性能主要由数据库、网络与 GORM 自身决定：

- `Open` 只构造连接池，不做网络往返；真正的连接在首次查询或 `Health` 时建立。
- 默认开启预编译语句缓存，重复查询省去 SQL 解析与计划生成。
- 连接池参数直接影响并发查询吞吐与等待时间；请按数据库上限与实例数配置。
- 纯 Go SQLite 避免了 cgo 与系统库依赖，但绝对吞吐通常低于原生 SQLite；对写密集场景
  应控制并发写入并使用 WAL。
- 慢查询日志只在实际超过阈值时输出；`ParamsFilter` 在日志路径做脱敏，不影响 SQL 执行。
- 方言能力层是编译期/启动期选择，不在查询热路径做驱动名字符串分支。

> 数据库客户端性能应以目标数据库与真实查询为基准；本模块不提供跨数据库的固定 ns/op。

## 第三方依赖与鸣谢

| 依赖 | 版本 | 许可证 | 用途 |
|---|---|---|---|
| [`gorm.io/gorm`](https://gorm.io) | v1.31.2 | MIT | ORM 核心 |
| [`gorm.io/driver/mysql`](https://github.com/go-gorm/mysql) | v1.6.0 | MIT | MySQL 方言 |
| [`gorm.io/driver/postgres`](https://github.com/go-gorm/postgres) | v1.6.3 | MIT | PostgreSQL 方言 |
| [`go-sql-driver/mysql`](https://github.com/go-sql-driver/mysql) | v1.10.1 | MPL-2.0 | MySQL 驱动 |
| [`jackc/pgx/v5`](https://github.com/jackc/pgx) | v5.11.0 | MIT | PostgreSQL 驱动 |
| [`glebarez/sqlite`](https://github.com/glebarez/sqlite) | v1.11.0 | MIT | 纯 Go SQLite 驱动 |
| [`godoes/gorm-dameng`](https://github.com/godoes/gorm-dameng) | v0.7.2 | 上游仓库未附 LICENSE 文件，采用前请确认授权 | 达梦 DM8 方言 |
| [`spf13/afero`](https://github.com/spf13/afero) | v1.15.0 | Apache-2.0 | 配置来源文件系统 |

仓库内依赖：`afs`、`config`、`errs`、`log`。

## 相关模块

- [`config`](../config/README.md)：`OptionsFromConfig` 读取 `gorm.*` 配置。
- [`log`](../log/README.md)：GORM 日志与慢查询。
- [`cache/gormcache`](../cache/README.md)：GORM 查询缓存子包。
- [`errs`](../errs/README.md)：哨兵错误。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
