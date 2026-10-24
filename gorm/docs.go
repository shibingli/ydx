// Package gorm is the framework's GORM assembly layer: it turns configuration,
// logging and connection pooling into a single Open. | Package gorm 是框架的 GORM
// 装配层：把配置、日志与连接池收敛为一次 Open。
//
// Responsibilities: | 职责边界：
//
//   - choose a driver from Options (usually produced by OptionsFromConfig) and open
//     a *gorm.DB; mysql / postgres / sqlite / dm are supported, sqlite is a pure-Go
//     implementation with no cgo, and dm selects the Dameng DM8 dialect; | 依据 Options
//     （通常来自 OptionsFromConfig）选择驱动并打开 *gorm.DB，支持 mysql / postgres /
//     sqlite / dm（sqlite 为纯 Go 实现，无 cgo，dm 选择达梦 DM8 方言）；
//   - apply the framework naming strategy: tables carry the yd_ prefix and derived
//     index names use the yd_idx_ form (see naming.go); | 施加框架命名策略：表统一带
//     yd_ 前缀，派生索引名统一取 yd_idx_ 形态（见 naming.go）；
//   - translate pool options onto sql.DB and enable prepared-statement caching by
//     default; | 把连接池参数落到 sql.DB，并按框架硬规则默认开启预编译语句缓存；
//   - route GORM logs through log: slow queries use log.SlowQuery (no reflection,
//     no string concatenation), and ParamsFilter masks passwords, tokens and other
//     sensitive arguments; | 用 log 承载 GORM 的日志：慢查询只经 log.SlowQuery 打点，
//     并由 ParamsFilter 屏蔽口令、Token 等敏感实参；
//   - provide AutoMigrate / Health / Close lifecycle helpers with package-level
//     sentinel errors; | 提供 AutoMigrate / Health / Close 等生命周期辅助函数，失败路径
//     统一返回包级哨兵错误；
//   - expose the dialect capability layer (DialectFor / Upsert / JSONExtract / ILike /
//     LockClause / Concat / Random) so callers do not switch on the driver name for
//     features whose support or spelling differs between MySQL, PostgreSQL, SQLite and
//     Dameng DM8. | 提供方言能力层（DialectFor / Upsert / JSONExtract / ILike /
//     LockClause / Concat / Random），让调用方不必为 MySQL、PostgreSQL、SQLite 与
//     达梦 DM8 之间支持情况或拼写不同的能力自行按驱动名分支。
//
// It does not define models or business queries, does not manage resources beyond the
// connection (caches, migration version tables), and does not decide retry or fallback
// policies beyond the DSN. | 它不定义模型与业务查询、不做连接以外的资源管理（缓存、迁移
// 版本表），也不替调用方决定 DSN 之外的重试与降级策略。
//
// Typical usage | 典型用法：
//
//	db, err := gorm.Open(gorm.OptionsFromConfig(cfg), logger)
//	if err != nil {
//		return err
//	}
//	if err := gorm.AutoMigrate(db, &User{}); err != nil {
//		return err
//	}
package gorm
