// Package config implements the framework's multi-source layered configuration engine.
// | Package config 实现框架的多源分层配置引擎。
//
// Value precedence (high to low): | 取值优先级（高 → 低）：
//
//	command-line flags (explicit pflag) > environment variables (including .env)
//	> configuration files > defaults | 命令行参数（显式传入的 pflag）> 环境变量（含 .env 注入）
//	> 配置文件 > 默认值
//
// The environment variable prefix is fixed as YD, and nested keys map through
// underscores: YD_DB_MAXCONN → db.maxconn. Config files support yaml / yml / toml /
// json and are deep-merged in the order config.<ext> then config.local.<ext> (local
// overrides base). | 环境变量前缀固定为 YD，嵌套键通过下划线映射：YD_DB_MAXCONN →
// db.maxconn。配置文件支持 yaml / yml / toml / json，并按 config.<ext> 与
// config.local.<ext> 的顺序深合并（local 覆盖 base）。
//
// Responsibility boundary: this package only reads, layers and watches configuration.
// It does not parse business semantics or validate values, and does not wire subsystems
// such as logging, database or server; those map their own OptionsFromConfig. | 职责边界：
// 本包只负责读取、分层合并与监视变更；不解析业务语义、不校验取值，也不装配日志/数据库/
// 服务器等子系统（由各子包通过自己的 OptionsFromConfig 映射）。
//
// Key correctness constraint: a pflag with a non-empty default value must never
// override environment variables or config files when it was not explicitly passed.
// BindFlags calls BindPFlag only for flags marked Changed; unchanged flags inject their
// type-parsed DefValue into the lowest-precedence default layer instead. | 关键正确性约束：
// 带非空默认值的 pflag 在未显式传参时绝不能覆盖环境变量与配置文件。BindFlags 只对 Changed
// 的标志调用 BindPFlag；未 Changed 的标志改为把按类型解析后的 DefValue 注入最低优先级的
// 默认值层。
//
// Typical usage | 典型用法：
//
//	cfg, err := config.Load(ctx, config.Options{Name: "app"})
//	port := cfg.GetInt("server.port")
package config
