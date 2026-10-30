// Package workflow implements a standalone BPMN 2.0 workflow engine with Chinese approval semantics.
//
// The module owns the domain model, the token-based execution engine, approval actions, automatic approval
// rules, notification outbox, BPMN import/export and a scheduler backed by ydx/cron, which may be private
// or supplied by the caller. It depends on no HTTP framework and no ORM: persistence is expressed by the
// Store interface and implemented by the gormstore subpackage for every dialect ydx/gorm supports. |
// Package workflow 实现一个可独立使用的 BPMN 2.0 工作流引擎，并内置中国式审批语义。
//
// 模块负责领域模型、基于令牌的执行引擎、审批动作、自动审批规则、通知 outbox、BPMN 导入导出与由 ydx/cron
// 驱动的调度器；该调度器可以是私有的，也可以由调用方提供。
// 它不依赖 HTTP 框架，也不依赖 ORM：持久化由 Store 接口表达，gormstore 子包为 ydx/gorm 支持的每种方言
// 提供实现。
package workflow
