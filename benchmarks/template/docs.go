// Package template benchmarks template engines on one shared page workload and verifies that
// every engine produces the same HTML. The module is independent of the product modules: it
// therefore never pulls benchmark-only dependencies into ydx/runtime consumers. | Package template
// 在同一份页面负载上对比各模板引擎，并校验每个引擎产出相同的 HTML。该模块独立于产品模块，
// 因此不会把仅用于基准的依赖带进 ydx 的使用方。
package template
