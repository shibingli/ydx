// Package xml benchmarks github.com/shibingli/ydx/xml against encoding/xml and the mainstream
// third-party XML libraries etree, xmlquery (XPath) and mxj, and checks their extraction results
// on a shared corpus. | Package xml 将 github.com/shibingli/ydx/xml 与 encoding/xml 及主流第三方
// XML 库 etree、xmlquery（XPath）、mxj 做性能对比，并在共享语料上校验提取结果的一致性。
//
// The module is a benchmark-only module: it may depend on benchmark libraries and must never be
// imported by product modules. | 本模块是基准专用模块：可以依赖基准库，产品模块不得导入它。
//
// Release gate: the module requires github.com/shibingli/ydx/xml v0.1.0. Until that tag is
// published, run it through a temporary go.work outside the repository that includes both the
// xml and benchmarks/xml modules; never commit a replace directive. | 发布门禁：本模块依赖
// github.com/shibingli/ydx/xml v0.1.0。在该标签发布之前，请在仓库之外创建临时 go.work，同时纳入
// xml 与 benchmarks/xml 两个模块后运行；不得提交 replace。
package xml
