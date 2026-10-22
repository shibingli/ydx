// Package local contains the L1 cache benchmarks that live outside the component module,
// so github.com/shibingli/ydx/cache/local never depends on benchmark-only code. The
// comparisons with bigcache, freecache, ristretto, sync.Map and patrickmn/go-cache and the
// measured tables are documented in ../README.md. |
// Package local 保存位于组件模块之外的 L1 缓存基准，使
// github.com/shibingli/ydx/cache/local 不依赖基准专用代码。与 bigcache、freecache、
// ristretto、sync.Map 及 patrickmn/go-cache 的对比与实测表见 ../README.md。
package local
