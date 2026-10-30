package cron

import "github.com/shibingli/ydx/router"

// Mount registers the administrative API on a ydx/router Router. This is the
// primary, router-native entry point; HTTPHandler is the plain net/http adapter
// built from the same route table. | Mount 把管理 API 注册到 ydx/router 的 Router 上；
// 这是首选的、路由原生的入口，HTTPHandler 是由同一路由表构建的纯 net/http 适配器。
//
// Every route is registered explicitly, so the router owns method matching,
// 404/405 handling and route listing: | 每条路由显式注册，方法匹配、404/405 与路由列表由路由器负责：
//
//	GET    <prefix>/jobs
//	POST   <prefix>/jobs
//	GET    <prefix>/jobs/:id
//	PUT    <prefix>/jobs/:id
//	DELETE <prefix>/jobs/:id
//	POST   <prefix>/jobs/:id/pause
//	POST   <prefix>/jobs/:id/resume
//	POST   <prefix>/jobs/:id/trigger
//	GET    <prefix>/jobs/:id/history
//	GET    <prefix>/stats
//	POST   <prefix>/reload
//
// The API still performs no authentication; wrap the routes with the
// application's admin middleware. A nil router reports ErrNilRouter. |
// API 仍不内建认证，请为这些路由套用应用的管理中间件。nil 路由器返回 ErrNilRouter。
func (s *Scheduler) Mount(r *router.Router, prefix string) error {
	if r == nil {
		return ErrNilRouter
	}
	s.mountRoutes(r, prefix)
	return nil
}
