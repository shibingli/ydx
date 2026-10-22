package ydrouter

import (
	"github.com/shibingli/ydx/openapi"
	"github.com/shibingli/ydx/router"
)

// FromRouter derives a document from the routes registered on r. | FromRouter 依据 r 上已注册的路由推导文档。
//
// Patterns are converted into OpenAPI path templates and their path parameters are merged
// into every operation, so /report/:id-xx.png becomes /report/{id}-xx.png and
// /static/*filepath becomes /static/{filepath}. | 模式会被转换为 OpenAPI 路径模板，其路径参数
// 会合并进每个操作，因此 /report/:id-xx.png 变为 /report/{id}-xx.png，/static/*filepath 变为
// /static/{filepath}。
//
// A nil router yields a document without paths, which keeps a disabled route table from
// failing the documentation endpoint. | 路由为 nil 时生成一份没有路径的文档，使未装配的路由表
// 不会让文档端点失败。
//
// o provides the fallback document title (Info.Title wins when set) and the type annotation
// sources (TypeAnnotations or SourceDirs). | o 提供文档标题兜底（Info.Title 非空时优先）与
// 类型注解来源（TypeAnnotations 或 SourceDirs）。
func FromRouter(r *router.Router, info openapi.Info, o openapi.Options) *openapi.Document {
	return FromRouterWithAnnotations(r, info, o, nil, nil)
}

// FromRouterWithAnnotations derives a document from the routes registered on r and merges the
// source annotations collected by openapi.ParseAnnotations. | FromRouterWithAnnotations 依据 r 上
// 已注册的路由推导文档，并合并由 openapi.ParseAnnotations 收集到的源码注解。
//
// Annotation keys use the converted path template ("GET /users/{id}"), so a hand written
// @Router block matches the route tree. Annotations take precedence over auto derivation;
// every other route gets a minimal operation with a default 200 response. | 注解键使用转换后的
// 路径模板（"GET /users/{id}"），手写的 @Router 注解因此能与路由树对上。注解优先于自动推导；
// 其余路由使用带默认 200 响应的最小操作。
//
// The report is filled with the coverage view (Matched, Missing, Orphan, Incomplete) and,
// when type annotations were merged, with AnnotatedTypes, UnannotatedTypes and EnumCount.
// Both annots and report may be nil. | report 会被写入覆盖视图（Matched、Missing、Orphan、
// Incomplete）；合并过类型注解时还会写入 AnnotatedTypes、UnannotatedTypes 与 EnumCount。
// annots 与 report 均允许为 nil。
func FromRouterWithAnnotations(r *router.Router, info openapi.Info, o openapi.Options,
	annots map[string]openapi.Annotation, report *openapi.Report) *openapi.Document {
	return openapi.FromRoutesWithAnnotations(Routes(r), info, o, annots, report)
}

// Routes converts the snapshot returned by r.Routes into openapi routes. | Routes 把 r.Routes
// 返回的快照转换为 openapi 路由。
//
// It is exported so callers can inspect, filter or extend the converted set before handing it
// to openapi.FromRoutes. | 导出它，是为了让调用方在交给 openapi.FromRoutes 之前检查、过滤或扩充
// 转换后的集合。
func Routes(r *router.Router) []openapi.Route {
	if r == nil {
		return nil
	}
	infos := r.Routes()
	out := make([]openapi.Route, 0, len(infos))
	for _, info := range infos {
		path, params := pathTemplate(info.Pattern)
		out = append(out, openapi.Route{Method: info.Method, Path: path, Params: params})
	}
	return out
}
