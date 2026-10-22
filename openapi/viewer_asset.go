// Package openapi embeds the viewer script so the documentation page is self-contained. | Package openapi
// 内嵌查看器脚本，使文档页面自包含。
package openapi

import _ "embed"

// viewerScript holds the embedded viewer JavaScript. | viewerScript 保存内嵌的查看器 JavaScript。
//
//go:embed assets/yd-openapi-viewer.js
var viewerScript []byte

// ViewerScript returns a copy of the embedded viewer JavaScript. | ViewerScript 返回内嵌查看器
// JavaScript 的副本。
//
// Callers that package the viewer through their own static pipeline can embed or write these
// bytes themselves and point Options.ViewerScript at the resulting URL. The default handler serves
// the same bytes under Options.AssetsPath + ViewerScriptName. | 通过自有静态管线打包查看器的调用方
// 可以自行嵌入或写出这些字节，并把 Options.ViewerScript 指向最终 URL；默认处理器会在
// Options.AssetsPath + ViewerScriptName 下提供同样的字节。
func ViewerScript() []byte {
	return append([]byte(nil), viewerScript...)
}
