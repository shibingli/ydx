package openapi

// ViewerPage renders the standalone viewer page for d. | ViewerPage 为 d 渲染可独立使用的查看器页面。
//
// The returned bytes form a complete HTML document with the document embedded as a JSON island.
// A caller can write them to disk and serve them with any static file server, including a plain
// http.FileServer, then serve ViewerScript() next to it and set Options.ViewerScript to that URL:
// | 返回的字节是完整 HTML 文档，文档以 JSON 数据岛内嵌。调用方可以把它写入磁盘，并用任意静态文件
// 服务器（包括原生 http.FileServer）托管；把 ViewerScript() 放在它旁边，并把 Options.ViewerScript
// 指向该 URL：
//
//	page, err := openapi.ViewerPage(doc, openapi.Options{ViewerScript: "./yd-openapi-viewer.js"})
//	os.WriteFile("public/docs/index.html", page, 0o644)
//	os.WriteFile("public/docs/yd-openapi-viewer.js", openapi.ViewerScript(), 0o644)
//
// When ViewerScript is left empty the page references the default AssetsPath URL, which the
// HTTPHandler/Handler serves. | ViewerScript 留空时，页面引用默认的 AssetsPath URL，由
// HTTPHandler/Handler 提供。
func ViewerPage(d *Document, o Options) ([]byte, error) {
	if d == nil {
		d = &Document{}
	}
	return renderViewer(d, o)
}
