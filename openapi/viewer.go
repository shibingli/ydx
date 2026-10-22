package openapi

import (
	"html"
	"strings"
)

// Viewer template placeholders. | 查看器模板占位符。
const (
	viewerTitlePlaceholder  = "__YD_OPENAPI_TITLE__"
	viewerDataPlaceholder   = "__YD_OPENAPI_DATA__"
	viewerScriptPlaceholder = "__YD_VIEWER_SCRIPT__"
	viewerCSSPlaceholder    = "__YD_VIEWER_CSS__"
	viewerIconsPlaceholder  = "__YD_VIEWER_ICONS__"
)

// renderViewer renders the self-contained viewer page. | renderViewer 渲染自包含的查看器页面。
//
// The page links only same-origin assets served by this module (stylesheet, script and icon
// sprite), never references an external CDN, and injects the document as an escaped JSON island
// that the script reads back. | 页面只引用本模块提供的同源资源（样式表、脚本与图标 sprite），
// 不引用任何外部 CDN，并把文档以转义后的 JSON 数据岛注入，由脚本读回。
func renderViewer(d *Document, o Options) ([]byte, error) {
	o = o.withDefaults()
	doc := d.normalized()
	raw, err := doc.JSON()
	if err != nil {
		return nil, err
	}
	return renderViewerWithJSON(doc, o, raw)
}

// renderViewerWithJSON renders the viewer from an already serialized document, so the handler
// can share one encoding between the JSON endpoint and the page. | renderViewerWithJSON 使用已
// 序列化的文档渲染查看器，使处理器能在 JSON 端点与页面之间共用一次编码。
func renderViewerWithJSON(doc Document, o Options, raw []byte) ([]byte, error) {
	o = o.withDefaults()
	// Insert the data first: a title containing the data placeholder would otherwise capture the
	// replacement and leave the script island holding the literal placeholder. | 先插入数据：
	// 否则包含数据占位符的标题会截获替换，让脚本岛里只剩字面占位符。
	page := strings.Replace(viewerTemplate, viewerDataPlaceholder, escapeJSONForScript(raw), 1)
	page = strings.Replace(page, viewerTitlePlaceholder, html.EscapeString(o.title(doc.Info)), 1)
	page = strings.Replace(page, viewerScriptPlaceholder, html.EscapeString(o.ViewerScript), 1)
	page = strings.Replace(page, viewerCSSPlaceholder, html.EscapeString(o.ViewerCSS), 1)
	// The icon sprite is referenced by every theme glyph, so all occurrences must be replaced. |
	// 图标 sprite 被每枚主题图标引用，必须替换全部出现位置。
	page = strings.ReplaceAll(page, viewerIconsPlaceholder, html.EscapeString(o.ViewerIcons))
	return []byte(page), nil
}

// escapeJSONForScript neutralises the characters that could break out of a script
// element. | escapeJSONForScript 中和可能突破 script 元素的字符。
//
// The replacement uses JSON unicode escapes, not HTML entities: script elements are raw text,
// so entities would be parsed literally and corrupt string values. | 替换使用 JSON 的 Unicode
// 转义而不是 HTML 实体：script 元素是原始文本，实体会被原样解析并破坏字符串内容。
func escapeJSONForScript(raw []byte) string {
	// The operands must be the JSON escape sequences, not the characters themselves; replacing a
	// character with itself is a no-op and leaves "</script>" able to terminate the element.
	// | 替换目标必须是 JSON 转义序列，而不是字符本身；把字符替换成它自己是空操作，会让
	// "</script>" 继续终止脚本元素。
	s := string(raw)
	s = strings.ReplaceAll(s, "<", `\u003c`)
	s = strings.ReplaceAll(s, ">", `\u003e`)
	s = strings.ReplaceAll(s, "&", `\u0026`)
	s = strings.ReplaceAll(s, "\u2028", `\u2028`)
	s = strings.ReplaceAll(s, "\u2029", `\u2029`)
	return s
}
