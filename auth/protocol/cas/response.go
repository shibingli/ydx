package cas

import (
	"net/http"
	"sort"
	"strings"

	"github.com/shibingli/ydx/xml"
)

// casContentType is the content type of CAS XML protocol responses. | casContentType 是 CAS XML 协议响应的内容类型。
const casContentType = "text/xml; charset=utf-8"

// validationResult is the successful outcome of a ticket validation. | validationResult 是票据校验的成功结果。
type validationResult struct {
	// User is the protocol user identifier. | User 是协议用户标识。
	User string
	// Attributes are the released user attributes. | Attributes 是发布的用户属性。
	Attributes map[string][]string
	// ProxyGrantingTicket is the PGT identifier sent to the service, if any. | ProxyGrantingTicket 是发送给服务的 PGT 标识（如有）。
	ProxyGrantingTicket string
	// Proxies lists the pgtUrl of every proxy traversed by the ticket. | Proxies 列出票据经过的每个代理 pgtUrl。
	Proxies []string
}

// writeValidationSuccess writes a CAS 2.0 or 3.0 authenticationSuccess response. cas3 selects the
// <cas:attribute name="..." value="..."/> representation; otherwise attributes use one element per
// attribute name. | writeValidationSuccess 写出 CAS 2.0 或 3.0 的 authenticationSuccess 响应。cas3
// 选择 <cas:attribute name="..." value="..."/> 表示法；否则每个属性名使用一个元素。
func writeValidationSuccess(w http.ResponseWriter, result *validationResult, cas3 bool) {
	var b strings.Builder
	writeResponseHead(&b)
	b.WriteString("<cas:authenticationSuccess>")
	b.WriteString("<cas:user>")
	writeEscaped(&b, result.User)
	b.WriteString("</cas:user>")
	writeAttributes(&b, result.Attributes, cas3)
	if result.ProxyGrantingTicket != "" {
		b.WriteString("<cas:proxyGrantingTicket>")
		writeEscaped(&b, result.ProxyGrantingTicket)
		b.WriteString("</cas:proxyGrantingTicket>")
	}
	if len(result.Proxies) > 0 {
		b.WriteString("<cas:proxies>")
		for _, proxy := range result.Proxies {
			b.WriteString("<cas:proxy>")
			writeEscaped(&b, proxy)
			b.WriteString("</cas:proxy>")
		}
		b.WriteString("</cas:proxies>")
	}
	b.WriteString("</cas:authenticationSuccess>")
	b.WriteString("</cas:serviceResponse>")
	writeCASXML(w, b.String())
}

// writeValidationFailure writes a CAS 2.0 or 3.0 authenticationFailure response. | writeValidationFailure
// 写出 CAS 2.0 或 3.0 的 authenticationFailure 响应。
func writeValidationFailure(w http.ResponseWriter, code, message string) {
	var b strings.Builder
	writeResponseHead(&b)
	b.WriteString("<cas:authenticationFailure code=\"")
	writeEscaped(&b, code)
	b.WriteString("\">")
	writeEscaped(&b, message)
	b.WriteString("</cas:authenticationFailure>")
	b.WriteString("</cas:serviceResponse>")
	writeCASXML(w, b.String())
}

// writeCAS10Validation writes the CAS 1.0 plain-text validation response. | writeCAS10Validation 写出
// CAS 1.0 纯文本校验响应。
func writeCAS10Validation(w http.ResponseWriter, success bool, user string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if success {
		_, _ = w.Write([]byte("yes\n" + user + "\n"))
		return
	}
	_, _ = w.Write([]byte("no\n\n"))
}

// writeProxySuccess writes a successful CAS 2.0 proxy response. | writeProxySuccess 写出成功的 CAS 2.0 代理响应。
func writeProxySuccess(w http.ResponseWriter, proxyTicket string) {
	var b strings.Builder
	writeResponseHead(&b)
	b.WriteString("<cas:proxySuccess>")
	b.WriteString("<cas:proxyTicket>")
	writeEscaped(&b, proxyTicket)
	b.WriteString("</cas:proxyTicket>")
	b.WriteString("</cas:proxySuccess>")
	b.WriteString("</cas:serviceResponse>")
	writeCASXML(w, b.String())
}

// writeProxyFailure writes a failed CAS 2.0 proxy response. | writeProxyFailure 写出失败的 CAS 2.0 代理响应。
func writeProxyFailure(w http.ResponseWriter, code, message string) {
	var b strings.Builder
	writeResponseHead(&b)
	b.WriteString("<cas:proxyFailure code=\"")
	writeEscaped(&b, code)
	b.WriteString("\">")
	writeEscaped(&b, message)
	b.WriteString("</cas:proxyFailure>")
	b.WriteString("</cas:serviceResponse>")
	writeCASXML(w, b.String())
}

// writeResponseHead writes the XML declaration and the serviceResponse root. | writeResponseHead
// 写出 XML 声明与 serviceResponse 根元素。
func writeResponseHead(b *strings.Builder) {
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
	b.WriteString("<cas:serviceResponse xmlns:cas=\"")
	b.WriteString(casNamespace)
	b.WriteString("\">")
}

// writeAttributes writes the attributes element in the selected CAS dialect. | writeAttributes
// 按选定的 CAS 方言写出 attributes 元素。
func writeAttributes(b *strings.Builder, attributes map[string][]string, cas3 bool) {
	if len(attributes) == 0 {
		return
	}
	keys := make([]string, 0, len(attributes))
	for key := range attributes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	b.WriteString("<cas:attributes>")
	for _, key := range keys {
		for _, value := range attributes[key] {
			if cas3 {
				b.WriteString("<cas:attribute name=\"")
				writeEscaped(b, key)
				b.WriteString("\" value=\"")
				writeEscaped(b, value)
				b.WriteString("\"/>")
				continue
			}
			if !validXMLName(key) {
				// CAS 2.0 encodes the attribute name as an element name; a name that is not a
				// legal XML name cannot be represented and is skipped. | CAS 2.0 把属性名编码为
				// 元素名；不是合法 XML 名称的属性无法表示，因此跳过。
				continue
			}
			b.WriteString("<cas:")
			b.WriteString(key)
			b.WriteString(">")
			writeEscaped(b, value)
			b.WriteString("</cas:")
			b.WriteString(key)
			b.WriteString(">")
		}
	}
	b.WriteString("</cas:attributes>")
}

// writeCASXML writes a complete CAS XML body with status 200. Protocol errors are carried in the
// body, not the HTTP status. | writeCASXML 以状态码 200 写出完整 CAS XML 正文。协议错误由正文承载，
// 而不是 HTTP 状态码。
func writeCASXML(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", casContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

// writeEscaped writes s as escaped XML text. | writeEscaped 把 s 作为转义后的 XML 文本写出。
func writeEscaped(b *strings.Builder, s string) {
	if s == "" {
		return
	}
	_ = xml.EscapeText(b, []byte(s))
}

// validXMLName reports whether name is a conservative XML name suitable for a CAS 2.0 attribute
// element. | validXMLName 报告 name 是否为适合 CAS 2.0 属性元素的保守 XML 名称。
func validXMLName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case i > 0 && (c >= '0' && c <= '9' || c == '-' || c == '.' || c == ':'):
		default:
			return false
		}
	}
	return true
}
