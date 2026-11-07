package saml

import (
	"io"
	"net/http"
	"strings"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/xml"
)

// SOAP binding constants. | SOAP 绑定常量。
const (
	// SOAPActionArtifactResolve is the SOAPAction of an ArtifactResolve message. | SOAPActionArtifactResolve
	// 是 ArtifactResolve 消息的 SOAPAction。
	SOAPActionArtifactResolve = "urn:oasis:names:tc:SAML:2.0:protocol:ArtifactResolve"
	// SOAPActionArtifactResponse is the SOAPAction of an ArtifactResponse message. | SOAPActionArtifactResponse
	// 是 ArtifactResponse 消息的 SOAPAction。
	SOAPActionArtifactResponse = "urn:oasis:names:tc:SAML:2.0:protocol:ArtifactResponse"
	// MaxSOAPMessageBytes bounds one SOAP request or response body. | MaxSOAPMessageBytes 约束单个
	// SOAP 请求或响应正文。
	MaxSOAPMessageBytes = MaxSAMLMessageBytes
	// SOAPContentType is the SOAP 1.1 content type. | SOAPContentType 是 SOAP 1.1 内容类型。
	SOAPContentType = "text/xml; charset=utf-8"
)

// SOAPFault is a SOAP 1.1 Fault returned by a peer. It matches ErrSOAPFault through errors.Is. |
// SOAPFault 是对端返回的 SOAP 1.1 异常。它通过 errors.Is 匹配 ErrSOAPFault。
type SOAPFault struct {
	// Code is the faultcode value, such as soap:Client. | Code 是 faultcode 取值，例如 soap:Client。
	Code string
	// Reason is the faultstring value. | Reason 是 faultstring 取值。
	Reason string
}

// Error returns the fault description. | Error 返回异常描述。
func (f *SOAPFault) Error() string {
	if f == nil {
		return ErrSOAPFault.Error()
	}
	if f.Reason != "" {
		return "saml: SOAP fault " + f.Code + ": " + f.Reason + " | saml：SOAP 异常 " + f.Code + "：" + f.Reason
	}
	return "saml: SOAP fault " + f.Code + " | saml：SOAP 异常 " + f.Code
}

// Unwrap returns ErrSOAPFault. | Unwrap 返回 ErrSOAPFault。
func (f *SOAPFault) Unwrap() error { return ErrSOAPFault }

// buildSOAPEnvelope wraps an already-serialized SAML protocol element in a SOAP 1.1 envelope. |
// buildSOAPEnvelope 把已序列化的 SAML 协议元素包装为 SOAP 1.1 信封。
func buildSOAPEnvelope(payload []byte) []byte {
	const prefix = `<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="` +
		NamespaceSOAP + `"><soapenv:Body>`
	const suffix = `</soapenv:Body></soapenv:Envelope>`
	out := make([]byte, 0, len(prefix)+len(payload)+len(suffix))
	out = append(out, prefix...)
	out = append(out, payload...)
	out = append(out, suffix...)
	return out
}

// writeSOAPPayload writes a SOAP envelope carrying payload. | writeSOAPPayload 写入携带 payload 的
// SOAP 信封。
func writeSOAPPayload(w http.ResponseWriter, payload []byte) {
	body := buildSOAPEnvelope(payload)
	w.Header().Set("Content-Type", SOAPContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// writeSOAPFault writes a SOAP 1.1 Fault envelope with the given HTTP status. | writeSOAPFault 以给定
// HTTP 状态写入 SOAP 1.1 异常信封。
func writeSOAPFault(w http.ResponseWriter, status int, code, reason string) {
	fault := `<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="` + NamespaceSOAP +
		`"><soapenv:Body><soapenv:Fault><faultcode>` + htmlEscape(code) +
		`</faultcode><faultstring>` + htmlEscape(reason) + `</faultstring></soapenv:Fault></soapenv:Body></soapenv:Envelope>`
	w.Header().Set("Content-Type", SOAPContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(fault))
}

// checkSOAPAction accepts a missing SOAPAction header and rejects a mismatched one. Quoted and
// unquoted action values are both accepted. | checkSOAPAction 接受缺失的 SOAPAction 头并拒绝不匹配
// 的取值。带引号与不带引号的取值均可接受。
func checkSOAPAction(r *http.Request, want string) error {
	if r == nil {
		return errs.Detail(ErrInvalidRequest, "request is nil | 请求为空")
	}
	action := strings.TrimSpace(r.Header.Get("SOAPAction"))
	action = strings.Trim(action, `"'`)
	if action == "" || action == want {
		return nil
	}
	return errs.Detail(ErrInvalidRequest, "SOAPAction %[1]q | SOAPAction %[1]q", action)
}

// readSOAPBody reads a SOAP request body bounded by MaxSOAPMessageBytes. | readSOAPBody 读取受
// MaxSOAPMessageBytes 约束的 SOAP 请求正文。
func readSOAPBody(r *http.Request) ([]byte, error) {
	if r == nil || r.Body == nil {
		return nil, errs.Detail(ErrInvalidRequest, "SOAP body is missing | 缺少 SOAP 正文")
	}
	if r.ContentLength > MaxSOAPMessageBytes {
		return nil, errs.Detail(ErrLimit, "SOAP body exceeds %d bytes | SOAP 正文超过 %d 字节", MaxSOAPMessageBytes, MaxSOAPMessageBytes)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxSOAPMessageBytes+1))
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidRequest, "SOAP body | SOAP 正文")
	}
	if len(body) > MaxSOAPMessageBytes {
		return nil, errs.Detail(ErrLimit, "SOAP body exceeds %d bytes | SOAP 正文超过 %d 字节", MaxSOAPMessageBytes, MaxSOAPMessageBytes)
	}
	return body, nil
}

// soapEnvelope is a parsed SOAP 1.1 envelope. | soapEnvelope 是解析后的 SOAP 1.1 信封。
type soapEnvelope struct {
	root *xml.Node
	body *xml.Node
}

// parseSOAPEnvelope parses and validates a SOAP 1.1 envelope. | parseSOAPEnvelope 解析并校验 SOAP 1.1
// 信封。
func parseSOAPEnvelope(message []byte) (*soapEnvelope, error) {
	document, err := xml.Parse(message)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidRequest, "SOAP envelope | SOAP 信封")
	}
	root := document.Root
	if root == nil || root.Name.Local != "Envelope" || root.Name.Space != NamespaceSOAP {
		return nil, errs.Detail(ErrInvalidRequest, "SOAP Envelope is missing | 缺少 SOAP Envelope")
	}
	body := root.FirstChild("Body")
	if body == nil || body.Name.Space != NamespaceSOAP {
		return nil, errs.Detail(ErrInvalidRequest, "SOAP Body is missing | 缺少 SOAP Body")
	}
	return &soapEnvelope{root: root, body: body}, nil
}

// payload returns the first element child of the SOAP body, reporting a SOAP Fault as ErrSOAPFault.
// | payload 返回 SOAP 正文的首个元素子节点；遇到 SOAP 异常时以 ErrSOAPFault 报告。
func (e *soapEnvelope) payload() (*xml.Node, error) {
	if e == nil || e.body == nil {
		return nil, errs.Detail(ErrInvalidRequest, "SOAP body is missing | 缺少 SOAP Body")
	}
	for _, child := range e.body.Children {
		if child.Kind != xml.ElementNode {
			continue
		}
		if child.Name.Local == "Fault" && (child.Name.Space == NamespaceSOAP || child.Name.Space == "") {
			return nil, parseSOAPFault(child)
		}
		return child, nil
	}
	return nil, errs.Detail(ErrInvalidRequest, "SOAP body is empty | SOAP 正文为空")
}

// parseSOAPFault converts a SOAP Fault element to *SOAPFault. | parseSOAPFault 把 SOAP Fault 元素
// 转换为 *SOAPFault。
func parseSOAPFault(node *xml.Node) *SOAPFault {
	fault := &SOAPFault{}
	if code := node.FirstChild("faultcode"); code != nil {
		fault.Code = strings.TrimSpace(code.Text())
	}
	if reason := node.FirstChild("faultstring"); reason != nil {
		fault.Reason = strings.TrimSpace(reason.Text())
	}
	if fault.Code == "" {
		fault.Code = "soap:Server"
	}
	return fault
}
