package saml

import (
	"io"
	"net/http"
	"strings"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/xml"
)

// SOAPVersion identifies the SOAP envelope version negotiated with a peer. | SOAPVersion 标识与对端
// 协商的 SOAP 信封版本。
type SOAPVersion string

// SOAP envelope versions. | SOAP 信封版本。
const (
	// SOAPVersion11 selects SOAP 1.1 envelopes, the SAML default. | SOAPVersion11 选择 SOAP 1.1
	// 信封，也是 SAML 的默认值。
	SOAPVersion11 SOAPVersion = "1.1"
	// SOAPVersion12 selects SOAP 1.2 envelopes. | SOAPVersion12 选择 SOAP 1.2 信封。
	SOAPVersion12 SOAPVersion = "1.2"
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
	// NamespaceSOAP12 is the SOAP 1.2 envelope namespace. | NamespaceSOAP12 是 SOAP 1.2 信封命名空间。
	NamespaceSOAP12 = "http://www.w3.org/2003/05/soap-envelope"
	// SOAPContentType is the SOAP 1.1 content type. | SOAPContentType 是 SOAP 1.1 内容类型。
	SOAPContentType = "text/xml; charset=utf-8"
	// SOAPContentType12 is the SOAP 1.2 content type. | SOAPContentType12 是 SOAP 1.2 内容类型。
	SOAPContentType12 = "application/soap+xml; charset=utf-8"
)

// SOAPFault is a SOAP Fault returned by a peer. It matches ErrSOAPFault through errors.Is. |
// SOAPFault 是对端返回的 SOAP 异常。它通过 errors.Is 匹配 ErrSOAPFault。
type SOAPFault struct {
	// Code is the fault code, such as soap:Client or env:Sender. | Code 是异常码，例如 soap:Client
	// 或 env:Sender。
	Code string
	// Reason is the human-readable fault reason. | Reason 是人类可读的异常原因。
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

// soapNamespace returns the envelope namespace of version, defaulting to SOAP 1.1. | soapNamespace
// 返回 version 的信封命名空间，默认 SOAP 1.1。
func soapNamespace(version SOAPVersion) string {
	if version == SOAPVersion12 {
		return NamespaceSOAP12
	}
	return NamespaceSOAP
}

// soapContentType returns the content type of version, defaulting to SOAP 1.1. | soapContentType 返回
// version 的内容类型，默认 SOAP 1.1。
func soapContentType(version SOAPVersion) string {
	if version == SOAPVersion12 {
		return SOAPContentType12
	}
	return SOAPContentType
}

// buildSOAPEnvelope wraps an already-serialized SAML protocol element in a SOAP 1.1 envelope. |
// buildSOAPEnvelope 把已序列化的 SAML 协议元素包装为 SOAP 1.1 信封。
func buildSOAPEnvelope(payload []byte) []byte {
	return buildSOAPEnvelopeVersion(SOAPVersion11, payload)
}

// buildSOAPEnvelopeVersion wraps payload in an envelope of version. | buildSOAPEnvelopeVersion 把
// payload 包装为 version 版本的信封。
func buildSOAPEnvelopeVersion(version SOAPVersion, payload []byte) []byte {
	prefix := `<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="` +
		soapNamespace(version) + `"><soapenv:Body>`
	const suffix = `</soapenv:Body></soapenv:Envelope>`
	out := make([]byte, 0, len(prefix)+len(payload)+len(suffix))
	out = append(out, prefix...)
	out = append(out, payload...)
	out = append(out, suffix...)
	return out
}

// writeSOAPPayload writes a SOAP 1.1 envelope carrying payload. | writeSOAPPayload 写入携带 payload
// 的 SOAP 1.1 信封。
func writeSOAPPayload(w http.ResponseWriter, payload []byte) {
	writeSOAPPayloadVersion(w, SOAPVersion11, payload)
}

// writeSOAPPayloadVersion writes a SOAP envelope of version carrying payload. | writeSOAPPayloadVersion
// 写入携带 payload 的 version 版本 SOAP 信封。
func writeSOAPPayloadVersion(w http.ResponseWriter, version SOAPVersion, payload []byte) {
	body := buildSOAPEnvelopeVersion(version, payload)
	w.Header().Set("Content-Type", soapContentType(version))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// writeSOAPFault writes a SOAP 1.1 Fault envelope with the given HTTP status. | writeSOAPFault 以给定
// HTTP 状态写入 SOAP 1.1 异常信封。
func writeSOAPFault(w http.ResponseWriter, status int, code, reason string) {
	writeSOAPFaultVersion(w, SOAPVersion11, status, code, reason)
}

// writeSOAPFaultVersion writes a SOAP Fault envelope of version with the given HTTP status. SOAP 1.2
// faults use Code/Value and Reason/Text with the env:Sender and env:Receiver codes. |
// writeSOAPFaultVersion 以给定 HTTP 状态写入 version 版本的 SOAP 异常信封。SOAP 1.2 异常使用
// Code/Value 与 Reason/Text，并采用 env:Sender 与 env:Receiver 代码。
func writeSOAPFaultVersion(w http.ResponseWriter, version SOAPVersion, status int, code, reason string) {
	var fault string
	if version == SOAPVersion12 {
		fault = `<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="` + NamespaceSOAP12 +
			`"><soapenv:Body><soapenv:Fault><soapenv:Code><soapenv:Value>` + htmlEscape(soap12FaultCode(code)) +
			`</soapenv:Value></soapenv:Code><soapenv:Reason><soapenv:Text xml:lang="en">` + htmlEscape(reason) +
			`</soapenv:Text></soapenv:Reason></soapenv:Fault></soapenv:Body></soapenv:Envelope>`
	} else {
		fault = `<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="` + NamespaceSOAP +
			`"><soapenv:Body><soapenv:Fault><faultcode>` + htmlEscape(code) +
			`</faultcode><faultstring>` + htmlEscape(reason) + `</faultstring></soapenv:Fault></soapenv:Body></soapenv:Envelope>`
	}
	w.Header().Set("Content-Type", soapContentType(version))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(fault))
}

// soap12FaultCode maps a SOAP 1.1-style fault code to a SOAP 1.2 fault code. | soap12FaultCode 把
// SOAP 1.1 风格异常码映射为 SOAP 1.2 异常码。
func soap12FaultCode(code string) string {
	lower := strings.ToLower(strings.TrimSpace(code))
	if strings.HasSuffix(lower, "client") || strings.HasSuffix(lower, "sender") {
		return "env:Sender"
	}
	return "env:Receiver"
}

// soapVersionFromContentType returns the SOAP version implied by a content type, or an empty version
// when the media type is not a SOAP media type. | soapVersionFromContentType 返回内容类型隐含的 SOAP
// 版本；不是 SOAP 媒体类型时返回空版本。
func soapVersionFromContentType(contentType string) SOAPVersion {
	mediaType := strings.ToLower(strings.TrimSpace(contentType))
	if index := strings.IndexByte(mediaType, ';'); index >= 0 {
		mediaType = strings.TrimSpace(mediaType[:index])
	}
	switch mediaType {
	case "application/soap+xml":
		return SOAPVersion12
	case "text/xml":
		return SOAPVersion11
	default:
		return ""
	}
}

// soapActionFromContentType returns the action parameter of a SOAP 1.2 content type. | soapActionFromContentType
// 返回 SOAP 1.2 内容类型的 action 参数。
func soapActionFromContentType(contentType string) string {
	parts := strings.Split(contentType, ";")
	for _, part := range parts[1:] {
		key, value, ok := strings.Cut(part, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "action") {
			continue
		}
		return strings.Trim(strings.TrimSpace(value), `"'`)
	}
	return ""
}

// soapRequestVersion returns the SOAP version declared by r, defaulting to SOAP 1.1. | soapRequestVersion
// 返回 r 声明的 SOAP 版本，默认 SOAP 1.1。
func soapRequestVersion(r *http.Request) SOAPVersion {
	if r == nil {
		return SOAPVersion11
	}
	if version := soapVersionFromContentType(r.Header.Get("Content-Type")); version != "" {
		return version
	}
	return SOAPVersion11
}

// checkSOAPAction accepts a missing SOAPAction header and rejects a mismatched one. Quoted and
// unquoted action values are both accepted; a SOAP 1.2 action parameter in the content type is used
// when the header is absent. | checkSOAPAction 接受缺失的 SOAPAction 头并拒绝不匹配的取值。带引号与
// 不带引号的取值均可接受；头缺失时使用内容类型中的 SOAP 1.2 action 参数。
func checkSOAPAction(r *http.Request, want string) error {
	if r == nil {
		return errs.Detail(ErrInvalidRequest, "request is nil | 请求为空")
	}
	action := strings.TrimSpace(r.Header.Get("SOAPAction"))
	action = strings.Trim(action, `"'`)
	if action == "" {
		action = soapActionFromContentType(r.Header.Get("Content-Type"))
	}
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

// soapEnvelope is a parsed SOAP 1.1 or SOAP 1.2 envelope. | soapEnvelope 是解析后的 SOAP 1.1 或
// SOAP 1.2 信封。
type soapEnvelope struct {
	root    *xml.Node
	body    *xml.Node
	version SOAPVersion
}

// parseSOAPEnvelope parses and validates a SOAP 1.1 or SOAP 1.2 envelope. | parseSOAPEnvelope 解析并
// 校验 SOAP 1.1 或 SOAP 1.2 信封。
func parseSOAPEnvelope(message []byte) (*soapEnvelope, error) {
	document, err := xml.Parse(message)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidRequest, "SOAP envelope | SOAP 信封")
	}
	root := document.Root
	if root == nil || root.Name.Local != "Envelope" {
		return nil, errs.Detail(ErrInvalidRequest, "SOAP Envelope is missing | 缺少 SOAP Envelope")
	}
	version := SOAPVersion("")
	switch root.Name.Space {
	case NamespaceSOAP:
		version = SOAPVersion11
	case NamespaceSOAP12:
		version = SOAPVersion12
	default:
		return nil, errs.Detail(ErrInvalidRequest, "SOAP Envelope namespace %[1]q | SOAP Envelope 命名空间 %[1]q", root.Name.Space)
	}
	body := root.FirstChild("Body")
	if body == nil || body.Name.Space != root.Name.Space {
		return nil, errs.Detail(ErrInvalidRequest, "SOAP Body is missing | 缺少 SOAP Body")
	}
	return &soapEnvelope{root: root, body: body, version: version}, nil
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
		if child.Name.Local == "Fault" && (child.Name.Space == NamespaceSOAP || child.Name.Space == NamespaceSOAP12 || child.Name.Space == "") {
			return nil, parseSOAPFault(child)
		}
		return child, nil
	}
	return nil, errs.Detail(ErrInvalidRequest, "SOAP body is empty | SOAP 正文为空")
}

// parseSOAPFault converts a SOAP 1.1 or SOAP 1.2 Fault element to *SOAPFault. | parseSOAPFault 把
// SOAP 1.1 或 SOAP 1.2 Fault 元素转换为 *SOAPFault。
func parseSOAPFault(node *xml.Node) *SOAPFault {
	fault := &SOAPFault{}
	if node == nil {
		return fault
	}
	if node.Name.Space == NamespaceSOAP12 {
		if code := node.FirstChild("Code"); code != nil {
			if value := code.FirstChild("Value"); value != nil {
				fault.Code = strings.TrimSpace(value.Text())
			}
		}
		if reason := node.FirstChild("Reason"); reason != nil {
			if text := reason.FirstChild("Text"); text != nil {
				fault.Reason = strings.TrimSpace(text.Text())
			}
		}
		if fault.Code == "" {
			fault.Code = "env:Receiver"
		}
		return fault
	}
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
