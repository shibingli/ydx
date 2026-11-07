package cas

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"

	"github.com/shibingli/ydx/json"
)

// casJSONContentType is the content type of CAS JSON protocol responses. | casJSONContentType 是
// CAS JSON 协议响应的内容类型。
const casJSONContentType = "application/json; charset=utf-8"

// validationFormat identifies the wire format of a validation response. | validationFormat 标识校验
// 响应的线格式。
type validationFormat int

const (
	// validationFormatXML selects the CAS 2.0/3.0 XML body or the CAS 1.0 plain-text body. |
	// validationFormatXML 选择 CAS 2.0/3.0 XML 正文或 CAS 1.0 纯文本正文。
	validationFormatXML validationFormat = iota
	// validationFormatJSON selects the CAS 3.0 JSON body. | validationFormatJSON 选择 CAS 3.0 JSON 正文。
	validationFormatJSON
)

// jsonAttributes is the CAS 3.0 JSON attributes object. It accepts both the protocol form, where
// every attribute maps to an array of strings, and the scalar form emitted by some CAS servers. |
// jsonAttributes 是 CAS 3.0 JSON 属性对象。它同时接受每个属性映射到字符串数组的协议形式，以及部分
// CAS 服务端发出的标量形式。
type jsonAttributes map[string][]string

// UnmarshalJSON implements json.Unmarshaler. | UnmarshalJSON 实现 json.Unmarshaler。
func (a *jsonAttributes) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if bytes.Equal(trimmed, []byte("null")) {
		*a = nil
		return nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	attributes := make(jsonAttributes, len(raw))
	for key, value := range raw {
		var list []string
		if err := json.Unmarshal(value, &list); err == nil {
			attributes[key] = list
			continue
		}
		var single string
		if err := json.Unmarshal(value, &single); err != nil {
			return err
		}
		attributes[key] = []string{single}
	}
	*a = attributes
	return nil
}

// jsonAuthenticationSuccess is the CAS 3.0 authenticationSuccess object. | jsonAuthenticationSuccess
// 是 CAS 3.0 authenticationSuccess 对象。
type jsonAuthenticationSuccess struct {
	// User is the protocol user identifier. | User 是协议用户标识。
	User string `json:"user"`
	// Attributes are the released user attributes. | Attributes 是发布的用户属性。
	Attributes jsonAttributes `json:"attributes,omitempty"`
	// ProxyGrantingTicket is the PGT identifier sent to the service, if any. | ProxyGrantingTicket
	// 是发送给服务的 PGT 标识（如有）。
	ProxyGrantingTicket string `json:"proxyGrantingTicket,omitempty"`
	// Proxies lists the pgtUrl of every proxy traversed by the ticket. | Proxies 列出票据经过的每个
	// 代理 pgtUrl。
	Proxies []string `json:"proxies,omitempty"`
}

// jsonAuthenticationFailure is the CAS 3.0 authenticationFailure object. | jsonAuthenticationFailure
// 是 CAS 3.0 authenticationFailure 对象。
type jsonAuthenticationFailure struct {
	// Code is the CAS protocol error code. | Code 是 CAS 协议错误码。
	Code string `json:"code"`
	// Description is the human-readable failure description. | Description 是人类可读的失败描述。
	Description string `json:"description"`
}

// jsonValidationEnvelope is the root object of a CAS 3.0 JSON validation response. | jsonValidationEnvelope
// 是 CAS 3.0 JSON 校验响应的根对象。
type jsonValidationEnvelope struct {
	// AuthenticationSuccess is set on success. | AuthenticationSuccess 在成功时设置。
	AuthenticationSuccess *jsonAuthenticationSuccess `json:"authenticationSuccess,omitempty"`
	// AuthenticationFailure is set on failure. | AuthenticationFailure 在失败时设置。
	AuthenticationFailure *jsonAuthenticationFailure `json:"authenticationFailure,omitempty"`
}

// validationResponseFormat selects the response dialect from the format parameter and, for the XML
// endpoints, the Accept header. An explicit format parameter always wins; format=xml (or an
// unrecognized value) preserves XML, and format=json selects JSON. The CAS 1.0 plain-text endpoint
// ignores Accept so that legacy clients keep receiving its yes/no body. | validationResponseFormat
// 从 format 参数以及 XML 端点的 Accept 头选择响应方言。显式 format 参数总是优先；format=xml（或
// 无法识别的值）保留 XML，format=json 选择 JSON。CAS 1.0 纯文本端点忽略 Accept，使旧客户端继续
// 收到 yes/no 正文。
func validationResponseFormat(r *http.Request, cas1 bool) validationFormat {
	if r == nil || r.URL == nil {
		return validationFormatXML
	}
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format"))) {
	case "json":
		return validationFormatJSON
	case "xml":
		return validationFormatXML
	case "":
	default:
		return validationFormatXML
	}
	if cas1 {
		return validationFormatXML
	}
	if prefersJSON(r.Header.Get("Accept")) {
		return validationFormatJSON
	}
	return validationFormatXML
}

// prefersJSON reports whether an Accept header prefers application/json over XML. Wildcards such as
// */* fall back to XML so the default protocol body never changes for clients that do not name a
// format. | prefersJSON 报告 Accept 头是否更偏好 application/json 而非 XML。*/* 之类的通配符回退到
// XML，因此未指明格式的客户端看到的默认协议正文不会改变。
func prefersJSON(accept string) bool {
	if strings.TrimSpace(accept) == "" {
		return false
	}
	jsonQuality, jsonPosition := -1.0, -1
	xmlQuality, xmlPosition := -1.0, -1
	for index, part := range strings.Split(accept, ",") {
		mediaType, quality := parseAcceptPart(part)
		if mediaType == "" || quality <= 0 {
			continue
		}
		switch {
		case mediaType == "application/json", strings.HasSuffix(mediaType, "+json"):
			if jsonQuality < 0 || quality > jsonQuality {
				jsonQuality, jsonPosition = quality, index
			}
		case mediaType == "text/xml", mediaType == "application/xml",
			mediaType == "text/*", mediaType == "application/*", mediaType == "*/*":
			if xmlQuality < 0 || quality > xmlQuality {
				xmlQuality, xmlPosition = quality, index
			}
		}
	}
	if jsonQuality <= 0 {
		return false
	}
	if xmlQuality <= 0 {
		return true
	}
	if jsonQuality != xmlQuality {
		return jsonQuality > xmlQuality
	}
	// Equal quality: the media range listed first wins. | 质量相同时排在前面的媒体范围胜出。
	return jsonPosition <= xmlPosition
}

// parseAcceptPart parses one comma-separated Accept entry into its media type and quality. | parseAcceptPart
// 把一个逗号分隔的 Accept 项解析为媒体类型与质量值。
func parseAcceptPart(part string) (string, float64) {
	quality := 1.0
	segments := strings.Split(part, ";")
	mediaType := strings.ToLower(strings.TrimSpace(segments[0]))
	for _, parameter := range segments[1:] {
		parameter = strings.TrimSpace(parameter)
		if len(parameter) < 2 || strings.ToLower(parameter[:2]) != "q=" {
			continue
		}
		value, err := strconv.ParseFloat(strings.TrimSpace(parameter[2:]), 64)
		if err != nil {
			return mediaType, 0
		}
		switch {
		case value < 0:
			value = 0
		case value > 1:
			value = 1
		}
		quality = value
	}
	return mediaType, quality
}

// writeValidationSuccessJSON writes a CAS 3.0 authenticationSuccess JSON body. | writeValidationSuccessJSON
// 写出 CAS 3.0 authenticationSuccess JSON 正文。
func writeValidationSuccessJSON(w http.ResponseWriter, result *validationResult) {
	if result == nil {
		result = &validationResult{}
	}
	writeCASJSON(w, jsonValidationEnvelope{
		AuthenticationSuccess: &jsonAuthenticationSuccess{
			User:                result.User,
			Attributes:          jsonAttributes(result.Attributes),
			ProxyGrantingTicket: result.ProxyGrantingTicket,
			Proxies:             result.Proxies,
		},
	})
}

// writeValidationFailureJSON writes a CAS 3.0 authenticationFailure JSON body. Protocol failures are
// carried in the body with HTTP 200, exactly like the XML dialect. | writeValidationFailureJSON 写出
// CAS 3.0 authenticationFailure JSON 正文。协议失败与 XML 方言一样由正文承载并使用 HTTP 200。
func writeValidationFailureJSON(w http.ResponseWriter, code, message string) {
	writeCASJSON(w, jsonValidationEnvelope{
		AuthenticationFailure: &jsonAuthenticationFailure{Code: code, Description: message},
	})
}

// writeCASJSON encodes value and writes it as a no-store JSON protocol response with status 200. |
// writeCASJSON 编码 value，并以状态 200 写出禁止缓存的 JSON 协议响应。
func writeCASJSON(w http.ResponseWriter, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		// The protocol payload only contains strings, slices and maps, so encoding cannot fail in
		// practice. Report a server error rather than an empty body if it ever does. | 协议载荷只含
		// 字符串、切片与映射，实际不会编码失败；若发生则报告服务端错误而不是空正文。
		body = []byte(`{"authenticationFailure":{"code":"INTERNAL_ERROR","description":"The response could not be encoded | 响应无法编码"}}`)
		w.Header().Set("Content-Type", casJSONContentType)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(body)
		return
	}
	w.Header().Set("Content-Type", casJSONContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
