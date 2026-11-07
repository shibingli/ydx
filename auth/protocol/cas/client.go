package cas

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/xml"
)

// defaultClientTimeout bounds a single CAS client exchange. | defaultClientTimeout 限定单次 CAS 客户端交换。
const defaultClientTimeout = 10 * time.Second

// ClientConfig configures a CAS client. | ClientConfig 配置 CAS 客户端。
type ClientConfig struct {
	// HTTPClient performs the protocol requests. Nil uses a client with a 10 second timeout that
	// refuses redirects, so a ticket is never forwarded to an unexpected host. | HTTPClient 执行
	// 协议请求。空值使用超时 10 秒且拒绝重定向的客户端，使票据绝不会被转发到意外主机。
	HTTPClient *http.Client
	// ServerURL is the CAS server base URL, for example "https://cas.example.com/cas". |
	// ServerURL 是 CAS 服务端基础 URL，例如 "https://cas.example.com/cas"。
	ServerURL string
	// ServiceURL is the default service URL used when a call leaves it empty. | ServiceURL 是调用
	// 未提供时使用的默认服务 URL。
	ServiceURL string
	// ValidationFormat selects the validation response dialect: "xml" (default, empty) or "json".
	// JSON requests the CAS 3.0 JSON view with format=json and an application/json Accept header;
	// the response parser detects the actual body, so a server that ignores the request still works.
	// ValidateCAS10 always uses the CAS 1.0 plain-text protocol. | ValidationFormat 选择校验响应
	// 方言："xml"（默认，空值）或 "json"。JSON 通过 format=json 与 application/json Accept 头请求
	// CAS 3.0 JSON 视图；响应解析器检测实际正文，因此忽略该请求的服务端仍可工作。ValidateCAS10 始终
	// 使用 CAS 1.0 纯文本协议。
	ValidationFormat string
}

// Client speaks the CAS 1.0, 2.0 and 3.0 client protocols against a remote server. | Client 以
// CAS 1.0、2.0 与 3.0 客户端协议访问远程服务端。
//
// A Client is immutable after construction and safe for concurrent use. | Client 构造后不可变，可并发使用。
type Client struct {
	config     ClientConfig
	httpClient *http.Client
	baseURL    string
}

// ValidationResponse is the parsed answer of a ticket validation. | ValidationResponse 是票据校验的解析结果。
type ValidationResponse struct {
	// Attributes are the released user attributes; keys map to every released value. | Attributes
	// 是发布的用户属性；键映射到全部已发布值。
	Attributes map[string][]string
	// User is the protocol user identifier. | User 是协议用户标识。
	User string
	// ProxyGrantingTicket is the PGT identifier issued through pgtUrl, if any. | ProxyGrantingTicket
	// 是通过 pgtUrl 签发的 PGT 标识（如有）。
	ProxyGrantingTicket string
	// Code is the protocol failure code, empty on success. | Code 是协议失败码，成功时为空。
	Code string
	// Message is the human-readable failure message, empty on success. | Message 是人类可读的失败消息，成功时为空。
	Message string
	// Proxies lists the proxy callback URLs traversed by the ticket. | Proxies 列出票据经过的代理回调 URL。
	Proxies []string
	// Raw is the complete protocol body. | Raw 是完整的协议正文。
	Raw []byte
	// Success reports a successful validation. | Success 表示校验成功。
	Success bool
}

// ProxyResponse is the parsed answer of a proxy ticket request. | ProxyResponse 是代理票据请求的解析结果。
type ProxyResponse struct {
	// ProxyTicket is the issued PT identifier. | ProxyTicket 是已签发的 PT 标识。
	ProxyTicket string
	// Code is the protocol failure code, empty on success. | Code 是协议失败码，成功时为空。
	Code string
	// Message is the human-readable failure message, empty on success. | Message 是人类可读的失败消息，成功时为空。
	Message string
	// Raw is the complete protocol body. | Raw 是完整的协议正文。
	Raw []byte
	// Success reports a successful proxy ticket issuance. | Success 表示代理票据签发成功。
	Success bool
}

// NewClient validates config and returns a CAS client. | NewClient 校验 config 并返回 CAS 客户端。
func NewClient(config ClientConfig) (*Client, error) {
	base := strings.TrimSpace(config.ServerURL)
	if base == "" {
		return nil, errs.Detail(ErrInvalidConfig, "server URL is required | server URL 必填")
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidConfig, "server URL %[1]q cannot be parsed | server URL %[1]q 无法解析", base)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if parsed.Host == "" || (scheme != "https" && scheme != "http") {
		return nil, errs.Detail(ErrInvalidConfig, "server URL %[1]q must be an absolute http(s) URL | server URL %[1]q 必须是绝对 http(s) URL", base)
	}
	config.ServerURL = base
	config.ServiceURL = strings.TrimSpace(config.ServiceURL)
	switch format := strings.ToLower(strings.TrimSpace(config.ValidationFormat)); format {
	case "", "xml":
		config.ValidationFormat = ""
	case "json":
		config.ValidationFormat = "json"
	default:
		return nil, errs.Detail(ErrInvalidConfig, "validation format %[1]q must be xml or json | 校验格式 %[1]q 必须是 xml 或 json", config.ValidationFormat)
	}
	client := &Client{
		config:  config,
		baseURL: strings.TrimRight(parsed.String(), "/"),
	}
	client.httpClient = config.HTTPClient
	if client.httpClient == nil {
		client.httpClient = &http.Client{
			Timeout: defaultClientTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return client, nil
}

// Config returns a copy of the client configuration. | Config 返回客户端配置副本。
func (c *Client) Config() ClientConfig { return c.config }

// LoginURL returns the login URL that sends the browser to service after authentication. | LoginURL
// 返回认证后把浏览器送往 service 的登录 URL。
func (c *Client) LoginURL(service string) string {
	endpoint := c.baseURL + "/login"
	if service == "" {
		return endpoint
	}
	query := url.Values{}
	query.Set("service", service)
	return endpoint + "?" + query.Encode()
}

// LogoutURL returns the logout URL, optionally asking the server to redirect to service afterwards.
// The service must be registered on the server for the redirect to happen. | LogoutURL 返回登出 URL，
// 可选择要求服务端随后重定向到 service。只有当 service 已在服务端注册时才会发生重定向。
func (c *Client) LogoutURL(service string) string {
	endpoint := c.baseURL + "/logout"
	if service == "" {
		return endpoint
	}
	query := url.Values{}
	query.Set("service", service)
	return endpoint + "?" + query.Encode()
}

// SendLogoutRequest sends a back-channel SAML 1.1 logout request to the CAS /logout endpoint. At
// least one of nameIdentifier and sessionIndex must be non-empty. A non-2xx answer is reported as
// ErrClientRequest. The request is the same one a service sends when its own session ends. |
// SendLogoutRequest 向后端 CAS /logout 端点发送 SAML 1.1 登出请求。nameIdentifier 与 sessionIndex
// 至少一个非空。非 2xx 应答报告为 ErrClientRequest。该请求与服务在自身会话结束时发送的请求相同。
func (c *Client) SendLogoutRequest(ctx context.Context, nameIdentifier, sessionIndex string) error {
	document, err := BuildLogoutRequest(nameIdentifier, sessionIndex, time.Now().UTC())
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	form := url.Values{}
	form.Set(logoutRequestParameter, string(document))
	target := c.baseURL + "/logout"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return errs.WrapDetail(err, ErrClientRequest, "cannot build logout request | 无法构建登出请求")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "text/plain, text/xml")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return errs.WrapDetail(err, ErrClientRequest, "logout request failed | 登出请求失败")
	}
	defer func() {
		_ = response.Body.Close()
	}()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxLogoutResponseBody))
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return errs.Detail(ErrClientRequest, "logout answered with status %[1]d | 登出返回状态 %[1]d", response.StatusCode)
	}
	return nil
}

// Validate validates an ST through /serviceValidate (CAS 2.0). | Validate 通过 /serviceValidate
// 校验 ST（CAS 2.0）。
func (c *Client) Validate(ctx context.Context, ticket, service string) (*ValidationResponse, error) {
	return c.validate(ctx, "serviceValidate", ticket, service)
}

// ValidateV3 validates an ST through /p3/serviceValidate (CAS 3.0). | ValidateV3 通过
// /p3/serviceValidate 校验 ST（CAS 3.0）。
func (c *Client) ValidateV3(ctx context.Context, ticket, service string) (*ValidationResponse, error) {
	return c.validate(ctx, "p3/serviceValidate", ticket, service)
}

// ProxyValidate validates an ST or PT through /proxyValidate (CAS 2.0). | ProxyValidate 通过
// /proxyValidate 校验 ST 或 PT（CAS 2.0）。
func (c *Client) ProxyValidate(ctx context.Context, ticket, service string) (*ValidationResponse, error) {
	return c.validate(ctx, "proxyValidate", ticket, service)
}

// ProxyValidateV3 validates an ST or PT through /p3/proxyValidate (CAS 3.0). | ProxyValidateV3 通过
// /p3/proxyValidate 校验 ST 或 PT（CAS 3.0）。
func (c *Client) ProxyValidateV3(ctx context.Context, ticket, service string) (*ValidationResponse, error) {
	return c.validate(ctx, "p3/proxyValidate", ticket, service)
}

// ValidateCAS10 validates an ST through /validate (CAS 1.0). | ValidateCAS10 通过 /validate 校验 ST
// （CAS 1.0）。
func (c *Client) ValidateCAS10(ctx context.Context, ticket, service string) (*ValidationResponse, error) {
	service, err := c.resolveService(service)
	if err != nil {
		return nil, err
	}
	query := url.Values{}
	query.Set("ticket", ticket)
	query.Set("service", service)
	raw, err := c.get(ctx, "validate", query, "")
	if err != nil {
		return nil, err
	}
	return parseCAS10Validation(raw)
}

// Proxy exchanges a PGT for a PT through /proxy. | Proxy 通过 /proxy 把 PGT 兑换为 PT。
func (c *Client) Proxy(ctx context.Context, pgt, targetService string) (*ProxyResponse, error) {
	if strings.TrimSpace(pgt) == "" {
		return nil, errs.Detail(ErrInvalidRequest, "pgt is required | pgt 必填")
	}
	query := url.Values{}
	query.Set("pgt", pgt)
	query.Set("targetService", targetService)
	raw, err := c.get(ctx, "proxy", query, "")
	if err != nil {
		return nil, err
	}
	return parseProxyResponse(raw)
}

// validate implements every XML or JSON validation endpoint. | validate 实现全部 XML 或 JSON 校验端点。
func (c *Client) validate(ctx context.Context, endpoint, ticket, service string) (*ValidationResponse, error) {
	service, err := c.resolveService(service)
	if err != nil {
		return nil, err
	}
	query := url.Values{}
	query.Set("ticket", ticket)
	query.Set("service", service)
	accept := "application/xml, text/xml, text/plain"
	if c.config.ValidationFormat == "json" {
		query.Set("format", "json")
		accept = "application/json"
	}
	raw, err := c.get(ctx, endpoint, query, accept)
	if err != nil {
		return nil, err
	}
	return parseValidationResponse(raw)
}

// resolveService returns service, falling back to the configured default. | resolveService 返回
// service，未提供时回退到配置的默认值。
func (c *Client) resolveService(service string) (string, error) {
	service = strings.TrimSpace(service)
	if service == "" {
		service = c.config.ServiceURL
	}
	if service == "" {
		return "", errs.Detail(ErrInvalidService, "service is required | service 必填")
	}
	return service, nil
}

// get performs a GET request against endpoint and returns the limited response body. An empty
// accept uses the XML-oriented default. | get 对 endpoint 执行 GET 请求并返回受限的响应正文。空
// accept 使用面向 XML 的默认值。
func (c *Client) get(ctx context.Context, endpoint string, query url.Values, accept string) ([]byte, error) {
	target := c.baseURL + "/" + strings.TrimLeft(endpoint, "/")
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrClientRequest, "cannot build request for %[1]s | 无法为 %[1]s 构建请求", endpoint)
	}
	if accept == "" {
		accept = "application/xml, text/xml, text/plain"
	}
	request.Header.Set("Accept", accept)
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrClientRequest, "request to %[1]s failed | 请求 %[1]s 失败", endpoint)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxProtocolBody+1))
	if err != nil {
		return nil, errs.WrapDetail(err, ErrClientRequest, "cannot read %[1]s response | 无法读取 %[1]s 响应", endpoint)
	}
	if len(body) > maxProtocolBody {
		return nil, errs.Detail(ErrInvalidResponse, "%[1]s response exceeds the size limit | %[1]s 响应超过大小限制", endpoint)
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, errs.Detail(ErrClientRequest, "%[1]s answered with status %[2]d | %[1]s 返回状态 %[2]d", endpoint, response.StatusCode)
	}
	return body, nil
}

// serviceResponseXML is the shared envelope of CAS 2.0 and 3.0 responses. | serviceResponseXML 是
// CAS 2.0 与 3.0 响应的共享信封。
type serviceResponseXML struct {
	AuthenticationSuccess *authenticationSuccess `xml:"authenticationSuccess"`
	AuthenticationFailure *authenticationFailure `xml:"authenticationFailure"`
	ProxySuccess          *proxySuccess          `xml:"proxySuccess"`
	ProxyFailure          *proxyFailure          `xml:"proxyFailure"`
	XMLName               xml.Name               `xml:"serviceResponse"`
}

// authenticationSuccess is the CAS authenticationSuccess element. | authenticationSuccess 是 CAS
// authenticationSuccess 元素。
type authenticationSuccess struct {
	User                string        `xml:"user"`
	Attributes          attributesXML `xml:"attributes"`
	ProxyGrantingTicket string        `xml:"proxyGrantingTicket"`
	Proxies             proxiesXML    `xml:"proxies"`
}

// authenticationFailure is the CAS authenticationFailure element. | authenticationFailure 是 CAS
// authenticationFailure 元素。
type authenticationFailure struct {
	Code    string `xml:"code,attr"`
	Message string `xml:",chardata"`
}

// proxySuccess is the CAS proxySuccess element. | proxySuccess 是 CAS proxySuccess 元素。
type proxySuccess struct {
	ProxyTicket string `xml:"proxyTicket"`
}

// proxyFailure is the CAS proxyFailure element. | proxyFailure 是 CAS proxyFailure 元素。
type proxyFailure struct {
	Code    string `xml:"code,attr"`
	Message string `xml:",chardata"`
}

// attributesXML parses both the CAS 2.0 element-per-attribute form and the CAS 3.0 name/value form.
// | attributesXML 解析 CAS 2.0 的每属性一元素形式与 CAS 3.0 的名称/值形式。
type attributesXML struct {
	// Values maps each attribute name to every released value. | Values 把每个属性名映射到全部已发布值。
	Values map[string][]string
}

// UnmarshalXML implements xml.Unmarshaler. | UnmarshalXML 实现 xml.Unmarshaler。
func (a *attributesXML) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	for {
		token, err := d.Token()
		if err != nil {
			return err
		}
		switch element := token.(type) {
		case xml.StartElement:
			var text string
			if err := d.DecodeElement(&text, &element); err != nil {
				return err
			}
			if element.Name.Local == "attribute" {
				name := attributeValue(element.Attr, "name")
				value := attributeValue(element.Attr, "value")
				if value == "" {
					value = text
				}
				if name != "" {
					if a.Values == nil {
						a.Values = make(map[string][]string)
					}
					a.Values[name] = append(a.Values[name], value)
				}
				continue
			}
			if a.Values == nil {
				a.Values = make(map[string][]string)
			}
			a.Values[element.Name.Local] = append(a.Values[element.Name.Local], text)
		case xml.EndElement:
			if element.Name.Local == start.Name.Local {
				return nil
			}
		}
	}
}

// proxiesXML collects the proxy elements of a validation response. | proxiesXML 收集校验响应中的 proxy 元素。
type proxiesXML struct {
	// Values holds every proxy URL in document order. | Values 按文档顺序保存每个代理 URL。
	Values []string
}

// UnmarshalXML implements xml.Unmarshaler. | UnmarshalXML 实现 xml.Unmarshaler。
func (p *proxiesXML) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	for {
		token, err := d.Token()
		if err != nil {
			return err
		}
		switch element := token.(type) {
		case xml.StartElement:
			var value string
			if err := d.DecodeElement(&value, &element); err != nil {
				return err
			}
			if element.Name.Local == "proxy" {
				p.Values = append(p.Values, value)
			}
		case xml.EndElement:
			if element.Name.Local == start.Name.Local {
				return nil
			}
		}
	}
}

// parseValidationResponse parses a CAS 2.0 or 3.0 XML body, a CAS 3.0 JSON body, or the CAS 1.0
// plain-text form. The dialect is detected from the body, so the configured request format only
// guides the server and never constrains the answer. | parseValidationResponse 解析 CAS 2.0/3.0 XML
// 正文、CAS 3.0 JSON 正文或 CAS 1.0 纯文本形式。方言由正文检测，配置的请求格式只引导服务端，绝不
// 限制应答。
func parseValidationResponse(raw []byte) (*ValidationResponse, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, errs.Detail(ErrInvalidResponse, "validation response is empty | 校验响应为空")
	}
	switch {
	case strings.HasPrefix(trimmed, "<"):
		return parseXMLValidationResponse(raw)
	case strings.HasPrefix(trimmed, "{"):
		return parseJSONValidationResponse(raw)
	default:
		return parseCAS10Validation(raw)
	}
}

// parseXMLValidationResponse parses a CAS 2.0 or 3.0 XML validation body. | parseXMLValidationResponse
// 解析 CAS 2.0 或 3.0 XML 校验正文。
func parseXMLValidationResponse(raw []byte) (*ValidationResponse, error) {
	var response serviceResponseXML
	if err := xml.Unmarshal(raw, &response); err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidResponse, "cannot parse validation response | 无法解析校验响应")
	}
	result := &ValidationResponse{Raw: append([]byte(nil), raw...)}
	switch {
	case response.AuthenticationSuccess != nil:
		success := response.AuthenticationSuccess
		result.Success = true
		result.User = success.User
		result.Attributes = success.Attributes.Values
		result.ProxyGrantingTicket = success.ProxyGrantingTicket
		result.Proxies = success.Proxies.Values
		return result, nil
	case response.AuthenticationFailure != nil:
		result.Code = response.AuthenticationFailure.Code
		result.Message = strings.TrimSpace(response.AuthenticationFailure.Message)
		return result, nil
	default:
		return nil, errs.Detail(ErrInvalidResponse, "validation response has no result element | 校验响应缺少结果元素")
	}
}

// parseJSONValidationResponse parses a CAS 3.0 JSON validation body. | parseJSONValidationResponse
// 解析 CAS 3.0 JSON 校验正文。
func parseJSONValidationResponse(raw []byte) (*ValidationResponse, error) {
	var response jsonValidationEnvelope
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidResponse, "cannot parse JSON validation response | 无法解析 JSON 校验响应")
	}
	result := &ValidationResponse{Raw: append([]byte(nil), raw...)}
	switch {
	case response.AuthenticationSuccess != nil:
		success := response.AuthenticationSuccess
		result.Success = true
		result.User = success.User
		if len(success.Attributes) > 0 {
			result.Attributes = map[string][]string(success.Attributes)
		}
		result.ProxyGrantingTicket = success.ProxyGrantingTicket
		result.Proxies = append([]string(nil), success.Proxies...)
		return result, nil
	case response.AuthenticationFailure != nil:
		result.Code = response.AuthenticationFailure.Code
		result.Message = strings.TrimSpace(response.AuthenticationFailure.Description)
		return result, nil
	default:
		return nil, errs.Detail(ErrInvalidResponse, "JSON validation response has no result element | JSON 校验响应缺少结果元素")
	}
}

// parseCAS10Validation parses the CAS 1.0 yes/no plain-text validation body. | parseCAS10Validation
// 解析 CAS 1.0 的 yes/no 纯文本校验正文。
func parseCAS10Validation(raw []byte) (*ValidationResponse, error) {
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
	result := &ValidationResponse{Raw: append([]byte(nil), raw...)}
	switch strings.TrimSpace(lines[0]) {
	case "yes":
		if len(lines) < 2 || strings.TrimSpace(lines[1]) == "" {
			return nil, errs.Detail(ErrInvalidResponse, "CAS 1.0 success has no user | CAS 1.0 成功响应缺少用户")
		}
		result.Success = true
		result.User = strings.TrimSpace(lines[1])
		return result, nil
	case "no":
		result.Code = ErrorCodeInvalidTicket
		result.Message = "The ticket is not valid | 票据无效"
		return result, nil
	default:
		return nil, errs.Detail(ErrInvalidResponse, "CAS 1.0 response must start with yes or no | CAS 1.0 响应必须以 yes 或 no 开头")
	}
}

// parseProxyResponse parses a CAS 2.0 proxy response. | parseProxyResponse 解析 CAS 2.0 代理响应。
func parseProxyResponse(raw []byte) (*ProxyResponse, error) {
	var response serviceResponseXML
	if err := xml.Unmarshal(raw, &response); err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidResponse, "cannot parse proxy response | 无法解析代理响应")
	}
	result := &ProxyResponse{Raw: append([]byte(nil), raw...)}
	switch {
	case response.ProxySuccess != nil:
		if response.ProxySuccess.ProxyTicket == "" {
			return nil, errs.Detail(ErrInvalidResponse, "proxy response has no ticket | 代理响应缺少票据")
		}
		result.Success = true
		result.ProxyTicket = response.ProxySuccess.ProxyTicket
		return result, nil
	case response.ProxyFailure != nil:
		result.Code = response.ProxyFailure.Code
		result.Message = strings.TrimSpace(response.ProxyFailure.Message)
		return result, nil
	default:
		return nil, errs.Detail(ErrInvalidResponse, "proxy response has no result element | 代理响应缺少结果元素")
	}
}

// attributeValue returns the value of the attribute with the given local name. | attributeValue
// 返回给定本地名属性的值。
func attributeValue(attributes []xml.Attr, name string) string {
	for _, attribute := range attributes {
		if attribute.Name.Local == name {
			return attribute.Value
		}
	}
	return ""
}
