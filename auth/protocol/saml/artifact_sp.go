package saml

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/xml"
)

// Artifact resolution failover limits. | 工件解析故障转移限制。
const (
	// DefaultArtifactResolutionMaxEndpoints is the default number of resolution endpoints tried for
	// one artifact. | DefaultArtifactResolutionMaxEndpoints 是单个工件默认尝试的解析端点数量。
	DefaultArtifactResolutionMaxEndpoints = 8
	// MaxArtifactResolutionEndpoints is the hard upper bound accepted for ArtifactResolutionMaxEndpoints.
	// | MaxArtifactResolutionEndpoints 是 ArtifactResolutionMaxEndpoints 接受的硬上限。
	MaxArtifactResolutionEndpoints = 16
)

// ArtifactResolutionAttempt records one endpoint attempt of an artifact resolution. | ArtifactResolutionAttempt
// 记录一次工件解析中的单个端点尝试。
type ArtifactResolutionAttempt struct {
	// Index is the metadata endpoint index. | Index 是元数据端点索引。
	Index int
	// URL is the endpoint location that was tried. | URL 是尝试的端点位置。
	URL string
	// Err is the attempt failure; nil marks the successful attempt. | Err 是尝试失败；nil 表示成功尝试。
	Err error
}

// ArtifactResolutionError aggregates the failed attempts of an artifact resolution. The attempted
// errors remain available through errors.Is and errors.As. | ArtifactResolutionError 汇总一次工件
// 解析的失败尝试。各尝试错误仍可通过 errors.Is 与 errors.As 获取。
type ArtifactResolutionError struct {
	// Attempts lists every attempted endpoint in order. | Attempts 按顺序列出每个尝试的端点。
	Attempts []ArtifactResolutionAttempt
}

// Error returns the aggregate failure description. | Error 返回聚合失败描述。
func (e *ArtifactResolutionError) Error() string {
	count := 0
	if e != nil {
		count = len(e.Attempts)
	}
	return "saml: artifact resolution failed after " + strconv.Itoa(count) + " endpoint attempt(s) | saml：工件解析在 " + strconv.Itoa(count) + " 次端点尝试后失败"
}

// Unwrap returns the attempt errors for errors.Is and errors.As. | Unwrap 返回尝试错误以支持
// errors.Is 与 errors.As。
func (e *ArtifactResolutionError) Unwrap() []error {
	if e == nil {
		return nil
	}
	out := make([]error, 0, len(e.Attempts))
	for _, attempt := range e.Attempts {
		if attempt.Err != nil {
			out = append(out, attempt.Err)
		}
	}
	return out
}

// artifactResolutionEndpoint is one candidate Artifact Resolution Service endpoint. |
// artifactResolutionEndpoint 是一个候选工件解析服务端点。
type artifactResolutionEndpoint struct {
	index    int
	location string
}

// resolveArtifact resolves a SAMLart through the IdP Artifact Resolution Service and returns the
// embedded Response XML. The artifact endpoint index is tried first, then the remaining SOAP
// endpoints in metadata order. | resolveArtifact 通过 IdP 工件解析服务解析 SAMLart 并返回嵌入的
// Response XML。先尝试工件端点索引，再按元数据顺序尝试其余 SOAP 端点。
func (sp *ServiceProvider) resolveArtifact(ctx context.Context, value string) ([]byte, error) {
	artifact, err := DecodeArtifact(value)
	if err != nil {
		return nil, err
	}
	if len(sp.config.ArtifactSourceID) == ArtifactSourceIDSize &&
		subtle.ConstantTimeCompare(artifact.SourceID[:], sp.config.ArtifactSourceID) != 1 {
		return nil, errs.Detail(ErrArtifactInvalid, "artifact source does not match | 工件源不匹配")
	}
	endpoints, err := sp.artifactResolutionEndpoints(artifact)
	if err != nil {
		return nil, err
	}
	version := sp.config.ArtifactSOAPVersion
	if version != SOAPVersion12 {
		version = SOAPVersion11
	}
	totalCtx, cancel := context.WithTimeout(ctx, sp.config.ArtifactResolutionTotalTimeout)
	defer cancel()
	attempts := make([]ArtifactResolutionAttempt, 0, len(endpoints))
	for _, endpoint := range endpoints {
		attempt := ArtifactResolutionAttempt{Index: endpoint.index, URL: endpoint.location}
		if err := totalCtx.Err(); err != nil {
			attempt.Err = errs.WrapDetail(err, ErrInvalidResponse, "artifact resolution aborted | 工件解析已中止")
			attempts = append(attempts, attempt)
			break
		}
		if err := validateSOAPEndpoint(endpoint.location); err != nil {
			attempt.Err = err
			attempts = append(attempts, attempt)
			continue
		}
		requestBody, requestID, err := sp.buildArtifactResolve(endpoint.location, artifact)
		if err != nil {
			attempt.Err = err
			attempts = append(attempts, attempt)
			continue
		}
		responseBody, status, contentType, err := sp.postArtifactResolve(totalCtx, endpoint.location, requestBody, version)
		if err != nil {
			attempt.Err = err
			attempts = append(attempts, attempt)
			if totalCtx.Err() != nil {
				break
			}
			continue
		}
		raw, err := sp.parseArtifactResponseContentType(totalCtx, responseBody, status, requestID, contentType)
		if err != nil {
			attempt.Err = err
			attempts = append(attempts, attempt)
			if totalCtx.Err() != nil {
				break
			}
			continue
		}
		return raw, nil
	}
	return nil, &ArtifactResolutionError{Attempts: attempts}
}

// artifactResolutionEndpoints returns the failover candidate endpoints for artifact. | artifactResolutionEndpoints
// 返回 artifact 的故障转移候选端点。
func (sp *ServiceProvider) artifactResolutionEndpoints(artifact *Artifact) ([]artifactResolutionEndpoint, error) {
	if artifact == nil {
		return nil, errs.Detail(ErrArtifactInvalid, "artifact is nil | 工件为空")
	}
	descriptor := sp.config.IDPMetadata
	if descriptor == nil || descriptor.IDPSSODescriptor == nil {
		return nil, errs.Detail(ErrInvalidMetadata, "IdP has no artifact resolution endpoint | IdP 没有工件解析端点")
	}
	services := descriptor.IDPSSODescriptor.ArtifactResolutionService
	primaryIndex := int(artifact.EndpointIndex)
	matched := false
	endpoints := make([]artifactResolutionEndpoint, 0, len(services))
	seen := make(map[string]struct{}, len(services))
	appendEndpoint := func(endpoint IndexedEndpoint) {
		key := strconv.Itoa(endpoint.Index) + "\x00" + strings.TrimSpace(endpoint.Location)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		endpoints = append(endpoints, artifactResolutionEndpoint{index: endpoint.Index, location: endpoint.Location})
	}
	// Prefer the SOAP binding of the artifact endpoint, then any binding with that index, matching
	// EntityDescriptor.ArtifactResolutionURL. | 优先使用工件端点的 SOAP 绑定，其次使用该索引的任意
	// 绑定，与 EntityDescriptor.ArtifactResolutionURL 一致。
	for _, endpoint := range services {
		if endpoint.Index == primaryIndex && endpoint.Binding == BindingSOAP {
			matched = true
			appendEndpoint(endpoint)
			break
		}
	}
	if !matched {
		for _, endpoint := range services {
			if endpoint.Index == primaryIndex {
				matched = true
				appendEndpoint(endpoint)
				break
			}
		}
	}
	if !matched {
		return nil, errs.Detail(ErrInvalidMetadata, "IdP has no artifact resolution endpoint %d | IdP 没有工件解析端点 %d", artifact.EndpointIndex, artifact.EndpointIndex)
	}
	// Remaining SOAP endpoints serve as failover candidates in metadata order. | 其余 SOAP 端点按元数据
	// 顺序作为故障转移候选。
	for _, endpoint := range services {
		if endpoint.Binding != "" && endpoint.Binding != BindingSOAP {
			continue
		}
		appendEndpoint(endpoint)
	}
	limit := sp.config.ArtifactResolutionMaxEndpoints
	if limit <= 0 || limit > MaxArtifactResolutionEndpoints {
		limit = DefaultArtifactResolutionMaxEndpoints
	}
	if len(endpoints) > limit {
		endpoints = endpoints[:limit]
	}
	return endpoints, nil
}

// buildArtifactResolve builds a SOAP ArtifactResolve message and returns it with its request ID. |
// buildArtifactResolve 构建 SOAP ArtifactResolve 消息并返回消息与其请求标识。
func (sp *ServiceProvider) buildArtifactResolve(destination string, artifact *Artifact) ([]byte, string, error) {
	now := Now(sp.now)
	request := &ArtifactResolve{
		ID:           auth.NewID("artifact-request"),
		Version:      Version,
		IssueInstant: FormatTime(now),
		Destination:  destination,
		Issuer:       &Issuer{Value: sp.config.EntityID},
		Artifact:     artifact.String(),
	}
	document, err := xml.Marshal(request)
	if err != nil {
		return nil, "", errs.Wrap(err, ErrInvalidRequest)
	}
	if sp.config.ArtifactRequestSigner != nil {
		document, err = sp.config.ArtifactRequestSigner.SignElement(document, request.ID)
		if err != nil {
			return nil, "", errs.Wrap(err, ErrInvalidSignature)
		}
	}
	version := sp.config.ArtifactSOAPVersion
	if version != SOAPVersion12 {
		version = SOAPVersion11
	}
	return buildSOAPEnvelopeVersion(version, document), request.ID, nil
}

// postArtifactResolve posts a SOAP ArtifactResolve and returns the bounded response body together
// with its HTTP status and content type. | postArtifactResolve 发送 SOAP ArtifactResolve，并返回受限的
// 响应正文、HTTP 状态与内容类型。
func (sp *ServiceProvider) postArtifactResolve(ctx context.Context, arsURL string, body []byte, version SOAPVersion) ([]byte, int, string, error) {
	requestCtx, cancel := context.WithTimeout(ctx, sp.config.ArtifactResolutionTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, arsURL, bytes.NewReader(body))
	if err != nil {
		return nil, 0, "", errs.WrapDetail(err, ErrInvalidMetadata, "artifact resolution request | 工件解析请求")
	}
	if version == SOAPVersion12 {
		request.Header.Set("Content-Type", SOAPContentType12+`; action="`+SOAPActionArtifactResolve+`"`)
		request.Header.Set("Accept", SOAPContentType12)
	} else {
		request.Header.Set("Content-Type", SOAPContentType)
		request.Header.Set("SOAPAction", SOAPActionArtifactResolve)
		request.Header.Set("Accept", SOAPContentType)
	}
	response, err := sp.artifactHTTPClient().Do(request)
	if err != nil {
		return nil, 0, "", errs.WrapDetail(err, ErrInvalidResponse, "artifact resolution | 工件解析")
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxSOAPMessageBytes+1))
	if err != nil {
		return nil, response.StatusCode, response.Header.Get("Content-Type"), errs.WrapDetail(err, ErrInvalidResponse, "artifact response | 工件响应")
	}
	if len(data) > MaxSOAPMessageBytes {
		return nil, response.StatusCode, response.Header.Get("Content-Type"), errs.Detail(ErrLimit, "SOAP response exceeds %d bytes | SOAP 响应超过 %d 字节", MaxSOAPMessageBytes, MaxSOAPMessageBytes)
	}
	return data, response.StatusCode, response.Header.Get("Content-Type"), nil
}

// artifactHTTPClient returns the configured client or a bounded client that does not follow
// redirects. | artifactHTTPClient 返回已配置客户端，或返回不跟随重定向的受限客户端。
func (sp *ServiceProvider) artifactHTTPClient() *http.Client {
	if sp.config.ArtifactHTTPClient != nil {
		return sp.config.ArtifactHTTPClient
	}
	return &http.Client{
		Timeout:       sp.config.ArtifactResolutionTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// parseArtifactResponse validates a SOAP ArtifactResponse and returns its embedded Response XML. |
// parseArtifactResponse 校验 SOAP ArtifactResponse 并返回其嵌入的 Response XML。
func (sp *ServiceProvider) parseArtifactResponse(ctx context.Context, body []byte, httpStatus int, requestID string) ([]byte, error) {
	return sp.parseArtifactResponseContentType(ctx, body, httpStatus, requestID, "")
}

// parseArtifactResponseContentType validates a SOAP ArtifactResponse whose transport content type is
// declared. A declared SOAP version must match the envelope, and a declared action must match
// ArtifactResponse. | parseArtifactResponseContentType 校验传输内容类型已声明的 SOAP ArtifactResponse。
// 声明的 SOAP 版本必须与信封一致，声明的 action 必须匹配 ArtifactResponse。
func (sp *ServiceProvider) parseArtifactResponseContentType(ctx context.Context, body []byte, httpStatus int, requestID, contentType string) ([]byte, error) {
	declared := soapVersionFromContentType(contentType)
	envelope, err := parseSOAPEnvelope(body)
	if err != nil {
		return nil, soaplessResponseError(err, httpStatus)
	}
	if declared != "" && declared != envelope.version {
		return nil, soaplessResponseError(errs.Detail(ErrInvalidResponse, "SOAP response version mismatch | SOAP 响应版本不匹配"), httpStatus)
	}
	if action := soapActionFromContentType(contentType); action != "" && action != SOAPActionArtifactResponse {
		return nil, soaplessResponseError(errs.Detail(ErrInvalidResponse, "SOAP response action %[1]q | SOAP 响应动作 %[1]q", action), httpStatus)
	}
	payload, err := envelope.payload()
	if err != nil {
		var fault *SOAPFault
		if errors.As(err, &fault) {
			return nil, err
		}
		return nil, soaplessResponseError(err, httpStatus)
	}
	if payload.Name.Local != "ArtifactResponse" || payload.Name.Space != NamespaceProtocol {
		return nil, soaplessResponseError(errs.Detail(ErrInvalidResponse, "unexpected SOAP payload | 意外的 SOAP 载荷"), httpStatus)
	}
	if httpStatus != http.StatusOK {
		return nil, errs.Detail(ErrInvalidResponse, "artifact resolution status %d | 工件解析状态 %d", httpStatus, httpStatus)
	}
	id := nodeAttr(payload, "ID")
	if id == "" {
		return nil, errs.Detail(ErrInvalidResponse, "ArtifactResponse ID is missing | 缺少 ArtifactResponse ID")
	}
	if version := nodeAttr(payload, "Version"); version != Version {
		return nil, errs.Detail(ErrInvalidResponse, "unsupported ArtifactResponse version %[1]q | 不支持的 ArtifactResponse 版本 %[1]q", version)
	}
	now := Now(sp.now)
	if err := validateProtocolInstant("ArtifactResponse", nodeAttr(payload, "IssueInstant"), now, sp.config.ClockSkew, sp.config.MaxIssueAge, ErrInvalidResponse); err != nil {
		return nil, err
	}
	signature := payload.FirstChild("Signature")
	signed := signature != nil && signature.Name.Space == NamespaceXMLDSig
	if signed {
		if sp.config.SignatureVerifier == nil {
			return nil, errs.Detail(ErrInvalidSignature, "no signature verifier configured | 未配置签名校验器")
		}
		if err := verifyEmbeddedSignature(ctx, sp.config.SignatureVerifier, body, payload, id); err != nil {
			return nil, err
		}
	} else if sp.config.RequireSignedArtifactResponse {
		return nil, errs.Detail(ErrInvalidSignature, "ArtifactResponse is not signed | ArtifactResponse 未签名")
	}
	if inResponseTo := nodeAttr(payload, "InResponseTo"); inResponseTo != requestID {
		return nil, errs.Detail(ErrInvalidResponse, "ArtifactResponse InResponseTo %[1]q | ArtifactResponse InResponseTo %[1]q", inResponseTo)
	}
	issuer := payload.FirstChild("Issuer")
	if issuer == nil || issuer.Name.Space != NamespaceAssertion || strings.TrimSpace(issuer.Text()) != sp.config.IDPMetadata.EntityID {
		return nil, errs.Detail(ErrInvalidIssuer, "ArtifactResponse issuer mismatch | ArtifactResponse 签发方不匹配")
	}
	status, err := artifactResponseStatus(payload)
	if err != nil {
		return nil, err
	}
	if status.StatusCode.Value != StatusSuccess {
		message := ""
		if status.StatusMessage != nil {
			message = status.StatusMessage.Value
		}
		return nil, errs.Detail(ErrStatusFailure, "artifact status %[1]q %[2]s | 工件状态 %[1]q %[2]s", status.StatusCode.Value, message)
	}
	response := payload.FirstChild("Response")
	if response == nil || response.Name.Space != NamespaceProtocol {
		return nil, errs.Detail(ErrInvalidResponse, "ArtifactResponse has no Response | ArtifactResponse 没有 Response")
	}
	raw := response.OuterXML()
	if len(raw) == 0 {
		return nil, errs.Detail(ErrInvalidResponse, "ArtifactResponse Response is not recoverable | 无法恢复 ArtifactResponse 的 Response")
	}
	return raw, nil
}

// artifactResponseStatus reads the Status of an ArtifactResponse. | artifactResponseStatus 读取
// ArtifactResponse 的 Status。
func artifactResponseStatus(payload *xml.Node) (*Status, error) {
	node := payload.FirstChild("Status")
	if node == nil || node.Name.Space != NamespaceProtocol {
		return nil, errs.Detail(ErrInvalidResponse, "ArtifactResponse status is missing | 缺少 ArtifactResponse 状态")
	}
	code := node.FirstChild("StatusCode")
	if code == nil || code.Name.Space != NamespaceProtocol {
		return nil, errs.Detail(ErrInvalidResponse, "ArtifactResponse status code is missing | 缺少 ArtifactResponse 状态码")
	}
	status := &Status{StatusCode: &StatusCode{Value: strings.TrimSpace(nodeAttr(code, "Value"))}}
	if status.StatusCode.Value == "" {
		return nil, errs.Detail(ErrInvalidResponse, "ArtifactResponse status code is empty | ArtifactResponse 状态码为空")
	}
	if nested := code.FirstChild("StatusCode"); nested != nil && nested.Name.Space == NamespaceProtocol {
		status.StatusCode.StatusCode = &StatusCode{Value: strings.TrimSpace(nodeAttr(nested, "Value"))}
	}
	if message := node.FirstChild("StatusMessage"); message != nil && message.Name.Space == NamespaceProtocol {
		status.StatusMessage = &StatusMessage{Value: strings.TrimSpace(message.Text())}
	}
	return status, nil
}

// soaplessResponseError maps a SOAP parsing failure to an invalid artifact response while preserving
// a non-200 transport status in the message. | soaplessResponseError 把 SOAP 解析失败映射为非法工件
// 响应，并在消息中保留非 200 的传输状态。
func soaplessResponseError(err error, httpStatus int) error {
	if httpStatus != http.StatusOK {
		return errs.WrapDetail(err, ErrInvalidResponse, "artifact resolution status %d | 工件解析状态 %d", httpStatus, httpStatus)
	}
	return errs.WrapDetail(err, ErrInvalidResponse, "invalid artifact response | 非法工件响应")
}

// validateSOAPEndpoint accepts absolute HTTP and HTTPS endpoints without credentials. | validateSOAPEndpoint
// 接受不带凭据的绝对 HTTP 与 HTTPS 端点。
func validateSOAPEndpoint(value string) error {
	parsed, err := url.Parse(value)
	if err != nil {
		return errs.WrapDetail(err, ErrInvalidMetadata, "artifact resolution URL | 工件解析 URL")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return errs.Detail(ErrInvalidMetadata, "artifact resolution scheme %[1]q | 工件解析协议 %[1]q", parsed.Scheme)
	}
	if parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return errs.Detail(ErrInvalidMetadata, "artifact resolution URL is not acceptable | 工件解析 URL 不可接受")
	}
	return nil
}
