package saml

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/xml"
)

// resolveArtifact resolves a SAMLart through the IdP Artifact Resolution Service and returns the
// embedded Response XML. | resolveArtifact 通过 IdP 工件解析服务解析 SAMLart 并返回嵌入的 Response
// XML。
func (sp *ServiceProvider) resolveArtifact(ctx context.Context, value string) ([]byte, error) {
	artifact, err := DecodeArtifact(value)
	if err != nil {
		return nil, err
	}
	if len(sp.config.ArtifactSourceID) == ArtifactSourceIDSize &&
		subtle.ConstantTimeCompare(artifact.SourceID[:], sp.config.ArtifactSourceID) != 1 {
		return nil, errs.Detail(ErrArtifactInvalid, "artifact source does not match | 工件源不匹配")
	}
	arsURL := sp.config.IDPMetadata.ArtifactResolutionURL(int(artifact.EndpointIndex))
	if arsURL == "" {
		return nil, errs.Detail(ErrInvalidMetadata, "IdP has no artifact resolution endpoint %d | IdP 没有工件解析端点 %d", artifact.EndpointIndex, artifact.EndpointIndex)
	}
	if err := validateSOAPEndpoint(arsURL); err != nil {
		return nil, err
	}
	requestBody, requestID, err := sp.buildArtifactResolve(arsURL, artifact)
	if err != nil {
		return nil, err
	}
	responseBody, status, err := sp.postArtifactResolve(ctx, arsURL, requestBody)
	if err != nil {
		return nil, err
	}
	return sp.parseArtifactResponse(ctx, responseBody, status, requestID)
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
	return buildSOAPEnvelope(document), request.ID, nil
}

// postArtifactResolve posts a SOAP ArtifactResolve and returns the bounded response body together
// with its HTTP status. | postArtifactResolve 发送 SOAP ArtifactResolve，并返回受限制的响应正文与
// HTTP 状态。
func (sp *ServiceProvider) postArtifactResolve(ctx context.Context, arsURL string, body []byte) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, sp.config.ArtifactResolutionTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, arsURL, bytes.NewReader(body))
	if err != nil {
		return nil, 0, errs.WrapDetail(err, ErrInvalidMetadata, "artifact resolution request | 工件解析请求")
	}
	request.Header.Set("Content-Type", SOAPContentType)
	request.Header.Set("SOAPAction", SOAPActionArtifactResolve)
	request.Header.Set("Accept", SOAPContentType)
	response, err := sp.artifactHTTPClient().Do(request)
	if err != nil {
		return nil, 0, errs.WrapDetail(err, ErrInvalidResponse, "artifact resolution | 工件解析")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxSOAPMessageBytes+1))
	if err != nil {
		return nil, response.StatusCode, errs.WrapDetail(err, ErrInvalidResponse, "artifact response | 工件响应")
	}
	if len(data) > MaxSOAPMessageBytes {
		return nil, response.StatusCode, errs.Detail(ErrLimit, "SOAP response exceeds %d bytes | SOAP 响应超过 %d 字节", MaxSOAPMessageBytes, MaxSOAPMessageBytes)
	}
	return data, response.StatusCode, nil
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
	envelope, err := parseSOAPEnvelope(body)
	if err != nil {
		return nil, soaplessResponseError(err, httpStatus)
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
