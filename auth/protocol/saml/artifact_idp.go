package saml

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/xml"
)

// HandleArtifactResolution serves the SOAP Artifact Resolution Service. It accepts a SOAP 1.1 or
// SOAP 1.2 ArtifactResolve, optionally verifies its XML signature, resolves an artifact issued by
// this IdP exactly once and returns an ArtifactResponse in the request envelope version carrying
// the original protocol Response. | HandleArtifactResolution 提供 SOAP 工件解析服务。它接受 SOAP 1.1
// 或 SOAP 1.2 ArtifactResolve，按配置校验其 XML 签名，对本 IdP 签发的工件只解析一次，并以请求的信封
// 版本返回携带原始协议 Response 的 ArtifactResponse。
func (idp *IdentityProvider) HandleArtifactResolution(w http.ResponseWriter, r *http.Request) {
	version := soapRequestVersion(r)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeSOAPFaultVersion(w, version, http.StatusMethodNotAllowed, "soap:Client", "method not allowed")
		return
	}
	if err := checkSOAPAction(r, SOAPActionArtifactResolve); err != nil {
		writeSOAPFaultVersion(w, version, http.StatusBadRequest, "soap:Client", "invalid SOAPAction")
		return
	}
	body, err := readSOAPBody(r)
	if err != nil {
		writeSOAPError(w, version, err)
		return
	}
	envelope, err := parseSOAPEnvelope(body)
	if err != nil {
		writeSOAPError(w, version, err)
		return
	}
	version = envelope.version
	payload, err := envelope.payload()
	if err != nil {
		writeSOAPError(w, version, err)
		return
	}
	if payload.Name.Local != "ArtifactResolve" || payload.Name.Space != NamespaceProtocol {
		writeSOAPFaultVersion(w, version, http.StatusBadRequest, "soap:Client", "unexpected SOAP payload")
		return
	}
	request, err := parseArtifactResolveNode(payload)
	if err != nil {
		writeSOAPError(w, version, err)
		return
	}
	now := Now(idp.now)
	if err := idp.validateArtifactResolve(r.Context(), body, payload, request, now); err != nil {
		writeSOAPError(w, version, err)
		return
	}
	store, err := artifactStoreOf(idp.store)
	if err != nil {
		writeSOAPFaultVersion(w, version, http.StatusInternalServerError, "soap:Server", "artifact store unavailable")
		return
	}
	artifact, err := DecodeArtifact(request.Artifact)
	if err != nil {
		idp.writeArtifactStatus(w, request, now, version, ErrArtifactInvalid)
		return
	}
	if artifact.EndpointIndex != 0 || !artifact.SameSource(Artifact{SourceID: idp.artifactSourceID}) {
		idp.writeArtifactStatus(w, request, now, version, ErrArtifactInvalid)
		return
	}
	record, err := store.TakeArtifact(r.Context(), *artifact, now)
	if err != nil {
		switch {
		case errors.Is(err, ErrArtifactInvalid), errors.Is(err, ErrResponseExpired), errors.Is(err, ErrReplay):
			idp.writeArtifactStatus(w, request, now, version, err)
		default:
			writeSOAPFaultVersion(w, version, http.StatusInternalServerError, "soap:Server", "artifact resolution failed")
		}
		return
	}
	if record.Artifact.EndpointIndex != artifact.EndpointIndex || record.Artifact.Type != artifact.Type ||
		!record.Artifact.sameMessage(*artifact) {
		idp.writeArtifactStatus(w, request, now, version, ErrArtifactInvalid)
		return
	}
	if record.SPEntityID != "" && record.SPEntityID != request.Issuer.Value {
		idp.writeArtifactStatus(w, request, now, version, ErrArtifactInvalid)
		return
	}
	if record.IDPEntityID != "" && record.IDPEntityID != idp.config.EntityID {
		idp.writeArtifactStatus(w, request, now, version, ErrArtifactInvalid)
		return
	}
	document := idp.buildArtifactResponse(request.ID, time.Time{}, statusFor(StatusSuccess), record.Message)
	document, err = idp.signArtifactResponse(document)
	if err != nil {
		writeSOAPFaultVersion(w, version, http.StatusInternalServerError, "soap:Server", "artifact response signing failed")
		return
	}
	writeSOAPPayloadVersion(w, version, document)
}

// validateArtifactResolve validates the protocol attributes and optional signature of an
// ArtifactResolve. | validateArtifactResolve 校验 ArtifactResolve 的协议属性与可选签名。
func (idp *IdentityProvider) validateArtifactResolve(ctx context.Context, body []byte, payload *xml.Node, request *ArtifactResolve, now time.Time) error {
	if request.ID == "" {
		return errs.Detail(ErrInvalidRequest, "ArtifactResolve ID is missing | 缺少 ArtifactResolve ID")
	}
	if request.Version != Version {
		return errs.Detail(ErrInvalidRequest, "unsupported ArtifactResolve version %[1]q | 不支持的 ArtifactResolve 版本 %[1]q", request.Version)
	}
	if err := validateProtocolInstant("ArtifactResolve", request.IssueInstant, now, idp.config.ClockSkew, idp.config.MaxIssueAge, ErrInvalidRequest); err != nil {
		return err
	}
	if request.Destination != "" && idp.config.ArtifactResolutionURL != "" && request.Destination != idp.config.ArtifactResolutionURL {
		return errs.Detail(ErrInvalidRecipient, "ArtifactResolve destination %[1]q | ArtifactResolve 目标 %[1]q", request.Destination)
	}
	if request.Issuer == nil || request.Issuer.Value == "" {
		return errs.Detail(ErrInvalidIssuer, "ArtifactResolve issuer is missing | 缺少 ArtifactResolve 签发方")
	}
	if request.Artifact == "" {
		return errs.Detail(ErrArtifactInvalid, "ArtifactResolve artifact is missing | 缺少 ArtifactResolve 工件")
	}
	if request.Signature != nil {
		if idp.config.SignatureVerifier == nil {
			return errs.Detail(ErrInvalidSignature, "no signature verifier configured | 未配置签名校验器")
		}
		if err := verifyEmbeddedSignature(ctx, idp.config.SignatureVerifier, body, payload, request.ID); err != nil {
			return err
		}
	} else if idp.config.WantArtifactResolveSigned {
		return errs.Detail(ErrInvalidSignature, "ArtifactResolve is not signed | ArtifactResolve 未签名")
	}
	return nil
}

// parseArtifactResolveNode reads an ArtifactResolve from its DOM node. | parseArtifactResolveNode
// 从其 DOM 节点读取 ArtifactResolve。
func parseArtifactResolveNode(node *xml.Node) (*ArtifactResolve, error) {
	request := &ArtifactResolve{
		ID:           nodeAttr(node, "ID"),
		Version:      nodeAttr(node, "Version"),
		IssueInstant: nodeAttr(node, "IssueInstant"),
		Destination:  nodeAttr(node, "Destination"),
		Consent:      nodeAttr(node, "Consent"),
	}
	if issuer := node.FirstChild("Issuer"); issuer != nil && issuer.Name.Space == NamespaceAssertion {
		request.Issuer = &Issuer{
			Format:          nodeAttr(issuer, "Format"),
			NameQualifier:   nodeAttr(issuer, "NameQualifier"),
			SPNameQualifier: nodeAttr(issuer, "SPNameQualifier"),
			Value:           strings.TrimSpace(issuer.Text()),
		}
	}
	if artifact := node.FirstChild("Artifact"); artifact != nil && artifact.Name.Space == NamespaceProtocol {
		request.Artifact = strings.TrimSpace(artifact.Text())
	}
	if signature := node.FirstChild("Signature"); signature != nil && signature.Name.Space == NamespaceXMLDSig {
		request.Signature = &SignatureMarker{}
	}
	return request, nil
}

// buildArtifactResponse builds an ArtifactResponse with an optional embedded protocol payload.
// The payload bytes are embedded verbatim so signatures over them remain valid. | buildArtifactResponse
// 构建可嵌入协议载荷的 ArtifactResponse。载荷字节原样嵌入，以保证其上的签名继续有效。
func (idp *IdentityProvider) buildArtifactResponse(inResponseTo string, issueInstant time.Time, status *Status, embedded []byte) []byte {
	now := issueInstant
	if now.IsZero() {
		now = Now(idp.now)
	}
	id := auth.NewID("artifact-response")
	var b []byte
	b = append(b, (`<samlp:ArtifactResponse xmlns:samlp="` + NamespaceProtocol + `" xmlns:saml="` + NamespaceAssertion +
		`" ID="` + htmlEscape(id) + `" Version="` + Version + `" IssueInstant="` + FormatTime(now) + `"`)...)
	if inResponseTo != "" {
		b = append(b, ` InResponseTo="`+htmlEscape(inResponseTo)+`"`...)
	}
	b = append(b, `><saml:Issuer>`+htmlEscape(idp.config.EntityID)+`</saml:Issuer>`...)
	b = appendStatusXML(b, status)
	b = append(b, embedded...)
	b = append(b, `</samlp:ArtifactResponse>`...)
	return b
}

// signArtifactResponse applies the configured ArtifactResponse signature. | signArtifactResponse
// 应用配置的 ArtifactResponse 签名。
func (idp *IdentityProvider) signArtifactResponse(document []byte) ([]byte, error) {
	if !idp.config.SignArtifactResponse || idp.config.Signer == nil {
		return document, nil
	}
	envelope, err := xml.Parse(document)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidResponse)
	}
	root := envelope.Root
	if root == nil {
		return nil, errs.Detail(ErrInvalidResponse, "ArtifactResponse is empty | ArtifactResponse 为空")
	}
	id := nodeAttr(root, "ID")
	if id == "" {
		return nil, errs.Detail(ErrInvalidResponse, "ArtifactResponse ID is missing | 缺少 ArtifactResponse ID")
	}
	signed, err := idp.config.Signer.SignElement(document, id)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidSignature)
	}
	return signed, nil
}

// writeArtifactStatus writes an ArtifactResponse in the request envelope version that carries a
// requester error status. | writeArtifactStatus 以请求的信封版本写入携带请求方错误状态的
// ArtifactResponse。
func (idp *IdentityProvider) writeArtifactStatus(w http.ResponseWriter, request *ArtifactResolve, now time.Time, version SOAPVersion, cause error) {
	status := &Status{
		StatusCode:    &StatusCode{Value: StatusRequester},
		StatusMessage: &StatusMessage{Value: artifactStatusMessage(cause)},
	}
	document := idp.buildArtifactResponse(request.ID, now, status, nil)
	document, err := idp.signArtifactResponse(document)
	if err != nil {
		writeSOAPFaultVersion(w, version, http.StatusInternalServerError, "soap:Server", "artifact response signing failed")
		return
	}
	writeSOAPPayloadVersion(w, version, document)
}

// artifactStatusMessage maps an artifact error to a non-sensitive status message. | artifactStatusMessage
// 把工件错误映射为不泄露细节的状态消息。
func artifactStatusMessage(err error) string {
	switch {
	case errors.Is(err, ErrResponseExpired):
		return "artifact expired"
	case errors.Is(err, ErrReplay):
		return "artifact already resolved"
	default:
		return "invalid artifact"
	}
}

// appendStatusXML appends a Status element. | appendStatusXML 追加 Status 元素。
func appendStatusXML(dst []byte, status *Status) []byte {
	if status == nil || status.StatusCode == nil {
		return dst
	}
	dst = append(dst, `<samlp:Status>`...)
	dst = appendStatusCodeXML(dst, status.StatusCode)
	if status.StatusMessage != nil {
		dst = append(dst, `<samlp:StatusMessage>`+htmlEscape(status.StatusMessage.Value)+`</samlp:StatusMessage>`...)
	}
	return append(dst, `</samlp:Status>`...)
}

// appendStatusCodeXML appends a nested StatusCode element. | appendStatusCodeXML 追加嵌套 StatusCode
// 元素。
func appendStatusCodeXML(dst []byte, code *StatusCode) []byte {
	if code == nil {
		return dst
	}
	dst = append(dst, (`<samlp:StatusCode Value="` + htmlEscape(code.Value) + `"`)...)
	if code.StatusCode == nil {
		return append(dst, `/>`...)
	}
	dst = append(dst, `>`...)
	dst = appendStatusCodeXML(dst, code.StatusCode)
	return append(dst, `</samlp:StatusCode>`...)
}

// nodeAttr returns an unqualified attribute value. | nodeAttr 返回无前缀属性值。
func nodeAttr(node *xml.Node, local string) string {
	if node == nil {
		return ""
	}
	value, _ := node.Attr(local)
	return strings.TrimSpace(value)
}

// verifyEmbeddedSignature verifies elementID against the embedded element bytes first and the whole
// SOAP message second, tolerating namespace declarations inherited from the envelope. | verifyEmbeddedSignature
// 先基于嵌入元素字节、再基于完整 SOAP 消息校验 elementID，以容忍从信封继承的命名空间声明。
func verifyEmbeddedSignature(ctx context.Context, verifier SignatureVerifier, message []byte, payload *xml.Node, elementID string) error {
	candidates := make([][]byte, 0, 2)
	if outer := payload.OuterXML(); len(outer) > 0 {
		candidates = append(candidates, outer)
	}
	candidates = append(candidates, message)
	var lastErr error
	for _, candidate := range candidates {
		if err := verifier.VerifySignature(ctx, candidate, elementID); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return errs.Wrap(lastErr, ErrInvalidSignature)
}

// writeSOAPError writes a SOAP fault in version for a request error. Body-size violations use status
// 413 and everything else status 400. | writeSOAPError 以 version 版本为请求错误写入 SOAP 异常。正文
// 超限使用 413，其余使用 400。
func writeSOAPError(w http.ResponseWriter, version SOAPVersion, err error) {
	var fault *SOAPFault
	if errors.As(err, &fault) {
		writeSOAPFaultVersion(w, version, http.StatusBadRequest, "soap:Client", fault.Error())
		return
	}
	if errors.Is(err, ErrLimit) {
		writeSOAPFaultVersion(w, version, http.StatusRequestEntityTooLarge, "soap:Client", "message too large")
		return
	}
	writeSOAPFaultVersion(w, version, http.StatusBadRequest, "soap:Client", "invalid SOAP request")
}
