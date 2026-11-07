package cas

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/xml"
)

// SAML 1.1 protocol constants. | SAML 1.1 协议常量。
const (
	// samlProtocolNamespace is the SAML 1.1 protocol namespace. | samlProtocolNamespace 是 SAML 1.1 协议命名空间。
	samlProtocolNamespace = "urn:oasis:names:tc:SAML:1.0:protocol"
	// samlAssertionNamespace is the SAML 1.1 assertion namespace. | samlAssertionNamespace 是 SAML 1.1 断言命名空间。
	samlAssertionNamespace = "urn:oasis:names:tc:SAML:1.0:assertion"
	// samlSOAPNamespace is the SOAP 1.1 envelope namespace. | samlSOAPNamespace 是 SOAP 1.1 信封命名空间。
	samlSOAPNamespace = "http://schemas.xmlsoap.org/soap/envelope/"
	// samlAuthenticationMethod is the password authentication method URI. | samlAuthenticationMethod 是口令认证方法 URI。
	samlAuthenticationMethod = "urn:oasis:names:tc:SAML:1.0:am:password"
	// samlClockSkew widens the assertion validity window. | samlClockSkew 扩展断言有效期窗口。
	samlClockSkew = time.Minute
	// samlValidity is the default assertion lifetime. | samlValidity 是默认断言寿命。
	samlValidity = 5 * time.Minute
)

// SAMLValidation carries the validated ticket and principal to a SAMLResponseBuilder. |
// SAMLValidation 把已校验的票据与主体传给 SAMLResponseBuilder。
type SAMLValidation struct {
	// IssueInstant is the assertion issue time. | IssueInstant 是断言签发时间。
	IssueInstant time.Time
	// Ticket is the consumed service or proxy ticket. | Ticket 是已消费的服务票据或代理票据。
	Ticket *Ticket
	// Principal is the authenticated principal. | Principal 是已认证主体。
	Principal *auth.Principal
	// Attributes are the released user attributes. | Attributes 是发布的用户属性。
	Attributes map[string][]string
	// Service is the TARGET service URL. | Service 是 TARGET 服务 URL。
	Service string
	// User is the protocol user identifier. | User 是协议用户标识。
	User string
	// Issuer is the configured CAS issuer. | Issuer 是配置的 CAS 签发方。
	Issuer string
}

// SAMLResponseBuilder builds a complete SOAP-wrapped SAML 1.1 response. It is the place to add an
// XML signature; the default implementation returns an unsigned assertion. | SAMLResponseBuilder
// 构建完整的、以 SOAP 包装的 SAML 1.1 响应。它是添加 XML 签名的位置；默认实现返回未签名断言。
type SAMLResponseBuilder func(ctx context.Context, validation *SAMLValidation) ([]byte, error)

// SAMLValidate serves GET and POST /samlValidate, the SAML 1.1 artifact profile. | SAMLValidate
// 提供 GET 与 POST /samlValidate，即 SAML 1.1 制品配置。
//
// The request carries a base64 SAMLRequest whose AssertionArtifact is an ST or PT, plus the target
// service in the TARGET query parameter. The ticket is consumed exactly like proxyValidate. | 请求
// 携带 base64 的 SAMLRequest，其 AssertionArtifact 为 ST 或 PT，并通过 TARGET 查询参数给出目标
// 服务。票据的消费方式与 proxyValidate 完全一致。
func (s *Server) SAMLValidate(w http.ResponseWriter, r *http.Request) {
	if !s.methodAllowed(w, r, http.MethodGet, http.MethodPost) {
		return
	}
	target := strings.TrimSpace(r.URL.Query().Get("TARGET"))
	var samlRequest string
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, maxProtocolBody)
		if err := r.ParseForm(); err != nil {
			writeSAMLFault(w, "Cannot parse the SAML request | 无法解析 SAML 请求")
			return
		}
		samlRequest = strings.TrimSpace(r.Form.Get("SAMLRequest"))
		if target == "" {
			target = strings.TrimSpace(r.Form.Get("TARGET"))
		}
	} else {
		samlRequest = strings.TrimSpace(r.URL.Query().Get("SAMLRequest"))
	}
	if samlRequest == "" {
		writeSAMLFault(w, "The SAMLRequest parameter is required | 缺少 SAMLRequest 参数")
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(samlRequest)
	if err != nil {
		writeSAMLFault(w, "The SAMLRequest is not valid base64 | SAMLRequest 不是合法的 base64")
		return
	}
	artifact, err := extractAssertionArtifact(decoded)
	if err != nil {
		writeSAMLFault(w, "The SAMLRequest has no assertion artifact | SAMLRequest 缺少断言制品")
		return
	}
	if target == "" {
		writeSAMLFault(w, "The TARGET parameter is required | 缺少 TARGET 参数")
		return
	}
	if !s.allowsService(r.Context(), target) {
		writeSAMLFault(w, "The target service is not registered | 目标服务未注册")
		return
	}
	ticket, err := s.store.Get(r.Context(), artifact)
	if err != nil || (ticket.Type != TicketST && ticket.Type != TicketPT) || !ticket.ActiveWithSkew(s.expiryNow(), 0) {
		writeSAMLFault(w, "The assertion artifact is not valid | 断言制品无效")
		return
	}
	if !s.servicesMatch(ticket.Service, target) {
		writeSAMLFault(w, "The target service does not match the ticket | 目标服务与票据不匹配")
		return
	}
	consumed, err := s.store.Consume(r.Context(), ticket.ID, ticket.Type, s.expiryNow())
	if err != nil {
		writeSAMLFault(w, "The assertion artifact is not valid | 断言制品无效")
		return
	}
	principal, err := s.principalFor(r.Context(), consumed)
	if err != nil {
		s.logWarn("cas: principal refresh failed | cas：主体刷新失败", err)
		writeSAMLFault(w, "The authentication principal is unavailable | 认证主体不可用")
		return
	}
	validation := &SAMLValidation{
		Service:      target,
		Ticket:       consumed,
		Principal:    principal,
		User:         userIdentifier(principal),
		Attributes:   attributeValues(principal.Attributes),
		Issuer:       s.config.Issuer,
		IssueInstant: s.nowTime(),
	}
	var body []byte
	if s.config.SAMLResponseBuilder != nil {
		body, err = s.config.SAMLResponseBuilder(r.Context(), validation)
		if err != nil {
			s.logWarn("cas: SAML response builder failed | cas：SAML 响应构建失败", err)
			writeSAMLFault(w, "The SAML response could not be built | SAML 响应无法构建")
			return
		}
	} else {
		body = defaultSAMLResponse(validation)
	}
	writeSAMLResponse(w, body)
}

// extractAssertionArtifact returns the AssertionArtifact text of a decoded SAML request. Name space
// prefixes are ignored and only the local name is matched. | extractAssertionArtifact 返回解码后
// SAML 请求中的 AssertionArtifact 文本。忽略命名空间前缀，只匹配本地名。
func extractAssertionArtifact(data []byte) (string, error) {
	decoder := xml.NewDecoderBytes(data)
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", errs.WrapDetail(err, ErrInvalidRequest, "cannot decode SAMLRequest | 无法解码 SAMLRequest")
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "AssertionArtifact" {
			continue
		}
		var value string
		if err := decoder.DecodeElement(&value, &start); err != nil {
			return "", errs.WrapDetail(err, ErrInvalidRequest, "cannot decode AssertionArtifact | 无法解码 AssertionArtifact")
		}
		value = strings.TrimSpace(value)
		if value == "" {
			return "", errs.Detail(ErrInvalidRequest, "AssertionArtifact is empty | AssertionArtifact 为空")
		}
		return value, nil
	}
	return "", errs.Detail(ErrInvalidRequest, "AssertionArtifact is missing | 缺少 AssertionArtifact")
}

// defaultSAMLResponse renders an unsigned SAML 1.1 response with an authentication statement and an
// attribute statement. | defaultSAMLResponse 渲染包含认证语句与属性语句的未签名 SAML 1.1 响应。
func defaultSAMLResponse(validation *SAMLValidation) []byte {
	now := validation.IssueInstant
	if now.IsZero() {
		now = time.Now().UTC()
	}
	notBefore := now.Add(-samlClockSkew)
	notOnOrAfter := now.Add(samlValidity)
	responseID, _ := auth.RandomToken(16)
	assertionID, _ := auth.RandomToken(16)
	authenticationInstant := validation.Ticket.IssuedAt
	if validation.Principal != nil && !validation.Principal.AuthTime.IsZero() {
		authenticationInstant = validation.Principal.AuthTime
	}
	if authenticationInstant.IsZero() {
		authenticationInstant = now
	}
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
	b.WriteString("<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"")
	b.WriteString(samlSOAPNamespace)
	b.WriteString("\">")
	b.WriteString("<SOAP-ENV:Header/><SOAP-ENV:Body>")
	b.WriteString("<saml1p:Response xmlns:saml1p=\"")
	b.WriteString(samlProtocolNamespace)
	b.WriteString("\" MajorVersion=\"1\" MinorVersion=\"1\" IssueInstant=\"")
	b.WriteString(now.UTC().Format(time.RFC3339))
	b.WriteString("\" ResponseID=\"_")
	writeEscaped(&b, responseID)
	b.WriteString("\"><saml1p:Status><saml1p:StatusCode Value=\"saml1p:Success\"/></saml1p:Status>")
	b.WriteString("<saml1:Assertion xmlns:saml1=\"")
	b.WriteString(samlAssertionNamespace)
	b.WriteString("\" MajorVersion=\"1\" MinorVersion=\"1\" AssertionID=\"_")
	writeEscaped(&b, assertionID)
	b.WriteString("\" IssueInstant=\"")
	b.WriteString(now.UTC().Format(time.RFC3339))
	b.WriteString("\" Issuer=\"")
	writeEscaped(&b, validation.Issuer)
	b.WriteString("\">")
	b.WriteString("<saml1:Conditions NotBefore=\"")
	b.WriteString(notBefore.UTC().Format(time.RFC3339))
	b.WriteString("\" NotOnOrAfter=\"")
	b.WriteString(notOnOrAfter.UTC().Format(time.RFC3339))
	b.WriteString("\"><saml1:AudienceRestrictionCondition><saml1:Audience>")
	writeEscaped(&b, validation.Service)
	b.WriteString("</saml1:Audience></saml1:AudienceRestrictionCondition></saml1:Conditions>")
	b.WriteString("<saml1:AuthenticationStatement AuthenticationInstant=\"")
	b.WriteString(authenticationInstant.UTC().Format(time.RFC3339))
	b.WriteString("\" AuthenticationMethod=\"")
	b.WriteString(samlAuthenticationMethod)
	b.WriteString("\"><saml1:Subject><saml1:NameIdentifier>")
	writeEscaped(&b, validation.User)
	b.WriteString("</saml1:NameIdentifier></saml1:Subject></saml1:AuthenticationStatement>")
	writeSAMLAttributeStatement(&b, validation)
	b.WriteString("</saml1:Assertion></saml1p:Response></SOAP-ENV:Body></SOAP-ENV:Envelope>")
	return []byte(b.String())
}

// writeSAMLAttributeStatement writes the attribute statement of the default assertion. Attributes
// without a legal XML name are omitted because SAML 1.1 cannot represent them. | writeSAMLAttributeStatement
// 写出默认断言的属性语句。名称不是合法 XML 的属性会被省略，因为 SAML 1.1 无法表示它们。
func writeSAMLAttributeStatement(b *strings.Builder, validation *SAMLValidation) {
	if len(validation.Attributes) == 0 {
		return
	}
	keys := make([]string, 0, len(validation.Attributes))
	for key := range validation.Attributes {
		if validXMLName(key) {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return
	}
	sort.Strings(keys)
	b.WriteString("<saml1:AttributeStatement><saml1:Subject><saml1:NameIdentifier>")
	writeEscaped(b, validation.User)
	b.WriteString("</saml1:NameIdentifier></saml1:Subject>")
	for _, key := range keys {
		b.WriteString("<saml1:Attribute AttributeName=\"")
		writeEscaped(b, key)
		b.WriteString("\" AttributeNamespace=\"urn:oasis:names:tc:SAML:1.0:assertion\">")
		for _, value := range validation.Attributes[key] {
			b.WriteString("<saml1:AttributeValue>")
			writeEscaped(b, value)
			b.WriteString("</saml1:AttributeValue>")
		}
		b.WriteString("</saml1:Attribute>")
	}
	b.WriteString("</saml1:AttributeStatement>")
}

// writeSAMLFault writes a SOAP fault for a SAML request that cannot be answered with an assertion. |
// writeSAMLFault 为无法以断言回答的 SAML 请求写出 SOAP 错误。
func writeSAMLFault(w http.ResponseWriter, message string) {
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
	b.WriteString("<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"")
	b.WriteString(samlSOAPNamespace)
	b.WriteString("\"><SOAP-ENV:Header/><SOAP-ENV:Body><SOAP-ENV:Fault>")
	b.WriteString("<faultcode>SOAP-ENV:Client</faultcode><faultstring>")
	writeEscaped(&b, message)
	b.WriteString("</faultstring></SOAP-ENV:Fault></SOAP-ENV:Body></SOAP-ENV:Envelope>")
	writeSAMLResponse(w, []byte(b.String()))
}

// writeSAMLResponse writes a complete SAML SOAP response. | writeSAMLResponse 写出完整的 SAML SOAP 响应。
func writeSAMLResponse(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", casContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
