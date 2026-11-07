package wsfed

import (
	"net/http"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/xml"
)

// FederationMetadata is a minimal WS-Federation metadata document. | FederationMetadata 是最小
// WS-Federation 元数据文档。
type FederationMetadata struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	// EntityID is the token service entity ID. | EntityID 是令牌服务实体标识。
	EntityID string `xml:"entityID,attr"`
	// RoleDescriptor describes the security token service role. | RoleDescriptor 描述安全令牌服务角色。
	RoleDescriptor *FederationRoleDescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata RoleDescriptor,omitempty"`
}

// FederationRoleDescriptor describes a WS-Federation security token service role. |
// FederationRoleDescriptor 描述 WS-Federation 安全令牌服务角色。
type FederationRoleDescriptor struct {
	// Type is the xsi:type QName. | Type 是 xsi:type QName。
	Type string `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
	// FederationNamespace declares the fed prefix. | FederationNamespace 声明 fed 前缀。
	FederationNamespace string `xml:"xmlns:fed,attr"`
	// ProtocolSupportEnumeration lists supported WS-Trust namespaces. | ProtocolSupportEnumeration
	// 列出支持的 WS-Trust 命名空间。
	ProtocolSupportEnumeration string `xml:"protocolSupportEnumeration,attr"`
	// SecurityTokenServiceEndpoint advertises the token endpoint. | SecurityTokenServiceEndpoint 通告
	// 令牌端点。
	SecurityTokenServiceEndpoint []FederationEndpoint `xml:"http://docs.oasis-open.org/wsfed/federation/200706 SecurityTokenServiceEndpoint,omitempty"`
	// PassiveRequestorEndpoint advertises passive sign-in and sign-out endpoints. |
	// PassiveRequestorEndpoint 通告被动登录与登出端点。
	PassiveRequestorEndpoint []FederationEndpoint `xml:"http://docs.oasis-open.org/wsfed/federation/200706 PassiveRequestorEndpoint,omitempty"`
	// TokenTypesOffered lists the issued token types. | TokenTypesOffered 列出已签发令牌类型。
	TokenTypesOffered *FederationTokenTypesOffered `xml:"http://docs.oasis-open.org/wsfed/federation/200706 TokenTypesOffered,omitempty"`
}

// FederationEndpoint is a WS-Addressing endpoint reference. | FederationEndpoint 是 WS-Addressing
// 端点引用。
type FederationEndpoint struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"http://www.w3.org/2005/08/addressing EndpointReference"`
	// Address is the endpoint address. | Address 是端点地址。
	Address string `xml:"http://www.w3.org/2005/08/addressing Address"`
}

// FederationTokenTypesOffered lists offered token types. | FederationTokenTypesOffered 列出提供的
// 令牌类型。
type FederationTokenTypesOffered struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"http://docs.oasis-open.org/wsfed/federation/200706 TokenTypesOffered"`
	// TokenType is the token type URI list. | TokenType 是令牌类型 URI 列表。
	TokenType []string `xml:"http://docs.oasis-open.org/wsfed/federation/200706 TokenType,omitempty"`
}

// Metadata returns the federation metadata document. | Metadata 返回联合元数据文档。
func (sts *SecurityTokenService) Metadata() *FederationMetadata {
	tokenTypes := []string{TokenTypeSAML20, TokenTypeSAML11}
	if sts.config.TokenType == TokenTypeJWT {
		tokenTypes = append([]string{TokenTypeJWT}, tokenTypes...)
	}
	endpoints := []FederationEndpoint{{Address: sts.signInURL}}
	if sts.signOutURL != "" {
		endpoints = append(endpoints, FederationEndpoint{Address: sts.signOutURL})
	}
	return &FederationMetadata{
		EntityID: sts.config.Issuer,
		RoleDescriptor: &FederationRoleDescriptor{
			Type:                       "fed:SecurityTokenServiceType",
			FederationNamespace:        NamespaceWSFed,
			ProtocolSupportEnumeration: NamespaceWSTrust + " " + NamespaceWSTrust2005,
			SecurityTokenServiceEndpoint: []FederationEndpoint{{
				Address: sts.signInURL,
			}},
			PassiveRequestorEndpoint: endpoints,
			TokenTypesOffered:        &FederationTokenTypesOffered{TokenType: tokenTypes},
		},
	}
}

// MetadataXML serializes the federation metadata document. | MetadataXML 序列化联合元数据文档。
func (sts *SecurityTokenService) MetadataXML() ([]byte, error) {
	data, err := xml.Marshal(sts.Metadata())
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidResponse)
	}
	return data, nil
}

// MetadataHandler serves the federation metadata document. | MetadataHandler 提供联合元数据文档。
func (sts *SecurityTokenService) MetadataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := sts.MetadataXML()
	if err != nil {
		http.Error(w, "metadata error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/wsfederationmetadata+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
