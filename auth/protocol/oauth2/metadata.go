package oauth2

import (
	"net/http"

	"github.com/shibingli/ydx/errs"
)

// MetadataDocument builds the RFC 8414 metadata for the server. | MetadataDocument 构建服务器的 RFC 8414 元数据。
func (s *Server) MetadataDocument() *ServerMetadata {
	responseTypes := []string{ResponseCode, ResponseNone}
	if s.config.AuthorizationEnricher != nil {
		responseTypes = append(responseTypes, ResponseIDToken, "code id_token")
	}
	if s.config.AllowImplicit {
		responseTypes = append(responseTypes, ResponseToken, "code token", "token id_token")
		if s.config.AuthorizationEnricher != nil {
			responseTypes = append(responseTypes, "code id_token token")
		}
	}
	grantTypes := []string{GrantAuthorizationCode, GrantRefreshToken, GrantClientCredentials}
	if s.config.AllowPasswordGrant {
		grantTypes = append(grantTypes, GrantPassword)
	}
	if !s.config.DisableDeviceFlow {
		grantTypes = append(grantTypes, GrantDeviceCode)
	}
	if s.config.EnableTokenExchange {
		grantTypes = append(grantTypes, GrantTokenExchange)
	}
	if s.config.EnableJWTBearer {
		grantTypes = append(grantTypes, GrantJWTBearer)
	}
	authMethods := []string{ClientAuthNone, ClientSecretBasic, ClientSecretPost}
	if s.config.ClientAssertionVerifier != nil {
		authMethods = append(authMethods, PrivateKeyJWT)
	}
	authMethods = append(authMethods, TLSClientAuth, SelfSignedTLSClientAuth)
	pkceMethods := []string{PKCES256}
	if s.config.AllowPKCEPlain {
		pkceMethods = append(pkceMethods, PKCEPlain)
	}
	responseModes := []string{ResponseModeQuery, ResponseModeFragment, ResponseModeFormPost}
	if s.config.AuthorizationResponseSigner != nil {
		responseModes = append(responseModes, ResponseModeQueryJWT, ResponseModeFragmentJWT, ResponseModeFormPostJWT)
	}
	metadata := &ServerMetadata{
		Issuer:                                     s.Issuer(),
		AuthorizationEndpoint:                      s.Endpoint(s.config.AuthorizationPath),
		TokenEndpoint:                              s.Endpoint(s.config.TokenPath),
		JWKSURI:                                    s.config.JWKSURI,
		RegistrationEndpoint:                       s.config.RegistrationEndpoint,
		ScopesSupported:                            s.scopeList(),
		ResponseTypesSupported:                     responseTypes,
		ResponseModesSupported:                     responseModes,
		RequestParameterSupported:                  s.config.RequestObjects.Enabled,
		RequestURIParameterSupported:               s.config.RequestURIs.Enabled,
		RequireRequestURIRegistration:              s.config.RequestURIs.Enabled && s.config.RequestURIs.RequireRegistration,
		GrantTypesSupported:                        grantTypes,
		TokenEndpointAuthMethodsSupported:          authMethods,
		RevocationEndpointAuthMethodsSupported:     append([]string(nil), authMethods...),
		IntrospectionEndpointAuthMethodsSupported:  append([]string(nil), authMethods...),
		RevocationEndpoint:                         s.Endpoint(s.config.RevocationPath),
		IntrospectionEndpoint:                      s.Endpoint(s.config.IntrospectionPath),
		PushedAuthorizationRequestEndpoint:         s.Endpoint(s.config.PARPath),
		CodeChallengeMethodsSupported:              pkceMethods,
		AuthorizationResponseIssParameterSupported: !s.config.DisableIssuerParameter,
	}
	if !s.config.DisableDeviceFlow {
		metadata.DeviceAuthorizationEndpoint = s.Endpoint(s.config.DeviceAuthorizationPath)
	}
	if s.config.RequestObjects.Enabled && s.requestObjects != nil {
		metadata.RequestObjectSigningAlgValuesSupported = append([]string(nil), s.requestObjects.config.SigningAlgs...)
	}
	if signer, ok := s.config.AuthorizationResponseSigner.(AuthorizationSigningAlgProvider); ok {
		metadata.AuthorizationSigningAlgValuesSupported = append([]string(nil), signer.AuthorizationSigningAlgValuesSupported()...)
	}
	if s.config.ClientAssertionVerifier != nil {
		metadata.TokenEndpointAuthSigningAlgValuesSupported = []string{"RS256", "PS256", "ES256", "EdDSA"}
	}
	if s.config.DPoPVerifier != nil {
		metadata.DPoPSigningAlgValuesSupported = []string{"RS256", "PS256", "ES256", "EdDSA"}
		metadata.DPoPBoundAccessTokensRequired = s.config.DPoPRequired
	}
	if s.config.TokenFormat == TokenFormatJWT {
		metadata.AccessTokenSigningAlgValuesSupported = []string{"RS256", "PS256", "ES256", "EdDSA"}
	}
	return metadata
}

// scopeList returns the registered scope names. | scopeList 返回已注册作用域名。
func (s *Server) scopeList() []string {
	if s.config.Scopes == nil {
		return nil
	}
	return s.config.Scopes.List()
}

// Metadata serves the RFC 8414 metadata document. | Metadata 提供 RFC 8414 元数据文档。
func (s *Server) Metadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		s.writeOAuthError(w, r, errs.Detail(ErrInvalidRequest, "method %[1]s not allowed | 不允许方法 %[1]s", r.Method))
		return
	}
	writeJSON(w, http.StatusOK, s.MetadataDocument())
}
