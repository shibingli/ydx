package saml

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/xml"
)

// HandleSLO processes a SAML Single Logout request or response. | HandleSLO 处理 SAML 单点登出请求或响应。
func (sp *ServiceProvider) HandleSLO(w http.ResponseWriter, r *http.Request) {
	boundFormBody(w, r)
	raw, relayState, isRequest, redirect, err := readSLOMessage(r)
	if err != nil {
		http.Error(w, "invalid SAML logout message", http.StatusBadRequest)
		return
	}
	if !isRequest {
		response, err := DecodeLogoutResponse(raw)
		if err != nil {
			http.Error(w, "invalid logout response", http.StatusBadRequest)
			return
		}
		if redirect {
			if err := verifySLORedirect(r.Context(), r.URL.RawQuery, "SAMLResponse", issuerString(response.Issuer), relayState, sp.config.RedirectVerifier, sp.config.RequireSignedLogout); err != nil {
				http.Error(w, "invalid logout response", http.StatusBadRequest)
				return
			}
		}
		if err := sp.validateLogoutResponse(r.Context(), raw, response, relayState, redirect); err != nil {
			http.Error(w, "invalid logout response", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("logged out"))
		return
	}
	request, err := DecodeLogoutRequest(raw)
	if err != nil {
		http.Error(w, "invalid logout request", http.StatusBadRequest)
		return
	}
	if redirect {
		if err := verifySLORedirect(r.Context(), r.URL.RawQuery, "SAMLRequest", issuerString(request.Issuer), relayState, sp.config.RedirectVerifier, sp.config.RequireSignedLogout); err != nil {
			http.Error(w, "invalid logout request", http.StatusBadRequest)
			return
		}
	}
	if err := sp.validateLogoutRequest(r.Context(), raw, request, redirect); err != nil {
		http.Error(w, "invalid logout request", http.StatusBadRequest)
		return
	}
	partial, err := sp.terminateSessions(r.Context(), request)
	if err != nil {
		http.Error(w, "logout failed", http.StatusInternalServerError)
		return
	}
	status := StatusSuccess
	if partial {
		status = StatusPartialLogout
	}
	binding := BindingHTTPPost
	if redirect {
		binding = BindingHTTPRedirect
	}
	destination := sp.config.IDPMetadata.SLOURL(binding)
	if destination == "" {
		destination = sp.config.IDPMetadata.SLOURL("")
	}
	document, err := encodeLogoutResponse(sp.config.EntityID, destination, request.ID, Now(sp.now), status)
	if err != nil {
		http.Error(w, "logout response error", http.StatusInternalServerError)
		return
	}
	if err := writeSLOMessage(w, r, destination, "SAMLResponse", document, relayState, redirect, sp.config.RequestSigningKey, sp.config.RequestSigningAlg); err != nil {
		http.Error(w, "logout response error", http.StatusInternalServerError)
	}
}

// validateLogoutRequest validates an IdP-initiated LogoutRequest and rejects replays. A redirect
// message has already satisfied the signed-only policy through its query signature. |
// validateLogoutRequest 校验 IdP 发起的 LogoutRequest 并拒绝重放。重定向消息已通过查询签名满足
// 仅签名策略。
func (sp *ServiceProvider) validateLogoutRequest(ctx context.Context, raw []byte, request *LogoutRequest, redirect bool) error {
	if request == nil {
		return errs.Detail(ErrInvalidRequest, "logout request is nil | 登出请求为空")
	}
	now := Now(sp.now)
	skew := sp.config.ClockSkew
	if skew <= 0 {
		skew = 2 * time.Minute
	}
	if request.Version != Version {
		return errs.Detail(ErrInvalidRequest, "unsupported version %[1]q | 不支持的版本 %[1]q", request.Version)
	}
	if request.ID == "" {
		return errs.Detail(ErrInvalidRequest, "logout request ID is missing | 缺少登出请求 ID")
	}
	if err := validateProtocolInstant("logout request", request.IssueInstant, now, skew, sp.config.MaxIssueAge, ErrInvalidRequest); err != nil {
		return err
	}
	if request.Issuer == nil || request.Issuer.Value != sp.config.IDPMetadata.EntityID {
		return errs.Detail(ErrInvalidIssuer, "logout issuer does not match | 登出签发方不匹配")
	}
	if request.NameID == nil || request.NameID.Value == "" {
		return errs.Detail(ErrInvalidRequest, "logout NameID is missing | 缺少登出 NameID")
	}
	if request.Destination != "" && sp.config.SLOURL != "" && request.Destination != sp.config.SLOURL {
		return errs.Detail(ErrInvalidRecipient, "logout destination mismatch | 登出目标不匹配")
	}
	expiresAt, err := logoutExpiry(request.NotOnOrAfter, now, skew)
	if err != nil {
		return err
	}
	if err := verifyLogoutSignature(ctx, raw, request.ID, request.Signature, sp.config.SignatureVerifier, sp.config.RequireSignedLogout && !redirect, request.Destination); err != nil {
		return err
	}
	if sp.store != nil {
		fresh, err := sp.store.SaveAssertion(ctx, "logout:"+request.ID, expiresAt, now)
		if err != nil {
			return err
		}
		if !fresh {
			return ErrReplay
		}
	}
	return nil
}

// validateLogoutResponse validates a LogoutResponse received by the SP and consumes the correlated
// request. A redirect message has already satisfied the signed-only policy through its query
// signature. | validateLogoutResponse 校验 SP 收到的 LogoutResponse 并消费关联请求。重定向消息已
// 通过查询签名满足仅签名策略。
func (sp *ServiceProvider) validateLogoutResponse(ctx context.Context, raw []byte, response *LogoutResponse, relayState string, redirect bool) error {
	if response == nil {
		return errs.Detail(ErrInvalidResponse, "logout response is nil | 登出响应为空")
	}
	now := Now(sp.now)
	skew := sp.config.ClockSkew
	if skew <= 0 {
		skew = 2 * time.Minute
	}
	if response.Version != Version {
		return errs.Detail(ErrInvalidResponse, "unsupported version %[1]q | 不支持的版本 %[1]q", response.Version)
	}
	if response.ID == "" {
		return errs.Detail(ErrInvalidResponse, "logout response ID is missing | 缺少登出响应 ID")
	}
	if response.InResponseTo == "" {
		return errs.Detail(ErrInvalidRequest, "logout InResponseTo is missing | 缺少登出 InResponseTo")
	}
	if err := validateProtocolInstant("logout response", response.IssueInstant, now, skew, sp.config.MaxIssueAge, ErrInvalidResponse); err != nil {
		return err
	}
	if response.Issuer == nil || response.Issuer.Value != sp.config.IDPMetadata.EntityID {
		return errs.Detail(ErrInvalidIssuer, "logout response issuer does not match | 登出响应签发方不匹配")
	}
	if response.Destination != "" && sp.config.SLOURL != "" && response.Destination != sp.config.SLOURL {
		return errs.Detail(ErrInvalidRecipient, "logout response destination mismatch | 登出响应目标不匹配")
	}
	if !logoutStatusAcceptable(response.Status) {
		return errs.Detail(ErrStatusFailure, "logout status is not successful | 登出状态非成功")
	}
	if err := verifyLogoutSignature(ctx, raw, response.ID, response.Signature, sp.config.SignatureVerifier, sp.config.RequireSignedLogout && !redirect, response.Destination); err != nil {
		return err
	}
	state, err := sp.consumeLogoutRequest(ctx, response.InResponseTo, now)
	if err != nil {
		return err
	}
	if relayState != "" && state.RelayState != "" && relayState != state.RelayState {
		return errs.Detail(ErrInvalidRequest, "logout RelayState mismatch | 登出 RelayState 不匹配")
	}
	return nil
}

// consumeLogoutRequest consumes the outstanding LogoutRequest answered by a response. |
// consumeLogoutRequest 消费响应所应答的未完成 LogoutRequest。
func (sp *ServiceProvider) consumeLogoutRequest(ctx context.Context, id string, now time.Time) (*RequestState, error) {
	if sp.store == nil {
		return nil, errs.Detail(ErrInvalidConfig, "logout correlation requires a Store | 登出关联需要 Store")
	}
	state, err := sp.store.ConsumeRequest(ctx, id, now)
	if err != nil {
		return nil, err
	}
	if state.SPEntityID != "" && state.SPEntityID != sp.config.EntityID {
		return nil, errs.Detail(ErrInvalidIssuer, "logout request SP entity mismatch | 登出请求 SP 实体不匹配")
	}
	return state, nil
}

// terminateSessions deletes the sessions named by a LogoutRequest and reports a partial logout. |
// terminateSessions 删除 LogoutRequest 指定的会话并报告部分登出。
func (sp *ServiceProvider) terminateSessions(ctx context.Context, request *LogoutRequest) (bool, error) {
	if sp.store == nil || request == nil || request.NameID == nil {
		return false, nil
	}
	return terminateStoreSessions(ctx, sp.store, request.NameID.Value, "", request.SessionIndex)
}

// terminateStoreSessions deletes matching sessions and reports whether any requested session was
// missing or belonged to another party. | terminateStoreSessions 删除匹配会话，并报告是否有请求的
// 会话缺失或属于其它方。
func terminateStoreSessions(ctx context.Context, store Store, nameID, spEntityID string, indices []string) (bool, error) {
	if store == nil {
		return false, nil
	}
	if len(indices) > 0 {
		partial := false
		for _, index := range indices {
			session, err := store.GetSession(ctx, index)
			if err != nil {
				partial = true
				continue
			}
			if session.NameID != "" && session.NameID != nameID {
				partial = true
				continue
			}
			if spEntityID != "" && session.SPEntityID != "" && session.SPEntityID != spEntityID {
				partial = true
				continue
			}
			if err := store.DeleteSession(ctx, index); err != nil {
				return partial, err
			}
		}
		return partial, nil
	}
	sessions, err := store.ListSessions(ctx, nameID)
	if err != nil {
		return false, err
	}
	for _, session := range sessions {
		if spEntityID != "" && session.SPEntityID != "" && session.SPEntityID != spEntityID {
			continue
		}
		if err := store.DeleteSession(ctx, session.ID); err != nil {
			return false, err
		}
	}
	return false, nil
}

// HandleSLO processes a SAML Single Logout request or response at the IdP. | HandleSLO 在 IdP 处理
// SAML 单点登出请求或响应。
func (idp *IdentityProvider) HandleSLO(w http.ResponseWriter, r *http.Request) {
	boundFormBody(w, r)
	raw, relayState, isRequest, redirect, err := readSLOMessage(r)
	if err != nil {
		http.Error(w, "invalid SAML logout message", http.StatusBadRequest)
		return
	}
	if !isRequest {
		response, err := DecodeLogoutResponse(raw)
		if err != nil {
			http.Error(w, "invalid logout response", http.StatusBadRequest)
			return
		}
		if redirect {
			if err := verifySLORedirect(r.Context(), r.URL.RawQuery, "SAMLResponse", issuerString(response.Issuer), relayState, idp.config.RedirectVerifier, idp.config.WantLogoutRequestsSigned); err != nil {
				http.Error(w, "invalid logout response", http.StatusBadRequest)
				return
			}
		}
		if err := idp.handleLogoutResponse(r.Context(), raw, relayState, redirect); err != nil {
			http.Error(w, "invalid logout response", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("logged out"))
		return
	}
	request, err := DecodeLogoutRequest(raw)
	if err != nil {
		http.Error(w, "invalid logout request", http.StatusBadRequest)
		return
	}
	if redirect {
		if err := verifySLORedirect(r.Context(), r.URL.RawQuery, "SAMLRequest", issuerString(request.Issuer), relayState, idp.config.RedirectVerifier, idp.config.WantLogoutRequestsSigned); err != nil {
			http.Error(w, "invalid logout request", http.StatusBadRequest)
			return
		}
	}
	partial, destination, err := idp.validateLogoutRequest(r.Context(), raw, request, redirect)
	if err != nil {
		http.Error(w, "invalid logout request", http.StatusBadRequest)
		return
	}
	status := StatusSuccess
	if partial {
		status = StatusPartialLogout
	}
	document, err := encodeLogoutResponse(idp.config.EntityID, destination, request.ID, Now(idp.now), status)
	if err != nil {
		http.Error(w, "logout response error", http.StatusInternalServerError)
		return
	}
	if !redirect && idp.config.Signer != nil {
		signed, signErr := idp.config.Signer.SignElement(document, logoutResponseID(document))
		if signErr != nil {
			http.Error(w, "logout response signature error", http.StatusInternalServerError)
			return
		}
		document = signed
	}
	if err := writeSLOMessage(w, r, destination, "SAMLResponse", document, relayState, redirect, idp.config.SigningKey, idp.config.SigningAlg); err != nil {
		http.Error(w, "logout response error", http.StatusInternalServerError)
	}
}

// handleLogoutResponse validates a LogoutResponse sent to the IdP. A redirect message has already
// satisfied the signed-only policy through its query signature. | handleLogoutResponse 校验发送给
// IdP 的 LogoutResponse。重定向消息已通过查询签名满足仅签名策略。
func (idp *IdentityProvider) handleLogoutResponse(ctx context.Context, raw []byte, relayState string, redirect bool) error {
	response, err := DecodeLogoutResponse(raw)
	if err != nil {
		return err
	}
	now := Now(idp.now)
	skew := idp.config.ClockSkew
	if skew <= 0 {
		skew = 2 * time.Minute
	}
	if response.Version != Version || response.ID == "" {
		return errs.Detail(ErrInvalidResponse, "invalid logout response | 登出响应非法")
	}
	if err := validateProtocolInstant("logout response", response.IssueInstant, now, skew, idp.config.MaxIssueAge, ErrInvalidResponse); err != nil {
		return err
	}
	if response.Issuer == nil || response.Issuer.Value == "" {
		return errs.Detail(ErrInvalidIssuer, "logout response issuer is missing | 缺少登出响应签发方")
	}
	if idp.config.SPResolver != nil {
		if _, err := idp.config.SPResolver.Resolve(ctx, response.Issuer.Value); err != nil {
			return errs.Wrap(err, ErrInvalidIssuer)
		}
	}
	if response.Destination != "" && idp.config.SLOURL != "" && response.Destination != idp.config.SLOURL {
		return errs.Detail(ErrInvalidRecipient, "logout response destination mismatch | 登出响应目标不匹配")
	}
	if !logoutStatusAcceptable(response.Status) {
		return errs.Detail(ErrStatusFailure, "logout status is not successful | 登出状态非成功")
	}
	if err := verifyLogoutSignature(ctx, raw, response.ID, response.Signature, idp.config.SignatureVerifier, idp.config.WantLogoutRequestsSigned && !redirect, response.Destination); err != nil {
		return err
	}
	if response.InResponseTo != "" {
		if idp.store == nil {
			return errs.Detail(ErrInvalidConfig, "logout correlation requires a Store | 登出关联需要 Store")
		}
		state, err := idp.store.ConsumeRequest(ctx, response.InResponseTo, now)
		if err != nil {
			return err
		}
		if relayState != "" && state.RelayState != "" && relayState != state.RelayState {
			return errs.Detail(ErrInvalidRequest, "logout RelayState mismatch | 登出 RelayState 不匹配")
		}
	}
	return nil
}

// validateLogoutRequest validates an SP-initiated LogoutRequest, deletes the target sessions and
// returns the SP response destination. A redirect message has already satisfied the signed-only
// policy through its query signature. | validateLogoutRequest 校验 SP 发起的 LogoutRequest、删除
// 目标会话并返回 SP 响应目标。重定向消息已通过查询签名满足仅签名策略。
func (idp *IdentityProvider) validateLogoutRequest(ctx context.Context, raw []byte, request *LogoutRequest, redirect bool) (bool, string, error) {
	if request == nil {
		return false, "", errs.Detail(ErrInvalidRequest, "logout request is nil | 登出请求为空")
	}
	now := Now(idp.now)
	skew := idp.config.ClockSkew
	if skew <= 0 {
		skew = 2 * time.Minute
	}
	if request.Version != Version || request.ID == "" {
		return false, "", errs.Detail(ErrInvalidRequest, "invalid logout request | 登出请求非法")
	}
	if err := validateProtocolInstant("logout request", request.IssueInstant, now, skew, idp.config.MaxIssueAge, ErrInvalidRequest); err != nil {
		return false, "", err
	}
	if request.Issuer == nil || request.Issuer.Value == "" {
		return false, "", errs.Detail(ErrInvalidIssuer, "logout request issuer is missing | 缺少登出请求签发方")
	}
	if request.NameID == nil || request.NameID.Value == "" {
		return false, "", errs.Detail(ErrInvalidRequest, "logout NameID is missing | 缺少登出 NameID")
	}
	if request.Destination != "" && idp.config.SLOURL != "" && request.Destination != idp.config.SLOURL {
		return false, "", errs.Detail(ErrInvalidRecipient, "logout destination mismatch | 登出目标不匹配")
	}
	expiresAt, err := logoutExpiry(request.NotOnOrAfter, now, skew)
	if err != nil {
		return false, "", err
	}
	if err := verifyLogoutSignature(ctx, raw, request.ID, request.Signature, idp.config.SignatureVerifier, idp.config.WantLogoutRequestsSigned && !redirect, request.Destination); err != nil {
		return false, "", err
	}
	if idp.store != nil {
		fresh, err := idp.store.SaveAssertion(ctx, "logout:"+request.ID, expiresAt, now)
		if err != nil {
			return false, "", err
		}
		if !fresh {
			return false, "", ErrReplay
		}
	}
	destination := ""
	if idp.config.SPResolver != nil {
		metadata, err := idp.config.SPResolver.Resolve(ctx, request.Issuer.Value)
		if err != nil {
			return false, "", errs.Wrap(err, ErrInvalidIssuer)
		}
		destination = metadata.SLOURL(BindingHTTPPost)
		if destination == "" {
			destination = metadata.SLOURL("")
		}
	}
	if destination == "" {
		return false, "", errs.Detail(ErrInvalidMetadata, "SP has no SLO endpoint | SP 没有 SLO 端点")
	}
	partial, err := terminateStoreSessions(ctx, idp.store, request.NameID.Value, request.Issuer.Value, request.SessionIndex)
	if err != nil {
		return false, "", err
	}
	return partial, destination, nil
}

// logoutExpiry returns the request expiry used for replay retention. | logoutExpiry 返回用于重放
// 保留的请求过期时间。
func logoutExpiry(notOnOrAfter string, now time.Time, skew time.Duration) (time.Time, error) {
	if notOnOrAfter == "" {
		return now.Add(10 * time.Minute), nil
	}
	parsed, err := ParseTime(notOnOrAfter)
	if err != nil {
		return time.Time{}, err
	}
	if !now.Add(-skew).Before(parsed) {
		return time.Time{}, ErrResponseExpired
	}
	return parsed, nil
}

// verifySLORedirect enforces the HTTP-Redirect binding signature policy for a logout message.
// rawQuery is the exact signed octet sequence. A signed message requires a configured verifier;
// an unsigned message is accepted only when required is false, preserving unsigned compatibility
// mode. | verifySLORedirect 对登出消息执行 HTTP-Redirect 绑定签名策略。rawQuery 是参与签名的精确
// 八位组序列。签名消息必须配置校验器；未签名消息仅在 required 为 false 时接受，以保留未签名兼容
// 模式。
func verifySLORedirect(ctx context.Context, rawQuery, parameter, issuer, relayState string, verifier RedirectVerifier, required bool) error {
	params, err := url.ParseQuery(rawQuery)
	if err != nil {
		return errs.WrapDetail(err, ErrInvalidSignature, "redirect %s query is invalid | 重定向 %s 查询非法", parameter, parameter)
	}
	signed := params.Get("Signature") != "" || params.Get("SigAlg") != ""
	if !signed {
		if required {
			return errs.Detail(ErrInvalidSignature, "redirect %s is not signed | 重定向 %s 未签名", parameter, parameter)
		}
		return nil
	}
	if verifier == nil {
		return errs.Detail(ErrInvalidSignature, "no redirect verifier configured | 未配置重定向签名校验器")
	}
	if err := verifier(ctx, rawQuery, params, issuer, relayState); err != nil {
		return errs.Wrap(err, ErrInvalidSignature)
	}
	return nil
}

// issuerString returns the issuer value or an empty string. | issuerString 返回签发方取值或空串。
func issuerString(issuer *Issuer) string {
	if issuer == nil {
		return ""
	}
	return issuer.Value
}

// verifyLogoutSignature verifies a present logout signature and enforces signed-only mode. |
// verifyLogoutSignature 校验存在的登出签名并强制仅签名模式。
func verifyLogoutSignature(ctx context.Context, raw []byte, id string, signature *SignatureMarker, verifier SignatureVerifier, required bool, destination string) error {
	if signature == nil {
		if required {
			return errs.Detail(ErrInvalidSignature, "logout message is not signed | 登出消息未签名")
		}
		return nil
	}
	if verifier == nil {
		return errs.Detail(ErrInvalidSignature, "no signature verifier configured | 未配置签名校验器")
	}
	if destination == "" {
		return errs.Detail(ErrInvalidRecipient, "signed logout message has no destination | 签名登出消息缺少目标")
	}
	if err := verifier.VerifySignature(ctx, raw, id); err != nil {
		return errs.Wrap(err, ErrInvalidSignature)
	}
	return nil
}

// logoutStatusAcceptable reports whether a status is success or partial logout. |
// logoutStatusAcceptable 报告状态是否为成功或部分登出。
func logoutStatusAcceptable(status *Status) bool {
	if status == nil || status.StatusCode == nil {
		return false
	}
	code := status.StatusCode.Value
	if code == StatusSuccess || code == StatusPartialLogout {
		return true
	}
	return status.StatusCode.StatusCode != nil && status.StatusCode.StatusCode.Value == StatusPartialLogout
}

// encodeLogoutResponse builds a LogoutResponse with a status. | encodeLogoutResponse 构建带状态的
// LogoutResponse。
func encodeLogoutResponse(issuer, destination, inResponseTo string, now time.Time, status string) ([]byte, error) {
	response := LogoutResponse{
		ID:           auth.NewID("logout"),
		InResponseTo: inResponseTo,
		Version:      Version,
		IssueInstant: FormatTime(now),
		Destination:  destination,
		Issuer:       &Issuer{Value: issuer},
		Status:       statusFor(status),
	}
	return xml.Marshal(&response)
}

// logoutResponseID parses the response ID for signing; an empty ID returns an empty string. |
// logoutResponseID 解析用于签名的响应标识；空标识返回空串。
func logoutResponseID(document []byte) string {
	response, err := DecodeLogoutResponse(document)
	if err != nil {
		return ""
	}
	return response.ID
}

// readSLOMessage reads a SAMLRequest or SAMLResponse. | readSLOMessage 读取 SAMLRequest 或 SAMLResponse。
func readSLOMessage(r *http.Request) ([]byte, string, bool, bool, error) {
	if r == nil {
		return nil, "", false, false, errs.Detail(ErrInvalidRequest, "request is nil | 请求为空")
	}
	if err := checkFormBody(r); err != nil {
		return nil, "", false, false, err
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			return nil, "", false, false, formParseError(err)
		}
		relayState := r.PostForm.Get("RelayState")
		if value := r.PostForm.Get("SAMLRequest"); value != "" {
			decoded, err := DecodePost(value)
			return decoded, relayState, true, false, err
		}
		if value := r.PostForm.Get("SAMLResponse"); value != "" {
			decoded, err := DecodePost(value)
			return decoded, relayState, false, false, err
		}
		return nil, "", false, false, errs.Detail(ErrInvalidRequest, "SAML message is missing | 缺少 SAML 消息")
	}
	relayState := r.URL.Query().Get("RelayState")
	if value := r.URL.Query().Get("SAMLRequest"); value != "" {
		decoded, err := DecodeRedirect(value)
		return decoded, relayState, true, true, err
	}
	if value := r.URL.Query().Get("SAMLResponse"); value != "" {
		decoded, err := DecodeRedirect(value)
		return decoded, relayState, false, true, err
	}
	return nil, "", false, false, errs.Detail(ErrInvalidRequest, "SAML message is missing | 缺少 SAML 消息")
}

// writeSLOMessage sends a SLO response using the request's binding when possible. | writeSLOMessage
// 尽可能使用请求的绑定发送 SLO 响应。
func writeSLOMessage(w http.ResponseWriter, r *http.Request, destination, parameter string, document []byte, relayState string, redirect bool, signingKey any, signingAlg string) error {
	if destination == "" {
		WritePostForm(w, r.URL.Path, parameter, EncodePost(document), relayState)
		return nil
	}
	if redirect {
		encoded, err := EncodeRedirect(document)
		if err != nil {
			return err
		}
		params := url.Values{parameter: {encoded}}
		if relayState != "" {
			params.Set("RelayState", relayState)
		}
		if signingKey != nil {
			if err := SignRedirectMessage(params, parameter, signingKey, signingAlg, relayState); err != nil {
				return err
			}
		}
		location, err := url.Parse(destination)
		if err != nil {
			return errs.Wrap(err, ErrInvalidMetadata)
		}
		query := location.Query()
		for key, values := range params {
			for _, value := range values {
				query.Set(key, value)
			}
		}
		location.RawQuery = query.Encode()
		http.Redirect(w, r, location.String(), http.StatusFound)
		return nil
	}
	WritePostForm(w, destination, parameter, EncodePost(document), relayState)
	return nil
}

// LogoutRequestURL builds an SP-initiated LogoutRequest redirect URL. | LogoutRequestURL 构建 SP 发起的 LogoutRequest 重定向 URL。
func (sp *ServiceProvider) LogoutRequestURL(nameID, sessionIndex, relayState string) (string, error) {
	destination := sp.config.IDPMetadata.SLOURL(BindingHTTPRedirect)
	if destination == "" {
		destination = sp.config.IDPMetadata.SLOURL("")
	}
	if destination == "" {
		return "", errs.Detail(ErrInvalidMetadata, "IdP has no SLO endpoint | IdP 没有 SLO 端点")
	}
	now := Now(sp.now)
	request := LogoutRequest{
		ID:           auth.NewID("logout"),
		Version:      Version,
		IssueInstant: FormatTime(now),
		Destination:  destination,
		NotOnOrAfter: FormatTime(now.Add(sp.config.AuthnRequestTTL)),
		Issuer:       &Issuer{Value: sp.config.EntityID},
		NameID:       NewNameID(NameIDUnspecified, nameID),
	}
	if sessionIndex != "" {
		request.SessionIndex = []string{sessionIndex}
	}
	document, err := xml.Marshal(&request)
	if err != nil {
		return "", err
	}
	encoded, err := EncodeRedirect(document)
	if err != nil {
		return "", err
	}
	params := url.Values{"SAMLRequest": {encoded}}
	if relayState != "" {
		params.Set("RelayState", relayState)
	}
	if sp.config.RequestSigningKey != nil {
		if err := SignRedirect(params, sp.config.RequestSigningKey, sp.config.RequestSigningAlg, relayState); err != nil {
			return "", err
		}
	}
	if sp.store != nil {
		if err := sp.store.SaveRequest(context.Background(), &RequestState{
			ID:           request.ID,
			SPEntityID:   sp.config.EntityID,
			IDPEntityID:  sp.config.IDPMetadata.EntityID,
			RelayState:   relayState,
			NameIDFormat: NameIDUnspecified,
			CreatedAt:    now,
			ExpiresAt:    now.Add(sp.config.AuthnRequestTTL),
		}); err != nil {
			return "", err
		}
	}
	location, err := url.Parse(destination)
	if err != nil {
		return "", errs.Wrap(err, ErrInvalidMetadata)
	}
	query := location.Query()
	for key, values := range params {
		for _, value := range values {
			query.Set(key, value)
		}
	}
	location.RawQuery = query.Encode()
	return location.String(), nil
}
