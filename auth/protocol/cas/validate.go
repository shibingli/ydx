package cas

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
)

// pgtCallbackTimeout bounds a single pgtUrl callback. | pgtCallbackTimeout 限定单次 pgtUrl 回调。
const pgtCallbackTimeout = 10 * time.Second

// validationOptions selects the dialect and accepted ticket types of a validation endpoint. |
// validationOptions 选择校验端点的方言与可接受票据类型。
type validationOptions struct {
	// proxy accepts PT in addition to ST. | proxy 除 ST 外还接受 PT。
	proxy bool
	// cas3 renders attributes in the CAS 3.0 name/value form. | cas3 以 CAS 3.0 名称/值形式渲染属性。
	cas3 bool
	// cas1 answers with the CAS 1.0 plain-text protocol. | cas1 以 CAS 1.0 纯文本协议回答。
	cas1 bool
	// format is the per-request response dialect. | format 是每请求的响应方言。
	format validationFormat
}

// ServiceValidate serves GET /serviceValidate (CAS 2.0). | ServiceValidate 提供 GET /serviceValidate（CAS 2.0）。
func (s *Server) ServiceValidate(w http.ResponseWriter, r *http.Request) {
	s.handleValidation(w, r, validationOptions{})
}

// P3ServiceValidate serves GET /p3/serviceValidate (CAS 3.0). | P3ServiceValidate 提供 GET
// /p3/serviceValidate（CAS 3.0）。
func (s *Server) P3ServiceValidate(w http.ResponseWriter, r *http.Request) {
	s.handleValidation(w, r, validationOptions{cas3: true})
}

// ProxyValidate serves GET /proxyValidate (CAS 2.0), which accepts ST and PT. | ProxyValidate 提供
// GET /proxyValidate（CAS 2.0），接受 ST 与 PT。
func (s *Server) ProxyValidate(w http.ResponseWriter, r *http.Request) {
	s.handleValidation(w, r, validationOptions{proxy: true})
}

// P3ProxyValidate serves GET /p3/proxyValidate (CAS 3.0). | P3ProxyValidate 提供 GET
// /p3/proxyValidate（CAS 3.0）。
func (s *Server) P3ProxyValidate(w http.ResponseWriter, r *http.Request) {
	s.handleValidation(w, r, validationOptions{proxy: true, cas3: true})
}

// Validate serves GET /validate, the CAS 1.0 yes/no plain-text protocol. | Validate 提供 GET /validate，
// 即 CAS 1.0 的 yes/no 纯文本协议。
func (s *Server) Validate(w http.ResponseWriter, r *http.Request) {
	s.handleValidation(w, r, validationOptions{cas1: true})
}

// handleValidation implements every validation endpoint. | handleValidation 实现全部校验端点。
func (s *Server) handleValidation(w http.ResponseWriter, r *http.Request, opts validationOptions) {
	if !s.methodAllowed(w, r, http.MethodGet) {
		return
	}
	opts.format = validationResponseFormat(r, opts.cas1)
	query := r.URL.Query()
	ticketID := strings.TrimSpace(query.Get("ticket"))
	service := strings.TrimSpace(query.Get("service"))
	renew := parseBoolParam(query.Get("renew"))
	pgtURL := strings.TrimSpace(query.Get("pgtUrl"))

	if ticketID == "" {
		s.failValidation(w, opts, ErrorCodeInvalidRequest, "The ticket parameter is required | 缺少 ticket 参数")
		return
	}
	if service == "" {
		s.failValidation(w, opts, ErrorCodeInvalidRequest, "The service parameter is required | 缺少 service 参数")
		return
	}
	if !s.allowsService(r.Context(), service) {
		s.failValidation(w, opts, ErrorCodeInvalidService, "The service is not registered | 服务未注册")
		return
	}
	ticket, err := s.store.Get(r.Context(), ticketID)
	if err != nil {
		s.failValidation(w, opts, validationCode(err), validationMessage(err))
		return
	}
	if !opts.accepts(ticket.Type) {
		s.failValidation(w, opts, ErrorCodeInvalidTicket, "The ticket type is not accepted here | 此端点不接受该票据类型")
		return
	}
	if !ticket.ActiveWithSkew(s.expiryNow(), 0) {
		// A consumed ticket is reported exactly like an expired one so replay attempts reveal
		// nothing about prior use. | 已消费票据与过期票据报告一致，使重放尝试无法推断先前的使用。
		s.failValidation(w, opts, ErrorCodeInvalidTicket, "The ticket is not valid | 票据无效")
		return
	}
	if renew && !ticket.Renewal {
		// CAS 1.0 also defines renew: a ticket from a reused session must not satisfy it. | CAS 1.0
		// 同样定义了 renew：来自复用会话的票据不能满足该要求。
		s.failValidation(w, opts, ErrorCodeInvalidTicket, "The ticket was not issued by a fresh authentication | 票据并非来自重新认证")
		return
	}
	if !s.servicesMatch(ticket.Service, service) {
		s.failValidation(w, opts, ErrorCodeInvalidService, "The service does not match the ticket | 服务与票据不匹配")
		return
	}
	consumed, err := s.store.Consume(r.Context(), ticket.ID, ticket.Type, s.expiryNow())
	if err != nil {
		s.failValidation(w, opts, validationCode(err), validationMessage(err))
		return
	}
	principal, err := s.principalFor(r.Context(), consumed)
	if err != nil {
		s.logWarn("cas: principal refresh failed | cas：主体刷新失败", err)
		s.failValidation(w, opts, ErrorCodeInternalError, "The authentication principal is unavailable | 认证主体不可用")
		return
	}
	result := &validationResult{
		User:       userIdentifier(principal),
		Attributes: attributeValues(principal.Attributes),
		Proxies:    append([]string(nil), consumed.ProxyChain...),
	}
	if pgtURL != "" && !opts.cas1 {
		pgt, _, err := s.issueProxyGrantingTicket(r.Context(), consumed, pgtURL)
		if err != nil {
			s.failValidation(w, opts, validationCode(err), validationMessage(err))
			return
		}
		result.ProxyGrantingTicket = pgt.ID
	}
	if opts.format == validationFormatJSON {
		writeValidationSuccessJSON(w, result)
		return
	}
	if opts.cas1 {
		writeCAS10Validation(w, true, result.User)
		return
	}
	writeValidationSuccess(w, result, opts.cas3)
}

// accepts reports whether t may be validated by the endpoint. | accepts 报告端点是否可校验 t。
func (o validationOptions) accepts(t TicketType) bool {
	if o.cas1 || !o.proxy {
		return t == TicketST
	}
	return t == TicketST || t == TicketPT
}

// failValidation writes a protocol failure in the dialect of opts. A CAS 1.0 failure is always the
// same "no" answer, regardless of cause. | failValidation 以 opts 的方言写出协议失败。CAS 1.0 失败
// 无论原因如何都是相同的 "no" 回答。
func (s *Server) failValidation(w http.ResponseWriter, opts validationOptions, code, message string) {
	if opts.format == validationFormatJSON {
		writeValidationFailureJSON(w, code, message)
		return
	}
	if opts.cas1 {
		writeCAS10Validation(w, false, "")
		return
	}
	writeValidationFailure(w, code, message)
}

// validationCode maps a store or protocol error to a CAS error code. | validationCode 把存储或协议
// 错误映射为 CAS 错误码。
func validationCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrTicketNotFound), errors.Is(err, ErrTicketUsed),
		errors.Is(err, ErrTicketExpired), errors.Is(err, ErrTicketTypeMismatch):
		return ErrorCodeInvalidTicket
	case errors.Is(err, ErrInvalidService), errors.Is(err, ErrServiceNotRegistered):
		return ErrorCodeInvalidService
	case errors.Is(err, ErrInvalidProxyCallback), errors.Is(err, ErrInsecureProxyCallback):
		return ErrorCodeInvalidProxyCallback
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrInvalidConfig):
		return ErrorCodeInvalidRequest
	default:
		return ErrorCodeInternalError
	}
}

// validationMessage returns the protocol message of a store or protocol error. The wording is
// intentionally coarse so ticket state is not disclosed. | validationMessage 返回存储或协议错误的协议
// 消息。措辞刻意笼统，避免泄露票据状态。
func validationMessage(err error) string {
	switch validationCode(err) {
	case ErrorCodeInvalidTicket:
		return "The ticket is not valid | 票据无效"
	case ErrorCodeInvalidService:
		return "The service is not valid | 服务无效"
	case ErrorCodeInvalidProxyCallback:
		return "The proxy callback could not be verified | 代理回调无法校验"
	case ErrorCodeInvalidRequest:
		return "The validation request is invalid | 校验请求非法"
	default:
		return "The ticket could not be validated | 票据无法校验"
	}
}

// issueProxyGrantingTicket validates pgtURL, issues a PGT, and performs the pgtUrl callback that
// hands the PGT identifier and a one-time IOU to the proxy. A callback failure removes the PGT. |
// issueProxyGrantingTicket 校验 pgtURL、签发 PGT，并执行把 PGT 标识与一次性 IOU 交给代理的 pgtUrl
// 回调。回调失败会删除该 PGT。
func (s *Server) issueProxyGrantingTicket(ctx context.Context, parent *Ticket, pgtURL string) (*Ticket, string, error) {
	parsed, err := url.Parse(pgtURL)
	if err != nil {
		return nil, "", errs.WrapDetail(err, ErrInvalidProxyCallback, "pgtUrl %[1]q cannot be parsed | pgtUrl %[1]q 无法解析", pgtURL)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if parsed.Host == "" || (scheme != "https" && scheme != "http") {
		return nil, "", errs.Detail(ErrInvalidProxyCallback, "pgtUrl %[1]q is not an absolute http(s) URL | pgtUrl %[1]q 不是绝对 http(s) URL", pgtURL)
	}
	if scheme != "https" && !s.config.AllowInsecurePGTCallback {
		return nil, "", errs.Detail(ErrInsecureProxyCallback, "pgtUrl %[1]q must use https | pgtUrl %[1]q 必须使用 https", pgtURL)
	}
	if s.config.ServiceRegistry != nil && !s.config.ServiceRegistry.Allows(ctx, pgtURL) {
		return nil, "", errs.Detail(ErrInvalidProxyCallback, "pgtUrl is not registered | pgtUrl 未注册")
	}
	pgt, err := s.issueTicket(ctx, TicketPGT, parent.Principal, parent.UserID, pgtURL, parent, s.config.ProxyGrantingTicketTimeout, parent.Renewal, parent.RememberMe)
	if err != nil {
		return nil, "", err
	}
	iou, err := newProxyGrantingTicketIOU()
	if err != nil {
		s.deleteQuietly(ctx, pgt.ID)
		return nil, "", err
	}
	if err := s.callbackProxyGrantingTicket(ctx, pgtURL, pgt.ID, iou); err != nil {
		s.deleteQuietly(ctx, pgt.ID)
		return nil, "", err
	}
	return pgt, iou, nil
}

// newProxyGrantingTicketIOU returns a fresh PGTIOU identifier. | newProxyGrantingTicketIOU 返回新的 PGTIOU 标识。
func newProxyGrantingTicketIOU() (string, error) {
	token, err := auth.RandomToken(24)
	if err != nil {
		return "", errs.Wrap(err, ErrTicketGeneration)
	}
	return TicketPrefixPGTIOU + token, nil
}

// callbackProxyGrantingTicket calls pgtUrl with pgtId and pgtIou. Any non-2xx answer fails. | callbackProxyGrantingTicket
// 携带 pgtId 与 pgtIou 调用 pgtUrl。任何非 2xx 应答都视为失败。
func (s *Server) callbackProxyGrantingTicket(ctx context.Context, pgtURL, pgtID, iou string) error {
	parsed, err := url.Parse(pgtURL)
	if err != nil {
		return errs.WrapDetail(err, ErrInvalidProxyCallback, "cannot parse pgtUrl | 无法解析 pgtUrl")
	}
	query := parsed.Query()
	query.Set("pgtId", pgtID)
	query.Set("pgtIou", iou)
	parsed.RawQuery = query.Encode()
	callbackCtx, cancel := context.WithTimeout(ctx, pgtCallbackTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(callbackCtx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return errs.Wrap(err, ErrInvalidProxyCallback)
	}
	response, err := s.httpClient.Do(request)
	if err != nil {
		return errs.Wrap(err, ErrInvalidProxyCallback)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return errs.Detail(ErrInvalidProxyCallback, "pgtUrl answered with status %[1]d | pgtUrl 返回状态 %[1]d", response.StatusCode)
	}
	return nil
}

// deleteQuietly removes id and logs a failure without the identifier. | deleteQuietly 删除 id，并在
// 失败时记录不含标识的告警。
func (s *Server) deleteQuietly(ctx context.Context, id string) {
	if err := s.store.Delete(ctx, id); err != nil {
		s.logWarn("cas: ticket cleanup failed | cas：票据清理失败", err)
	}
}
