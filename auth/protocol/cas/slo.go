package cas

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
	"github.com/shibingli/ydx/xml"
)

// DefaultLogoutCallbackTimeout bounds one back-channel logout POST. | DefaultLogoutCallbackTimeout
// 限定单次后端登出 POST。
const DefaultLogoutCallbackTimeout = 10 * time.Second

// maxLogoutResponseBody is the number of response bytes read from a logout callback. | maxLogoutResponseBody
// 是从登出回调读取的响应字节数。
const maxLogoutResponseBody = 4 << 10

// logoutRequestParameter is the CAS form parameter carrying a SAML logout request. | logoutRequestParameter
// 是携带 SAML 登出请求的 CAS 表单参数。
const logoutRequestParameter = "logoutRequest"

// LogoutRequest is a parsed SAML 1.1 LogoutRequest as used by CAS Single Logout. | LogoutRequest 是
// CAS 单点登出使用的已解析 SAML 1.1 LogoutRequest。
//
// A request must carry at least one of NameIdentifier and SessionIndex. When both are present,
// SessionIndex is authoritative because it names one service session; the NameIdentifier is not used
// to widen the revocation scope. | 请求必须至少携带 NameIdentifier 与 SessionIndex 之一。两者都存在时
// SessionIndex 为准，因为它精确命名一个服务会话；不会用 NameIdentifier 扩大撤销范围。
type LogoutRequest struct {
	// NotOnOrAfter is the optional request deadline. It is exposed for callers but is not enforced,
	// so replaying an old request stays idempotent. | NotOnOrAfter 是可选的请求期限。它仅供调用方
	// 使用而不强制校验，使旧请求的重放保持幂等。
	NotOnOrAfter time.Time
	// ID is the request identifier, if present. | ID 是请求标识（如有）。
	ID string
	// Issuer is the optional SAML issuer. | Issuer 是可选的 SAML 签发方。
	Issuer string
	// NameIdentifier is the user identifier. | NameIdentifier 是用户标识。
	NameIdentifier string
	// SessionIndex is the ST/PT identifier of the session to revoke. | SessionIndex 是要撤销会话的
	// ST/PT 标识。
	SessionIndex string
}

// BuildLogoutRequest renders a SAML 1.1 LogoutRequest for nameIdentifier and sessionIndex. At least
// one identifier must be non-empty. The result is the raw XML document a CAS server expects in the
// logoutRequest form parameter. | BuildLogoutRequest 为 nameIdentifier 与 sessionIndex 渲染 SAML 1.1
// LogoutRequest。至少一个标识必须非空。结果是 CAS 服务端在 logoutRequest 表单参数中期望的原始 XML
// 文档。
func BuildLogoutRequest(nameIdentifier, sessionIndex string, now time.Time) ([]byte, error) {
	nameIdentifier = strings.TrimSpace(nameIdentifier)
	sessionIndex = strings.TrimSpace(sessionIndex)
	if nameIdentifier == "" && sessionIndex == "" {
		return nil, errs.Detail(ErrInvalidLogoutRequest, "logout request needs a name identifier or session index | 登出请求需要名称标识或会话索引")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	requestID, err := logoutRequestID()
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.Grow(512)
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<samlp:LogoutRequest xmlns:samlp="`)
	b.WriteString(samlProtocolNamespace)
	b.WriteString(`" xmlns:saml="`)
	b.WriteString(samlAssertionNamespace)
	b.WriteString(`" ID="`)
	writeEscaped(&b, requestID)
	b.WriteString(`" Version="2.0" IssueInstant="`)
	b.WriteString(now.UTC().Format(time.RFC3339))
	b.WriteString(`">`)
	if nameIdentifier != "" {
		b.WriteString("<saml:NameIdentifier>")
		writeEscaped(&b, nameIdentifier)
		b.WriteString("</saml:NameIdentifier>")
	}
	if sessionIndex != "" {
		b.WriteString("<samlp:SessionIndex>")
		writeEscaped(&b, sessionIndex)
		b.WriteString("</samlp:SessionIndex>")
	}
	b.WriteString("</samlp:LogoutRequest>")
	return []byte(b.String()), nil
}

// logoutRequestID returns a fresh XML-safe SAML request identifier. | logoutRequestID 返回新的
// XML 安全的 SAML 请求标识。
func logoutRequestID() (string, error) {
	token, err := auth.RandomToken(16)
	if err != nil {
		return "", errs.Wrap(err, ErrInvalidLogoutRequest)
	}
	return "_" + token, nil
}

// ParseLogoutRequest parses a LogoutRequest from raw XML or from base64-encoded XML. Namespace
// prefixes are ignored and only local element names are matched, so both the SAML 1.1 and SAML 2.0
// spellings (NameIdentifier and NameID) are accepted. | ParseLogoutRequest 从原始 XML 或 base64 编码的
// XML 解析 LogoutRequest。忽略命名空间前缀，只匹配本地元素名，因此同时接受 SAML 1.1 与 SAML 2.0
// 拼写（NameIdentifier 与 NameID）。
func ParseLogoutRequest(value string) (*LogoutRequest, error) {
	document, err := decodeLogoutRequestValue(value)
	if err != nil {
		return nil, err
	}
	decoder := xml.NewDecoderBytes(document)
	found := false
	request := &LogoutRequest{}
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidLogoutRequest, "cannot decode logout request | 无法解码登出请求")
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "LogoutRequest" {
			continue
		}
		found = true
		request.ID = startAttribute(start, "ID")
		request.NotOnOrAfter = parseSAMLTime(startAttribute(start, "NotOnOrAfter"))
		depth := 1
		for depth > 0 {
			token, err := decoder.Token()
			if err != nil {
				return nil, errs.WrapDetail(err, ErrInvalidLogoutRequest, "logout request ended unexpectedly | 登出请求意外结束")
			}
			switch element := token.(type) {
			case xml.StartElement:
				depth++
				switch element.Name.Local {
				case "NameIdentifier", "NameID":
					value, err := decodeSAMLText(decoder, element)
					if err != nil {
						return nil, err
					}
					if request.NameIdentifier == "" {
						request.NameIdentifier = value
					}
					depth--
				case "SessionIndex":
					value, err := decodeSAMLText(decoder, element)
					if err != nil {
						return nil, err
					}
					if request.SessionIndex == "" {
						request.SessionIndex = value
					}
					depth--
				case "Issuer":
					value, err := decodeSAMLText(decoder, element)
					if err != nil {
						return nil, err
					}
					if request.Issuer == "" {
						request.Issuer = value
					}
					depth--
				}
			case xml.EndElement:
				depth--
			}
		}
		break
	}
	if !found {
		return nil, errs.Detail(ErrInvalidLogoutRequest, "LogoutRequest element is missing | 缺少 LogoutRequest 元素")
	}
	if request.NameIdentifier == "" && request.SessionIndex == "" {
		return nil, errs.Detail(ErrInvalidLogoutRequest, "logout request has neither NameIdentifier nor SessionIndex | 登出请求既无 NameIdentifier 也无 SessionIndex")
	}
	return request, nil
}

// decodeLogoutRequestValue returns the XML bytes of a logout request value. Raw XML is returned
// unchanged; anything else is tried as standard or URL-safe base64 with or without padding. Spaces
// are treated as '+' so form and query decoding cannot corrupt base64. | decodeLogoutRequestValue 返回
// 登出请求值的 XML 字节。原始 XML 原样返回；其它值按标准或 URL 安全的 base64（带或不带填充）尝试。
// 空格按 '+' 处理，避免表单与查询解码破坏 base64。
func decodeLogoutRequestValue(value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, errs.Detail(ErrInvalidLogoutRequest, "logoutRequest is empty | logoutRequest 为空")
	}
	if len(trimmed) > maxProtocolBody {
		return nil, errs.Detail(ErrInvalidLogoutRequest, "logoutRequest is too large | logoutRequest 过大")
	}
	if strings.HasPrefix(trimmed, "<") {
		return []byte(trimmed), nil
	}
	// A form or query decoder turns '+' into ' ', so spaces are restored before decoding. The
	// untrimmed form is tried first because a leading or trailing '+' becomes a leading or trailing
	// space that TrimSpace would otherwise delete. | 表单或查询解码器会把 '+' 变成空格，因此在解码前
	// 还原空格。先尝试未裁剪的形式，因为位于首尾的 '+' 会变成首尾空格，而被 TrimSpace 删除。
	candidates := []string{strings.ReplaceAll(value, " ", "+")}
	if trimmed != value {
		trimmedCandidate := strings.ReplaceAll(trimmed, " ", "+")
		if trimmedCandidate != candidates[0] {
			candidates = append(candidates, trimmedCandidate)
		}
	}
	encodings := [...]*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, encoded := range candidates {
		for _, encoding := range encodings {
			document, err := encoding.DecodeString(encoded)
			if err != nil || len(document) == 0 {
				continue
			}
			if len(document) > maxProtocolBody {
				return nil, errs.Detail(ErrInvalidLogoutRequest, "logoutRequest is too large | logoutRequest 过大")
			}
			return document, nil
		}
	}
	return nil, errs.Detail(ErrInvalidLogoutRequest, "logoutRequest is neither XML nor base64 XML | logoutRequest 既不是 XML 也不是 base64 XML")
}

// decodeSAMLText decodes one text element and returns its trimmed value. | decodeSAMLText 解码一个
// 文本元素并返回去空白后的值。
func decodeSAMLText(decoder *xml.Decoder, start xml.StartElement) (string, error) {
	var value string
	if err := decoder.DecodeElement(&value, &start); err != nil {
		return "", errs.WrapDetail(err, ErrInvalidLogoutRequest, "cannot decode %[1]s | 无法解码 %[1]s", start.Name.Local)
	}
	return strings.TrimSpace(value), nil
}

// startAttribute returns the value of the named attribute, ignoring its namespace prefix. |
// startAttribute 返回指定名称属性的值，忽略命名空间前缀。
func startAttribute(start xml.StartElement, name string) string {
	for _, attribute := range start.Attr {
		if attribute.Name.Local == name {
			return strings.TrimSpace(attribute.Value)
		}
	}
	return ""
}

// parseSAMLTime parses a SAML date-time attribute, returning the zero time on failure. | parseSAMLTime
// 解析 SAML 日期时间属性，失败时返回零值时间。
func parseSAMLTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}

// logoutRequestValue returns the logout request carried by r. A logoutRequest form field or query
// parameter is recognized on both GET and POST. The boolean reports presence, so an empty value can be
// rejected as malformed instead of being mistaken for an ordinary logout. | logoutRequestValue 返回 r
// 携带的登出请求。GET 与 POST 都会识别 logoutRequest 表单字段或查询参数。布尔值报告是否存在，使空值
// 能被当作格式错误拒绝，而不会被误认为普通登出。
func logoutRequestValue(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	if r.Method == http.MethodPost {
		if values, ok := r.PostForm[logoutRequestParameter]; ok {
			if len(values) == 0 {
				return "", true
			}
			return values[0], true
		}
	}
	if r.URL != nil {
		if values, ok := r.URL.Query()[logoutRequestParameter]; ok {
			if len(values) == 0 {
				return "", true
			}
			return values[0], true
		}
	}
	return "", false
}

// LogoutDeliveryResult records one back-channel logout delivery. | LogoutDeliveryResult 记录一次后端
// 登出投递。
type LogoutDeliveryResult struct {
	// Err is non-nil when delivery failed. | Err 在投递失败时非空。
	Err error
	// Service is the target service URL. | Service 是目标服务 URL。
	Service string
	// SessionIndex is the session the request refers to. Treat it as a secret ticket identifier and
	// do not log it. | SessionIndex 是请求引用的会话。请把它视为秘密票据标识，不要记录到日志。
	SessionIndex string
	// StatusCode is the HTTP status of the answer, or 0 when no answer was received. | StatusCode
	// 是应答的 HTTP 状态，未收到应答时为 0。
	StatusCode int
	// Duration is the time spent delivering. | Duration 是投递耗时。
	Duration time.Duration
}

// LogoutObserver receives every back-channel logout result. It is called after all deliveries of one
// logout finish, from the logout request goroutine. Implementations must be fast and safe for
// concurrent use. | LogoutObserver 接收每个后端登出结果。它在一次登出的全部投递完成后由登出请求
// goroutine 调用。实现必须快速且并发安全。
type LogoutObserver func(ctx context.Context, result LogoutDeliveryResult)

// DeliverLogoutRequests sends one SAML logout request per session to its service in parallel. The
// session named by skipSessionIndex is not notified, which prevents a service that initiated a
// back-channel logout from receiving its own request. A delivery failure is recorded in the result
// and never fails the logout. ctx cancels deliveries, and each delivery is additionally bounded by
// LogoutCallbackTimeout. | DeliverLogoutRequests 并行地向每个会话的服务发送一个 SAML 登出请求。
// skipSessionIndex 命名的会话不会被通知，避免发起后端登出的服务收到自己的请求。投递失败记录在结果中，
// 绝不会使登出失败。ctx 可取消投递，每次投递还受 LogoutCallbackTimeout 限制。
func (s *Server) DeliverLogoutRequests(ctx context.Context, sessions []*ServiceSession, skipSessionIndex string) []LogoutDeliveryResult {
	if s == nil || len(sessions) == 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	targets := make([]*ServiceSession, 0, len(sessions))
	for _, session := range sessions {
		if session == nil || session.Service == "" {
			continue
		}
		if skipSessionIndex != "" && session.SessionIndex == skipSessionIndex {
			continue
		}
		targets = append(targets, session.Clone())
	}
	if len(targets) == 0 {
		return nil
	}
	results := make([]LogoutDeliveryResult, len(targets))
	var wg sync.WaitGroup
	for index := range targets {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			results[index] = s.deliverLogoutRequest(ctx, targets[index])
		}(index)
	}
	wg.Wait()
	for _, result := range results {
		if result.Err != nil && s.config.Logger != nil {
			s.config.Logger.Warn("cas: back-channel logout failed | cas：后端登出失败",
				log.Str("service", result.Service), log.Err(result.Err))
		}
		if s.config.LogoutObserver != nil {
			s.config.LogoutObserver(ctx, result)
		}
	}
	return results
}

// deliverLogoutRequest performs one back-channel POST. | deliverLogoutRequest 执行一次后端 POST。
func (s *Server) deliverLogoutRequest(ctx context.Context, session *ServiceSession) (result LogoutDeliveryResult) {
	result.Service = session.Service
	result.SessionIndex = session.SessionIndex
	started := time.Now()
	defer func() {
		result.Duration = time.Since(started)
	}()
	if !validServiceURL(session.Service) {
		result.Err = errs.Detail(ErrLogoutDelivery, "service %[1]q is not an absolute http(s) URL | 服务 %[1]q 不是绝对 http(s) URL", session.Service)
		return result
	}
	document, err := BuildLogoutRequest(session.User, session.SessionIndex, s.nowTime())
	if err != nil {
		result.Err = err
		return result
	}
	form := url.Values{}
	form.Set(logoutRequestParameter, string(document))
	timeout := s.config.LogoutCallbackTimeout
	if timeout <= 0 {
		timeout = DefaultLogoutCallbackTimeout
	}
	deliveryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(deliveryCtx, http.MethodPost, session.Service, strings.NewReader(form.Encode()))
	if err != nil {
		result.Err = errs.WrapDetail(err, ErrLogoutDelivery, "cannot build logout request for %[1]q | 无法为 %[1]q 构建登出请求", session.Service)
		return result
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "text/plain, text/xml, application/xml")
	response, err := s.httpClient.Do(request)
	if err != nil {
		result.Err = errs.WrapDetail(err, ErrLogoutDelivery, "logout request to %[1]q failed | 向 %[1]q 发送登出请求失败", session.Service)
		return result
	}
	defer func() {
		_ = response.Body.Close()
	}()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxLogoutResponseBody))
	result.StatusCode = response.StatusCode
	if response.StatusCode < 200 || response.StatusCode > 299 {
		result.Err = errs.Detail(ErrLogoutDelivery, "%[1]q answered with status %[2]d | %[1]q 返回状态 %[2]d", session.Service, response.StatusCode)
	}
	return result
}

// handleLogoutRequest processes a SAML logout request carried by the logoutRequest parameter. A
// syntactically valid and accepted request answers 200, even when its session was already revoked,
// so retries and replays are harmless. Malformed, oversized, unsigned-when-required and
// badly-signed requests are rejected before any state changes. | handleLogoutRequest 处理
// logoutRequest 参数携带的 SAML 登出请求。语法合法且被接受的请求返回 200，即使其会话已被撤销，因此
// 重试与重放无害。格式错误、超大、在要求签名时未签名以及签名错误的请求会在任何状态变更之前被拒绝。
func (s *Server) handleLogoutRequest(w http.ResponseWriter, r *http.Request, value string) {
	if len(value) > maxProtocolBody {
		s.fail(w, r, http.StatusRequestEntityTooLarge, errs.Detail(ErrInvalidLogoutRequest, "logoutRequest is too large | logoutRequest 过大"))
		return
	}
	// Decode once and parse the XML bytes directly so signature verification and parsing observe the
	// same document; re-decoding could otherwise disagree with the exact signed octets. | 只解码一次并
	// 直接解析 XML 字节，使签名校验与解析看到同一文档；重复解码可能与实际签名字节不一致。
	document, err := decodeLogoutRequestValue(value)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, err)
		return
	}
	request, err := ParseLogoutRequest(string(document))
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, err)
		return
	}
	if err := s.verifyLogoutRequestSignature(r.Context(), document, request); err != nil {
		s.fail(w, r, http.StatusBadRequest, err)
		return
	}
	sessions := s.revokeForLogoutRequest(r.Context(), request)
	_ = s.DeliverLogoutRequests(r.Context(), sessions, request.SessionIndex)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
}

// revokeForLogoutRequest performs the local revocation of a parsed logout request and returns the
// removed service sessions that still need a back-channel notification. A request with a
// SessionIndex only revokes that session's TGT family; an unknown index is a no-op, which keeps
// replays idempotent. Only a request without SessionIndex falls back to the NameIdentifier and
// revokes every session of that user. | revokeForLogoutRequest 执行已解析登出请求的本地撤销，并返回
// 仍需后端通知的已删除服务会话。带 SessionIndex 的请求只撤销该会话的 TGT 族；未知索引不执行操作，
// 使重放保持幂等。只有不带 SessionIndex 的请求才回退到 NameIdentifier 并撤销该用户的全部会话。
func (s *Server) revokeForLogoutRequest(ctx context.Context, request *LogoutRequest) []*ServiceSession {
	if request == nil {
		return nil
	}
	if index := strings.TrimSpace(request.SessionIndex); index != "" {
		root := s.rootTGTForSession(ctx, index)
		if root == "" {
			return nil
		}
		return s.destroyTGT(ctx, root)
	}
	user := strings.TrimSpace(request.NameIdentifier)
	if user == "" {
		return nil
	}
	var sessions []*ServiceSession
	if s.sessions != nil {
		removed, err := s.sessions.DeleteByUser(ctx, user)
		if err != nil {
			s.logWarn("cas: service session cleanup failed | cas：服务会话清理失败", err)
		} else {
			sessions = removed
		}
	}
	// Destroy each session family explicitly: the protocol user name may differ from the backend
	// user ID used by the ticket store. | 显式销毁每个会话族：协议用户名可能与票据存储使用的后端账号
	// 标识不同。
	seen := make(map[string]struct{}, len(sessions))
	for _, session := range sessions {
		if session.TGTID == "" {
			continue
		}
		if _, ok := seen[session.TGTID]; ok {
			continue
		}
		seen[session.TGTID] = struct{}{}
		s.destroyTGT(ctx, session.TGTID)
	}
	if _, err := s.store.DeleteByUser(ctx, user); err != nil {
		s.logWarn("cas: user ticket cleanup failed | cas：用户票据清理失败", err)
	}
	return sessions
}

// rootTGTForSession returns the TGT at the root of the session index. The ticket store is consulted
// first because consumed ST/PT records remain readable until expiry or janitor cleanup; the session
// registry is the fallback after cleanup. | rootTGTForSession 返回会话索引根部的 TGT。优先查询票据
// 存储，因为已消费的 ST/PT 记录在过期或清理前仍可读取；清理之后回退到会话注册表。
func (s *Server) rootTGTForSession(ctx context.Context, sessionIndex string) string {
	if sessionIndex == "" {
		return ""
	}
	if ticket, err := s.store.Get(ctx, sessionIndex); err == nil && ticket != nil {
		if ticket.RootTGTID != "" {
			return ticket.RootTGTID
		}
		return ticket.ID
	}
	if s.sessions != nil {
		if session, err := s.sessions.Get(ctx, sessionIndex); err == nil && session != nil {
			return session.TGTID
		}
	}
	return ""
}
