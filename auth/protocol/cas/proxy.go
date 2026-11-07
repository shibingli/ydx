package cas

import (
	"net/http"
	"strings"
)

// Proxy serves GET /proxy, exchanging a PGT for a PT. | Proxy 提供 GET /proxy，把 PGT 兑换为 PT。
//
// The pgt parameter names a proxy granting ticket previously handed to a pgtUrl callback and
// targetService is the service the proxy wants to call. The PGT is reusable until it expires; each
// call mints a fresh single-use PT whose proxy chain records the callback URL of this proxy. | pgt
// 参数是此前交给 pgtUrl 回调的代理授予票据，targetService 是代理希望调用的服务。PGT 在过期前可重复
// 使用；每次调用都会签发新的、一次性 PT，其代理链记录本代理的回调 URL。
func (s *Server) Proxy(w http.ResponseWriter, r *http.Request) {
	if !s.methodAllowed(w, r, http.MethodGet) {
		return
	}
	query := r.URL.Query()
	pgtID := strings.TrimSpace(query.Get("pgt"))
	targetService := strings.TrimSpace(query.Get("targetService"))
	if pgtID == "" {
		writeProxyFailure(w, ErrorCodeInvalidRequest, "The pgt parameter is required | 缺少 pgt 参数")
		return
	}
	if targetService == "" {
		writeProxyFailure(w, ErrorCodeInvalidRequest, "The targetService parameter is required | 缺少 targetService 参数")
		return
	}
	if !s.allowsService(r.Context(), targetService) {
		writeProxyFailure(w, ErrorCodeInvalidService, "The target service is not registered | 目标服务未注册")
		return
	}
	pgt, err := s.store.Get(r.Context(), pgtID)
	if err != nil || pgt.Type != TicketPGT {
		writeProxyFailure(w, ErrorCodeInvalidTicket, "The proxy granting ticket is not valid | 代理授予票据无效")
		return
	}
	if !pgt.ActiveWithSkew(s.expiryNow(), 0) {
		writeProxyFailure(w, ErrorCodeInvalidTicket, "The proxy granting ticket is not valid | 代理授予票据无效")
		return
	}
	pt, err := s.issueTicket(r.Context(), TicketPT, pgt.Principal, pgt.UserID, targetService, pgt, s.config.ProxyTicketTimeout, pgt.Renewal, pgt.RememberMe)
	if err != nil {
		s.logWarn("cas: proxy ticket issuance failed | cas：代理票据签发失败", err)
		writeProxyFailure(w, ErrorCodeInternalError, "The proxy ticket could not be issued | 代理票据无法签发")
		return
	}
	if pgt.Service != "" {
		pt.ProxyChain = append(pt.ProxyChain, pgt.Service)
		if err := s.store.Save(r.Context(), pt); err != nil {
			s.deleteQuietly(r.Context(), pt.ID)
			s.logWarn("cas: proxy ticket save failed | cas：代理票据保存失败", err)
			writeProxyFailure(w, ErrorCodeInternalError, "The proxy ticket could not be issued | 代理票据无法签发")
			return
		}
	}
	writeProxySuccess(w, pt.ID)
}
