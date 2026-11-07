package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/base64"
)

// SessionState returns an OpenID Connect session_state value. | SessionState 返回 OpenID Connect
// session_state 取值。
//
// The value is "<hash>.<salt>"; the OP iframe recomputes the hash from the current browser session
// and the carried salt. | 取值为 "<hash>.<salt>"；OP iframe 用当前浏览器会话与携带的盐重新计算哈希。
func (p *Provider) SessionState(clientID, sessionID string) string {
	salt, err := auth.RandomToken(8)
	if err != nil {
		return ""
	}
	return sessionStateHash(clientID, sessionID, salt) + "." + salt
}

// sessionStateHash computes the session_state hash. | sessionStateHash 计算 session_state 哈希。
func sessionStateHash(clientID, sessionID, salt string) string {
	sum := sha256.Sum256([]byte(clientID + " " + sessionID + " " + salt))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// CheckSession serves the OP iframe and its polling endpoint. | CheckSession 提供 OP iframe 及其轮询端点。
//
// A request carrying session_state returns "unchanged" or "changed" as text/plain. A request
// without it returns the iframe HTML that listens for the RP's postMessage. | 带 session_state 的请求
// 以 text/plain 返回 "unchanged" 或 "changed"；不带时返回监听 RP postMessage 的 iframe HTML。
func (p *Provider) CheckSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed | 方法不允许")
		return
	}
	state := r.URL.Query().Get("session_state")
	if state == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(checkSessionHTML))
		return
	}
	clientID := r.URL.Query().Get("client_id")
	result := "changed"
	if p.config.Sessions != nil && clientID != "" {
		if session, err := p.config.Sessions.ValidateRequest(r.Context(), r); err == nil {
			hash, salt, ok := strings.Cut(state, ".")
			if ok && salt != "" {
				want := sessionStateHash(clientID, session.ID, salt)
				if subtle.ConstantTimeCompare([]byte(hash), []byte(want)) == 1 {
					result = "unchanged"
				}
			}
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(result))
}

// checkSessionHTML is the minimal OP iframe. | checkSessionHTML 是最小 OP iframe。
const checkSessionHTML = `<!doctype html><html><head><meta charset="utf-8"><title>OP session</title></head><body><script>
window.addEventListener("message", function (event) {
  var parts = String(event.data || "").split(" ");
  if (parts.length < 2) { return; }
  var url = location.pathname + "?client_id=" + encodeURIComponent(parts[0]) +
    "&session_state=" + encodeURIComponent(parts[1]);
  fetch(url, { credentials: "include", cache: "no-store" }).then(function (r) { return r.text(); })
    .then(function (text) { event.source.postMessage(text, event.origin); })
    .catch(function () { event.source.postMessage("changed", event.origin); });
});
</script></body></html>`
