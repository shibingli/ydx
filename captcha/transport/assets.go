package transport

import (
	_ "embed"
	"net/http"
)

// Embedded frontend assets. | 嵌入的前端资源。
var (
	//go:embed assets/yd-captcha.js
	sdkScript []byte
	//go:embed assets/yd-captcha.css
	sdkStyle []byte
)

// SDKScript returns the embedded browser SDK bytes for static hosting. | SDKScript 返回用于静态托管的嵌入浏览器 SDK 字节。
func SDKScript() []byte { return append([]byte(nil), sdkScript...) }

// SDKStyle returns the embedded browser SDK stylesheet bytes. | SDKStyle 返回嵌入的浏览器 SDK 样式表字节。
func SDKStyle() []byte { return append([]byte(nil), sdkStyle...) }

// assetEntry is one embedded asset. | assetEntry 是一个嵌入资源。
type assetEntry struct {
	mime string
	data []byte
}

// serveAsset writes one whitelisted embedded asset. | serveAsset 写出一个白名单内的嵌入资源。
func (h *Handler) serveAsset(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header()["Allow"] = []string{http.MethodGet, http.MethodHead}
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{OK: false, Error: &apiError{Code: "method_not_allowed", Message: "GET required | 需要 GET"}})
		return
	}
	var entry assetEntry
	switch name {
	case "yd-captcha.js":
		entry = assetEntry{data: sdkScript, mime: "text/javascript; charset=utf-8"}
	case "yd-captcha.css":
		entry = assetEntry{data: sdkStyle, mime: "text/css; charset=utf-8"}
	default:
		http.NotFound(w, r)
		return
	}
	header := w.Header()
	header["Content-Type"] = []string{entry.mime}
	header["Cache-Control"] = []string{"public, max-age=300"}
	header["X-Content-Type-Options"] = []string{"nosniff"}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(entry.data)
}
