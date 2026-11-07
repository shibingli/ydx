package kms

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	kmsauth "github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/router"
)

// The stable authorization actions passed to Authorizer. | 传给 Authorizer 的稳定授权动作。
const (
	// ActionKeyCreate authorizes POST /keys. | ActionKeyCreate 授权 POST /keys。
	ActionKeyCreate = "kms.keys.create"
	// ActionKeyList authorizes GET /keys. | ActionKeyList 授权 GET /keys。
	ActionKeyList = "kms.keys.list"
	// ActionKeyGet authorizes GET /keys/{id}. | ActionKeyGet 授权 GET /keys/{id}。
	ActionKeyGet = "kms.keys.get"
	// ActionKeyUpdate authorizes PATCH /keys/{id}. | ActionKeyUpdate 授权 PATCH /keys/{id}。
	ActionKeyUpdate = "kms.keys.update"
	// ActionKeyDelete authorizes DELETE /keys/{id} and scheduled deletion. | ActionKeyDelete 授权 DELETE /keys/{id} 与计划删除。
	ActionKeyDelete = "kms.keys.delete"
	// ActionKeyActivate authorizes POST /keys/{id}/activate. | ActionKeyActivate 授权 POST /keys/{id}/activate。
	ActionKeyActivate = "kms.keys.activate"
	// ActionKeyDeactivate authorizes POST /keys/{id}/deactivate. | ActionKeyDeactivate 授权 POST /keys/{id}/deactivate。
	ActionKeyDeactivate = "kms.keys.deactivate"
	// ActionKeyCompromise authorizes POST /keys/{id}/compromise. | ActionKeyCompromise 授权 POST /keys/{id}/compromise。
	ActionKeyCompromise = "kms.keys.compromise"
	// ActionKeyDestroy authorizes POST /keys/{id}/destroy. | ActionKeyDestroy 授权 POST /keys/{id}/destroy。
	ActionKeyDestroy = "kms.keys.destroy"
	// ActionKeyRotate authorizes POST /keys/{id}/rotate. | ActionKeyRotate 授权 POST /keys/{id}/rotate。
	ActionKeyRotate = "kms.keys.rotate"
	// ActionKeyVersions authorizes GET /keys/{id}/versions. | ActionKeyVersions 授权 GET /keys/{id}/versions。
	ActionKeyVersions = "kms.keys.versions"
	// ActionKeyExport authorizes POST /keys/{id}/export. | ActionKeyExport 授权 POST /keys/{id}/export。
	ActionKeyExport = "kms.keys.export"
	// ActionEncrypt authorizes POST /encrypt. | ActionEncrypt 授权 POST /encrypt。
	ActionEncrypt = "kms.crypto.encrypt"
	// ActionDecrypt authorizes POST /decrypt. | ActionDecrypt 授权 POST /decrypt。
	ActionDecrypt = "kms.crypto.decrypt"
	// ActionSign authorizes POST /sign. | ActionSign 授权 POST /sign。
	ActionSign = "kms.crypto.sign"
	// ActionVerify authorizes POST /verify. | ActionVerify 授权 POST /verify。
	ActionVerify = "kms.crypto.verify"
	// ActionGenerateDataKey authorizes POST /generate-data-key. | ActionGenerateDataKey 授权 POST /generate-data-key。
	ActionGenerateDataKey = "kms.crypto.generate_data_key"
	// ActionRandom authorizes POST /random. | ActionRandom 授权 POST /random。
	ActionRandom = "kms.crypto.random"
	// ActionAudit authorizes GET /audit. | ActionAudit 授权 GET /audit。
	ActionAudit = "kms.audit.list"
)

// Authorizer decides whether a request may perform action on keyID. | Authorizer 决定请求是否可对
// keyID 执行 action。
//
// Returning nil allows the request. Returning any error denies it: ErrUnauthorized maps to 401,
// ErrForbidden and ErrExportDenied map to 403, and other errors are treated as ErrForbidden. keyID
// is empty for operations that have no single target key. | 返回 nil 允许请求。返回任何错误都会拒绝：
// ErrUnauthorized 映射为 401，ErrForbidden 与 ErrExportDenied 映射为 403，其它错误按 ErrForbidden
// 处理。没有单一目标密钥的操作 keyID 为空。
type Authorizer func(ctx context.Context, r *http.Request, action, keyID string) error

// ServerConfig configures the HTTP surface. | ServerConfig 配置 HTTP 接口。
type ServerConfig struct {
	// Authorizer applies request authorization; nil allows every request. | Authorizer 执行请求授权；nil 允许所有请求。
	Authorizer Authorizer
	// MaxBodyBytes limits request bodies; <=0 means 1 MiB. | MaxBodyBytes 限制请求体；<=0 表示 1 MiB。
	MaxBodyBytes int64
}

// Server exposes a Service over the YD router and net/http. | Server 通过 YD 路由与 net/http 暴露 Service。
type Server struct {
	// service is the backing KMS. | service 是底层 KMS。
	service *Service
	// authorizer applies request authorization. | authorizer 执行请求授权。
	authorizer Authorizer
	// maxBodyBytes limits request bodies. | maxBodyBytes 限制请求体。
	maxBodyBytes int64
}

// NewServer builds an HTTP server for service. | NewServer 为 service 构建 HTTP 服务。
//
// It returns ErrInvalidConfig when service is nil. | service 为空时返回 ErrInvalidConfig。
func NewServer(service *Service, config ServerConfig) (*Server, error) {
	if service == nil {
		return nil, errs.Detail(ErrInvalidConfig, "kms service is required | 必须提供 kms 服务")
	}
	maxBody := config.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = defaultMaxBodyBytes
	}
	return &Server{service: service, authorizer: config.Authorizer, maxBodyBytes: maxBody}, nil
}

// Service returns the backing service. | Service 返回底层服务。
func (s *Server) Service() *Service {
	if s == nil {
		return nil
	}
	return s.service
}

// Register mounts the KMS routes on r under prefix. | Register 在 prefix 下把 KMS 路由挂载到 r。
//
// prefix may be empty or start with "/"; trailing slashes are removed. Path parameters use the YD
// router's ":id" syntax. A nil router is ignored. | prefix 可为空或以 "/" 开头；末尾斜杠会被移除。
// 路径参数使用 YD 路由的 ":id" 语法。nil 路由器会被忽略。
func (s *Server) Register(r *router.Router, prefix string) {
	if s == nil || s.service == nil || r == nil {
		return
	}
	mount := normalizePrefix(prefix)
	r.Handle(http.MethodPost, mount+"/keys", s.routerHandler(s.handleCreateKey))
	r.Handle(http.MethodGet, mount+"/keys", s.routerHandler(s.handleListKeys))
	r.Handle(http.MethodGet, mount+"/keys/:id", s.routerIDHandler(s.handleGetKey))
	r.Handle(http.MethodPatch, mount+"/keys/:id", s.routerIDHandler(s.handleUpdateKey))
	r.Handle(http.MethodDelete, mount+"/keys/:id", s.routerIDHandler(s.handleScheduleDelete))
	r.Handle(http.MethodPost, mount+"/keys/:id/activate", s.lifecycleRouter(ActionKeyActivate, (*Service).Activate))
	r.Handle(http.MethodPost, mount+"/keys/:id/deactivate", s.lifecycleRouter(ActionKeyDeactivate, (*Service).Deactivate))
	r.Handle(http.MethodPost, mount+"/keys/:id/compromise", s.lifecycleRouter(ActionKeyCompromise, (*Service).Compromise))
	r.Handle(http.MethodPost, mount+"/keys/:id/destroy", s.lifecycleRouter(ActionKeyDestroy, (*Service).Destroy))
	r.Handle(http.MethodPost, mount+"/keys/:id/rotate", s.lifecycleRouter(ActionKeyRotate, (*Service).Rotate))
	r.Handle(http.MethodGet, mount+"/keys/:id/versions", s.routerIDHandler(s.handleListVersions))
	r.Handle(http.MethodPost, mount+"/keys/:id/export", s.routerIDHandler(s.handleExportKey))
	r.Handle(http.MethodPost, mount+"/encrypt", s.routerHandler(s.handleEncrypt))
	r.Handle(http.MethodPost, mount+"/decrypt", s.routerHandler(s.handleDecrypt))
	r.Handle(http.MethodPost, mount+"/sign", s.routerHandler(s.handleSign))
	r.Handle(http.MethodPost, mount+"/verify", s.routerHandler(s.handleVerify))
	r.Handle(http.MethodPost, mount+"/generate-data-key", s.routerHandler(s.handleGenerateDataKey))
	r.Handle(http.MethodPost, mount+"/random", s.routerHandler(s.handleRandom))
	r.Handle(http.MethodGet, mount+"/audit", s.routerHandler(s.handleListAudit))
}

// HTTPHandler returns the same API as a net/http handler. | HTTPHandler 以 net/http 处理器返回相同 API。
//
// Path parameters use net/http's "{id}" syntax and r.PathValue. | 路径参数使用 net/http 的 "{id}"
// 语法与 r.PathValue。
func (s *Server) HTTPHandler(prefix string) http.Handler {
	if s == nil || s.service == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusServiceUnavailable, errorBody{Error: errorPayload{Code: "unavailable", Message: "kms server is unavailable | kms 服务不可用"}})
		})
	}
	mount := normalizePrefix(prefix)
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+mount+"/keys", s.handleCreateKey)
	mux.HandleFunc("GET "+mount+"/keys", s.handleListKeys)
	mux.HandleFunc("GET "+mount+"/keys/{id}", s.httpIDHandler(s.handleGetKey))
	mux.HandleFunc("PATCH "+mount+"/keys/{id}", s.httpIDHandler(s.handleUpdateKey))
	mux.HandleFunc("DELETE "+mount+"/keys/{id}", s.httpIDHandler(s.handleScheduleDelete))
	mux.HandleFunc("POST "+mount+"/keys/{id}/activate", s.lifecycleHTTP(ActionKeyActivate, (*Service).Activate))
	mux.HandleFunc("POST "+mount+"/keys/{id}/deactivate", s.lifecycleHTTP(ActionKeyDeactivate, (*Service).Deactivate))
	mux.HandleFunc("POST "+mount+"/keys/{id}/compromise", s.lifecycleHTTP(ActionKeyCompromise, (*Service).Compromise))
	mux.HandleFunc("POST "+mount+"/keys/{id}/destroy", s.lifecycleHTTP(ActionKeyDestroy, (*Service).Destroy))
	mux.HandleFunc("POST "+mount+"/keys/{id}/rotate", s.lifecycleHTTP(ActionKeyRotate, (*Service).Rotate))
	mux.HandleFunc("GET "+mount+"/keys/{id}/versions", s.httpIDHandler(s.handleListVersions))
	mux.HandleFunc("POST "+mount+"/keys/{id}/export", s.httpIDHandler(s.handleExportKey))
	mux.HandleFunc("POST "+mount+"/encrypt", s.handleEncrypt)
	mux.HandleFunc("POST "+mount+"/decrypt", s.handleDecrypt)
	mux.HandleFunc("POST "+mount+"/sign", s.handleSign)
	mux.HandleFunc("POST "+mount+"/verify", s.handleVerify)
	mux.HandleFunc("POST "+mount+"/generate-data-key", s.handleGenerateDataKey)
	mux.HandleFunc("POST "+mount+"/random", s.handleRandom)
	mux.HandleFunc("GET "+mount+"/audit", s.handleListAudit)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})
}

// lifecycleRouter adapts a lifecycle method to a YD router handler. | lifecycleRouter 把生命周期方法
// 适配为 YD 路由处理器。
func (s *Server) lifecycleRouter(action string, fn func(*Service, context.Context, string) (*Key, error)) router.HandlerFunc {
	return func(c *router.Ctx) {
		s.serveLifecycle(c.Writer, c.Request, c.ParamUnescaped("id"), action, fn)
	}
}

// lifecycleHTTP adapts a lifecycle method to a net/http handler. | lifecycleHTTP 把生命周期方法适配为 net/http 处理器。
func (s *Server) lifecycleHTTP(action string, fn func(*Service, context.Context, string) (*Key, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.serveLifecycle(w, r, r.PathValue("id"), action, fn)
	}
}

// routerHandler adapts a net/http handler to a YD router handler. | routerHandler 把 net/http 处理器
// 适配为 YD 路由处理器。
func (s *Server) routerHandler(fn http.HandlerFunc) router.HandlerFunc {
	return func(c *router.Ctx) {
		fn(c.Writer, c.Request)
	}
}

// routerIDHandler adapts a net/http handler with a path identifier to the YD router. | routerIDHandler
// 把带路径标识的 net/http 处理器适配到 YD 路由。
func (s *Server) routerIDHandler(fn func(http.ResponseWriter, *http.Request, string)) router.HandlerFunc {
	return func(c *router.Ctx) {
		fn(c.Writer, c.Request, c.ParamUnescaped("id"))
	}
}

// httpIDHandler adapts an identifier handler to net/http ServeMux patterns. | httpIDHandler 把标识
// 处理器适配为 net/http ServeMux 模式。
func (s *Server) httpIDHandler(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fn(w, r, r.PathValue("id"))
	}
}

// serveLifecycle authorizes and runs one lifecycle transition. | serveLifecycle 授权并执行一次生命周期迁移。
func (s *Server) serveLifecycle(w http.ResponseWriter, r *http.Request, id, action string, fn func(*Service, context.Context, string) (*Key, error)) {
	ctx := s.requestContext(r)
	if err := s.authorize(r, action, id); err != nil {
		writeError(w, err)
		return
	}
	key, err := fn(s.service, ctx, id)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, key)
}

// requestContext derives the operation context with the authenticated actor. | requestContext 派生带有
// 已认证触发者的操作上下文。
func (s *Server) requestContext(r *http.Request) context.Context {
	ctx := r.Context()
	if principal, ok := kmsauth.PrincipalFromRequest(r); ok {
		actor := principal.Subject
		if actor == "" {
			actor = principal.ClientID
		}
		if actor != "" {
			ctx = WithActor(ctx, actor)
		}
	}
	return ctx
}

// authorize applies the configured Authorizer. | authorize 应用配置的 Authorizer。
func (s *Server) authorize(r *http.Request, action, keyID string) error {
	if s.authorizer == nil {
		return nil
	}
	err := s.authorizer(r.Context(), r, action, keyID)
	if err == nil {
		return nil
	}
	if errorsIs(err, ErrUnauthorized) || errorsIs(err, ErrForbidden) || errorsIs(err, ErrExportDenied) {
		return err
	}
	return errs.WrapDetail(err, ErrForbidden, "authorizer denied %[1]s | 授权器拒绝 %[1]s", action)
}

// decodeJSON reads a size-bounded JSON request body. | decodeJSON 读取大小受限的 JSON 请求体。
func (s *Server) decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	body := http.MaxBytesReader(w, r.Body, s.maxBodyBytes)
	decoder := json.NewDecoder(body)
	err := decoder.Decode(dst)
	if err == nil {
		return nil
	}
	if err == io.EOF {
		return nil
	}
	return errs.WrapDetail(err, ErrInvalidRequest, "decode request body | 解码请求体")
}

// writeJSON writes a no-store JSON response. | writeJSON 写出 no-store JSON 响应。
func writeJSON(w http.ResponseWriter, status int, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		writeError(w, errs.WrapDetail(err, ErrStoreUnavailable, "encode response | 编码响应"))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// errorPayload is the stable JSON error object. | errorPayload 是稳定的 JSON 错误对象。
type errorPayload struct {
	// Code is a stable classification label. | Code 是稳定的分类标签。
	Code string `json:"code"`
	// Message is a human-readable bilingual description without secrets. | Message 是不含机密的中英双语描述。
	Message string `json:"message"`
}

// errorBody wraps errorPayload. | errorBody 包装 errorPayload。
type errorBody struct {
	// Error is the error object. | Error 是错误对象。
	Error errorPayload `json:"error"`
}

// writeError maps err to an HTTP status without exposing key material. | writeError 把 err 映射为
// HTTP 状态，且不暴露密钥材料。
func writeError(w http.ResponseWriter, err error) {
	status := httpStatusOf(err)
	writeJSON(w, status, errorBody{Error: errorPayload{Code: errorLabel(err), Message: err.Error()}})
}

// httpStatusOf classifies err as an HTTP status. | httpStatusOf 把 err 分类为 HTTP 状态。
func httpStatusOf(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errorsIs(err, ErrInvalidRequest), errorsIs(err, ErrInvalidKeyType), errorsIs(err, ErrInvalidKeySize),
		errorsIs(err, ErrInvalidMaterial), errorsIs(err, ErrInvalidCiphertext), errorsIs(err, ErrAuthentication):
		return http.StatusBadRequest
	case errorsIs(err, ErrUnauthorized):
		return http.StatusUnauthorized
	case errorsIs(err, ErrForbidden), errorsIs(err, ErrExportDenied):
		return http.StatusForbidden
	case errorsIs(err, ErrNotFound), errorsIs(err, ErrAliasNotFound), errorsIs(err, ErrVersionNotFound):
		return http.StatusNotFound
	case errorsIs(err, ErrKeyExists), errorsIs(err, ErrAliasExists), errorsIs(err, ErrVersionExists),
		errorsIs(err, ErrConflict), errorsIs(err, ErrInvalidState), errorsIs(err, ErrKeyNotUsable),
		errorsIs(err, ErrUsageNotAllowed), errorsIs(err, ErrNonceReuse):
		return http.StatusConflict
	case errorsIs(err, ErrNotSupported):
		return http.StatusNotImplemented
	default:
		return http.StatusInternalServerError
	}
}

// normalizePrefix trims and normalizes a mount prefix. | normalizePrefix 清理并规范化挂载前缀。
func normalizePrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || prefix == "/" {
		return ""
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	return strings.TrimRight(prefix, "/")
}

// decodeBase64 decodes standard or raw URL-safe Base64. | decodeBase64 解码标准或原始 URL 安全 Base64。
func decodeBase64(value, field string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	out, err := base64.StdEncoding.DecodeString(value)
	if err == nil {
		return out, nil
	}
	out, rawErr := base64.RawURLEncoding.DecodeString(value)
	if rawErr == nil {
		return out, nil
	}
	return nil, errs.Detail(ErrInvalidRequest, "field %[1]s is not valid base64 | 字段 %[1]s 不是合法 base64", field)
}

// queryInt reads an optional non-negative integer query parameter. | queryInt 读取可选的非负整数查询参数。
func queryInt(r *http.Request, name string) (int, error) {
	value := strings.TrimSpace(r.URL.Query().Get(name))
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return 0, errs.Detail(ErrInvalidRequest, "query %[1]s must be a non-negative integer | 查询参数 %[1]s 必须为非负整数", name)
	}
	return parsed, nil
}

// queryTime reads an optional RFC 3339 query parameter. | queryTime 读取可选的 RFC 3339 查询参数。
func queryTime(r *http.Request, name string) (time.Time, error) {
	value := strings.TrimSpace(r.URL.Query().Get(name))
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, errs.Detail(ErrInvalidRequest, "query %[1]s must be RFC 3339 | 查询参数 %[1]s 必须为 RFC 3339", name)
	}
	return parsed.UTC(), nil
}

// defaultMaxBodyBytes bounds request bodies. | defaultMaxBodyBytes 限制请求体大小。
const defaultMaxBodyBytes = 1 << 20
