package scim

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
	ydxjson "github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/router"
)

// Authorizer decides whether a request may perform action on resource. A nil Authorizer allows
// every request. | Authorizer 决定请求是否可对 resource 执行 action。nil Authorizer 允许所有请求。
type Authorizer func(ctx context.Context, r *http.Request, action, resource string) error

// PasswordSetter provisions a write-only SCIM password. The server never stores the plain value;
// it clears it before persistence and calls this hook with the stored user. | PasswordSetter 预配
// 只写的 SCIM 口令。服务端绝不存储明文；它在持久化前清空口令，并用已存储用户调用该钩子。
type PasswordSetter func(ctx context.Context, user *User, password string) error

// PasswordPrechecker validates a password before the server commits a profile write. A precheck
// failure rejects the request with a client error before any store mutation, so no compensation is
// needed. It is optional; when absent only the post-commit PasswordSetter runs. | PasswordPrechecker
// 在服务端提交资料写入前校验口令。预检失败会在任何存储变更前以客户端错误拒绝请求，因此无需补偿。
// 它可选；缺失时只运行提交后的 PasswordSetter。
type PasswordPrechecker interface {
	// PreparePassword validates password for user. user carries the identifier of an existing
	// resource on replace and patch, and no identifier on create. | PreparePassword 为 user 校验
	// password。替换与补丁时 user 带有既有资源标识，创建时没有标识。
	PreparePassword(ctx context.Context, user *User, password string) error
}

// PasswordValidator adapts an ordinary function to PasswordPrechecker. | PasswordValidator 把普通
// 函数适配为 PasswordPrechecker。
type PasswordValidator func(ctx context.Context, user *User, password string) error

// PreparePassword calls v(ctx, user, password). A nil validator accepts every password. |
// PreparePassword 调用 v(ctx, user, password)。nil 校验器接受所有口令。
func (v PasswordValidator) PreparePassword(ctx context.Context, user *User, password string) error {
	if v == nil {
		return nil
	}
	return v(ctx, user, password)
}

// Authorization actions passed to Authorizer. | 传给 Authorizer 的授权动作。
const (
	// ActionRead covers GET and search requests. | ActionRead 覆盖 GET 与搜索请求。
	ActionRead = "read"
	// ActionCreate covers POST resource creation. | ActionCreate 覆盖 POST 资源创建。
	ActionCreate = "create"
	// ActionUpdate covers PUT and PATCH. | ActionUpdate 覆盖 PUT 与 PATCH。
	ActionUpdate = "update"
	// ActionDelete covers DELETE. | ActionDelete 覆盖 DELETE。
	ActionDelete = "delete"
)

// Discovery route resources passed to Authorizer. | 传给 Authorizer 的发现路由资源。
const (
	ResourceServiceProviderConfig = "ServiceProviderConfig"
	ResourceResourceType          = "ResourceType"
	ResourceSchemaDefinition      = "Schema"
	ResourceBulk                  = "Bulk"
)

// Options configures a Server. | Options 配置 Server。
type Options struct {
	// Store persists Users and Groups. A nil Store uses a new MemoryStore. | Store 持久化 User 与
	// Group。nil 时使用新的 MemoryStore。
	Store Store
	// Authorizer authorizes each request. nil allows every request. | Authorizer 对每个请求授权。
	// nil 允许所有请求。
	Authorizer Authorizer
	// PasswordSetter provisions passwords. Without it a request carrying password is rejected. |
	// PasswordSetter 预配口令。缺失时携带 password 的请求会被拒绝。
	PasswordSetter PasswordSetter
	// PasswordPrecheck validates passwords before a profile write is committed. Without it the
	// server calls PasswordSetter only after the store mutation and compensates a rejection by
	// restoring the prior profile. | PasswordPrecheck 在资料写入提交前校验口令。缺失时服务端仅在
	// 存储变更后调用 PasswordSetter，并通过恢复先前资料来补偿拒绝。
	PasswordPrecheck PasswordPrechecker
	// AllowAnyContentType accepts any request Content-Type on SCIM write requests. The default
	// rejects POST, PUT and PATCH bodies whose media type is neither application/scim+json nor
	// application/json with HTTP 415 as required by RFC 7644 section 3.1. | AllowAnyContentType
	// 在 SCIM 写请求上接受任意 Content-Type。默认按 RFC 7644 第 3.1 节，对媒体类型既非
	// application/scim+json 也非 application/json 的 POST、PUT 与 PATCH 请求体返回 HTTP 415。
	AllowAnyContentType bool
	// Clock supplies timestamps for discovery metadata. nil uses time.Now. | Clock 为发现元数据
	// 提供时间戳。nil 使用 time.Now。
	Clock func() time.Time
	// BaseURL is the absolute public base URL, including any prefix, used for Location and $ref
	// values. When empty it is derived from the request scheme, host and registered prefix. |
	// BaseURL 是用于 Location 与 $ref 的绝对公开基础 URL，包含任何前缀。为空时由请求协议、主机与
	// 注册前缀推导。
	BaseURL string
	// DocumentationURI points to service documentation in ServiceProviderConfig. |
	// DocumentationURI 在 ServiceProviderConfig 中指向服务文档。
	DocumentationURI string
	// MaxResults caps a page and defaults to DefaultMaxResults. | MaxResults 限制单页大小，默认
	// DefaultMaxResults。
	MaxResults int
	// BulkMaxOperations caps operations per bulk request and defaults to DefaultBulkMaxOperations. |
	// BulkMaxOperations 限制单次批量请求的操作数，默认 DefaultBulkMaxOperations。
	BulkMaxOperations int
	// BulkMaxPayloadSize caps the bulk request body in bytes and defaults to
	// DefaultBulkMaxPayloadSize. | BulkMaxPayloadSize 限制批量请求体字节数，默认
	// DefaultBulkMaxPayloadSize。
	BulkMaxPayloadSize int64
	// BulkMaxUndoBytes caps the estimated memory of the atomic bulk undo log and defaults to
	// DefaultBulkMaxUndoBytes. It is only consulted when BulkAtomic is enabled. | BulkMaxUndoBytes
	// 限制原子批量撤销日志的估算内存，默认 DefaultBulkMaxUndoBytes。仅在启用 BulkAtomic 时使用。
	BulkMaxUndoBytes int64
	// BulkAtomic makes bulk requests transactional: every mutation records a compensating undo
	// entry, the first failure rolls back all previously applied operations in reverse order and
	// removes their bulkId mappings, and FailOnErrors is ignored because processing always stops at
	// the first failure. Disabled keeps the RFC 7644 non-transactional behavior. | BulkAtomic 使批量
	// 请求具备事务性：每个变更记录补偿撤销条目，首次失败会按逆序回滚全部先前已应用的操作并移除其
	// bulkId 映射，同时忽略 FailOnErrors，因为处理总是在首次失败时停止。关闭时保持 RFC 7644 的
	// 非事务行为。
	BulkAtomic bool
}

// Server implements the RFC 7644 SCIM protocol over a Store. | Server 在 Store 之上实现 RFC 7644
// SCIM 协议。
type Server struct {
	// store is the persistence backend. | store 是持久化后端。
	store Store
	// authorizer authorizes requests. | authorizer 对请求授权。
	authorizer Authorizer
	// passwordSetter provisions write-only passwords. | passwordSetter 预配只写口令。
	passwordSetter PasswordSetter
	// passwordPrecheck validates passwords before a profile write commits. | passwordPrecheck 在
	// 资料写入提交前校验口令。
	passwordPrecheck PasswordPrechecker
	// allowAnyContentType accepts any write request media type. | allowAnyContentType 接受任意写
	// 请求媒体类型。
	allowAnyContentType bool
	// clock supplies timestamps. | clock 提供时间戳。
	clock func() time.Time
	// baseURL is the optional configured public base URL. | baseURL 是可选配置的公开基础 URL。
	baseURL string
	// documentationURI is rendered by ServiceProviderConfig. | documentationURI 由
	// ServiceProviderConfig 输出。
	documentationURI string
	// maxResults caps a page. | maxResults 限制单页大小。
	maxResults int
	// bulkMaxOperations caps a bulk request. | bulkMaxOperations 限制一次批量请求。
	bulkMaxOperations int
	// bulkMaxPayloadSize caps a bulk request body. | bulkMaxPayloadSize 限制批量请求体。
	bulkMaxPayloadSize int64
	// bulkMaxUndoBytes caps the estimated undo log memory. | bulkMaxUndoBytes 限制撤销日志的估算
	// 内存。
	bulkMaxUndoBytes int64
	// bulkAtomic enables compensating rollback for bulk requests. | bulkAtomic 启用批量请求的补偿
	// 回滚。
	bulkAtomic bool
}

// New creates a Server. It returns ErrInvalidConfig for contradictory limits. | New 创建 Server。
// 限制互相矛盾时返回 ErrInvalidConfig。
func New(options Options) (*Server, error) {
	store := options.Store
	if store == nil {
		store = NewMemoryStore()
	}
	maxResults := options.MaxResults
	if maxResults == 0 {
		maxResults = DefaultMaxResults
	}
	if maxResults < 0 {
		return nil, errs.Detail(ErrInvalidConfig, "MaxResults must be positive | MaxResults 必须为正数")
	}
	bulkMaxOperations := options.BulkMaxOperations
	if bulkMaxOperations == 0 {
		bulkMaxOperations = DefaultBulkMaxOperations
	}
	if bulkMaxOperations < 0 {
		return nil, errs.Detail(ErrInvalidConfig, "BulkMaxOperations must be positive | BulkMaxOperations 必须为正数")
	}
	bulkMaxPayloadSize := options.BulkMaxPayloadSize
	if bulkMaxPayloadSize == 0 {
		bulkMaxPayloadSize = DefaultBulkMaxPayloadSize
	}
	if bulkMaxPayloadSize < 0 {
		return nil, errs.Detail(ErrInvalidConfig, "BulkMaxPayloadSize must be positive | BulkMaxPayloadSize 必须为正数")
	}
	bulkMaxUndoBytes := options.BulkMaxUndoBytes
	if bulkMaxUndoBytes == 0 {
		bulkMaxUndoBytes = DefaultBulkMaxUndoBytes
	}
	if bulkMaxUndoBytes < 0 {
		return nil, errs.Detail(ErrInvalidConfig, "BulkMaxUndoBytes must be positive | BulkMaxUndoBytes 必须为正数")
	}
	clock := options.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &Server{
		store:               store,
		authorizer:          options.Authorizer,
		baseURL:             strings.TrimRight(strings.TrimSpace(options.BaseURL), "/"),
		documentationURI:    options.DocumentationURI,
		maxResults:          maxResults,
		bulkMaxOperations:   bulkMaxOperations,
		bulkMaxPayloadSize:  bulkMaxPayloadSize,
		bulkAtomic:          options.BulkAtomic,
		bulkMaxUndoBytes:    bulkMaxUndoBytes,
		passwordSetter:      options.PasswordSetter,
		passwordPrecheck:    options.PasswordPrecheck,
		allowAnyContentType: options.AllowAnyContentType,
		clock:               clock,
	}, nil
}

// requestPrefixKey carries the mount prefix from the entry point to response URL building. |
// requestPrefixKey 把挂载前缀从入口传递到响应 URL 构建逻辑。
type requestPrefixKey struct{}

// withRequestPrefix returns a request carrying prefix. | withRequestPrefix 返回携带 prefix 的请求。
func withRequestPrefix(r *http.Request, prefix string) *http.Request {
	if r == nil {
		return nil
	}
	return r.WithContext(context.WithValue(r.Context(), requestPrefixKey{}, normalizePrefix(prefix)))
}

// requestPrefix returns the mount prefix stored on r. | requestPrefix 返回 r 上保存的挂载前缀。
func requestPrefix(r *http.Request) string {
	if r == nil {
		return ""
	}
	prefix, _ := r.Context().Value(requestPrefixKey{}).(string)
	return prefix
}

// normalizePrefix turns prefix into "" or a leading-slash form without a trailing slash. |
// normalizePrefix 把 prefix 规范化为 "" 或带前导斜杠且无尾斜杠的形式。
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

// Register mounts the SCIM endpoints on a ydx router below prefix. | Register 把 SCIM 端点挂载到
// ydx 路由器 prefix 之下。
//
// Static .search routes take precedence over the :id routes because the router ranks static
// segments above parameter segments. | 由于路由器将静态段排在参数段之前，静态 .search 路由优先于
// :id 路由。
func (s *Server) Register(r *router.Router, prefix string) {
	if s == nil || r == nil {
		return
	}
	mount := normalizePrefix(prefix)
	register := func(method, path, route, param string) {
		handler := s.routerHandler(mount, route, param)
		r.Handle(method, mount+path, handler)
	}
	register(http.MethodGet, "/Users", routeUsersCollection, "")
	register(http.MethodPost, "/Users", routeUsersCollection, "")
	register(http.MethodPost, "/Users/.search", routeUsersSearch, "")
	register(http.MethodGet, "/Users/:id", routeUser, "id")
	register(http.MethodPut, "/Users/:id", routeUser, "id")
	register(http.MethodPatch, "/Users/:id", routeUser, "id")
	register(http.MethodDelete, "/Users/:id", routeUser, "id")
	register(http.MethodGet, "/Groups", routeGroupsCollection, "")
	register(http.MethodPost, "/Groups", routeGroupsCollection, "")
	register(http.MethodPost, "/Groups/.search", routeGroupsSearch, "")
	register(http.MethodGet, "/Groups/:id", routeGroup, "id")
	register(http.MethodPut, "/Groups/:id", routeGroup, "id")
	register(http.MethodPatch, "/Groups/:id", routeGroup, "id")
	register(http.MethodDelete, "/Groups/:id", routeGroup, "id")
	register(http.MethodGet, "/Me", routeMe, "")
	register(http.MethodPut, "/Me", routeMe, "")
	register(http.MethodPatch, "/Me", routeMe, "")
	register(http.MethodGet, "/ServiceProviderConfig", routeServiceProviderConfig, "")
	register(http.MethodGet, "/ResourceTypes", routeResourceTypes, "")
	register(http.MethodGet, "/ResourceTypes/:name", routeResourceType, "name")
	register(http.MethodGet, "/Schemas", routeSchemas, "")
	register(http.MethodGet, "/Schemas/:urn", routeSchema, "urn")
	register(http.MethodPost, "/Bulk", routeBulk, "")
}

// routerHandler adapts one SCIM route to a ydx router handler. | routerHandler 把一条 SCIM 路由
// 适配为 ydx 路由器处理器。
func (s *Server) routerHandler(prefix, route, param string) router.HandlerFunc {
	return func(c *router.Ctx) {
		id := ""
		if param != "" {
			id = c.ParamUnescaped(param)
		}
		s.serveRoute(c.Writer, withRequestPrefix(c.Request, prefix), route, id)
	}
}

// HTTPHandler returns a native net/http handler mounted below prefix. | HTTPHandler 返回挂载在
// prefix 之下的原生 net/http 处理器。
func (s *Server) HTTPHandler(prefix string) http.Handler {
	mount := normalizePrefix(prefix)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if mount != "" {
			if path == mount {
				path = "/"
			} else if strings.HasPrefix(path, mount+"/") {
				path = path[len(mount):]
			} else {
				writeStatusError(w, http.StatusNotFound, "", "scim: resource not found | scim：资源不存在")
				return
			}
		}
		s.servePath(w, withRequestPrefix(r, mount), path)
	})
}

// servePath dispatches a native HTTP request by path. | servePath 按路径分派原生 HTTP 请求。
func (s *Server) servePath(w http.ResponseWriter, r *http.Request, path string) {
	segments := splitRequestPath(path)
	if len(segments) == 0 {
		writeStatusError(w, http.StatusNotFound, "", "scim: resource not found | scim：资源不存在")
		return
	}
	head := strings.ToLower(segments[0])
	rest := segments[1:]
	switch head {
	case "users":
		switch {
		case len(rest) == 0:
			s.serveRoute(w, r, routeUsersCollection, "")
		case len(rest) == 1 && rest[0] == ".search":
			s.serveRoute(w, r, routeUsersSearch, "")
		case len(rest) == 1:
			s.serveRoute(w, r, routeUser, rest[0])
		default:
			writeStatusError(w, http.StatusNotFound, "", "scim: resource not found | scim：资源不存在")
		}
	case "groups":
		switch {
		case len(rest) == 0:
			s.serveRoute(w, r, routeGroupsCollection, "")
		case len(rest) == 1 && rest[0] == ".search":
			s.serveRoute(w, r, routeGroupsSearch, "")
		case len(rest) == 1:
			s.serveRoute(w, r, routeGroup, rest[0])
		default:
			writeStatusError(w, http.StatusNotFound, "", "scim: resource not found | scim：资源不存在")
		}
	case "me":
		if len(rest) == 0 {
			s.serveRoute(w, r, routeMe, "")
			return
		}
		writeStatusError(w, http.StatusNotFound, "", "scim: resource not found | scim：资源不存在")
	case "serviceproviderconfig":
		s.serveRoute(w, r, routeServiceProviderConfig, "")
	case "resourcetypes":
		if len(rest) == 0 {
			s.serveRoute(w, r, routeResourceTypes, "")
			return
		}
		if len(rest) == 1 {
			s.serveRoute(w, r, routeResourceType, rest[0])
			return
		}
		writeStatusError(w, http.StatusNotFound, "", "scim: resource not found | scim：资源不存在")
	case "schemas":
		if len(rest) == 0 {
			s.serveRoute(w, r, routeSchemas, "")
			return
		}
		if len(rest) == 1 {
			s.serveRoute(w, r, routeSchema, rest[0])
			return
		}
		writeStatusError(w, http.StatusNotFound, "", "scim: resource not found | scim：资源不存在")
	case "bulk":
		if len(rest) == 0 {
			s.serveRoute(w, r, routeBulk, "")
			return
		}
		writeStatusError(w, http.StatusNotFound, "", "scim: resource not found | scim：资源不存在")
	default:
		writeStatusError(w, http.StatusNotFound, "", "scim: resource not found | scim：资源不存在")
	}
}

// splitRequestPath splits a URL path into non-empty segments. | splitRequestPath 把 URL 路径切分为
// 非空段。
func splitRequestPath(path string) []string {
	path = strings.Trim(path, "/")
	if path == "" {
		return nil
	}
	parts := strings.Split(path, "/")
	out := parts[:0]
	for _, part := range parts {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// serveRoute dispatches one logical route with its optional identifier. | serveRoute 分派一条逻辑
// 路由及其可选标识。
func (s *Server) serveRoute(w http.ResponseWriter, r *http.Request, route, id string) {
	switch route {
	case routeUsersCollection:
		switch r.Method {
		case http.MethodGet:
			s.handleListUsers(w, r)
		case http.MethodPost:
			s.handleCreateUser(w, r)
		default:
			methodNotAllowed(w, http.MethodGet, http.MethodPost)
		}
	case routeUsersSearch:
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}
		s.handleSearchUsers(w, r)
	case routeUser:
		switch r.Method {
		case http.MethodGet:
			s.handleGetUser(w, r, id)
		case http.MethodPut:
			s.handleReplaceUser(w, r, id)
		case http.MethodPatch:
			s.handlePatchUser(w, r, id)
		case http.MethodDelete:
			s.handleDeleteUser(w, r, id)
		default:
			methodNotAllowed(w, http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete)
		}
	case routeGroupsCollection:
		switch r.Method {
		case http.MethodGet:
			s.handleListGroups(w, r)
		case http.MethodPost:
			s.handleCreateGroup(w, r)
		default:
			methodNotAllowed(w, http.MethodGet, http.MethodPost)
		}
	case routeGroupsSearch:
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}
		s.handleSearchGroups(w, r)
	case routeGroup:
		switch r.Method {
		case http.MethodGet:
			s.handleGetGroup(w, r, id)
		case http.MethodPut:
			s.handleReplaceGroup(w, r, id)
		case http.MethodPatch:
			s.handlePatchGroup(w, r, id)
		case http.MethodDelete:
			s.handleDeleteGroup(w, r, id)
		default:
			methodNotAllowed(w, http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete)
		}
	case routeMe:
		switch r.Method {
		case http.MethodGet:
			s.handleGetMe(w, r)
		case http.MethodPut:
			s.handleReplaceMe(w, r)
		case http.MethodPatch:
			s.handlePatchMe(w, r)
		default:
			methodNotAllowed(w, http.MethodGet, http.MethodPut, http.MethodPatch)
		}
	case routeServiceProviderConfig:
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		s.handleServiceProviderConfig(w, r)
	case routeResourceTypes:
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		s.handleResourceTypes(w, r)
	case routeResourceType:
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		s.handleResourceType(w, r, id)
	case routeSchemas:
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		s.handleSchemas(w, r)
	case routeSchema:
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		s.handleSchema(w, r, id)
	case routeBulk:
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}
		s.handleBulk(w, r)
	default:
		writeStatusError(w, http.StatusNotFound, "", "scim: resource not found | scim：资源不存在")
	}
}

// Logical route names. | 逻辑路由名。
const (
	routeUsersCollection       = "users"
	routeUsersSearch           = "users.search"
	routeUser                  = "user"
	routeGroupsCollection      = "groups"
	routeGroupsSearch          = "groups.search"
	routeGroup                 = "group"
	routeMe                    = "me"
	routeServiceProviderConfig = "serviceProviderConfig"
	routeResourceTypes         = "resourceTypes"
	routeResourceType          = "resourceType"
	routeSchemas               = "schemas"
	routeSchema                = "schema"
	routeBulk                  = "bulk"
)

// authorize applies the configured Authorizer. | authorize 应用已配置的 Authorizer。
func (s *Server) authorize(r *http.Request, action, resource string) error {
	if s.authorizer == nil {
		return nil
	}
	ctx := context.Background()
	if r != nil {
		ctx = r.Context()
	}
	if err := s.authorizer(ctx, r, action, resource); err != nil {
		switch {
		case errors.Is(err, ErrUnauthorized), errors.Is(err, ErrForbidden):
			return err
		default:
			return errs.WrapDetail(err, ErrForbidden, "authorizer rejected request | 授权器拒绝了请求")
		}
	}
	return nil
}

// baseURLFor returns the public base URL for response links. | baseURLFor 返回响应链接使用的公开
// 基础 URL。
func (s *Server) baseURLFor(r *http.Request) string {
	if s.baseURL != "" {
		return s.baseURL
	}
	scheme := "http"
	if r != nil && r.TLS != nil {
		scheme = "https"
	}
	host := ""
	if r != nil {
		host = r.Host
	}
	prefix := requestPrefix(r)
	if host == "" {
		return prefix
	}
	return scheme + "://" + host + prefix
}

// userLocation returns the absolute Location of a User. | userLocation 返回 User 的绝对 Location。
func (s *Server) userLocation(r *http.Request, id string) string {
	return s.baseURLFor(r) + "/Users/" + url.PathEscape(id)
}

// groupLocation returns the absolute Location of a Group. | groupLocation 返回 Group 的绝对
// Location。
func (s *Server) groupLocation(r *http.Request, id string) string {
	return s.baseURLFor(r) + "/Groups/" + url.PathEscape(id)
}

// prepareUser returns a response-safe copy with metadata location and entity tag. | prepareUser
// 返回带有元数据 Location 与实体标签的响应安全副本。
func (s *Server) prepareUser(r *http.Request, user *User) *User {
	if user == nil {
		return nil
	}
	out := user.Sanitize()
	out.EnsureSchemas()
	if out.Meta == nil {
		out.Meta = &Meta{}
	}
	out.Meta.ResourceType = ResourceTypeNameUser
	if out.ID != "" {
		out.Meta.Location = s.userLocation(r, out.ID)
	}
	return out
}

// prepareGroup returns a response-safe copy with metadata location and entity tag. | prepareGroup
// 返回带有元数据 Location 与实体标签的响应安全副本。
func (s *Server) prepareGroup(r *http.Request, group *Group) *Group {
	if group == nil {
		return nil
	}
	out := group.Clone()
	out.EnsureSchemas()
	if out.Meta == nil {
		out.Meta = &Meta{}
	}
	out.Meta.ResourceType = ResourceTypeNameGroup
	if out.ID != "" {
		out.Meta.Location = s.groupLocation(r, out.ID)
	}
	return out
}

// checkPreconditions evaluates If-Match and If-None-Match. mutating selects 412 instead of 304 for
// If-None-Match matches. | checkPreconditions 评估 If-Match 与 If-None-Match。mutating 选择在
// If-None-Match 命中时返回 412 而不是 304。
func checkPreconditions(r *http.Request, version string, mutating bool) error {
	if r == nil {
		return nil
	}
	if header := strings.TrimSpace(r.Header.Get("If-Match")); header != "" {
		if !etagListMatches(header, version) {
			return errs.Detail(ErrInvalidVersion, "If-Match does not match current version | If-Match 与当前版本不匹配")
		}
	}
	if header := strings.TrimSpace(r.Header.Get("If-None-Match")); header != "" {
		if etagListMatches(header, version) {
			if mutating {
				return errs.Detail(ErrInvalidVersion, "If-None-Match matched current version | If-None-Match 命中当前版本")
			}
			return ErrNotModified
		}
	}
	return nil
}

// etagListMatches reports whether a comma separated entity tag list matches version. | etagListMatches
// 报告逗号分隔的实体标签列表是否匹配 version。
func etagListMatches(header, version string) bool {
	if header == "*" {
		return true
	}
	if version == "" {
		return false
	}
	want := normalizeETag(version)
	for _, token := range strings.Split(header, ",") {
		token = strings.TrimSpace(token)
		if token == "*" {
			return true
		}
		if normalizeETag(token) == want {
			return true
		}
	}
	return false
}

// normalizeETag removes the weak marker and quotes from an entity tag. | normalizeETag 移除实体标签
// 的弱标记与引号。
func normalizeETag(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "W/")
	value = strings.TrimPrefix(value, "w/")
	value = strings.TrimSpace(value)
	return strings.Trim(value, `"`)
}

// setETag writes the resource entity tag header. | setETag 写入资源实体标签响应头。
func setETag(w http.ResponseWriter, version string) {
	if version != "" {
		w.Header().Set("ETag", version)
	}
}

// writeSCIM writes value with the SCIM media type. | writeSCIM 以 SCIM 媒体类型写出 value。
func writeSCIM(w http.ResponseWriter, status int, value any) {
	data, err := ydxjson.Marshal(value)
	if err != nil {
		writeStaticInternalError(w)
		return
	}
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

// writeStaticInternalError writes a generic internal error without encoding a value. |
// writeStaticInternalError 在不编码值的情况下写出通用内部错误。
func writeStaticInternalError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"500","detail":"scim: internal error | scim：内部错误"}`))
}

// writeError translates err into an RFC 7644 Error response. | writeError 把 err 转换为 RFC 7644
// 错误响应。
func writeError(w http.ResponseWriter, err error) {
	info := classifyError(err)
	if info.status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	detail := errorDetail(err, info.status)
	writeSCIM(w, info.status, Error{
		Schemas:  []string{ErrorSchema},
		Status:   intString(info.status),
		ScimType: info.scimType,
		Detail:   detail,
	})
}

// writeStatusError writes an error with an explicit HTTP status. | writeStatusError 以显式 HTTP
// 状态写出错误。
func writeStatusError(w http.ResponseWriter, status int, scimType, detail string) {
	writeSCIM(w, status, Error{
		Schemas:  []string{ErrorSchema},
		Status:   intString(status),
		ScimType: scimType,
		Detail:   detail,
	})
}

// errorDetail returns a client-safe detail for err. Server failures never echo backend text. |
// errorDetail 返回 err 的客户端安全明细。服务端故障绝不回显后端文本。
func errorDetail(err error, status int) string {
	if err == nil {
		return ""
	}
	if status >= http.StatusInternalServerError {
		return "scim: internal error | scim：内部错误"
	}
	return err.Error()
}

// methodNotAllowed writes a 405 response with an Allow header. | methodNotAllowed 写出带 Allow 响应头
// 的 405 响应。
func methodNotAllowed(w http.ResponseWriter, methods ...string) {
	w.Header().Set("Allow", strings.Join(methods, ", "))
	writeStatusError(w, http.StatusMethodNotAllowed, "", "scim: method not allowed | scim：方法不允许")
}

// maxSCIMRequestBody bounds non-bulk request bodies so a peer cannot make the
// server buffer an unbounded JSON document. | maxSCIMRequestBody 限制非批量请求体，
// 避免对端让服务端缓冲无界 JSON 文档。
const maxSCIMRequestBody = 4 << 20

// decodeBody decodes a size-limited request body through ydx/json. | decodeBody 经
// ydx/json 解码有大小上限的请求体。
func decodeBody(r *http.Request, target any) error {
	if r == nil || r.Body == nil {
		return errs.Detail(ErrInvalidSyntax, "missing request body | 缺少请求体")
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, int64(maxSCIMRequestBody)+1))
	if err != nil {
		return errs.Detail(ErrInvalidSyntax, "cannot read request body | 无法读取请求体")
	}
	if len(data) > maxSCIMRequestBody {
		return errs.Detail(ErrTooMany, "request body exceeds %d bytes | 请求体超过 %d 字节",
			maxSCIMRequestBody, maxSCIMRequestBody)
	}
	if err := ydxjson.Unmarshal(data, target); err != nil {
		return errs.Detail(ErrInvalidSyntax, "invalid JSON body | JSON 请求体非法")
	}
	return nil
}

// parseListParams normalizes the RFC 7644 collection query parameters. | parseListParams 规范化
// RFC 7644 集合查询参数。
func (s *Server) parseListParams(r *http.Request) (listParams, error) {
	values := r.URL.Query()
	params := listParams{startIndex: 1, count: s.maxResults}
	if raw := strings.TrimSpace(values.Get("filter")); raw != "" {
		filter, err := ParseFilter(raw)
		if err != nil {
			return listParams{}, err
		}
		params.filter = filter
	}
	if raw := strings.TrimSpace(values.Get("sortBy")); raw != "" {
		if _, err := ParseAttributePath(raw); err != nil {
			return listParams{}, errs.Detail(ErrInvalidValue, "invalid sortBy %q | 非法 sortBy %q", raw, raw)
		}
		params.sortBy = raw
	}
	order, err := ParseSortOrder(values.Get("sortOrder"))
	if err != nil {
		return listParams{}, err
	}
	params.sortOrder = order
	if raw := strings.TrimSpace(values.Get("startIndex")); raw != "" {
		index, err := strconv.Atoi(raw)
		if err != nil || index < 0 {
			return listParams{}, errs.Detail(ErrInvalidValue, "invalid startIndex %q | 非法 startIndex %q", raw, raw)
		}
		if index > 0 {
			params.startIndex = index
		}
	}
	if raw := strings.TrimSpace(values.Get("count")); raw != "" {
		count, err := strconv.Atoi(raw)
		if err != nil || count < 0 {
			return listParams{}, errs.Detail(ErrInvalidValue, "invalid count %q | 非法 count %q", raw, raw)
		}
		if count > s.maxResults {
			return listParams{}, errs.Detail(ErrTooMany, "count %d exceeds maxResults %d | count %d 超过 maxResults %d",
				count, s.maxResults, count, s.maxResults)
		}
		params.count = count
	}
	attributes, excluded, err := parseAttributeSelection(values)
	if err != nil {
		return listParams{}, err
	}
	params.attributes = attributes
	params.excluded = excluded
	return params, nil
}

// parseAttributeSelection parses attributes and excludedAttributes query parameters. |
// parseAttributeSelection 解析 attributes 与 excludedAttributes 查询参数。
func parseAttributeSelection(values url.Values) ([]string, []string, error) {
	attributes := splitCSV(values["attributes"])
	excluded := splitCSV(values["excludedAttributes"])
	if len(attributes) > 0 && len(excluded) > 0 {
		return nil, nil, errs.Detail(ErrInvalidValue, "attributes and excludedAttributes are mutually exclusive | attributes 与 excludedAttributes 互斥")
	}
	return attributes, excluded, nil
}

// splitCSV flattens repeated comma separated query values. | splitCSV 展平重复的逗号分隔查询值。
func splitCSV(values []string) []string {
	var out []string
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

// listParams holds normalized list query state. | listParams 保存规范化后的列表查询状态。
type listParams struct {
	// filter is the parsed filter, nil when absent. | filter 是已解析过滤器，缺失时为 nil。
	filter Filter
	// sortBy is the requested sort attribute. | sortBy 是请求的排序属性。
	sortBy string
	// sortOrder is the requested direction. | sortOrder 是请求的排序方向。
	sortOrder SortOrder
	// attributes and excluded select response attributes. | attributes 与 excluded 选择响应属性。
	attributes []string
	excluded   []string
	// startIndex is the normalized 1-based start. | startIndex 是规范化后的 1 基起点。
	startIndex int
	// count is the normalized page size. | count 是规范化后的分页大小。
	count int
}

// searchParams converts a POST .search body into list parameters. | searchParams 把 POST .search
// 请求体转换为列表参数。
func (s *Server) searchParams(request SearchRequest) (listParams, error) {
	params := listParams{
		sortBy:     strings.TrimSpace(request.SortBy),
		startIndex: request.StartIndex,
		count:      request.Count,
		attributes: cleanAttributeList(request.Attributes),
		excluded:   cleanAttributeList(request.ExcludedAttributes),
	}
	if len(params.attributes) > 0 && len(params.excluded) > 0 {
		return listParams{}, errs.Detail(ErrInvalidValue, "attributes and excludedAttributes are mutually exclusive | attributes 与 excludedAttributes 互斥")
	}
	if raw := strings.TrimSpace(request.Filter); raw != "" {
		filter, err := ParseFilter(raw)
		if err != nil {
			return listParams{}, err
		}
		params.filter = filter
	}
	order, err := ParseSortOrder(request.SortOrder)
	if err != nil {
		return listParams{}, err
	}
	params.sortOrder = order
	if params.startIndex <= 0 {
		params.startIndex = 1
	}
	if params.count <= 0 {
		params.count = s.maxResults
	}
	if params.count > s.maxResults {
		return listParams{}, errs.Detail(ErrTooMany, "count %d exceeds maxResults %d | count %d 超过 maxResults %d",
			params.count, s.maxResults, params.count, s.maxResults)
	}
	if params.sortBy != "" {
		if _, err := ParseAttributePath(params.sortBy); err != nil {
			return listParams{}, errs.Detail(ErrInvalidValue, "invalid sortBy %q | 非法 sortBy %q", params.sortBy, params.sortBy)
		}
	}
	return params, nil
}

// cleanAttributeList trims and drops empty attribute names. | cleanAttributeList 去除空白并丢弃空
// 属性名。
func cleanAttributeList(list []string) []string {
	out := make([]string, 0, len(list))
	for _, item := range list {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// acceptedWriteMediaType reports whether mediaType is one of the RFC 7644 JSON media types. |
// acceptedWriteMediaType 报告 mediaType 是否为 RFC 7644 的 JSON 媒体类型之一。
func acceptedWriteMediaType(mediaType string) bool {
	switch strings.ToLower(strings.TrimSpace(mediaType)) {
	case ContentType, ContentTypeJSON:
		return true
	default:
		return false
	}
}

// requireWriteContentType enforces the RFC 7644 write media types. When the request carries a
// missing, malformed or unsupported Content-Type it writes a 415 Error response and returns false.
// Callers must only use it for POST, PUT and PATCH routes; GET and HEAD never check a request
// media type. | requireWriteContentType 强制 RFC 7644 的写媒体类型。请求的 Content-Type 缺失、
// 格式错误或不受支持时，它写出 415 Error 响应并返回 false。调用方只能把它用于 POST、PUT 与 PATCH
// 路由；GET 与 HEAD 从不检查请求媒体类型。
func (s *Server) requireWriteContentType(w http.ResponseWriter, r *http.Request) bool {
	if s == nil || s.allowAnyContentType {
		return true
	}
	header := ""
	if r != nil {
		header = strings.TrimSpace(r.Header.Get("Content-Type"))
	}
	if header != "" {
		if mediaType, _, err := mime.ParseMediaType(header); err == nil && acceptedWriteMediaType(mediaType) {
			return true
		}
	}
	writeStatusError(w, http.StatusUnsupportedMediaType, "",
		"scim: unsupported media type; use "+ContentType+" or "+ContentTypeJSON+" | scim：不支持的媒体类型；请使用 "+ContentType+" 或 "+ContentTypeJSON)
	return false
}
