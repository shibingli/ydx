package scim

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
	ydxjson "github.com/shibingli/ydx/json"
)

// ClientOption configures a Client. | ClientOption 配置 Client。
type ClientOption func(*Client)

// WithHTTPClient sets the HTTP client used for requests. | WithHTTPClient 设置请求使用的 HTTP
// 客户端。
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *Client) {
		if httpClient != nil {
			c.httpClient = httpClient
		}
	}
}

// WithBearerToken sets the OAuth bearer token used for authentication. | WithBearerToken 设置认证
// 使用的 OAuth 持有者令牌。
func WithBearerToken(token string) ClientOption {
	return func(c *Client) {
		c.token = strings.TrimSpace(token)
	}
}

// WithBasicAuth sets HTTP basic credentials used for authentication. | WithBasicAuth 设置认证使用
// 的 HTTP 基本认证凭据。
func WithBasicAuth(username, password string) ClientOption {
	return func(c *Client) {
		c.username = username
		c.password = password
	}
}

// WithUserAgent sets the User-Agent header sent with every request. | WithUserAgent 设置每个请求发送
// 的 User-Agent 响应头。
func WithUserAgent(userAgent string) ClientOption {
	return func(c *Client) {
		c.userAgent = strings.TrimSpace(userAgent)
	}
}

// Client is an RFC 7644 SCIM protocol client. | Client 是 RFC 7644 SCIM 协议客户端。
type Client struct {
	// baseURL is the absolute service root without a trailing slash. | baseURL 是无尾斜杠的绝对服务
	// 根地址。
	baseURL string
	// httpClient performs requests. | httpClient 执行请求。
	httpClient *http.Client
	// token is the bearer token, empty when unset. | token 是持有者令牌，未设置时为空。
	token string
	// username and password are basic credentials. | username 与 password 是基本认证凭据。
	username string
	password string
	// userAgent is sent as User-Agent. | userAgent 作为 User-Agent 发送。
	userAgent string
}

// NewClient creates a Client for an absolute SCIM service root. | NewClient 为绝对 SCIM 服务根地址
// 创建 Client。
func NewClient(baseURL string, options ...ClientOption) (*Client, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, errs.Detail(ErrInvalidConfig, "BaseURL is required | BaseURL 为必需")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errs.Detail(ErrInvalidConfig, "BaseURL must be absolute | BaseURL 必须是绝对地址")
	}
	client := &Client{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		userAgent:  "ydx-scim",
	}
	for _, option := range options {
		if option != nil {
			option(client)
		}
	}
	return client, nil
}

// BaseURL returns the configured service root. | BaseURL 返回已配置的服务根地址。
func (c *Client) BaseURL() string {
	if c == nil {
		return ""
	}
	return c.baseURL
}

// RequestOption customizes one request. | RequestOption 定制单个请求。
type RequestOption func(*requestHeaders)

// requestHeaders holds conditional request headers. | requestHeaders 保存条件请求头。
type requestHeaders struct {
	ifMatch     string
	ifNoneMatch string
}

// WithIfMatch sets the If-Match precondition. | WithIfMatch 设置 If-Match 前置条件。
func WithIfMatch(version string) RequestOption {
	return func(headers *requestHeaders) {
		headers.ifMatch = strings.TrimSpace(version)
	}
}

// WithIfNoneMatch sets the If-None-Match precondition. | WithIfNoneMatch 设置 If-None-Match 前置
// 条件。
func WithIfNoneMatch(version string) RequestOption {
	return func(headers *requestHeaders) {
		headers.ifNoneMatch = strings.TrimSpace(version)
	}
}

// ListOptions holds RFC 7644 collection query parameters. | ListOptions 保存 RFC 7644 集合查询参数。
type ListOptions struct {
	// Filter is the filter expression. | Filter 是过滤表达式。
	Filter string
	// SortBy is the sort attribute path. | SortBy 是排序属性路径。
	SortBy string
	// SortOrder is the sort direction. | SortOrder 是排序方向。
	SortOrder SortOrder
	// Attributes selects returned attributes. | Attributes 选择返回的属性。
	Attributes []string
	// ExcludedAttributes removes returned attributes. | ExcludedAttributes 移除返回的属性。
	ExcludedAttributes []string
	// StartIndex is the 1-based first result. | StartIndex 是 1 基的首个结果。
	StartIndex int
	// Count is the page size. | Count 是分页大小。
	Count int
}

// values renders options as URL query parameters. | values 把选项渲染为 URL 查询参数。
func (o ListOptions) values() url.Values {
	values := url.Values{}
	if filter := strings.TrimSpace(o.Filter); filter != "" {
		values.Set("filter", filter)
	}
	if attributes := cleanAttributeList(o.Attributes); len(attributes) > 0 {
		values.Set("attributes", strings.Join(attributes, ","))
	}
	if excluded := cleanAttributeList(o.ExcludedAttributes); len(excluded) > 0 {
		values.Set("excludedAttributes", strings.Join(excluded, ","))
	}
	if sortBy := strings.TrimSpace(o.SortBy); sortBy != "" {
		values.Set("sortBy", sortBy)
	}
	if o.SortOrder != "" {
		values.Set("sortOrder", string(o.SortOrder))
	}
	if o.StartIndex > 0 {
		values.Set("startIndex", intString(o.StartIndex))
	}
	if o.Count != 0 {
		values.Set("count", intString(o.Count))
	}
	return values
}

// UserPage is a page of Users. | UserPage 是一页 User。
type UserPage struct {
	// Schemas is the message schema list. | Schemas 是消息 Schema 列表。
	Schemas []string `json:"schemas,omitempty"`
	// Resources holds the page of Users. | Resources 保存本页 User。
	Resources []*User `json:"Resources"`
	// TotalResults is the number of matching resources. | TotalResults 是匹配资源总数。
	TotalResults int `json:"totalResults"`
	// StartIndex is the 1-based first result index. | StartIndex 是 1 基的首个结果索引。
	StartIndex int `json:"startIndex"`
	// ItemsPerPage is the number of resources in this page. | ItemsPerPage 是本页资源数。
	ItemsPerPage int `json:"itemsPerPage"`
}

// GroupPage is a page of Groups. | GroupPage 是一页 Group。
type GroupPage struct {
	// Schemas is the message schema list. | Schemas 是消息 Schema 列表。
	Schemas []string `json:"schemas,omitempty"`
	// Resources holds the page of Groups. | Resources 保存本页 Group。
	Resources []*Group `json:"Resources"`
	// TotalResults is the number of matching resources. | TotalResults 是匹配资源总数。
	TotalResults int `json:"totalResults"`
	// StartIndex is the 1-based first result index. | StartIndex 是 1 基的首个结果索引。
	StartIndex int `json:"startIndex"`
	// ItemsPerPage is the number of resources in this page. | ItemsPerPage 是本页资源数。
	ItemsPerPage int `json:"itemsPerPage"`
}

// ErrorResponse is a non-2xx SCIM response. It unwraps to the matching sentinel so callers can use
// errors.Is. | ErrorResponse 是非 2xx SCIM 响应。它展开为匹配的哨兵，调用方可用 errors.Is 判定。
type ErrorResponse struct {
	// Status is the status rendered by the server. | Status 是服务端渲染的状态。
	Status string
	// ScimType is the RFC 7644 scimType. | ScimType 是 RFC 7644 scimType。
	ScimType string
	// Detail is the server-provided description. | Detail 是服务端提供的描述。
	Detail string
	// Schemas is the error message schema list. | Schemas 是错误消息 Schema 列表。
	Schemas []string
	// StatusCode is the HTTP status code. | StatusCode 是 HTTP 状态码。
	StatusCode int
}

// Error returns a safe description of the failed response. | Error 返回失败响应的安全描述。
func (e *ErrorResponse) Error() string {
	if e == nil {
		return "scim: request failed | scim：请求失败"
	}
	if e.Detail != "" {
		return e.Detail
	}
	sentinel := sentinelForStatus(e.StatusCode, e.ScimType)
	if sentinel != nil {
		return sentinel.Error()
	}
	return "scim: request failed | scim：请求失败"
}

// Unwrap returns the sentinel matching the status and scimType. | Unwrap 返回匹配状态与 scimType 的
// 哨兵。
func (e *ErrorResponse) Unwrap() error {
	if e == nil {
		return nil
	}
	return sentinelForStatus(e.StatusCode, e.ScimType)
}

// ListUsers returns one page of Users. | ListUsers 返回一页 User。
func (c *Client) ListUsers(ctx context.Context, options ListOptions) (*UserPage, error) {
	query := options.values()
	data, _, err := c.do(ctx, http.MethodGet, "/Users", query, nil, nil)
	if err != nil {
		return nil, err
	}
	var page UserPage
	if err := decodeClientJSON(data, &page); err != nil {
		return nil, err
	}
	return &page, nil
}

// SearchUsers runs a POST /Users/.search query. | SearchUsers 执行 POST /Users/.search 查询。
func (c *Client) SearchUsers(ctx context.Context, request SearchRequest) (*UserPage, error) {
	if len(request.Schemas) == 0 {
		request.Schemas = []string{SearchRequestSchema}
	}
	data, _, err := c.do(ctx, http.MethodPost, "/Users/.search", nil, request, nil)
	if err != nil {
		return nil, err
	}
	var page UserPage
	if err := decodeClientJSON(data, &page); err != nil {
		return nil, err
	}
	return &page, nil
}

// GetUser returns one User. | GetUser 返回一个 User。
func (c *Client) GetUser(ctx context.Context, id string, options ...RequestOption) (*User, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errs.Detail(ErrInvalidValue, "User id is required | User 标识为必需")
	}
	data, _, err := c.do(ctx, http.MethodGet, "/Users/"+url.PathEscape(id), nil, nil, options)
	if err != nil {
		return nil, err
	}
	var user User
	if err := decodeClientJSON(data, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

// CreateUser creates one User. | CreateUser 创建一个 User。
func (c *Client) CreateUser(ctx context.Context, user *User, options ...RequestOption) (*User, error) {
	if user == nil {
		return nil, errs.Detail(ErrInvalidValue, "nil User | User 为空")
	}
	data, _, err := c.do(ctx, http.MethodPost, "/Users", nil, user, options)
	if err != nil {
		return nil, err
	}
	var created User
	if err := decodeClientJSON(data, &created); err != nil {
		return nil, err
	}
	return &created, nil
}

// ReplaceUser replaces one User with PUT semantics. | ReplaceUser 以 PUT 语义替换一个 User。
func (c *Client) ReplaceUser(ctx context.Context, user *User, options ...RequestOption) (*User, error) {
	if user == nil || strings.TrimSpace(user.ID) == "" {
		return nil, errs.Detail(ErrInvalidValue, "User id is required | User 标识为必需")
	}
	data, _, err := c.do(ctx, http.MethodPut, "/Users/"+url.PathEscape(user.ID), nil, user, options)
	if err != nil {
		return nil, err
	}
	var updated User
	if err := decodeClientJSON(data, &updated); err != nil {
		return nil, err
	}
	return &updated, nil
}

// PatchUser applies PATCH operations to one User. | PatchUser 对一个 User 应用 PATCH 操作。
func (c *Client) PatchUser(ctx context.Context, id string, operations []PatchOperation, options ...RequestOption) (*User, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errs.Detail(ErrInvalidValue, "User id is required | User 标识为必需")
	}
	if len(operations) == 0 {
		return nil, errs.Detail(ErrInvalidValue, "PATCH requires at least one operation | PATCH 至少需要一个操作")
	}
	request := PatchRequest{Schemas: []string{PatchOpSchema}, Operations: operations}
	data, _, err := c.do(ctx, http.MethodPatch, "/Users/"+url.PathEscape(id), nil, request, options)
	if err != nil {
		return nil, err
	}
	var patched User
	if err := decodeClientJSON(data, &patched); err != nil {
		return nil, err
	}
	return &patched, nil
}

// DeleteUser removes one User. | DeleteUser 移除一个 User。
func (c *Client) DeleteUser(ctx context.Context, id string, options ...RequestOption) error {
	if strings.TrimSpace(id) == "" {
		return errs.Detail(ErrInvalidValue, "User id is required | User 标识为必需")
	}
	_, _, err := c.do(ctx, http.MethodDelete, "/Users/"+url.PathEscape(id), nil, nil, options)
	return err
}

// ListGroups returns one page of Groups. | ListGroups 返回一页 Group。
func (c *Client) ListGroups(ctx context.Context, options ListOptions) (*GroupPage, error) {
	query := options.values()
	data, _, err := c.do(ctx, http.MethodGet, "/Groups", query, nil, nil)
	if err != nil {
		return nil, err
	}
	var page GroupPage
	if err := decodeClientJSON(data, &page); err != nil {
		return nil, err
	}
	return &page, nil
}

// SearchGroups runs a POST /Groups/.search query. | SearchGroups 执行 POST /Groups/.search 查询。
func (c *Client) SearchGroups(ctx context.Context, request SearchRequest) (*GroupPage, error) {
	if len(request.Schemas) == 0 {
		request.Schemas = []string{SearchRequestSchema}
	}
	data, _, err := c.do(ctx, http.MethodPost, "/Groups/.search", nil, request, nil)
	if err != nil {
		return nil, err
	}
	var page GroupPage
	if err := decodeClientJSON(data, &page); err != nil {
		return nil, err
	}
	return &page, nil
}

// GetGroup returns one Group. | GetGroup 返回一个 Group。
func (c *Client) GetGroup(ctx context.Context, id string, options ...RequestOption) (*Group, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errs.Detail(ErrInvalidValue, "Group id is required | Group 标识为必需")
	}
	data, _, err := c.do(ctx, http.MethodGet, "/Groups/"+url.PathEscape(id), nil, nil, options)
	if err != nil {
		return nil, err
	}
	var group Group
	if err := decodeClientJSON(data, &group); err != nil {
		return nil, err
	}
	return &group, nil
}

// CreateGroup creates one Group. | CreateGroup 创建一个 Group。
func (c *Client) CreateGroup(ctx context.Context, group *Group, options ...RequestOption) (*Group, error) {
	if group == nil {
		return nil, errs.Detail(ErrInvalidValue, "nil Group | Group 为空")
	}
	data, _, err := c.do(ctx, http.MethodPost, "/Groups", nil, group, options)
	if err != nil {
		return nil, err
	}
	var created Group
	if err := decodeClientJSON(data, &created); err != nil {
		return nil, err
	}
	return &created, nil
}

// ReplaceGroup replaces one Group with PUT semantics. | ReplaceGroup 以 PUT 语义替换一个 Group。
func (c *Client) ReplaceGroup(ctx context.Context, group *Group, options ...RequestOption) (*Group, error) {
	if group == nil || strings.TrimSpace(group.ID) == "" {
		return nil, errs.Detail(ErrInvalidValue, "Group id is required | Group 标识为必需")
	}
	data, _, err := c.do(ctx, http.MethodPut, "/Groups/"+url.PathEscape(group.ID), nil, group, options)
	if err != nil {
		return nil, err
	}
	var updated Group
	if err := decodeClientJSON(data, &updated); err != nil {
		return nil, err
	}
	return &updated, nil
}

// PatchGroup applies PATCH operations to one Group. | PatchGroup 对一个 Group 应用 PATCH 操作。
func (c *Client) PatchGroup(ctx context.Context, id string, operations []PatchOperation, options ...RequestOption) (*Group, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errs.Detail(ErrInvalidValue, "Group id is required | Group 标识为必需")
	}
	if len(operations) == 0 {
		return nil, errs.Detail(ErrInvalidValue, "PATCH requires at least one operation | PATCH 至少需要一个操作")
	}
	request := PatchRequest{Schemas: []string{PatchOpSchema}, Operations: operations}
	data, _, err := c.do(ctx, http.MethodPatch, "/Groups/"+url.PathEscape(id), nil, request, options)
	if err != nil {
		return nil, err
	}
	var patched Group
	if err := decodeClientJSON(data, &patched); err != nil {
		return nil, err
	}
	return &patched, nil
}

// DeleteGroup removes one Group. | DeleteGroup 移除一个 Group。
func (c *Client) DeleteGroup(ctx context.Context, id string, options ...RequestOption) error {
	if strings.TrimSpace(id) == "" {
		return errs.Detail(ErrInvalidValue, "Group id is required | Group 标识为必需")
	}
	_, _, err := c.do(ctx, http.MethodDelete, "/Groups/"+url.PathEscape(id), nil, nil, options)
	return err
}

// maxClientResponseSize bounds how much of a SCIM response the client buffers. |
// maxClientResponseSize 限制客户端缓冲的 SCIM 响应大小。
const maxClientResponseSize = 16 << 20

// do performs one SCIM request. | do 执行一次 SCIM 请求。
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any, options []RequestOption) ([]byte, int, error) {
	if c == nil || c.httpClient == nil {
		return nil, 0, errs.Detail(ErrInvalidConfig, "client is not initialized | 客户端未初始化")
	}
	endpoint := c.baseURL + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		data, err := ydxjson.Marshal(body)
		if err != nil {
			return nil, 0, errs.Detail(ErrInvalidValue, "cannot encode request body | 无法编码请求体")
		}
		reader = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, 0, errs.Detail(ErrInvalidConfig, "cannot build request | 无法构建请求")
	}
	request.Header.Set("Accept", ContentType+", "+ContentTypeJSON)
	if body != nil {
		request.Header.Set("Content-Type", ContentType)
	}
	if c.userAgent != "" {
		request.Header.Set("User-Agent", c.userAgent)
	}
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	} else if c.username != "" || c.password != "" {
		request.SetBasicAuth(c.username, c.password)
	}
	headers := requestHeaders{}
	for _, option := range options {
		if option != nil {
			option(&headers)
		}
	}
	if headers.ifMatch != "" {
		request.Header.Set("If-Match", headers.ifMatch)
	}
	if headers.ifNoneMatch != "" {
		request.Header.Set("If-None-Match", headers.ifNoneMatch)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, 0, errs.WrapDetail(err, ErrStoreUnavailable, "scim request failed | scim 请求失败")
	}
	defer func() {
		_ = response.Body.Close()
	}()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxClientResponseSize+1))
	if err != nil {
		return nil, response.StatusCode, errs.WrapDetail(err, ErrStoreUnavailable, "cannot read SCIM response | 无法读取 SCIM 响应")
	}
	if len(data) > maxClientResponseSize {
		return nil, response.StatusCode, errs.Detail(ErrInvalidSyntax,
			"SCIM response exceeds %d bytes | SCIM 响应超过 %d 字节", maxClientResponseSize, maxClientResponseSize)
	}
	if response.StatusCode == http.StatusNotModified {
		return data, response.StatusCode, ErrNotModified
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return data, response.StatusCode, clientError(response.StatusCode, data)
	}
	return data, response.StatusCode, nil
}

// clientError builds an ErrorResponse from a failed response body. | clientError 从失败响应体构建
// ErrorResponse。
func clientError(status int, data []byte) error {
	failure := &ErrorResponse{StatusCode: status}
	var body Error
	if err := ydxjson.Unmarshal(data, &body); err == nil {
		failure.Schemas = body.Schemas
		failure.Status = body.Status
		failure.ScimType = body.ScimType
		failure.Detail = body.Detail
	}
	return failure
}

// decodeClientJSON decodes a SCIM response body. | decodeClientJSON 解码 SCIM 响应体。
func decodeClientJSON(data []byte, target any) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return errs.Detail(ErrInvalidSyntax, "empty SCIM response | 空 SCIM 响应")
	}
	if err := ydxjson.Unmarshal(data, target); err != nil {
		return errs.Detail(ErrInvalidSyntax, "invalid SCIM response | 非法 SCIM 响应")
	}
	return nil
}

// Iterator walks a paginated SCIM collection one resource at a time. | Iterator 逐个遍历分页 SCIM
// 集合。
type Iterator[T any] struct {
	// ctx is the request context. | ctx 是请求上下文。
	ctx context.Context
	// failure is the first iterator error. | failure 是首个迭代错误。
	failure error
	// fetch loads one page. | fetch 加载一页。
	fetch func(context.Context, ListOptions) ([]*T, int, error)
	// buffer holds the current page. | buffer 保存当前页。
	buffer []*T
	// options is the base query. | options 是基础查询。
	options ListOptions
	// index is the next buffer position. | index 是下一个缓冲区位置。
	index int
	// startIndex is the next page start. | startIndex 是下一页起点。
	startIndex int
	// total is the last reported total. | total 是最后报告的总数。
	total int
	// exhausted reports that no further pages exist. | exhausted 表示不存在更多页。
	exhausted bool
}

// newIterator creates an iterator over a paged collection. | newIterator 创建分页集合的迭代器。
func newIterator[T any](ctx context.Context, options ListOptions, fetch func(context.Context, ListOptions) ([]*T, int, error)) *Iterator[T] {
	if ctx == nil {
		ctx = context.Background()
	}
	if options.StartIndex <= 0 {
		options.StartIndex = 1
	}
	return &Iterator[T]{ctx: ctx, options: options, fetch: fetch, startIndex: options.StartIndex}
}

// Next returns the next resource, false at the end, or an error. | Next 返回下一个资源，结束时返回
// false，或返回错误。
func (it *Iterator[T]) Next() (*T, bool, error) {
	if it == nil {
		return nil, false, nil
	}
	if it.failure != nil {
		return nil, false, it.failure
	}
	for {
		if it.index < len(it.buffer) {
			item := it.buffer[it.index]
			it.index++
			return item, true, nil
		}
		if it.exhausted {
			return nil, false, nil
		}
		options := it.options
		options.StartIndex = it.startIndex
		if options.Count == 0 {
			options.Count = DefaultMaxResults
		}
		items, total, err := it.fetch(it.ctx, options)
		if err != nil {
			it.failure = err
			return nil, false, err
		}
		it.total = total
		if len(items) == 0 {
			it.exhausted = true
			return nil, false, nil
		}
		it.buffer = items
		it.index = 0
		it.startIndex += len(items)
		if it.startIndex > it.total {
			it.exhausted = true
		}
	}
}

// TotalResults returns the total reported by the most recent page. | TotalResults 返回最近一页报告
// 的总数。
func (it *Iterator[T]) TotalResults() int {
	if it == nil {
		return 0
	}
	return it.total
}

// IterateUsers returns an iterator over Users matching options. | IterateUsers 返回遍历匹配 options
// 的 User 的迭代器。
func (c *Client) IterateUsers(ctx context.Context, options ListOptions) *Iterator[User] {
	options.Count = iteratorPageSize(options.Count)
	return newIterator(ctx, options, func(ctx context.Context, page ListOptions) ([]*User, int, error) {
		result, err := c.ListUsers(ctx, page)
		if err != nil {
			return nil, 0, err
		}
		return result.Resources, result.TotalResults, nil
	})
}

// IterateGroups returns an iterator over Groups matching options. | IterateGroups 返回遍历匹配
// options 的 Group 的迭代器。
func (c *Client) IterateGroups(ctx context.Context, options ListOptions) *Iterator[Group] {
	options.Count = iteratorPageSize(options.Count)
	return newIterator(ctx, options, func(ctx context.Context, page ListOptions) ([]*Group, int, error) {
		result, err := c.ListGroups(ctx, page)
		if err != nil {
			return nil, 0, err
		}
		return result.Resources, result.TotalResults, nil
	})
}

// iteratorPageSize normalizes an iterator page size. | iteratorPageSize 规范化迭代器分页大小。
func iteratorPageSize(count int) int {
	if count <= 0 || count > DefaultMaxResults {
		return DefaultMaxResults
	}
	return count
}
