package scim

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"

	"github.com/shibingli/ydx/errs"
	ydxjson "github.com/shibingli/ydx/json"
)

// BulkRequest is the RFC 7644 section 3.7 bulk request body. | BulkRequest 是 RFC 7644 第 3.7 节的
// 批量请求体。
//
// By default operations run sequentially and are not transactional: each operation commits
// independently, a failed operation is reported in place, and later failures never roll back
// resources created or changed by earlier operations. A single operation can also fail after the
// store committed a change, for example when a password hook rejects the write; the server
// compensates only that operation by restoring its own prior profile, while earlier operations stay
// committed. FailOnErrors only stops processing subsequent operations. When the server
// enables Options.BulkAtomic, the request becomes transactional instead: the first failure rolls
// back every applied operation in reverse order, removes their bulkId mappings, and FailOnErrors is
// ignored. | 默认情况下操作按顺序执行且不具备事务性：每个操作独立提交，失败的操作就地报告，后续失败
// 绝不会回滚先前操作创建或修改的资源。单个操作也可能在存储已提交变更后失败，例如口令钩子拒绝写入；
// 服务端只补偿该操作并恢复它自己的先前资料，更早的操作保持已提交。FailOnErrors 只会停止处理后续
// 操作。服务端启用 Options.BulkAtomic 后请求转为事务性：首次失败会按逆序回滚所有已应用操作、移除
// 其 bulkId 映射，并忽略 FailOnErrors。
type BulkRequest struct {
	// Schemas is the message schema list; BulkRequestSchema is required by the RFC. | Schemas 是消息
	// Schema 列表；RFC 要求包含 BulkRequestSchema。
	Schemas []string `json:"schemas,omitempty"`
	// Operations is the ordered list of bulk operations. | Operations 是有序的批量操作列表。
	Operations []BulkOperation `json:"Operations"`
	// FailOnErrors stops processing after this many failed operations; zero never stops and
	// negative values are rejected. | FailOnErrors 在累计该数量失败操作后停止处理；零表示不停止，
	// 负数会被拒绝。
	FailOnErrors int `json:"failOnErrors,omitempty"`
}

// BulkOperation is one operation inside a BulkRequest. | BulkOperation 是 BulkRequest 中的一个操作。
type BulkOperation struct {
	// BulkID is an optional request-scoped identifier. Later operations may reference it with the
	// exact string value "bulkId:<id>"; substrings inside larger strings are never rewritten.
	// BulkIDs are unique per request and are only resolvable after the defining operation
	// succeeds. | BulkID 是可选的请求内标识。后续操作可用恰好等于 "bulkId:<id>" 的字符串值引用它；
	// 更长字符串中的子串绝不会被改写。BulkID 在单次请求内唯一，且只有在定义它的操作成功后才能解析。
	BulkID string `json:"bulkId,omitempty"`
	// Method is the HTTP method: POST, PUT, PATCH or DELETE. | Method 是 HTTP 方法：POST、PUT、
	// PATCH 或 DELETE。
	Method string `json:"method"`
	// Path is the resource endpoint, for example "/Users/1234". | Path 是资源端点，例如
	// "/Users/1234"。
	Path string `json:"path"`
	// Data is the operation payload for POST, PUT and PATCH. | Data 是 POST、PUT 与 PATCH 的操作
	// 负载。
	Data any `json:"data,omitempty"`
	// Version is an optional entity tag used as an If-Match precondition. | Version 是可选的实体
	// 标签，用作 If-Match 前置条件。
	Version string `json:"version,omitempty"`
}

// BulkResponse is the RFC 7644 section 3.7 bulk response body. | BulkResponse 是 RFC 7644 第 3.7 节
// 的批量响应体。
type BulkResponse struct {
	// Schemas is the message schema list. | Schemas 是消息 Schema 列表。
	Schemas []string `json:"schemas"`
	// Operations holds one result per processed operation. | Operations 保存每个已处理操作的结果。
	Operations []BulkResponseOperation `json:"Operations"`
}

// BulkResponseOperation is the result of one BulkOperation. | BulkResponseOperation 是一个
// BulkOperation 的结果。
type BulkResponseOperation struct {
	// BulkID echoes the request bulk identifier. | BulkID 回显请求的批量标识。
	BulkID string `json:"bulkId,omitempty"`
	// Method echoes the request method. | Method 回显请求方法。
	Method string `json:"method,omitempty"`
	// Version is the entity tag of a created or replaced resource. | Version 是创建或替换资源的实体
	// 标签。
	Version string `json:"version,omitempty"`
	// Location is the absolute URL of a created resource. | Location 是已创建资源的绝对 URL。
	Location string `json:"location,omitempty"`
	// Response is the resource body or an Error object. | Response 是资源体或 Error 对象。
	Response any `json:"response,omitempty"`
	// Status is the HTTP status code rendered as a string. | Status 是渲染为字符串的 HTTP 状态码。
	Status string `json:"status"`
}

// handleBulk serves POST /Bulk. Operations are processed in request order. In the default
// non-transactional mode there is no rollback and bulkId mappings are recorded only when the
// defining operation succeeds; atomic mode delegates to handleBulkAtomic. | handleBulk 提供
// POST /Bulk。操作按请求顺序处理。默认非事务模式下不回滚，bulkId 映射仅在定义它的操作成功时记录；
// 原子模式委托给 handleBulkAtomic。
func (s *Server) handleBulk(w http.ResponseWriter, r *http.Request) {
	if err := s.authorize(r, ActionCreate, ResourceBulk); err != nil {
		writeError(w, err)
		return
	}
	if !s.requireWriteContentType(w, r) {
		return
	}
	request, err := s.decodeBulkRequest(r)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := validateBulkIDs(request.Operations); err != nil {
		writeError(w, err)
		return
	}
	if s.bulkAtomic {
		s.handleBulkAtomic(w, r, request)
		return
	}
	ids := make(map[string]string, len(request.Operations))
	results := make([]BulkResponseOperation, 0, len(request.Operations))
	failures := 0
	for _, operation := range request.Operations {
		result, _ := s.runBulkOperation(r, operation, ids, nil)
		results = append(results, result)
		if isFailureStatus(result.Status) {
			failures++
			if request.FailOnErrors > 0 && failures >= request.FailOnErrors {
				break
			}
		}
	}
	writeSCIM(w, http.StatusOK, BulkResponse{
		Schemas:    []string{BulkResponseSchema},
		Operations: results,
	})
}

// decodeBulkRequest reads and validates a bulk request within the configured limits. |
// decodeBulkRequest 在配置限制内读取并校验批量请求。
func (s *Server) decodeBulkRequest(r *http.Request) (*BulkRequest, error) {
	if r == nil || r.Body == nil {
		return nil, errs.Detail(ErrInvalidSyntax, "missing request body | 缺少请求体")
	}
	// Read one byte past the limit so oversize bodies are distinguishable from bodies that
	// exactly hit the limit; saturate instead of overflowing when the limit is MaxInt64. | 多读一
	// 字节以区分超限与恰好达到上限；上限为 MaxInt64 时饱和而非溢出。
	limit := s.bulkMaxPayloadSize
	if limit < math.MaxInt64 {
		limit++
	}
	reader := io.LimitReader(r.Body, limit)
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, errs.Detail(ErrInvalidSyntax, "cannot read request body | 无法读取请求体")
	}
	if int64(len(data)) > s.bulkMaxPayloadSize {
		return nil, errs.Detail(ErrTooMany, "bulk payload exceeds %d bytes | 批量负载超过 %d 字节",
			s.bulkMaxPayloadSize, s.bulkMaxPayloadSize)
	}
	var request BulkRequest
	if err := ydxjson.Unmarshal(data, &request); err != nil {
		return nil, errs.Detail(ErrInvalidSyntax, "invalid JSON body | JSON 请求体非法")
	}
	if len(request.Schemas) > 0 && !containsFold(request.Schemas, BulkRequestSchema) {
		return nil, errs.Detail(ErrInvalidSyntax, "bulk schemas must include BulkRequest | bulk schemas 必须包含 BulkRequest")
	}
	if len(request.Operations) == 0 {
		return nil, errs.Detail(ErrInvalidSyntax, "bulk requires at least one operation | 批量至少需要一个操作")
	}
	if len(request.Operations) > s.bulkMaxOperations {
		return nil, errs.Detail(ErrTooMany, "bulk operations exceed %d | 批量操作超过 %d",
			s.bulkMaxOperations, s.bulkMaxOperations)
	}
	if request.FailOnErrors < 0 {
		return nil, errs.Detail(ErrInvalidValue, "failOnErrors must not be negative | failOnErrors 不得为负数")
	}
	return &request, nil
}

// validateBulkIDs rejects duplicate non-empty bulkId definitions before any operation runs. |
// validateBulkIDs 在任何操作执行前拒绝重复的非空 bulkId 定义。
func validateBulkIDs(operations []BulkOperation) error {
	seen := make(map[string]struct{}, len(operations))
	for _, operation := range operations {
		if operation.BulkID == "" {
			continue
		}
		if _, exists := seen[operation.BulkID]; exists {
			return errs.Detail(ErrBulkIDDuplicate, "duplicate bulkId %q | 重复 bulkId %q",
				operation.BulkID, operation.BulkID)
		}
		seen[operation.BulkID] = struct{}{}
	}
	return nil
}

// runBulkOperation executes one bulk operation and converts any failure into a response entry. The
// returned error carries the same failure for the atomic rollback path; non-atomic callers ignore
// it. | runBulkOperation 执行一个批量操作，并把任何失败转换为响应条目。返回的错误为原子回滚路径
// 携带同一失败；非事务调用方会忽略它。
func (s *Server) runBulkOperation(r *http.Request, operation BulkOperation, ids map[string]string, undo *bulkUndoLog) (BulkResponseOperation, error) {
	response := BulkResponseOperation{
		BulkID: operation.BulkID,
		Method: strings.ToUpper(strings.TrimSpace(operation.Method)),
	}
	if response.Method == "" {
		return bulkFailure(response, errs.Detail(ErrInvalidSyntax, "missing method | 缺少方法"))
	}
	action, err := bulkAction(response.Method)
	if err != nil {
		return bulkFailure(response, err)
	}
	if err := s.authorize(r, action, ResourceBulk); err != nil {
		return bulkFailure(response, err)
	}
	path, err := resolveBulkPathReferences(operation.Path, ids)
	if err != nil {
		return bulkFailure(response, err)
	}
	resource, id, err := parseBulkPath(path)
	if err != nil {
		return bulkFailure(response, err)
	}
	version := substituteBulkIDs(operation.Version, ids)
	ctx := r.Context()
	switch resource {
	case ResourceTypeNameUser:
		return s.runBulkUser(ctx, r, response, id, version, operation.Data, ids, undo)
	case ResourceTypeNameGroup:
		return s.runBulkGroup(ctx, r, response, id, version, operation.Data, ids, undo)
	default:
		return bulkFailure(response, errs.Detail(ErrInvalidPath, "unsupported bulk path | 不支持的批量路径"))
	}
}

// bulkFailure pairs a failed response entry with its originating error. | bulkFailure 把失败的响应
// 条目与其来源错误配对。
func bulkFailure(response BulkResponseOperation, err error) (BulkResponseOperation, error) {
	return bulkErrorResult(response, err), err
}

// bulkAction maps a bulk HTTP method onto an authorization action. | bulkAction 把批量 HTTP 方法
// 映射为授权动作。
func bulkAction(method string) (string, error) {
	switch method {
	case http.MethodPost:
		return ActionCreate, nil
	case http.MethodPut, http.MethodPatch:
		return ActionUpdate, nil
	case http.MethodDelete:
		return ActionDelete, nil
	default:
		return "", errs.Detail(ErrInvalidSyntax, "unsupported method %q | 不支持的方法 %q", method, method)
	}
}

// runBulkUser executes a user bulk operation. | runBulkUser 执行用户批量操作。
func (s *Server) runBulkUser(ctx context.Context, r *http.Request, response BulkResponseOperation, id, version string, data any, ids map[string]string, undo *bulkUndoLog) (BulkResponseOperation, error) {
	switch response.Method {
	case http.MethodPost:
		if id != "" {
			return bulkFailure(response, errs.Detail(ErrInvalidPath, "POST requires a collection path | POST 需要集合路径"))
		}
		var user User
		if err := decodeBulkData(data, ids, &user); err != nil {
			return bulkFailure(response, err)
		}
		created, err := s.createUser(ctx, &user, user.Password, undo, response.BulkID)
		if err != nil {
			return bulkFailure(response, err)
		}
		return s.bulkResourceResult(response, r, ids, http.StatusCreated, created.ID, userVersion(created), created), nil
	case http.MethodPut:
		if id == "" {
			return bulkFailure(response, errs.Detail(ErrInvalidPath, "PUT requires a resource path | PUT 需要资源路径"))
		}
		existing, err := s.store.GetUser(ctx, id)
		if err != nil {
			return bulkFailure(response, err)
		}
		if err := bulkVersionCheck(version, userVersion(existing)); err != nil {
			return bulkFailure(response, err)
		}
		var incoming User
		if err := decodeBulkData(data, ids, &incoming); err != nil {
			return bulkFailure(response, err)
		}
		handle, err := undo.prepareUserRestore(existing, response.BulkID)
		if err != nil {
			return bulkFailure(response, err)
		}
		updated, err := s.replaceUser(ctx, existing, &incoming, incoming.Password, handle)
		if err != nil {
			return bulkFailure(response, err)
		}
		return s.bulkResourceResult(response, r, ids, http.StatusOK, updated.ID, userVersion(updated), updated), nil
	case http.MethodPatch:
		if id == "" {
			return bulkFailure(response, errs.Detail(ErrInvalidPath, "PATCH requires a resource path | PATCH 需要资源路径"))
		}
		existing, err := s.store.GetUser(ctx, id)
		if err != nil {
			return bulkFailure(response, err)
		}
		if err := bulkVersionCheck(version, userVersion(existing)); err != nil {
			return bulkFailure(response, err)
		}
		var request PatchRequest
		if err := decodeBulkData(data, ids, &request); err != nil {
			return bulkFailure(response, err)
		}
		if err := validatePatchRequest(&request); err != nil {
			return bulkFailure(response, err)
		}
		patched, err := ApplyUserPatch(existing, request.Operations)
		if err != nil {
			return bulkFailure(response, err)
		}
		password := patched.Password
		patched.Password = ""
		patched.ID = existing.ID
		patched.Meta = nil
		handle, err := undo.prepareUserRestore(existing, response.BulkID)
		if err != nil {
			return bulkFailure(response, err)
		}
		stored, err := s.replaceUser(ctx, existing, patched, password, handle)
		if err != nil {
			return bulkFailure(response, err)
		}
		return s.bulkResourceResult(response, r, ids, http.StatusOK, stored.ID, userVersion(stored), stored), nil
	case http.MethodDelete:
		if id == "" {
			return bulkFailure(response, errs.Detail(ErrInvalidPath, "DELETE requires a resource path | DELETE 需要资源路径"))
		}
		existing, err := s.store.GetUser(ctx, id)
		if err != nil {
			return bulkFailure(response, err)
		}
		if err := bulkVersionCheck(version, userVersion(existing)); err != nil {
			return bulkFailure(response, err)
		}
		handle, err := undo.prepareUserRecreate(existing, response.BulkID)
		if err != nil {
			return bulkFailure(response, err)
		}
		if err := s.store.DeleteUser(ctx, id); err != nil {
			return bulkFailure(response, err)
		}
		handle.markApplied("")
		response.Status = intString(http.StatusNoContent)
		return response, nil
	default:
		return bulkFailure(response, errs.Detail(ErrInvalidSyntax, "unsupported method %q | 不支持的方法 %q",
			response.Method, response.Method))
	}
}

// runBulkGroup executes a group bulk operation. | runBulkGroup 执行组批量操作。
func (s *Server) runBulkGroup(ctx context.Context, r *http.Request, response BulkResponseOperation, id, version string, data any, ids map[string]string, undo *bulkUndoLog) (BulkResponseOperation, error) {
	switch response.Method {
	case http.MethodPost:
		if id != "" {
			return bulkFailure(response, errs.Detail(ErrInvalidPath, "POST requires a collection path | POST 需要集合路径"))
		}
		var group Group
		if err := decodeBulkData(data, ids, &group); err != nil {
			return bulkFailure(response, err)
		}
		group.ID = ""
		group.Meta = nil
		created, err := s.store.CreateGroup(ctx, &group)
		if err != nil {
			return bulkFailure(response, err)
		}
		if undo != nil {
			if err := undo.recordCreatedGroup(created, response.BulkID); err != nil {
				if deleteErr := s.store.DeleteGroup(ctx, created.ID); deleteErr != nil {
					return bulkFailure(response, errs.WrapDetail(errors.Join(err, deleteErr), ErrBulkRollbackFailed,
						"cannot record undo entry and cannot remove created Group | 无法记录撤销条目且无法删除已创建 Group"))
				}
				return bulkFailure(response, err)
			}
		}
		return s.bulkResourceResult(response, r, ids, http.StatusCreated, created.ID, groupVersion(created), created), nil
	case http.MethodPut:
		if id == "" {
			return bulkFailure(response, errs.Detail(ErrInvalidPath, "PUT requires a resource path | PUT 需要资源路径"))
		}
		existing, err := s.store.GetGroup(ctx, id)
		if err != nil {
			return bulkFailure(response, err)
		}
		if err := bulkVersionCheck(version, groupVersion(existing)); err != nil {
			return bulkFailure(response, err)
		}
		var incoming Group
		if err := decodeBulkData(data, ids, &incoming); err != nil {
			return bulkFailure(response, err)
		}
		incoming.ID = existing.ID
		incoming.Meta = nil
		handle, err := undo.prepareGroupRestore(existing, response.BulkID)
		if err != nil {
			return bulkFailure(response, err)
		}
		updated, err := s.store.ReplaceGroup(ctx, &incoming)
		if err != nil {
			return bulkFailure(response, err)
		}
		handle.markApplied(groupVersion(updated))
		return s.bulkResourceResult(response, r, ids, http.StatusOK, updated.ID, groupVersion(updated), updated), nil
	case http.MethodPatch:
		if id == "" {
			return bulkFailure(response, errs.Detail(ErrInvalidPath, "PATCH requires a resource path | PATCH 需要资源路径"))
		}
		existing, err := s.store.GetGroup(ctx, id)
		if err != nil {
			return bulkFailure(response, err)
		}
		if err := bulkVersionCheck(version, groupVersion(existing)); err != nil {
			return bulkFailure(response, err)
		}
		var request PatchRequest
		if err := decodeBulkData(data, ids, &request); err != nil {
			return bulkFailure(response, err)
		}
		if err := validatePatchRequest(&request); err != nil {
			return bulkFailure(response, err)
		}
		patched, err := ApplyGroupPatch(existing, request.Operations)
		if err != nil {
			return bulkFailure(response, err)
		}
		patched.ID = existing.ID
		patched.Meta = nil
		handle, err := undo.prepareGroupRestore(existing, response.BulkID)
		if err != nil {
			return bulkFailure(response, err)
		}
		updated, err := s.store.ReplaceGroup(ctx, patched)
		if err != nil {
			return bulkFailure(response, err)
		}
		handle.markApplied(groupVersion(updated))
		return s.bulkResourceResult(response, r, ids, http.StatusOK, updated.ID, groupVersion(updated), updated), nil
	case http.MethodDelete:
		if id == "" {
			return bulkFailure(response, errs.Detail(ErrInvalidPath, "DELETE requires a resource path | DELETE 需要资源路径"))
		}
		existing, err := s.store.GetGroup(ctx, id)
		if err != nil {
			return bulkFailure(response, err)
		}
		if err := bulkVersionCheck(version, groupVersion(existing)); err != nil {
			return bulkFailure(response, err)
		}
		handle, err := undo.prepareGroupRecreate(existing, response.BulkID)
		if err != nil {
			return bulkFailure(response, err)
		}
		if err := s.store.DeleteGroup(ctx, id); err != nil {
			return bulkFailure(response, err)
		}
		handle.markApplied("")
		response.Status = intString(http.StatusNoContent)
		return response, nil
	default:
		return bulkFailure(response, errs.Detail(ErrInvalidSyntax, "unsupported method %q | 不支持的方法 %q",
			response.Method, response.Method))
	}
}

// bulkResourceResult records the identifier of a created or replaced resource and builds the
// response entry. | bulkResourceResult 记录已创建或替换资源的标识并构建响应条目。
func (s *Server) bulkResourceResult(response BulkResponseOperation, r *http.Request, ids map[string]string, status int, id, version string, resource any) BulkResponseOperation {
	if ids != nil && response.BulkID != "" && id != "" {
		ids[response.BulkID] = id
	}
	response.Status = intString(status)
	response.Version = version
	if status == http.StatusCreated {
		switch typed := resource.(type) {
		case *User:
			response.Location = s.userLocation(r, typed.ID)
		case *Group:
			response.Location = s.groupLocation(r, typed.ID)
		}
	}
	response.Response = resource
	return response
}

// bulkErrorResult converts err into a failed BulkResponseOperation. | bulkErrorResult 把 err 转换为
// 失败的 BulkResponseOperation。
func bulkErrorResult(response BulkResponseOperation, err error) BulkResponseOperation {
	info := classifyError(err)
	status := info.status
	if status < 400 {
		status = http.StatusBadRequest
	}
	response.Status = intString(status)
	response.Response = Error{
		Schemas:  []string{ErrorSchema},
		Status:   intString(status),
		ScimType: info.scimType,
		Detail:   errorDetail(err, status),
	}
	return response
}

// isFailureStatus reports whether an HTTP status string represents a failure. | isFailureStatus
// 报告 HTTP 状态字符串是否表示失败。
func isFailureStatus(status string) bool {
	if len(status) == 0 {
		return false
	}
	first := status[0]
	return first >= '4' && first <= '5'
}

// bulkVersionCheck evaluates an optional bulk entity tag precondition. | bulkVersionCheck 评估可选的
// 批量实体标签前置条件。
func bulkVersionCheck(version, current string) error {
	if strings.TrimSpace(version) == "" {
		return nil
	}
	if !etagListMatches(version, current) {
		return errs.Detail(ErrInvalidVersion, "bulk version does not match current version | 批量版本与当前版本不匹配")
	}
	return nil
}

// parseBulkPath extracts the resource type and optional identifier from a bulk path. | parseBulkPath
// 从批量路径提取资源类型与可选标识。
func parseBulkPath(path string) (string, string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", "", errs.Detail(ErrInvalidPath, "missing bulk path | 缺少批量路径")
	}
	if parsed, err := url.Parse(path); err == nil && parsed.Path != "" {
		path = parsed.Path
	}
	segments := splitRequestPath(path)
	if len(segments) == 0 || len(segments) > 2 {
		return "", "", errs.Detail(ErrInvalidPath, "invalid bulk path | 非法批量路径")
	}
	resource := ""
	switch strings.ToLower(segments[0]) {
	case "users":
		resource = ResourceTypeNameUser
	case "groups":
		resource = ResourceTypeNameGroup
	default:
		return "", "", errs.Detail(ErrInvalidPath, "unsupported bulk path %q | 不支持的批量路径 %q", path, path)
	}
	id := ""
	if len(segments) == 2 {
		id = segments[1]
	}
	return resource, id, nil
}
