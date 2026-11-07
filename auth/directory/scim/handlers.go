package scim

import (
	"context"
	"errors"
	"net/http"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
)

// handleListUsers serves GET /Users. | handleListUsers 提供 GET /Users。
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if err := s.authorize(r, ActionRead, ResourceTypeNameUser); err != nil {
		writeError(w, err)
		return
	}
	params, err := s.parseListParams(r)
	if err != nil {
		writeError(w, err)
		return
	}
	s.writeUserList(w, r, params)
}

// handleSearchUsers serves POST /Users/.search. | handleSearchUsers 提供 POST /Users/.search。
func (s *Server) handleSearchUsers(w http.ResponseWriter, r *http.Request) {
	if err := s.authorize(r, ActionRead, ResourceTypeNameUser); err != nil {
		writeError(w, err)
		return
	}
	var request SearchRequest
	if err := decodeBody(r, &request); err != nil {
		writeError(w, err)
		return
	}
	params, err := s.searchParams(request)
	if err != nil {
		writeError(w, err)
		return
	}
	s.writeUserList(w, r, params)
}

// writeUserList runs the query and writes a ListResponse. | writeUserList 执行查询并写出
// ListResponse。
func (s *Server) writeUserList(w http.ResponseWriter, r *http.Request, params listParams) {
	users, total, err := s.store.ListUsers(r.Context(), ListQuery{
		Filter:     params.filter,
		SortBy:     params.sortBy,
		SortOrder:  params.sortOrder,
		StartIndex: params.startIndex,
		Count:      params.count,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	resources := make([]any, 0, len(users))
	for _, user := range users {
		projected, err := projectResource(s.prepareUser(r, user), params.attributes, params.excluded)
		if err != nil {
			writeError(w, err)
			return
		}
		resources = append(resources, projected)
	}
	writeSCIM(w, http.StatusOK, ListResponse{
		Schemas:      []string{ListResponseSchema},
		TotalResults: total,
		StartIndex:   params.startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	})
}

// handleGetUser serves GET /Users/{id}. | handleGetUser 提供 GET /Users/{id}。
func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.authorize(r, ActionRead, ResourceTypeNameUser); err != nil {
		writeError(w, err)
		return
	}
	user, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := checkPreconditions(r, userVersion(user), false); err != nil {
		if err == ErrNotModified || isNotModified(err) {
			setETag(w, userVersion(user))
			w.WriteHeader(http.StatusNotModified)
			return
		}
		writeError(w, err)
		return
	}
	attributes, excluded, err := parseAttributeSelection(r.URL.Query())
	if err != nil {
		writeError(w, err)
		return
	}
	s.respondUser(w, r, http.StatusOK, user, attributes, excluded)
}

// isNotModified reports whether err is ErrNotModified after wrapping. | isNotModified 报告 err 在
// 包装后是否为 ErrNotModified。
func isNotModified(err error) bool {
	return errors.Is(err, ErrNotModified)
}

// handleCreateUser serves POST /Users. | handleCreateUser 提供 POST /Users。
func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if err := s.authorize(r, ActionCreate, ResourceTypeNameUser); err != nil {
		writeError(w, err)
		return
	}
	var user User
	if err := decodeBody(r, &user); err != nil {
		writeError(w, err)
		return
	}
	password := user.Password
	attributes, excluded, err := parseAttributeSelection(r.URL.Query())
	if err != nil {
		writeError(w, err)
		return
	}
	created, err := s.createUser(r.Context(), &user, password, nil, "")
	if err != nil {
		writeError(w, err)
		return
	}
	s.respondUser(w, r, http.StatusCreated, created, attributes, excluded)
}

// createUser persists a new user and provisions its password. When undo is non-nil an atomic bulk
// request records a delete compensation before the password hook runs, so a rejected password
// still rolls the created resource back with the rest of the transaction. | createUser 持久化新用户
// 并预配口令。undo 非 nil 时，原子批量请求会在口令钩子运行前记录删除补偿，因此口令被拒绝时仍会连同
// 事务其余部分一起回滚已创建资源。
func (s *Server) createUser(ctx context.Context, user *User, password string, undo *bulkUndoLog, bulkID string) (*User, error) {
	if user == nil {
		return nil, errs.Detail(ErrInvalidValue, "nil User | User 为空")
	}
	if password != "" && s.passwordSetter == nil {
		return nil, errs.Detail(ErrNotConfigured, "password provisioning requires PasswordSetter | 口令预配需要 PasswordSetter")
	}
	incoming := user.Clone()
	incoming.ID = ""
	incoming.Meta = nil
	incoming.Groups = nil
	incoming.Password = ""
	created, err := s.store.CreateUser(ctx, incoming)
	if err != nil {
		return nil, err
	}
	if undo != nil {
		if err := undo.recordCreatedUser(created, bulkID); err != nil {
			if deleteErr := s.store.DeleteUser(ctx, created.ID); deleteErr != nil {
				return nil, errs.WrapDetail(errors.Join(err, deleteErr), ErrBulkRollbackFailed,
					"cannot record undo entry and cannot remove created User | 无法记录撤销条目且无法删除已创建 User")
			}
			return nil, err
		}
	}
	if err := s.setPassword(ctx, created, password); err != nil {
		if undo == nil {
			_ = s.store.DeleteUser(ctx, created.ID)
		}
		return nil, err
	}
	return created, nil
}

// handleReplaceUser serves PUT /Users/{id}. | handleReplaceUser 提供 PUT /Users/{id}。
func (s *Server) handleReplaceUser(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.authorize(r, ActionUpdate, ResourceTypeNameUser); err != nil {
		writeError(w, err)
		return
	}
	existing, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := checkPreconditions(r, userVersion(existing), true); err != nil {
		writeError(w, err)
		return
	}
	var incoming User
	if err := decodeBody(r, &incoming); err != nil {
		writeError(w, err)
		return
	}
	password := incoming.Password
	attributes, excluded, err := parseAttributeSelection(r.URL.Query())
	if err != nil {
		writeError(w, err)
		return
	}
	updated, err := s.replaceUser(r.Context(), existing, &incoming, password, nil)
	if err != nil {
		writeError(w, err)
		return
	}
	s.respondUser(w, r, http.StatusOK, updated, attributes, excluded)
}

// replaceUser replaces an existing user, preserving read-only membership and provisioning the
// password. The undo handle marks the recorded compensation applied as soon as the store commits,
// so a later password rejection still triggers a rollback in atomic bulk mode. | replaceUser 替换
// 已有用户，保留只读成员关系并预配口令。存储提交后 undo 句柄立即把已记录的补偿标记为已应用，因此
// 后续口令拒绝在原子批量模式下仍会触发回滚。
func (s *Server) replaceUser(ctx context.Context, existing, incoming *User, password string, undo *bulkUndoHandle) (*User, error) {
	if existing == nil || incoming == nil {
		return nil, errs.Detail(ErrInvalidValue, "nil User | User 为空")
	}
	if password != "" && s.passwordSetter == nil {
		return nil, errs.Detail(ErrNotConfigured, "password provisioning requires PasswordSetter | 口令预配需要 PasswordSetter")
	}
	replacement := incoming.Clone()
	replacement.ID = existing.ID
	replacement.Meta = nil
	replacement.Groups = existing.Clone().Groups
	replacement.Password = ""
	stored, err := s.store.ReplaceUser(ctx, replacement)
	if err != nil {
		return nil, err
	}
	undo.markApplied(userVersion(stored))
	if err := s.setPassword(ctx, stored, password); err != nil {
		return nil, err
	}
	return stored, nil
}

// handlePatchUser serves PATCH /Users/{id}. | handlePatchUser 提供 PATCH /Users/{id}。
func (s *Server) handlePatchUser(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.authorize(r, ActionUpdate, ResourceTypeNameUser); err != nil {
		writeError(w, err)
		return
	}
	existing, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := checkPreconditions(r, userVersion(existing), true); err != nil {
		writeError(w, err)
		return
	}
	var request PatchRequest
	if err := decodeBody(r, &request); err != nil {
		writeError(w, err)
		return
	}
	if err := validatePatchRequest(&request); err != nil {
		writeError(w, err)
		return
	}
	attributes, excluded, err := parseAttributeSelection(r.URL.Query())
	if err != nil {
		writeError(w, err)
		return
	}
	patched, err := ApplyUserPatch(existing, request.Operations)
	if err != nil {
		writeError(w, err)
		return
	}
	password := patched.Password
	patched.Password = ""
	patched.Groups = existing.Clone().Groups
	patched.ID = existing.ID
	patched.Meta = nil
	if password != "" && s.passwordSetter == nil {
		writeError(w, errs.Detail(ErrNotConfigured, "password provisioning requires PasswordSetter | 口令预配需要 PasswordSetter"))
		return
	}
	stored, err := s.store.ReplaceUser(r.Context(), patched)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.setPassword(r.Context(), stored, password); err != nil {
		writeError(w, err)
		return
	}
	s.respondUser(w, r, http.StatusOK, stored, attributes, excluded)
}

// handleDeleteUser serves DELETE /Users/{id}. | handleDeleteUser 提供 DELETE /Users/{id}。
func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.authorize(r, ActionDelete, ResourceTypeNameUser); err != nil {
		writeError(w, err)
		return
	}
	existing, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := checkPreconditions(r, userVersion(existing), true); err != nil {
		writeError(w, err)
		return
	}
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleListGroups serves GET /Groups. | handleListGroups 提供 GET /Groups。
func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	if err := s.authorize(r, ActionRead, ResourceTypeNameGroup); err != nil {
		writeError(w, err)
		return
	}
	params, err := s.parseListParams(r)
	if err != nil {
		writeError(w, err)
		return
	}
	s.writeGroupList(w, r, params)
}

// handleSearchGroups serves POST /Groups/.search. | handleSearchGroups 提供 POST /Groups/.search。
func (s *Server) handleSearchGroups(w http.ResponseWriter, r *http.Request) {
	if err := s.authorize(r, ActionRead, ResourceTypeNameGroup); err != nil {
		writeError(w, err)
		return
	}
	var request SearchRequest
	if err := decodeBody(r, &request); err != nil {
		writeError(w, err)
		return
	}
	params, err := s.searchParams(request)
	if err != nil {
		writeError(w, err)
		return
	}
	s.writeGroupList(w, r, params)
}

// writeGroupList runs the group query and writes a ListResponse. | writeGroupList 执行组查询并写出
// ListResponse。
func (s *Server) writeGroupList(w http.ResponseWriter, r *http.Request, params listParams) {
	groups, total, err := s.store.ListGroups(r.Context(), ListQuery{
		Filter:     params.filter,
		SortBy:     params.sortBy,
		SortOrder:  params.sortOrder,
		StartIndex: params.startIndex,
		Count:      params.count,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	resources := make([]any, 0, len(groups))
	for _, group := range groups {
		projected, err := projectResource(s.prepareGroup(r, group), params.attributes, params.excluded)
		if err != nil {
			writeError(w, err)
			return
		}
		resources = append(resources, projected)
	}
	writeSCIM(w, http.StatusOK, ListResponse{
		Schemas:      []string{ListResponseSchema},
		TotalResults: total,
		StartIndex:   params.startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	})
}

// handleGetGroup serves GET /Groups/{id}. | handleGetGroup 提供 GET /Groups/{id}。
func (s *Server) handleGetGroup(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.authorize(r, ActionRead, ResourceTypeNameGroup); err != nil {
		writeError(w, err)
		return
	}
	group, err := s.store.GetGroup(r.Context(), id)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := checkPreconditions(r, groupVersion(group), false); err != nil {
		if isNotModified(err) {
			setETag(w, groupVersion(group))
			w.WriteHeader(http.StatusNotModified)
			return
		}
		writeError(w, err)
		return
	}
	attributes, excluded, err := parseAttributeSelection(r.URL.Query())
	if err != nil {
		writeError(w, err)
		return
	}
	s.respondGroup(w, r, http.StatusOK, group, attributes, excluded)
}

// handleCreateGroup serves POST /Groups. | handleCreateGroup 提供 POST /Groups。
func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	if err := s.authorize(r, ActionCreate, ResourceTypeNameGroup); err != nil {
		writeError(w, err)
		return
	}
	var group Group
	if err := decodeBody(r, &group); err != nil {
		writeError(w, err)
		return
	}
	attributes, excluded, err := parseAttributeSelection(r.URL.Query())
	if err != nil {
		writeError(w, err)
		return
	}
	group.ID = ""
	group.Meta = nil
	created, err := s.store.CreateGroup(r.Context(), &group)
	if err != nil {
		writeError(w, err)
		return
	}
	s.respondGroup(w, r, http.StatusCreated, created, attributes, excluded)
}

// handleReplaceGroup serves PUT /Groups/{id}. | handleReplaceGroup 提供 PUT /Groups/{id}。
func (s *Server) handleReplaceGroup(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.authorize(r, ActionUpdate, ResourceTypeNameGroup); err != nil {
		writeError(w, err)
		return
	}
	existing, err := s.store.GetGroup(r.Context(), id)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := checkPreconditions(r, groupVersion(existing), true); err != nil {
		writeError(w, err)
		return
	}
	var incoming Group
	if err := decodeBody(r, &incoming); err != nil {
		writeError(w, err)
		return
	}
	attributes, excluded, err := parseAttributeSelection(r.URL.Query())
	if err != nil {
		writeError(w, err)
		return
	}
	incoming.ID = existing.ID
	incoming.Meta = nil
	updated, err := s.store.ReplaceGroup(r.Context(), &incoming)
	if err != nil {
		writeError(w, err)
		return
	}
	s.respondGroup(w, r, http.StatusOK, updated, attributes, excluded)
}

// handlePatchGroup serves PATCH /Groups/{id}. | handlePatchGroup 提供 PATCH /Groups/{id}。
func (s *Server) handlePatchGroup(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.authorize(r, ActionUpdate, ResourceTypeNameGroup); err != nil {
		writeError(w, err)
		return
	}
	existing, err := s.store.GetGroup(r.Context(), id)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := checkPreconditions(r, groupVersion(existing), true); err != nil {
		writeError(w, err)
		return
	}
	var request PatchRequest
	if err := decodeBody(r, &request); err != nil {
		writeError(w, err)
		return
	}
	if err := validatePatchRequest(&request); err != nil {
		writeError(w, err)
		return
	}
	attributes, excluded, err := parseAttributeSelection(r.URL.Query())
	if err != nil {
		writeError(w, err)
		return
	}
	patched, err := ApplyGroupPatch(existing, request.Operations)
	if err != nil {
		writeError(w, err)
		return
	}
	patched.ID = existing.ID
	patched.Meta = nil
	updated, err := s.store.ReplaceGroup(r.Context(), patched)
	if err != nil {
		writeError(w, err)
		return
	}
	s.respondGroup(w, r, http.StatusOK, updated, attributes, excluded)
}

// handleDeleteGroup serves DELETE /Groups/{id}. | handleDeleteGroup 提供 DELETE /Groups/{id}。
func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.authorize(r, ActionDelete, ResourceTypeNameGroup); err != nil {
		writeError(w, err)
		return
	}
	existing, err := s.store.GetGroup(r.Context(), id)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := checkPreconditions(r, groupVersion(existing), true); err != nil {
		writeError(w, err)
		return
	}
	if err := s.store.DeleteGroup(r.Context(), id); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleGetMe serves GET /Me for the authenticated principal. | handleGetMe 为已认证主体提供
// GET /Me。
func (s *Server) handleGetMe(w http.ResponseWriter, r *http.Request) {
	if err := s.authorize(r, ActionRead, ResourceTypeNameUser); err != nil {
		writeError(w, err)
		return
	}
	user, err := s.meUser(r)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := checkPreconditions(r, userVersion(user), false); err != nil {
		if isNotModified(err) {
			setETag(w, userVersion(user))
			w.WriteHeader(http.StatusNotModified)
			return
		}
		writeError(w, err)
		return
	}
	attributes, excluded, err := parseAttributeSelection(r.URL.Query())
	if err != nil {
		writeError(w, err)
		return
	}
	s.respondUser(w, r, http.StatusOK, user, attributes, excluded)
}

// handleReplaceMe serves PUT /Me. | handleReplaceMe 提供 PUT /Me。
func (s *Server) handleReplaceMe(w http.ResponseWriter, r *http.Request) {
	if err := s.authorize(r, ActionUpdate, ResourceTypeNameUser); err != nil {
		writeError(w, err)
		return
	}
	existing, err := s.meUser(r)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := checkPreconditions(r, userVersion(existing), true); err != nil {
		writeError(w, err)
		return
	}
	var incoming User
	if err := decodeBody(r, &incoming); err != nil {
		writeError(w, err)
		return
	}
	updated, err := s.replaceUser(r.Context(), existing, &incoming, incoming.Password, nil)
	if err != nil {
		writeError(w, err)
		return
	}
	s.respondUser(w, r, http.StatusOK, updated, nil, nil)
}

// handlePatchMe serves PATCH /Me. | handlePatchMe 提供 PATCH /Me。
func (s *Server) handlePatchMe(w http.ResponseWriter, r *http.Request) {
	if err := s.authorize(r, ActionUpdate, ResourceTypeNameUser); err != nil {
		writeError(w, err)
		return
	}
	existing, err := s.meUser(r)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := checkPreconditions(r, userVersion(existing), true); err != nil {
		writeError(w, err)
		return
	}
	var request PatchRequest
	if err := decodeBody(r, &request); err != nil {
		writeError(w, err)
		return
	}
	if err := validatePatchRequest(&request); err != nil {
		writeError(w, err)
		return
	}
	patched, err := ApplyUserPatch(existing, request.Operations)
	if err != nil {
		writeError(w, err)
		return
	}
	password := patched.Password
	patched.Password = ""
	patched.ID = existing.ID
	patched.Meta = nil
	patched.Groups = existing.Clone().Groups
	stored, err := s.store.ReplaceUser(r.Context(), patched)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.setPassword(r.Context(), stored, password); err != nil {
		writeError(w, err)
		return
	}
	s.respondUser(w, r, http.StatusOK, stored, nil, nil)
}

// meUser resolves the user referenced by the authenticated principal. | meUser 解析已认证主体引用
// 的用户。
func (s *Server) meUser(r *http.Request) (*User, error) {
	principal, ok := auth.PrincipalFromRequest(r)
	if !ok || principal == nil || principal.Subject == "" {
		return nil, errs.Detail(ErrUnauthorized, "authentication required | 需要认证")
	}
	return s.store.GetUser(r.Context(), principal.Subject)
}

// respondUser writes a User response with entity tag, location and attribute selection. |
// respondUser 写出带实体标签、Location 与属性选择的 User 响应。
func (s *Server) respondUser(w http.ResponseWriter, r *http.Request, status int, user *User, attributes, excluded []string) {
	prepared := s.prepareUser(r, user)
	setETag(w, userVersion(prepared))
	if status == http.StatusCreated && prepared.Meta != nil {
		w.Header().Set("Location", prepared.Meta.Location)
	}
	projected, err := projectResource(prepared, attributes, excluded)
	if err != nil {
		writeError(w, err)
		return
	}
	writeSCIM(w, status, projected)
}

// respondGroup writes a Group response with entity tag, location and attribute selection. |
// respondGroup 写出带实体标签、Location 与属性选择的 Group 响应。
func (s *Server) respondGroup(w http.ResponseWriter, r *http.Request, status int, group *Group, attributes, excluded []string) {
	prepared := s.prepareGroup(r, group)
	setETag(w, groupVersion(prepared))
	if status == http.StatusCreated && prepared.Meta != nil {
		w.Header().Set("Location", prepared.Meta.Location)
	}
	projected, err := projectResource(prepared, attributes, excluded)
	if err != nil {
		writeError(w, err)
		return
	}
	writeSCIM(w, status, projected)
}

// userVersion returns the entity tag of a User. | userVersion 返回 User 的实体标签。
func userVersion(user *User) string {
	if user == nil || user.Meta == nil {
		return ""
	}
	return user.Meta.Version
}

// groupVersion returns the entity tag of a Group. | groupVersion 返回 Group 的实体标签。
func groupVersion(group *Group) string {
	if group == nil || group.Meta == nil {
		return ""
	}
	return group.Meta.Version
}

// validatePatchRequest checks the PatchOp schema and the operation list. | validatePatchRequest
// 检查 PatchOp Schema 与操作列表。
func validatePatchRequest(request *PatchRequest) error {
	if request == nil {
		return errs.Detail(ErrInvalidSyntax, "missing PATCH request | 缺少 PATCH 请求")
	}
	if len(request.Schemas) > 0 && !containsFold(request.Schemas, PatchOpSchema) {
		return errs.Detail(ErrInvalidSyntax, "PATCH schemas must include PatchOp | PATCH schemas 必须包含 PatchOp")
	}
	if len(request.Operations) == 0 {
		return errs.Detail(ErrInvalidSyntax, "PATCH requires at least one operation | PATCH 至少需要一个操作")
	}
	return nil
}
