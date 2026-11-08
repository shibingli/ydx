package kms

import (
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// secondsToDuration converts a second count to a Duration and rejects int64 overflow. |
// secondsToDuration 把秒数转换为 Duration，并拒绝 int64 溢出。
func secondsToDuration(seconds int64) (time.Duration, error) {
	const maxDurationSeconds = int64(math.MaxInt64) / int64(time.Second)
	if seconds > maxDurationSeconds || seconds < -maxDurationSeconds {
		return 0, errs.Detail(ErrInvalidRequest, "duration %[1]d seconds is out of range | 时长 %[1]d 秒超出范围", seconds)
	}
	return time.Duration(seconds) * time.Second, nil
}

// createKeyJSON is the POST /keys request body. | createKeyJSON 是 POST /keys 请求体。
type createKeyJSON struct {
	// ID is an optional custom identifier. | ID 是可选自定义标识。
	ID string `json:"id"`
	// Alias is an optional unique alias. | Alias 是可选唯一别名。
	Alias string `json:"alias"`
	// Type is the key family. | Type 是密钥族。
	Type KeyType `json:"type"`
	// Bits is the key size. | Bits 是密钥长度。
	Bits int `json:"bits"`
	// Usage lists permitted operations. | Usage 列出允许操作。
	Usage []KeyUsage `json:"usage"`
	// Metadata holds scalar attributes. | Metadata 保存标量属性。
	Metadata map[string]string `json:"metadata"`
	// Tags is a label set. | Tags 是标签集合。
	Tags []string `json:"tags"`
	// ParentID links the key to a parent. | ParentID 把密钥关联到父密钥。
	ParentID string `json:"parentId"`
	// Exportable authorizes private export with policy opt-in. | Exportable 在策略开启时授权私钥导出。
	Exportable bool `json:"exportable"`
	// RotationSeconds is the rotation recommendation in seconds. | RotationSeconds 是轮换建议秒数。
	RotationSeconds int64 `json:"rotationSeconds"`
}

// updateKeyJSON is the PATCH /keys/{id} request body. | updateKeyJSON 是 PATCH /keys/{id} 请求体。
type updateKeyJSON struct {
	// Alias changes the alias; an empty string clears it. | Alias 修改别名；空字符串清除。
	Alias *string `json:"alias"`
	// Metadata replaces the metadata map. | Metadata 替换元数据映射。
	Metadata map[string]string `json:"metadata"`
	// Tags replaces the tag set. | Tags 替换标签集合。
	Tags *[]string `json:"tags"`
	// RotationSeconds changes the rotation recommendation. | RotationSeconds 修改轮换建议。
	RotationSeconds *int64 `json:"rotationSeconds"`
	// Exportable changes private-export authorization. | Exportable 修改私钥导出授权。
	Exportable *bool `json:"exportable"`
}

// exportKeyJSON is the POST /keys/{id}/export request body. | exportKeyJSON 是 POST /keys/{id}/export 请求体。
type exportKeyJSON struct {
	// Format selects the encoding. | Format 选择编码。
	Format ExportFormat `json:"format"`
	// Version selects the version; 0 means current. | Version 选择版本；0 表示当前。
	Version uint32 `json:"version"`
	// Private requests private or symmetric material. | Private 请求私钥或对称材料。
	Private bool `json:"private"`
}

// keyListResponse is the GET /keys response body. | keyListResponse 是 GET /keys 响应体。
type keyListResponse struct {
	// Keys holds material-safe metadata views. | Keys 保存材料安全元数据视图。
	Keys []*Key `json:"keys"`
	// Count is the number of returned keys. | Count 是返回的密钥数量。
	Count int `json:"count"`
}

// versionListResponse is the GET /keys/{id}/versions response body. | versionListResponse 是
// GET /keys/{id}/versions 响应体。
type versionListResponse struct {
	// Versions holds material-safe version views. | Versions 保存材料安全的版本视图。
	Versions []*KeyVersion `json:"versions"`
	// Count is the number of returned versions. | Count 是返回的版本数量。
	Count int `json:"count"`
}

// handleCreateKey serves POST /keys. | handleCreateKey 处理 POST /keys。
func (s *Server) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	var body createKeyJSON
	if err := s.decodeJSON(w, r, &body); err != nil {
		writeError(w, err)
		return
	}
	if err := s.authorize(r, ActionKeyCreate, body.ID); err != nil {
		writeError(w, err)
		return
	}
	rotation, err := secondsToDuration(body.RotationSeconds)
	if err != nil {
		writeError(w, err)
		return
	}
	key, err := s.service.CreateKey(s.requestContext(r), CreateKeyRequest{
		ID:               body.ID,
		Alias:            body.Alias,
		Type:             body.Type,
		Bits:             body.Bits,
		Usage:            body.Usage,
		Metadata:         body.Metadata,
		Tags:             body.Tags,
		ParentID:         body.ParentID,
		Exportable:       body.Exportable,
		RotationInterval: rotation,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, key)
}

// handleListKeys serves GET /keys. | handleListKeys 处理 GET /keys。
func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	filter, err := keyFilterFromQuery(r)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.authorize(r, ActionKeyList, ""); err != nil {
		writeError(w, err)
		return
	}
	keys, err := s.service.ListKeys(s.requestContext(r), filter)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, keyListResponse{Keys: keys, Count: len(keys)})
}

// handleGetKey serves GET /keys/{id}. | handleGetKey 处理 GET /keys/{id}。
func (s *Server) handleGetKey(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.authorize(r, ActionKeyGet, id); err != nil {
		writeError(w, err)
		return
	}
	key, err := s.service.GetKey(s.requestContext(r), id)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, key)
}

// handleUpdateKey serves PATCH /keys/{id}. | handleUpdateKey 处理 PATCH /keys/{id}。
func (s *Server) handleUpdateKey(w http.ResponseWriter, r *http.Request, id string) {
	var body updateKeyJSON
	if err := s.decodeJSON(w, r, &body); err != nil {
		writeError(w, err)
		return
	}
	if err := s.authorize(r, ActionKeyUpdate, id); err != nil {
		writeError(w, err)
		return
	}
	request := UpdateKeyRequest{
		Alias:      body.Alias,
		Metadata:   body.Metadata,
		Exportable: body.Exportable,
	}
	if body.Tags != nil {
		request.Tags = *body.Tags
	}
	if body.RotationSeconds != nil {
		interval, err := secondsToDuration(*body.RotationSeconds)
		if err != nil {
			writeError(w, err)
			return
		}
		request.RotationInterval = &interval
	}
	key, err := s.service.UpdateKey(s.requestContext(r), id, request)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, key)
}

// handleScheduleDelete serves DELETE /keys/{id}. | handleScheduleDelete 处理 DELETE /keys/{id}。
//
// The optional "delay" query parameter is a delay in seconds; 0 uses the service default. | 可选
// "delay" 查询参数为延迟秒数；0 使用服务默认值。
func (s *Server) handleScheduleDelete(w http.ResponseWriter, r *http.Request, id string) {
	seconds, err := queryInt(r, "delay")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.authorize(r, ActionKeyDelete, id); err != nil {
		writeError(w, err)
		return
	}
	delay, err := secondsToDuration(int64(seconds))
	if err != nil {
		writeError(w, err)
		return
	}
	key, err := s.service.ScheduleDelete(s.requestContext(r), id, delay)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, key)
}

// handleListVersions serves GET /keys/{id}/versions. | handleListVersions 处理 GET /keys/{id}/versions。
func (s *Server) handleListVersions(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.authorize(r, ActionKeyVersions, id); err != nil {
		writeError(w, err)
		return
	}
	versions, err := s.service.ListVersions(s.requestContext(r), id)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, versionListResponse{Versions: versions, Count: len(versions)})
}

// handleExportKey serves POST /keys/{id}/export. | handleExportKey 处理 POST /keys/{id}/export。
func (s *Server) handleExportKey(w http.ResponseWriter, r *http.Request, id string) {
	var body exportKeyJSON
	if err := s.decodeJSON(w, r, &body); err != nil {
		writeError(w, err)
		return
	}
	if err := s.authorize(r, ActionKeyExport, id); err != nil {
		writeError(w, err)
		return
	}
	exported, err := s.service.ExportKey(s.requestContext(r), id, ExportRequest(body))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, exported)
}

// keyFilterFromQuery builds a KeyFilter from URL query parameters. | keyFilterFromQuery 由 URL 查询参数
// 构建 KeyFilter。
func keyFilterFromQuery(r *http.Request) (KeyFilter, error) {
	query := r.URL.Query()
	offset, err := queryInt(r, "offset")
	if err != nil {
		return KeyFilter{}, err
	}
	limit, err := queryInt(r, "limit")
	if err != nil {
		return KeyFilter{}, err
	}
	return KeyFilter{
		State:    KeyState(strings.TrimSpace(query.Get("state"))),
		Type:     KeyType(strings.TrimSpace(query.Get("type"))),
		Usage:    KeyUsage(strings.TrimSpace(query.Get("usage"))),
		Tag:      strings.TrimSpace(query.Get("tag")),
		Query:    strings.TrimSpace(query.Get("q")),
		ParentID: strings.TrimSpace(query.Get("parentId")),
		Offset:   offset,
		Limit:    limit,
	}, nil
}
