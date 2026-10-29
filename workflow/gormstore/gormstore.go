// Package gormstore is the GORM persistence implementation of the workflow domain. | Package gormstore
// 是流程域的 GORM 持久化实现。
//
// The store owns the DDL of the eight yd_workflow_* tables. It declares no associations and no
// foreign keys: every relation is a plain identifier maintained by the domain (CLAUDE.md §25). |
// 本存储拥有八张 yd_workflow_* 表的 DDL。它不声明关联、不建外键：每个关系都是域层维护的普通标识
// （见 CLAUDE.md 第 25 节）。
package gormstore

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
	gormx "github.com/shibingli/ydx/gorm"
	"github.com/shibingli/ydx/workflow"
	gormlib "gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrUnavailable reports a missing database handle. | ErrUnavailable 表示数据库句柄为空。
var ErrUnavailable = errs.New("workflow gorm store is unavailable | 流程 GORM 存储不可用")

// Store implements workflow.Store over one *gorm.DB. | Store 在一个 *gorm.DB 之上实现 workflow.Store。
type Store struct {
	// db is the handle, or a transaction-bound handle inside WithTx. | db 是数据库句柄，或在 WithTx 内绑定事务的句柄。
	db *gormlib.DB
}

// New returns a workflow store over db. | New 返回 db 之上的流程存储。
func New(db *gormlib.DB) (*Store, error) {
	if db == nil {
		return nil, ErrUnavailable
	}
	return &Store{db: db}, nil
}

// models lists every table the migration manages. | models 列出迁移管理的全部表。
func models() []any {
	return []any{
		&workflow.Definition{},
		&workflow.Version{},
		&workflow.Instance{},
		&workflow.Token{},
		&workflow.Task{},
		&workflow.TaskCandidate{},
		&workflow.Event{},
		&workflow.Comment{},
		&workflow.Notification{},
		&workflow.Group{},
		&workflow.GroupMember{},
	}
}

// Migrate creates or updates every workflow table. It is idempotent. | Migrate 创建或更新全部流程表，且幂等。
func Migrate(ctx context.Context, db *gormlib.DB) error {
	if db == nil {
		return ErrUnavailable
	}
	if err := db.WithContext(ctx).AutoMigrate(models()...); err != nil {
		return errs.Wrap(err, ErrUnavailable)
	}
	return nil
}

// WithTx runs fn in one transaction. | WithTx 在一个事务内执行 fn。
func (s *Store) WithTx(ctx context.Context, fn func(workflow.Store) error) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gormlib.DB) error {
		return fn(&Store{db: tx})
	})
}

// locked returns a query whose single-row read takes a write lock on dialects that support it. |
// locked 返回在支持的后端上对单行读取加写锁的查询。
//
// The decision comes from ydx/gorm's dialect catalogue rather than a driver-name switch, so a
// newly supported dialect inherits the right behaviour the moment its feature bits say so. |
// 该决定来自 ydx/gorm 的方言目录而不是驱动名分支，因此新支持的方言只要能力位正确就自动获得正确行为。
func (s *Store) locked() *gormlib.DB {
	if !s.supportsRowLock() {
		return s.db
	}
	return s.db.Clauses(clause.Locking{Strength: "UPDATE"})
}

// supportsRowLock reports whether the connected dialect supports SELECT ... FOR UPDATE. |
// supportsRowLock 报告连接的方言是否支持 SELECT ... FOR UPDATE。
func (s *Store) supportsRowLock() bool {
	dialect, err := gormx.DialectFor(s.db.Dialector.Name())
	if err != nil {
		return false
	}
	return dialect.Features.Has(gormx.FeatureRowLock)
}

// findOne maps a record-not-found error onto workflow.ErrNotFound. | findOne 把记录不存在映射为 workflow.ErrNotFound。
func findOne(err error) error {
	if errors.Is(err, gormlib.ErrRecordNotFound) {
		return workflow.ErrNotFound
	}
	return err
}

// create maps a duplicate-key error onto workflow.ErrConflict. | create 把唯一键冲突映射为 workflow.ErrConflict。
func create(err error) error {
	if errors.Is(err, gormlib.ErrDuplicatedKey) {
		return errs.Wrap(err, workflow.ErrConflict)
	}
	return err
}

// escapeLike escapes the LIKE wildcards with '!' as the escape character. | escapeLike 用 '!' 作为转义符转义 LIKE 通配符。
func escapeLike(value string) string {
	value = strings.ReplaceAll(value, "!", "!!")
	value = strings.ReplaceAll(value, "%", "!%")
	value = strings.ReplaceAll(value, "_", "!_")
	return value
}

// likeAll wraps a value in wildcards. | likeAll 用通配符包裹值。
func likeAll(value string) string { return "%" + escapeLike(value) + "%" }

// CreateDefinition inserts one definition. | CreateDefinition 插入一个定义。
func (s *Store) CreateDefinition(ctx context.Context, def workflow.Definition) error {
	return create(s.db.WithContext(ctx).Create(&def).Error)
}

// UpdateDefinition updates one definition. | UpdateDefinition 更新一个定义。
func (s *Store) UpdateDefinition(ctx context.Context, def workflow.Definition) error {
	result := s.db.WithContext(ctx).Model(&workflow.Definition{}).
		Where("tenant_id = ? AND id = ?", def.TenantID, def.ID).
		Select("name", "name_en", "description", "category", "icon", "status", "current_version", "updated_by", "updated_at").
		Updates(&def)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return workflow.ErrNotFound
	}
	return nil
}

// DeleteDefinition deletes one definition and its versions. | DeleteDefinition 删除一个定义及其版本。
func (s *Store) DeleteDefinition(ctx context.Context, tenantID, id string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gormlib.DB) error {
		if err := tx.Where("tenant_id = ? AND definition_id = ?", tenantID, id).Delete(&workflow.Version{}).Error; err != nil {
			return err
		}
		result := tx.Where("tenant_id = ? AND id = ?", tenantID, id).Delete(&workflow.Definition{})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return workflow.ErrNotFound
		}
		return nil
	})
}

// GetDefinition reads one definition. | GetDefinition 读取一个定义。
func (s *Store) GetDefinition(ctx context.Context, tenantID, id string) (workflow.Definition, error) {
	var def workflow.Definition
	err := s.locked().WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, id).First(&def).Error
	return def, findOne(err)
}

// GetDefinitionByKey reads one definition by key. | GetDefinitionByKey 按键读取一个定义。
func (s *Store) GetDefinitionByKey(ctx context.Context, tenantID, key string) (workflow.Definition, error) {
	var def workflow.Definition
	err := s.locked().WithContext(ctx).Where("tenant_id = ? AND def_key = ?", tenantID, key).First(&def).Error
	return def, findOne(err)
}

// ListDefinitions returns one page of definitions. | ListDefinitions 返回一页定义。
func (s *Store) ListDefinitions(ctx context.Context, tenantID string, filter workflow.DefinitionFilter) ([]workflow.Definition, int, error) {
	query := s.db.WithContext(ctx).Model(&workflow.Definition{}).Where("tenant_id = ?", tenantID)
	if filter.Status != "" {
		query = query.Where("status = ?", filter.Status)
	}
	if filter.Category != "" {
		query = query.Where("category = ?", filter.Category)
	}
	if filter.Query != "" {
		pattern := likeAll(filter.Query)
		query = query.Where("(def_key LIKE ? ESCAPE '!' OR name LIKE ? ESCAPE '!' OR name_en LIKE ? ESCAPE '!')", pattern, pattern, pattern)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	items := make([]workflow.Definition, 0, listCapacity(filter.PageSize))
	offset := (filter.Page - 1) * filter.PageSize
	if err := query.Order("updated_at DESC").Offset(offset).Limit(filter.PageSize).Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, int(total), nil
}

// CountVersionsForDefinitions groups version counts by definition id. | CountVersionsForDefinitions
// 按定义 ID 分组统计版本数。
func (s *Store) CountVersionsForDefinitions(ctx context.Context, tenantID string, definitionIDs []string) (map[string]int, error) {
	return s.countByDefinition(ctx, &workflow.Version{}, tenantID, definitionIDs)
}

// CountInstancesForDefinitions groups instance counts by definition id. | CountInstancesForDefinitions
// 按定义 ID 分组统计实例数。
func (s *Store) CountInstancesForDefinitions(ctx context.Context, tenantID string, definitionIDs []string) (map[string]int, error) {
	return s.countByDefinition(ctx, &workflow.Instance{}, tenantID, definitionIDs)
}

// countByDefinition runs one grouped count for a page of definitions. | countByDefinition 为一页
// 定义执行一次分组统计。
func (s *Store) countByDefinition(ctx context.Context, model any, tenantID string, definitionIDs []string) (map[string]int, error) {
	out := make(map[string]int, len(definitionIDs))
	if len(definitionIDs) == 0 {
		return out, nil
	}
	rows := make([]struct {
		DefinitionID string `gorm:"column:definition_id"`
		Total        int    `gorm:"column:total"`
	}, 0, len(definitionIDs))
	if err := s.db.WithContext(ctx).Model(model).
		Select("definition_id, COUNT(*) AS total").
		Where("tenant_id = ? AND definition_id IN ?", tenantID, definitionIDs).
		Group("definition_id").Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, row := range rows {
		out[row.DefinitionID] = row.Total
	}
	return out, nil
}

// CreateVersion inserts one version. | CreateVersion 插入一个版本。
func (s *Store) CreateVersion(ctx context.Context, version workflow.Version) error {
	return create(s.db.WithContext(ctx).Create(&version).Error)
}

// UpdateVersion updates the editable columns of one draft version. | UpdateVersion 更新一个草稿版本的可编辑列。
func (s *Store) UpdateVersion(ctx context.Context, version workflow.Version) error {
	result := s.db.WithContext(ctx).Model(&workflow.Version{}).
		Where("tenant_id = ? AND id = ?", version.TenantID, version.ID).
		Select("status", "design", "bpmn", "checksum", "note", "published_at", "published_by", "updated_at", "created_by").
		Updates(&version)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return workflow.ErrNotFound
	}
	return nil
}

// DeleteVersion deletes one version. | DeleteVersion 删除一个版本。
func (s *Store) DeleteVersion(ctx context.Context, tenantID, id string) error {
	result := s.db.WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, id).Delete(&workflow.Version{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return workflow.ErrNotFound
	}
	return nil
}

// GetVersion reads one version. | GetVersion 读取一个版本。
func (s *Store) GetVersion(ctx context.Context, tenantID, id string) (workflow.Version, error) {
	var version workflow.Version
	err := s.locked().WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, id).First(&version).Error
	return version, findOne(err)
}

// GetVersionByNumber reads one version by number. | GetVersionByNumber 按版本号读取一个版本。
func (s *Store) GetVersionByNumber(ctx context.Context, tenantID, definitionID string, version int) (workflow.Version, error) {
	var row workflow.Version
	err := s.locked().WithContext(ctx).
		Where("tenant_id = ? AND definition_id = ? AND version_number = ?", tenantID, definitionID, version).
		First(&row).Error
	return row, findOne(err)
}

// GetLatestPublishedVersion returns the highest published version of one definition. |
// GetLatestPublishedVersion 返回一个定义的最高已发布版本。
func (s *Store) GetLatestPublishedVersion(ctx context.Context, tenantID, definitionID string) (workflow.Version, error) {
	var version workflow.Version
	err := s.db.WithContext(ctx).
		Where("tenant_id = ? AND definition_id = ? AND status = ?", tenantID, definitionID, workflow.VersionPublished).
		Order("version_number DESC").First(&version).Error
	return version, findOne(err)
}

// GetLatestPublishedVersionMeta resolves the latest published version to its primary key only.
// The engine already holds the parsed design after the first start, so transferring the design,
// BPMN and note columns on every start would be pure waste; a cache miss falls back to GetVersion. |
// GetLatestPublishedVersionMeta 只把最新已发布版本解析为主键。引擎在首次发起之后已持有解析后的设计，
// 每次发起都传输设计、BPMN 与说明列纯属浪费；缓存未命中时再由 GetVersion 读取完整行。
func (s *Store) GetLatestPublishedVersionMeta(ctx context.Context, tenantID, definitionID string) (workflow.Version, error) {
	var version workflow.Version
	err := s.db.WithContext(ctx).Select("id").
		Where("tenant_id = ? AND definition_id = ? AND status = ?", tenantID, definitionID, workflow.VersionPublished).
		Order("version_number DESC").First(&version).Error
	return version, findOne(err)
}

// GetVersionByNumberMeta resolves one version number to its primary key only. | GetVersionByNumberMeta
// 只把一个版本号解析为主键。
func (s *Store) GetVersionByNumberMeta(ctx context.Context, tenantID, definitionID string, version int) (workflow.Version, error) {
	var row workflow.Version
	err := s.db.WithContext(ctx).Select("id").
		Where("tenant_id = ? AND definition_id = ? AND version_number = ?", tenantID, definitionID, version).
		First(&row).Error
	return row, findOne(err)
}

// ListVersions returns every version in descending order. | ListVersions 按降序返回全部版本。
func (s *Store) ListVersions(ctx context.Context, tenantID, definitionID string) ([]workflow.Version, error) {
	items := make([]workflow.Version, 0, 8)
	if err := s.db.WithContext(ctx).
		Where("tenant_id = ? AND definition_id = ?", tenantID, definitionID).
		Order("version_number DESC").Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

// ListVersionSummariesForDefinitions returns lightweight version projections for several
// definitions. The workbench only needs status and version number; selecting design and BPMN for
// every version would transfer the whole history on each page render. | ListVersionSummariesForDefinitions
// 返回多个定义的轻量版本投影。工作台只需要状态与版本号；为每个版本读取设计与 BPMN 会在每次页面渲染时
// 传输整段历史。
func (s *Store) ListVersionSummariesForDefinitions(ctx context.Context, tenantID string, definitionIDs []string) (map[string][]workflow.VersionSummary, error) {
	out := make(map[string][]workflow.VersionSummary, len(definitionIDs))
	if len(definitionIDs) == 0 {
		return out, nil
	}
	rows := make([]workflow.Version, 0, len(definitionIDs)*2)
	if err := s.db.WithContext(ctx).
		Select("id", "definition_id", "status", "version_number", "published_at", "note").
		Where("tenant_id = ? AND definition_id IN ?", tenantID, definitionIDs).
		Order("definition_id ASC, version_number DESC").Find(&rows).Error; err != nil {
		return nil, err
	}
	for _, row := range rows {
		out[row.DefinitionID] = append(out[row.DefinitionID], workflow.VersionSummary{
			ID: row.ID, DefinitionID: row.DefinitionID, Status: row.Status, Version: row.Version,
			PublishedAt: row.PublishedAt, Note: row.Note,
		})
	}
	return out, nil
}

// NextVersionNumber returns the next free version number. | NextVersionNumber 返回下一个空闲版本号。
func (s *Store) NextVersionNumber(ctx context.Context, tenantID, definitionID string) (int, error) {
	var maximum int
	err := s.db.WithContext(ctx).Model(&workflow.Version{}).
		Where("tenant_id = ? AND definition_id = ?", tenantID, definitionID).
		Select("COALESCE(MAX(version_number), 0)").Scan(&maximum).Error
	if err != nil {
		return 0, err
	}
	return maximum + 1, nil
}

// CreateInstance inserts one instance. | CreateInstance 插入一个实例。
func (s *Store) CreateInstance(ctx context.Context, inst workflow.Instance) error {
	return create(s.db.WithContext(ctx).Create(&inst).Error)
}

// UpdateInstance updates the mutable columns of one instance. | UpdateInstance 更新一个实例的可变列。
func (s *Store) UpdateInstance(ctx context.Context, inst workflow.Instance) error {
	result := s.db.WithContext(ctx).Model(&workflow.Instance{}).
		Where("tenant_id = ? AND id = ?", inst.TenantID, inst.ID).
		Select("status", "outcome", "ended_at", "ended_reason", "variables", "visited_nodes", "current_nodes", "due_at", "updated_at").
		Updates(&inst)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return workflow.ErrNotFound
	}
	return nil
}

// GetInstance reads one instance and locks it on supported dialects. | GetInstance 读取一个实例，并在支持的后端上加锁。
func (s *Store) GetInstance(ctx context.Context, tenantID, id string) (workflow.Instance, error) {
	var inst workflow.Instance
	err := s.locked().WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, id).First(&inst).Error
	return inst, findOne(err)
}

// instanceListColumns is the lean projection: every list field, none of the unbounded payloads. |
// instanceListColumns 是精简投影：包含全部列表字段，不含无界载荷。
const instanceListColumns = "id, created_at, updated_at, started_at, ended_at, due_at, tenant_id, definition_id, version_id, definition_key, definition_name, title, business_key, category, initiator_id, initiator_name, status, outcome, ended_reason, version_number"

// ListInstances returns one page of instances. | ListInstances 返回一页实例。
func (s *Store) ListInstances(ctx context.Context, tenantID string, filter workflow.InstanceFilter) ([]workflow.Instance, int, error) {
	query := s.db.WithContext(ctx).Model(&workflow.Instance{}).Where("tenant_id = ?", tenantID)
	if filter.Status != "" {
		query = query.Where("status = ?", filter.Status)
	}
	if filter.Category != "" {
		query = query.Where("category = ?", filter.Category)
	}
	if filter.DefinitionID != "" {
		query = query.Where("definition_id = ?", filter.DefinitionID)
	}
	if filter.InitiatorID != "" {
		query = query.Where("initiator_id = ?", filter.InitiatorID)
	}
	if filter.Query != "" {
		pattern := likeAll(filter.Query)
		query = query.Where("(title LIKE ? ESCAPE '!' OR business_key LIKE ? ESCAPE '!' OR initiator_name LIKE ? ESCAPE '!')", pattern, pattern, pattern)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if filter.Lean {
		query = query.Select(instanceListColumns)
	}
	items := make([]workflow.Instance, 0, listCapacity(filter.PageSize))
	offset := (filter.Page - 1) * filter.PageSize
	if err := query.Order("updated_at DESC").Offset(offset).Limit(filter.PageSize).Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, int(total), nil
}

// CountRunningInstances counts running instances with one business key. | CountRunningInstances
// 统计使用同一业务键的运行中实例。
func (s *Store) CountRunningInstances(ctx context.Context, tenantID, definitionID, businessKey string) (int, error) {
	var total int64
	err := s.db.WithContext(ctx).Model(&workflow.Instance{}).
		Where("tenant_id = ? AND definition_id = ? AND business_key = ? AND status = ?", tenantID, definitionID, businessKey, workflow.InstanceRunning).
		Count(&total).Error
	return int(total), err
}

// CreateToken inserts one token. | CreateToken 插入一个令牌。
func (s *Store) CreateToken(ctx context.Context, token workflow.Token) error {
	return create(s.db.WithContext(ctx).Create(&token).Error)
}

// UpdateToken updates one token. | UpdateToken 更新一个令牌。
func (s *Store) UpdateToken(ctx context.Context, token workflow.Token) error {
	result := s.db.WithContext(ctx).Model(&workflow.Token{}).
		Where("tenant_id = ? AND id = ?", token.TenantID, token.ID).
		Select("node_id", "status", "fork_group", "fork_node", "remaining", "wait_type", "wait_until", "message_name", "wait_group", "updated_at").
		Updates(&token)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return workflow.ErrNotFound
	}
	return nil
}

// GetToken reads one token and locks it on supported dialects. | GetToken 读取一个令牌，并在支持的后端上加锁。
func (s *Store) GetToken(ctx context.Context, tenantID, id string) (workflow.Token, error) {
	var token workflow.Token
	err := s.locked().WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, id).First(&token).Error
	return token, findOne(err)
}

// ListTokens returns every token of one instance. | ListTokens 返回一个实例的全部令牌。
func (s *Store) ListTokens(ctx context.Context, tenantID, instanceID string) ([]workflow.Token, error) {
	items := make([]workflow.Token, 0, 8)
	if err := s.db.WithContext(ctx).
		Where("tenant_id = ? AND instance_id = ?", tenantID, instanceID).
		Order("created_at ASC").Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

// ListTokensAtNode returns active and waiting tokens at one node. | ListTokensAtNode 返回节点上的活动与等待令牌。
func (s *Store) ListTokensAtNode(ctx context.Context, tenantID, instanceID, nodeID string) ([]workflow.Token, error) {
	items := make([]workflow.Token, 0, 4)
	if err := s.db.WithContext(ctx).
		Where("tenant_id = ? AND instance_id = ? AND node_id = ? AND status IN ?", tenantID, instanceID, nodeID,
			[]string{workflow.TokenActive, workflow.TokenWaiting}).
		Order("seq_order ASC, created_at ASC").Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

// ListWaitingTokens returns only waiting tokens of one instance. The workflow runtime recomputes
// current nodes after every transition; fetching completed tokens too would make that scan grow
// with the instance's whole history, while the (tenant_id, instance_id, status) index answers the
// narrowed query directly. | ListWaitingTokens 只返回一个实例的等待令牌。流程运行期在每次状态流转后
// 重算当前节点；连已完成令牌一起读取会让扫描随实例全部历史增长，而 (tenant_id, instance_id, status)
// 索引可以直接回答收窄后的查询。
func (s *Store) ListWaitingTokens(ctx context.Context, tenantID, instanceID string) ([]workflow.Token, error) {
	items := make([]workflow.Token, 0, 8)
	if err := s.db.WithContext(ctx).
		Where("tenant_id = ? AND instance_id = ? AND status = ?", tenantID, instanceID, workflow.TokenWaiting).
		Order("created_at ASC").Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

// CountLiveTokens counts active and waiting tokens. | CountLiveTokens 统计活动与等待令牌。
func (s *Store) CountLiveTokens(ctx context.Context, tenantID, instanceID string) (int, error) {
	var total int64
	err := s.db.WithContext(ctx).Model(&workflow.Token{}).
		Where("tenant_id = ? AND instance_id = ? AND status IN ?", tenantID, instanceID,
			[]string{workflow.TokenActive, workflow.TokenWaiting}).Count(&total).Error
	return int(total), err
}

// CountLiveTokensByForkGroup counts live tokens in one inclusive fork group. | CountLiveTokensByForkGroup
// 统计一个包容分支组内的活动令牌。
func (s *Store) CountLiveTokensByForkGroup(ctx context.Context, tenantID, instanceID, forkGroup string) (int, error) {
	var total int64
	err := s.db.WithContext(ctx).Model(&workflow.Token{}).
		Where("tenant_id = ? AND instance_id = ? AND fork_group = ? AND status IN ?", tenantID, instanceID, forkGroup,
			[]string{workflow.TokenActive, workflow.TokenWaiting}).Count(&total).Error
	return int(total), err
}

// CreateTask inserts one task and its normalised candidate rows. | CreateTask 插入一条任务及其规范化候选人行。
func (s *Store) CreateTask(ctx context.Context, task workflow.Task) error {
	normalizeTask(&task)
	return s.db.WithContext(ctx).Transaction(func(tx *gormlib.DB) error {
		if err := create(tx.Create(&task).Error); err != nil {
			return err
		}
		return s.replaceCandidates(ctx, tx, task)
	})
}

// UpdateTask updates one task and refreshes its normalised candidate rows. | UpdateTask 更新一条任务
// 并刷新其规范化候选人行。
func (s *Store) UpdateTask(ctx context.Context, task workflow.Task) error {
	normalizeTask(&task)
	return s.db.WithContext(ctx).Transaction(func(tx *gormlib.DB) error {
		result := tx.Model(&workflow.Task{}).
			Where("tenant_id = ? AND id = ?", task.TenantID, task.ID).
			Select("assignee_id", "assignee_name", "original_assignee_id", "original_assignee_name",
				"delegated_to", "delegated_from", "candidates", "candidate_refs", "status", "decision",
				"comment", "form_data", "claimed_at", "completed_at", "last_remind_at", "next_remind_at",
				"remind_count", "max_remind", "remind_every_seconds", "updated_at").
			Updates(&task)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return workflow.ErrNotFound
		}
		return s.replaceCandidates(ctx, tx, task)
	})
}

// replaceCandidates rewrites the candidate index rows of one task. | replaceCandidates 重写一条任务的候选人索引行。
func (s *Store) replaceCandidates(ctx context.Context, tx *gormlib.DB, task workflow.Task) error {
	if err := tx.Where("tenant_id = ? AND task_id = ?", task.TenantID, task.ID).Delete(&workflow.TaskCandidate{}).Error; err != nil {
		return err
	}
	for _, userID := range task.CandidateList() {
		row := workflow.TaskCandidate{
			CreatedAt: task.CreatedAt,
			ID:        task.ID + "_" + userID,
			TenantID:  task.TenantID,
			TaskID:    task.ID,
			UserID:    userID,
		}
		if row.CreatedAt.IsZero() {
			row.CreatedAt = task.UpdatedAt
		}
		err := tx.Create(&row).Error
		if err != nil && !errors.Is(err, gormlib.ErrDuplicatedKey) {
			return err
		}
	}
	return nil
}

// normalizeTask keeps the candidate index in step with the JSON candidate list. | normalizeTask
// 让候选人索引与 JSON 候选人列表保持一致。
func normalizeTask(task *workflow.Task) {
	if task.Decision == "" {
		task.Decision = workflow.DecisionNone
	}
	if task.Status == "" {
		task.Status = workflow.TaskPending
	}
	task.CandidateRefs = workflow.CandidateIndex(task.Candidates)
}

// ClaimTask claims one task atomically. | ClaimTask 原子领取一条任务。
func (s *Store) ClaimTask(ctx context.Context, tenantID, id, actorID, actorName string, now time.Time) (workflow.Task, error) {
	var claimed workflow.Task
	err := s.db.WithContext(ctx).Transaction(func(tx *gormlib.DB) error {
		var task workflow.Task
		query := tx
		if dialect, err := gormx.DialectFor(tx.Dialector.Name()); err == nil && dialect.Features.Has(gormx.FeatureRowLock) {
			query = tx.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := query.Where("tenant_id = ? AND id = ?", tenantID, id).First(&task).Error; err != nil {
			return findOne(err)
		}
		if task.Status != workflow.TaskPending {
			if task.Status == workflow.TaskClaimed && task.AssigneeID == actorID {
				claimed = task
				return nil
			}
			return workflow.ErrTaskClosed
		}
		if task.AssigneeID != "" && task.AssigneeID != actorID {
			return workflow.ErrTaskNotMine
		}
		if len(task.Candidates) > 0 && !containsCandidate(task.Candidates, actorID) {
			return workflow.ErrTaskNotMine
		}
		task.AssigneeID = actorID
		task.AssigneeName = actorName
		task.Status = workflow.TaskClaimed
		task.ClaimedAt = now
		task.UpdatedAt = now
		normalizeTask(&task)
		result := tx.Model(&workflow.Task{}).Where("tenant_id = ? AND id = ? AND status = ?", tenantID, id, workflow.TaskPending).
			Select("assignee_id", "assignee_name", "status", "candidate_refs", "claimed_at", "updated_at").
			Updates(&task)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return workflow.ErrTaskClosed
		}
		claimed = task
		return nil
	})
	return claimed, err
}

// containsCandidate reports whether the pipe-delimited index names id. | containsCandidate 报告竖线索引是否包含 id。
func containsCandidate(candidates []string, id string) bool {
	for _, candidate := range candidates {
		if candidate == id {
			return true
		}
	}
	return false
}

// GetTask reads one task and locks it on supported dialects. | GetTask 读取一条任务，并在支持的后端上加锁。
func (s *Store) GetTask(ctx context.Context, tenantID, id string) (workflow.Task, error) {
	var task workflow.Task
	err := s.locked().WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, id).First(&task).Error
	if err != nil {
		return task, findOne(err)
	}
	items := []workflow.Task{task}
	s.fillTaskProjections(ctx, tenantID, items)
	return items[0], nil
}

// GetTaskBare reads one task without the instance projection query. The runtime and the detail
// drawer load the instance themselves, so the extra SELECT only duplicated work on every action. |
// GetTaskBare 读取一条任务且不执行实例投影查询。运行期与详情抽屉本来就会读取实例，额外的 SELECT
// 只会让每次动作重复一次工作。
func (s *Store) GetTaskBare(ctx context.Context, tenantID, id string) (workflow.Task, error) {
	var task workflow.Task
	err := s.locked().WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, id).First(&task).Error
	return task, findOne(err)
}

// taskQuery builds the shared task filter. | taskQuery 构建共享的任务过滤条件。
func (s *Store) taskQuery(ctx context.Context, tenantID string, filter workflow.TaskFilter) *gormlib.DB {
	query := s.db.WithContext(ctx).Model(&workflow.Task{}).Where("tenant_id = ?", tenantID)
	if filter.Status != "" {
		query = query.Where("status = ?", filter.Status)
	} else if len(filter.Statuses) > 0 {
		query = query.Where("status IN ?", filter.Statuses)
	}
	if filter.ActorID != "" {
		query = query.Where("(assignee_id = ? OR id IN (?))", filter.ActorID,
			s.db.WithContext(ctx).Model(&workflow.TaskCandidate{}).Select("task_id").
				Where("tenant_id = ? AND user_id = ?", tenantID, filter.ActorID))
	}
	if filter.AssigneeID != "" {
		query = query.Where("assignee_id = ?", filter.AssigneeID)
	}
	if filter.CandidateID != "" {
		query = query.Where("id IN (?)", s.db.WithContext(ctx).Model(&workflow.TaskCandidate{}).Select("task_id").
			Where("tenant_id = ? AND user_id = ?", tenantID, filter.CandidateID))
	}
	if filter.InstanceID != "" {
		query = query.Where("instance_id = ?", filter.InstanceID)
	}
	if filter.Category != "" {
		query = query.Where("category = ?", filter.Category)
	}
	if filter.DefinitionID != "" {
		query = query.Where("instance_id IN (?)", s.db.WithContext(ctx).Model(&workflow.Instance{}).
			Select("id").Where("tenant_id = ? AND definition_id = ?", tenantID, filter.DefinitionID))
	}
	if filter.Query != "" {
		pattern := likeAll(filter.Query)
		query = query.Where("(node_name LIKE ? ESCAPE '!' OR instance_id IN (?))", pattern,
			s.db.WithContext(ctx).Model(&workflow.Instance{}).Select("id").
				Where("tenant_id = ? AND (title LIKE ? ESCAPE '!' OR initiator_name LIKE ? ESCAPE '!')", tenantID, pattern, pattern))
	}
	if filter.Overdue {
		query = query.Where("due_at > ? AND due_at < ?", time.Unix(1, 0).UTC(), time.Now().UTC())
	}
	return query
}

// ListTasks returns one page of tasks. | ListTasks 返回一页任务。
func (s *Store) ListTasks(ctx context.Context, tenantID string, filter workflow.TaskFilter) ([]workflow.Task, int, error) {
	query := s.taskQuery(ctx, tenantID, filter)
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	items := make([]workflow.Task, 0, listCapacity(filter.PageSize))
	offset := (filter.Page - 1) * filter.PageSize
	order := "created_at DESC"
	if filter.Status == "" && len(filter.Statuses) == 0 {
		order = "created_at DESC"
	}
	if err := query.Order(order).Offset(offset).Limit(filter.PageSize).Find(&items).Error; err != nil {
		return nil, 0, err
	}
	s.fillTaskProjections(ctx, tenantID, items)
	return items, int(total), nil
}

// fillTaskProjections adds the instance title and initiator to a task page. | fillTaskProjections
// 为任务页补充实例标题与发起人。
func (s *Store) fillTaskProjections(ctx context.Context, tenantID string, items []workflow.Task) {
	if len(items) == 0 {
		return
	}
	ids := make([]string, 0, len(items))
	seen := map[string]bool{}
	for i := range items {
		if seen[items[i].InstanceID] {
			continue
		}
		seen[items[i].InstanceID] = true
		ids = append(ids, items[i].InstanceID)
	}
	rows := make([]workflow.Instance, 0, len(ids))
	if err := s.db.WithContext(ctx).Select("id", "title", "initiator_name", "definition_key", "category").
		Where("tenant_id = ? AND id IN ?", tenantID, ids).Find(&rows).Error; err != nil {
		return
	}
	byID := make(map[string]workflow.Instance, len(rows))
	for _, row := range rows {
		byID[row.ID] = row
	}
	for i := range items {
		if inst, ok := byID[items[i].InstanceID]; ok {
			items[i].InstanceTitle = inst.Title
			items[i].InstanceInitiator = inst.InitiatorName
			if items[i].DefinitionKey == "" {
				items[i].DefinitionKey = inst.DefinitionKey
			}
			if items[i].Category == "" {
				items[i].Category = inst.Category
			}
		}
	}
}

// ListTasksByToken returns the tasks of one token ordered by sequence. | ListTasksByToken 按顺序返回一个令牌的任务。
func (s *Store) ListTasksByToken(ctx context.Context, tenantID, tokenID string) ([]workflow.Task, error) {
	items := make([]workflow.Task, 0, 4)
	if err := s.db.WithContext(ctx).
		Where("tenant_id = ? AND token_id = ?", tenantID, tokenID).
		Order("seq_order ASC, created_at ASC").Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

// ListDueTasks returns tasks whose next reminder is due. | ListDueTasks 返回下次催办已到期的任务。
func (s *Store) ListDueTasks(ctx context.Context, now time.Time, limit int) ([]workflow.Task, error) {
	items := make([]workflow.Task, 0, listCapacity(limit))
	if err := s.db.WithContext(ctx).
		Where("status IN ? AND next_remind_at > ? AND next_remind_at <= ? AND (max_remind = 0 OR remind_count < max_remind)",
			[]string{workflow.TaskPending, workflow.TaskClaimed}, time.Unix(1, 0).UTC(), now).
		Order("next_remind_at ASC").Limit(limit).Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

// ClaimReminder moves one due reminder forward atomically. | ClaimReminder 原子推进一次到期催办。
func (s *Store) ClaimReminder(ctx context.Context, tenantID, id string, now, next time.Time) (workflow.Task, bool, error) {
	result := s.db.WithContext(ctx).Model(&workflow.Task{}).
		Where("tenant_id = ? AND id = ? AND status IN ? AND next_remind_at > ? AND next_remind_at <= ? AND (max_remind = 0 OR remind_count < max_remind)",
			tenantID, id, []string{workflow.TaskPending, workflow.TaskClaimed}, time.Unix(1, 0).UTC(), now).
		Updates(map[string]any{
			"remind_count":   gormlib.Expr("remind_count + 1"),
			"last_remind_at": now,
			"next_remind_at": next,
			"updated_at":     now,
		})
	if result.Error != nil {
		return workflow.Task{}, false, result.Error
	}
	if result.RowsAffected == 0 {
		return workflow.Task{}, false, nil
	}
	var task workflow.Task
	if err := s.db.WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, id).First(&task).Error; err != nil {
		return workflow.Task{}, false, findOne(err)
	}
	return task, true, nil
}

// CreateEvent inserts one timeline event. | CreateEvent 插入一条时间线事件。
func (s *Store) CreateEvent(ctx context.Context, event workflow.Event) error {
	return create(s.db.WithContext(ctx).Create(&event).Error)
}

// ListEvents returns the newest events of one instance in ascending order. | ListEvents 按升序返回实例的最近事件。
func (s *Store) ListEvents(ctx context.Context, tenantID, instanceID string, limit int) ([]workflow.Event, error) {
	if limit <= 0 {
		limit = 200
	}
	ids := make([]string, 0, listCapacity(limit))
	if err := s.db.WithContext(ctx).Model(&workflow.Event{}).Select("id").
		Where("tenant_id = ? AND instance_id = ?", tenantID, instanceID).
		Order("created_at DESC").Limit(limit).Pluck("id", &ids).Error; err != nil {
		return nil, err
	}
	items := make([]workflow.Event, 0, len(ids))
	if len(ids) == 0 {
		return items, nil
	}
	if err := s.db.WithContext(ctx).Where("id IN ?", ids).Order("created_at ASC").Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

// CreateComment inserts one comment. | CreateComment 插入一条评论。
func (s *Store) CreateComment(ctx context.Context, comment workflow.Comment) error {
	return create(s.db.WithContext(ctx).Create(&comment).Error)
}

// ListComments returns comments in ascending order. | ListComments 按升序返回评论。
func (s *Store) ListComments(ctx context.Context, tenantID, instanceID string, limit int) ([]workflow.Comment, error) {
	if limit <= 0 {
		limit = 200
	}
	items := make([]workflow.Comment, 0, listCapacity(limit))
	if err := s.db.WithContext(ctx).
		Where("tenant_id = ? AND instance_id = ?", tenantID, instanceID).
		Order("created_at ASC").Limit(limit).Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

// CreateNotification inserts one outbox row. | CreateNotification 插入一条发件箱记录。
func (s *Store) CreateNotification(ctx context.Context, note workflow.Notification) error {
	if note.Status == "" {
		note.Status = workflow.NotificationPending
	}
	return create(s.db.WithContext(ctx).Create(&note).Error)
}

// UpdateNotification updates delivery state. | UpdateNotification 更新投递状态。
func (s *Store) UpdateNotification(ctx context.Context, note workflow.Notification) error {
	result := s.db.WithContext(ctx).Model(&workflow.Notification{}).
		Where("tenant_id = ? AND id = ?", note.TenantID, note.ID).
		Select("status", "attempts", "last_error", "sent_at", "next_attempt_at", "updated_at").
		Updates(&note)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return workflow.ErrNotFound
	}
	return nil
}

// ClaimNotification leases one pending notification to this node. | ClaimNotification 把一条待投递通知租给当前节点。
func (s *Store) ClaimNotification(ctx context.Context, tenantID, id string, now, leaseUntil time.Time) (workflow.Notification, bool, error) {
	result := s.db.WithContext(ctx).Model(&workflow.Notification{}).
		Where("tenant_id = ? AND id = ? AND status = ? AND next_attempt_at <= ?", tenantID, id, workflow.NotificationPending, now).
		Updates(map[string]any{"next_attempt_at": leaseUntil, "updated_at": now})
	if result.Error != nil {
		return workflow.Notification{}, false, result.Error
	}
	if result.RowsAffected == 0 {
		return workflow.Notification{}, false, nil
	}
	var note workflow.Notification
	if err := s.db.WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, id).First(&note).Error; err != nil {
		return workflow.Notification{}, false, findOne(err)
	}
	return note, true, nil
}

// ListPendingNotifications returns pending notifications whose retry time has arrived. |
// ListPendingNotifications 返回重试时间已到的待投递通知。
func (s *Store) ListPendingNotifications(ctx context.Context, now time.Time, limit int) ([]workflow.Notification, error) {
	items := make([]workflow.Notification, 0, listCapacity(limit))
	if err := s.db.WithContext(ctx).
		Where("status = ? AND next_attempt_at <= ?", workflow.NotificationPending, now).
		Order("next_attempt_at ASC").Limit(limit).Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

// sqlLiteral quotes a fixed internal constant for a CASE expression. | sqlLiteral 为 CASE 表达式
// 引用固定的内部常量。
func sqlLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

// Stats returns the tenant summary. Each table is read once with conditional aggregation instead
// of one COUNT round trip per status: the overview page used to issue nine queries per render. |
// Stats 返回租户汇总。每张表用条件聚合读取一次，而不是为每个状态各发一次 COUNT：概览页过去每次
// 渲染要发九条查询。
func (s *Store) Stats(ctx context.Context, tenantID string) (workflow.Stats, error) {
	stats := workflow.Stats{}
	var definitions struct {
		Definitions int
		Published   int
	}
	if err := s.db.WithContext(ctx).Model(&workflow.Definition{}).
		Select("COUNT(*) AS definitions, COUNT(CASE WHEN status = "+sqlLiteral(workflow.DefinitionPublished)+" THEN 1 END) AS published").
		Where("tenant_id = ?", tenantID).Scan(&definitions).Error; err != nil {
		return stats, err
	}
	stats.Definitions = definitions.Definitions
	stats.Published = definitions.Published
	var instances struct {
		Instances int
		Running   int
		Completed int
		Withdrawn int
		Rejected  int
	}
	if err := s.db.WithContext(ctx).Model(&workflow.Instance{}).
		Select("COUNT(*) AS instances, "+
			"COUNT(CASE WHEN status = "+sqlLiteral(workflow.InstanceRunning)+" THEN 1 END) AS running, "+
			"COUNT(CASE WHEN outcome = 'approved' THEN 1 END) AS completed, "+
			"COUNT(CASE WHEN status = "+sqlLiteral(workflow.InstanceWithdrawn)+" THEN 1 END) AS withdrawn, "+
			"COUNT(CASE WHEN outcome = 'rejected' THEN 1 END) AS rejected").
		Where("tenant_id = ?", tenantID).Scan(&instances).Error; err != nil {
		return stats, err
	}
	stats.Instances = instances.Instances
	stats.Running = instances.Running
	stats.Completed = instances.Completed
	stats.Withdrawn = instances.Withdrawn
	stats.Rejected = instances.Rejected
	var tasks struct {
		PendingTasks int
	}
	openStatuses := sqlLiteral(workflow.TaskPending) + ", " + sqlLiteral(workflow.TaskClaimed)
	if err := s.db.WithContext(ctx).Model(&workflow.Task{}).
		Select("COUNT(CASE WHEN status IN ("+openStatuses+") THEN 1 END) AS pending_tasks").
		Where("tenant_id = ?", tenantID).Scan(&tasks).Error; err != nil {
		return stats, err
	}
	stats.PendingTasks = tasks.PendingTasks
	var overdue int64
	if err := s.db.WithContext(ctx).Model(&workflow.Task{}).
		Where("tenant_id = ? AND status IN ? AND due_at > ? AND due_at < ?", tenantID,
			[]string{workflow.TaskPending, workflow.TaskClaimed}, time.Unix(1, 0).UTC(), time.Now().UTC()).
		Count(&overdue).Error; err != nil {
		return stats, err
	}
	stats.OverdueTasks = int(overdue)
	return stats, nil
}

// compile-time assertion that *Store implements workflow.Store. | *Store 实现 workflow.Store 的编译期断言。
var _ workflow.Store = (*Store)(nil)

// listCapacity keeps a caller-supplied limit from preallocating hundreds of rows on a query that
// usually returns none. Drawer queries ask for up to 500 comments; preallocating all of them for
// an empty result made one read allocate roughly a hundred kilobytes. The slice grows on demand,
// so a busy page at most copies a few times. | listCapacity 避免调用方传入的上限在通常没有结果的
// 查询上预分配数百行。抽屉查询最多请求 500 条评论；为空结果预分配全部容量会让一次读取分配约
// 一百 KB。切片按需增长，真正繁忙的页面最多多复制几次。
func listCapacity(limit int) int {
	if limit <= 0 {
		return 8
	}
	if limit > 32 {
		return 32
	}
	return limit
}

// CreateGroup inserts one workflow group. | CreateGroup 插入一个流程组。
func (s *Store) CreateGroup(ctx context.Context, group workflow.Group) error {
	return create(s.db.WithContext(ctx).Create(&group).Error)
}

// UpdateGroup updates one workflow group. | UpdateGroup 更新一个流程组。
func (s *Store) UpdateGroup(ctx context.Context, group workflow.Group) error {
	result := s.db.WithContext(ctx).Model(&workflow.Group{}).
		Where("tenant_id = ? AND id = ?", group.TenantID, group.ID).
		Select("name", "name_en", "description", "linked_role", "status", "updated_at").
		Updates(&group)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return workflow.ErrNotFound
	}
	return nil
}

// DeleteGroup deletes one group and its members. | DeleteGroup 删除一个组及其成员。
func (s *Store) DeleteGroup(ctx context.Context, tenantID, id string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gormlib.DB) error {
		if err := tx.Where("tenant_id = ? AND group_id = ?", tenantID, id).Delete(&workflow.GroupMember{}).Error; err != nil {
			return err
		}
		result := tx.Where("tenant_id = ? AND id = ?", tenantID, id).Delete(&workflow.Group{})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return workflow.ErrNotFound
		}
		return nil
	})
}

// GetGroup reads one group. | GetGroup 读取一个组。
func (s *Store) GetGroup(ctx context.Context, tenantID, id string) (workflow.Group, error) {
	var group workflow.Group
	err := s.db.WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, id).First(&group).Error
	if err != nil {
		return group, findOne(err)
	}
	s.fillGroupCounts(ctx, tenantID, []workflow.Group{group})
	return group, nil
}

// GetGroupByKey reads one group by key. | GetGroupByKey 按键读取一个组。
func (s *Store) GetGroupByKey(ctx context.Context, tenantID, key string) (workflow.Group, error) {
	var group workflow.Group
	err := s.db.WithContext(ctx).Where("tenant_id = ? AND group_key = ?", tenantID, key).First(&group).Error
	if err != nil {
		return group, findOne(err)
	}
	s.fillGroupCounts(ctx, tenantID, []workflow.Group{group})
	return group, nil
}

// ListGroups returns one page of groups. | ListGroups 返回一页组。
func (s *Store) ListGroups(ctx context.Context, tenantID string, filter workflow.GroupFilter) ([]workflow.Group, int, error) {
	query := s.db.WithContext(ctx).Model(&workflow.Group{}).Where("tenant_id = ?", tenantID)
	if filter.Status != "" {
		query = query.Where("status = ?", filter.Status)
	}
	if filter.Query != "" {
		pattern := likeAll(filter.Query)
		query = query.Where("(group_key LIKE ? ESCAPE '!' OR name LIKE ? ESCAPE '!' OR name_en LIKE ? ESCAPE '!')", pattern, pattern, pattern)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	items := make([]workflow.Group, 0, listCapacity(filter.PageSize))
	offset := (filter.Page - 1) * filter.PageSize
	if err := query.Order("updated_at DESC").Offset(offset).Limit(filter.PageSize).Find(&items).Error; err != nil {
		return nil, 0, err
	}
	s.fillGroupCounts(ctx, tenantID, items)
	return items, int(total), nil
}

// fillGroupCounts adds explicit member counts to a page of groups. | fillGroupCounts 为组页补充显式成员数。
func (s *Store) fillGroupCounts(ctx context.Context, tenantID string, items []workflow.Group) {
	if len(items) == 0 {
		return
	}
	ids := make([]string, 0, len(items))
	for i := range items {
		ids = append(ids, items[i].ID)
	}
	rows := []struct {
		GroupID string `gorm:"column:group_id"`
		Total   int    `gorm:"column:total"`
	}{}
	if err := s.db.WithContext(ctx).Model(&workflow.GroupMember{}).
		Select("group_id, COUNT(*) AS total").
		Where("tenant_id = ? AND group_id IN ?", tenantID, ids).
		Group("group_id").Scan(&rows).Error; err != nil {
		return
	}
	counts := make(map[string]int, len(rows))
	for _, row := range rows {
		counts[row.GroupID] = row.Total
	}
	for i := range items {
		items[i].MemberCount = counts[items[i].ID]
	}
}

// ListGroupsByUser returns the enabled groups a user explicitly belongs to. | ListGroupsByUser
// 返回用户显式隶属的启用组。
func (s *Store) ListGroupsByUser(ctx context.Context, tenantID, userID string) ([]workflow.Group, error) {
	items := make([]workflow.Group, 0, 4)
	err := s.db.WithContext(ctx).
		Where("tenant_id = ? AND id IN (?) AND status = ?", tenantID,
			s.db.WithContext(ctx).Model(&workflow.GroupMember{}).Select("group_id").
				Where("tenant_id = ? AND user_id = ?", tenantID, userID),
			workflow.GroupEnabled).
		Order("group_key ASC").Find(&items).Error
	if err != nil {
		return nil, err
	}
	return items, nil
}

// ListGroupMembers returns the explicit members of one group. | ListGroupMembers 返回组的显式成员。
func (s *Store) ListGroupMembers(ctx context.Context, tenantID, groupID string) ([]workflow.GroupMember, error) {
	items := make([]workflow.GroupMember, 0, 8)
	if err := s.db.WithContext(ctx).
		Where("tenant_id = ? AND group_id = ?", tenantID, groupID).
		Order("created_at ASC").Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

// AddGroupMember inserts one member idempotently. A duplicate is success, which keeps the
// call portable: ON CONFLICT is not available on every GORM dialect. | AddGroupMember 幂等插入一名成员。
// 重复视为成功，从而保持可移植：并非每种 GORM 方言都支持 ON CONFLICT。
func (s *Store) AddGroupMember(ctx context.Context, member workflow.GroupMember) error {
	err := s.db.WithContext(ctx).Create(&member).Error
	if errors.Is(err, gormlib.ErrDuplicatedKey) {
		return nil
	}
	return err
}

// RemoveGroupMember removes one member. | RemoveGroupMember 移除一名成员。
func (s *Store) RemoveGroupMember(ctx context.Context, tenantID, groupID, userID string) error {
	return s.db.WithContext(ctx).
		Where("tenant_id = ? AND group_id = ? AND user_id = ?", tenantID, groupID, userID).
		Delete(&workflow.GroupMember{}).Error
}

// ListDueTimerTokens returns waiting timer tokens whose deadline has passed. | ListDueTimerTokens
// 返回截止时间已过的等待定时令牌。
func (s *Store) ListDueTimerTokens(ctx context.Context, now time.Time, limit int) ([]workflow.Token, error) {
	items := make([]workflow.Token, 0, listCapacity(limit))
	if err := s.db.WithContext(ctx).
		Where("status = ? AND wait_type = ? AND wait_until > ? AND wait_until <= ?",
			workflow.TokenWaiting, workflow.WaitTimer, time.Unix(1, 0).UTC(), now).
		Order("wait_until ASC").Limit(limit).Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

// ListMessageTokens returns waiting message tokens matching one instance and signal. |
// ListMessageTokens 返回匹配实例与信号的等待消息令牌。
func (s *Store) ListMessageTokens(ctx context.Context, tenantID, instanceID, messageName string) ([]workflow.Token, error) {
	query := s.db.WithContext(ctx).Where("tenant_id = ? AND instance_id = ? AND status = ? AND wait_type = ?",
		tenantID, instanceID, workflow.TokenWaiting, workflow.WaitMessage)
	if messageName != "" {
		query = query.Where("message_name = ?", messageName)
	}
	items := make([]workflow.Token, 0, 4)
	if err := query.Order("created_at ASC").Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

// CancelWaitGroup cancels the other competitors of one event gateway. | CancelWaitGroup
// 取消一个事件网关的其它竞争令牌。
func (s *Store) CancelWaitGroup(ctx context.Context, tenantID, instanceID, waitGroup, exceptID string, now time.Time) error {
	if waitGroup == "" {
		return nil
	}
	return s.db.WithContext(ctx).Model(&workflow.Token{}).
		Where("tenant_id = ? AND instance_id = ? AND wait_group = ? AND id <> ? AND status = ?",
			tenantID, instanceID, waitGroup, exceptID, workflow.TokenWaiting).
		Updates(map[string]any{"status": workflow.TokenCancelled, "updated_at": now}).Error
}
