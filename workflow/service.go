package workflow

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
	ydlog "github.com/shibingli/ydx/log"
)

// Deps carries the optional collaborators of a workflow service. | Deps 承载流程服务的可选协作者。
type Deps struct {
	// Directory resolves assignees; nil makes user and role assignment unavailable. | Directory 解析审批人；
	// 为 nil 时用户与角色指派不可用。
	Directory Directory
	// Decider is the optional AI automatic-approval decider. | Decider 是可选的 AI 自动审批决策器。
	Decider Decider
	// Dispatcher delivers queued notifications; nil keeps them pending for a scheduler. | Dispatcher
	// 投递排队的通知；为 nil 时保持待投递，由调度器稍后处理。
	Dispatcher *Dispatcher
	// Logger records delivery failures and automatic decisions. | Logger 记录投递失败与自动决策。
	Logger *ydlog.Logger
	// Notify tunes notification rendering, language and deep links. | Notify 调整通知渲染、语言与深链。
	Notify NotificationOptions
	// Options tune limits, windows and defaults. | Options 调整上限、窗口与默认值。
	Options Options
}

// Service implements the workflow domain over a Store. | Service 在 Store 之上实现流程域。
type Service struct {
	// store persists every row. | store 持久化全部数据行。
	store Store
	// directory resolves assignees and their roles. | directory 解析审批人及其角色。
	directory Directory
	// decider is the optional AI automatic-approval decision maker. | decider 是可选的 AI 自动审批决策器。
	decider Decider
	// dispatcher delivers queued notifications. | dispatcher 投递排队通知。
	dispatcher *Dispatcher
	// log records background failures. | log 记录后台失败。
	log *ydlog.Logger
	// notificationOptions tune notification rendering and retries. | notificationOptions 调整通知渲染与重试。
	notificationOptions NotificationOptions
	// versions caches parsed published versions. | versions 缓存已解析的已发布版本。
	versions *runtimeVersionCache
	// options are the normalized effective options. | options 是归一化后的生效选项。
	options Options
}

// New constructs a workflow service. A nil store is refused; every other collaborator is optional
// and degrades to a documented failure mode. | New 构造流程服务。存储为空会被拒绝；其余协作者可选，
// 缺失时退化为文档化的失败模式。
func New(store Store, deps Deps) (*Service, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	logger := deps.Logger
	if logger == nil {
		logger = ydlog.Default()
	}
	svc := &Service{
		directory:           deps.Directory,
		decider:             deps.Decider,
		dispatcher:          deps.Dispatcher,
		log:                 logger,
		options:             deps.Options.normalize(),
		notificationOptions: normalizeNotificationOptions(deps.Notify),
		versions:            newRuntimeVersionCache(),
	}
	// The wrapper keeps external AI calls outside transaction scopes. | 包装层把外部 AI 调用挡在事务之外。
	svc.store = &aiDeferringStore{Store: store, svc: svc}
	return svc, nil
}

// Options returns the effective options. | Options 返回生效选项。
func (s *Service) Options() Options { return s.options }

// SetDispatcher attaches or replaces the notification dispatcher. It exists so a project can
// construct the service before its messaging dependency. | SetDispatcher 挂载或替换通知分发器。
// 它让项目可以在消息中心依赖就绪之前先构造服务。
func (s *Service) SetDispatcher(dispatcher *Dispatcher) { s.dispatcher = dispatcher }

// SetDecider attaches or replaces the optional AI decider. | SetDecider 挂载或替换可选的 AI 决策器。
func (s *Service) SetDecider(decider Decider) { s.decider = decider }

// CreateDefinition inserts one draft definition. | CreateDefinition 插入一个草稿定义。
func (s *Service) CreateDefinition(ctx context.Context, tenantID, actorID string, in DefinitionInput) (Definition, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Definition{}, ErrInvalidInput
	}
	in, err := s.normalizeDefinitionInput(in, true)
	if err != nil {
		return Definition{}, err
	}
	if _, err := s.store.GetDefinitionByKey(ctx, tenantID, in.Key); err == nil {
		return Definition{}, ErrConflict
	} else if !errors.Is(err, ErrNotFound) {
		return Definition{}, err
	}
	id, err := s.options.NewID("wfdef_")
	if err != nil {
		return Definition{}, errs.Wrap(err, ErrUnavailable)
	}
	now := s.options.Now().UTC()
	created := Definition{
		CreatedAt:   now,
		UpdatedAt:   now,
		ID:          id,
		TenantID:    tenantID,
		Key:         in.Key,
		Name:        in.Name,
		NameEN:      in.NameEN,
		Description: in.Description,
		Category:    in.Category,
		Icon:        in.Icon,
		// A definition never starts published: publication is granted by a published version. |
		// 定义不会一开始就发布：发布状态由已发布版本授予。
		Status:    DefinitionDraft,
		CreatedBy: strings.TrimSpace(actorID),
		UpdatedBy: strings.TrimSpace(actorID),
	}
	if err := s.store.CreateDefinition(ctx, created); err != nil {
		return Definition{}, err
	}
	return created, nil
}

// UpdateDefinition replaces the editable fields of a definition. The key is immutable. | UpdateDefinition
// 覆盖定义的可编辑字段；键不可变。
func (s *Service) UpdateDefinition(ctx context.Context, tenantID, id, actorID string, in DefinitionInput) (Definition, error) {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return Definition{}, ErrInvalidInput
	}
	current, err := s.store.GetDefinition(ctx, tenantID, id)
	if err != nil {
		return Definition{}, err
	}
	if in.Status == "" {
		in.Status = current.Status
	}
	in, err = s.normalizeDefinitionInput(in, false)
	if err != nil {
		return Definition{}, err
	}
	if in.Status == DefinitionPublished && current.CurrentVersion <= 0 {
		return Definition{}, errs.Detail(ErrInvalidInput, "publish a version before publishing the definition | 请先发布一个版本再启用定义")
	}
	current.Name = in.Name
	current.NameEN = in.NameEN
	current.Description = in.Description
	current.Category = in.Category
	current.Icon = in.Icon
	current.Status = in.Status
	current.UpdatedBy = strings.TrimSpace(actorID)
	current.UpdatedAt = s.options.Now().UTC()
	if err := s.store.UpdateDefinition(ctx, current); err != nil {
		return Definition{}, err
	}
	return current, nil
}

// SetDefinitionStatus enables, disables or drafts one definition. | SetDefinitionStatus 启用、停用或恢复草稿状态。
func (s *Service) SetDefinitionStatus(ctx context.Context, tenantID, id, actorID, status string) (Definition, error) {
	status = strings.TrimSpace(status)
	switch status {
	case DefinitionDraft, DefinitionPublished, DefinitionDisabled:
	default:
		return Definition{}, ErrInvalidInput
	}
	current, err := s.store.GetDefinition(ctx, tenantID, id)
	if err != nil {
		return Definition{}, err
	}
	if status == DefinitionPublished && current.CurrentVersion <= 0 {
		return Definition{}, errs.Detail(ErrInvalidInput, "publish a version before enabling the definition | 请先发布一个版本再启用定义")
	}
	current.Status = status
	current.UpdatedBy = strings.TrimSpace(actorID)
	current.UpdatedAt = s.options.Now().UTC()
	if err := s.store.UpdateDefinition(ctx, current); err != nil {
		return Definition{}, err
	}
	return current, nil
}

// DeleteDefinition removes a definition that has no instances. Its versions are removed in the
// same transaction by the store. | DeleteDefinition 删除没有实例的定义；其版本由存储在同一事务内删除。
func (s *Service) DeleteDefinition(ctx context.Context, tenantID, id string) error {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return ErrInvalidInput
	}
	current, err := s.store.GetDefinition(ctx, tenantID, id)
	if err != nil {
		return err
	}
	_, total, err := s.store.ListInstances(ctx, tenantID, InstanceFilter{DefinitionID: current.ID, Page: 1, PageSize: 1})
	if err != nil {
		return err
	}
	if total > 0 {
		return errs.Detail(ErrDefinitionPublished, "definition %[1]q has %[2]d instances | 定义 %[1]q 仍有 %[2]d 个实例", current.Key, total)
	}
	return s.store.DeleteDefinition(ctx, tenantID, current.ID)
}

// GetDefinition reads one definition inside the tenant. | GetDefinition 读取租户内的一个定义。
func (s *Service) GetDefinition(ctx context.Context, tenantID, id string) (Definition, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(id) == "" {
		return Definition{}, ErrInvalidInput
	}
	return s.store.GetDefinition(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(id))
}

// GetDefinitionByKey reads one definition by its immutable key. | GetDefinitionByKey 按不可变键读取定义。
func (s *Service) GetDefinitionByKey(ctx context.Context, tenantID, key string) (Definition, error) {
	tenantID = strings.TrimSpace(tenantID)
	key = strings.ToLower(strings.TrimSpace(key))
	if tenantID == "" || !keyRe.MatchString(key) {
		return Definition{}, ErrInvalidInput
	}
	return s.store.GetDefinitionByKey(ctx, tenantID, key)
}

// ListDefinitions returns one page of definitions. | ListDefinitions 返回一页流程定义。
func (s *Service) ListDefinitions(ctx context.Context, tenantID string, filter DefinitionFilter) (DefinitionPage, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return DefinitionPage{}, ErrInvalidInput
	}
	filter.Query = strings.TrimSpace(filter.Query)
	filter.Category = strings.TrimSpace(filter.Category)
	if len([]rune(filter.Query)) > 128 {
		return DefinitionPage{}, ErrInvalidInput
	}
	if filter.Status != "" {
		switch filter.Status {
		case DefinitionDraft, DefinitionPublished, DefinitionDisabled:
		default:
			return DefinitionPage{}, ErrInvalidInput
		}
	}
	filter.Page, filter.PageSize = s.page(filter.Page, filter.PageSize)
	items, total, err := s.store.ListDefinitions(ctx, tenantID, filter)
	if err != nil {
		return DefinitionPage{}, err
	}
	if len(items) > 0 {
		ids := make([]string, 0, len(items))
		for i := range items {
			ids = append(ids, items[i].ID)
		}
		if reader, ok := s.store.(definitionMetricsReader); ok {
			// Two grouped counts replace two round trips per definition. The fallback below keeps
			// custom stores working without the optional extension. | 两条分组统计取代每个定义
			// 两次往返；下面的回退让未实现可选扩展的自定义存储照常工作。
			versionCounts, err := reader.CountVersionsForDefinitions(ctx, tenantID, ids)
			if err != nil {
				return DefinitionPage{}, err
			}
			instanceCounts, err := reader.CountInstancesForDefinitions(ctx, tenantID, ids)
			if err != nil {
				return DefinitionPage{}, err
			}
			for i := range items {
				items[i].VersionCount = versionCounts[items[i].ID]
				items[i].InstanceCount = instanceCounts[items[i].ID]
			}
		} else {
			for i := range items {
				versions, err := s.store.ListVersions(ctx, tenantID, items[i].ID)
				if err != nil {
					return DefinitionPage{}, err
				}
				items[i].VersionCount = len(versions)
				_, instances, err := s.store.ListInstances(ctx, tenantID, InstanceFilter{DefinitionID: items[i].ID, Page: 1, PageSize: 1})
				if err != nil {
					return DefinitionPage{}, err
				}
				items[i].InstanceCount = instances
			}
		}
	}
	return DefinitionPage{Items: items, Total: total, Page: filter.Page, PageSize: filter.PageSize}, nil
}

// CreateVersion appends one draft version to a definition. | CreateVersion 为定义追加一个草稿版本。
func (s *Service) CreateVersion(ctx context.Context, tenantID, definitionID, actorID string, in VersionInput) (Version, error) {
	tenantID = strings.TrimSpace(tenantID)
	definitionID = strings.TrimSpace(definitionID)
	if tenantID == "" || definitionID == "" {
		return Version{}, ErrInvalidInput
	}
	def, err := s.store.GetDefinition(ctx, tenantID, definitionID)
	if err != nil {
		return Version{}, err
	}
	design, canonical, err := s.normalizeDesign(in.Design)
	if err != nil {
		return Version{}, err
	}
	number, err := s.store.NextVersionNumber(ctx, tenantID, def.ID)
	if err != nil {
		return Version{}, err
	}
	id, err := s.options.NewID("wfver_")
	if err != nil {
		return Version{}, errs.Wrap(err, ErrUnavailable)
	}
	now := s.options.Now().UTC()
	bpmn, err := BuildBPMN(def, number, design)
	if err != nil {
		return Version{}, err
	}
	note, ok := trimLen(in.Note, 500)
	if !ok {
		return Version{}, ErrInvalidInput
	}
	created := Version{
		CreatedAt:    now,
		UpdatedAt:    now,
		ID:           id,
		TenantID:     tenantID,
		DefinitionID: def.ID,
		Version:      number,
		Status:       VersionDraft,
		Design:       canonical,
		BPMN:         bpmn,
		Checksum:     checksum(canonical),
		Note:         note,
		CreatedBy:    strings.TrimSpace(actorID),
	}
	if err := s.store.CreateVersion(ctx, created); err != nil {
		return Version{}, err
	}
	return created, nil
}

// UpdateVersion replaces the design of one draft version. | UpdateVersion 覆盖一个草稿版本的设计。
func (s *Service) UpdateVersion(ctx context.Context, tenantID, versionID, actorID string, in VersionInput) (Version, error) {
	tenantID = strings.TrimSpace(tenantID)
	versionID = strings.TrimSpace(versionID)
	if tenantID == "" || versionID == "" {
		return Version{}, ErrInvalidInput
	}
	current, err := s.store.GetVersion(ctx, tenantID, versionID)
	if err != nil {
		return Version{}, err
	}
	if current.Status != VersionDraft {
		return Version{}, ErrVersionPublished
	}
	def, err := s.store.GetDefinition(ctx, tenantID, current.DefinitionID)
	if err != nil {
		return Version{}, err
	}
	design, canonical, err := s.normalizeDesign(in.Design)
	if err != nil {
		return Version{}, err
	}
	bpmn, err := BuildBPMN(def, current.Version, design)
	if err != nil {
		return Version{}, err
	}
	note, ok := trimLen(in.Note, 500)
	if !ok {
		return Version{}, ErrInvalidInput
	}
	current.Design = canonical
	current.BPMN = bpmn
	current.Checksum = checksum(canonical)
	current.Note = note
	current.UpdatedAt = s.options.Now().UTC()
	current.CreatedBy = strings.TrimSpace(actorID)
	if err := s.store.UpdateVersion(ctx, current); err != nil {
		return Version{}, err
	}
	return current, nil
}

// DeleteVersion removes one draft version. A published version is immutable and permanent. |
// DeleteVersion 删除一个草稿版本；已发布版本不可变且永久保留。
func (s *Service) DeleteVersion(ctx context.Context, tenantID, versionID string) error {
	tenantID = strings.TrimSpace(tenantID)
	versionID = strings.TrimSpace(versionID)
	if tenantID == "" || versionID == "" {
		return ErrInvalidInput
	}
	current, err := s.store.GetVersion(ctx, tenantID, versionID)
	if err != nil {
		return err
	}
	if current.Status != VersionDraft {
		return ErrVersionPublished
	}
	return s.store.DeleteVersion(ctx, tenantID, current.ID)
}

// PublishVersion freezes a draft and makes it the latest usable version. Previous published
// versions remain readable and keep serving their running instances. | PublishVersion 冻结草稿并
// 使其成为最新可用版本。此前的已发布版本仍然可读，并继续服务其运行中的实例。
func (s *Service) PublishVersion(ctx context.Context, tenantID, versionID, actorID, note string) (Version, error) {
	tenantID = strings.TrimSpace(tenantID)
	versionID = strings.TrimSpace(versionID)
	if tenantID == "" || versionID == "" {
		return Version{}, ErrInvalidInput
	}
	now := s.options.Now().UTC()
	var published Version
	err := s.store.WithTx(ctx, func(st Store) error {
		current, err := st.GetVersion(ctx, tenantID, versionID)
		if err != nil {
			return err
		}
		if current.Status != VersionDraft {
			return ErrVersionPublished
		}
		def, err := st.GetDefinition(ctx, tenantID, current.DefinitionID)
		if err != nil {
			return err
		}
		design, err := parseDesign(current.Design)
		if err != nil {
			return err
		}
		if _, _, err := s.normalizeDesign(design); err != nil {
			return err
		}
		trimmedNote, ok := trimLen(note, 500)
		if !ok {
			return ErrInvalidInput
		}
		current.Status = VersionPublished
		current.PublishedAt = now
		current.PublishedBy = strings.TrimSpace(actorID)
		current.UpdatedAt = now
		if trimmedNote != "" {
			current.Note = trimmedNote
		}
		if err := st.UpdateVersion(ctx, current); err != nil {
			return err
		}
		def.Status = DefinitionPublished
		def.CurrentVersion = current.Version
		def.UpdatedBy = strings.TrimSpace(actorID)
		def.UpdatedAt = now
		if err := st.UpdateDefinition(ctx, def); err != nil {
			return err
		}
		published = current
		return nil
	})
	if err != nil {
		return Version{}, err
	}
	return published, nil
}

// GetVersion reads one version inside the tenant. | GetVersion 读取租户内的一个版本。
func (s *Service) GetVersion(ctx context.Context, tenantID, versionID string) (Version, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(versionID) == "" {
		return Version{}, ErrInvalidInput
	}
	return s.store.GetVersion(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(versionID))
}

// LatestPublishedVersion returns the newest published version together with its parsed design.
// The start drawer needs exactly one published version; listing every version would transfer draft
// designs and BPMN documents the caller has no use for. | LatestPublishedVersion 返回最新已发布
// 版本及其解析后的设计。发起抽屉只需要一个已发布版本；列出全部版本会传输调用方用不到的草稿设计
// 与 BPMN 文档。
func (s *Service) LatestPublishedVersion(ctx context.Context, tenantID, definitionID string) (Version, Design, error) {
	tenantID = strings.TrimSpace(tenantID)
	definitionID = strings.TrimSpace(definitionID)
	if tenantID == "" || definitionID == "" {
		return Version{}, Design{}, ErrInvalidInput
	}
	version, err := s.store.GetLatestPublishedVersion(ctx, tenantID, definitionID)
	if err != nil {
		return Version{}, Design{}, err
	}
	design, err := s.designOf(version)
	if err != nil {
		return Version{}, Design{}, err
	}
	return version, design, nil
}

// VersionSummariesForDefinitions loads lightweight version projections for several definitions.
// Lists need draft/published state and version numbers, not the design and BPMN payloads. |
// VersionSummariesForDefinitions 加载多个定义的轻量版本投影。列表只需要草稿/已发布状态与版本号，
// 不需要设计与 BPMN 载荷。
func (s *Service) VersionSummariesForDefinitions(ctx context.Context, tenantID string, definitionIDs []string) (map[string][]VersionSummary, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, ErrInvalidInput
	}
	ids := make([]string, 0, len(definitionIDs))
	seen := make(map[string]bool, len(definitionIDs))
	for _, id := range definitionIDs {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return map[string][]VersionSummary{}, nil
	}
	if reader, ok := s.store.(versionSummaryReader); ok {
		return reader.ListVersionSummariesForDefinitions(ctx, tenantID, ids)
	}
	out := make(map[string][]VersionSummary, len(ids))
	for _, id := range ids {
		items, err := s.store.ListVersions(ctx, tenantID, id)
		if err != nil {
			return nil, err
		}
		summaries := make([]VersionSummary, 0, len(items))
		for _, item := range items {
			summaries = append(summaries, VersionSummary{ID: item.ID, DefinitionID: item.DefinitionID, Status: item.Status, Version: item.Version, PublishedAt: item.PublishedAt, Note: item.Note})
		}
		out[id] = summaries
	}
	return out, nil
}

// ListVersions returns every version of one definition in descending version order. | ListVersions
// 按版本号降序返回一个定义的全部版本。
func (s *Service) ListVersions(ctx context.Context, tenantID, definitionID string) (VersionPage, error) {
	tenantID = strings.TrimSpace(tenantID)
	definitionID = strings.TrimSpace(definitionID)
	if tenantID == "" || definitionID == "" {
		return VersionPage{}, ErrInvalidInput
	}
	if _, err := s.store.GetDefinition(ctx, tenantID, definitionID); err != nil {
		return VersionPage{}, err
	}
	items, err := s.store.ListVersions(ctx, tenantID, definitionID)
	if err != nil {
		return VersionPage{}, err
	}
	return VersionPage{Items: items, Total: len(items)}, nil
}

// ListVersionSummaries returns every version of one definition without loading designs or BPMN
// documents; a single-version read returns the full document. | ListVersionSummaries 返回一个定义的
// 全部版本但不加载设计与 BPMN 文档；单版本读取返回完整文档。
func (s *Service) ListVersionSummaries(ctx context.Context, tenantID, definitionID string) (VersionSummaryPage, error) {
	tenantID = strings.TrimSpace(tenantID)
	definitionID = strings.TrimSpace(definitionID)
	if tenantID == "" || definitionID == "" {
		return VersionSummaryPage{}, ErrInvalidInput
	}
	if _, err := s.store.GetDefinition(ctx, tenantID, definitionID); err != nil {
		return VersionSummaryPage{}, err
	}
	byDefinition, err := s.VersionSummariesForDefinitions(ctx, tenantID, []string{definitionID})
	if err != nil {
		return VersionSummaryPage{}, err
	}
	items := byDefinition[definitionID]
	return VersionSummaryPage{Items: items, Total: len(items)}, nil
}

// DesignOf parses the design stored on one version. | DesignOf 解析版本上存储的设计。
func DesignOf(version Version) (Design, error) {
	return parseDesign(version.Design)
}

// loadVersion returns one version and its parsed design, using the bounded published-version cache
// when possible. Published versions cannot be edited or deleted, so a cache hit is always current;
// drafts bypass the cache because UpdateVersion may change them at any time. | loadVersion 返回一个
// 版本及其解析后的设计，尽可能使用有界已发布版本缓存。已发布版本不可编辑也不可删除，因此缓存命中
// 始终是最新数据；草稿绕过缓存，因为 UpdateVersion 随时可以修改它们。
func (s *Service) loadVersion(ctx context.Context, st Store, tenantID, versionID string) (Version, Design, error) {
	key := runtimeVersionKey{TenantID: tenantID, VersionID: versionID}
	if version, design, ok := s.versions.get(key); ok {
		return version, design, nil
	}
	version, err := st.GetVersion(ctx, tenantID, versionID)
	if err != nil {
		return Version{}, Design{}, err
	}
	design, err := DesignOf(version)
	if err != nil {
		return Version{}, Design{}, err
	}
	if version.Status == VersionPublished {
		s.versions.put(key, version, design)
	}
	return version, design, nil
}

// designOf parses an already loaded version, reusing or filling the published-version cache. |
// designOf 解析一个已加载的版本，复用或填充已发布版本缓存。
func (s *Service) designOf(version Version) (Design, error) {
	if version.Status != VersionPublished {
		return DesignOf(version)
	}
	key := runtimeVersionKey{TenantID: version.TenantID, VersionID: version.ID}
	if _, design, ok := s.versions.get(key); ok {
		return design, nil
	}
	design, err := DesignOf(version)
	if err != nil {
		return Design{}, err
	}
	s.versions.put(key, version, design)
	return design, nil
}

// parseDesign decodes a canonical design document. | parseDesign 解码规范化设计文档。
func parseDesign(raw string) (Design, error) {
	design := Design{}
	if err := json.Unmarshal([]byte(raw), &design); err != nil {
		return Design{}, errs.Wrap(err, ErrInvalidDesign)
	}
	if design.Forms == nil {
		design.Forms = map[string][]FormField{}
	}
	if design.SchemaVersion <= 0 {
		design.SchemaVersion = 1
	}
	design.index = buildDesignIndex(design)
	return design, nil
}

// page clamps a requested page and page size into the configured range. | page 把请求的页码与页长收敛到配置范围。
func (s *Service) page(page, size int) (int, int) {
	if page <= 0 {
		page = 1
	}
	if size <= 0 {
		size = s.options.PageSize
	}
	if size > s.options.MaxPageSize {
		size = s.options.MaxPageSize
	}
	return page, size
}

// now returns the service clock in UTC. | now 返回 UTC 下的服务时钟。
func (s *Service) now() time.Time { return s.options.Now().UTC() }
