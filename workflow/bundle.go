package workflow

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// BundleSchemaVersion is the current JSON bundle schema. | BundleSchemaVersion 是当前 JSON 流程包 schema。
const BundleSchemaVersion = 1

// Bundle is a portable collection of definitions and versions. | Bundle 是可移植的流程定义与版本集合。
type Bundle struct {
	// ExportedAt is the UTC export instant. | ExportedAt 是 UTC 导出时刻。
	ExportedAt time.Time `json:"exported_at"`
	// Definitions are the exported definitions. | Definitions 是导出的定义。
	Definitions []BundleDefinition `json:"definitions"`
	// SchemaVersion is the bundle schema version. | SchemaVersion 是流程包 schema 版本。
	SchemaVersion int `json:"schema_version"`
}

// BundleDefinition is one definition inside a bundle. | BundleDefinition 是流程包中的一个定义。
type BundleDefinition struct {
	// Key is the immutable definition key. | Key 是不可变定义键。
	Key string `json:"key"`
	// Name, NameEN, Description, Category and Icon are the definition metadata. | Name、NameEN、
	// Description、Category 与 Icon 是定义元数据。
	Name        string `json:"name"`
	NameEN      string `json:"name_en,omitempty"`
	Description string `json:"description,omitempty"`
	Category    string `json:"category,omitempty"`
	Icon        string `json:"icon,omitempty"`
	// Status is the definition lifecycle state. | Status 是定义生命周期状态。
	Status string `json:"status,omitempty"`
	// Versions are the exported versions in ascending order. | Versions 是按版本号升序导出的版本。
	Versions []BundleVersion `json:"versions"`
}

// BundleVersion is one version inside a bundle. | BundleVersion 是流程包中的一个版本。
type BundleVersion struct {
	// Status is draft or published. | Status 取 draft 或 published。
	Status string `json:"status"`
	// Note is the draft or publication note. | Note 是草稿或发布说明。
	Note string `json:"note,omitempty"`
	// Design is the graph document. | Design 是图文档。
	Design Design `json:"design"`
	// Version is the version number; zero assigns the next number on import. | Version 是版本号；
	// 导入时零值表示分配下一个版本号。
	Version int `json:"version"`
}

// ImportReport summarises one import. | ImportReport 汇总一次导入。
type ImportReport struct {
	// Definitions is the number of definitions touched. | Definitions 是涉及的定义数量。
	Definitions int `json:"definitions"`
	// Created, Updated and Skipped count versions. | Created、Updated 与 Skipped 统计版本。
	Created int `json:"created"`
	Updated int `json:"updated"`
	Skipped int `json:"skipped"`
}

// ExportBundle exports the named definitions, or every definition when keys is empty. |
// ExportBundle 导出指定定义；keys 为空时导出全部定义。
func (s *Service) ExportBundle(ctx context.Context, tenantID string, keys []string) (Bundle, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Bundle{}, ErrInvalidInput
	}
	wanted := map[string]bool{}
	for _, key := range keys {
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			continue
		}
		if !keyRe.MatchString(key) {
			return Bundle{}, ErrInvalidInput
		}
		wanted[key] = true
	}
	definitions, err := s.allDefinitions(ctx, tenantID)
	if err != nil {
		return Bundle{}, err
	}
	bundle := Bundle{SchemaVersion: BundleSchemaVersion, ExportedAt: s.now()}
	for _, def := range definitions {
		if len(wanted) > 0 && !wanted[def.Key] {
			continue
		}
		versions, err := s.store.ListVersions(ctx, tenantID, def.ID)
		if err != nil {
			return Bundle{}, err
		}
		entry := BundleDefinition{
			Key:         def.Key,
			Name:        def.Name,
			NameEN:      def.NameEN,
			Description: def.Description,
			Category:    def.Category,
			Icon:        def.Icon,
			Status:      def.Status,
			Versions:    make([]BundleVersion, 0, len(versions)),
		}
		for _, version := range versions {
			design, err := DesignOf(version)
			if err != nil {
				return Bundle{}, err
			}
			entry.Versions = append(entry.Versions, BundleVersion{
				Version: version.Version,
				Status:  version.Status,
				Design:  design,
				Note:    version.Note,
			})
		}
		bundle.Definitions = append(bundle.Definitions, entry)
	}
	return bundle, nil
}

// allDefinitions lists every definition of one tenant, paging through the store. | allDefinitions
// 分页列出租户的全部定义。
func (s *Service) allDefinitions(ctx context.Context, tenantID string) ([]Definition, error) {
	var all []Definition
	for page := 1; ; page++ {
		items, total, err := s.store.ListDefinitions(ctx, tenantID, DefinitionFilter{Page: page, PageSize: s.options.MaxPageSize})
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		if len(all) >= total || len(items) == 0 {
			break
		}
	}
	return all, nil
}

// ImportBundle merges a bundle into the tenant. Published versions are immutable: a differing
// published version is refused rather than overwritten, so an import can never rewrite history. |
// ImportBundle 把流程包合并进租户。已发布版本不可变：内容不同的已发布版本会被拒绝而不是覆盖，
// 因此导入永远不能改写历史。
func (s *Service) ImportBundle(ctx context.Context, tenantID, actorID string, bundle Bundle) (ImportReport, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return ImportReport{}, ErrInvalidInput
	}
	if bundle.SchemaVersion <= 0 || bundle.SchemaVersion > BundleSchemaVersion {
		return ImportReport{}, errs.Detail(ErrImportInvalid, "unsupported bundle schema %[1]d | 不支持的流程包 schema %[1]d", bundle.SchemaVersion)
	}
	if len(bundle.Definitions) == 0 {
		return ImportReport{}, errs.Detail(ErrImportInvalid, "the bundle carries no definitions | 流程包没有定义")
	}
	if len(bundle.Definitions) > s.options.MaxBundleDefinitions {
		return ImportReport{}, errs.Detail(ErrLimit, "bundle has %[1]d definitions, limit %[2]d | 流程包有 %[1]d 个定义，上限 %[2]d", len(bundle.Definitions), s.options.MaxBundleDefinitions)
	}
	report := ImportReport{}
	now := s.now()
	err := s.store.WithTx(ctx, func(st Store) error {
		for _, entry := range bundle.Definitions {
			key := strings.ToLower(strings.TrimSpace(entry.Key))
			if !keyRe.MatchString(key) {
				return errs.Detail(ErrImportInvalid, "definition key %[1]q is invalid | 定义键 %[1]q 非法", entry.Key)
			}
			def, err := st.GetDefinitionByKey(ctx, tenantID, key)
			if err != nil {
				if !isNotFound(err) {
					return err
				}
				name, ok := trimLen(entry.Name, s.options.MaxNameLen)
				if !ok || name == "" {
					return errs.Detail(ErrImportInvalid, "definition %[1]q needs a name | 定义 %[1]q 需要名称", key)
				}
				id, err := s.options.NewID("wfdef_")
				if err != nil {
					return errs.Wrap(err, ErrUnavailable)
				}
				def = Definition{
					CreatedAt:   now,
					UpdatedAt:   now,
					ID:          id,
					TenantID:    tenantID,
					Key:         key,
					Name:        name,
					NameEN:      entry.NameEN,
					Description: entry.Description,
					Category:    entry.Category,
					Icon:        entry.Icon,
					Status:      DefinitionDraft,
					CreatedBy:   strings.TrimSpace(actorID),
					UpdatedBy:   strings.TrimSpace(actorID),
				}
				if err := st.CreateDefinition(ctx, def); err != nil {
					return err
				}
			}
			report.Definitions++
			maxPublished := def.CurrentVersion
			for _, source := range entry.Versions {
				normalized, canonical, err := s.normalizeDesign(source.Design)
				if err != nil {
					return errs.Detail(ErrImportInvalid, "definition %[1]q version %[2]d: %[3]s | 定义 %[1]q 版本 %[2]d：%[3]s", key, source.Version, err.Error())
				}
				bpmn, err := BuildBPMN(def, source.Version, normalized)
				if err != nil {
					return err
				}
				sum := checksum(canonical)
				number := source.Version
				if number <= 0 {
					number, err = st.NextVersionNumber(ctx, tenantID, def.ID)
					if err != nil {
						return err
					}
				}
				existing, err := st.GetVersionByNumber(ctx, tenantID, def.ID, number)
				if err != nil && !isNotFound(err) {
					return err
				}
				if err == nil {
					if existing.Checksum == sum {
						report.Skipped++
					} else if existing.Status == VersionPublished {
						return errs.Detail(ErrConflict, "definition %[1]q version %[2]d is published and differs | 定义 %[1]q 版本 %[2]d 已发布且内容不同", key, number)
					} else {
						existing.Design = canonical
						existing.BPMN = bpmn
						existing.Checksum = sum
						existing.Note = source.Note
						existing.UpdatedAt = now
						if err := st.UpdateVersion(ctx, existing); err != nil {
							return err
						}
						report.Updated++
					}
					continue
				}
				status := VersionDraft
				if source.Status == VersionPublished {
					status = VersionPublished
					if number > maxPublished {
						maxPublished = number
					}
				}
				id, err := s.options.NewID("wfver_")
				if err != nil {
					return errs.Wrap(err, ErrUnavailable)
				}
				version := Version{
					CreatedAt:    now,
					UpdatedAt:    now,
					ID:           id,
					TenantID:     tenantID,
					DefinitionID: def.ID,
					Version:      number,
					Status:       status,
					Design:       canonical,
					BPMN:         bpmn,
					Checksum:     sum,
					Note:         source.Note,
					CreatedBy:    strings.TrimSpace(actorID),
				}
				if status == VersionPublished {
					version.PublishedAt = now
					version.PublishedBy = strings.TrimSpace(actorID)
				}
				if err := st.CreateVersion(ctx, version); err != nil {
					return err
				}
				report.Created++
			}
			if maxPublished > def.CurrentVersion {
				def.CurrentVersion = maxPublished
				def.Status = DefinitionPublished
				def.UpdatedAt = now
				def.UpdatedBy = strings.TrimSpace(actorID)
				if err := st.UpdateDefinition(ctx, def); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return ImportReport{}, err
	}
	return report, nil
}

// ImportBPMN parses one BPMN document and appends it as a draft version of the named definition. |
// ImportBPMN 解析一个 BPMN 文档，并把它作为指定定义的新草稿版本追加。
func (s *Service) ImportBPMN(ctx context.Context, tenantID, actorID string, process BPMNProcess) (Definition, Version, error) {
	tenantID = strings.TrimSpace(tenantID)
	key := strings.ToLower(strings.TrimSpace(process.Key))
	if tenantID == "" || !keyRe.MatchString(key) {
		return Definition{}, Version{}, ErrInvalidInput
	}
	name, ok := trimLen(process.Name, s.options.MaxNameLen)
	if !ok || name == "" {
		name = key
	}
	var def Definition
	var version Version
	err := s.store.WithTx(ctx, func(st Store) error {
		current, err := st.GetDefinitionByKey(ctx, tenantID, key)
		if err != nil {
			if !isNotFound(err) {
				return err
			}
			id, err := s.options.NewID("wfdef_")
			if err != nil {
				return errs.Wrap(err, ErrUnavailable)
			}
			now := s.now()
			current = Definition{
				CreatedAt:   now,
				UpdatedAt:   now,
				ID:          id,
				TenantID:    tenantID,
				Key:         key,
				Name:        name,
				Description: process.Description,
				Status:      DefinitionDraft,
				CreatedBy:   strings.TrimSpace(actorID),
				UpdatedBy:   strings.TrimSpace(actorID),
			}
			if err := st.CreateDefinition(ctx, current); err != nil {
				return err
			}
		}
		def = current
		normalized, canonical, err := s.normalizeDesign(process.Design)
		if err != nil {
			return err
		}
		number, err := st.NextVersionNumber(ctx, tenantID, current.ID)
		if err != nil {
			return err
		}
		bpmn, err := BuildBPMN(current, number, normalized)
		if err != nil {
			return err
		}
		id, err := s.options.NewID("wfver_")
		if err != nil {
			return errs.Wrap(err, ErrUnavailable)
		}
		now := s.now()
		version = Version{
			CreatedAt:    now,
			UpdatedAt:    now,
			ID:           id,
			TenantID:     tenantID,
			DefinitionID: current.ID,
			Version:      number,
			Status:       VersionDraft,
			Design:       canonical,
			BPMN:         bpmn,
			Checksum:     checksum(canonical),
			CreatedBy:    strings.TrimSpace(actorID),
		}
		return st.CreateVersion(ctx, version)
	})
	if err != nil {
		return Definition{}, Version{}, err
	}
	return def, version, nil
}

// ExportBPMN returns the BPMN document of one version. | ExportBPMN 返回一个版本的 BPMN 文档。
func (s *Service) ExportBPMN(ctx context.Context, tenantID, versionID string) (string, error) {
	tenantID = strings.TrimSpace(tenantID)
	version, err := s.store.GetVersion(ctx, tenantID, versionID)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(version.BPMN) != "" {
		return version.BPMN, nil
	}
	def, err := s.store.GetDefinition(ctx, tenantID, version.DefinitionID)
	if err != nil {
		return "", err
	}
	design, err := DesignOf(version)
	if err != nil {
		return "", err
	}
	return BuildBPMN(def, version.Version, design)
}

// isNotFound reports the domain not-found sentinel. | isNotFound 报告领域未找到哨兵。
func isNotFound(err error) bool { return errors.Is(err, ErrNotFound) }
