package workflow

import "context"

// waitingTokenLister is an optional Store extension used by refreshCurrentNodes. Stores that do
// not implement it fall back to ListTokens and filter in memory. | waitingTokenLister 是
// refreshCurrentNodes 使用的可选 Store 扩展。未实现它的存储回退到 ListTokens 并在内存中过滤。
type waitingTokenLister interface {
	// ListWaitingTokens returns the waiting tokens of one instance. | ListWaitingTokens 返回一个实例的
	// 等待令牌。
	ListWaitingTokens(ctx context.Context, tenantID, instanceID string) ([]Token, error)
}

// taskRowReader is an optional Store extension that reads one task without filling the instance
// projection columns. The runtime and the detail drawer already load the instance. | taskRowReader
// 是一个可选 Store 扩展，读取单条任务时不填充实例投影列。运行期与详情抽屉本来就会加载实例。
type taskRowReader interface {
	// GetTaskBare returns one task row only. | GetTaskBare 只返回任务行。
	GetTaskBare(ctx context.Context, tenantID, id string) (Task, error)
}

// definitionMetricsReader is an optional Store extension that counts versions and instances for a
// whole page of definitions in two grouped queries instead of two queries per row. |
// definitionMetricsReader 是一个可选 Store 扩展，用两条分组查询统计整页定义的版本数与实例数，
// 而不是为每行各发两条查询。
type definitionMetricsReader interface {
	// CountVersionsForDefinitions groups version counts by definition id. |
	// CountVersionsForDefinitions 按定义 ID 分组统计版本数。
	CountVersionsForDefinitions(ctx context.Context, tenantID string, definitionIDs []string) (map[string]int, error)
	// CountInstancesForDefinitions groups instance counts by definition id. |
	// CountInstancesForDefinitions 按定义 ID 分组统计实例数。
	CountInstancesForDefinitions(ctx context.Context, tenantID string, definitionIDs []string) (map[string]int, error)
}

// The service asserts the grouped-count extension on the transaction wrapper, so the wrapper must
// keep forwarding it. | 服务在事务包装层上断言分组统计扩展，因此包装层必须持续转发它。
var _ definitionMetricsReader = (*aiDeferringStore)(nil)

// versionSummaryReader is an optional Store extension that loads lightweight version projections. |
// versionSummaryReader 是一个可选 Store 扩展，加载轻量版本投影。
type versionSummaryReader interface {
	// ListVersionSummariesForDefinitions groups summaries by definition id. |
	// ListVersionSummariesForDefinitions 按定义 ID 分组返回摘要。
	ListVersionSummariesForDefinitions(ctx context.Context, tenantID string, definitionIDs []string) (map[string][]VersionSummary, error)
}

// CountVersionsForDefinitions forwards the optional grouped count or counts the full version rows.
// | CountVersionsForDefinitions 转发可选的分组统计，或对完整版本行逐个计数。
func (s *aiDeferringStore) CountVersionsForDefinitions(ctx context.Context, tenantID string, definitionIDs []string) (map[string]int, error) {
	if reader, ok := s.Store.(definitionMetricsReader); ok {
		return reader.CountVersionsForDefinitions(ctx, tenantID, definitionIDs)
	}
	out := make(map[string]int, len(definitionIDs))
	for _, id := range definitionIDs {
		versions, err := s.Store.ListVersions(ctx, tenantID, id)
		if err != nil {
			return nil, err
		}
		out[id] = len(versions)
	}
	return out, nil
}

// CountInstancesForDefinitions forwards the optional grouped count or counts each definition with
// one bounded page read. | CountInstancesForDefinitions 转发可选的分组统计，或对每个定义做一次
// 有界分页读取来计数。
func (s *aiDeferringStore) CountInstancesForDefinitions(ctx context.Context, tenantID string, definitionIDs []string) (map[string]int, error) {
	if reader, ok := s.Store.(definitionMetricsReader); ok {
		return reader.CountInstancesForDefinitions(ctx, tenantID, definitionIDs)
	}
	out := make(map[string]int, len(definitionIDs))
	for _, id := range definitionIDs {
		_, total, err := s.Store.ListInstances(ctx, tenantID, InstanceFilter{DefinitionID: id, Page: 1, PageSize: 1})
		if err != nil {
			return nil, err
		}
		out[id] = total
	}
	return out, nil
}

// ListVersionSummariesForDefinitions forwards the optional summary read or derives summaries from
// the full version list. | ListVersionSummariesForDefinitions 转发可选的摘要读取，或从完整版本列表
// 推导摘要。
func (s *aiDeferringStore) ListVersionSummariesForDefinitions(ctx context.Context, tenantID string, definitionIDs []string) (map[string][]VersionSummary, error) {
	if reader, ok := s.Store.(versionSummaryReader); ok {
		return reader.ListVersionSummariesForDefinitions(ctx, tenantID, definitionIDs)
	}
	out := make(map[string][]VersionSummary, len(definitionIDs))
	for _, id := range definitionIDs {
		items, err := s.Store.ListVersions(ctx, tenantID, id)
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

// GetTaskBare forwards the optional row read or falls back to the projecting GetTask. |
// GetTaskBare 转发可选的单行读取，或回退到带投影的 GetTask。
func (s *aiDecisionStore) GetTaskBare(ctx context.Context, tenantID, id string) (Task, error) {
	if reader, ok := s.Store.(taskRowReader); ok {
		return reader.GetTaskBare(ctx, tenantID, id)
	}
	return s.Store.GetTask(ctx, tenantID, id)
}

// GetTaskBare forwards the optional row read or falls back to the projecting GetTask. |
// GetTaskBare 转发可选的单行读取，或回退到带投影的 GetTask。
func (s *aiDeferringStore) GetTaskBare(ctx context.Context, tenantID, id string) (Task, error) {
	if reader, ok := s.Store.(taskRowReader); ok {
		return reader.GetTaskBare(ctx, tenantID, id)
	}
	return s.Store.GetTask(ctx, tenantID, id)
}

// runtimeVersionMetaReader is an optional Store extension that resolves a version to its primary
// key without reading the design or BPMN documents. Start can then reuse the parsed-version cache
// after the first call instead of transferring the whole design on every start. | runtimeVersionMetaReader
// 是一个可选 Store 扩展，把版本解析为主键而不读取设计串或 BPMN 串。Start 因此可以在首次调用之后
// 复用已解析版本缓存，而不必在每次发起时传输整份设计。
type runtimeVersionMetaReader interface {
	// GetLatestPublishedVersionMeta returns the latest published version key. |
	// GetLatestPublishedVersionMeta 返回最新已发布版本的主键。
	GetLatestPublishedVersionMeta(ctx context.Context, tenantID, definitionID string) (Version, error)
	// GetVersionByNumberMeta returns one version key. | GetVersionByNumberMeta 返回一个版本的主键。
	GetVersionByNumberMeta(ctx context.Context, tenantID, definitionID string, version int) (Version, error)
}

// GetLatestPublishedVersionMeta forwards the optional runtime read or falls back to the full row. |
// GetLatestPublishedVersionMeta 转发可选的运行期读取，或回退到完整行。
func (s *aiDeferringStore) GetLatestPublishedVersionMeta(ctx context.Context, tenantID, definitionID string) (Version, error) {
	if reader, ok := s.Store.(runtimeVersionMetaReader); ok {
		return reader.GetLatestPublishedVersionMeta(ctx, tenantID, definitionID)
	}
	return s.Store.GetLatestPublishedVersion(ctx, tenantID, definitionID)
}

// GetVersionByNumberMeta forwards the optional runtime read or falls back to the full row. |
// GetVersionByNumberMeta 转发可选的运行期读取，或回退到完整行。
func (s *aiDeferringStore) GetVersionByNumberMeta(ctx context.Context, tenantID, definitionID string, version int) (Version, error) {
	if reader, ok := s.Store.(runtimeVersionMetaReader); ok {
		return reader.GetVersionByNumberMeta(ctx, tenantID, definitionID, version)
	}
	return s.Store.GetVersionByNumber(ctx, tenantID, definitionID, version)
}

// ListWaitingTokens exposes the optional extension through the transaction wrapper. Without this
// forwarding method a type assertion on the wrapped store would always fail and every transition
// would keep scanning the instance's completed-token history. | ListWaitingTokens 通过事务包装层
// 暴露可选扩展。没有这个转发方法，对包装后存储的类型断言会永远失败，每次流转都会继续扫描实例的
// 已完成令牌历史。
func (s *aiDecisionStore) ListWaitingTokens(ctx context.Context, tenantID, instanceID string) ([]Token, error) {
	if lister, ok := s.Store.(waitingTokenLister); ok {
		return lister.ListWaitingTokens(ctx, tenantID, instanceID)
	}
	tokens, err := s.Store.ListTokens(ctx, tenantID, instanceID)
	if err != nil {
		return nil, err
	}
	waiting := tokens[:0]
	for _, token := range tokens {
		if token.Status == TokenWaiting {
			waiting = append(waiting, token)
		}
	}
	return waiting, nil
}
