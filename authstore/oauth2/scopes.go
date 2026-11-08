package oauth2

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	authoauth2 "github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/errs"
)

// ScopeRegistry is a Redis-shared authoauth2.ScopeRegistry. The read interface has no context and
// no error return, so reads use an in-process snapshot loaded on first use and refreshed lazily
// after ScopeCacheTTL. RegisterScopes, DeleteScope and ReplaceScopes mutate Redis atomically and
// refresh the local snapshot; other instances observe the change after their next lazy refresh or
// explicit Reload. | ScopeRegistry 是 Redis 共享的 authoauth2.ScopeRegistry。读取接口没有上下文与
// 错误返回，因此读取使用进程内快照，首次读取时加载，并在 ScopeCacheTTL 之后惰性刷新。
// RegisterScopes、DeleteScope 与 ReplaceScopes 原子修改 Redis 并刷新本地快照；其他实例在下一次
// 惰性刷新或显式 Reload 后看到变更。
type ScopeRegistry struct {
	// base carries the shared client and key namespace. | base 承载共享客户端与键命名空间。
	base
	// ttl bounds how long a loaded snapshot is reused; zero disables lazy refresh.
	// | ttl 限定已加载快照的复用时长；零值关闭惰性刷新。
	ttl time.Duration
	// reloadMu serializes Redis loads. | reloadMu 串行化 Redis 加载。
	reloadMu sync.Mutex
	// mu guards defs, order and loaded. | mu 保护 defs、order 与 loaded。
	mu sync.RWMutex
	// defs indexes the current snapshot by scope name. | defs 按作用域名索引当前快照。
	defs map[string]authoauth2.Scope
	// order preserves registration order in the current snapshot. | order 保留当前快照的注册顺序。
	order []string
	// loaded is when the current snapshot was read. | loaded 是当前快照的读取时间。
	loaded time.Time
}

// ScopeRegistry satisfies the authoauth2 read port. | ScopeRegistry 满足 authoauth2 读取端口。
var _ authoauth2.ScopeRegistry = (*ScopeRegistry)(nil)

// Reload replaces the in-process snapshot with the current Redis registry. | Reload 用当前 Redis
// 注册表替换进程内快照。
func (s *ScopeRegistry) Reload(ctx context.Context) error {
	if s == nil {
		return errs.Detail(authoauth2.ErrServerError, "scope registry is nil | 作用域注册表为空")
	}
	values, err := s.runStrings(ctx, scriptScopeList, "load scopes",
		[]string{s.keys.scopesDefs(), s.keys.scopesOrder()})
	if err != nil {
		return err
	}
	defs := make(map[string]authoauth2.Scope, len(values))
	order := make([]string, 0, len(values))
	for _, value := range values {
		scope, err := decodeScope([]byte(value))
		if err != nil {
			return err
		}
		if scope.Name == "" {
			continue
		}
		if _, exists := defs[scope.Name]; exists {
			continue
		}
		defs[scope.Name] = scope
		order = append(order, scope.Name)
	}
	s.mu.Lock()
	s.defs = defs
	s.order = order
	s.loaded = time.Now()
	s.mu.Unlock()
	return nil
}

// refresh reloads an expired or never-loaded snapshot and keeps the previous snapshot when the
// backend fails. | refresh 重新加载已过期或从未加载的快照，后端失败时保留旧快照。
func (s *ScopeRegistry) refresh() {
	if s == nil || s.ttl <= 0 {
		return
	}
	s.mu.RLock()
	due := s.loaded.IsZero() || time.Since(s.loaded) >= s.ttl
	s.mu.RUnlock()
	if !due {
		return
	}
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	s.mu.RLock()
	due = s.loaded.IsZero() || time.Since(s.loaded) >= s.ttl
	s.mu.RUnlock()
	if !due {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), scopeReloadTimeout)
	defer cancel()
	if err := s.Reload(ctx); err != nil {
		// Back off until the next ttl window instead of retrying on every request. | 退避到下一个
		// ttl 窗口，而不是每个请求都重试。
		s.mu.Lock()
		s.loaded = time.Now()
		s.mu.Unlock()
	}
}

// snapshot returns the current definitions and order without exposing internal storage.
// | snapshot 返回当前定义与顺序，且不暴露内部存储。
func (s *ScopeRegistry) snapshot() (map[string]authoauth2.Scope, []string) {
	if s == nil {
		return nil, nil
	}
	s.refresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.defs, s.order
}

// Validate returns the deduplicated granted subset of requested. | Validate 返回 requested 的去重授予子集。
func (s *ScopeRegistry) Validate(requested []string, client *authoauth2.Client) ([]string, error) {
	if s == nil {
		return requested, nil
	}
	defs, _ := s.snapshot()
	out := make([]string, 0, len(requested))
	seen := make(map[string]bool, len(requested))
	for _, name := range requested {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		if _, ok := defs[name]; !ok {
			return nil, errs.Detail(authoauth2.ErrInvalidScope, "unknown scope %[1]q | 未知作用域 %[1]q", name)
		}
		if client != nil && !client.AllowsScope(name) {
			return nil, errs.Detail(authoauth2.ErrInvalidScope, "scope %[1]q is not allowed for this client | 客户端不允许作用域 %[1]q", name)
		}
		out = append(out, name)
	}
	if len(requested) > 0 && len(out) == 0 {
		return nil, authoauth2.ErrInvalidScope
	}
	return out, nil
}

// List returns every registered scope name in registration order. | List 按注册顺序返回全部已注册作用域名。
func (s *ScopeRegistry) List() []string {
	_, order := s.snapshot()
	return append([]string(nil), order...)
}

// Exists reports whether name is registered. | Exists 报告 name 是否已注册。
func (s *ScopeRegistry) Exists(name string) bool {
	defs, _ := s.snapshot()
	_, ok := defs[name]
	return ok
}

// Get returns the definition of name. | Get 返回 name 的定义。
func (s *ScopeRegistry) Get(name string) (authoauth2.Scope, bool) {
	defs, _ := s.snapshot()
	scope, ok := defs[name]
	if !ok {
		return authoauth2.Scope{}, false
	}
	scope.Claims = append([]string(nil), scope.Claims...)
	return scope, true
}

// SortedScopes returns the registered names sorted lexically. | SortedScopes 返回按字典序排序的已注册名称。
func (s *ScopeRegistry) SortedScopes() []string {
	out := s.List()
	sort.Strings(out)
	return out
}

// RegisterScopes adds the scopes whose names are not registered yet and returns how many were
// added. Empty names are ignored and duplicate names within one call keep the first definition.
// | RegisterScopes 添加尚不存在的作用域并返回新增数量。空名称被忽略，同一次调用中的重复名称保留
// 首个定义。
func (s *ScopeRegistry) RegisterScopes(ctx context.Context, scopes ...authoauth2.Scope) (int, error) {
	args, err := scopeArgs(scopes)
	if err != nil {
		return 0, err
	}
	if len(args) == 0 {
		return 0, nil
	}
	added, err := s.runInt(ctx, scriptScopeRegister, "register scopes",
		[]string{s.keys.scopesDefs(), s.keys.scopesOrder()}, args...)
	if err != nil {
		return 0, err
	}
	s.refreshAfterMutation()
	return int(added), nil
}

// DeleteScope removes one registered scope and reports whether it existed. | DeleteScope 删除单个已注册
// 作用域并报告其是否存在。
func (s *ScopeRegistry) DeleteScope(ctx context.Context, name string) (bool, error) {
	status, err := s.runInt(ctx, scriptScopeDelete, "delete scope",
		[]string{s.keys.scopesDefs(), s.keys.scopesOrder()}, name)
	if err != nil {
		return false, err
	}
	s.refreshAfterMutation()
	return status == 1, nil
}

// ReplaceScopes atomically replaces the whole registry and returns the registered count. Empty
// names are ignored and duplicate names within one call keep the first definition.
// | ReplaceScopes 原子替换整个注册表并返回注册数量。空名称被忽略，同一次调用中的重复名称保留首个定义。
func (s *ScopeRegistry) ReplaceScopes(ctx context.Context, scopes ...authoauth2.Scope) (int, error) {
	args, err := scopeArgs(scopes)
	if err != nil {
		return 0, err
	}
	replaced, err := s.runInt(ctx, scriptScopeReplace, "replace scopes",
		[]string{s.keys.scopesDefs(), s.keys.scopesOrder()}, args...)
	if err != nil {
		return 0, err
	}
	s.refreshAfterMutation()
	return int(replaced), nil
}

// scopeArgs encodes distinct non-empty scope definitions as flat name/JSON arguments.
// | scopeArgs 把不重复且非空的作用域定义编码为扁平名称/JSON 参数。
func scopeArgs(scopes []authoauth2.Scope) ([]any, error) {
	seen := make(map[string]bool, len(scopes))
	args := make([]any, 0, len(scopes)*2)
	for _, scope := range scopes {
		if scope.Name == "" || seen[scope.Name] {
			continue
		}
		seen[scope.Name] = true
		data, err := encodeScope(scope)
		if err != nil {
			return nil, err
		}
		args = append(args, scope.Name, string(data))
	}
	return args, nil
}

// refreshAfterMutation refreshes the local snapshot after a successful Redis write. A failed
// refresh leaves the previous snapshot in place; reads retry at the next ttl window. | refreshAfterMutation
// 在 Redis 写入成功后刷新本地快照。刷新失败时保留旧快照；读取会在下一个 ttl 窗口重试。
func (s *ScopeRegistry) refreshAfterMutation() {
	ctx, cancel := context.WithTimeout(context.Background(), scopeReloadTimeout)
	defer cancel()
	if err := s.Reload(ctx); err != nil {
		s.mu.Lock()
		s.loaded = time.Now()
		s.mu.Unlock()
	}
}
