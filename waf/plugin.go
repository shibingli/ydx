package waf

import (
	"sync"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
)

// PluginContext is passed to a native plugin during initialization. Version and Data describe the
// bundle active when the plugin generation was created. | PluginContext 在原生插件初始化时传入。
// Version 与 Data 描述创建该插件代际时生效的规则包。
type PluginContext struct {
	Logger  *log.Logger
	Version string
	Data    []byte
}

// Plugin is a native Go extension. It is initialized once per WAF plugin generation and closed
// only after every engine snapshot using it has drained; rule reloads are observed through the
// HookReload hook. | Plugin 是原生 Go 扩展。每个 WAF 插件代际只初始化一次，并在所有使用它的引擎
// 快照排空后才关闭；规则重载通过 HookReload 钩子观察。
type Plugin interface {
	Name() string
	Init(*PluginContext) error
	OnHook(*HookContext) error
	Close() error
}

// PluginFunc adapts functions to Plugin. | PluginFunc 把函数适配为 Plugin。
type PluginFunc struct {
	PluginName string
	InitFn     func(*PluginContext) error
	HookFn     func(*HookContext) error
	CloseFn    func() error
	HookPoints []HookPoint
}

// Name returns the plugin name. | Name 返回插件名称。
func (p PluginFunc) Name() string {
	if p.PluginName == "" {
		return "plugin"
	}
	return p.PluginName
}

// Init calls the initialization function. | Init 调用初始化函数。
func (p PluginFunc) Init(ctx *PluginContext) error {
	if p.InitFn == nil {
		return nil
	}
	return p.InitFn(ctx)
}

// OnHook calls the hook function. | OnHook 调用钩子函数。
func (p PluginFunc) OnHook(ctx *HookContext) error {
	if p.HookFn == nil {
		return nil
	}
	return p.HookFn(ctx)
}

// Close calls the close function. | Close 调用关闭函数。
func (p PluginFunc) Close() error {
	if p.CloseFn == nil {
		return nil
	}
	return p.CloseFn()
}

// Points restricts the plugin to selected hook points. | Points 把插件限定到选定的钩子点。
func (p PluginFunc) Points() []HookPoint { return p.HookPoints }

// nativePlugin wraps a plugin with its point subscription. | nativePlugin 把插件与其事件点订阅
// 包装在一起。
type nativePlugin struct {
	plugin Plugin
	points []HookPoint
}

// nativePluginSet owns the native plugins of one WAF configuration generation. Plugins are
// initialized once and closed only after every engine snapshot using them has drained. |
// nativePluginSet 持有同一 WAF 配置代际的原生插件。插件仅初始化一次，并在所有使用它们的引擎
// 快照排空后才关闭。
type nativePluginSet struct {
	logger    *log.Logger
	entries   []nativePlugin
	mu        sync.Mutex
	closeOnce sync.Once
	refs      int
}

// newNativePluginSet initializes one plugin generation. The returned set carries one owner
// reference; buildEngine adds one reference per engine snapshot. | newNativePluginSet 初始化一个
// 插件代际。返回的集合带有一个持有者引用；buildEngine 为每个引擎快照增加一个引用。
func newNativePluginSet(plugins []Plugin, bundle *Bundle, logger *log.Logger, lenient bool) (*nativePluginSet, error) {
	if len(plugins) == 0 {
		return nil, nil
	}
	var data []byte
	version := ""
	if bundle != nil {
		data = bundle.Data
		version = bundleVersion(bundle)
	}
	set := &nativePluginSet{logger: logger, refs: 1}
	pluginContext := &PluginContext{Logger: logger, Version: version, Data: data}
	for _, plugin := range plugins {
		if plugin == nil {
			continue
		}
		name := plugin.Name()
		if name == "" {
			set.discard()
			return nil, errs.Detail(ErrPlugin, "plugin has no name | 插件没有名称")
		}
		if err := plugin.Init(pluginContext); err != nil {
			_ = plugin.Close()
			if !lenient {
				set.discard()
				return nil, errs.WrapDetail(err, ErrPlugin, "plugin %q init failed | 插件 %q 初始化失败", name, name)
			}
			logger.Warn("waf plugin skipped | WAF 插件已跳过",
				log.Str("plugin", name), log.Err(err))
			continue
		}
		points := allHookPoints()
		if subscriber, ok := plugin.(pointSubscriber); ok {
			if subscribed := subscriber.Points(); len(subscribed) > 0 {
				points = subscribed
			}
		}
		set.entries = append(set.entries, nativePlugin{plugin: plugin, points: points})
	}
	if len(set.entries) == 0 {
		set.discard()
		return nil, nil
	}
	return set, nil
}

// acquire adds one engine reference. | acquire 增加一个引擎引用。
func (s *nativePluginSet) acquire() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.refs++
	s.mu.Unlock()
}

// release drops one reference and closes the plugins when the last one is gone. | release 释放
// 一个引用，并在最后一个引用消失时关闭插件。
func (s *nativePluginSet) release() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.refs > 0 {
		s.refs--
	}
	closeNow := s.refs == 0
	s.mu.Unlock()
	if closeNow {
		s.shutdown()
	}
}

// discard closes a set that has never been published. | discard 关闭从未发布的集合。
func (s *nativePluginSet) discard() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.refs = 0
	s.mu.Unlock()
	s.shutdown()
}

// shutdown closes every initialized plugin exactly once. | shutdown 仅关闭每个已初始化插件一次。
func (s *nativePluginSet) shutdown() {
	s.closeOnce.Do(func() {
		for _, entry := range s.entries {
			if err := entry.plugin.Close(); err != nil {
				s.logger.Error("waf plugin close failed | WAF 插件关闭失败",
					log.Str("plugin", entry.plugin.Name()), log.Err(err))
			}
		}
	})
}

// samePluginNames reports whether two plugin lists name the same plugins in the same order. Names
// identify a native plugin across ReloadWith so a live plugin is never re-initialized or closed
// while an engine still uses it. | samePluginNames 报告两个插件列表是否按顺序命名相同插件。名称在
// ReloadWith 中标识原生插件，避免在引擎仍使用插件时重新初始化或关闭它。
func samePluginNames(left, right []Plugin) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if pluginName(left[index]) != pluginName(right[index]) {
			return false
		}
	}
	return true
}

// pluginName returns a plugin name without dereferencing nil. | pluginName 在不解引用 nil 的情况下
// 返回插件名称。
func pluginName(plugin Plugin) string {
	if plugin == nil {
		return ""
	}
	return plugin.Name()
}

// pluginManager owns the plugin references of one engine snapshot. Native plugin objects are
// shared between snapshots through nativePluginSet; WASM plugins are built per snapshot. |
// pluginManager 持有一个引擎快照的插件引用。原生插件对象经 nativePluginSet 在快照间共享；WASM
// 插件按快照构建。
type pluginManager struct {
	logger      *log.Logger
	counters    *counters
	hooks       *hookRegistry
	nativeSet   *nativePluginSet
	native      []nativePlugin
	wasm        []*wasmPlugin
	pointCounts [hookPointCount]int
}

// buildPlugins attaches one native plugin generation and initializes the WASM plugins of an
// engine snapshot. | buildPlugins 附加一个原生插件代际并初始化引擎快照的 WASM 插件。
func buildPlugins(opts Options, bundle *Bundle, native *nativePluginSet, logger *log.Logger, counters *counters, hooks *hookRegistry) (*pluginManager, error) {
	if native == nil && len(opts.WASMPlugins) == 0 {
		return nil, nil
	}
	manager := &pluginManager{logger: logger, counters: counters, hooks: hooks, nativeSet: native}
	if native != nil {
		native.acquire()
		manager.native = native.entries
		for _, entry := range native.entries {
			for _, point := range entry.points {
				if int(point) < hookPointCount {
					manager.pointCounts[point]++
				}
			}
		}
	}
	for _, config := range opts.WASMPlugins {
		plugin, err := newWASMPlugin(config, logger, counters, opts.PluginTimeout)
		if err != nil {
			manager.close()
			if !opts.Lenient {
				return nil, errs.WrapDetail(err, ErrPlugin, "wasm plugin %q init failed | WASM 插件 %q 初始化失败", config.Name, config.Name)
			}
			logger.Warn("waf wasm plugin skipped | WAF WASM 插件已跳过",
				log.Str("plugin", config.Name), log.Err(err))
			continue
		}
		manager.wasm = append(manager.wasm, plugin)
		for _, point := range plugin.points {
			if int(point) < hookPointCount {
				manager.pointCounts[point]++
			}
		}
	}
	if len(manager.native) == 0 && len(manager.wasm) == 0 {
		manager.close()
		return nil, nil
	}
	return manager, nil
}

// allHookPoints returns every hook point. | allHookPoints 返回全部钩子点。
func allHookPoints() []HookPoint {
	points := make([]HookPoint, 0, hookPointCount)
	for point := HookBeforePhase; point <= HookRequestComplete; point++ {
		points = append(points, point)
	}
	return points
}

// has reports whether any plugin listens to a point. | has 报告是否有插件监听某个事件点。
func (m *pluginManager) has(point HookPoint) bool {
	return m != nil && int(point) < hookPointCount && m.pointCounts[point] > 0
}

// runHook dispatches one event to native and WASM plugins. | runHook 把一个事件分发给原生与
// WASM 插件。
func (m *pluginManager) runHook(ctx *HookContext) {
	if m == nil || ctx == nil {
		return
	}
	for i := range m.native {
		entry := &m.native[i]
		if !pointIn(entry.points, ctx.Point) {
			continue
		}
		if err := invokeNative(entry.plugin, ctx); err != nil {
			m.counters.plugins.Add(1)
			m.logger.Error("waf plugin failed | WAF 插件失败",
				log.Str("plugin", entry.plugin.Name()), log.Err(err))
			m.notifyError(ctx, err)
		}
	}
	for _, plugin := range m.wasm {
		if !pointIn(plugin.points, ctx.Point) {
			continue
		}
		if err := plugin.run(ctx); err != nil {
			m.counters.plugins.Add(1)
			m.logger.Error("waf wasm plugin failed | WAF WASM 插件失败",
				log.Str("plugin", plugin.name), log.Err(err))
			m.notifyError(ctx, err)
		}
	}
}

// notifyError delivers a plugin failure to hooks subscribed to HookPluginError. Plugin calls are
// not re-entered, so a failing error hook cannot recurse into the plugin that failed.
// | notifyError 把插件失败投递给订阅 HookPluginError 的钩子。不会重新进入插件调用，因此失败的
// 错误钩子不会递归回到出错的插件。
func (m *pluginManager) notifyError(ctx *HookContext, err error) {
	if m == nil || m.hooks == nil || !m.hooks.has(HookPluginError) {
		return
	}
	hookCtx := &HookContext{
		Point:   HookPluginError,
		Err:     err,
		tx:      ctx.tx,
		Request: ctx.Request,
		Rule:    ctx.Rule,
		Match:   ctx.Match,
		Phase:   ctx.Phase,
		Version: ctx.Version,
	}
	if ctx.tx != nil {
		hookCtx.Tx = &Transaction{tx: ctx.tx}
	}
	m.hooks.run(hookCtx)
}

// invokeNative calls a native plugin with panic isolation. | invokeNative 在 panic 隔离下调用
// 原生插件。
func invokeNative(plugin Plugin, ctx *HookContext) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = errs.Detail(ErrPlugin, "panic: %v | panic：%v", recovered, recovered)
		}
	}()
	return plugin.OnHook(ctx)
}

// pointIn reports whether points contains point. | pointIn 报告 points 是否包含 point。
func pointIn(points []HookPoint, point HookPoint) bool {
	for _, candidate := range points {
		if candidate == point {
			return true
		}
	}
	return false
}

// close releases one engine reference and closes its WASM plugins. Native plugin objects stay
// alive until the owning generation and every engine using it have released their references.
// | close 释放一个引擎引用并关闭其 WASM 插件。原生插件对象会一直存活，直到所属代际与所有使用它的
// 引擎都释放引用。
func (m *pluginManager) close() {
	if m == nil {
		return
	}
	if m.nativeSet != nil {
		m.nativeSet.release()
		m.nativeSet = nil
	}
	m.native = nil
	for _, plugin := range m.wasm {
		plugin.close()
	}
	m.wasm = nil
}
