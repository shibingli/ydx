package waf

import (
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
)

// PluginContext is passed to a native plugin during initialization. | PluginContext 在原生插件
// 初始化时传入。
type PluginContext struct {
	Logger  *log.Logger
	Version string
	Data    []byte
}

// Plugin is a native Go extension initialized with every engine snapshot. | Plugin 是随每个引擎
// 快照初始化的原生 Go 扩展。
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

// pluginManager owns the native and WASM plugins of one engine snapshot. | pluginManager 持有一个
// 引擎快照的原生与 WASM 插件。
type pluginManager struct {
	logger      *log.Logger
	counters    *counters
	hooks       *hookRegistry
	native      []nativePlugin
	wasm        []*wasmPlugin
	pointCounts [hookPointCount]int
}

// buildPlugins initializes every configured plugin. | buildPlugins 初始化每个已配置插件。
func buildPlugins(opts Options, bundle *Bundle, logger *log.Logger, counters *counters, hooks *hookRegistry) (*pluginManager, error) {
	if len(opts.Plugins) == 0 && len(opts.WASMPlugins) == 0 {
		return nil, nil
	}
	manager := &pluginManager{logger: logger, counters: counters, hooks: hooks}
	pluginContext := &PluginContext{Logger: logger, Version: bundleVersion(bundle), Data: bundle.Data}
	for _, plugin := range opts.Plugins {
		if plugin == nil {
			continue
		}
		if plugin.Name() == "" {
			return nil, errs.Detail(ErrPlugin, "plugin has no name | 插件没有名称")
		}
		if err := plugin.Init(pluginContext); err != nil {
			_ = plugin.Close()
			manager.closeNative()
			if !opts.Lenient {
				return nil, errs.WrapDetail(err, ErrPlugin, "plugin %q init failed | 插件 %q 初始化失败", plugin.Name(), plugin.Name())
			}
			logger.Warn("waf plugin skipped | WAF 插件已跳过",
				log.Str("plugin", plugin.Name()), log.Err(err))
			continue
		}
		points := allHookPoints()
		if subscriber, ok := plugin.(pointSubscriber); ok {
			if subscribed := subscriber.Points(); len(subscribed) > 0 {
				points = subscribed
			}
		}
		manager.native = append(manager.native, nativePlugin{plugin: plugin, points: points})
		for _, point := range points {
			if int(point) < hookPointCount {
				manager.pointCounts[point]++
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

// close releases every plugin. | close 释放每个插件。
func (m *pluginManager) close() {
	if m == nil {
		return
	}
	m.closeNative()
	for _, plugin := range m.wasm {
		plugin.close()
	}
	m.wasm = nil
}

// closeNative closes native plugins. | closeNative 关闭原生插件。
func (m *pluginManager) closeNative() {
	for _, entry := range m.native {
		if err := entry.plugin.Close(); err != nil {
			m.logger.Error("waf plugin close failed | WAF 插件关闭失败",
				log.Str("plugin", entry.plugin.Name()), log.Err(err))
		}
	}
	m.native = nil
}
