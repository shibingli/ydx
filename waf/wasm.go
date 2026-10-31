package waf

import (
	"context"
	"io/fs"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/log"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// WASM ABI constants. The guest imports host module "ydx_waf" and exports the functions below.
// | WASM ABI 常量。客户模块导入宿主模块 "ydx_waf" 并导出下列函数。
const (
	wasmABIVersion         = 1
	wasmHostModule         = "ydx_waf"
	defaultWASMMemoryPages = 256
	defaultWASMInstances   = 32
	wasmFailureThreshold   = 5
	wasmDisableCooldown    = 30 * time.Second
	maxWASMModuleBytes     = 32 << 20
	maxWASMPayloadBytes    = 1 << 20
	maxWASMLogBytes        = 4 << 10
	maxWASMNameBytes       = 256
	maxWASMValueBytes      = 64 << 10
)

// WASMPluginConfig configures one WebAssembly plugin. | WASMPluginConfig 配置一个 WebAssembly 插件。
type WASMPluginConfig struct {
	// FS resolves Path. | FS 解析 Path。
	FS fs.FS
	// Name identifies the plugin in logs and events. | Name 在日志与事件中标识插件。
	Name string
	// Path is the module path, resolved through FS when set. | Path 是模块路径，设置 FS 时经它解析。
	Path string
	// Bytes is the compiled module. When empty Path is read. | Bytes 是已编译模块；为空时读取 Path。
	Bytes []byte
	// Config is passed to ydx_waf_init. | Config 传给 ydx_waf_init。
	Config []byte
	// Points restricts the plugin to selected hook points; empty selects every point.
	// | Points 把插件限定到选定的钩子点；为空选择全部事件点。
	Points []HookPoint
	// Timeout bounds one hook call; zero selects Options.PluginTimeout. | Timeout 限制单次钩子调用；
	// 零值使用 Options.PluginTimeout。
	Timeout time.Duration
	// MaxInstances caps concurrent instances; zero selects 32. | MaxInstances 限制并发实例数；零值使用 32。
	MaxInstances int
	// MaxMemoryPages caps guest memory in 64 KiB pages; zero selects 256. | MaxMemoryPages 以 64 KiB
	// 页为单位限制客户内存；零值使用 256。
	MaxMemoryPages uint32
	// FailClosed denies the request when the plugin fails; false isolates the failure and
	// continues. | FailClosed 在插件失败时拒绝请求；false 隔离失败并继续。
	FailClosed bool
}

// wasmPlugin is one loaded WebAssembly plugin with its circuit breaker. | wasmPlugin 是一个已加载
// 的 WebAssembly 插件及其熔断器。
type wasmPlugin struct {
	runtime       *wasmRuntime
	logger        *log.Logger
	counters      *counters
	name          string
	points        []HookPoint
	timeout       time.Duration
	disabledUntil atomic.Int64
	failures      atomic.Int32
	closed        atomic.Bool
	failClosed    bool
}

// wasmRuntime owns the wazero runtime, the compiled module and an instance pool. | wasmRuntime 持有
// wazero 运行时、已编译模块与实例池。
type wasmRuntime struct {
	rt       wazero.Runtime
	compiled wazero.CompiledModule
	logger   *log.Logger
	sem      chan struct{}

	modules sync.Map // module name -> *wasmInstance | 模块名 -> *wasmInstance
	name    string

	config []byte
	idle   []*wasmInstance
	seq    atomic.Uint64
	mu     sync.Mutex
	closed atomic.Bool
}

// wasmInstance is one guest module instance. | wasmInstance 是一个客户模块实例。
type wasmInstance struct {
	mod     api.Module
	fnHook  api.Function
	fnAlloc api.Function
	fnFree  api.Function
	current atomic.Pointer[wasmCallState]
	name    string
	closed  atomic.Bool
}

// wasmCallState carries the request state visible to host functions during one call.
// | wasmCallState 在一次调用期间承载宿主函数可见的请求状态。
type wasmCallState struct {
	tx      *transaction
	message string
	verdict int32
	status  int32
}

// wasmCallResult is the verdict returned by one guest call. | wasmCallResult 是一次客户调用返回的裁决。
type wasmCallResult struct {
	message string
	status  int
	verdict int32
}

// wasmHookEvent is the JSON document passed to ydx_waf_on_hook. | wasmHookEvent 是传给
// ydx_waf_on_hook 的 JSON 文档。
type wasmHookEvent struct {
	Interrupted *Interruption `json:"interruption,omitempty"`
	Point       string        `json:"point"`
	TxID        string        `json:"tx_id,omitempty"`
	Method      string        `json:"method,omitempty"`
	Path        string        `json:"path,omitempty"`
	ClientIP    string        `json:"client_ip,omitempty"`
	Var         string        `json:"var,omitempty"`
	Key         string        `json:"key,omitempty"`
	Value       string        `json:"value,omitempty"`
	Message     string        `json:"message,omitempty"`
	Severity    string        `json:"severity,omitempty"`
	Version     string        `json:"rule_version,omitempty"`
	Error       string        `json:"error,omitempty"`
	Tags        []string      `json:"tags,omitempty"`
	Phase       int           `json:"phase"`
	RuleID      int           `json:"rule_id,omitempty"`
}

// newWASMPlugin loads, validates and prepares one WASM plugin. | newWASMPlugin 加载、校验并准备一个
// WASM 插件。
func newWASMPlugin(config WASMPluginConfig, logger *log.Logger, counters *counters, defaultTimeout time.Duration) (*wasmPlugin, error) {
	if config.Name == "" {
		return nil, errs.Detail(ErrWASM, "wasm plugin has no name | WASM 插件没有名称")
	}
	moduleBytes, err := loadWASMBytes(config)
	if err != nil {
		return nil, err
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if timeout <= 0 {
		timeout = defaultPluginTimeout
	}
	pages := config.MaxMemoryPages
	if pages == 0 {
		pages = defaultWASMMemoryPages
	}
	if pages > 65536 {
		pages = 65536
	}
	instances := config.MaxInstances
	if instances <= 0 {
		instances = defaultWASMInstances
	}
	ctx := context.Background()
	runtimeConfig := wazero.NewRuntimeConfig().
		WithCloseOnContextDone(true).
		WithMemoryLimitPages(pages)
	runtime := wazero.NewRuntimeWithConfig(ctx, runtimeConfig)
	if runtime == nil {
		return nil, errs.Detail(ErrWASM, "cannot create wazero runtime | 无法创建 wazero 运行时")
	}
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, runtime); err != nil {
		_ = runtime.Close(ctx)
		return nil, errs.Wrap(err, ErrWASM)
	}
	rt := &wasmRuntime{
		rt:     runtime,
		config: append([]byte(nil), config.Config...),
		logger: logger,
		name:   config.Name,
		sem:    make(chan struct{}, instances),
	}
	if _, err := runtime.NewHostModuleBuilder(wasmHostModule).
		NewFunctionBuilder().WithFunc(rt.hostLog).Export("log").
		NewFunctionBuilder().WithFunc(rt.hostGetVar).Export("get_var").
		NewFunctionBuilder().WithFunc(rt.hostSetVar).Export("set_var").
		NewFunctionBuilder().WithFunc(rt.hostSetVerdict).Export("set_verdict").
		Instantiate(ctx); err != nil {
		_ = runtime.Close(ctx)
		return nil, errs.Wrap(err, ErrWASM)
	}
	compiled, err := runtime.CompileModule(ctx, moduleBytes)
	if err != nil {
		_ = runtime.Close(ctx)
		return nil, errs.Wrap(err, ErrWASM)
	}
	rt.compiled = compiled
	probe, err := rt.newInstance(ctx)
	if err != nil {
		_ = runtime.Close(ctx)
		return nil, errs.Wrap(err, ErrWASM)
	}
	rt.mu.Lock()
	rt.idle = append(rt.idle, probe)
	rt.mu.Unlock()
	points := config.Points
	if len(points) == 0 {
		points = allHookPoints()
	}
	return &wasmPlugin{
		name:       config.Name,
		points:     points,
		runtime:    rt,
		timeout:    timeout,
		failClosed: config.FailClosed,
		logger:     logger,
		counters:   counters,
	}, nil
}

// loadWASMBytes reads the module from Bytes, FS or the operating system. | loadWASMBytes 从 Bytes、
// FS 或操作系统读取模块。
func loadWASMBytes(config WASMPluginConfig) ([]byte, error) {
	if len(config.Bytes) > 0 {
		if len(config.Bytes) > maxWASMModuleBytes {
			return nil, errs.Detail(ErrWASM, "wasm module too large | WASM 模块过大")
		}
		return config.Bytes, nil
	}
	if config.Path == "" {
		return nil, errs.Detail(ErrWASM, "wasm plugin %q has no module | WASM 插件 %q 没有模块", config.Name, config.Name)
	}
	var data []byte
	var err error
	if config.FS != nil {
		data, err = fs.ReadFile(config.FS, config.Path)
	} else {
		data, err = os.ReadFile(config.Path)
	}
	if err != nil {
		return nil, errs.WrapDetail(err, ErrWASM, "cannot read wasm module %q | 无法读取 WASM 模块 %q", config.Path, config.Path)
	}
	if len(data) > maxWASMModuleBytes {
		return nil, errs.Detail(ErrWASM, "wasm module too large | WASM 模块过大")
	}
	return data, nil
}

// run invokes the plugin for one hook event. | run 为一个钩子事件调用插件。
func (p *wasmPlugin) run(ctx *HookContext) error {
	if p == nil || p.closed.Load() || ctx == nil || ctx.tx == nil {
		return nil
	}
	if until := p.disabledUntil.Load(); until != 0 {
		if time.Now().UnixNano() < until {
			if p.failClosed {
				ctx.Deny(http.StatusServiceUnavailable, "wasm plugin disabled | WASM 插件已禁用")
				return ErrDisabled
			}
			return nil
		}
		p.disabledUntil.Store(0)
	}
	payload, err := json.Marshal(buildWASMEvent(ctx))
	if err != nil {
		return errs.Wrap(err, ErrWASM)
	}
	if len(payload) > maxWASMPayloadBytes {
		return errs.Detail(ErrWASM, "wasm event too large | WASM 事件过大")
	}
	base := context.Background()
	if ctx.Request != nil {
		base = ctx.Request.Context()
	}
	callCtx, cancel := context.WithTimeout(base, p.timeout)
	defer cancel()
	result, err := p.runtime.invoke(callCtx, ctx.tx, payload)
	if err != nil {
		p.recordFailure()
		if p.failClosed {
			ctx.Deny(http.StatusServiceUnavailable, "wasm plugin unavailable | WASM 插件不可用")
		}
		return errs.Wrap(err, ErrWASM)
	}
	p.failures.Store(0)
	switch result.verdict {
	case 1:
		ctx.Deny(result.status, result.message)
	case 2:
		ctx.Drop(result.status, result.message)
	case 3:
		ctx.tx.allow = true
	}
	return nil
}

// recordFailure advances the circuit breaker. | recordFailure 推进熔断器。
func (p *wasmPlugin) recordFailure() {
	if p.failures.Add(1) >= wasmFailureThreshold {
		p.disabledUntil.Store(time.Now().Add(wasmDisableCooldown).UnixNano())
		p.failures.Store(0)
		p.logger.Error("waf wasm plugin disabled by circuit breaker | WAF WASM 插件因熔断被禁用",
			log.Str("plugin", p.name), log.Dur("cooldown", wasmDisableCooldown))
	}
}

// close releases the runtime. | close 释放运行时。
func (p *wasmPlugin) close() {
	if p == nil || p.closed.Swap(true) {
		return
	}
	p.runtime.close()
}

// invoke runs one guest hook call on a pooled instance. | invoke 在池化实例上执行一次客户钩子调用。
func (r *wasmRuntime) invoke(ctx context.Context, tx *transaction, payload []byte) (wasmCallResult, error) {
	instance, err := r.acquire(ctx)
	if err != nil {
		return wasmCallResult{}, err
	}
	broken := false
	defer func() { r.release(instance, broken) }()
	state := &wasmCallState{tx: tx}
	instance.current.Store(state)
	defer instance.current.Store(nil)
	var ptr uint32
	if len(payload) > 0 {
		if instance.fnAlloc == nil {
			broken = true
			return wasmCallResult{}, errs.Detail(ErrWASM, "guest does not export ydx_waf_alloc | 客户未导出 ydx_waf_alloc")
		}
		results, allocErr := instance.fnAlloc.Call(ctx, uint64(len(payload)))
		if allocErr != nil {
			broken = true
			return wasmCallResult{}, allocErr
		}
		if len(results) == 0 || results[0] == 0 {
			broken = true
			return wasmCallResult{}, errs.Detail(ErrWASM, "guest allocation failed | 客户内存分配失败")
		}
		ptr = uint32(results[0])
		if !instance.mod.Memory().Write(ptr, payload) {
			broken = true
			return wasmCallResult{}, errs.Detail(ErrWASM, "guest memory write failed | 客户内存写入失败")
		}
	}
	results, callErr := instance.fnHook.Call(ctx, uint64(ptr), uint64(len(payload)))
	if ptr != 0 && instance.fnFree != nil {
		freeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, _ = instance.fnFree.Call(freeCtx, uint64(ptr))
		cancel()
	}
	if callErr != nil {
		broken = true
		return wasmCallResult{}, callErr
	}
	verdict := state.verdict
	if verdict == 0 && len(results) > 0 {
		verdict = int32(results[0])
	}
	return wasmCallResult{verdict: verdict, status: int(state.status), message: state.message}, nil
}

// acquire borrows an idle instance or creates one within the concurrency limit. | acquire 借用一个
// 空闲实例，或在并发上限内创建新实例。
func (r *wasmRuntime) acquire(ctx context.Context) (*wasmInstance, error) {
	select {
	case r.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	r.mu.Lock()
	if count := len(r.idle); count > 0 {
		instance := r.idle[count-1]
		r.idle = r.idle[:count-1]
		r.mu.Unlock()
		return instance, nil
	}
	r.mu.Unlock()
	instance, err := r.newInstance(ctx)
	if err != nil {
		<-r.sem
		return nil, err
	}
	return instance, nil
}

// release returns an instance to the pool or discards a broken one. | release 把实例归还池中，或
// 丢弃已损坏的实例。
func (r *wasmRuntime) release(instance *wasmInstance, broken bool) {
	defer func() { <-r.sem }()
	if broken {
		instance.close()
		return
	}
	if r.closed.Load() {
		instance.close()
		return
	}
	r.mu.Lock()
	r.idle = append(r.idle, instance)
	r.mu.Unlock()
}

// newInstance instantiates and initializes one guest module. | newInstance 实例化并初始化一个客户模块。
func (r *wasmRuntime) newInstance(ctx context.Context) (*wasmInstance, error) {
	name := r.name + "-" + strconv.FormatUint(r.seq.Add(1), 36)
	module, err := r.rt.InstantiateModule(ctx, r.compiled, wazero.NewModuleConfig().WithName(name))
	if err != nil {
		return nil, err
	}
	cleanup := func() { _ = module.Close(context.Background()) }
	if module.Memory() == nil {
		cleanup()
		return nil, errs.Detail(ErrWASM, "guest module has no memory | 客户模块没有内存")
	}
	fnHook := module.ExportedFunction("ydx_waf_on_hook")
	fnVersion := module.ExportedFunction("ydx_waf_abi_version")
	if fnHook == nil || fnVersion == nil {
		cleanup()
		return nil, errs.Detail(ErrWASM, "guest does not export ydx_waf_on_hook and ydx_waf_abi_version | 客户未导出 ABI 函数")
	}
	versionResults, err := fnVersion.Call(ctx)
	if err != nil {
		cleanup()
		return nil, err
	}
	if len(versionResults) == 0 || int32(versionResults[0]) != wasmABIVersion {
		cleanup()
		return nil, errs.Detail(ErrWASM, "unsupported wasm ABI version | 不支持的 WASM ABI 版本")
	}
	instance := &wasmInstance{
		name:    name,
		mod:     module,
		fnHook:  fnHook,
		fnAlloc: module.ExportedFunction("ydx_waf_alloc"),
		fnFree:  module.ExportedFunction("ydx_waf_free"),
	}
	r.modules.Store(name, instance)
	if len(r.config) > 0 {
		fnInit := module.ExportedFunction("ydx_waf_init")
		if fnInit == nil || instance.fnAlloc == nil {
			instance.close()
			return nil, errs.Detail(ErrWASM, "guest does not export ydx_waf_init and ydx_waf_alloc | 客户未导出初始化 ABI")
		}
		results, callErr := instance.fnAlloc.Call(ctx, uint64(len(r.config)))
		if callErr != nil || len(results) == 0 || results[0] == 0 {
			instance.close()
			if callErr != nil {
				return nil, callErr
			}
			return nil, errs.Detail(ErrWASM, "guest allocation failed | 客户内存分配失败")
		}
		ptr := uint32(results[0])
		if !module.Memory().Write(ptr, r.config) {
			instance.close()
			return nil, errs.Detail(ErrWASM, "guest memory write failed | 客户内存写入失败")
		}
		initResults, initErr := fnInit.Call(ctx, uint64(ptr), uint64(len(r.config)))
		if instance.fnFree != nil {
			_, _ = instance.fnFree.Call(context.Background(), uint64(ptr))
		}
		if initErr != nil {
			instance.close()
			return nil, initErr
		}
		if len(initResults) > 0 && int32(initResults[0]) != 0 {
			instance.close()
			return nil, errs.Detail(ErrWASM, "guest init returned failure | 客户初始化返回失败")
		}
	}
	return instance, nil
}

// close releases the runtime and every instance. | close 释放运行时与全部实例。
func (r *wasmRuntime) close() {
	if r == nil || r.closed.Swap(true) {
		return
	}
	_ = r.rt.Close(context.Background())
}

// close releases one guest module. | close 释放一个客户模块。
func (i *wasmInstance) close() {
	if i == nil || i.closed.Swap(true) {
		return
	}
	_ = i.mod.Close(context.Background())
}

// instanceFor resolves the instance that owns a calling guest module. | instanceFor 解析调用中的
// 客户模块所属实例。
func (r *wasmRuntime) instanceFor(module api.Module) *wasmInstance {
	if module == nil {
		return nil
	}
	value, ok := r.modules.Load(module.Name())
	if !ok {
		return nil
	}
	instance, _ := value.(*wasmInstance)
	return instance
}

// hostLog implements ydx_waf.log(level, ptr, len). | hostLog 实现 ydx_waf.log(level, ptr, len)。
func (r *wasmRuntime) hostLog(_ context.Context, module api.Module, level, ptr, size uint32) {
	if size > maxWASMLogBytes {
		size = maxWASMLogBytes
	}
	data, ok := readGuestMemory(module, ptr, size)
	if !ok {
		return
	}
	fields := []log.Field{log.Str("plugin", r.name), log.Str("message", string(data))}
	switch level {
	case 0:
		r.logger.Debug("waf wasm log | WAF WASM 日志", fields...)
	case 1:
		r.logger.Info("waf wasm log | WAF WASM 日志", fields...)
	case 2:
		r.logger.Warn("waf wasm log | WAF WASM 日志", fields...)
	default:
		r.logger.Error("waf wasm log | WAF WASM 日志", fields...)
	}
}

// hostGetVar implements ydx_waf.get_var(namePtr, nameLen, outPtr, outCap) -> length.
// | hostGetVar 实现 ydx_waf.get_var(namePtr, nameLen, outPtr, outCap) -> length。
func (r *wasmRuntime) hostGetVar(_ context.Context, module api.Module, namePtr, nameLen, outPtr, outCap uint32) int32 {
	instance := r.instanceFor(module)
	if instance == nil {
		return -1
	}
	state := instance.current.Load()
	if state == nil || state.tx == nil {
		return -1
	}
	if nameLen > maxWASMNameBytes {
		return -1
	}
	name, ok := readGuestMemory(module, namePtr, nameLen)
	if !ok {
		return -1
	}
	value := state.tx.lastTX(string(name))
	if outPtr != 0 && outCap > 0 {
		length := len(value)
		if length > int(outCap) {
			length = int(outCap)
		}
		if module.Memory() != nil {
			_ = module.Memory().Write(outPtr, []byte(value[:length]))
		}
	}
	return int32(len(value))
}

// hostSetVar implements ydx_waf.set_var(namePtr, nameLen, valuePtr, valueLen). | hostSetVar 实现
// ydx_waf.set_var(namePtr, nameLen, valuePtr, valueLen)。
func (r *wasmRuntime) hostSetVar(_ context.Context, module api.Module, namePtr, nameLen, valuePtr, valueLen uint32) int32 {
	instance := r.instanceFor(module)
	if instance == nil {
		return -1
	}
	state := instance.current.Load()
	if state == nil || state.tx == nil {
		return -1
	}
	if nameLen > maxWASMNameBytes || valueLen > maxWASMValueBytes {
		return -1
	}
	name, ok := readGuestMemory(module, namePtr, nameLen)
	if !ok {
		return -1
	}
	value, ok := readGuestMemory(module, valuePtr, valueLen)
	if !ok {
		return -1
	}
	state.tx.setTXValue(string(name), string(value), 0)
	return 0
}

// hostSetVerdict implements ydx_waf.set_verdict(code, status, msgPtr, msgLen). | hostSetVerdict
// 实现 ydx_waf.set_verdict(code, status, msgPtr, msgLen)。
func (r *wasmRuntime) hostSetVerdict(_ context.Context, module api.Module, code, status, msgPtr, msgLen uint32) int32 {
	instance := r.instanceFor(module)
	if instance == nil {
		return -1
	}
	state := instance.current.Load()
	if state == nil {
		return -1
	}
	state.verdict = int32(code)
	state.status = int32(status)
	if message, ok := readGuestMemory(module, msgPtr, msgLen); ok {
		state.message = string(message)
	}
	return 0
}

// readGuestMemory copies a guest memory range. | readGuestMemory 复制一段客户内存。
func readGuestMemory(module api.Module, ptr, size uint32) ([]byte, bool) {
	if size == 0 {
		return nil, true
	}
	if module == nil || module.Memory() == nil {
		return nil, false
	}
	data, ok := module.Memory().Read(ptr, size)
	if !ok {
		return nil, false
	}
	return append([]byte(nil), data...), true
}

// buildWASMEvent renders the hook context as the JSON event document. | buildWASMEvent 把钩子上下文
// 渲染为 JSON 事件文档。
func buildWASMEvent(ctx *HookContext) wasmHookEvent {
	event := wasmHookEvent{
		Point:       ctx.Point.String(),
		Phase:       int(ctx.Phase),
		Version:     ctx.Version,
		Interrupted: ctx.Interruption,
	}
	if ctx.tx != nil {
		event.TxID = ctx.tx.id
		event.ClientIP = ctx.tx.clientIP
	}
	if ctx.Request != nil {
		event.Method = ctx.Request.Method
		event.Path = ctx.Request.URL.Path
	}
	if ctx.Rule != nil {
		event.RuleID = ctx.Rule.ID
		event.Message = ctx.Rule.Msg
		event.Severity = ctx.Rule.Severity
		event.Tags = ctx.Rule.Tags
	}
	if ctx.Match != nil {
		event.Var = ctx.Match.Var
		event.Key = ctx.Match.Key
		event.Value = ctx.Match.Value
		event.Message = ctx.Match.Message
		event.Severity = ctx.Match.Severity
		event.Tags = ctx.Match.Tags
	}
	if ctx.Err != nil {
		event.Error = ctx.Err.Error()
	}
	return event
}
