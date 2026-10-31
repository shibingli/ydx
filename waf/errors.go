package waf

import "github.com/shibingli/ydx/errs"

// Package-level sentinel errors. | 包级哨兵错误。
var (
	// ErrNoRules reports a configuration that would inspect every request with no rule.
	// | ErrNoRules 表示配置会检测每个请求却没有任何规则。
	ErrNoRules = errs.New("waf: no rules loaded | waf：未加载任何规则")
	// ErrInvalidMode reports an out-of-range engine mode. | ErrInvalidMode 表示引擎模式越界。
	ErrInvalidMode = errs.New("waf: invalid mode | waf：非法的模式")
	// ErrInvalidLimit reports a body or argument limit outside its supported range.
	// | ErrInvalidLimit 表示正文或参数上限超出支持范围。
	ErrInvalidLimit = errs.New("waf: invalid limit | waf：非法的上限")
	// ErrInvalidOption reports a malformed option value. | ErrInvalidOption 表示选项取值格式错误。
	ErrInvalidOption = errs.New("waf: invalid option | waf：非法的选项")
	// ErrClosed reports use of an instance after Close or Shutdown. | ErrClosed 表示实例已关闭后仍被使用。
	ErrClosed = errs.New("waf: instance is closed | waf：实例已关闭")
	// ErrBuild reports a failure while compiling a rule snapshot. | ErrBuild 表示编译规则快照失败。
	ErrBuild = errs.New("waf: rule build failed | waf：规则构建失败")
	// ErrParse reports a SecLang syntax error. | ErrParse 表示 SecLang 语法错误。
	ErrParse = errs.New("waf: rule parse failed | waf：规则解析失败")
	// ErrUnsupported reports a rule construct the engine does not implement.
	// | ErrUnsupported 表示引擎未实现的规则构造。
	ErrUnsupported = errs.New("waf: unsupported rule construct | waf：不支持的规则构造")
	// ErrSource reports a rule source failure. | ErrSource 表示规则来源失败。
	ErrSource = errs.New("waf: rule source failed | waf：规则来源失败")
	// ErrNotModified reports that a source still serves the loaded bundle.
	// | ErrNotModified 表示来源提供的规则包未变化。
	ErrNotModified = errs.New("waf: rule bundle not modified | waf：规则包未变化")
	// ErrSignature reports a bundle whose signature is missing or invalid.
	// | ErrSignature 表示规则包签名缺失或无效。
	ErrSignature = errs.New("waf: rule bundle signature invalid | waf：规则包签名无效")
	// ErrShutdownTimeout reports that graceful draining exceeded its context.
	// | ErrShutdownTimeout 表示优雅排空超过上下文期限。
	ErrShutdownTimeout = errs.New("waf: shutdown timed out | waf：关闭超时")
	// ErrPlugin reports a plugin lifecycle or invocation failure. | ErrPlugin 表示插件生命周期或调用失败。
	ErrPlugin = errs.New("waf: plugin failed | waf：插件失败")
	// ErrHook reports a hook invocation failure. | ErrHook 表示钩子调用失败。
	ErrHook = errs.New("waf: hook failed | waf：钩子失败")
	// ErrRequestBodyTooLarge reports a request body that exceeded its configured limit.
	// | ErrRequestBodyTooLarge 表示请求正文超过配置上限。
	ErrRequestBodyTooLarge = errs.New("waf: request body too large | waf：请求正文过大")
	// ErrResponseBodyTooLarge reports a response body that exceeded its configured limit.
	// | ErrResponseBodyTooLarge 表示响应正文超过配置上限。
	ErrResponseBodyTooLarge = errs.New("waf: response body too large | waf：响应正文过大")
	// ErrBodyRead reports a failed request body read. | ErrBodyRead 表示请求正文读取失败。
	ErrBodyRead = errs.New("waf: request body read failed | waf：请求正文读取失败")
	// ErrInvalidBundle reports a bundle whose envelope or digest is malformed.
	// | ErrInvalidBundle 表示规则包信封或摘要格式错误。
	ErrInvalidBundle = errs.New("waf: invalid rule bundle | waf：非法的规则包")
	// ErrWASM reports a WASM plugin runtime failure. | ErrWASM 表示 WASM 插件运行时失败。
	ErrWASM = errs.New("waf: wasm plugin failed | waf：WASM 插件失败")
	// ErrDisabled reports a plugin disabled by its circuit breaker. | ErrDisabled 表示插件已被熔断禁用。
	ErrDisabled = errs.New("waf: plugin disabled | waf：插件已禁用")
	// ErrInternal reports an unexpected internal failure such as a recovered panic.
	// | ErrInternal 表示恢复的 panic 等意外内部失败。
	ErrInternal = errs.New("waf: internal failure | waf：内部失败")
)
