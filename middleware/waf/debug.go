package waf

import (
	"fmt"
	"io"

	"github.com/corazawaf/coraza/v3/debuglog"
)

// noopDebugLogger implements debuglog.Logger without allocating on With. Coraza calls
// Logger.With for every transaction to attach the transaction ID; the default logger allocates
// an event and appends fields even when no debug record is emitted. | noopDebugLogger 实现
// debuglog.Logger，且 With 不分配。Coraza 会为每个事务调用 Logger.With 附加事务 ID；默认
// 日志器即使不输出记录也会分配事件并追加字段。
type noopDebugLogger struct{}

// WithOutput returns the same no-op logger. | WithOutput 返回同一个 no-op 日志器。
func (noopDebugLogger) WithOutput(io.Writer) debuglog.Logger { return noopDebugLogger{} }

// WithLevel returns the same no-op logger. | WithLevel 返回同一个 no-op 日志器。
func (noopDebugLogger) WithLevel(debuglog.Level) debuglog.Logger { return noopDebugLogger{} }

// With returns the same no-op logger without materializing context fields. | With 不物化上下文
// 字段，直接返回同一个 no-op 日志器。
func (noopDebugLogger) With(...debuglog.ContextField) debuglog.Logger { return noopDebugLogger{} }

// Trace returns a disabled event. | Trace 返回禁用的事件。
func (noopDebugLogger) Trace() debuglog.Event { return noopDebugEvent{} }

// Debug returns a disabled event. | Debug 返回禁用的事件。
func (noopDebugLogger) Debug() debuglog.Event { return noopDebugEvent{} }

// Info returns a disabled event. | Info 返回禁用的事件。
func (noopDebugLogger) Info() debuglog.Event { return noopDebugEvent{} }

// Warn returns a disabled event. | Warn 返回禁用的事件。
func (noopDebugLogger) Warn() debuglog.Event { return noopDebugEvent{} }

// Error returns a disabled event. | Error 返回禁用的事件。
func (noopDebugLogger) Error() debuglog.Event { return noopDebugEvent{} }

// noopDebugEvent is a zero-allocation disabled event. | noopDebugEvent 是零分配的禁用事件。
type noopDebugEvent struct{}

// Msg discards the message. | Msg 丢弃消息。
func (noopDebugEvent) Msg(string) {}

// Str discards the field. | Str 丢弃字段。
func (e noopDebugEvent) Str(string, string) debuglog.Event { return e }

// Err discards the error. | Err 丢弃错误。
func (e noopDebugEvent) Err(error) debuglog.Event { return e }

// Bool discards the field. | Bool 丢弃字段。
func (e noopDebugEvent) Bool(string, bool) debuglog.Event { return e }

// Int discards the field. | Int 丢弃字段。
func (e noopDebugEvent) Int(string, int) debuglog.Event { return e }

// Uint discards the field. | Uint 丢弃字段。
func (e noopDebugEvent) Uint(string, uint) debuglog.Event { return e }

// Stringer discards the field. | Stringer 丢弃字段。
func (e noopDebugEvent) Stringer(string, fmt.Stringer) debuglog.Event { return e }

// IsEnabled reports false so callers can skip formatting. | IsEnabled 返回 false，调用方可以
// 跳过格式化。
func (noopDebugEvent) IsEnabled() bool { return false }

var (
	_ debuglog.Logger = noopDebugLogger{}
	_ debuglog.Event  = noopDebugEvent{}
)
