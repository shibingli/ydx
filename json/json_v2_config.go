package json

import (
	stdjson "encoding/json"
	"encoding/json/jsontext"
	stdjsonv2 "encoding/json/v2"

	"github.com/shibingli/ydx/errs"
)

var (
	errUnregisteredMarshalers   = errs.New("jsonx: Marshalers must be constructed by this package | jsonx：Marshalers 必须由本包构造")
	errUnregisteredUnmarshalers = errs.New("jsonx: Unmarshalers must be constructed by this package | jsonx：Unmarshalers 必须由本包构造")
)

// v2Config is the fully resolved option set of one v2 marshal or unmarshal call. The zero value
// is never used: every field carries the effective value after joining DefaultOptionsV2 with the
// caller's options. | v2Config 是一次 v2 编解码调用完全解析后的选项集合。不会使用零值：每个字段都
// 携带 DefaultOptionsV2 与调用方选项合并后的生效值。
type v2Config struct {
	opts Options

	invalid      error
	indent       string
	indentPrefix string

	marshalers   []marshalerEntry
	unmarshalers []unmarshalerEntry

	// Marshal behavior. | 编码行为。
	escapeHTML               bool
	escapeJS                 bool
	allowInvalidUTF8         bool
	preserveRawStrings       bool
	canonicalizeRawInts      bool
	canonicalizeRawFloats    bool
	reorderRawObjects        bool
	formatNilMapAsNull       bool
	formatNilSliceAsNull     bool
	deterministic            bool
	omitZeroStructFields     bool
	stringifyNumbers         bool
	formatByteArrayAsArray   bool
	formatDurationAsNano     bool
	formatBytesWithLegacy    bool
	callMethodsWithLegacy    bool
	omitEmptyWithLegacy      bool
	stringifyWithLegacy      bool
	reportErrorsWithLegacy   bool
	matchCaseSensitiveDelim  bool
	mergeWithLegacySemantics bool

	// Unmarshal behavior. | 解码行为。
	allowDuplicateNames         bool
	matchCaseInsensitiveNames   bool
	rejectUnknownMembers        bool
	unmarshalArrayFromAnyLength bool
	parseBytesWithLooseRFC4648  bool
	parseTimeWithLooseRFC3339   bool

	// Formatting. | 格式化。
	multiline       bool
	indentSet       bool
	indentPrefixSet bool
	spaceAfterColon bool
	spaceAfterComma bool
}

// v2DefaultConfig is the immutable option set defined by DefaultOptionsV2. Sharing one instance
// keeps the common v2 entry allocation-free; it must never be mutated. | v2DefaultConfig 是
// DefaultOptionsV2 定义的不可变选项集合。共享单例使常见 v2 入口零分配；它绝不能被修改。
var v2DefaultConfig = &v2Config{}

// newV2Defaults returns a fresh, mutable copy of the v2 defaults. | newV2Defaults 返回可修改的
// v2 默认值副本。
func newV2Defaults() *v2Config { return &v2Config{} }

// parseV2Config resolves opts into a v2Config. A nil result means the effective options are the
// v1 defaults and the native v1 fast path can run unchanged. | parseV2Config 把 opts 解析为
// v2Config；返回 nil 表示生效选项就是 v1 默认值，可直接走原生 v1 快速路径。
func parseV2Config(opts []Options) *v2Config {
	if len(opts) == 1 {
		// DefaultOptionsV2 is a stable pointer; the common v2 entry avoids joining and querying
		// every flag. | DefaultOptionsV2 是稳定指针；常见 v2 入口无需合并并逐项查询标志位。
		if opts[0] == stdjsonv2.DefaultOptionsV2() {
			return v2DefaultConfig
		}
		if opts[0] == DefaultOptionsV1() {
			return nil
		}
	}
	joined := stdjsonv2.JoinOptions(opts...)
	c := newV2Defaults()
	c.opts = joined
	c.escapeHTML = getBoolOption(joined, jsontext.EscapeForHTML, false)
	c.escapeJS = getBoolOption(joined, jsontext.EscapeForJS, false)
	c.allowDuplicateNames = getBoolOption(joined, jsontext.AllowDuplicateNames, false)
	c.allowInvalidUTF8 = getBoolOption(joined, jsontext.AllowInvalidUTF8, false)
	c.preserveRawStrings = getBoolOption(joined, jsontext.PreserveRawStrings, false)
	c.canonicalizeRawInts = getBoolOption(joined, jsontext.CanonicalizeRawInts, false)
	c.canonicalizeRawFloats = getBoolOption(joined, jsontext.CanonicalizeRawFloats, false)
	c.reorderRawObjects = getBoolOption(joined, jsontext.ReorderRawObjects, false)
	c.multiline = getBoolOption(joined, jsontext.Multiline, false)
	c.spaceAfterColon = getBoolOption(joined, jsontext.SpaceAfterColon, false)
	c.spaceAfterComma = getBoolOption(joined, jsontext.SpaceAfterComma, false)
	c.indent, c.indentSet = stdjsonv2.GetOption(joined, jsontext.WithIndent)
	c.indentPrefix, c.indentPrefixSet = stdjsonv2.GetOption(joined, jsontext.WithIndentPrefix)
	c.deterministic = getBoolOption(joined, stdjsonv2.Deterministic, false)
	c.formatNilMapAsNull = getBoolOption(joined, stdjsonv2.FormatNilMapAsNull, false)
	c.formatNilSliceAsNull = getBoolOption(joined, stdjsonv2.FormatNilSliceAsNull, false)
	c.omitZeroStructFields = getBoolOption(joined, stdjsonv2.OmitZeroStructFields, false)
	c.matchCaseInsensitiveNames = getBoolOption(joined, stdjsonv2.MatchCaseInsensitiveNames, false)
	c.rejectUnknownMembers = getBoolOption(joined, stdjsonv2.RejectUnknownMembers, false)
	c.stringifyNumbers = getBoolOption(joined, stdjsonv2.StringifyNumbers, false)
	c.callMethodsWithLegacy = getBoolOption(joined, stdjson.CallMethodsWithLegacySemantics, false)
	c.formatByteArrayAsArray = getBoolOption(joined, stdjson.FormatByteArrayAsArray, false)
	c.formatBytesWithLegacy = getBoolOption(joined, stdjson.FormatBytesWithLegacySemantics, false)
	c.formatDurationAsNano = getBoolOption(joined, stdjson.FormatDurationAsNano, false)
	c.matchCaseSensitiveDelim = getBoolOption(joined, stdjson.MatchCaseSensitiveDelimiter, false)
	c.mergeWithLegacySemantics = getBoolOption(joined, stdjson.MergeWithLegacySemantics, false)
	c.omitEmptyWithLegacy = getBoolOption(joined, stdjson.OmitEmptyWithLegacySemantics, false)
	c.parseBytesWithLooseRFC4648 = getBoolOption(joined, stdjson.ParseBytesWithLooseRFC4648, false)
	c.parseTimeWithLooseRFC3339 = getBoolOption(joined, stdjson.ParseTimeWithLooseRFC3339, false)
	c.reportErrorsWithLegacy = getBoolOption(joined, stdjson.ReportErrorsWithLegacySemantics, false)
	c.stringifyWithLegacy = getBoolOption(joined, stdjson.StringifyWithLegacySemantics, false)
	c.unmarshalArrayFromAnyLength = getBoolOption(joined, stdjson.UnmarshalArrayFromAnyLength, false)

	if ms, ok := stdjsonv2.GetOption(joined, stdjsonv2.WithMarshalers); ok && ms != nil {
		c.marshalers = lookupMarshalers(ms)
		if len(c.marshalers) == 0 {
			c.invalid = errUnregisteredMarshalers
		}
	}
	if us, ok := stdjsonv2.GetOption(joined, stdjsonv2.WithUnmarshalers); ok && us != nil {
		c.unmarshalers = lookupUnmarshalers(us)
		if len(c.unmarshalers) == 0 {
			c.invalid = errUnregisteredUnmarshalers
		}
	}
	if becomesV1(c) {
		return nil
	}
	return c
}

// getBoolOption returns the effective boolean value of one option, falling back to def. |
// getBoolOption 返回单个选项的生效布尔值，缺省时返回 def。
func getBoolOption[T any](opts Options, setter func(T) Options, def bool) bool {
	if v, ok := stdjsonv2.GetOption(opts, setter); ok {
		return asBool(v)
	}
	return def
}

// asBool converts the boolean option value family to bool. GetOption's type parameter makes the
// value statically bool in normal use; this helper keeps the call sites short. | asBool 把布尔选项
// 值族转换为 bool。正常使用时 GetOption 的类型参数已保证静态 bool，这里只是让调用点更简洁。
func asBool[T any](v T) bool { return any(v).(bool) }

// becomesV1 reports whether c is behaviorally identical to the v1 defaults, in which case the
// native v1 fast path handles the call with no v2 branches. | becomesV1 报告 c 是否与 v1 默认行为
// 完全一致；若是，则由原生 v1 快速路径处理，不引入 v2 分支。
func becomesV1(c *v2Config) bool {
	if c.invalid != nil || c.marshalers != nil || c.unmarshalers != nil {
		return false
	}
	return c.escapeHTML && c.escapeJS && c.allowInvalidUTF8 &&
		c.preserveRawStrings && !c.canonicalizeRawInts && !c.canonicalizeRawFloats &&
		!c.reorderRawObjects && c.formatNilMapAsNull && c.formatNilSliceAsNull &&
		c.deterministic && !c.omitZeroStructFields && !c.stringifyNumbers &&
		c.formatByteArrayAsArray && c.formatDurationAsNano && c.formatBytesWithLegacy &&
		c.callMethodsWithLegacy && c.omitEmptyWithLegacy &&
		c.stringifyWithLegacy && c.reportErrorsWithLegacy && c.matchCaseSensitiveDelim &&
		c.mergeWithLegacySemantics && c.allowDuplicateNames && c.matchCaseInsensitiveNames &&
		!c.rejectUnknownMembers && c.unmarshalArrayFromAnyLength &&
		c.parseBytesWithLooseRFC4648 && c.parseTimeWithLooseRFC3339 &&
		!c.multiline && c.indent == "" && c.indentPrefix == "" &&
		!c.spaceAfterColon && !c.spaceAfterComma
}
