//go:build !jsonx_std

package json

import (
	"encoding/json/jsontext"
	stdjsonv2 "encoding/json/v2"
	"errors"
	"reflect"
)

// marshalV2 encodes v with the resolved v2 option set. The buffer strategy is shared with the v1
// path so both modes keep the same allocation profile. | marshalV2 按解析后的 v2 选项集合编码 v；
// 缓冲策略与 v1 路径共用，使两种模式保持相同的分配特征。
func marshalV2(v any, cfg *v2Config) ([]byte, error) {
	if cfg.invalid != nil {
		return nil, cfg.invalid
	}
	return marshalMode(v, cfg)
}

// getEncoderMode returns a pooled encoder for the resolved mode. | getEncoderMode 返回解析模式对应的
// 池化编码器。
func getEncoderMode(cfg *v2Config) *encoder {
	if cfg == nil {
		return getEncoder(true)
	}
	return getEncoderV2(cfg)
}

// cfgEscapeHTML is the effective HTML escaping setting. | cfgEscapeHTML 是生效的 HTML 转义设置。
func cfgEscapeHTML(cfg *v2Config) bool {
	if cfg == nil {
		return true
	}
	return cfg.escapeHTML
}

// fastStructAllowed reports whether the branch-free fast struct plan can honor cfg. |
// fastStructAllowed 报告无分支快速结构体计划能否满足 cfg。
func fastStructAllowed(cfg *v2Config) bool {
	return cfg == nil || !(cfg.omitZeroStructFields || cfg.stringifyNumbers || len(cfg.marshalers) > 0)
}

// finalizeBuf applies v2 error and formatting handling to an encoded buffer. |
// finalizeBuf 对已编码缓冲应用 v2 错误与格式化处理。
func finalizeBuf(e *encoder, cfg *v2Config) error {
	if e.err != nil {
		return e.err
	}
	if cfg != nil && cfg.compactFormatting() {
		e.buf = formatV2(e.buf, cfg)
	}
	return nil
}

// compactFormatting reports whether the call needs whitespace formatting after encoding. |
// compactFormatting 报告调用是否需要编码后的空白格式化。
func (c *v2Config) compactFormatting() bool {
	return c.multiline || c.indent != "" || c.indentPrefix != "" || c.spaceAfterColon || c.spaceAfterComma
}

// v2MarshalError normalizes a native error into the encoding/json/v2 error shape on the error
// path. The success path never calls it. | v2MarshalError 在错误路径上把原生错误归一为
// encoding/json/v2 的错误形态；成功路径绝不会调用。
func v2MarshalError(v any, cfg *v2Config, err error) error {
	var se *stdjsonv2.SemanticError
	var syn *jsontext.SyntacticError
	if errors.As(err, &se) || errors.As(err, &syn) || errors.Is(err, errUnregisteredMarshalers) {
		return err
	}
	t := reflect.TypeOf(v)
	if t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	se = &stdjsonv2.SemanticError{GoType: t, Err: err}
	setSemanticAction(se, "marshal")
	return se
}

// unmarshalV2 decodes data into out with the resolved v2 option set. | unmarshalV2 按解析后的 v2
// 选项集合把 data 解码进 out。
func unmarshalV2(data []byte, out any, cfg *v2Config) error {
	if cfg.invalid != nil {
		return cfg.invalid
	}
	rv := reflect.ValueOf(out)
	if !rv.IsValid() || rv.Kind() != reflect.Pointer || rv.IsNil() {
		var t reflect.Type
		if rv.IsValid() {
			t = rv.Type()
		}
		return newUnmarshalSemanticError(t, 0, nil, "value must be passed as a non-nil pointer reference")
	}
	d := decoderPool.Get().(*decoder)
	d.data = data
	d.pos = 0
	d.depth = 0
	d.useNumber = false
	d.skipLen = false
	d.timeLen = 0
	d.disallowUnknown = cfg.rejectUnknownMembers
	d.v2 = cfg
	err := d.unmarshal(rv)
	pos := d.pos
	d.data = nil
	d.v2 = nil
	d.disallowUnknown = false
	if cap(d.arena) > maxArenaRetain {
		d.arena = nil
	}
	decoderPool.Put(d)
	if err != nil {
		return v2UnmarshalError(data, out, cfg, pos, err)
	}
	return nil
}

// v2UnmarshalError normalizes a native error into the encoding/json/v2 error shape on the error
// path. Errors that already carry a standard v2 type pass through unchanged. v2 reports a
// syntactic error before a type mismatch, so a type error is re-checked against a strict syntax
// scan; that scan runs only on the error path. | v2UnmarshalError 在错误路径上把原生错误归一为
// encoding/json/v2 的错误形态；已携带标准 v2 类型的错误原样返回。v2 在类型不匹配之前报告语法错误，
// 因此类型错误会用严格语法扫描复核；该扫描只在错误路径执行。
func v2UnmarshalError(data []byte, out any, cfg *v2Config, pos int, err error) error {
	var se *stdjsonv2.SemanticError
	var syn *jsontext.SyntacticError
	if errors.As(err, &se) || errors.As(err, &syn) {
		return err
	}
	if errors.Is(err, ErrSyntax) {
		return &jsontext.SyntacticError{ByteOffset: int64(pos), Err: err}
	}
	if errors.Is(err, ErrTypeMismatch) {
		check := &decoder{data: data, v2: cfg}
		if verr := check.skipValue(); verr != nil {
			return verr
		}
	}
	t := reflect.TypeOf(out)
	if t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	se = &stdjsonv2.SemanticError{GoType: t, Err: err}
	setSemanticAction(se, "unmarshal")
	return se
}
