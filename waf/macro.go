package waf

import (
	"strings"

	"github.com/shibingli/ydx/errs"
)

// macroPart is either literal text or a variable selector. | macroPart 是字面量文本或变量选择器。
type macroPart struct {
	literal  string
	selector varSelector
	isVar    bool
}

// macro is a compiled SecLang macro string. | macro 是编译后的 SecLang 宏字符串。
type macro struct {
	plain string
	parts []macroPart
}

// compileMacro parses %{NAME} and %{NAME.KEY} references into a reusable macro. | compileMacro 把
// %{NAME} 与 %{NAME.KEY} 引用解析为可复用宏。
func compileMacro(s string) (macro, error) {
	if !strings.Contains(s, "%{") {
		return macro{plain: s}, nil
	}
	parts := make([]macroPart, 0, 4)
	for {
		start := strings.Index(s, "%{")
		if start < 0 {
			if s != "" {
				parts = append(parts, macroPart{literal: s})
			}
			break
		}
		if start > 0 {
			parts = append(parts, macroPart{literal: s[:start]})
		}
		end := strings.IndexByte(s[start+2:], '}')
		if end < 0 {
			return macro{}, errs.Detail(ErrParse, "unterminated macro %q | 宏未闭合 %q", s, s)
		}
		inner := s[start+2 : start+2+end]
		s = s[start+2+end+1:]
		selector, err := parseMacroSelector(inner)
		if err != nil {
			return macro{}, err
		}
		parts = append(parts, macroPart{selector: selector, isVar: true})
	}
	return macro{parts: parts}, nil
}

// parseMacroSelector parses the inside of a %{...} reference. | parseMacroSelector 解析 %{...} 引用内部。
func parseMacroSelector(inner string) (varSelector, error) {
	inner = strings.TrimSpace(inner)
	if inner == "" {
		return varSelector{}, errs.Detail(ErrParse, "empty macro selector | 空宏选择器")
	}
	name := inner
	key := ""
	if idx := strings.IndexByte(inner, '.'); idx >= 0 {
		name = inner[:idx]
		key = inner[idx+1:]
	}
	name = strings.ToUpper(name)
	if _, ok := knownVariables[name]; !ok {
		return varSelector{}, errs.Detail(ErrUnsupported, "unknown macro variable %q | 未知宏变量 %q", name, name)
	}
	selector := varSelector{Name: name, Key: key}
	if len(key) >= 2 && key[0] == '/' && key[len(key)-1] == '/' {
		parsed, _, err := parseVarSelector(name + ":" + key)
		if err != nil {
			return varSelector{}, err
		}
		return parsed, nil
	}
	return finishSelector(selector), nil
}

// expand renders the macro for one transaction. | expand 为一个事务渲染宏。
func (m macro) expand(tx *transaction) string {
	if len(m.parts) == 0 {
		return m.plain
	}
	// A single variable reference is the common case for setvar values. Return it directly to
	// avoid a Builder allocation. | 单个变量引用是 setvar 的常见形态，直接返回其值以避免 Builder
	// 分配。
	if len(m.parts) == 1 && m.parts[0].isVar {
		selector := m.parts[0].selector
		if selector.Name == "RULE" && selector.Key != "" {
			return tx.ruleField(selector.Key)
		}
		if value, found, handled := selector.fastValue(tx); handled {
			if !found {
				return ""
			}
			return value.Value
		}
		values := selector.collect(tx)
		if len(values) == 0 {
			return ""
		}
		return values[0].Value
	}
	var b strings.Builder
	b.Grow(len(m.plain) + 32)
	for _, part := range m.parts {
		if !part.isVar {
			b.WriteString(part.literal)
			continue
		}
		if part.selector.Name == "RULE" && part.selector.Key != "" {
			b.WriteString(tx.ruleField(part.selector.Key))
			continue
		}
		values := part.selector.collect(tx)
		if len(values) == 0 {
			continue
		}
		b.WriteString(values[0].Value)
	}
	return b.String()
}

// usesAny reports whether the macro references one of the given variables. | usesAny 报告宏是否
// 引用了给定变量之一。
func (m macro) usesAny(names map[string]struct{}) bool {
	for _, part := range m.parts {
		if !part.isVar {
			continue
		}
		if _, ok := names[part.selector.Name]; ok {
			return true
		}
	}
	return false
}

// isPlain reports whether the macro has no variable references. | isPlain 报告宏是否不含变量引用。
func (m macro) isPlain() bool {
	for _, part := range m.parts {
		if part.isVar {
			return false
		}
	}
	return true
}
