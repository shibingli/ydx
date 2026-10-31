package waf

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// maxIncludeDepth bounds recursive Include expansion. | maxIncludeDepth 限制递归 Include 深度。
const maxIncludeDepth = 16

// ruleLoader reads rule files from an fs.FS or the operating system and expands Include
// directives into one self-contained source. | ruleLoader 从 fs.FS 或操作系统读取规则文件，并把
// Include 指令展开为一个自包含源码。
type ruleLoader struct {
	fsys     fs.FS
	warnings []string
	strict   bool
}

// readFile reads one rule file. | readFile 读取一个规则文件。
func (l *ruleLoader) readFile(name string) ([]byte, error) {
	if l.fsys != nil {
		return fs.ReadFile(l.fsys, strings.TrimPrefix(name, "/"))
	}
	return os.ReadFile(name)
}

// glob expands a path pattern. | glob 展开路径模式。
func (l *ruleLoader) glob(pattern string) ([]string, error) {
	if l.fsys != nil {
		return fs.Glob(l.fsys, strings.TrimPrefix(pattern, "/"))
	}
	return filepath.Glob(pattern)
}

// join joins a base directory and a path. | join 拼接基准目录与路径。
func (l *ruleLoader) join(base, name string) string {
	if l.fsys != nil {
		return path.Join(base, strings.TrimPrefix(name, "/"))
	}
	if filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(base, name)
}

// dir returns the directory part of a path. | dir 返回路径的目录部分。
func (l *ruleLoader) dir(name string) string {
	if l.fsys != nil {
		return path.Dir(name)
	}
	return filepath.Dir(name)
}

// warn records a loader warning. | warn 记录加载器警告。
func (l *ruleLoader) warn(message string) {
	l.warnings = append(l.warnings, message)
}

// expandFile reads a file and inlines every Include directive recursively. | expandFile 读取文件
// 并递归内联每个 Include 指令。
func (l *ruleLoader) expandFile(name string, depth int, stack map[string]bool) (string, error) {
	if depth > maxIncludeDepth {
		return "", errs.Detail(ErrParse, "include depth exceeded at %q | Include 深度超限 %q", name, name)
	}
	canonical := name
	if l.fsys == nil {
		canonical = filepath.Clean(name)
	} else {
		canonical = path.Clean(name)
	}
	if stack[canonical] {
		return "", errs.Detail(ErrParse, "include cycle at %q | Include 循环 %q", name, name)
	}
	stack[canonical] = true
	defer delete(stack, canonical)
	data, err := l.readFile(name)
	if err != nil {
		return "", errs.WrapDetail(err, ErrSource, "cannot read rule file %q | 无法读取规则文件 %q", name, name)
	}
	return l.expandText(string(data), name, depth, stack)
}

// expandText expands Include directives in already-read text. | expandText 在已读取文本中展开
// Include 指令。
func (l *ruleLoader) expandText(text, file string, depth int, stack map[string]bool) (string, error) {
	var b strings.Builder
	b.Grow(len(text) + 256)
	base := l.dir(file)
	for _, line := range splitLogicalLines(text) {
		tokens, err := lexLine(line.text)
		if err != nil {
			return "", errs.WrapDetail(err, ErrParse, "%s:%d", file, line.line)
		}
		if len(tokens) == 0 || (tokens[0] != "Include" && tokens[0] != "IncludeOptional") {
			// Source markers preserve the original file and line for diagnostics after every
			// Include has been inlined. | 源码标记在 Include 全部内联后保留原始文件与行号，供诊断使用。
			b.WriteString("#@ydx ")
			b.WriteString(file)
			b.WriteByte(':')
			b.WriteString(itoa(line.line))
			b.WriteByte('\n')
			b.WriteString(line.text)
			b.WriteByte('\n')
			continue
		}
		if len(tokens) != 2 {
			return "", errs.Detail(ErrParse, "%s:%d: Include requires one path | %s:%d：Include 需要一个路径",
				file, line.line, file, line.line)
		}
		pattern := tokens[1]
		resolved := l.join(base, pattern)
		matches, err := l.glob(resolved)
		if err != nil {
			return "", errs.WrapDetail(err, ErrSource, "%s:%d: include glob failed | %s:%d：Include 通配失败",
				file, line.line, file, line.line)
		}
		if len(matches) == 0 {
			if tokens[0] == "IncludeOptional" {
				l.warn(file + ":" + itoa(line.line) + ": optional include not found: " + pattern +
					" | 可选 Include 未找到")
				continue
			}
			return "", errs.Detail(ErrSource, "%s:%d: include not found: %q | %s:%d：Include 未找到 %q",
				file, line.line, pattern, file, line.line, pattern)
		}
		for _, match := range matches {
			expanded, err := l.expandFile(match, depth+1, stack)
			if err != nil {
				return "", err
			}
			b.WriteString(expanded)
			if !strings.HasSuffix(expanded, "\n") {
				b.WriteByte('\n')
			}
		}
	}
	return b.String(), nil
}

// expandTopLevel expands every configured rule file and appends inline directives. | expandTopLevel
// 展开每个已配置规则文件并追加内联指令。
func (l *ruleLoader) expandTopLevel(files, directives []string) (string, error) {
	var b strings.Builder
	for _, pattern := range files {
		matches, err := l.glob(pattern)
		if err != nil {
			return "", errs.WrapDetail(err, ErrSource, "rule file glob failed: %q | 规则文件通配失败：%q", pattern, pattern)
		}
		if len(matches) == 0 {
			return "", errs.Detail(ErrSource, "rule file not found: %q | 规则文件未找到：%q", pattern, pattern)
		}
		for _, match := range matches {
			expanded, err := l.expandFile(match, 0, make(map[string]bool))
			if err != nil {
				return "", err
			}
			b.WriteString(expanded)
			if !strings.HasSuffix(expanded, "\n") {
				b.WriteByte('\n')
			}
		}
	}
	for _, directive := range directives {
		expanded, err := l.expandText(directive, "<directives>", 0, make(map[string]bool))
		if err != nil {
			return "", err
		}
		b.WriteString(expanded)
		if !strings.HasSuffix(expanded, "\n") {
			b.WriteByte('\n')
		}
	}
	return b.String(), nil
}

// itoa renders an integer without importing fmt. | itoa 在不引入 fmt 的情况下渲染整数。
func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for value > 0 {
		pos--
		buf[pos] = byte('0' + value%10)
		value /= 10
	}
	return string(buf[pos:])
}

// loadLocalSource builds a self-contained SecLang bundle from RuleFiles and Directives.
// | loadLocalSource 从 RuleFiles 与 Directives 构建自包含 SecLang 规则包。
func loadLocalSource(opts Options) (*Bundle, []string, error) {
	if len(opts.RuleFiles) == 0 && len(opts.Directives) == 0 {
		return nil, nil, ErrNoRules
	}
	loader := &ruleLoader{fsys: opts.RootFS, strict: !opts.Lenient}
	source, err := loader.expandTopLevel(opts.RuleFiles, opts.Directives)
	if err != nil {
		return nil, loader.warnings, err
	}
	bundle := &Bundle{Format: FormatSecLang, Data: []byte(source), Version: "local"}
	if err := bundle.seal(); err != nil {
		return nil, loader.warnings, err
	}
	return bundle, loader.warnings, nil
}
