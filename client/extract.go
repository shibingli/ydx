package client

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/regexpx"
)

// extractContext is the buffered response view passed to extractors. | extractContext 是传给提取器的缓冲响应视图。
type extractContext struct {
	Header http.Header
	Body   []byte
	Status int
}

// Extractor stores one named extraction rule. | Extractor 存储一条命名提取规则。
type Extractor struct {
	fn   func(extractContext, *Vars) error
	name string
}

// apply runs the extractor and wraps failures with ErrExtract. | apply 运行提取器并用 ErrExtract 包装失败。
func (e Extractor) apply(ctx extractContext, vars *Vars) error {
	if e.name == "" {
		return errs.Detail(ErrExtract, "empty extractor name | 空提取器名")
	}
	if e.fn == nil {
		return errs.Detail(ErrExtract, "nil extractor %q | 空提取器 %q", e.name, e.name)
	}
	if err := e.fn(ctx, vars); err != nil {
		return errs.WrapDetail(err, ErrExtract, "extract %s", e.name)
	}
	return nil
}

// ExtractJSON stores a value at a simple JSON path such as a.b[0].c. | ExtractJSON 按 a.b[0].c 这类简单路径提取值。
func ExtractJSON(name, path string) Extractor {
	tokens := parseJSONPath(path)
	return Extractor{name: name, fn: func(ctx extractContext, vars *Vars) error {
		decoder := json.NewDecoder(bytes.NewReader(ctx.Body))
		decoder.UseNumber()
		var root any
		if err := decoder.Decode(&root); err != nil {
			return err
		}
		value, ok := walkJSON(root, tokens)
		if !ok {
			return errs.Detail(ErrExtract, "path %q missing | 路径 %q 缺失", path, path)
		}
		vars.Set(name, value)
		return nil
	}}
}

// ExtractHeader stores one response header value. | ExtractHeader 存储一个响应头值。
func ExtractHeader(name, header string) Extractor {
	return Extractor{name: name, fn: func(ctx extractContext, vars *Vars) error {
		vars.Set(name, ctx.Header.Get(header))
		return nil
	}}
}

// ExtractStatus stores the response status code. | ExtractStatus 存储响应状态码。
func ExtractStatus(name string) Extractor {
	return Extractor{name: name, fn: func(ctx extractContext, vars *Vars) error {
		vars.Set(name, ctx.Status)
		return nil
	}}
}

// ExtractBody stores the response body as a string. | ExtractBody 把响应正文存为字符串。
func ExtractBody(name string) Extractor {
	return Extractor{name: name, fn: func(ctx extractContext, vars *Vars) error {
		vars.Set(name, string(ctx.Body))
		return nil
	}}
}

// ExtractRegexp stores one capture group from a body regex. | ExtractRegexp 从正文正则中存储一个捕获组。
func ExtractRegexp(name, pattern string, group int) Extractor {
	compiled, compileErr := regexpx.Compile(pattern)
	return Extractor{name: name, fn: func(ctx extractContext, vars *Vars) error {
		if compileErr != nil {
			return compileErr
		}
		matches := compiled.FindStringSubmatch(string(ctx.Body))
		if group < 0 || group >= len(matches) {
			return errs.Detail(ErrExtract, "group %d missing | 捕获组 %d 缺失", group, group)
		}
		vars.Set(name, matches[group])
		return nil
	}}
}

// ExtractFunc stores a value produced by a custom callback. | ExtractFunc 存储自定义回调产生的值。
func ExtractFunc(name string, fn func(*Response, *Vars) error) Extractor {
	return Extractor{name: name, fn: func(ctx extractContext, vars *Vars) error {
		if fn == nil {
			return errs.Detail(ErrExtract, "nil extract func | 空提取函数")
		}
		header := ctx.Header.Clone()
		if header == nil {
			header = make(http.Header)
		}
		resp := &Response{Response: &http.Response{
			StatusCode: ctx.Status,
			Header:     header,
			Body:       io.NopCloser(bytes.NewReader(ctx.Body)),
		}}
		return fn(resp, vars)
	}}
}

// jsonPathToken is one key or index in a simple JSON path. | jsonPathToken 是简单 JSON 路径中的一个键或索引。
type jsonPathToken struct {
	key     string
	index   int
	isIndex bool
}

// parseJSONPath parses a.b[0].c into tokens. | parseJSONPath 把 a.b[0].c 解析为 token。
func parseJSONPath(path string) []jsonPathToken {
	var tokens []jsonPathToken
	for i := 0; i < len(path); {
		switch path[i] {
		case '.':
			i++
		case '[':
			end := strings.IndexByte(path[i:], ']')
			if end < 0 {
				return tokens
			}
			index, err := strconv.Atoi(path[i+1 : i+end])
			if err == nil {
				tokens = append(tokens, jsonPathToken{index: index, isIndex: true})
			}
			i += end + 1
		default:
			start := i
			for i < len(path) && path[i] != '.' && path[i] != '[' {
				i++
			}
			if start < i {
				tokens = append(tokens, jsonPathToken{key: path[start:i]})
			}
		}
	}
	return tokens
}

// walkJSON resolves tokens against a decoded JSON value. | walkJSON 在已解码 JSON 值上解析 token。
func walkJSON(root any, tokens []jsonPathToken) (any, bool) {
	current := root
	for _, token := range tokens {
		if token.isIndex {
			list, ok := current.([]any)
			if !ok || token.index < 0 || token.index >= len(list) {
				return nil, false
			}
			current = list[token.index]
			continue
		}
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		value, ok := object[token.key]
		if !ok {
			return nil, false
		}
		current = value
	}
	return current, true
}
