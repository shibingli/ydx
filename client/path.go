package client

import (
	"net/url"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// matchPath returns the decoded, unambiguous path used for rule matching. RawPath must describe
// the same segment structure as Path; encoded separators, dot segments, backslashes and duplicate
// slashes are rejected so one URL cannot have two interpretations. | matchPath 返回用于规则匹配的
// 解码且无歧义路径。RawPath 必须与 Path 的段结构一致；编码分隔符、点段、反斜杠与重复斜杠均被
// 拒绝，避免同一 URL 存在两种解释。
func matchPath(u *url.URL) (string, error) {
	if u == nil {
		return "", errs.Detail(ErrAmbiguousPath, "nil URL | URL 为 nil")
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	if path[0] != '/' {
		path = "/" + path
	}
	if err := validateDecodedPath(path); err != nil {
		return "", err
	}
	if u.RawPath != "" {
		if err := validateRawPath(u.RawPath, path); err != nil {
			return "", err
		}
	}
	return path, nil
}

// validateDecodedPath rejects dot segments, duplicate slashes and backslashes in a decoded path. |
// validateDecodedPath 拒绝解码路径中的点段、重复斜杠与反斜杠。
func validateDecodedPath(path string) error {
	if strings.ContainsRune(path, '\\') {
		return errs.Detail(ErrAmbiguousPath, "backslash in path %q | 路径 %q 含反斜杠", path, path)
	}
	segments := strings.Split(path, "/")
	for i := 1; i < len(segments); i++ {
		segment := segments[i]
		if segment == "" {
			if i == len(segments)-1 {
				continue
			}
			return errs.Detail(ErrAmbiguousPath, "duplicate slash in path %q | 路径 %q 含重复斜杠", path, path)
		}
		if segment == "." || segment == ".." {
			return errs.Detail(ErrAmbiguousPath, "dot segment in path %q | 路径 %q 含点段", path, path)
		}
	}
	return nil
}

// validateRawPath checks that RawPath unescapes segment by segment to the equivalent Path
// segments and that no encoded separator hides inside one segment. | validateRawPath 校验 RawPath
// 逐段解码后与对应 Path 段一致，且段内不隐藏编码分隔符。
func validateRawPath(raw, decoded string) error {
	rawSegments := strings.Split(raw, "/")
	decodedSegments := strings.Split(decoded, "/")
	if len(rawSegments) != len(decodedSegments) {
		return errs.Detail(ErrAmbiguousPath, "RawPath %q and Path %q disagree on segments | RawPath %q 与 Path %q 的段结构不一致", raw, decoded, raw, decoded)
	}
	for i := range rawSegments {
		segment, err := url.PathUnescape(rawSegments[i])
		if err != nil {
			return errs.Detail(ErrAmbiguousPath, "RawPath %q has an invalid escape | RawPath %q 含非法转义", raw, raw)
		}
		if segment != decodedSegments[i] {
			return errs.Detail(ErrAmbiguousPath, "RawPath %q and Path %q disagree on segments | RawPath %q 与 Path %q 的段结构不一致", raw, decoded, raw, decoded)
		}
		if strings.ContainsAny(segment, "/\\") {
			return errs.Detail(ErrAmbiguousPath, "encoded separator inside path segment %q | 路径段 %q 内含编码分隔符", segment, segment)
		}
	}
	return nil
}

// joinBasePath joins a base path with a request path after segment-wise cleaning. Dot segments
// that would pop a base segment are rejected with ErrAmbiguousPath. When escaped is true the
// inputs are percent-encoded and segments are unescaped only for classification; the output keeps
// its original segment spelling. | joinBasePath 按段清理后拼接 base path 与请求路径。会弹出 base 段
// 的点段以 ErrAmbiguousPath 拒绝。escaped 为 true 时输入为百分号编码，段仅用于分类时解码，输出
// 保留原始段写法。
func joinBasePath(base, path string, escaped bool) (string, error) {
	baseSegments, err := cleanPathSegments(base, escaped, true)
	if err != nil {
		return "", err
	}
	pathSegments, err := cleanPathSegments(path, escaped, false)
	if err != nil {
		return "", err
	}
	segments := make([]string, 0, len(baseSegments)+len(pathSegments))
	segments = append(segments, baseSegments...)
	segments = append(segments, pathSegments...)
	joined := "/" + strings.Join(segments, "/")
	if len(segments) > 0 && (path == "" || strings.HasSuffix(path, "/")) {
		joined += "/"
	}
	return joined, nil
}

// cleanPathSegments splits one path form and applies segment-wise cleaning. An empty segment
// (duplicate or trailing slash) is dropped; "." is skipped; ".." pops the previous segment. When
// clampRoot is false, a ".." that would pop the last retained segment is rejected because it
// would escape the base path. | cleanPathSegments 切分一种路径形式并按段清理。空段（重复或末尾斜杠）
// 被丢弃；"." 跳过；".." 弹出上一段。clampRoot 为 false 时，会弹出最后一个保留段的 ".." 因为
// 越出 base path 而被拒绝。
func cleanPathSegments(path string, escaped, clampRoot bool) ([]string, error) {
	if path == "" || path == "/" {
		return nil, nil
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	segments := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		decoded := part
		if escaped {
			value, err := url.PathUnescape(part)
			if err != nil {
				return nil, errs.Detail(ErrAmbiguousPath, "invalid path escape %q | 非法路径转义 %q", part, part)
			}
			if strings.ContainsAny(value, "/\\") {
				return nil, errs.Detail(ErrAmbiguousPath, "encoded path separator in %q | %q 中存在编码路径分隔符", part, part)
			}
			decoded = value
		} else if strings.ContainsRune(part, '\\') {
			return nil, errs.Detail(ErrAmbiguousPath, "backslash in path segment %q | 路径段 %q 含反斜杠", part, part)
		}
		switch decoded {
		case ".":
			continue
		case "..":
			if len(segments) == 0 {
				if clampRoot {
					continue
				}
				return nil, errs.Detail(ErrAmbiguousPath, "dot-dot escapes the base path | 点段越出了 base path")
			}
			segments = segments[:len(segments)-1]
			continue
		}
		segments = append(segments, part)
	}
	return segments, nil
}

// resolveTargetPaths cleans an escaped request path and returns matching RawPath and Path forms.
// A rewrite that yields an unparsable or structurally inconsistent path is rejected. |
// resolveTargetPaths 清理转义请求路径并返回相互匹配的 RawPath 与 Path 形式。重写产生无法解析或
// 结构不一致的路径时拒绝。
func resolveTargetPaths(escaped string) (string, string, error) {
	if escaped == "" {
		escaped = "/"
	}
	decoded, err := url.PathUnescape(escaped)
	if err != nil {
		return "", "", errs.Detail(ErrAmbiguousPath, "invalid escaped path %q | 非法转义路径 %q", escaped, escaped)
	}
	rawPath, err := joinBasePath("", escaped, true)
	if err != nil {
		return "", "", err
	}
	path, err := joinBasePath("", decoded, false)
	if err != nil {
		return "", "", err
	}
	check, err := url.PathUnescape(rawPath)
	if err != nil || check != path {
		return "", "", errs.Detail(ErrAmbiguousPath, "escaped path %q has two interpretations | 转义路径 %q 存在两种解释", escaped, escaped)
	}
	return rawPath, path, nil
}

// targetPathForms joins a host base path with an escaped request path and returns consistent
// RawPath and Path forms. | targetPathForms 拼接 Host base path 与转义请求路径，并返回相互匹配的
// RawPath 与 Path 形式。
func targetPathForms(basePath, baseEscaped, escaped string) (string, string, error) {
	if escaped == "" {
		escaped = "/"
	}
	decoded, err := url.PathUnescape(escaped)
	if err != nil {
		return "", "", errs.Detail(ErrAmbiguousPath, "invalid escaped path %q | 非法转义路径 %q", escaped, escaped)
	}
	rawPath, err := joinBasePath(baseEscaped, escaped, true)
	if err != nil {
		return "", "", err
	}
	path, err := joinBasePath(basePath, decoded, false)
	if err != nil {
		return "", "", err
	}
	check, err := url.PathUnescape(rawPath)
	if err != nil || check != path {
		return "", "", errs.Detail(ErrAmbiguousPath, "escaped path %q has two interpretations | 转义路径 %q 存在两种解释", escaped, escaped)
	}
	return rawPath, path, nil
}
