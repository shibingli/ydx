package waf

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"hash/crc32"
	"strconv"
	"strings"
)

// transformFunc applies one SecLang transformation. | transformFunc 应用一个 SecLang 变换。
type transformFunc func(string) string

// transformEntry describes one registered transformation. | transformEntry 描述一个已注册变换。
type transformEntry struct {
	name string
	fn   transformFunc
}

// transforms lists every built-in transformation by its lowercase SecLang name. | transforms 按
// 小写 SecLang 名称列出全部内置变换。
var transforms = map[string]transformEntry{
	"none":               {"none", func(s string) string { return s }},
	"lowercase":          {"lowercase", strings.ToLower},
	"uppercase":          {"uppercase", strings.ToUpper},
	"trim":               {"trim", strings.TrimSpace},
	"trimleft":           {"trimLeft", func(s string) string { return strings.TrimLeft(s, " \t\r\n\v\f") }},
	"trimright":          {"trimRight", func(s string) string { return strings.TrimRight(s, " \t\r\n\v\f") }},
	"compresswhitespace": {"compressWhitespace", compressWhitespace},
	"removewhitespace":   {"removeWhitespace", removeWhitespace},
	"removenulls":        {"removeNulls", removeNulls},
	"replacenulls":       {"replaceNulls", replaceNulls},
	"removecomments":     {"removeComments", func(s string) string { return comments(s, "") }},
	"removecommentschar": {"removeCommentsChar", removeCommentsChar},
	"replacecomments":    {"replaceComments", func(s string) string { return comments(s, " ") }},
	"cmdline":            {"cmdLine", cmdLine},
	"length":             {"length", func(s string) string { return strconv.Itoa(len(s)) }},
	"md5":                {"md5", func(s string) string { return hashHex(md5.New(), s) }},
	"sha1":               {"sha1", func(s string) string { return hashHex(sha1.New(), s) }},
	"sha256":             {"sha256", func(s string) string { return hashHex(sha256.New(), s) }},
	"crc32":              {"crc32", func(s string) string { return strconv.FormatUint(uint64(crc32.ChecksumIEEE([]byte(s))), 10) }},
	"urldecode":          {"urlDecode", func(s string) string { return percentDecode(s, false) }},
	"urldecodeuni":       {"urlDecodeUni", func(s string) string { return percentDecode(s, true) }},
	"urlencode":          {"urlEncode", urlEncode},
	"base64decode":       {"base64Decode", base64Decode},
	"base64decodeext":    {"base64DecodeExt", base64DecodeExt},
	"base64encode":       {"base64Encode", base64Encode},
	"hexdecode":          {"hexDecode", hexDecode},
	"hexencode":          {"hexEncode", hexEncode},
	"htmlentitydecode":   {"htmlEntityDecode", htmlEntityDecode},
	"jsdecode":           {"jsDecode", jsDecode},
	"cssdecode":          {"cssDecode", cssDecode},
	"escapeseqdecode":    {"escapeSeqDecode", escapeSeqDecode},
	"utf8tounicode":      {"utf8toUnicode", utf8toUnicode},
	"normalizepath":      {"normalizePath", normalizePath},
	"normalizepathwin":   {"normalizePathWin", normalizePathWin},
	"sqlhexdecode":       {"sqlHexDecode", sqlHexDecode},
}

// lookupTransform resolves a transformation by name, case-insensitively. | lookupTransform 按名称
// 大小写不敏感地解析变换。
func lookupTransform(name string) (transformEntry, bool) {
	entry, ok := transforms[strings.ToLower(strings.TrimSpace(name))]
	return entry, ok
}

// applyTransforms applies every transformation in order. | applyTransforms 按顺序应用每个变换。
func applyTransforms(value string, chain []transformFunc) string {
	for _, fn := range chain {
		value = fn(value)
		if value == "" {
			return ""
		}
	}
	return value
}

// transformL1 caches the most recent transform result for one rule evaluation. Collections often
// repeat the same value across adjacent entries, and this small cache works during parallel rule
// evaluation where the shared transaction map is unavailable. | transformL1 缓存单条规则求值中最近的
// 变换结果。集合的相邻条目经常重复相同取值，且该小型缓存在并行规则求值、共享事务 map 不可用时仍可工作。
type transformL1 struct {
	input  string
	output string
	valid  bool
}

// transformCacheKey identifies one chain result within a transaction. | transformCacheKey 标识事务内
// 一个变换链的结果。
type transformCacheKey struct {
	chain uint32
	value string
}

// Transform cache bounds. Large bodies are not cached, and the entry count is capped so a hostile
// request cannot grow per-transaction memory without limit. | 变换缓存上限。大正文不缓存，条目数也有限，
// 避免恶意请求无限增长事务内存。
const (
	maxTransformCacheEntries = 1024
	maxTransformCacheValue   = 4096
)

// transformCacheWorthy reports whether a transformation is expensive enough, or a chain long
// enough, that caching beats a map lookup. | transformCacheWorthy 报告变换是否足够昂贵，或链是否
// 足够长，使缓存优于一次 map 查找。
func transformCacheWorthy(name string, chainLength int) bool {
	if chainLength >= 3 {
		return true
	}
	switch name {
	case "urlDecode", "urlDecodeUni", "htmlEntityDecode", "jsDecode", "cssDecode",
		"escapeSeqDecode", "base64Decode", "base64DecodeExt", "hexDecode", "sqlHexDecode",
		"normalizePath", "normalizePathWin", "removeComments", "replaceComments",
		"compressWhitespace", "removeWhitespace", "cmdLine", "utf8toUnicode",
		"md5", "sha1", "sha256", "urlEncode", "base64Encode", "hexEncode":
		return true
	default:
		return false
	}
}

// applyCachedTransforms applies a transform chain with a per-transaction result cache. The cache is
// disabled during parallel rule evaluation because workers share the transaction. | applyCachedTransforms
// 使用事务级结果缓存应用变换链。并行规则求值共享事务，因此该阶段禁用缓存。
func applyCachedTransforms(tx *transaction, value string, chain []transformFunc, chainID uint32, cacheable bool) string {
	if len(chain) == 0 {
		return value
	}
	if !cacheable || tx == nil || chainID == 0 || tx.parallelEval || len(value) > maxTransformCacheValue {
		return applyTransforms(value, chain)
	}
	cacheKey := transformCacheKey{chain: chainID, value: value}
	if tx.transformCache == nil {
		tx.transformCache = make(map[transformCacheKey]string, 16)
	} else if len(tx.transformCache) >= maxTransformCacheEntries {
		return applyTransforms(value, chain)
	}
	if cached, ok := tx.transformCache[cacheKey]; ok {
		return cached
	}
	transformed := applyTransforms(value, chain)
	tx.transformCache[cacheKey] = transformed
	return transformed
}

// hashHex renders a digest in lowercase hexadecimal. | hashHex 以小写十六进制渲染摘要。
func hashHex(h interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}, s string) string {
	_, _ = h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

// compressWhitespace collapses every whitespace run to one space. | compressWhitespace 把每个
// 空白运行折叠为一个空格。
func compressWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inSpace := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isSpaceByte(c) {
			if !inSpace {
				b.WriteByte(' ')
				inSpace = true
			}
			continue
		}
		inSpace = false
		b.WriteByte(c)
	}
	return b.String()
}

// removeWhitespace removes every whitespace byte. | removeWhitespace 删除所有空白字节。
func removeWhitespace(s string) string {
	if !strings.ContainsAny(s, " \t\r\n\v\f") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if !isSpaceByte(s[i]) {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// removeNulls removes NUL bytes. | removeNulls 删除 NUL 字节。
func removeNulls(s string) string {
	if !strings.ContainsRune(s, 0) {
		return s
	}
	return strings.ReplaceAll(s, "\x00", "")
}

// replaceNulls replaces NUL bytes with spaces. | replaceNulls 把 NUL 字节替换为空格。
func replaceNulls(s string) string {
	if !strings.ContainsRune(s, 0) {
		return s
	}
	return strings.ReplaceAll(s, "\x00", " ")
}

// removeCommentsChar removes comment delimiters without removing their contents. | removeCommentsChar
// 删除注释定界符但保留其内容。
func removeCommentsChar(s string) string {
	if !strings.Contains(s, "/*") && !strings.Contains(s, "<!--") {
		return s
	}
	replacer := strings.NewReplacer("<!--", "", "-->", "", "/*", "", "*/", "")
	return replacer.Replace(s)
}

// cmdLine normalizes a command line: lowercases, removes backslashes and collapses whitespace.
// | cmdLine 规范化命令行：转小写、去反斜杠并折叠空白。
func cmdLine(s string) string {
	s = strings.ReplaceAll(s, "\\", "")
	return compressWhitespace(strings.ToLower(s))
}

// comments removes or replaces C-style and HTML comments. | comments 删除或替换 C 风格与 HTML 注释。
func comments(s, replacement string) string {
	if !strings.Contains(s, "/*") && !strings.Contains(s, "<!--") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if i+1 < len(s) && s[i] == '/' && s[i+1] == '*' {
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				break
			}
			b.WriteString(replacement)
			i += 2 + end + 2
			continue
		}
		if i+3 < len(s) && s[i:i+4] == "<!--" {
			end := strings.Index(s[i+4:], "-->")
			if end < 0 {
				break
			}
			b.WriteString(replacement)
			i += 4 + end + 3
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// isSpaceByte reports whether c is ASCII whitespace. | isSpaceByte 报告 c 是否为 ASCII 空白。
func isSpaceByte(c byte) bool {
	switch c {
	case ' ', '\t', '\r', '\n', '\v', '\f':
		return true
	default:
		return false
	}
}
