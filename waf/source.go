package waf

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Format identifies the serialization of a rule bundle. | Format 标识规则包的序列化格式。
type Format uint8

// Supported bundle formats. | 支持的规则包格式。
const (
	// FormatSecLang is the ModSecurity/Coraza SecLang text format. | FormatSecLang 是
	// ModSecurity/Coraza SecLang 文本格式。
	FormatSecLang Format = iota
	// FormatJSON is the native JSON rule format. | FormatJSON 是原生 JSON 规则格式。
	FormatJSON
)

// String returns the format name used in headers and logs. | String 返回头部与日志中使用的格式名称。
func (f Format) String() string {
	if f == FormatJSON {
		return "json"
	}
	return "seclang"
}

// Bundle is one immutable rule bundle. | Bundle 是一个不可变规则包。
type Bundle struct {
	ModTime time.Time
	Version string
	Digest  string
	Data    []byte
	Format  Format
}

// seal computes the digest and fills a default version. | seal 计算摘要并填充默认版本。
func (b *Bundle) seal() error {
	if b == nil || len(b.Data) == 0 {
		return ErrInvalidBundle
	}
	sum := sha256.Sum256(b.Data)
	b.Digest = hex.EncodeToString(sum[:])
	if b.Version == "" {
		b.Version = b.Digest[:16]
	}
	return nil
}

// Source supplies rule bundles for startup, reload and multi-machine distribution.
// | Source 为启动、重载与多机分发提供规则包。
type Source interface {
	Load(ctx context.Context) (*Bundle, error)
}

// FileSource reads SecLang files from a filesystem and expands Includes. | FileSource 从文件系统
// 读取 SecLang 文件并展开 Include。
type FileSource struct {
	FS         fs.FS
	Paths      []string
	Directives []string
}

// Load builds a bundle from the configured files. | Load 从已配置文件构建规则包。
func (s FileSource) Load(_ context.Context) (*Bundle, error) {
	loader := &ruleLoader{fsys: s.FS, strict: true}
	source, err := loader.expandTopLevel(s.Paths, s.Directives)
	if err != nil {
		return nil, errs.Wrap(err, ErrSource)
	}
	bundle := &Bundle{Format: FormatSecLang, Data: []byte(source)}
	if err := bundle.seal(); err != nil {
		return nil, err
	}
	return bundle, nil
}

// HTTPSource pulls a bundle from a rule server. It sends If-None-Match and treats 304 as
// ErrNotModified, verifies an optional HMAC-SHA256 signature and never buffers more than
// MaxBytes. | HTTPSource 从规则服务器拉取规则包。它发送 If-None-Match 并把 304 视为
// ErrNotModified，校验可选的 HMAC-SHA256 签名，且不会缓冲超过 MaxBytes 的内容。
type HTTPSource struct {
	lastMod      time.Time
	Client       *http.Client
	Headers      map[string]string
	URL          string
	etag         string
	SignatureKey []byte
	lastBody     []byte
	MaxBytes     int64

	mu sync.Mutex
}

// defaultSourceMaxBytes bounds an HTTP bundle read. | defaultSourceMaxBytes 限制 HTTP 规则包读取。
const defaultSourceMaxBytes = 16 << 20

// Load fetches the bundle once. | Load 拉取一次规则包。
func (s *HTTPSource) Load(ctx context.Context) (*Bundle, error) {
	if strings.TrimSpace(s.URL) == "" {
		return nil, errs.Detail(ErrSource, "empty source URL | 空的来源 URL")
	}
	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return nil, errs.Wrap(err, ErrSource)
	}
	for name, value := range s.Headers {
		request.Header.Set(name, value)
	}
	s.mu.Lock()
	etag := s.etag
	s.mu.Unlock()
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, errs.Wrap(err, ErrSource)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusNotModified {
		return nil, ErrNotModified
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, errs.Detail(ErrSource, "source returned status %d | 来源返回状态 %d", response.StatusCode, response.StatusCode)
	}
	limit := s.MaxBytes
	if limit <= 0 {
		limit = defaultSourceMaxBytes
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, errs.Wrap(err, ErrSource)
	}
	if int64(len(data)) > limit {
		return nil, errs.Detail(ErrSource, "bundle exceeds %d bytes | 规则包超过 %d 字节", limit, limit)
	}
	if len(s.SignatureKey) > 0 {
		signature := response.Header.Get("X-YDX-WAF-Signature")
		if !verifySignature(s.SignatureKey, data, signature) {
			return nil, ErrSignature
		}
	}
	if expected := response.Header.Get("X-YDX-WAF-Digest"); expected != "" {
		sum := sha256.Sum256(data)
		if !strings.EqualFold(expected, hex.EncodeToString(sum[:])) {
			return nil, errs.Detail(ErrSignature, "bundle digest mismatch | 规则包摘要不匹配")
		}
	}
	format := FormatSecLang
	if strings.EqualFold(response.Header.Get("X-YDX-WAF-Format"), "json") ||
		strings.HasSuffix(strings.ToLower(strings.Split(s.URL, "?")[0]), ".json") {
		format = FormatJSON
	}
	bundle := &Bundle{
		Version: response.Header.Get("X-YDX-WAF-Version"),
		Format:  format,
		Data:    data,
		ModTime: parseHTTPTime(response.Header.Get("Last-Modified")),
	}
	if err := bundle.seal(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.etag = response.Header.Get("ETag")
	s.lastMod = bundle.ModTime
	s.lastBody = append(s.lastBody[:0], data...)
	s.mu.Unlock()
	return bundle, nil
}

// MultiSource tries its sources in order. ErrNotModified is returned immediately.
// | MultiSource 按顺序尝试来源；ErrNotModified 会立即返回。
type MultiSource []Source

// Load tries each source until one succeeds. | Load 依次尝试来源直到成功。
func (m MultiSource) Load(ctx context.Context) (*Bundle, error) {
	var collected []error
	for _, source := range m {
		if source == nil {
			continue
		}
		bundle, err := source.Load(ctx)
		if err == nil {
			return bundle, nil
		}
		if errors.Is(err, ErrNotModified) {
			return nil, err
		}
		collected = append(collected, err)
	}
	if len(collected) == 0 {
		return nil, errs.Detail(ErrSource, "no source configured | 未配置来源")
	}
	return nil, errors.Join(collected...)
}

// FuncSource adapts a function to Source. | FuncSource 把函数适配为 Source。
type FuncSource func(context.Context) (*Bundle, error)

// Load calls the function. | Load 调用函数。
func (f FuncSource) Load(ctx context.Context) (*Bundle, error) {
	if f == nil {
		return nil, errs.Detail(ErrSource, "nil source function | 空的来源函数")
	}
	return f(ctx)
}

// verifySignature verifies a hexadecimal HMAC-SHA256 signature. | verifySignature 校验十六进制
// HMAC-SHA256 签名。
func verifySignature(key, data []byte, signature string) bool {
	signature = strings.TrimSpace(signature)
	if signature == "" {
		return false
	}
	decoded, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return hmac.Equal(decoded, mac.Sum(nil))
}

// parseHTTPTime parses an HTTP date, returning the zero time on failure. | parseHTTPTime 解析 HTTP
// 日期，失败时返回零值时间。
func parseHTTPTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	parsed, err := http.ParseTime(value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

// bundleVersion renders a bundle version for logs. | bundleVersion 为日志渲染规则包版本。
func bundleVersion(bundle *Bundle) string {
	if bundle == nil {
		return ""
	}
	if bundle.Version != "" {
		return bundle.Version
	}
	if len(bundle.Digest) >= 12 {
		return bundle.Digest[:12]
	}
	return strconv.Itoa(len(bundle.Data))
}
