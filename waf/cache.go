package waf

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// maxCacheBytes bounds the decoded last-known-good bundle. | maxCacheBytes 限制解码后的
// last-known-good 规则包大小。
const maxCacheBytes = 64 << 20

// cacheEnvelope is the single-file last-known-good format. Writing one file and renaming it
// atomically means a crash can never pair new metadata with old rules. | cacheEnvelope 是单文件
// last-known-good 格式。写入一个文件并原子重命名，意味着崩溃绝不会把新元数据与旧规则配对。
type cacheEnvelope struct {
	Version string `json:"version"`
	Digest  string `json:"digest"`
	Format  string `json:"format"`
	Data    string `json:"data"`
	ModTime int64  `json:"mod_time"`
}

// writeLastKnownGood persists a bundle as one atomically replaced file. | writeLastKnownGood 把
// 规则包持久化为一个原子替换的文件。
func writeLastKnownGood(name string, bundle *Bundle) error {
	if name == "" || bundle == nil || len(bundle.Data) == 0 {
		return nil
	}
	if err := bundle.seal(); err != nil {
		return err
	}
	envelope := cacheEnvelope{
		Version: bundle.Version,
		Digest:  bundle.Digest,
		Format:  bundle.Format.String(),
		ModTime: bundle.ModTime.Unix(),
		Data:    base64.StdEncoding.EncodeToString(bundle.Data),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return errs.Wrap(err, ErrBuild)
	}
	if err := atomicWrite(name, encoded, 0o600); err != nil {
		return errs.Wrap(err, ErrBuild)
	}
	return nil
}

// readLastKnownGood loads and verifies a cached bundle. | readLastKnownGood 加载并校验缓存规则包。
func readLastKnownGood(name string) (*Bundle, error) {
	if name == "" {
		return nil, ErrInvalidBundle
	}
	info, err := os.Stat(name)
	if err != nil {
		return nil, errs.Wrap(err, ErrSource)
	}
	// Base64 expands data by four thirds; allow for the envelope overhead.
	// | Base64 将数据扩大四分之三；为信封开销留出余量。
	if info.Size() > int64(maxCacheBytes)*2 {
		return nil, errs.Detail(ErrInvalidBundle, "cached bundle too large | 缓存规则包过大")
	}
	encoded, err := os.ReadFile(name)
	if err != nil {
		return nil, errs.Wrap(err, ErrSource)
	}
	var envelope cacheEnvelope
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		return nil, errs.Wrap(err, ErrInvalidBundle)
	}
	data, err := base64.StdEncoding.DecodeString(envelope.Data)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidBundle)
	}
	if len(data) > maxCacheBytes {
		return nil, errs.Detail(ErrInvalidBundle, "cached bundle too large | 缓存规则包过大")
	}
	bundle := &Bundle{
		Version: envelope.Version,
		Format:  FormatSecLang,
		Data:    data,
		ModTime: time.Unix(envelope.ModTime, 0),
	}
	if strings.EqualFold(envelope.Format, "json") {
		bundle.Format = FormatJSON
	}
	if err := bundle.seal(); err != nil {
		return nil, err
	}
	if envelope.Digest != "" && !strings.EqualFold(envelope.Digest, bundle.Digest) {
		return nil, errs.Detail(ErrInvalidBundle, "cached bundle digest mismatch | 缓存规则包摘要不匹配")
	}
	return bundle, nil
}

// atomicWrite writes data to a temporary file and renames it over the destination. | atomicWrite
// 把数据写入临时文件并重命名覆盖目标。
func atomicWrite(name string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".waf-cache-*")
	if err != nil {
		return err
	}
	tempName := file.Name()
	cleanup := func() {
		_ = file.Close()
		_ = os.Remove(tempName)
	}
	if _, err := file.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := file.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := file.Chmod(mode); err != nil {
		cleanup()
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tempName)
		return err
	}
	if err := os.Rename(tempName, name); err != nil {
		_ = os.Remove(tempName)
		return err
	}
	return nil
}
