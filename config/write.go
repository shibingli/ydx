package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/afero"

	"github.com/shibingli/ydx/errs"
)

// WriteConfig writes the current configuration back to the file it was loaded from. |
// WriteConfig 把当前配置写回加载时的文件。
//
// The write is atomic: the encoded document goes to a temporary file in the same
// directory and is renamed over the target, which is created with mode 0600. The
// target is the base config file; a lone config.local file is used when no base
// file was loaded. | 写入是原子的：编码结果先写到同目录的临时文件，再改名覆盖目标；
// 目标以 0600 权限创建。目标是基础配置文件；未加载基础文件时使用单独的
// config.local 文件。
func (c *Config) WriteConfig() error {
	return c.writeLoadedConfig(true)
}

// SafeWriteConfig writes the current configuration to the loaded config file only
// when that file does not already exist. | SafeWriteConfig 仅在加载时的配置文件尚不
// 存在时才写入。
//
// A missing target file reports ErrWriteConfig; an existing one reports
// ErrConfigExists. | 目标文件缺失返回 ErrWriteConfig；目标已存在返回 ErrConfigExists。
func (c *Config) SafeWriteConfig() error {
	return c.writeLoadedConfig(false)
}

// WriteConfigAs writes the current configuration to filename. | WriteConfigAs 把当前配置写入 filename。
//
// The format is inferred from the file extension, falling back to the format of
// the loaded config. The write uses a same-directory temporary file and an atomic
// rename, and the resulting file has mode 0600. | 格式由文件扩展名推断，无法推断时使用
// 已加载配置的格式。写入使用同目录临时文件与原子改名，最终文件权限为 0600。
func (c *Config) WriteConfigAs(filename string) error {
	return c.writeConfigFile(filename, "", true)
}

// SafeWriteConfigAs writes the current configuration to filename only when it
// does not already exist. | SafeWriteConfigAs 仅在 filename 不存在时才写入当前配置。
//
// An existing target reports ErrConfigExists. | 目标已存在返回 ErrConfigExists。
func (c *Config) SafeWriteConfigAs(filename string) error {
	return c.writeConfigFile(filename, "", false)
}

// writeLoadedConfig resolves the file loaded by Load and rewrites it. | writeLoadedConfig
// 解析 Load 加载的文件并重写它。
func (c *Config) writeLoadedConfig(force bool) error {
	if c == nil {
		return errs.Detail(ErrWriteConfig, "nil config | 配置为 nil")
	}
	c.mu.RLock()
	filename := c.configFile
	if filename == "" {
		filename = c.configLocal
	}
	format := c.configType
	c.mu.RUnlock()
	if filename == "" {
		return errs.Detail(ErrWriteConfig, "no config file was loaded | 没有已加载的配置文件")
	}
	return c.writeConfigFile(filename, format, force)
}

// writeConfigFile encodes the current configuration into a same-directory
// temporary file and renames it over filename. | writeConfigFile 把当前配置编码到
// 同目录临时文件，再改名覆盖 filename。
func (c *Config) writeConfigFile(filename, fallbackFormat string, force bool) error {
	filename = strings.TrimSpace(filename)
	if filename == "" {
		return errs.Detail(ErrWriteConfig, "empty config file name | 配置文件名为空")
	}
	format := configWriteFormat(filename, fallbackFormat)
	if format == "" {
		return errs.Detail(ErrWriteConfig, "cannot determine config type for %q | 无法确定 %q 的配置类型", filename, filename)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Reserve the target atomically for the Safe* variants so two writers cannot
	// both pass an existence check. | Safe* 变体原子预留目标，避免两个写入者同时通过存在性检查。
	reserved := false
	if !force {
		f, err := c.fs.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				return errs.Detail(ErrConfigExists, "%s", filename)
			}
			return errs.WrapDetail(err, ErrWriteConfig, "reserve %s | 预留 %s 失败", filename, filename)
		}
		if err := f.Close(); err != nil {
			_ = c.fs.Remove(filename)
			return errs.WrapDetail(err, ErrWriteConfig, "reserve %s | 预留 %s 失败", filename, filename)
		}
		reserved = true
	}

	tmp, err := afero.TempFile(c.fs, filepath.Dir(filename), "."+filepath.Base(filename)+".tmp-*")
	if err != nil {
		if reserved {
			_ = c.fs.Remove(filename)
		}
		return errs.WrapDetail(err, ErrWriteConfig, "create temporary file for %s | 为 %s 创建临时文件失败", filename, filename)
	}
	tmpName := tmp.Name()
	fail := func(err error) error {
		_ = tmp.Close()
		_ = c.fs.Remove(tmpName)
		if reserved {
			_ = c.fs.Remove(filename)
		}
		return err
	}

	c.Viper.SetConfigType(format)
	if err := c.Viper.WriteConfigTo(tmp); err != nil {
		return fail(errs.WrapDetail(err, ErrWriteConfig, "encode %s | 编码 %s 失败", filename, filename))
	}
	if err := tmp.Sync(); err != nil {
		return fail(errs.WrapDetail(err, ErrWriteConfig, "sync %s | 同步 %s 失败", filename, filename))
	}
	if err := tmp.Close(); err != nil {
		return fail(errs.WrapDetail(err, ErrWriteConfig, "close %s | 关闭 %s 失败", filename, filename))
	}
	if err := c.fs.Rename(tmpName, filename); err != nil {
		_ = c.fs.Remove(tmpName)
		if reserved {
			_ = c.fs.Remove(filename)
		}
		return errs.WrapDetail(err, ErrWriteConfig, "replace %s | 替换 %s 失败", filename, filename)
	}
	return nil
}

// configWriteFormat picks the writer format from the target extension and falls
// back to the loaded config format. | configWriteFormat 从目标扩展名选择写入格式，
// 无法确定时回退到已加载配置的格式。
func configWriteFormat(filename, fallback string) string {
	ext := strings.TrimPrefix(filepath.Ext(filename), ".")
	if ext != "" && ext != filepath.Base(filename) {
		return strings.ToLower(ext)
	}
	return strings.ToLower(strings.TrimSpace(fallback))
}
