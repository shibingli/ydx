package core

import (
	"embed"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// messageFS embeds the built-in captcha catalogs. | messageFS 嵌入内置验证码语言目录。
//
//go:embed langs/*.json
var messageFS embed.FS

// defaultMessageLocale is the fallback language when none is configured. | defaultMessageLocale 是未配置时的回退语言。
const defaultMessageLocale = "zh-CN"

// fallbackMessageLocale is the secondary fallback for partial catalogs. | fallbackMessageLocale 是部分目录缺失时的第二回退语言。
const fallbackMessageLocale = "en"

var (
	builtinOnce    sync.Once
	builtinCache   map[string]map[string]string
	builtinLoadErr error
)

// builtinCatalogs loads the embedded message catalogs once. | builtinCatalogs 只加载一次嵌入消息目录。
func builtinCatalogs() (map[string]map[string]string, error) {
	builtinOnce.Do(func() {
		builtinCache, builtinLoadErr = loadBuiltinCatalogs()
	})
	return builtinCache, builtinLoadErr
}

// loadBuiltinCatalogs parses every embedded locale file. | loadBuiltinCatalogs 解析全部内嵌语言文件。
func loadBuiltinCatalogs() (map[string]map[string]string, error) {
	entries, err := messageFS.ReadDir("langs")
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidOptions)
	}
	out := make(map[string]map[string]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		locale := strings.TrimSuffix(entry.Name(), ".json")
		if !validLocaleTag(locale) {
			return nil, errs.Detail(ErrInvalidOptions, "invalid embedded locale %q | 非法内置语言 %q", locale, locale)
		}
		data, readErr := messageFS.ReadFile("langs/" + entry.Name())
		if readErr != nil {
			return nil, errs.Wrap(readErr, ErrInvalidOptions)
		}
		var catalog map[string]string
		if unmarshalErr := json.Unmarshal(data, &catalog); unmarshalErr != nil {
			return nil, errs.Wrap(unmarshalErr, ErrInvalidOptions)
		}
		if len(catalog) == 0 {
			return nil, errs.Detail(ErrInvalidOptions, "empty locale catalog %q | 空语言目录 %q", locale, locale)
		}
		for key, value := range catalog {
			if !validMessageKey(key) || strings.ContainsAny(value, "\r\n") {
				return nil, errs.Detail(ErrInvalidOptions, "invalid catalog entry %q in %q | 语言目录 %q 中的条目 %q 非法", key, locale, locale, key)
			}
		}
		out[locale] = catalog
	}
	if len(out) == 0 {
		return nil, errs.Detail(ErrInvalidOptions, "no embedded captcha catalogs | 没有内置验证码语言目录")
	}
	return out, nil
}

// buildMessages merges built-in and host catalogs and returns sorted locales. | buildMessages 合并内置与宿主目录并返回排序后的语言列表。
func buildMessages(overrides map[string]map[string]string) (map[string]map[string]string, []string, error) {
	builtin, err := builtinCatalogs()
	if err != nil {
		return nil, nil, err
	}
	messages := make(map[string]map[string]string, len(builtin)+len(overrides))
	for locale, catalog := range builtin {
		copied := make(map[string]string, len(catalog))
		for key, value := range catalog {
			copied[key] = value
		}
		messages[locale] = copied
	}
	for locale, catalog := range overrides {
		locale = canonicalLocaleTag(locale)
		if !validLocaleTag(locale) {
			return nil, nil, errs.Detail(ErrInvalidOptions, "invalid locale %q | 非法语言 %q", locale, locale)
		}
		if len(catalog) == 0 {
			return nil, nil, errs.Detail(ErrInvalidOptions, "empty locale catalog %q | 空语言目录 %q", locale, locale)
		}
		target := messages[locale]
		if target == nil {
			target = make(map[string]string, len(catalog))
			messages[locale] = target
		}
		for key, value := range catalog {
			if !validMessageKey(key) || strings.ContainsAny(value, "\r\n") {
				return nil, nil, errs.Detail(ErrInvalidOptions, "invalid message %q for locale %q | 语言 %q 的消息 %q 非法", key, locale, locale, key)
			}
			target[key] = value
		}
	}
	locales := make([]string, 0, len(messages))
	for locale := range messages {
		locales = append(locales, locale)
	}
	sort.Strings(locales)
	return messages, locales, nil
}

// validLocaleTag reports whether a tag is a safe locale identifier. | validLocaleTag 报告标签是否为安全的语言标识。
func validLocaleTag(tag string) bool {
	if tag == "" || len(tag) > 35 {
		return false
	}
	for i := 0; i < len(tag); i++ {
		c := tag[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return false
	}
	return true
}

// validMessageKey reports whether a catalog key is safe and namespaced. | validMessageKey 报告目录键是否安全且带命名空间。
func validMessageKey(key string) bool {
	if key == "" || len(key) > 128 || !strings.Contains(key, ".") {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}

// canonicalLocaleTag normalizes separators and common Chinese aliases. | canonicalLocaleTag 归一化分隔符与常见中文别名。
func canonicalLocaleTag(tag string) string {
	tag = strings.TrimSpace(strings.ReplaceAll(tag, "_", "-"))
	lower := strings.ToLower(tag)
	switch lower {
	case "zh", "zh-hans", "zh-sg", "zh-cn":
		return "zh-CN"
	case "zh-hant", "zh-hk", "zh-mo", "zh-tw":
		return "zh-TW"
	case "en":
		return "en"
	}
	if strings.HasPrefix(lower, "en-") {
		return "en"
	}
	return lower
}

// matchLocale picks the best supported tag for a plain tag or Accept-Language value. | matchLocale 为普通标签或 Accept-Language 取值挑选最佳支持语言。
func matchLocale(value string, locales []string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	if !strings.ContainsAny(value, ",;*") {
		if matched := matchLocaleTag(value, locales); matched != "" {
			return matched
		}
		return fallback
	}
	for _, pref := range parseLocalePreferences(value) {
		if pref.tag == "*" {
			return fallback
		}
		if matched := matchLocaleTag(pref.tag, locales); matched != "" {
			return matched
		}
	}
	return fallback
}

// matchLocaleTag matches one tag exactly, then by prefix, then by primary subtag. | matchLocaleTag 依次按精确、前缀与主语言子标签匹配。
func matchLocaleTag(tag string, locales []string) string {
	tag = canonicalLocaleTag(tag)
	if tag == "" {
		return ""
	}
	for _, locale := range locales {
		if strings.EqualFold(locale, tag) {
			return locale
		}
	}
	candidate := strings.ToLower(tag)
	for {
		index := strings.LastIndexByte(candidate, '-')
		if index <= 0 {
			break
		}
		candidate = candidate[:index]
		for _, locale := range locales {
			if strings.EqualFold(locale, candidate) {
				return locale
			}
		}
	}
	primary := strings.ToLower(tag)
	if index := strings.IndexByte(primary, '-'); index > 0 {
		primary = primary[:index]
	}
	for _, locale := range locales {
		localePrimary := strings.ToLower(locale)
		if index := strings.IndexByte(localePrimary, '-'); index > 0 {
			localePrimary = localePrimary[:index]
		}
		if localePrimary == primary {
			return locale
		}
	}
	return ""
}

// localePreference is one parsed Accept-Language entry. | localePreference 是一条解析后的 Accept-Language 条目。
type localePreference struct {
	tag   string
	q     float64
	order int
}

// parseLocalePreferences parses and sorts Accept-Language preferences by q value. | parseLocalePreferences 按 q 值解析并排序 Accept-Language。
func parseLocalePreferences(value string) []localePreference {
	parts := strings.Split(value, ",")
	prefs := make([]localePreference, 0, len(parts))
	for index, part := range parts {
		fields := strings.Split(part, ";")
		tag := strings.TrimSpace(fields[0])
		if tag == "" {
			continue
		}
		q := 1.0
		for _, field := range fields[1:] {
			field = strings.TrimSpace(field)
			if !strings.HasPrefix(strings.ToLower(field), "q=") {
				continue
			}
			if parsed, err := strconv.ParseFloat(strings.TrimSpace(field[2:]), 64); err == nil {
				q = parsed
			}
		}
		if q <= 0 {
			continue
		}
		prefs = append(prefs, localePreference{tag: tag, q: q, order: index})
	}
	sort.SliceStable(prefs, func(i, j int) bool {
		if prefs[i].q == prefs[j].q {
			return prefs[i].order < prefs[j].order
		}
		return prefs[i].q > prefs[j].q
	})
	return prefs
}

// Localizer resolves and formats captcha message catalogs. | Localizer 解析并格式化验证码消息目录。
type Localizer struct {
	messages      map[string]map[string]string
	locales       []string
	defaultLocale string
	translate     func(locale, key string, args ...string) string
}

// NewLocalizer builds an immutable localizer from options. | NewLocalizer 从选项构建不可变本地化器。
func NewLocalizer(o Options) (*Localizer, error) {
	messages, locales, err := buildMessages(o.Messages)
	if err != nil {
		return nil, err
	}
	defaultLocale := o.DefaultLocale
	if defaultLocale == "" {
		defaultLocale = defaultMessageLocale
	}
	defaultLocale = matchLocaleTag(defaultLocale, locales)
	if defaultLocale == "" {
		return nil, errs.Detail(ErrInvalidOptions, "unsupported default locale %q | 不支持的默认语言 %q", o.DefaultLocale, o.DefaultLocale)
	}
	return &Localizer{
		messages:      messages,
		locales:       locales,
		defaultLocale: defaultLocale,
		translate:     o.Translate,
	}, nil
}

// Normalize resolves an arbitrary locale to a catalog tag. | Normalize 把任意语言解析为目录标签。
func (l *Localizer) Normalize(locale string) string {
	if l == nil {
		return canonicalLocaleTag(locale)
	}
	return matchLocale(locale, l.locales, l.defaultLocale)
}

// Message looks up and formats one localized message. | Message 查找并格式化一条本地化消息。
func (l *Localizer) Message(locale, key string, args ...string) string {
	if l == nil {
		return ""
	}
	locale = l.Normalize(locale)
	if l.translate != nil {
		if translated := l.translate(locale, key, args...); translated != "" && translated != key {
			return translated
		}
	}
	if catalog := l.messages[locale]; catalog != nil {
		if value, ok := catalog[key]; ok {
			return formatMessage(value, args)
		}
	}
	if locale != l.defaultLocale {
		if catalog := l.messages[l.defaultLocale]; catalog != nil {
			if value, ok := catalog[key]; ok {
				return formatMessage(value, args)
			}
		}
	}
	if catalog := l.messages[fallbackMessageLocale]; catalog != nil {
		if value, ok := catalog[key]; ok {
			return formatMessage(value, args)
		}
	}
	return ""
}

// formatMessage fills positional {0}, {1} placeholders in one pass. | formatMessage 一次填充位置占位符 {0}、{1}。
func formatMessage(raw string, args []string) string {
	if len(args) == 0 || !strings.Contains(raw, "{") {
		return raw
	}
	for index, arg := range args {
		raw = strings.ReplaceAll(raw, "{"+strconv.Itoa(index)+"}", arg)
	}
	return raw
}

// Localized returns a translated message or the supplied fallback. | Localized 返回译文或给定回退文案。
func (l *Localizer) Localized(locale, key, fallback string, args ...string) string {
	if message := l.Message(locale, key, args...); message != "" {
		return message
	}
	return fallback
}

// Prompt builds a localized prompt pair with English fallbacks. | Prompt 构建带英文回退的本地化提示对。
func (l *Localizer) Prompt(locale, textKey, hintKey, fallbackText, fallbackHint string, args ...string) Prompt {
	return Prompt{
		Text: l.Localized(locale, textKey, fallbackText, args...),
		Hint: l.Localized(locale, hintKey, fallbackHint),
	}
}

// ErrorMessageKey maps a public error code to a catalog key. | ErrorMessageKey 把公开错误码映射到目录键。
func ErrorMessageKey(code string) string {
	switch code {
	case "invalid_type", "unsupported_channel", "unsupported_media_type", "request_too_large",
		"pow_required", "pow_invalid", "invalid_options", "method_not_allowed":
		return "error.invalid_request"
	case "origin_not_allowed":
		return "error.forbidden"
	case "provider", "store", "closed":
		return "error.unavailable"
	case "token_invalid", "token_expired":
		return "error.unauthorized"
	}
	return "error." + code
}

// Locales returns the supported locale tags. | Locales 返回支持的语言标签。
func (l *Localizer) Locales() []string {
	if l == nil {
		return nil
	}
	return append([]string(nil), l.locales...)
}

// DefaultLocale returns the fallback locale tag. | DefaultLocale 返回回退语言标签。
func (l *Localizer) DefaultLocale() string {
	if l == nil {
		return ""
	}
	return l.defaultLocale
}
