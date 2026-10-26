package core

import "strings"

// Header and hint length caps keep untrusted transport data out of records and audit output. | 头与提示长度上限防止不可信传输数据进入记录与审计。
const (
	maxMetaIP        = 64
	maxMetaUserAgent = 512
	maxMetaOrigin    = 512
	maxMetaRequestID = 128
	maxMetaLocale    = 64
	maxSignalString  = 512
	maxSignalShort   = 128
	maxSignalList    = 8
)

// SanitizeMeta trims and caps transport fields supplied by a request or a direct caller. | sanitizeMeta 清理并限制请求或直接调用方提供的传输字段。
func SanitizeMeta(meta Meta) Meta {
	meta.IP = CleanMeta(meta.IP, maxMetaIP)
	meta.UserAgent = CleanMeta(meta.UserAgent, maxMetaUserAgent)
	meta.Origin = CleanMeta(meta.Origin, maxMetaOrigin)
	meta.RequestID = CleanMeta(meta.RequestID, maxMetaRequestID)
	return meta
}

// SanitizeSignals treats every signal as untrusted and caps stored strings. | sanitizeSignals 把所有信号视为不可信并限制存储字符串。
func SanitizeSignals(signals Signals) Signals {
	signals.UserAgent = CleanMeta(signals.UserAgent, maxMetaUserAgent)
	signals.Platform = CleanMeta(signals.Platform, maxSignalShort)
	signals.Language = CleanMeta(signals.Language, maxMetaLocale)
	signals.Timezone = CleanMeta(signals.Timezone, maxSignalShort)
	signals.CanvasHash = CleanMeta(signals.CanvasHash, maxSignalShort)
	signals.WebGLHash = CleanMeta(signals.WebGLHash, maxSignalShort)
	signals.AudioHash = CleanMeta(signals.AudioHash, maxSignalShort)
	signals.DoNotTrack = CleanMeta(signals.DoNotTrack, 32)
	signals.Visibility = CleanMeta(signals.Visibility, 32)
	if len(signals.Languages) > maxSignalList {
		signals.Languages = signals.Languages[:maxSignalList]
	}
	if len(signals.Languages) > 0 {
		languages := make([]string, 0, len(signals.Languages))
		for _, language := range signals.Languages {
			languages = append(languages, CleanMeta(language, maxMetaLocale))
		}
		signals.Languages = languages
	}
	return signals
}

// CleanMeta drops control characters, trims spaces and caps bytes at a rune boundary. | cleanMeta 去除控制字符、裁剪空白并在字符边界截断字节。
func CleanMeta(value string, limit int) string {
	value = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value))
	if limit <= 0 || len(value) <= limit {
		return value
	}
	cut := 0
	for index := range value {
		if index > limit {
			break
		}
		cut = index
	}
	if cut == 0 {
		return ""
	}
	return value[:cut]
}
