package challenge

import (
	"strings"
	"time"

	"github.com/shibingli/ydx/captcha/risk"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// localizedPrompt builds a prompt from Translate with English fallbacks. | localizedPrompt 用 Translate 和英文回退构建提示。
func localizedPrompt(req GenerateRequest, textKey, hintKey, fallbackText, fallbackHint string, args ...string) Prompt {
	text := fallbackText
	hint := fallbackHint
	if req.Translate != nil {
		if translated := req.Translate(textKey, args...); translated != "" {
			text = translated
		}
		if translated := req.Translate(hintKey); translated != "" {
			hint = translated
		}
	}
	return Prompt{Text: text, Hint: hint}
}

// encodeAnswer serializes opaque provider state. | encodeAnswer 序列化不透明的生成器状态。
func encodeAnswer(value any) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, errs.Wrap(err, ErrProvider)
	}
	return payload, nil
}

// decodeAnswer deserializes opaque provider state. | decodeAnswer 反序列化不透明的生成器状态。
func decodeAnswer(payload []byte, value any) error {
	if err := json.Unmarshal(payload, value); err != nil {
		return errs.Wrap(err, ErrProvider)
	}
	return nil
}

// isHanLocale reports whether a locale uses Han script. | isHanLocale 报告语言是否使用汉字。
func isHanLocale(locale string) bool { return strings.HasPrefix(strings.ToLower(locale), "zh") }

// iconLabel returns the localized name of one icon. | iconLabel 返回一个图标的本地化名称。
func iconLabel(req GenerateRequest, spec iconSpec) string {
	fallback := spec.EN
	if isHanLocale(req.Locale) {
		fallback = spec.ZH
	}
	if req.Translate != nil {
		if translated := req.Translate("icon." + spec.Name); translated != "" {
			return translated
		}
	}
	return fallback
}

// scoreTrack forwards trajectory scoring to the risk package. | scoreTrack 把轨迹评分转发给 risk 包。
func scoreTrack(track Track, expectedPoints int) (int, []string) {
	return risk.ScoreTrack(track, expectedPoints)
}

// trackDuration forwards duration parsing to the risk package. | trackDuration 把时长解析转发给 risk 包。
func trackDuration(track Track) time.Duration {
	return risk.TrackDuration(track)
}

// pickRunes samples n distinct runes from pool. | pickRunes 从 pool 中无放回抽取 n 个字符。
func pickRunes(r *rng, pool []rune, n int) []rune {
	if n > len(pool) {
		n = len(pool)
	}
	perm := r.src.Perm(len(pool))
	out := make([]rune, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, pool[perm[i]])
	}
	return out
}
