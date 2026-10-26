package core

import (
	"strings"
	"testing"
)

func TestBuiltinCatalogsCoverEnglishKeys(t *testing.T) {
	catalogs, err := builtinCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	base := catalogs["en"]
	if len(base) == 0 {
		t.Fatal("missing English catalog")
	}
	for locale, catalog := range catalogs {
		for key := range base {
			if _, ok := catalog[key]; !ok {
				t.Fatalf("locale %s is missing %s", locale, key)
			}
		}
	}
	for _, key := range []string{"prompt.text", "prompt.sms", "icon.apple", "category.fruit", "error.invalid_answer", "sdk.submit", "sdk.fallbackSMS", "notice.fallback_sms"} {
		if _, ok := base[key]; !ok {
			t.Fatalf("English catalog is missing %s", key)
		}
	}
}

func TestMatchLocaleNegotiation(t *testing.T) {
	locales := []string{"de", "en", "es", "fr", "ja", "ko", "zh-CN", "zh-TW"}
	cases := map[string]string{
		"ja-JP":                "ja",
		"zh-HK":                "zh-TW",
		"zh-Hant":              "zh-TW",
		"zh-Hans-CN":           "zh-CN",
		"en-US":                "en",
		"fr-CA":                "fr",
		"fr;q=0.4, ja;q=0.9":   "ja",
		"de-DE,en;q=0.8":       "de",
		"unknown":              "en",
		"":                     "en",
		"*":                    "en",
		"ko-KR,zh-TW;q=0.2":    "ko",
		"es-419, en-US;q=0.7":  "es",
		"zh-TW;q=0.1,en;q=0.9": "en",
		"de;q=0, fr;q=0.5":     "fr",
		"ja-JP, en-US;q=0.9":   "ja",
		"ZH_tw":                "zh-TW",
	}
	for input, want := range cases {
		if got := matchLocale(input, locales, "en"); got != want {
			t.Fatalf("matchLocale(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestMessageOverridesAndHostTranslator(t *testing.T) {
	localizer, err := NewLocalizer(Options{
		DefaultLocale: "zh-CN",
		Messages:      map[string]map[string]string{"xx": {"prompt.text": "Custom text"}},
		Translate: func(locale, key string, _ ...string) string {
			if locale == "xx" && key == "hint.text" {
				return "Custom hint"
			}
			return ""
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := localizer.Message("xx", "prompt.text"); got != "Custom text" {
		t.Fatalf("override = %q", got)
	}
	if got := localizer.Message("xx", "hint.text"); got != "Custom hint" {
		t.Fatalf("translator = %q", got)
	}
	if got := localizer.Message("xx", "missing.key"); got != "" {
		t.Fatalf("missing message = %q", got)
	}
}

func TestUnsupportedDefaultLocaleRejected(t *testing.T) {
	if _, err := NewLocalizer(Options{DefaultLocale: "xx-YY"}); err == nil {
		t.Fatal("expected unsupported locale rejection")
	}
}

func TestPromptPlaceholdersAreFilled(t *testing.T) {
	localizer, err := NewLocalizer(Options{
		Messages: map[string]map[string]string{"en": {"prompt.click_text": "Pick {0} now"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := localizer.Message("en", "prompt.click_text", "a, b, c"); got != "Pick a, b, c now" {
		t.Fatalf("formatted = %q", got)
	}
	if strings.Contains(localizer.Message("en", "prompt.click_text", "a, b, c"), "{0}") {
		t.Fatal("placeholder was not replaced")
	}
}
