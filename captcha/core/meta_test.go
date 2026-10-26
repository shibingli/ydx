package core

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCleanMetaCapsAtRuneBoundary(t *testing.T) {
	if got := CleanMeta("  hello\x00world  ", 64); got != "helloworld" {
		t.Fatalf("control cleanup = %q", got)
	}
	value := strings.Repeat("验", 10)
	got := CleanMeta(value, 11)
	if len(got) > 11 || !utf8.ValidString(got) {
		t.Fatalf("truncated = %q (%d bytes)", got, len(got))
	}
}

func TestSanitizeMetaAndSignals(t *testing.T) {
	meta := SanitizeMeta(Meta{
		IP:        strings.Repeat("1", 100),
		UserAgent: strings.Repeat("u", 1000),
		Origin:    strings.Repeat("o", 1000),
		RequestID: strings.Repeat("r", 1000),
	})
	if len(meta.IP) != maxMetaIP || len(meta.UserAgent) != maxMetaUserAgent ||
		len(meta.Origin) != maxMetaOrigin || len(meta.RequestID) != maxMetaRequestID {
		t.Fatalf("meta lengths = %d %d %d %d", len(meta.IP), len(meta.UserAgent), len(meta.Origin), len(meta.RequestID))
	}
	languages := make([]string, 20)
	for i := range languages {
		languages[i] = strings.Repeat("x", 200)
	}
	signals := SanitizeSignals(Signals{UserAgent: strings.Repeat("u", 1000), Languages: languages})
	if len(signals.UserAgent) != maxMetaUserAgent || len(signals.Languages) != maxSignalList {
		t.Fatalf("signals = %d/%d", len(signals.UserAgent), len(signals.Languages))
	}
	for _, language := range signals.Languages {
		if len(language) > maxMetaLocale {
			t.Fatalf("language length = %d", len(language))
		}
	}
}
