package challenge

import (
	"context"
	"strings"
	"testing"
)

func TestLocalizedPromptIgnoresKeyEcho(t *testing.T) {
	echo := func(key string, _ ...string) string { return key }
	req := GenerateRequest{Locale: "en", Translate: echo}
	prompt := localizedPrompt(req, "prompt.text", "hint.text", "Type the characters", "Case-insensitive")
	if prompt.Text != "Type the characters" || prompt.Hint != "Case-insensitive" {
		t.Fatalf("key echo leaked into prompt: %+v", prompt)
	}
}

func TestLocalizedPromptUsesTranslations(t *testing.T) {
	translate := func(key string, args ...string) string {
		switch key {
		case "prompt.click_text":
			if len(args) == 1 {
				return "Respectez l'ordre : " + args[0]
			}
			return "Respectez l'ordre"
		case "hint.click_text":
			return "Suivez l'ordre"
		default:
			return ""
		}
	}
	req := GenerateRequest{Locale: "fr", Translate: translate}
	prompt := localizedPrompt(req, "prompt.click_text", "hint.click_text", "Click in order", "Follow the order", "ABC")
	if prompt.Text != "Respectez l'ordre : ABC" || prompt.Hint != "Suivez l'ordre" {
		t.Fatalf("translations were not used: %+v", prompt)
	}
}

func TestIconLabelIgnoresKeyEcho(t *testing.T) {
	echo := func(key string, _ ...string) string { return key }
	spec := iconSpec{Name: "apple", ZH: "苹果", EN: "apple"}
	zh := iconLabel(GenerateRequest{Locale: "zh-CN", Translate: echo}, spec)
	if zh != "苹果" {
		t.Fatalf("zh icon label = %q", zh)
	}
	en := iconLabel(GenerateRequest{Locale: "en", Translate: echo}, spec)
	if en != "apple" {
		t.Fatalf("en icon label = %q", en)
	}
}

func TestSemanticPromptIgnoresCategoryKeyEcho(t *testing.T) {
	echo := func(key string, _ ...string) string { return key }
	provider := newSemanticProvider()
	generated, err := provider.Generate(context.Background(), GenerateRequest{
		Locale:    "en",
		Width:     320,
		Height:    200,
		Translate: echo,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(generated.Prompt.Text, "Select all ") || strings.Contains(generated.Prompt.Text, "category.") {
		t.Fatalf("category key leaked into prompt: %q", generated.Prompt.Text)
	}
}
