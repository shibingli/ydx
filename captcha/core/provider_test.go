package core

import "testing"

func TestLocalizedPromptIgnoresKeyEcho(t *testing.T) {
	echo := func(key string, _ ...string) string { return key }
	req := GenerateRequest{Translate: echo}
	prompt := localizedPrompt(req, "prompt.text", "hint.text", "Type the characters", "Case-insensitive")
	if prompt.Text != "Type the characters" || prompt.Hint != "Case-insensitive" {
		t.Fatalf("key echo leaked into prompt: %+v", prompt)
	}
}
