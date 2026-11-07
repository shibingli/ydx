package cn

import "testing"

func TestValidateBankCard(t *testing.T) {
	t.Parallel()
	valid := []string{
		"4111111111111111",
		"5500005555555559",
		"378282246310005",
		"6011111111111117",
		"4222222222222",
		"6200000000000005",
		"4111 1111 1111 1111",
		"4111-1111-1111-1111",
		"3782 822463 10005",
		"4111111111111111　",
	}
	for _, raw := range valid {
		if !ValidateBankCard(raw) {
			t.Fatalf("ValidateBankCard(%q) = false, want true", raw)
		}
	}
	invalid := []string{
		"",
		"41111111111",
		"41111111111111111111",
		"4111111111111112",
		"123456789012",
		"411111111111111a",
		"4111.1111.1111.1111",
	}
	for _, raw := range invalid {
		if ValidateBankCard(raw) {
			t.Fatalf("ValidateBankCard(%q) = true, want false", raw)
		}
	}
}

func TestMaskBankCard(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"4111111111111111", "4111********1111"},
		{"4111 1111 1111 1111", "4111********1111"},
		{"6222021234567890123", "6222***********0123"},
		{"123456", "**3456"},
		{"1234", "****"},
		{"123", "***"},
		{"", ""},
		{"4111-abcd", "4*******d"},
	}
	for _, tc := range cases {
		if got := MaskBankCard(tc.in); got != tc.want {
			t.Fatalf("MaskBankCard(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
