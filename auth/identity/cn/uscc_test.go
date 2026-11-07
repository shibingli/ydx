package cn

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateUnifiedSocialCreditCode(t *testing.T) {
	t.Parallel()
	valid := []string{
		"91350100M000100Y43",
		"91110108551385082Q",
		"91440300708416088X",
		"91330100716105852F",
		"91310115076449132M",
		"91350100m000100y43",
		" 91350100M000100Y43 ",
	}
	for _, raw := range valid {
		if !ValidateUnifiedSocialCreditCode(raw) {
			t.Fatalf("ValidateUnifiedSocialCreditCode(%q) = false, want true", raw)
		}
	}
	invalid := []string{
		"",
		"91350100M000100Y4",
		"91350100M000100Y433",
		"91350100M000100Y44",
		"91350100M000100Y4I",
		"91350100M000100Y4O",
		"91350100M000100Y4S",
		"91350100M000100Y4V",
		"91350100M000100Y4Z",
		"91350100-000100Y43",
	}
	for _, raw := range invalid {
		if ValidateUnifiedSocialCreditCode(raw) {
			t.Fatalf("ValidateUnifiedSocialCreditCode(%q) = true, want false", raw)
		}
	}
}

func TestParseUnifiedSocialCreditCode(t *testing.T) {
	t.Parallel()
	code, err := ParseUnifiedSocialCreditCode("91350100M000100Y43")
	if err != nil {
		t.Fatalf("ParseUnifiedSocialCreditCode returned error: %v", err)
	}
	if code.Code != "91350100M000100Y43" {
		t.Fatalf("Code = %q", code.Code)
	}
	if code.RegistrationAuthority != "9" || code.RegistrationAuthorityName != "market_regulation" {
		t.Fatalf("authority = %q/%q", code.RegistrationAuthority, code.RegistrationAuthorityName)
	}
	if code.EntityType != "91" || code.EntityTypeName != "enterprise" {
		t.Fatalf("entity = %q/%q", code.EntityType, code.EntityTypeName)
	}
	if code.RegionCode != "350100" {
		t.Fatalf("RegionCode = %q, want 350100", code.RegionCode)
	}
	if code.OrganizationCode != "M000100Y4" {
		t.Fatalf("OrganizationCode = %q, want M000100Y4", code.OrganizationCode)
	}

	if _, err := ParseUnifiedSocialCreditCode("91350100M000100Y44"); !errors.Is(err, ErrInvalidUSCC) {
		t.Fatalf("parse invalid error = %v, want ErrInvalidUSCC", err)
	}
	if _, err := ParseUnifiedSocialCreditCode("bad"); !errors.Is(err, ErrInvalidUSCC) {
		t.Fatalf("parse short error = %v, want ErrInvalidUSCC", err)
	}
}

func TestParseUnifiedSocialCreditCodeUnknownNames(t *testing.T) {
	t.Parallel()
	// A checksum-valid code with authority "0" and category "00"; only the decode labels are unknown. | 校验码合法但部门为 "0"、类别为 "00" 的代码，仅解码标签未知。
	base := "00000000000000000"
	code := base + string(usccCheckDigit(base))
	parsed, err := ParseUnifiedSocialCreditCode(code)
	if err != nil {
		t.Fatalf("ParseUnifiedSocialCreditCode returned error: %v", err)
	}
	if parsed.RegistrationAuthorityName != nameUnknown || parsed.EntityTypeName != nameUnknown {
		t.Fatalf("unknown names = %q/%q", parsed.RegistrationAuthorityName, parsed.EntityTypeName)
	}
}

func TestUSCCErrorDoesNotLeakCode(t *testing.T) {
	t.Parallel()
	raw := "91350100M000100Y44"
	_, err := ParseUnifiedSocialCreditCode(raw)
	if err == nil {
		t.Fatal("ParseUnifiedSocialCreditCode unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), raw) {
		t.Fatalf("error %q leaks the full code", err)
	}
}
