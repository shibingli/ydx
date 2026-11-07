package cn

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeMobile(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"13800138000", "+8613800138000"},
		{"+8613800138000", "+8613800138000"},
		{"8613800138000", "+8613800138000"},
		{"008613800138000", "+8613800138000"},
		{"+86 138-0013-8000", "+8613800138000"},
		{"(+86) 138 0013 8000", "+8613800138000"},
		{" 13800138000 ", "+8613800138000"},
		{"　13800138000　", "+8613800138000"},
		{"138\t0013\r\n8000", "+8613800138000"},
	}
	for _, tc := range cases {
		got, err := NormalizeMobile(tc.in)
		if err != nil {
			t.Fatalf("NormalizeMobile(%q) returned error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("NormalizeMobile(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeMobileRejects(t *testing.T) {
	t.Parallel()
	cases := []string{
		"",
		"1380013800",
		"138001380000",
		"+861380013800",
		"+1 415 555 0100",
		"12800138000",
		"19412345678",
		"15412345678",
		"16012345678",
		"1380013800a",
		"+8613800138000+",
	}
	for _, raw := range cases {
		if _, err := NormalizeMobile(raw); err == nil {
			t.Fatalf("NormalizeMobile(%q) unexpectedly succeeded", raw)
		} else if !errors.Is(err, ErrInvalidMobile) {
			t.Fatalf("NormalizeMobile(%q) error = %v, want ErrInvalidMobile", raw, err)
		}
	}
}

func TestIsMainlandMobile(t *testing.T) {
	t.Parallel()
	valid := []string{
		"13000000000", "13100000000", "13200000000", "13300000000", "13400000000", "13500000000",
		"13600000000", "13700000000", "13800000000", "13900000000",
		"14000000000", "14100000000", "14200000000", "14300000000", "14400000000", "14500000000",
		"14600000000", "14700000000", "14800000000", "14900000000",
		"15000000000", "15300000000", "15500000000", "15900000000",
		"16200000000", "16500000000", "16600000000", "16700000000",
		"17000000000", "17100000000", "17200000000", "17300000000", "17400000000", "17500000000",
		"17600000000", "17700000000", "17800000000",
		"18000000000", "18500000000", "18900000000",
		"19000000000", "19100000000", "19200000000", "19300000000", "19500000000", "19600000000",
		"19700000000", "19800000000", "19900000000",
		"+86 138-0013-8000",
	}
	for _, raw := range valid {
		if !IsMainlandMobile(raw) {
			t.Fatalf("IsMainlandMobile(%q) = false, want true", raw)
		}
	}
	invalid := []string{
		"", "1380013800", "138001380000", "12800138000", "15400000000", "16000000000",
		"16100000000", "16300000000", "16400000000", "16800000000", "16900000000",
		"17900000000", "19400000000", "20000000000", "1380013800a",
	}
	for _, raw := range invalid {
		if IsMainlandMobile(raw) {
			t.Fatalf("IsMainlandMobile(%q) = true, want false", raw)
		}
	}
}

func TestCarrier(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"13800138000", CarrierChinaMobile},
		{"14700147000", CarrierChinaMobile},
		{"16500165000", CarrierChinaMobile},
		{"19500195000", CarrierChinaMobile},
		{"13000130000", CarrierChinaUnicom},
		{"16200162000", CarrierChinaUnicom},
		{"16700167000", CarrierChinaUnicom},
		{"19600196000", CarrierChinaUnicom},
		{"13300133000", CarrierChinaTelecom},
		{"17400174000", CarrierChinaTelecom},
		{"19900199000", CarrierChinaTelecom},
		{"19200192000", CarrierChinaBroadnet},
		{"17000170000", CarrierChinaTelecom},
		{"17040170400", CarrierChinaUnicom},
		{"17030170300", CarrierChinaMobile},
		{"19412345678", CarrierUnknown},
	}
	for _, tc := range cases {
		got, err := Carrier(tc.in)
		if err != nil {
			t.Fatalf("Carrier(%q) returned error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("Carrier(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if _, err := Carrier("12345"); !errors.Is(err, ErrInvalidMobile) {
		t.Fatalf("Carrier(\"12345\") error = %v, want ErrInvalidMobile", err)
	}
}

func TestMaskMobile(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"13800138000", "138****8000"},
		{"+86 138-0013-8000", "138****8000"},
		{"+8619912345678", "199****5678"},
		{"", ""},
		{"abc", "a*c"},
	}
	for _, tc := range cases {
		if got := MaskMobile(tc.in); got != tc.want {
			t.Fatalf("MaskMobile(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestMobileErrorsDoNotLeakNumber(t *testing.T) {
	t.Parallel()
	raw := "12345678901"
	_, err := NormalizeMobile(raw)
	if err == nil {
		t.Fatal("NormalizeMobile unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), raw) {
		t.Fatalf("error %q leaks the full mobile number", err)
	}
}
