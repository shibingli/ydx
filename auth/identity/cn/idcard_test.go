package cn

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// idCardTestNow is the deterministic clock for age assertions: 2026-11-07 12:00 China Standard Time. | idCardTestNow 是年龄断言的确定性时钟：2026-11-07 12:00 中国标准时间。
var idCardTestNow = time.Date(2026, time.November, 7, 12, 0, 0, 0, idCardLocation)

func TestParseIDCardKnownVectors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw        string
		number     string
		region     string
		birthdate  string
		gender     string
		ageAtFixed int
	}{
		{"11010519491231002X", "11010519491231002X", "110105", "1949-12-31", "female", 76},
		{"11010519491231002x", "11010519491231002X", "110105", "1949-12-31", "female", 76},
		{"110105194912310038", "110105194912310038", "110105", "1949-12-31", "male", 76},
		{"110105491231002", "11010519491231002X", "110105", "1949-12-31", "female", 76},
		{"110105190001010028", "110105190001010028", "110105", "1900-01-01", "female", 126},
	}
	for _, tc := range cases {
		card, err := parseIDCardAt(tc.raw, idCardTestNow)
		if err != nil {
			t.Fatalf("parseIDCardAt(%q) returned error: %v", tc.raw, err)
		}
		if card.Number != tc.number {
			t.Fatalf("Number = %q, want %q", card.Number, tc.number)
		}
		if card.RegionCode != tc.region {
			t.Fatalf("RegionCode = %q, want %q", card.RegionCode, tc.region)
		}
		if card.Birthdate != tc.birthdate {
			t.Fatalf("Birthdate = %q, want %q", card.Birthdate, tc.birthdate)
		}
		if card.Gender != tc.gender {
			t.Fatalf("Gender = %q, want %q", card.Gender, tc.gender)
		}
		if card.Age != tc.ageAtFixed {
			t.Fatalf("Age = %d, want %d", card.Age, tc.ageAtFixed)
		}
		if !card.Valid {
			t.Fatal("Valid = false, want true")
		}
	}
}

func TestParseIDCardErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw  string
		want error
	}{
		{"", ErrInvalidIDCard},
		{"11010519491231002", ErrInvalidIDCard},
		{"1101051949123100211", ErrInvalidIDCard},
		{"11010519491231002A", ErrInvalidIDCard},
		{"11010549123100X", ErrInvalidIDCard},
		{"110105194912310021", ErrIDCardChecksum},
		{"110105194902310026", ErrIDCardBirthdate},
		{"110105209912310029", ErrIDCardBirthdate},
		{"110105189912310023", ErrIDCardBirthdate},
		{"990105194912310023", ErrIDCardRegion},
		{"110105490231002", ErrIDCardBirthdate},
		{"990105491231002", ErrIDCardRegion},
	}
	for _, tc := range cases {
		card, err := ParseIDCard(tc.raw)
		if err == nil {
			t.Fatalf("ParseIDCard(%q) unexpectedly succeeded: %+v", tc.raw, card)
		}
		if card != nil {
			t.Fatalf("ParseIDCard(%q) returned a non-nil card on error", tc.raw)
		}
		if !errors.Is(err, tc.want) {
			t.Fatalf("ParseIDCard(%q) error = %v, want %v", tc.raw, err, tc.want)
		}
	}
}

func TestIDCardHelpers(t *testing.T) {
	t.Parallel()
	const valid = "11010519491231002X"
	if !ValidateIDCard(valid) {
		t.Fatal("ValidateIDCard(valid) = false")
	}
	if ValidateIDCard("110105194912310021") {
		t.Fatal("ValidateIDCard(invalid) = true")
	}
	if got := IDCardBirthdate(valid); got != "1949-12-31" {
		t.Fatalf("IDCardBirthdate = %q, want 1949-12-31", got)
	}
	if got := IDCardBirthdate("bad"); got != "" {
		t.Fatalf("IDCardBirthdate(invalid) = %q, want empty", got)
	}
	if got := IDCardGender(valid); got != "female" {
		t.Fatalf("IDCardGender = %q, want female", got)
	}
	if got := IDCardGender("110105194912310038"); got != "male" {
		t.Fatalf("IDCardGender(male) = %q, want male", got)
	}
	if got := IDCardGender("bad"); got != "unknown" {
		t.Fatalf("IDCardGender(invalid) = %q, want unknown", got)
	}
}

func TestMaskIDCard(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"11010519491231002X", "110105********002X"},
		{"11010519491231002x", "110105********002X"},
		{"110105491231002", "110105******002"},
		{" 11010519491231002X ", "110105********002X"},
		{"abc", "A*C"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := MaskIDCard(tc.in); got != tc.want {
			t.Fatalf("MaskIDCard(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIDCardErrorsDoNotLeakNumber(t *testing.T) {
	t.Parallel()
	raw := "110105194912310021"
	_, err := ParseIDCard(raw)
	if err == nil {
		t.Fatal("ParseIDCard unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), raw) {
		t.Fatalf("error %q leaks the full identity card number", err)
	}
}

func TestFullYearsBetween(t *testing.T) {
	t.Parallel()
	birth := time.Date(2000, time.February, 29, 0, 0, 0, 0, idCardLocation)
	cases := []struct {
		now  time.Time
		want int
	}{
		{time.Date(2026, time.February, 28, 0, 0, 0, 0, idCardLocation), 25},
		{time.Date(2026, time.March, 1, 0, 0, 0, 0, idCardLocation), 26},
		{time.Date(1999, time.March, 1, 0, 0, 0, 0, idCardLocation), 0},
	}
	for _, tc := range cases {
		if got := fullYearsBetween(birth, tc.now); got != tc.want {
			t.Fatalf("fullYearsBetween(%v) = %d, want %d", tc.now, got, tc.want)
		}
	}
}
