package rdma

import (
	"bytes"
	"errors"
	"testing"
)

func TestRingConfigValidation(t *testing.T) {
	if _, err := normalizeRingConfig(RingConfig{}); err == nil {
		t.Fatal("empty config accepted")
	}
	if _, err := normalizeRingConfig(RingConfig{Addr: "127.0.0.1:1", Secret: []byte("short")}); err == nil {
		t.Fatal("short secret accepted")
	}
	cfg, err := normalizeRingConfig(RingConfig{Addr: "127.0.0.1:1", Secret: []byte("0123456789abcdef")})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SlotSize != 64<<10 || cfg.Slots != 64 {
		t.Fatalf("defaults = %+v", cfg)
	}
}

func TestRingFrameRoundTripAndTamper(t *testing.T) {
	secret := []byte("0123456789abcdef")
	var buf bytes.Buffer
	want := ringHandshake{Info: RingInfo{QPN: 7, PSN: 9, MTU: 1024, Addr: 0x1000, RKey: 0x42, SlotSize: 4096, Slots: 8}}
	if err := writeRingFrame(&buf, secret, want); err != nil {
		t.Fatal(err)
	}
	raw := append([]byte(nil), buf.Bytes()...)
	var got ringHandshake
	if err := readRingFrame(&buf, secret, &got); err != nil {
		t.Fatal(err)
	}
	if got.Info.QPN != 7 || got.Info.RKey != 0x42 {
		t.Fatalf("decoded = %+v", got)
	}
	raw[9] ^= 0xff
	if err := readRingFrame(bytes.NewReader(raw), secret, &got); !errors.Is(err, ErrRingProtocol) {
		t.Fatalf("tamper err = %v", err)
	}
}
