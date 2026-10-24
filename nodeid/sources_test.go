package nodeid

import "testing"

// TestValidMachineID pins the systemd machine-id shape. | TestValidMachineID 固定 systemd
// machine-id 形态。
func TestValidMachineID(t *testing.T) {
	cases := map[string]bool{
		"0123456789abcdef0123456789abcdef": true,
		"0123456789ABCDEF0123456789ABCDEF": true,
		"short":                            false,
		"zzzz456789abcdef0123456789abcdef": false,
		"0123456789abcdef0123456789abcde":  false,
	}
	for value, want := range cases {
		if got := validMachineID(value); got != want {
			t.Fatalf("validMachineID(%q) = %v, want %v", value, got, want)
		}
	}
}

// TestValidUUIDRejectsPlaceholders pins the SMBIOS UUID check. | TestValidUUIDRejectsPlaceholders
// 固定 SMBIOS UUID 检查。
func TestValidUUIDRejectsPlaceholders(t *testing.T) {
	cases := map[string]bool{
		"4c4c4544-0044-3510-8051-b4c04f4a4d32": true,
		"00000000-0000-0000-0000-000000000000": false,
		"03000200-0400-0500-0006-000700080009": false,
		"ffffffff-ffff-ffff-ffff-ffffffffffff": false,
		"not-a-uuid":                           false,
		"4c4c4544-0044-3510-8051-b4c04f4a4d3":  false,
	}
	for value, want := range cases {
		if got := validUUID(value); got != want {
			t.Fatalf("validUUID(%q) = %v, want %v", value, got, want)
		}
	}
}

// TestCleanSerial pins firmware placeholder rejection. | TestCleanSerial 固定固件占位值拒绝。
func TestCleanSerial(t *testing.T) {
	empty := []string{"", "None", "To be filled by O.E.M.", "Default string", "0000-0000", " - . "}
	for _, value := range empty {
		if got := cleanSerial(value); got != "" {
			t.Fatalf("cleanSerial(%q) = %q, want empty", value, got)
		}
	}
	if got := cleanSerial("  SN-12345  "); got != "SN-12345" {
		t.Fatalf("cleanSerial = %q", got)
	}
}
