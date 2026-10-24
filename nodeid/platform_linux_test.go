//go:build linux

package nodeid

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLinuxPlatformSeed pins machine-id, SMBIOS and container policy. | TestLinuxPlatformSeed
// 固定 machine-id、SMBIOS 与容器策略。
func TestLinuxPlatformSeed(t *testing.T) {
	dir := t.TempDir()
	machineID := filepath.Join(dir, "machine-id")
	if err := os.WriteFile(machineID, []byte("0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatalf("write machine-id: %v", err)
	}
	uuid := filepath.Join(dir, "product_uuid")
	if err := os.WriteFile(uuid, []byte("4c4c4544-0044-3510-8051-b4c04f4a4d32\n"), 0o600); err != nil {
		t.Fatalf("write uuid: %v", err)
	}
	serial := filepath.Join(dir, "product_serial")
	if err := os.WriteFile(serial, []byte("SN-12345\n"), 0o600); err != nil {
		t.Fatalf("write serial: %v", err)
	}

	oldMachine, oldUUID, oldSerials := machineIDPaths, dmiUUIDPath, dmiSerialPaths
	t.Cleanup(func() {
		machineIDPaths, dmiUUIDPath, dmiSerialPaths = oldMachine, oldUUID, oldSerials
	})

	machineIDPaths = []string{machineID}
	dmiUUIDPath = uuid
	dmiSerialPaths = []string{serial}

	source, seed, ok := platformSeed(EnvironmentPhysical, false)
	if !ok || source != SourceMachineID || seed != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("physical seed = (%q, %q, %v)", source, seed, ok)
	}
	if _, _, ok := platformSeed(EnvironmentContainer, false); ok {
		t.Fatal("container used a host seed without allowShared | 容器在未开启 allowShared 时使用了宿主种子")
	}
	if source, _, ok := platformSeed(EnvironmentContainer, true); !ok || source != SourceMachineID {
		t.Fatalf("container allowShared seed = (%q, %v)", source, ok)
	}

	machineIDPaths = nil
	if source, seed, ok := platformSeed(EnvironmentPhysical, false); !ok || source != SourceSMBIOS || seed != "4c4c4544-0044-3510-8051-b4c04f4a4d32" {
		t.Fatalf("SMBIOS seed = (%q, %q, %v)", source, seed, ok)
	}

	if err := os.WriteFile(uuid, []byte("03000200-0400-0500-0006-000700080009\n"), 0o600); err != nil {
		t.Fatalf("write placeholder uuid: %v", err)
	}
	if source, seed, ok := platformSeed(EnvironmentPhysical, false); !ok || source != SourceSMBIOS || seed != "SN-12345" {
		t.Fatalf("serial fallback = (%q, %q, %v)", source, seed, ok)
	}
}

// TestLinuxIsDurableRejectsTemporaryFiles proves the temp path is never
// reported as durable. | TestLinuxIsDurableRejectsTemporaryFiles 证明临时路径绝不会被报告
// 为持久。
func TestLinuxIsDurableRejectsTemporaryFiles(t *testing.T) {
	if IsDurable(filepath.Join(t.TempDir(), "node-id")) {
		t.Fatal("temporary path reported as durable | 临时路径被报告为持久")
	}
}

// TestExistingPathWalksUp proves a missing leaf resolves to an existing
// ancestor. | TestExistingPathWalksUp 证明缺失的叶子路径会解析到存在的祖先。
func TestExistingPathWalksUp(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "a", "b", "node-id")
	if got := existingPath(missing); got != dir {
		t.Fatalf("existingPath = %q, want %q", got, dir)
	}
}
