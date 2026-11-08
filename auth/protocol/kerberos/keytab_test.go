package kerberos

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testKeyTabEntry describes a keytab entry used to build synthetic images. |
// testKeyTabEntry 描述用于构建合成镜像的 keytab 条目。
type testKeyTabEntry struct {
	components []string
	realm      string
	nameType   int32
	timestamp  uint32
	kvno8      uint8
	etype      int32
	key        []byte
	kvno32     *uint32
}

// appendTestUint16 appends a big-endian uint16. | appendTestUint16 追加一个大端 uint16。
func appendTestUint16(buffer []byte, value uint16) []byte {
	return append(buffer, byte(value>>8), byte(value))
}

// appendTestUint32 appends a big-endian uint32. | appendTestUint32 追加一个大端 uint32。
func appendTestUint32(buffer []byte, value uint32) []byte {
	return append(buffer, byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
}

// appendTestString appends a uint16-length-prefixed octet string. | appendTestString
// 追加一个带 uint16 长度前缀的八位组字符串。
func appendTestString(buffer []byte, value []byte) []byte {
	buffer = appendTestUint16(buffer, uint16(len(value)))
	return append(buffer, value...)
}

// buildTestKeyTabEntry encodes one keytab record body. The MIT layout puts the
// realm before the principal components. | buildTestKeyTabEntry 编码一条 keytab
// 记录主体。MIT 布局把 realm 放在主体组成部分之前。
func buildTestKeyTabEntry(entry testKeyTabEntry) []byte {
	var body []byte
	body = appendTestUint16(body, uint16(len(entry.components)))
	body = appendTestString(body, []byte(entry.realm))
	for _, component := range entry.components {
		body = appendTestString(body, []byte(component))
	}
	body = appendTestUint32(body, uint32(entry.nameType))
	body = appendTestUint32(body, entry.timestamp)
	body = append(body, entry.kvno8)
	body = appendTestUint16(body, uint16(entry.etype))
	body = appendTestString(body, entry.key)
	if entry.kvno32 != nil {
		body = appendTestUint32(body, *entry.kvno32)
	}
	var out []byte
	out = appendTestUint32(out, uint32(len(body)))
	return append(out, body...)
}

// buildTestKeyTab encodes a complete MIT keytab image. | buildTestKeyTab 编码完整的 MIT
// keytab 镜像。
func buildTestKeyTab(entries ...testKeyTabEntry) []byte {
	out := appendTestUint16(nil, keyTabVersion)
	for _, entry := range entries {
		out = append(out, buildTestKeyTabEntry(entry)...)
	}
	return out
}

// TestParseKeyTab verifies MIT keytab parsing including duplicates and both key
// version encodings. | TestParseKeyTab 校验 MIT keytab 解析，包括重复项与两种密钥版本
// 编码。
func TestParseKeyTab(t *testing.T) {
	aes128 := bytes.Repeat([]byte{0x11}, 16)
	aes256 := bytes.Repeat([]byte{0x22}, 32)
	rc4 := bytes.Repeat([]byte{0x33}, 16)
	kvno32 := uint32(7)
	image := buildTestKeyTab(
		testKeyTabEntry{components: []string{"user"}, realm: "EXAMPLE.COM", nameType: NameTypePrincipal, timestamp: 1700000000, kvno8: 1, etype: ETypeAES128CTS, key: aes128},
		testKeyTabEntry{components: []string{"user"}, realm: "EXAMPLE.COM", nameType: NameTypePrincipal, timestamp: 1700000100, kvno8: 2, etype: ETypeAES256CTS, key: aes256},
		testKeyTabEntry{components: []string{"user"}, realm: "EXAMPLE.COM", nameType: NameTypePrincipal, timestamp: 1700000100, kvno8: 2, etype: ETypeAES256CTS, key: aes256},
		testKeyTabEntry{components: []string{"user"}, realm: "EXAMPLE.COM", nameType: NameTypePrincipal, timestamp: 1700000200, kvno8: 0, etype: ETypeRC4HMAC, key: rc4, kvno32: &kvno32},
		testKeyTabEntry{components: []string{"ldap", "dc1.example.com"}, realm: "EXAMPLE.COM", nameType: NameTypeSRVInst, timestamp: 1700000300, kvno8: 5, etype: ETypeAES256CTS, key: aes256},
	)
	tab, err := ParseKeyTab(image)
	if err != nil {
		t.Fatalf("ParseKeyTab: %v", err)
	}
	entries := tab.Entries()
	if len(entries) != 5 {
		t.Fatalf("entries = %d, want 5", len(entries))
	}
	if entries[0].Principal.String() != "user" || entries[0].Realm != "EXAMPLE.COM" {
		t.Errorf("first principal = %s@%s", entries[0].Principal.String(), entries[0].Realm)
	}
	if entries[0].KVNO != 1 || entries[0].Key.KeyType != ETypeAES128CTS || !bytes.Equal(entries[0].Key.KeyValue, aes128) {
		t.Errorf("first entry = %+v", entries[0])
	}
	if !entries[0].Timestamp.Equal(entries[1].Timestamp.Add(-100 * time.Second)) {
		t.Errorf("timestamps not preserved: %v and %v", entries[0].Timestamp, entries[1].Timestamp)
	}
	if entries[3].KVNO != 7 {
		t.Errorf("32-bit kvno = %d, want 7", entries[3].KVNO)
	}
	if entries[4].Principal.NameType != NameTypeSRVInst {
		t.Errorf("service name type = %d, want %d", entries[4].Principal.NameType, NameTypeSRVInst)
	}
	user := PrincipalName{NameType: NameTypePrincipal, NameString: []string{"user"}}
	entry, err := tab.Lookup(user, "EXAMPLE.COM", 0, 0)
	if err != nil {
		t.Fatalf("Lookup wildcard: %v", err)
	}
	if entry.KVNO != 7 || entry.Key.KeyType != ETypeRC4HMAC {
		t.Errorf("wildcard lookup = %+v, want kvno 7 rc4", entry)
	}
	entry, err = tab.Lookup(user, "EXAMPLE.COM", ETypeAES256CTS, 0)
	if err != nil {
		t.Fatalf("Lookup etype: %v", err)
	}
	if entry.KVNO != 2 || !bytes.Equal(entry.Key.KeyValue, aes256) {
		t.Errorf("etype lookup = %+v", entry)
	}
	if _, err := tab.Lookup(user, "OTHER.COM", 0, 0); !errors.Is(err, ErrNoKey) {
		t.Fatalf("Lookup wrong realm error = %v, want ErrNoKey", err)
	}
	if _, err := tab.Lookup(user, "", ETypeAES128CTS, 2); !errors.Is(err, ErrNoKey) {
		t.Fatalf("Lookup wrong kvno error = %v, want ErrNoKey", err)
	}
	if _, err := tab.Lookup(PrincipalName{NameString: []string{"absent"}}, "", 0, 0); !errors.Is(err, ErrNoKey) {
		t.Fatalf("Lookup missing principal error = %v, want ErrNoKey", err)
	}
	var nilTab *KeyTab
	if nilTab.Entries() != nil {
		t.Error("nil KeyTab returned entries")
	}
	if _, err := nilTab.Lookup(user, "", 0, 0); !errors.Is(err, ErrNoKey) {
		t.Fatalf("nil Lookup error = %v, want ErrNoKey", err)
	}
}

// TestParseKeyTabErrors covers malformed keytab images. | TestParseKeyTabErrors 覆盖
// 畸形 keytab 镜像。
func TestParseKeyTabErrors(t *testing.T) {
	valid := buildTestKeyTab(testKeyTabEntry{components: []string{"user"}, realm: "EXAMPLE.COM", kvno8: 1, etype: ETypeAES256CTS, key: bytes.Repeat([]byte{0x22}, 32)})
	zeroComponents := buildTestKeyTab(testKeyTabEntry{realm: "EXAMPLE.COM", kvno8: 1, etype: ETypeAES256CTS, key: bytes.Repeat([]byte{0x22}, 32)})
	trailing := buildTestKeyTab(testKeyTabEntry{components: []string{"user"}, realm: "EXAMPLE.COM", kvno8: 1, etype: ETypeAES256CTS, key: bytes.Repeat([]byte{0x22}, 32)})
	trailing = append(trailing, 0, 0, 0, 0, 9)
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"one byte", []byte{0x05}},
		{"wrong version", []byte{0x05, 0x01}},
		{"only header", []byte{0x05, 0x02}},
		{"truncated size", append([]byte{0x05, 0x02}, 0, 0, 0)},
		{"negative size", []byte{0x05, 0x02, 0xff, 0xff, 0xff, 0xff}},
		{"oversized", []byte{0x05, 0x02, 0, 0, 0, 99}},
		{"zero components", zeroComponents},
		{"trailing bytes", trailing},
		{"truncated body", valid[:len(valid)-4]},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseKeyTab(test.data); !errors.Is(err, ErrKeytab) {
				t.Fatalf("ParseKeyTab error = %v, want ErrKeytab", err)
			}
		})
	}
}

// TestReadKeyTabFile verifies file-based keytab loading. | TestReadKeyTabFile 校验基于文件
// 的 keytab 加载。
func TestReadKeyTabFile(t *testing.T) {
	image := buildTestKeyTab(testKeyTabEntry{components: []string{"user"}, realm: "EXAMPLE.COM", kvno8: 3, etype: ETypeAES256CTS, key: bytes.Repeat([]byte{0x44}, 32)})
	path := filepath.Join(t.TempDir(), "test.keytab")
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	tab, err := ReadKeyTabFile(path)
	if err != nil {
		t.Fatalf("ReadKeyTabFile: %v", err)
	}
	entry, err := tab.Lookup(PrincipalName{NameString: []string{"user"}}, "EXAMPLE.COM", 0, 0)
	if err != nil || entry.KVNO != 3 {
		t.Fatalf("Lookup = %+v, %v", entry, err)
	}
	if _, err := ReadKeyTabFile(filepath.Join(t.TempDir(), "missing.keytab")); !errors.Is(err, ErrKeytab) {
		t.Fatalf("missing file error = %v, want ErrKeytab", err)
	}
}

// TestKeyTabPrincipalEquality verifies principal comparison is case sensitive and
// order sensitive. | TestKeyTabPrincipalEquality 校验主体比较区分大小写且顺序敏感。
func TestKeyTabPrincipalEquality(t *testing.T) {
	image := buildTestKeyTab(
		testKeyTabEntry{components: []string{"user"}, realm: "EXAMPLE.COM", kvno8: 1, etype: ETypeAES256CTS, key: bytes.Repeat([]byte{0x22}, 32)},
	)
	tab, err := ParseKeyTab(image)
	if err != nil {
		t.Fatalf("ParseKeyTab: %v", err)
	}
	for _, principal := range []PrincipalName{
		{NameString: []string{"USER"}},
		{NameString: []string{"user", "admin"}},
		{NameString: []string{"admin", "user"}},
	} {
		if _, err := tab.Lookup(principal, "EXAMPLE.COM", 0, 1); !errors.Is(err, ErrNoKey) {
			t.Errorf("Lookup(%s) error = %v, want ErrNoKey", principal.String(), err)
		}
	}
}

// TestKeyTabWireGolden verifies a hand-computed keytab record. | TestKeyTabWireGolden
// 校验手工计算的 keytab 记录。
func TestKeyTabWireGolden(t *testing.T) {
	key := bytes.Repeat([]byte{0xaa}, 16)
	image := buildTestKeyTab(testKeyTabEntry{components: []string{"u"}, realm: "R", nameType: NameTypePrincipal, timestamp: 1, kvno8: 2, etype: ETypeAES128CTS, key: key})
	want := mustHex(t, "0502"+"00000025"+"0001"+"0001"+"52"+"0001"+"75"+"00000001"+"00000001"+"02"+"0011"+"0010"+"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if !bytes.Equal(image, want) {
		t.Fatalf("image = %x, want %x", image, want)
	}
	tab, err := ParseKeyTab(image)
	if err != nil {
		t.Fatalf("ParseKeyTab: %v", err)
	}
	entries := tab.Entries()
	if len(entries) != 1 || entries[0].Principal.String() != "u" || entries[0].Realm != "R" {
		t.Fatalf("entries = %+v", entries)
	}
	if entries[0].Timestamp.Unix() != 1 {
		t.Fatalf("timestamp = %v", entries[0].Timestamp)
	}
	if got := binary.BigEndian.Uint32(image[2:6]); int(got) != 37 {
		t.Fatalf("entry size = %d, want 37", got)
	}
}

// TestKeyTabLookupIgnoresNameType verifies that keytab matching follows MIT
// ktutil and krb5_kt_get_entry semantics and ignores the principal name type. |
// TestKeyTabLookupIgnoresNameType 校验 keytab 匹配遵循 MIT ktutil 与
// krb5_kt_get_entry 语义并忽略主体名称类型。
func TestKeyTabLookupIgnoresNameType(t *testing.T) {
	image := buildTestKeyTab(testKeyTabEntry{
		components: []string{"ldap", "dc1.example.com"},
		realm:      "EXAMPLE.COM",
		nameType:   NameTypePrincipal,
		kvno8:      2,
		etype:      ETypeAES256CTS,
		key:        bytes.Repeat([]byte{0x55}, 32),
	})
	table, err := ParseKeyTab(image)
	if err != nil {
		t.Fatalf("ParseKeyTab: %v", err)
	}
	requested := NewPrincipalName(NameTypeSRVInst, "ldap", "dc1.example.com")
	entry, err := table.Lookup(requested, "EXAMPLE.COM", ETypeAES256CTS, 2)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if entry.Principal.NameType != NameTypePrincipal {
		t.Fatalf("entry name type = %d, want %d", entry.Principal.NameType, NameTypePrincipal)
	}
	if _, err := table.Lookup(NewPrincipalName(NameTypeSRVInst, "ldap", "other.example.com"), "EXAMPLE.COM", ETypeAES256CTS, 2); !errors.Is(err, ErrNoKey) {
		t.Fatalf("Lookup different component error = %v, want ErrNoKey", err)
	}
}
