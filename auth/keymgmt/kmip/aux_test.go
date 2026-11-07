package kmip

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// TestTTLVHelperItems covers long-integer, big-integer, child and append helpers. |
// TestTTLVHelperItems 覆盖长整数、大整数、子项与追加辅助函数。
func TestTTLVHelperItems(t *testing.T) {
	long := NewLongInteger(TagKeyFormatType, -7)
	if value, err := long.AsLongInteger(); err != nil || value != -7 {
		t.Fatalf("AsLongInteger = %d, %v | 长整数解码 = %d，%v", value, err, value, err)
	}
	if _, err := NewInteger(TagKeyFormatType, 1).AsLongInteger(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("AsLongInteger type error = %v | 长整数类型错误 = %v", err, err)
	}
	bigValue := NewBigIntegerBytes(TagCryptographicLength, []byte{0, 0, 0, 0, 0, 0, 0, 9})
	if value, err := bigValue.AsBigInteger(); err != nil || value.Int64() != 9 {
		t.Fatalf("AsBigInteger = %v, %v | 大整数解码 = %v，%v", value, err, value, err)
	}
	encoded, err := Encode(bigValue)
	if err != nil || len(encoded) != ttlvHeaderSize+8 {
		t.Fatalf("Encode big integer = %d bytes, %v | 编码大整数 = %d 字节，%v", len(encoded), err, len(encoded), err)
	}
	if _, err := NewBigIntegerBytes(TagCryptographicLength, []byte{1, 2, 3}).AsBigInteger(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("short big integer error = %v | 过短大整数错误 = %v", err, err)
	}

	structure := NewStructure(TagTemplateAttribute,
		NewTextString(TagUniqueIdentifier, "first"),
		NewTextString(TagUniqueIdentifier, "second"),
		NewLongInteger(TagKeyFormatType, 3),
	)
	if children := structure.ChildrenOf(TagUniqueIdentifier); len(children) != 2 {
		t.Fatalf("ChildrenOf identifier = %d, want 2 | 标识符子项 = %d，期望 2", len(children), len(children))
	}
	if children, err := structure.AsStructure(); err != nil || len(children) != 3 {
		t.Fatalf("AsStructure = %d children, %v | 结构解码 = %d 个子项，%v", len(children), err, len(children), err)
	}
	if _, err := NewInteger(TagCryptographicLength, 1).AsStructure(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("AsStructure type error = %v | 结构类型错误 = %v", err, err)
	}
	appended, err := AppendItem([]byte("prefix"), NewTextString(TagUniqueIdentifier, "value"))
	if err != nil || !bytes.HasPrefix(appended, []byte("prefix")) || len(appended) <= len("prefix") {
		t.Fatalf("AppendItem = %q, %v | 追加项 = %q，%v", appended, err, appended, err)
	}
}

// TestAuthenticationEncoding covers Authentication encode/decode and validation. |
// TestAuthenticationEncoding 覆盖认证编码/解码与校验。
func TestAuthenticationEncoding(t *testing.T) {
	original := Authentication{Credentials: []Credential{
		{Username: "alice", Password: "secret"},
		{Type: CredentialTypeUsernameAndPassword, Username: "bob"},
	}}
	item, err := original.Item()
	if err != nil {
		t.Fatalf("Authentication.Item: %v | 认证编码失败：%v", err, err)
	}
	decoded, err := DecodeAuthentication(item)
	if err != nil || len(decoded.Credentials) != 2 || decoded.Credentials[0].Username != "alice" ||
		decoded.Credentials[0].Password != "secret" || decoded.Credentials[1].Password != "" {
		t.Fatalf("DecodeAuthentication = %+v, %v | 认证解码 = %+v，%v", decoded, err, decoded, err)
	}
	if _, err := (Authentication{}).Item(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty Authentication error = %v | 空认证错误 = %v", err, err)
	}
	if _, err := (Authentication{Credentials: []Credential{{Type: CredentialType(0x7F), Username: "x"}}}).Item(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported credential type error = %v | 不支持凭据类型错误 = %v", err, err)
	}
	if _, err := DecodeAuthentication(NewInteger(TagAuthentication, 1)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("non-structure Authentication error = %v | 非结构认证错误 = %v", err, err)
	}
	for name, malformed := range map[string]Item{
		"unexpected tag": NewStructure(TagAuthentication, NewInteger(TagUniqueIdentifier, 1)),
		"missing type":   NewStructure(TagAuthentication, NewStructure(TagCredential)),
		"bad value": NewStructure(TagAuthentication, NewStructure(TagCredential,
			NewEnumeration(TagCredentialType, uint32(CredentialTypeUsernameAndPassword)),
			NewInteger(TagCredentialValue, 1))),
		"unsupported type": NewStructure(TagAuthentication, NewStructure(TagCredential,
			NewEnumeration(TagCredentialType, 0x7F),
			NewStructure(TagCredentialValue, NewTextString(TagUsername, "alice")))),
		"no credentials": NewStructure(TagAuthentication),
	} {
		if _, err := DecodeAuthentication(malformed); !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%s error = %v | %s 错误 = %v", name, err, name, err)
		}
	}
	if _, err := DecodeAuthentication(Authentication{Credentials: []Credential{{Username: "x"}}}.mustItem(t)); err != nil {
		t.Fatalf("round-trip Authentication failed: %v | 认证往返失败：%v", err, err)
	}
}

// mustItem encodes the Authentication or fails the test. | mustItem 编码认证，失败时终止测试。
func (a Authentication) mustItem(t *testing.T) Item {
	t.Helper()
	item, err := a.Item()
	if err != nil {
		t.Fatalf("Authentication.Item: %v | 认证编码失败：%v", err, err)
	}
	return item
}

// TestServerAddrAndEnumStrings covers Addr plus the remaining enum String methods. |
// TestServerAddrAndEnumStrings 覆盖 Addr 与剩余枚举 String 方法。
func TestServerAddrAndEnumStrings(t *testing.T) {
	server, address := startTestServer(t)
	deadline := time.Now().Add(2 * time.Second)
	for server.Addr() == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if server.Addr() == nil || server.Addr().String() != address {
		t.Fatalf("Addr = %v, want %s | Addr = %v，期望 %s", server.Addr(), address, server.Addr(), address)
	}
	reasons := map[RevocationReasonCode]string{
		RevocationUnspecified:          "Unspecified",
		RevocationKeyCompromise:        "Key Compromise",
		RevocationCACompromise:         "CA Compromise",
		RevocationAffiliationChanged:   "Affiliation Changed",
		RevocationSuperseded:           "Superseded",
		RevocationCessationOfOperation: "Cessation Of Operation",
		RevocationPrivilegeWithdrawn:   "Privilege Withdrawn",
		RevocationReasonCode(0x7F):     "Unknown",
	}
	for code, want := range reasons {
		if got := code.String(); got != want {
			t.Errorf("RevocationReasonCode(%d).String() = %q, want %q | 撤销原因字符串 = %q，期望 %q", code, got, want, got, want)
		}
	}
	if got := NameTypeURI.String(); got != "URI" {
		t.Errorf("NameTypeURI.String() = %q | 名称类型字符串 = %q", got, got)
	}
	if got := NameType(0x7F).String(); got != "Unknown" {
		t.Errorf("unknown NameType.String() = %q | 未知名称类型字符串 = %q", got, got)
	}
}
