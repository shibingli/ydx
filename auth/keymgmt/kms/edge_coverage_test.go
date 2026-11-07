package kms

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"testing"
	"time"
)

// TestUsageMaskAndKeyPredicates exercises the usage bitset and nil-safe key predicates. | TestUsageMaskAndKeyPredicates
// 覆盖用途位集与空安全的密钥判定。
func TestUsageMaskAndKeyPredicates(t *testing.T) {
	all := []KeyUsage{UsageEncrypt, UsageDecrypt, UsageSign, UsageVerify, UsageWrapKey, UsageUnwrapKey, UsageDeriveKey, UsageGenerateDataKey}
	var mask UsageMask
	for _, usage := range all {
		mask = mask.Add(usage)
		if !mask.Has(usage) {
			t.Fatalf("Has(%q) = false after Add", usage)
		}
	}
	if got := len(mask.Usages()); got != len(all) {
		t.Fatalf("Usages length = %d, want %d", got, len(all))
	}
	unknown := KeyUsage("bogus")
	if mask.Has(unknown) || mask.Add(unknown) != mask || mask.Remove(unknown) != mask {
		t.Fatal("unknown usage must be ignored by Has/Add/Remove")
	}
	if UsageMaskOf(KeyUsage("bogus")) != 0 || UsageMaskOf(UsageEncrypt) != MaskEncrypt {
		t.Fatal("UsageMaskOf mismatch")
	}
	removed := mask.Remove(UsageEncrypt)
	if removed.Has(UsageEncrypt) || !removed.Has(UsageDecrypt) {
		t.Fatal("Remove must clear only the requested bit")
	}
	var nilKey *Key
	if nilKey.HasUsage(UsageEncrypt) || nilKey.IsSymmetric() || nilKey.IsSigning() {
		t.Fatal("nil key predicates must be false")
	}
	if nilKey.Clone() != nil || nilKey.PublicView() != nil || nilKey.MetadataView() != nil {
		t.Fatal("nil key views must be nil")
	}
	if nilKey.CurrentVersion() != nil || nilKey.VersionAt(1) != nil || nilKey.MaxVersion() != 0 {
		t.Fatal("nil key version accessors must be nil/zero")
	}
	if (*KeyVersion)(nil).Clone() != nil {
		t.Fatal("nil version clone must be nil")
	}
	if (*AuditEvent)(nil).Clone() != nil || (*Envelope)(nil).Clone() != nil {
		t.Fatal("nil clone helpers must return nil")
	}
	symmetric := []KeyType{KeyTypeAES, KeyTypeChaCha20, KeyTypeSM4}
	signing := []KeyType{KeyTypeRSA, KeyTypeECDSA, KeyTypeEd25519, KeyTypeSM2}
	for _, keyType := range symmetric {
		k := &Key{Type: keyType}
		if !k.IsSymmetric() || k.IsSigning() {
			t.Fatalf("%s symmetric classification wrong", keyType)
		}
	}
	for _, keyType := range signing {
		k := &Key{Type: keyType}
		if k.IsSymmetric() || !k.IsSigning() {
			t.Fatalf("%s signing classification wrong", keyType)
		}
	}
	k := &Key{Type: "bogus"}
	if k.IsSymmetric() || k.IsSigning() {
		t.Fatal("unknown key type must be neither symmetric nor signing")
	}

	original := &Key{
		ID:             "view-key",
		Version:        2,
		Material:       []byte{1, 2, 3},
		PublicMaterial: []byte{4, 5},
		Versions: []*KeyVersion{
			nil,
			{Version: 1, Material: []byte{6}, PublicMaterial: []byte{7}},
			{Version: 2, Material: []byte{8}, PublicMaterial: []byte{9}},
		},
	}
	pub := original.PublicView()
	if pub.Material != nil || len(pub.PublicMaterial) == 0 || pub.Versions[1].Material != nil || len(pub.Versions[1].PublicMaterial) == 0 {
		t.Fatal("PublicView must drop private material and keep public material")
	}
	if original.Material[0] != 1 || original.Versions[2].Material[0] != 8 {
		t.Fatal("PublicView must not mutate the original")
	}
	meta := original.MetadataView()
	if len(meta.PublicMaterial) != 0 || len(meta.Versions[1].PublicMaterial) != 0 {
		t.Fatal("MetadataView must drop all material")
	}
	if original.CurrentVersion().Version != 2 || original.VersionAt(1).Version != 1 || original.VersionAt(9) != nil {
		t.Fatal("version accessors mismatch")
	}
	if original.MaxVersion() != 2 {
		t.Fatal("MaxVersion must consider k.Version and versions")
	}
	if (&Key{Version: 5}).MaxVersion() != 5 {
		t.Fatal("MaxVersion must fall back to k.Version")
	}

	filtered := &Key{ID: "Orders-Key", Alias: "Primary", Type: KeyTypeAES, State: StateActive, UsageMask: MaskEncrypt, ParentID: "p1", Tags: []string{"prod"}, Metadata: map[string]string{"team": "Payments"}}
	cases := []struct {
		name   string
		filter KeyFilter
		want   bool
	}{
		{"empty", KeyFilter{}, true},
		{"nil", KeyFilter{ParentID: "p2"}, false},
		{"state", KeyFilter{State: StateActive}, true},
		{"state mismatch", KeyFilter{State: StateDestroyed}, false},
		{"type", KeyFilter{Type: KeyTypeAES}, true},
		{"type mismatch", KeyFilter{Type: KeyTypeRSA}, false},
		{"usage", KeyFilter{Usage: UsageEncrypt}, true},
		{"usage mismatch", KeyFilter{Usage: UsageSign}, false},
		{"parent", KeyFilter{ParentID: "p1"}, true},
		{"tag", KeyFilter{Tag: "prod"}, true},
		{"tag missing", KeyFilter{Tag: "dev"}, false},
		{"query id", KeyFilter{Query: "orders"}, true},
		{"query alias", KeyFilter{Query: "primary"}, true},
		{"query metadata", KeyFilter{Query: "payments"}, true},
		{"query missing", KeyFilter{Query: "absent"}, false},
	}
	for _, tc := range cases {
		if got := tc.filter.matches(filtered); got != tc.want {
			t.Fatalf("%s: matches = %v, want %v", tc.name, got, tc.want)
		}
	}
	if (KeyFilter{}).matches(nil) {
		t.Fatal("nil key must not match")
	}

	now := time.Unix(1700000000, 0).UTC()
	keys := []*Key{
		{ID: "b", CreatedAt: now},
		{ID: "a", CreatedAt: now},
		{ID: "c", CreatedAt: now.Add(-time.Hour)},
	}
	sortKeys(keys)
	if keys[0].ID != "c" || keys[1].ID != "a" || keys[2].ID != "b" {
		t.Fatalf("sortKeys order = %s,%s,%s", keys[0].ID, keys[1].ID, keys[2].ID)
	}
}

// TestTransitionMatrix covers every lifecycle edge and material preservation of CanTransition.
// | TestTransitionMatrix 覆盖全部生命周期转换边与 CanTransition 的材料保持。
func TestTransitionMatrix(t *testing.T) {
	states := []KeyState{StatePreActive, StateActive, StateDeactivated, StateCompromised, StateDestroyed, StatePendingDeletion}
	allowed := map[KeyState][]KeyState{
		StatePreActive:       {StateActive, StateDeactivated, StateCompromised, StatePendingDeletion, StateDestroyed},
		StateActive:          {StateDeactivated, StateCompromised, StatePendingDeletion},
		StateDeactivated:     {StateCompromised, StatePendingDeletion, StateDestroyed},
		StateCompromised:     {StatePendingDeletion, StateDestroyed},
		StateDestroyed:       {},
		StatePendingDeletion: {StateDestroyed},
	}
	for _, from := range states {
		for _, to := range states {
			want := false
			for _, candidate := range allowed[from] {
				if candidate == to {
					want = true
				}
			}
			key := &Key{ID: "k", State: from, Material: []byte{1}, PublicMaterial: []byte{2}, Versions: []*KeyVersion{{Version: 1, Material: []byte{3}, PublicMaterial: []byte{4}}}}
			err := key.Transition(to, time.Time{})
			if got := err == nil; got != want {
				t.Fatalf("%s -> %s: err=%v, want success=%v", from, to, err, want)
			}
			if !want {
				if !errors.Is(err, ErrInvalidState) {
					t.Fatalf("%s -> %s: err = %v, want ErrInvalidState", from, to, err)
				}
				if len(key.Material) == 0 {
					t.Fatalf("%s -> %s: rejected transition erased material", from, to)
				}
				continue
			}
			if to == StateDestroyed {
				if key.Material != nil || key.PublicMaterial != nil || key.Versions[0].Material != nil {
					t.Fatalf("%s -> destroyed did not erase material", from)
				}
			} else if key.State != to {
				t.Fatalf("%s -> %s: state = %s", from, to, key.State)
			}
		}
	}
	unknown := &Key{ID: "k", State: StateActive}
	if err := unknown.Transition(KeyState("bogus"), time.Now()); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("unknown target err = %v", err)
	}
	var nilKey *Key
	if !errors.Is(nilKey.Transition(StateActive, time.Now()), ErrNotFound) {
		t.Fatal("nil Transition must return ErrNotFound")
	}
	if nilKey.CanTransition(StateActive) {
		t.Fatal("nil CanTransition must be false")
	}
	deactivated := &Key{State: StateDeactivated, Material: []byte{1, 2, 3}, PublicMaterial: []byte{4}, Versions: []*KeyVersion{{Version: 1, Material: []byte{5}}}}
	if !deactivated.CanTransition(StateDestroyed) {
		t.Fatal("deactivated can be destroyed")
	}
	if len(deactivated.Material) == 0 || len(deactivated.Versions[0].Material) == 0 {
		t.Fatal("CanTransition must not erase the original material")
	}
	active := &Key{State: StateActive}
	if !active.CanTransition(StateDeactivated) || active.CanTransition(StateDestroyed) || active.CanTransition(StateActive) {
		t.Fatal("active CanTransition matrix mismatch")
	}

	for _, usage := range []KeyUsage{UsageDecrypt, UsageUnwrapKey, UsageVerify} {
		if err := (&Key{State: StateDeactivated, UsageMask: UsageMaskOf(usage)}).usableFor(usage); err != nil {
			t.Fatalf("deactivated must allow %q: %v", usage, err)
		}
		if err := (&KeyVersion{State: StateDeactivated}).usableFor(usage); err != nil {
			t.Fatalf("deactivated version must allow %q: %v", usage, err)
		}
	}
	if err := (&Key{State: StateDeactivated, UsageMask: MaskEncrypt}).usableFor(UsageEncrypt); !errors.Is(err, ErrKeyNotUsable) {
		t.Fatalf("deactivated encrypt err = %v", err)
	}
	if err := (&KeyVersion{State: StateDeactivated}).usableFor(UsageEncrypt); !errors.Is(err, ErrKeyNotUsable) {
		t.Fatalf("deactivated version encrypt err = %v", err)
	}
	if err := (&Key{State: StateDestroyed, UsageMask: MaskDecrypt}).usableFor(UsageDecrypt); !errors.Is(err, ErrKeyNotUsable) {
		t.Fatalf("destroyed err = %v", err)
	}
	if err := (&KeyVersion{State: StateCompromised}).usableFor(UsageDecrypt); !errors.Is(err, ErrKeyNotUsable) {
		t.Fatalf("compromised version err = %v", err)
	}
	if err := (&Key{}).usableFor(UsageDecrypt); !errors.Is(err, ErrUsageNotAllowed) {
		t.Fatalf("missing usage err = %v", err)
	}
	if err := (&KeyVersion{}).usableFor(UsageDecrypt); !errors.Is(err, ErrKeyNotUsable) {
		t.Fatalf("inactive version err = %v", err)
	}
	var nilVersion *KeyVersion
	if !errors.Is(nilVersion.usableFor(UsageDecrypt), ErrVersionNotFound) {
		t.Fatal("nil version usableFor must return ErrVersionNotFound")
	}
	var nilForUse *Key
	if !errors.Is(nilForUse.usableFor(UsageDecrypt), ErrNotFound) {
		t.Fatal("nil key usableFor must return ErrNotFound")
	}
}

// TestServiceConfigAndHelpers covers constructor validation, nil-safe accessors and error labels.
// | TestServiceConfigAndHelpers 覆盖构造校验、空安全访问器与错误标签。
func TestServiceConfigAndHelpers(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil store err = %v", err)
	}
	root := &Key{Material: []byte("0123456789abcdef")}
	if _, err := New(Config{Store: NewMemoryStore(), RootKey: root, Passphrase: "x"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("root+passphrase err = %v", err)
	}
	if _, err := New(Config{Store: NewMemoryStore(), RootKey: &Key{}}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("root without material err = %v", err)
	}
	if _, err := New(Config{Store: NewMemoryStore(), RootKey: &Key{Material: []byte("short")}}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("short root err = %v", err)
	}
	if wrapper, err := newAtRestWrapper(nil, ""); wrapper != nil || err != nil {
		t.Fatalf("empty at-rest wrapper = %v, %v", wrapper, err)
	}
	if _, err := newAtRestWrapper(nil, "passphrase"); err != nil {
		t.Fatalf("passphrase wrapper: %v", err)
	}
	service, clock := newServiceForTest(t, Config{MaxDataKeyLength: -3, ExportPolicy: ExportPolicy{AllowPrivate: true}})
	if service.Store() == nil || service.Keys() == nil || !service.ExportPolicy().AllowPrivate {
		t.Fatal("accessors must reflect configuration")
	}
	if service.Now().IsZero() || !service.Now().Equal(clock.Now()) {
		t.Fatal("Now must use configured clock")
	}
	if service.maxDataKeyLength != defaultMaxDerivedLength {
		t.Fatal("non-positive MaxDataKeyLength must use the default")
	}
	var nilService *Service
	if nilService.Store() != nil || nilService.Keys() != nil || nilService.ExportPolicy().AllowPrivate {
		t.Fatal("nil service accessors mismatch")
	}
	if nilService.log() == nil {
		t.Fatal("nil service log must return default logger")
	}
	if nilService.Now().IsZero() {
		t.Fatal("nil service Now must return wall clock")
	}
	if events, err := nilService.ListAudit(context.Background(), AuditFilter{}); !errors.Is(err, ErrStoreUnavailable) || events != nil {
		t.Fatalf("nil ListAudit = %v, %v", events, err)
	}
	if _, err := nilService.mutateStoredKey(context.Background(), "x", func(*Key) error { return nil }); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("nil mutate err = %v", err)
	}

	sentinels := []error{ErrNotFound, ErrKeyExists, ErrAliasExists, ErrAliasNotFound, ErrVersionNotFound, ErrVersionExists, ErrConflict, ErrInvalidState, ErrKeyNotUsable, ErrUsageNotAllowed, ErrInvalidKeyType, ErrInvalidKeySize, ErrInvalidMaterial, ErrInvalidCiphertext, ErrAuthentication, ErrExportDenied, ErrNotSupported, ErrNonceReuse, ErrRandomSource, ErrInvalidRequest, ErrInvalidConfig, ErrUnauthorized, ErrForbidden}
	for _, sentinel := range sentinels {
		if label := errorLabel(sentinel); label == "" || label == "internal" {
			t.Fatalf("errorLabel(%v) = %q", sentinel, label)
		}
	}
	if errorLabel(nil) != "none" || errorLabel(errors.New("boom")) != "internal" {
		t.Fatal("errorLabel defaults mismatch")
	}
	if strconvUint32(0) != "0" || strconvUint32(1) != "1" || strconvUint32(4294967295) != "4294967295" {
		t.Fatal("strconvUint32 mismatch")
	}
	if !containsFold("Orders", "orders") || containsFold("orders", "x") || !containsFold("orders", "") {
		t.Fatal("containsFold mismatch")
	}
	if lowerASCII("ABC") != "abc" {
		t.Fatal("lowerASCII mismatch")
	}
	if !errorsIs(ErrNotFound, ErrNotFound) || errorsIs(nil, ErrNotFound) {
		t.Fatal("errorsIs mismatch")
	}
	buf := []byte{1, 2, 3}
	zeroBytes(buf)
	if buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
		t.Fatal("zeroBytes did not zero the buffer")
	}
	if _, err := randomBytes(0); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("randomBytes(0) err = %v", err)
	}
	id, err := randomID()
	if err != nil || len(id) != 32 {
		t.Fatalf("randomID = %q, %v", id, err)
	}
	s := &Service{}
	if s.rememberNonce("k", 1, []byte("short")) {
		t.Fatal("short nonce must be rejected")
	}
	if !s.rememberNonce("k", 1, bytes.Repeat([]byte{1}, gcmNonceSize)) {
		t.Fatal("fresh nonce must be accepted")
	}
	if s.rememberNonce("k", 1, bytes.Repeat([]byte{1}, gcmNonceSize)) {
		t.Fatal("replayed nonce must be rejected")
	}
	cache := newNonceCache(1)
	var first, second [gcmNonceSize]byte
	first[0], second[0] = 1, 2
	if !cache.add(first) || cache.add(first) || !cache.add(second) {
		t.Fatal("nonce cache insertion semantics mismatch")
	}
	if !cache.add(first) {
		t.Fatal("evicted nonce must be accepted again")
	}
}

// TestServiceValidationAndMaterial covers identifier/alias validation and material generation.
// | TestServiceValidationAndMaterial 覆盖标识、别名校验与材料生成。
func TestServiceValidationAndMaterial(t *testing.T) {
	for _, id := range []string{"", string(bytes.Repeat([]byte{'a'}, maxKeyIDLength+1)), "bad id", "bad/slash"} {
		if err := validateKeyID(id); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("validateKeyID(%q) err = %v", id, err)
		}
	}
	for _, id := range []string{"a", "Key-1_2.3:4@5+6", string(bytes.Repeat([]byte{'a'}, maxKeyIDLength))} {
		if err := validateKeyID(id); err != nil {
			t.Fatalf("validateKeyID(%q): %v", id, err)
		}
	}
	if err := validateAlias(""); err != nil {
		t.Fatalf("empty alias: %v", err)
	}
	if err := validateAlias(string(bytes.Repeat([]byte{'a'}, maxAliasLength+1))); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("long alias err = %v", err)
	}
	if err := validateAlias("bad\x00alias"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("control alias err = %v", err)
	}
	if err := validateAlias(string([]byte{0xff, 0xfe})); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid UTF-8 alias err = %v", err)
	}
	if got := uniqueTags([]string{"b", "", "a", "b"}); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("uniqueTags = %v", got)
	}
	if uniqueTags([]string{"", ""}) != nil || uniqueTags(nil) != nil {
		t.Fatal("empty tags must normalize to nil")
	}
	meta := copyMetadata(map[string]string{"a": "b"})
	meta["a"] = "changed"
	if copyMetadata(nil) != nil {
		t.Fatal("nil metadata must stay nil")
	}
	if boolLabel(true) != "true" || boolLabel(false) != "false" {
		t.Fatal("boolLabel mismatch")
	}
	if got := algorithmFor(KeyTypeECDSA, 384); got != "ECDSA-P384" {
		t.Fatalf("algorithmFor ECDSA = %q", got)
	}
	if got := algorithmFor(KeyTypeEd25519, 256); got != "Ed25519" {
		t.Fatalf("algorithmFor Ed25519 = %q", got)
	}
	if got := algorithmFor(KeyTypeSM2, 256); got != "SM2" {
		t.Fatalf("algorithmFor SM2 = %q", got)
	}
	if got := algorithmFor(KeyTypeSM4, 128); got != "SM4-GCM" {
		t.Fatalf("algorithmFor SM4 = %q", got)
	}
	if got := algorithmFor(KeyTypeChaCha20, 256); got != "ChaCha20-Poly1305" {
		t.Fatalf("algorithmFor ChaCha = %q", got)
	}
	if got := algorithmFor(KeyTypeAES, 192); got != "AES-192-GCM" {
		t.Fatalf("algorithmFor AES = %q", got)
	}
	if got := algorithmFor(KeyTypeRSA, 2048); got != "RSA" {
		t.Fatalf("algorithmFor RSA = %q", got)
	}
	if got := algorithmFor(KeyType("bogus"), 0); got != "" {
		t.Fatalf("algorithmFor unknown = %q", got)
	}
	if !isSymmetricType(KeyTypeAES) || !isSymmetricType(KeyTypeChaCha20) || !isSymmetricType(KeyTypeSM4) || isSymmetricType(KeyTypeRSA) {
		t.Fatal("isSymmetricType mismatch")
	}
	if aesAlgorithm(128, "GCM") != "AES-128-GCM" {
		t.Fatal("aesAlgorithm mismatch")
	}
	if curve, err := ecdsaCurve(256); err != nil || curve == nil {
		t.Fatalf("ecdsaCurve(256) = %v, %v", curve, err)
	}
	if _, err := ecdsaCurve(123); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("ecdsaCurve(123) err = %v", err)
	}
	if _, err := ecdsaCurve(384); err != nil {
		t.Fatalf("ecdsaCurve(384): %v", err)
	}
	if _, err := ecdsaCurve(521); err != nil {
		t.Fatalf("ecdsaCurve(521): %v", err)
	}
	if mask := defaultUsageMask(KeyTypeAES); !mask.Has(UsageEncrypt) || !mask.Has(UsageGenerateDataKey) {
		t.Fatal("default symmetric usage mask mismatch")
	}
	if mask := defaultUsageMask(KeyTypeECDSA); mask != MaskSign|MaskVerify {
		t.Fatalf("default signing mask = %d", mask)
	}
	if mask := defaultUsageMask(KeyType("bogus")); mask != 0 {
		t.Fatal("unknown type default mask must be zero")
	}
	if _, err := filterUsages(KeyTypeAES, []KeyUsage{UsageSign}); !errors.Is(err, ErrUsageNotAllowed) {
		t.Fatalf("unsupported usage err = %v", err)
	}
	if _, err := filterUsages(KeyTypeAES, []KeyUsage{KeyUsage("bogus")}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unknown usage err = %v", err)
	}
	if mask, err := filterUsages(KeyTypeAES, []KeyUsage{UsageEncrypt}); err != nil || mask != MaskEncrypt {
		t.Fatalf("filterUsages explicit = %d, %v", mask, err)
	}

	invalid := []struct {
		keyType KeyType
		bits    int
	}{
		{KeyTypeAES, 100},
		{KeyTypeChaCha20, 128},
		{KeyTypeSM4, 256},
		{KeyTypeRSA, 1024},
		{KeyTypeECDSA, 100},
		{KeyTypeEd25519, 128},
		{KeyTypeSM2, 512},
		{KeyType("bogus"), 0},
	}
	for _, tc := range invalid {
		if _, _, _, _, err := generateMaterial(tc.keyType, tc.bits); err == nil {
			t.Fatalf("generateMaterial(%s,%d) must fail", tc.keyType, tc.bits)
		}
	}
	if _, _, _, bits, err := generateMaterial(KeyTypeChaCha20, 0); err != nil || bits != 256 {
		t.Fatalf("generateMaterial ChaCha = %d, %v", bits, err)
	}
	if _, _, _, bits, err := generateMaterial(KeyTypeSM4, 0); err != nil || bits != 128 {
		t.Fatalf("generateMaterial SM4 = %d, %v", bits, err)
	}
	if _, _, _, bits, err := generateMaterial(KeyTypeEd25519, 0); err != nil || bits != 256 {
		t.Fatalf("generateMaterial Ed25519 = %d, %v", bits, err)
	}
	if _, _, _, bits, err := generateMaterial(KeyTypeSM2, 0); err != nil || bits != 256 {
		t.Fatalf("generateMaterial SM2 = %d, %v", bits, err)
	}
	if _, _, _, bits, err := generateMaterial(KeyTypeAES, 0); err != nil || bits != 256 {
		t.Fatalf("generateMaterial AES = %d, %v", bits, err)
	}
	if _, _, _, bits, err := generateMaterial(KeyTypeECDSA, 0); err != nil || bits != 256 {
		t.Fatalf("generateMaterial ECDSA = %d, %v", bits, err)
	}

	if _, _, _, err := ValidateMaterial(KeyType("bogus"), 0, []byte("x"), nil); !errors.Is(err, ErrInvalidKeyType) {
		t.Fatalf("ValidateMaterial unknown type err = %v", err)
	}
	if _, _, _, err := ValidateMaterial(KeyTypeAES, 256, nil, nil); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("ValidateMaterial empty symmetric err = %v", err)
	}
	if _, _, _, err := ValidateMaterial(KeyTypeAES, 256, []byte("short"), nil); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("ValidateMaterial short AES err = %v", err)
	}
	if _, _, _, err := ValidateMaterial(KeyTypeRSA, 2048, []byte("garbage"), nil); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("ValidateMaterial garbage RSA err = %v", err)
	}
	private, public, bits, err := ValidateMaterial(KeyTypeAES, 128, bytes.Repeat([]byte{1}, 16), nil)
	if err != nil || len(private) != 16 || public != nil || bits != 128 {
		t.Fatalf("ValidateMaterial AES = %d, %d, %d, %v", len(private), len(public), bits, err)
	}
	for _, opt := range []SignOption{WithDigest(), WithPSS(), WithHash(crypto.SHA384), nil} {
		if _, err := normalizeSignOptions([]SignOption{opt}); err != nil {
			t.Fatalf("normalizeSignOptions(%v): %v", opt, err)
		}
	}
	if _, err := normalizeSignOptions([]SignOption{WithHash(crypto.MD5)}); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("normalizeSignOptions MD5 err = %v", err)
	}
	if _, err := normalizeSignOptions([]SignOption{WithHash(crypto.Hash(9999))}); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("normalizeSignOptions unknown hash err = %v", err)
	}
}

// TestKMSStoreFacadeAndMemoryEdges covers KeyStore nil safety, resolve fallbacks and memory store edges.
// | TestKMSStoreFacadeAndMemoryEdges 覆盖 KeyStore 空安全、解析回退与内存存储边界。
func TestKMSStoreFacadeAndMemoryEdges(t *testing.T) {
	ctx := context.Background()
	var nilFacade *KeyStore
	if nilFacade.Store() != nil {
		t.Fatal("nil KeyStore.Store must be nil")
	}
	for _, call := range []func() error{
		func() error { _, err := nilFacade.Get(ctx, "x"); return err },
		func() error { _, err := nilFacade.Resolve(ctx, "x"); return err },
		func() error { _, err := nilFacade.List(ctx, KeyFilter{}); return err },
		func() error { _, err := nilFacade.Export(ctx, "x", ExportRequest{}); return err },
	} {
		if err := call(); !errors.Is(err, ErrStoreUnavailable) {
			t.Fatalf("nil facade err = %v", err)
		}
	}
	key := testKey("k1", "alias-1")
	key.Metadata = map[string]string{"team": "core"}
	key.Tags = []string{"prod"}
	key.Versions = []*KeyVersion{{Version: 1, Material: []byte{1, 2, 3, 4}, PublicMaterial: []byte{5}}}
	store := NewMemoryStore()
	if err := store.CreateKey(ctx, key); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if err := store.CreateKey(ctx, key); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("duplicate CreateKey err = %v", err)
	}
	if _, err := store.GetKey(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetKey missing err = %v", err)
	}
	if _, err := store.ResolveAlias(ctx, ""); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty ResolveAlias err = %v", err)
	}
	if _, err := store.ResolveAlias(ctx, "missing"); !errors.Is(err, ErrAliasNotFound) {
		t.Fatalf("missing ResolveAlias err = %v", err)
	}
	if err := store.SetAlias(ctx, "", "k1"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty SetAlias err = %v", err)
	}
	if err := store.SetAlias(ctx, "alias-x", "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing key SetAlias err = %v", err)
	}
	if err := store.SetAlias(ctx, "alias-1", "k1"); err != nil {
		t.Fatalf("same-owner SetAlias: %v", err)
	}
	other := testKey("k2", "alias-2")
	if err := store.CreateKey(ctx, other); err != nil {
		t.Fatalf("create k2: %v", err)
	}
	if err := store.SetAlias(ctx, "alias-1", "k2"); !errors.Is(err, ErrAliasExists) {
		t.Fatalf("conflicting SetAlias err = %v", err)
	}
	if err := store.DeleteAlias(ctx, "alias-2"); err != nil {
		t.Fatalf("DeleteAlias: %v", err)
	}
	if err := store.DeleteAlias(ctx, "alias-2"); !errors.Is(err, ErrAliasNotFound) {
		t.Fatalf("second DeleteAlias err = %v", err)
	}
	if err := store.SaveVersion(ctx, "missing", &KeyVersion{Version: 2}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SaveVersion missing key err = %v", err)
	}
	if err := store.SaveVersion(ctx, "k1", nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("SaveVersion nil err = %v", err)
	}
	if err := store.SaveVersion(ctx, "k1", &KeyVersion{Version: 2, Material: []byte{9}}); err != nil {
		t.Fatalf("SaveVersion: %v", err)
	}
	if err := store.SaveVersion(ctx, "k1", &KeyVersion{Version: 2}); !errors.Is(err, ErrVersionExists) {
		t.Fatalf("duplicate version err = %v", err)
	}
	if version, err := store.GetVersion(ctx, "k1", 2); err != nil || version.Version != 2 {
		t.Fatalf("GetVersion = %v, %v", version, err)
	}
	if _, err := store.GetVersion(ctx, "k1", 9); !errors.Is(err, ErrVersionNotFound) {
		t.Fatalf("GetVersion missing err = %v", err)
	}
	if _, err := store.GetVersion(ctx, "missing", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetVersion missing key err = %v", err)
	}
	if versions, err := store.ListVersions(ctx, "k1"); err != nil || len(versions) != 2 {
		t.Fatalf("ListVersions = %d, %v", len(versions), err)
	}
	if _, err := store.ListVersions(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ListVersions missing err = %v", err)
	}
	if keys, err := store.ListKeys(ctx, KeyFilter{Offset: 5}); err != nil || len(keys) != 0 {
		t.Fatalf("offset beyond end = %d, %v", len(keys), err)
	}
	if keys, err := store.ListKeys(ctx, KeyFilter{Limit: 1, Query: "alias"}); err != nil || len(keys) != 1 {
		t.Fatalf("filtered list = %d, %v", len(keys), err)
	}
	facade := NewKeyStore(store, ExportPolicy{AllowPrivate: true})
	if facade.Store() == nil {
		t.Fatal("facade Store must be set")
	}
	got, err := facade.Get(ctx, "k1")
	if err != nil || len(got.Material) != 0 || len(got.PublicMaterial) != 0 {
		t.Fatalf("facade.Get = %+v, %v", got, err)
	}
	if got, err := facade.Resolve(ctx, "alias-1"); err != nil || got.ID != "k1" {
		t.Fatalf("facade.Resolve = %v, %v", got, err)
	}
	if list, err := facade.List(ctx, KeyFilter{}); err != nil || len(list) != 2 {
		t.Fatalf("facade.List = %d, %v", len(list), err)
	}
	if list, err := facade.List(ctx, KeyFilter{}); err != nil || len(list[0].PublicMaterial) != 0 {
		t.Fatal("facade.List must return metadata views")
	}
	if exported, err := facade.Export(ctx, "k1", ExportRequest{Format: ExportFormatRaw, Private: true}); err != nil || !exported.Private || len(exported.Material) != 4 {
		t.Fatalf("facade.Export private = %+v, %v", exported, err)
	}
	if _, err := facade.Export(ctx, "k1", ExportRequest{Private: false}); !errors.Is(err, ErrExportDenied) {
		t.Fatalf("symmetric public export err = %v", err)
	}
	if _, err := NewKeyStore(store, ExportPolicy{}).Export(ctx, "k1", ExportRequest{Format: ExportFormatRaw, Private: true}); !errors.Is(err, ErrExportDenied) {
		t.Fatal("policy must deny private export")
	}
	if _, err := resolveStoredKey(ctx, nil, "k1"); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("nil store resolve err = %v", err)
	}
	if _, err := resolveStoredKey(ctx, store, ""); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty resolve err = %v", err)
	}
	if _, err := resolveStoredKey(ctx, store, "missing"); !errors.Is(err, ErrAliasNotFound) {
		t.Fatalf("missing resolve err = %v", err)
	}

	if err := store.AppendAudit(ctx, nil); !errors.Is(err, errAuditNilEvent) {
		t.Fatalf("nil audit err = %v", err)
	}
	base := time.Unix(1700000000, 0).UTC()
	for i, event := range []*AuditEvent{
		{ID: "b", Operation: OperationKeyCreate, Outcome: OutcomeSuccess, At: base},
		{ID: "a", Operation: OperationKeyCreate, Outcome: OutcomeSuccess, At: base},
		{ID: "c", Operation: OperationEncrypt, KeyID: "k1", Actor: "alice", Outcome: OutcomeFailure, At: base.Add(time.Minute)},
	} {
		event.Detail = map[string]string{"i": strconvUint32(uint32(i))}
		if err := store.AppendAudit(ctx, event); err != nil {
			t.Fatalf("AppendAudit: %v", err)
		}
	}
	if events, err := store.ListAudit(ctx, AuditFilter{}); err != nil || len(events) != 3 {
		t.Fatalf("ListAudit = %d, %v", len(events), err)
	}
	if events, _ := store.ListAudit(ctx, AuditFilter{Descending: true}); events[0].ID != "c" {
		t.Fatal("descending audit order mismatch")
	}
	if events, _ := store.ListAudit(ctx, AuditFilter{Operation: OperationKeyCreate, Limit: 1}); len(events) != 1 {
		t.Fatal("audit filter/limit mismatch")
	}
	if events, _ := store.ListAudit(ctx, AuditFilter{KeyID: "k1", Actor: "alice", Outcome: OutcomeFailure}); len(events) != 1 {
		t.Fatal("audit key/actor/outcome filter mismatch")
	}
	if events, _ := store.ListAudit(ctx, AuditFilter{Since: base.Add(30 * time.Second)}); len(events) != 1 {
		t.Fatal("audit since filter mismatch")
	}
	if events, _ := store.ListAudit(ctx, AuditFilter{Until: base}); len(events) != 2 {
		t.Fatal("audit until filter mismatch")
	}
	if events, _ := store.ListAudit(ctx, AuditFilter{Offset: 9}); len(events) != 0 {
		t.Fatal("audit offset beyond end mismatch")
	}
	if events, _ := store.ListAudit(ctx, AuditFilter{Offset: 1, Limit: 1}); len(events) != 1 {
		t.Fatal("audit pagination mismatch")
	}
	if (AuditFilter{}).matches(nil) {
		t.Fatal("nil audit event must not match")
	}
	clone := (&AuditEvent{ID: "x", Detail: map[string]string{"a": "b"}}).Clone()
	clone.Detail["a"] = "c"
	played := &AuditEvent{ID: "x", At: base, Detail: map[string]string{"a": "z"}}
	if played.Detail["a"] != "z" {
		t.Fatal("audit clone must deep-copy detail")
	}
	if WithActor(nil, "alice") == nil || ActorFromContext(WithActor(ctx, "alice")) != "alice" {
		t.Fatal("actor context helpers mismatch")
	}
	if ActorFromContext(nil) != "" || ActorFromContext(ctx) != "" {
		t.Fatal("actor must be empty without WithActor")
	}
	sorted := []*AuditEvent{{ID: "b", At: base}, {ID: "a", At: base}, {ID: "c", At: base.Add(-time.Minute)}}
	sortAudit(sorted, false)
	if sorted[0].ID != "c" || sorted[1].ID != "a" || sorted[2].ID != "b" {
		t.Fatal("ascending audit sort mismatch")
	}
	sortAudit(sorted, true)
	if sorted[0].ID != "b" || sorted[1].ID != "a" {
		t.Fatal("descending audit tie-break mismatch")
	}
}

// TestAtRestWrapperEdges covers wrapper error paths and material version selection.
// | TestAtRestWrapperEdges 覆盖包装器错误路径与材料版本选择。
func TestAtRestWrapperEdges(t *testing.T) {
	ctx := context.Background()
	root := &Key{Type: KeyTypeAES, Material: []byte("0123456789abcdef")}
	wrapper, err := newAtRestWrapper(root, "")
	if err != nil {
		t.Fatalf("newAtRestWrapper: %v", err)
	}
	raw, ok := wrapper.(*atRestWrapper)
	if !ok {
		t.Fatal("unexpected wrapper type")
	}
	if out, err := raw.Wrap(ctx, "k", 1, nil); err != nil || out != nil {
		t.Fatalf("empty Wrap = %v, %v", out, err)
	}
	wrapped, err := raw.Wrap(ctx, "k", 1, []byte("secret"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	plain, err := raw.Unwrap(ctx, "k", 1, wrapped)
	if err != nil || string(plain) != "secret" {
		t.Fatalf("Unwrap = %q, %v", plain, err)
	}
	if _, err := raw.Unwrap(ctx, "k", 2, wrapped); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("wrong version unwrap err = %v", err)
	}
	if _, err := raw.Unwrap(ctx, "other", 1, wrapped); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("wrong key unwrap err = %v", err)
	}
	if _, err := raw.Unwrap(ctx, "k", 1, []byte("garbage")); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("missing magic err = %v", err)
	}
	if _, err := raw.Unwrap(ctx, "k", 1, append([]byte(nil), atRestMagic...)); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("truncated err = %v", err)
	}
	if _, err := (*atRestWrapper)(nil).Wrap(ctx, "k", 1, []byte("x")); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil wrapper Wrap err = %v", err)
	}
	if _, err := (*atRestWrapper)(nil).Unwrap(ctx, "k", 1, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil wrapper Unwrap err = %v", err)
	}

	service, _ := newServiceForTest(t, Config{})
	if _, err := service.persistKey(ctx, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("persistKey nil err = %v", err)
	}
	stored, err := service.persistKey(ctx, &Key{ID: "k", Version: 1, Material: []byte{1}, Versions: []*KeyVersion{nil, {Version: 1, Material: []byte{2}}}})
	if err != nil || len(stored.Material) != 1 {
		t.Fatalf("persistKey no wrapper = %+v, %v", stored, err)
	}
	if _, err := service.loadKey(ctx, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("loadKey nil err = %v", err)
	}
	if _, err := service.loadKey(ctx, &Key{ID: "k", Material: append([]byte(nil), atRestMagic...)}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("wrapped material without wrapper err = %v", err)
	}
	if loaded, err := service.loadKey(ctx, &Key{ID: "k", Material: []byte{1}}); err != nil || len(loaded.Material) != 1 {
		t.Fatalf("loadKey plain = %+v, %v", loaded, err)
	}
	key := &Key{Version: 2, Material: []byte{9}, Versions: []*KeyVersion{{Version: 1, Material: []byte{1}}, {Version: 2, Material: []byte{2}}}}
	if got := materialForVersion(key, 1); len(got) != 1 || got[0] != 1 {
		t.Fatalf("materialForVersion(1) = %v", got)
	}
	if got := materialForVersion(key, 2); len(got) != 1 || got[0] != 2 {
		t.Fatalf("materialForVersion(2) = %v", got)
	}
	if got := materialForVersion(&Key{Version: 3, Material: []byte{3}}, 3); len(got) != 1 || got[0] != 3 {
		t.Fatalf("materialForVersion fallback = %v", got)
	}
	if materialForVersion(nil, 1) != nil || materialForVersion(key, 9) != nil {
		t.Fatal("materialForVersion missing must be nil")
	}
}

// TestAEADAndCryptoEdgePaths covers AEAD helpers, authorization and crypto failure paths.
// | TestAEADAndCryptoEdgePaths 覆盖 AEAD 辅助、授权与密码失败路径。
func TestAEADAndCryptoEdgePaths(t *testing.T) {
	ctx := context.Background()
	if cipherAlgorithmLabel(cipherAlgorithm(99)) != "unknown" {
		t.Fatal("unknown algorithm label mismatch")
	}
	if _, _, err := cipherAlgorithmForKey(nil, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("nil key algorithm err = %v", err)
	}
	if _, _, err := cipherAlgorithmForKey(&Key{Type: KeyTypeAES, Version: 1}, 1); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("missing material err = %v", err)
	}
	if _, _, err := cipherAlgorithmForKey(&Key{Type: KeyTypeAES, Version: 1, Material: []byte{1}}, 1); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("bad AES size err = %v", err)
	}
	if alg, _, err := cipherAlgorithmForKey(&Key{Type: KeyTypeAES, Version: 1, Material: make([]byte, 16)}, 1); err != nil || alg != algAES128GCM {
		t.Fatalf("AES-128 alg = %v, %v", alg, err)
	}
	if alg, _, err := cipherAlgorithmForKey(&Key{Type: KeyTypeAES, Version: 1, Material: make([]byte, 24)}, 1); err != nil || alg != algAES192GCM {
		t.Fatalf("AES-192 alg = %v, %v", alg, err)
	}
	if alg, _, err := cipherAlgorithmForKey(&Key{Type: KeyTypeChaCha20, Version: 1, Material: make([]byte, 12)}, 1); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("bad ChaCha size err = %v, alg=%v", err, alg)
	}
	if alg, _, err := cipherAlgorithmForKey(&Key{Type: KeyTypeChaCha20, Version: 1, Material: make([]byte, 32)}, 1); err != nil || alg != algChaCha20Poly1305 {
		t.Fatalf("ChaCha alg = %v, %v", alg, err)
	}
	if alg, _, err := cipherAlgorithmForKey(&Key{Type: KeyTypeSM4, Version: 1, Material: make([]byte, 8)}, 1); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("bad SM4 size err = %v, alg=%v", err, alg)
	}
	if alg, _, err := cipherAlgorithmForKey(&Key{Type: KeyTypeSM4, Version: 1, Material: make([]byte, 16)}, 1); err != nil || alg != algSM4GCM {
		t.Fatalf("SM4 alg = %v, %v", alg, err)
	}
	if _, _, err := cipherAlgorithmForKey(&Key{Type: KeyTypeRSA, Version: 1, Material: make([]byte, 32)}, 1); !errors.Is(err, ErrInvalidKeyType) {
		t.Fatalf("asymmetric AEAD err = %v", err)
	}
	if _, err := sealAEAD(cipherAlgorithm(99), nil, make([]byte, gcmNonceSize), nil, nil); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("sealAEAD unknown err = %v", err)
	}
	if _, err := openAEAD(cipherAlgorithm(99), nil, make([]byte, gcmNonceSize), nil, nil); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("openAEAD unknown err = %v", err)
	}
	if _, err := newAESGCM([]byte("short")); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("newAESGCM bad key err = %v", err)
	}
	if _, err := sealAEAD(algAES256GCM, []byte("bad"), nil, nil, nil); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("sealAEAD bad key err = %v", err)
	}
	if _, err := sealAEAD(algChaCha20Poly1305, []byte("bad"), nil, nil, nil); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("sealAEAD bad ChaCha key err = %v", err)
	}
	nonce := bytes.Repeat([]byte{7}, gcmNonceSize)
	sealed, err := sealAEAD(algAES256GCM, bytes.Repeat([]byte{1}, 32), nonce, []byte("x"), nil)
	if err != nil {
		t.Fatalf("sealAEAD: %v", err)
	}
	if _, err := openAEAD(algAES256GCM, bytes.Repeat([]byte{2}, 32), nonce, sealed, nil); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong-key open err = %v", err)
	}
	if _, err := openAEAD(algChaCha20Poly1305, bytes.Repeat([]byte{1}, 32), nonce, make([]byte, 20), nil); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("ChaCha tamper err = %v", err)
	}
	if _, err := openAEAD(algSM4GCM, bytes.Repeat([]byte{1}, 16), nonce, make([]byte, 20), nil); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("SM4 tamper err = %v", err)
	}
	if _, err := openAEAD(algAES256GCM, []byte("bad"), nonce, sealed, nil); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("open bad AES key err = %v", err)
	}
	if _, err := openAEAD(algChaCha20Poly1305, []byte("bad"), nonce, sealed, nil); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("open bad ChaCha key err = %v", err)
	}
	if _, err := openAEAD(algAES256GCM, bytes.Repeat([]byte{1}, 32), []byte("short"), sealed, nil); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatal("short nonce must fail")
	}

	service, _ := newServiceForTest(t, Config{})
	aes := createKeyForTest(t, service, CreateKeyRequest{ID: "aes", Type: KeyTypeAES, Bits: 256}, true)
	if _, err := service.Encrypt(ctx, "missing", []byte("x"), nil); !errors.Is(err, ErrAliasNotFound) {
		t.Fatalf("Encrypt missing err = %v", err)
	}
	if _, err := service.Decrypt(ctx, "aes", []byte("garbage"), nil); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("Decrypt garbage err = %v", err)
	}
	ciphertext, err := service.Encrypt(ctx, aes.ID, []byte("payload"), []byte("aad"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := service.Decrypt(ctx, aes.ID, ciphertext, []byte("other")); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("Decrypt wrong aad err = %v", err)
	}
	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := service.Decrypt(ctx, aes.ID, tampered, []byte("aad")); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("Decrypt tamper err = %v", err)
	}
	other := createKeyForTest(t, service, CreateKeyRequest{ID: "aes2", Type: KeyTypeAES, Bits: 256}, true)
	if _, err := service.Decrypt(ctx, other.ID, ciphertext, []byte("aad")); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("Decrypt wrong key err = %v", err)
	}
	if _, err := service.Encrypt(ctx, aes.ID, nil, nil); err != nil {
		t.Fatalf("Encrypt empty plaintext: %v", err)
	}
	if _, err := service.GenerateRandom(ctx, 0); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("GenerateRandom(0) err = %v", err)
	}
	if _, err := service.GenerateRandom(ctx, (1<<20)+1); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("GenerateRandom too large err = %v", err)
	}
	if out, err := service.GenerateRandom(ctx, 8); err != nil || len(out) != 8 {
		t.Fatalf("GenerateRandom = %d, %v", len(out), err)
	}

	signKey := createKeyForTest(t, service, CreateKeyRequest{ID: "ed", Type: KeyTypeEd25519}, true)
	signature, err := service.Sign(ctx, signKey.ID, []byte("message"))
	if err != nil || len(signature) == 0 {
		t.Fatalf("Sign = %d, %v", len(signature), err)
	}
	if valid, err := service.Verify(ctx, signKey.ID, []byte("message"), signature); err != nil || !valid {
		t.Fatalf("Verify = %v, %v", valid, err)
	}
	if valid, err := service.Verify(ctx, signKey.ID, []byte("other"), signature); err != nil || valid {
		t.Fatalf("Verify wrong data = %v, %v", valid, err)
	}
	if _, err := service.Sign(ctx, "missing", []byte("x")); !errors.Is(err, ErrAliasNotFound) {
		t.Fatalf("Sign missing err = %v", err)
	}
	if _, err := service.Sign(ctx, aes.ID, []byte("x")); !errors.Is(err, ErrUsageNotAllowed) {
		t.Fatalf("Sign symmetric err = %v", err)
	}
	if _, err := service.Verify(ctx, aes.ID, []byte("x"), []byte("sig")); !errors.Is(err, ErrUsageNotAllowed) {
		t.Fatalf("Verify symmetric err = %v", err)
	}
	if _, err := service.Sign(ctx, signKey.ID, []byte("x"), WithDigest()); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("Ed25519 digest err = %v", err)
	}
	if _, err := service.Verify(ctx, signKey.ID, []byte("x"), []byte("bad"), WithDigest()); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("Ed25519 verify digest err = %v", err)
	}
	if _, err := service.Verify(ctx, signKey.ID, []byte("x"), []byte("bad")); err != nil {
		t.Fatalf("Verify malformed signature err = %v", err)
	}
}

// TestDemoEnvelopeAndWrapEdgePaths covers envelope validation, parsing and negative decrypt paths.
// | TestDemoEnvelopeAndWrapEdgePaths 覆盖信封校验、解析与解密失败路径。
func TestDemoEnvelopeAndWrapEdgePaths(t *testing.T) {
	ctx := context.Background()
	valid := &Envelope{KeyID: "k", KeyVersion: 1, WrappedKey: bytes.Repeat([]byte{1}, 20), Nonce: bytes.Repeat([]byte{2}, gcmNonceSize), Ciphertext: bytes.Repeat([]byte{3}, 16)}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid envelope: %v", err)
	}
	invalid := []*Envelope{
		nil,
		{KeyID: "", WrappedKey: []byte{1}, Nonce: make([]byte, gcmNonceSize), Ciphertext: make([]byte, 16)},
		{KeyID: string(bytes.Repeat([]byte{'k'}, maxKeyIDLength+1)), WrappedKey: []byte{1}, Nonce: make([]byte, gcmNonceSize), Ciphertext: make([]byte, 16)},
		{KeyID: "k", WrappedKey: nil, Nonce: make([]byte, gcmNonceSize), Ciphertext: make([]byte, 16)},
		{KeyID: "k", WrappedKey: bytes.Repeat([]byte{1}, 65536), Nonce: make([]byte, gcmNonceSize), Ciphertext: make([]byte, 16)},
		{KeyID: "k", WrappedKey: []byte{1}, Nonce: make([]byte, gcmNonceSize-1), Ciphertext: make([]byte, 16)},
		{KeyID: "k", WrappedKey: []byte{1}, Nonce: make([]byte, gcmNonceSize), Ciphertext: make([]byte, 15)},
	}
	for i, env := range invalid {
		if err := env.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("invalid envelope %d err = %v", i, err)
		}
		if _, err := env.MarshalBinary(); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("invalid MarshalBinary %d err = %v", i, err)
		}
	}
	blob, err := valid.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	parsed, err := ParseEnvelope(blob)
	if err != nil || parsed.KeyID != valid.KeyID || parsed.KeyVersion != valid.KeyVersion || !bytes.Equal(parsed.Ciphertext, valid.Ciphertext) {
		t.Fatalf("ParseEnvelope = %+v, %v", parsed, err)
	}
	parseCases := map[string][]byte{
		"nil":              nil,
		"bad magic":        append([]byte("NOPE"), blob[4:]...),
		"bad version":      append([]byte(nil), blob...),
		"zero key id":      append([]byte(nil), blob...),
		"zero wrapped":     append([]byte(nil), blob...),
		"bad nonce":        append([]byte(nil), blob...),
		"truncated cipher": append([]byte(nil), blob[:len(blob)-16]...),
	}
	parseCases["bad version"][4] = 9
	parseCases["zero key id"][5], parseCases["zero key id"][6] = 0, 0
	parseCases["zero wrapped"][12], parseCases["zero wrapped"][13] = 0, 0
	parseCases["bad nonce"][34] = 0
	for name, data := range parseCases {
		if _, err := ParseEnvelope(data); !errors.Is(err, ErrInvalidCiphertext) {
			t.Fatalf("ParseEnvelope %s err = %v", name, err)
		}
	}

	service, _ := newServiceForTest(t, Config{})
	key := createKeyForTest(t, service, CreateKeyRequest{ID: "env", Type: KeyTypeAES, Bits: 256}, true)
	env, err := service.EncryptEnvelope(ctx, key.ID, []byte("bulk"), []byte("aad"))
	if err != nil {
		t.Fatalf("EncryptEnvelope: %v", err)
	}
	if plain, err := service.DecryptEnvelope(ctx, env, []byte("aad")); err != nil || string(plain) != "bulk" {
		t.Fatalf("DecryptEnvelope = %q, %v", plain, err)
	}
	if _, err := service.DecryptEnvelope(ctx, nil, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil envelope err = %v", err)
	}
	if _, err := service.DecryptEnvelope(ctx, &Envelope{KeyID: "missing"}, nil); !errors.Is(err, ErrAliasNotFound) {
		t.Fatalf("missing envelope key err = %v", err)
	}
	if _, err := service.DecryptEnvelope(ctx, env, []byte("wrong")); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong envelope aad err = %v", err)
	}
	badNonce := env.Clone()
	badNonce.Nonce = []byte("short")
	if _, err := service.DecryptEnvelope(ctx, badNonce, []byte("aad")); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("bad envelope nonce err = %v", err)
	}
	badVersion := env.Clone()
	badVersion.KeyVersion = 99
	if _, err := service.DecryptEnvelope(ctx, badVersion, []byte("aad")); !errors.Is(err, ErrVersionNotFound) {
		t.Fatalf("bad envelope version err = %v", err)
	}
	tampered := env.Clone()
	tampered.Ciphertext[len(tampered.Ciphertext)-1] ^= 0xff
	if _, err := service.DecryptEnvelope(ctx, tampered, []byte("aad")); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered envelope err = %v", err)
	}
	tamperedWrap := env.Clone()
	tamperedWrap.WrappedKey[len(tamperedWrap.WrappedKey)-1] ^= 0xff
	if _, err := service.DecryptEnvelope(ctx, tamperedWrap, []byte("aad")); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered wrapped key err = %v", err)
	}
	if _, err := service.CreateKey(ctx, CreateKeyRequest{ID: "env-alias-key", Alias: "env-alias", Type: KeyTypeAES, Bits: 256}); err != nil {
		t.Fatalf("create alias key: %v", err)
	}
	wrongKeyEnv := env.Clone()
	wrongKeyEnv.KeyID = "env-alias"
	if _, err := service.DecryptEnvelope(ctx, wrongKeyEnv, []byte("aad")); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("envelope wrong key id err = %v", err)
	}

	if _, err := service.WrapKey(ctx, key.ID, nil, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty wrap err = %v", err)
	}
	if _, err := service.WrapKey(ctx, "missing", []byte("x"), nil); !errors.Is(err, ErrAliasNotFound) {
		t.Fatalf("missing wrap err = %v", err)
	}
	wrapped, err := service.WrapKey(ctx, key.ID, []byte("material"), []byte("aad"))
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	if plain, err := service.UnwrapKey(ctx, key.ID, wrapped, []byte("aad")); err != nil || string(plain) != "material" {
		t.Fatalf("UnwrapKey = %q, %v", plain, err)
	}
	if _, err := service.UnwrapKey(ctx, key.ID, []byte("garbage"), nil); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("UnwrapKey garbage err = %v", err)
	}
	other := createKeyForTest(t, service, CreateKeyRequest{ID: "env2", Type: KeyTypeAES, Bits: 256}, true)
	if _, err := service.UnwrapKey(ctx, other.ID, wrapped, []byte("aad")); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("UnwrapKey wrong key err = %v", err)
	}
	if _, err := service.UnwrapKey(ctx, key.ID, wrapped, []byte("wrong")); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("UnwrapKey wrong aad err = %v", err)
	}
	if _, err := service.GenerateDataKey(ctx, key.ID, -1, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("negative DEK err = %v", err)
	}
	if _, err := service.GenerateDataKey(ctx, key.ID, 4096, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("oversized DEK err = %v", err)
	}
	dek, err := service.GenerateDataKey(ctx, key.ID, 0, nil)
	if err != nil || len(dek.Plaintext) != 32 || len(dek.Wrapped) == 0 {
		t.Fatalf("GenerateDataKey = %+v, %v", dek, err)
	}
	if plain, err := service.UnwrapKey(ctx, key.ID, dek.Wrapped, nil); err != nil || !bytes.Equal(plain, dek.Plaintext) {
		t.Fatalf("UnwrapKey DEK mismatch: %v", err)
	}
	if _, err := service.DeriveKey(ctx, key.ID, -1, "info", nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("negative derive err = %v", err)
	}
	if _, err := service.DeriveKey(ctx, key.ID, 8192, "info", nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("oversized derive err = %v", err)
	}
	if out, err := service.DeriveKey(ctx, key.ID, 16, "info", []byte("salt")); err != nil || len(out) != 16 {
		t.Fatalf("DeriveKey = %d, %v", len(out), err)
	}
	if _, err := service.DeriveKey(ctx, "missing", 16, "info", nil); !errors.Is(err, ErrAliasNotFound) {
		t.Fatalf("missing derive err = %v", err)
	}
	signingKey := createKeyForTest(t, service, CreateKeyRequest{ID: "sig-key", Type: KeyTypeEd25519}, true)
	if _, err := service.DeriveKey(ctx, signingKey.ID, 16, "info", nil); !errors.Is(err, ErrUsageNotAllowed) {
		t.Fatalf("derive signing key err = %v", err)
	}
	if _, err := service.GenerateDataKey(ctx, signingKey.ID, 32, nil); !errors.Is(err, ErrUsageNotAllowed) {
		t.Fatalf("DEK signing key err = %v", err)
	}
	if _, err := service.WrapKey(ctx, signingKey.ID, []byte("x"), nil); !errors.Is(err, ErrUsageNotAllowed) {
		t.Fatalf("wrap signing key err = %v", err)
	}
}

// TestExportFormatsAndImportEdges covers every export encoding and import derivation branch.
// | TestExportFormatsAndImportEdges 覆盖全部导出编码与导入推导分支。
func TestExportFormatsAndImportEdges(t *testing.T) {
	ctx := context.Background()
	service, _ := newServiceForTest(t, Config{ExportPolicy: ExportPolicy{AllowPrivate: true}})

	type materialSet struct {
		keyType KeyType
		bits    int
	}
	for _, tc := range []materialSet{
		{KeyTypeRSA, 2048},
		{KeyTypeECDSA, 256},
		{KeyTypeEd25519, 0},
		{KeyTypeSM2, 0},
		{KeyTypeAES, 256},
		{KeyTypeChaCha20, 0},
		{KeyTypeSM4, 0},
	} {
		private, public, _, _, err := generateMaterial(tc.keyType, tc.bits)
		if err != nil {
			t.Fatalf("generateMaterial(%s): %v", tc.keyType, err)
		}
		request := ImportKeyRequest{
			CreateKeyRequest: CreateKeyRequest{ID: "import-" + string(tc.keyType), Type: tc.keyType, Exportable: true},
			Material:         private,
		}
		imported, err := service.ImportKey(ctx, request)
		if err != nil {
			t.Fatalf("ImportKey(%s): %v", tc.keyType, err)
		}
		if !imported.Exportable || imported.Algorithm == "" {
			t.Fatalf("imported %s metadata incomplete: %+v", tc.keyType, imported)
		}
		if len(imported.PublicMaterial) == 0 && !imported.IsSymmetric() {
			t.Fatalf("imported %s missing derived public material", tc.keyType)
		}
		_ = public
		if tc.keyType == KeyTypeAES || tc.keyType == KeyTypeChaCha20 || tc.keyType == KeyTypeSM4 {
			if exported, err := service.ExportKey(ctx, imported.ID, ExportRequest{Format: ExportFormatRaw, Private: true}); err != nil || !exported.Private || len(exported.Material) == 0 {
				t.Fatalf("symmetric raw export %s = %+v, %v", tc.keyType, exported, err)
			}
			if tc.keyType == KeyTypeAES {
				if exported, err := service.ExportKey(ctx, imported.ID, ExportRequest{Format: ExportFormatJWK, Private: true}); err != nil || len(exported.Material) == 0 {
					t.Fatalf("AES JWK export = %+v, %v", exported, err)
				}
			}
			if _, err := service.ExportKey(ctx, imported.ID, ExportRequest{Format: ExportFormatRaw}); !errors.Is(err, ErrExportDenied) {
				t.Fatalf("symmetric public export err = %v", err)
			}
			if _, err := service.ExportKey(ctx, imported.ID, ExportRequest{Format: ExportFormatPEM, Private: true}); !errors.Is(err, ErrNotSupported) {
				t.Fatalf("symmetric PEM export err = %v", err)
			}
			continue
		}
		for _, format := range []ExportFormat{ExportFormatRaw, ExportFormatPEM, ExportFormatJWK} {
			exported, err := service.ExportKey(ctx, imported.ID, ExportRequest{Format: format, Private: true})
			if tc.keyType == KeyTypeSM2 && format == ExportFormatJWK {
				if !errors.Is(err, ErrNotSupported) {
					t.Fatalf("SM2 private JWK err = %v", err)
				}
			} else if err != nil || len(exported.Material) == 0 {
				t.Fatalf("private export %s/%s = %+v, %v", tc.keyType, format, exported, err)
			}
			publicExported, err := service.ExportKey(ctx, imported.ID, ExportRequest{Format: format})
			if tc.keyType == KeyTypeSM2 && format == ExportFormatJWK {
				if !errors.Is(err, ErrNotSupported) {
					t.Fatalf("SM2 public JWK err = %v", err)
				}
			} else if err != nil || len(publicExported.PublicMaterial) == 0 {
				t.Fatalf("public export %s/%s = %+v, %v", tc.keyType, format, publicExported, err)
			}
		}
	}
	if _, err := service.ExportKey(ctx, "missing", ExportRequest{}); !errors.Is(err, ErrAliasNotFound) {
		t.Fatalf("missing export err = %v", err)
	}
	aes, err := service.ImportKey(ctx, ImportKeyRequest{CreateKeyRequest: CreateKeyRequest{ID: "aes-export", Type: KeyTypeAES, Bits: 128, Exportable: true}, Material: bytes.Repeat([]byte{1}, 16)})
	if err != nil {
		t.Fatalf("import AES: %v", err)
	}
	if exported, err := service.ExportKey(ctx, aes.ID, ExportRequest{Private: true}); err != nil || exported.Format != ExportFormatRaw {
		t.Fatalf("default symmetric format = %+v, %v", exported, err)
	}
	if _, err := service.ExportKey(ctx, aes.ID, ExportRequest{Format: ExportFormat("bogus"), Private: true}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unknown format err = %v", err)
	}
	if _, err := service.ExportKey(ctx, aes.ID, ExportRequest{Version: 99, Private: true}); !errors.Is(err, ErrVersionNotFound) {
		t.Fatalf("unknown version err = %v", err)
	}
	if _, err := exportKeyMaterial(nil, ExportPolicy{}, ExportRequest{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("export nil key err = %v", err)
	}
	notExportable := &Key{ID: "n", Type: KeyTypeAES, Version: 1, Material: []byte{1, 2}, Versions: []*KeyVersion{{Version: 1}}}
	if _, err := exportKeyMaterial(notExportable, ExportPolicy{AllowPrivate: true}, ExportRequest{Private: true}); !errors.Is(err, ErrExportDenied) {
		t.Fatalf("not exportable err = %v", err)
	}
	if _, err := exportKeyMaterial(&Key{ID: "n", Type: KeyTypeAES, Version: 1, Exportable: true, Versions: []*KeyVersion{{Version: 1}}}, ExportPolicy{AllowPrivate: true}, ExportRequest{Private: true, Version: 1}); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("missing material export err = %v", err)
	}
	if _, err := exportKeyMaterial(&Key{ID: "n", Type: KeyTypeRSA, Version: 1, Exportable: true, Material: []byte("garbage"), Versions: []*KeyVersion{{Version: 1}}}, ExportPolicy{AllowPrivate: true}, ExportRequest{Private: true, Format: ExportFormatPEM}); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("garbage RSA PEM err = %v", err)
	}

	if _, err := service.ImportKey(ctx, ImportKeyRequest{CreateKeyRequest: CreateKeyRequest{Type: KeyTypeAES}}); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("symmetric import without material err = %v", err)
	}
	if _, err := service.ImportKey(ctx, ImportKeyRequest{CreateKeyRequest: CreateKeyRequest{Type: ""}}); !errors.Is(err, ErrInvalidKeyType) {
		t.Fatalf("import empty type err = %v", err)
	}
	if _, err := service.ImportKey(ctx, ImportKeyRequest{CreateKeyRequest: CreateKeyRequest{ID: "bad id", Type: KeyTypeAES}}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("import bad id err = %v", err)
	}
	if _, err := service.ImportKey(ctx, ImportKeyRequest{CreateKeyRequest: CreateKeyRequest{Type: KeyTypeAES, Alias: "bad\x00"}, Material: bytes.Repeat([]byte{1}, 16)}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("import bad alias err = %v", err)
	}
	if _, err := service.ImportKey(ctx, ImportKeyRequest{CreateKeyRequest: CreateKeyRequest{Type: KeyTypeAES, RotationInterval: -time.Second}, Material: bytes.Repeat([]byte{1}, 32)}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("import negative rotation err = %v", err)
	}
	if _, err := service.ImportKey(ctx, ImportKeyRequest{CreateKeyRequest: CreateKeyRequest{Type: KeyType("bogus")}, Material: []byte{1}}); !errors.Is(err, ErrInvalidKeyType) {
		t.Fatalf("import unknown type err = %v", err)
	}
	if _, err := service.CreateKey(ctx, CreateKeyRequest{Type: ""}); !errors.Is(err, ErrInvalidKeyType) {
		t.Fatalf("create empty type err = %v", err)
	}
	if _, err := service.CreateKey(ctx, CreateKeyRequest{ID: "bad id", Type: KeyTypeAES}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("create bad id err = %v", err)
	}
	if _, err := service.CreateKey(ctx, CreateKeyRequest{Type: KeyTypeAES, Alias: "bad\x00"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("create bad alias err = %v", err)
	}
	if _, err := service.CreateKey(ctx, CreateKeyRequest{Type: KeyTypeAES, Usage: []KeyUsage{UsageSign}}); !errors.Is(err, ErrUsageNotAllowed) {
		t.Fatalf("create bad usage err = %v", err)
	}
	if _, err := service.CreateKey(ctx, CreateKeyRequest{Type: KeyTypeAES, RotationInterval: -time.Second}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("create negative rotation err = %v", err)
	}
	if key, err := service.CreateKey(ctx, CreateKeyRequest{Type: KeyTypeAES}); err != nil || key.ID == "" || key.Version != 1 {
		t.Fatalf("create generated id = %+v, %v", key, err)
	}
	publicOnlyPrivate, publicOnlyPublic, _, _, err := generateMaterial(KeyTypeECDSA, 256)
	if err != nil {
		t.Fatalf("generate ECDSA: %v", err)
	}
	_ = publicOnlyPrivate
	publicOnly, err := service.ImportKey(ctx, ImportKeyRequest{CreateKeyRequest: CreateKeyRequest{ID: "pub-only", Type: KeyTypeECDSA, Bits: 256}, PublicMaterial: publicOnlyPublic})
	if err != nil || publicOnly.UsageMask != MaskVerify {
		t.Fatalf("public-only import = %+v, %v", publicOnly, err)
	}
	if _, err := service.ImportKey(ctx, ImportKeyRequest{CreateKeyRequest: CreateKeyRequest{Type: KeyTypeECDSA, Bits: 256, Usage: []KeyUsage{UsageSign}}, PublicMaterial: publicOnlyPublic}); !errors.Is(err, ErrUsageNotAllowed) {
		t.Fatalf("public-only sign usage err = %v", err)
	}
	if _, err := service.ImportKey(ctx, ImportKeyRequest{CreateKeyRequest: CreateKeyRequest{Type: KeyTypeECDSA, Bits: 256, Usage: []KeyUsage{UsageVerify}}, PublicMaterial: publicOnlyPublic}); err != nil {
		t.Fatalf("public-only verify usage: %v", err)
	}
	if _, err := service.ImportKey(ctx, ImportKeyRequest{CreateKeyRequest: CreateKeyRequest{Type: KeyTypeECDSA, Bits: 256, Usage: []KeyUsage{KeyUsage("bogus")}}, PublicMaterial: publicOnlyPublic}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("public-only unknown usage err = %v", err)
	}
}

// TestLifecycleFailurePaths covers lifecycle guards, scheduled jobs and rotation edge cases.
// | TestLifecycleFailurePaths 覆盖生命周期守卫、计划任务与轮换边界。
func TestLifecycleFailurePaths(t *testing.T) {
	ctx := context.Background()
	service, clock := newServiceForTest(t, Config{DeletionDelay: 2 * time.Hour})
	key := createKeyForTest(t, service, CreateKeyRequest{ID: "life", Type: KeyTypeAES, Bits: 256, RotationInterval: time.Hour}, true)

	if _, err := service.Activate(ctx, "missing"); !errors.Is(err, ErrAliasNotFound) {
		t.Fatalf("activate missing err = %v", err)
	}
	if _, err := service.Activate(ctx, key.ID); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("reactivate err = %v", err)
	}
	if _, err := service.Destroy(ctx, key.ID); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("destroy active err = %v", err)
	}
	deactivated, err := service.Deactivate(ctx, key.ID)
	if err != nil || deactivated.State != StateDeactivated {
		t.Fatalf("Deactivate = %+v, %v", deactivated, err)
	}
	if _, err := service.Deactivate(ctx, key.ID); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("double deactivate err = %v", err)
	}
	if _, err := service.Activate(ctx, key.ID); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("reactivate deactivated err = %v", err)
	}
	compromised, err := service.Compromise(ctx, key.ID)
	if err != nil || compromised.State != StateCompromised {
		t.Fatalf("Compromise = %+v, %v", compromised, err)
	}
	if _, err := service.Compromise(ctx, key.ID); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("double compromise err = %v", err)
	}
	destroyed, err := service.Destroy(ctx, key.ID)
	if err != nil || destroyed.State != StateDestroyed || len(destroyed.Material) != 0 {
		t.Fatalf("Destroy = %+v, %v", destroyed, err)
	}
	if _, err := service.Destroy(ctx, key.ID); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("double destroy err = %v", err)
	}
	if _, err := service.Destroy(ctx, "missing"); !errors.Is(err, ErrAliasNotFound) {
		t.Fatalf("destroy missing err = %v", err)
	}

	scheduled := createKeyForTest(t, service, CreateKeyRequest{ID: "scheduled", Type: KeyTypeAES, Bits: 256}, true)
	scheduledView, err := service.ScheduleDelete(ctx, scheduled.ID, 0)
	if err != nil {
		t.Fatalf("ScheduleDelete: %v", err)
	}
	if !scheduledView.DeleteAfter.Equal(clock.Now().Add(2 * time.Hour)) {
		t.Fatalf("DeleteAfter = %v, want %v", scheduledView.DeleteAfter, clock.Now().Add(2*time.Hour))
	}
	if _, err := service.ScheduleDelete(ctx, scheduled.ID, time.Hour); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("reschedule err = %v", err)
	}
	defaultService, defaultClock := newServiceForTest(t, Config{})
	defaultDelayed := createKeyForTest(t, defaultService, CreateKeyRequest{ID: "default-delay", Type: KeyTypeAES, Bits: 256}, true)
	if view, err := defaultService.ScheduleDelete(ctx, defaultDelayed.ID, 0); err != nil || !view.DeleteAfter.Equal(defaultClock.Now().Add(defaultDeletionDelay)) {
		t.Fatalf("default deletion delay = %+v, %v", view, err)
	}
	clock.Advance(3 * time.Hour)
	destroyedCount, err := service.DestroyExpired(ctx, clock.Now())
	if err != nil || destroyedCount != 1 {
		t.Fatalf("DestroyExpired = %d, %v", destroyedCount, err)
	}
	if got, _ := service.GetKey(ctx, scheduled.ID); got.State != StateDestroyed {
		t.Fatalf("scheduled key state = %s", got.State)
	}
	if count, err := service.DestroyExpired(ctx, time.Time{}); err != nil || count != 0 {
		t.Fatalf("second DestroyExpired = %d, %v", count, err)
	}

	rotateKey := createKeyForTest(t, service, CreateKeyRequest{ID: "rotate", Type: KeyTypeAES, Bits: 256}, true)
	ciphertext, err := service.Encrypt(ctx, rotateKey.ID, []byte("legacy"), nil)
	if err != nil {
		t.Fatalf("Encrypt before rotate: %v", err)
	}
	rotated, err := service.Rotate(ctx, rotateKey.ID)
	if err != nil || rotated.Version != 2 {
		t.Fatalf("Rotate = %+v, %v", rotated, err)
	}
	if plain, err := service.Decrypt(ctx, rotateKey.ID, ciphertext, nil); err != nil || string(plain) != "legacy" {
		t.Fatalf("legacy decrypt after rotate = %q, %v", plain, err)
	}
	if versions, err := service.ListVersions(ctx, rotateKey.ID); err != nil || len(versions) != 2 || len(versions[0].Material) != 0 {
		t.Fatalf("ListVersions = %d, %v", len(versions), err)
	}
	preActive := createKeyForTest(t, service, CreateKeyRequest{ID: "pre", Type: KeyTypeAES, Bits: 256}, false)
	if _, err := service.Rotate(ctx, preActive.ID); !errors.Is(err, ErrKeyNotUsable) {
		t.Fatalf("rotate pre-active err = %v", err)
	}
	if _, err := service.Rotate(ctx, "missing"); !errors.Is(err, ErrAliasNotFound) {
		t.Fatalf("rotate missing err = %v", err)
	}
	if _, err := service.Rotate(ctx, scheduled.ID); !errors.Is(err, ErrKeyNotUsable) {
		t.Fatalf("rotate destroyed err = %v", err)
	}

	private, public, _, _, err := generateMaterial(KeyTypeECDSA, 256)
	if err != nil {
		t.Fatalf("generate ECDSA: %v", err)
	}
	_ = private
	publicOnly, err := service.ImportKey(ctx, ImportKeyRequest{CreateKeyRequest: CreateKeyRequest{ID: "public-only-rotate", Type: KeyTypeECDSA, Bits: 256}, PublicMaterial: public})
	if err != nil {
		t.Fatalf("import public-only: %v", err)
	}
	if _, err := service.Activate(ctx, publicOnly.ID); err != nil {
		t.Fatalf("activate public-only: %v", err)
	}
	if _, err := service.Rotate(ctx, publicOnly.ID); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("rotate public-only err = %v", err)
	}

	due := createKeyForTest(t, service, CreateKeyRequest{ID: "due", Type: KeyTypeAES, Bits: 256, RotationInterval: time.Hour}, true)
	noInterval := createKeyForTest(t, service, CreateKeyRequest{ID: "no-interval", Type: KeyTypeAES, Bits: 256}, true)
	if rotatedCount, err := service.RotateAllDue(ctx, clock.Now()); err != nil || rotatedCount != 0 {
		t.Fatalf("RotateAllDue early = %d, %v", rotatedCount, err)
	}
	clock.Advance(2 * time.Hour)
	if rotatedCount, err := service.RotateAllDue(ctx, clock.Now()); err != nil || rotatedCount != 1 {
		t.Fatalf("RotateAllDue due = %d, %v", rotatedCount, err)
	}
	if got, _ := service.GetKey(ctx, due.ID); got.Version != 2 {
		t.Fatalf("due key version = %d", got.Version)
	}
	if got, _ := service.GetKey(ctx, noInterval.ID); got.Version != 1 {
		t.Fatalf("no-interval key version = %d", got.Version)
	}
	if count, err := service.RotateAllDue(ctx, time.Time{}); err != nil || count != 0 {
		t.Fatalf("RotateAllDue none = %d, %v", count, err)
	}

	if _, err := service.UpdateKey(ctx, "missing", UpdateKeyRequest{}); !errors.Is(err, ErrAliasNotFound) {
		t.Fatalf("update missing err = %v", err)
	}
	if _, err := service.UpdateKey(ctx, rotateKey.ID, UpdateKeyRequest{Alias: stringPointerRaw("bad\x00")}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("update bad alias err = %v", err)
	}
	negative := -time.Second
	if _, err := service.UpdateKey(ctx, rotateKey.ID, UpdateKeyRequest{RotationInterval: &negative}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("update negative rotation err = %v", err)
	}
	empty := ""
	updated, err := service.UpdateKey(ctx, rotateKey.ID, UpdateKeyRequest{Alias: &empty, Metadata: map[string]string{"a": "b"}, Tags: []string{"z", "a", "z"}, Exportable: boolPointerRaw(true)})
	if err != nil || updated.Alias != "" || len(updated.Tags) != 2 {
		t.Fatalf("UpdateKey = %+v, %v", updated, err)
	}
	if updated.Metadata["a"] != "b" || !updated.Exportable {
		t.Fatalf("UpdateKey metadata/exportable = %+v", updated)
	}
	if err := service.store.UpdateKey(ctx, &Key{ID: "x", Revision: 99}); err == nil {
		t.Fatal("store update on missing key must fail")
	}
	if _, err := service.ListVersions(ctx, "missing"); !errors.Is(err, ErrAliasNotFound) {
		t.Fatalf("ListVersions missing err = %v", err)
	}
	if events, err := service.ListAudit(ctx, AuditFilter{}); err != nil || len(events) == 0 {
		t.Fatalf("ListAudit = %d, %v", len(events), err)
	}
}

func stringPointerRaw(value string) *string { return &value }

func boolPointerRaw(value bool) *bool { return &value }
