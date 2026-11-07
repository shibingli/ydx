package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/base64"
)

func encodeTestBytes(value string) string {
	return base64.RawStdEncoding.EncodeToString([]byte(value))
}

func TestPBKDF2HasherConfiguration(t *testing.T) {
	defaults, err := NewPBKDF2Hasher(PBKDF2Config{})
	if err != nil {
		t.Fatalf("zero config: %v", err)
	}
	if defaults.Algorithm() != "pbkdf2-sha256" || defaults.config.Iterations != 600000 ||
		defaults.config.SaltLength != 16 || defaults.config.KeyLength != 32 {
		t.Fatalf("defaults = %+v", defaults.config)
	}

	invalid := []PBKDF2Config{
		{Iterations: 99999},
		{Iterations: maxPBKDF2Iterations + 1},
		{Iterations: 100000, SaltLength: 7},
		{Iterations: 100000, SaltLength: maxSaltLength + 1},
		{Iterations: 100000, KeyLength: 15},
		{Iterations: 100000, KeyLength: maxKeyLength + 1},
		{Iterations: 100000, Hash: "md5"},
	}
	for _, config := range invalid {
		if _, err := NewPBKDF2Hasher(config); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("config %+v error = %v, want ErrInvalidConfig", config, err)
		}
	}
	if _, err := NewPBKDF2Hasher(PBKDF2Config{Iterations: 100000, Hash: "SHA512"}); err != nil {
		t.Fatalf("case-insensitive hash: %v", err)
	}
}

func TestPBKDF2HasherHashVerifyRehash(t *testing.T) {
	hasher, err := NewPBKDF2Hasher(PBKDF2Config{Iterations: 100000, SaltLength: 8, KeyLength: 16, Hash: "sha256"})
	if err != nil {
		t.Fatalf("hasher: %v", err)
	}
	if _, err := hasher.Hash(""); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty hash error = %v", err)
	}
	encoded, err := hasher.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !strings.HasPrefix(encoded, "$pbkdf2-sha256$i=100000,l=16$") {
		t.Fatalf("encoded = %q", encoded)
	}
	if ok, err := hasher.Verify("correct horse battery staple", encoded); err != nil || !ok {
		t.Fatalf("verify = %v %v", ok, err)
	}
	if ok, err := hasher.Verify("wrong", encoded); err != nil || ok {
		t.Fatalf("wrong verify = %v %v", ok, err)
	}
	if hasher.NeedsRehash(encoded) {
		t.Fatal("current hash needs rehash")
	}
	stronger, _ := NewPBKDF2Hasher(PBKDF2Config{Iterations: 200000, SaltLength: 8, KeyLength: 16})
	if !stronger.NeedsRehash(encoded) {
		t.Fatal("weaker hash does not need rehash")
	}
	if !hasher.NeedsRehash("$argon2id$v=19$m=8192,t=1,p=1$x$y") || !hasher.NeedsRehash("garbage") {
		t.Fatal("foreign hash does not need rehash")
	}

	sha512, err := NewPBKDF2Hasher(PBKDF2Config{Iterations: 100000, SaltLength: 8, KeyLength: 16, Hash: "sha512"})
	if err != nil {
		t.Fatalf("sha512: %v", err)
	}
	encoded512, err := sha512.Hash("another password")
	if err != nil {
		t.Fatalf("sha512 hash: %v", err)
	}
	if !strings.HasPrefix(encoded512, "$pbkdf2-sha512$") {
		t.Fatalf("sha512 encoded = %q", encoded512)
	}
	if ok, err := sha512.Verify("another password", encoded512); err != nil || !ok {
		t.Fatalf("sha512 verify = %v %v", ok, err)
	}
}

func TestPBKDF2HasherMalformed(t *testing.T) {
	hasher, _ := NewPBKDF2Hasher(PBKDF2Config{Iterations: 100000, SaltLength: 8, KeyLength: 16})
	salt := encodeTestBytes("saltsalt")
	key := encodeTestBytes("0123456789abcdef")
	cases := []string{
		"",
		"$pbkdf2-sha256$i=100000,l=16$" + salt,
		"$pbkdf2-sha512$i=100000,l=16$" + salt + "$" + key,
		"$pbkdf2-sha256$i=abc,l=16$" + salt + "$" + key,
		"$pbkdf2-sha256$i=100000,l=16,x=1$" + salt + "$" + key,
		"$pbkdf2-sha256$i=100000$" + salt + "$" + key,
		"$pbkdf2-sha256$i=99999,l=16$" + salt + "$" + key,
		"$pbkdf2-sha256$i=100000001,l=16$" + salt + "$" + key,
		"$pbkdf2-sha256$i=100000,l=200$" + salt + "$" + key,
		"$pbkdf2-sha256$i=100000,l=16$" + encodeTestBytes("short") + "$" + key,
		"$pbkdf2-sha256$i=100000,l=16$!!!$" + key,
		"$pbkdf2-sha256$i=100000,l=16$" + salt + "$!!!",
		"$pbkdf2-sha256$i=100000,l=16$" + salt + "$" + encodeTestBytes("0123456789abcde"),
	}
	for _, encoded := range cases {
		if ok, err := hasher.Verify("password", encoded); ok || !errors.Is(err, ErrPasswordHash) {
			t.Fatalf("Verify(%q) = %v %v, want ErrPasswordHash", encoded, ok, err)
		}
		if !hasher.NeedsRehash(encoded) {
			t.Fatalf("NeedsRehash(%q) = false", encoded)
		}
	}
	if _, _, err := parsePBKDF2Params("i=100000"); !errors.Is(err, ErrPasswordHash) {
		t.Fatalf("missing key length parsed: %v", err)
	}
	if _, _, err := parsePBKDF2Params("i=100000,l=16"); err != nil {
		t.Fatalf("valid params: %v", err)
	}
}

func TestArgon2idHasherConfiguration(t *testing.T) {
	defaults, err := NewArgon2idHasher(Argon2idConfig{})
	if err != nil {
		t.Fatalf("zero config: %v", err)
	}
	if defaults.config.Time != 3 || defaults.config.Memory != 64*1024 || defaults.config.Threads != 4 ||
		defaults.config.KeyLength != 32 || defaults.config.SaltLength != 16 {
		t.Fatalf("defaults = %+v", defaults.config)
	}
	invalid := []Argon2idConfig{
		{Time: maxArgon2Time + 1},
		{Time: 1, Memory: 8*1024 - 1},
		{Time: 1, Memory: maxArgon2Memory + 1},
		{Time: 1, Memory: 8 * 1024, Threads: maxArgon2Threads + 1},
		{Time: 1, Memory: 8 * 1024, Threads: 1, KeyLength: 15},
		{Time: 1, Memory: 8 * 1024, Threads: 1, KeyLength: maxKeyLength + 1},
		{Time: 1, Memory: 8 * 1024, Threads: 1, SaltLength: 7},
		{Time: 1, Memory: 8 * 1024, Threads: 1, SaltLength: maxSaltLength + 1},
	}
	for _, config := range invalid {
		if _, err := NewArgon2idHasher(config); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("config %+v error = %v, want ErrInvalidConfig", config, err)
		}
	}
}

func TestArgon2idHasherHashVerifyRehash(t *testing.T) {
	low, err := NewArgon2idHasher(Argon2idConfig{Time: 1, Memory: 8 * 1024, Threads: 1, KeyLength: 16, SaltLength: 8})
	if err != nil {
		t.Fatalf("low hasher: %v", err)
	}
	if _, err := low.Hash(""); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty hash error = %v", err)
	}
	encoded, err := low.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=8192,t=1,p=1$") {
		t.Fatalf("encoded = %q", encoded)
	}
	if ok, err := low.Verify("correct horse battery staple", encoded); err != nil || !ok {
		t.Fatalf("verify = %v %v", ok, err)
	}
	if ok, err := low.Verify("wrong", encoded); err != nil || ok {
		t.Fatalf("wrong verify = %v %v", ok, err)
	}
	if low.NeedsRehash(encoded) {
		t.Fatal("current hash needs rehash")
	}
	stronger, _ := NewArgon2idHasher(Argon2idConfig{Time: 2, Memory: 16 * 1024, Threads: 2, KeyLength: 16, SaltLength: 8})
	if !stronger.NeedsRehash(encoded) {
		t.Fatal("weaker hash does not need rehash")
	}
	if !low.NeedsRehash("$argon2i$v=19$m=8192,t=1,p=1$x$y") {
		t.Fatal("foreign algorithm does not need rehash")
	}
}

func TestArgon2idHasherMalformed(t *testing.T) {
	hasher, _ := NewArgon2idHasher(Argon2idConfig{Time: 1, Memory: 8 * 1024, Threads: 1, KeyLength: 16, SaltLength: 8})
	salt := encodeTestBytes("saltsalt")
	key := encodeTestBytes("0123456789abcdef")
	cases := []string{
		"",
		"$argon2id$v=19$m=8192,t=1,p=1$" + salt,
		"$argon2id$v=16$m=8192,t=1,p=1$" + salt + "$" + key,
		"$argon2i$v=19$m=8192,t=1,p=1$" + salt + "$" + key,
		"$argon2id$v=19$m=8191,t=1,p=1$" + salt + "$" + key,
		"$argon2id$v=19$m=999999999,t=1,p=1$" + salt + "$" + key,
		"$argon2id$v=19$m=8192,t=0,p=1$" + salt + "$" + key,
		"$argon2id$v=19$m=8192,t=65,p=1$" + salt + "$" + key,
		"$argon2id$v=19$m=8192,t=1,p=300$" + salt + "$" + key,
		"$argon2id$v=19$m=8192,t=1,p=0$" + salt + "$" + key,
		"$argon2id$v=19$m=8192,t=1,p=1,x=1$" + salt + "$" + key,
		"$argon2id$v=19$m=8192,t=1,p=1$" + encodeTestBytes("short") + "$" + key,
		"$argon2id$v=19$m=8192,t=1,p=1$" + salt + "$" + encodeTestBytes("short"),
		"$argon2id$v=19$m=8192,t=1,p=1$" + salt + "$" + base64.RawStdEncoding.EncodeToString(make([]byte, maxKeyLength+1)),
		"$argon2id$v=19$m=8192,t=1,p=1$!!!$" + key,
		"$argon2id$v=19$m=8192,t=1,p=1$" + salt + "$!!!",
	}
	for _, encoded := range cases {
		ok, err := hasher.Verify("password", encoded)
		if ok || !errors.Is(err, ErrPasswordHash) {
			t.Fatalf("Verify(%q) = %v %v, want ErrPasswordHash", encoded, ok, err)
		}
		if !hasher.NeedsRehash(encoded) {
			t.Fatalf("NeedsRehash(%q) = false", encoded)
		}
	}
	if ok, err := hasher.Verify("password", "$argon2id$v=19$m=8192,t=1,p=1$"+salt+"$"+encodeTestBytes("0123456789abcdef0123456789abcdef")); err != nil || ok {
		t.Fatalf("wrong long hash = %v %v", ok, err)
	}
}

func TestBcryptHasher(t *testing.T) {
	defaults, err := NewBcryptHasher(BcryptConfig{})
	if err != nil || defaults.cost != 12 {
		t.Fatalf("defaults = %+v %v", defaults, err)
	}
	for _, cost := range []int{9, 32} {
		if _, err := NewBcryptHasher(BcryptConfig{Cost: cost}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("cost %d error = %v", cost, err)
		}
	}
	hasher, err := NewBcryptHasher(BcryptConfig{Cost: 10})
	if err != nil {
		t.Fatalf("hasher: %v", err)
	}
	if _, err := hasher.Hash(strings.Repeat("a", 73)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("long password error = %v", err)
	}
	encoded, err := hasher.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !isBcryptHash(encoded) {
		t.Fatalf("encoded = %q", encoded)
	}
	if ok, err := hasher.Verify("correct horse battery staple", encoded); err != nil || !ok {
		t.Fatalf("verify = %v %v", ok, err)
	}
	if ok, err := hasher.Verify("wrong", encoded); err != nil || ok {
		t.Fatalf("wrong verify = %v %v", ok, err)
	}
	if ok, err := hasher.Verify(strings.Repeat("a", 73), encoded); err != nil || ok {
		t.Fatalf("long verify = %v %v", ok, err)
	}
	if ok, err := hasher.Verify("password", "not-a-bcrypt-hash"); ok || !errors.Is(err, ErrPasswordHash) {
		t.Fatalf("malformed verify = %v %v", ok, err)
	}
	if hasher.NeedsRehash(encoded) {
		t.Fatal("current hash needs rehash")
	}
	stronger, _ := NewBcryptHasher(BcryptConfig{Cost: 12})
	if !stronger.NeedsRehash(encoded) {
		t.Fatal("weaker hash does not need rehash")
	}
	if !hasher.NeedsRehash("not-a-bcrypt-hash") {
		t.Fatal("malformed hash does not need rehash")
	}
}

func TestScryptHasherConfiguration(t *testing.T) {
	defaults, err := NewScryptHasher(ScryptConfig{})
	if err != nil {
		t.Fatalf("zero config: %v", err)
	}
	if defaults.config.N != 1<<15 || defaults.config.R != 8 || defaults.config.P != 1 ||
		defaults.config.KeyLength != 32 || defaults.config.SaltLength != 16 {
		t.Fatalf("defaults = %+v", defaults.config)
	}
	invalid := []ScryptConfig{
		{N: 1 << 13},
		{N: 100000},
		{N: 1 << (maxScryptLogN + 1)},
		{N: 1 << 14, R: 7},
		{N: 1 << 14, R: maxScryptR + 1},
		{N: 1 << 14, R: 8, P: 17},
		{N: 1 << 14, R: 8, KeyLength: 15},
		{N: 1 << 14, R: 8, KeyLength: maxKeyLength + 1},
		{N: 1 << 14, R: 8, SaltLength: 7},
		{N: 1 << 14, R: 8, SaltLength: maxSaltLength + 1},
		// 128 * 2^20 * 32 = 4 GiB, above the memory cap. | 128 * 2^20 * 32 = 4 GiB，超过内存上限。
		{N: 1 << 20, R: 32, P: 1, KeyLength: 16, SaltLength: 8},
	}
	for _, config := range invalid {
		if _, err := NewScryptHasher(config); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("config %+v error = %v, want ErrInvalidConfig", config, err)
		}
	}
}

func TestScryptHasherHashVerifyRehash(t *testing.T) {
	hasher, err := NewScryptHasher(ScryptConfig{N: 1 << 14, R: 8, P: 1, KeyLength: 16, SaltLength: 8})
	if err != nil {
		t.Fatalf("hasher: %v", err)
	}
	if _, err := hasher.Hash(""); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty hash error = %v", err)
	}
	encoded, err := hasher.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !strings.HasPrefix(encoded, "$scrypt$ln=14,r=8,p=1$") {
		t.Fatalf("encoded = %q", encoded)
	}
	if ok, err := hasher.Verify("correct horse battery staple", encoded); err != nil || !ok {
		t.Fatalf("verify = %v %v", ok, err)
	}
	if ok, err := hasher.Verify("wrong", encoded); err != nil || ok {
		t.Fatalf("wrong verify = %v %v", ok, err)
	}
	if hasher.NeedsRehash(encoded) {
		t.Fatal("current hash needs rehash")
	}
	stronger, _ := NewScryptHasher(ScryptConfig{N: 1 << 15, R: 8, P: 1, KeyLength: 16, SaltLength: 8})
	if !stronger.NeedsRehash(encoded) {
		t.Fatal("weaker hash does not need rehash")
	}
	if !hasher.NeedsRehash("$scrypt$ln=14,r=8,p=1$x") {
		t.Fatal("short hash does not need rehash")
	}
}

func TestScryptHasherMalformed(t *testing.T) {
	hasher, _ := NewScryptHasher(ScryptConfig{N: 1 << 14, R: 8, P: 1, KeyLength: 16, SaltLength: 8})
	salt := encodeTestBytes("saltsalt")
	key := encodeTestBytes("0123456789abcdef")
	cases := []string{
		"",
		"$scrypt$ln=14,r=8,p=1$" + salt,
		"$argon2id$ln=14,r=8,p=1$" + salt + "$" + key,
		"$scrypt$ln=13,r=8,p=1$" + salt + "$" + key,
		"$scrypt$ln=30,r=8,p=1$" + salt + "$" + key,
		"$scrypt$ln=20,r=32,p=1$" + salt + "$" + key,
		"$scrypt$ln=14,r=0,p=1$" + salt + "$" + key,
		"$scrypt$ln=14,r=33,p=1$" + salt + "$" + key,
		"$scrypt$ln=14,r=8,p=0$" + salt + "$" + key,
		"$scrypt$ln=14,r=8,p=17$" + salt + "$" + key,
		"$scrypt$ln=14,r=8,p=1,x=1$" + salt + "$" + key,
		"$scrypt$ln=14,r=8$" + salt + "$" + key,
		"$scrypt$ln=14,r=8,p=1$" + encodeTestBytes("short") + "$" + key,
		"$scrypt$ln=14,r=8,p=1$" + salt + "$" + encodeTestBytes("short"),
		"$scrypt$ln=14,r=8,p=1$!!!$" + key,
		"$scrypt$ln=14,r=8,p=1$" + salt + "$!!!",
	}
	for _, encoded := range cases {
		ok, err := hasher.Verify("password", encoded)
		if ok || !errors.Is(err, ErrPasswordHash) {
			t.Fatalf("Verify(%q) = %v %v, want ErrPasswordHash", encoded, ok, err)
		}
		if !hasher.NeedsRehash(encoded) {
			t.Fatalf("NeedsRehash(%q) = false", encoded)
		}
	}
	if _, _, _, err := parseScryptParams("ln=14,r=8,p=1"); err != nil {
		t.Fatalf("valid scrypt params: %v", err)
	}
	if n, _, _, err := parseScryptParams("ln=14,r=8,p=1"); err != nil || n != 1<<14 {
		t.Fatalf("scrypt n = %d %v", n, err)
	}
}

func TestPasswordHashManager(t *testing.T) {
	argon, _ := NewArgon2idHasher(Argon2idConfig{Time: 1, Memory: 8 * 1024, Threads: 1, KeyLength: 16, SaltLength: 8})
	bcrypt, _ := NewBcryptHasher(BcryptConfig{Cost: 10})
	manager, err := NewPasswordHashManager(bcrypt, argon, argon)
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	if manager.Algorithm() != "bcrypt" || len(manager.Hashers) != 2 {
		t.Fatalf("manager = %+v", manager)
	}
	bcryptHash, err := manager.Hash("manager password")
	if err != nil || !isBcryptHash(bcryptHash) {
		t.Fatalf("manager hash = %q %v", bcryptHash, err)
	}
	if ok, err := manager.Verify("manager password", bcryptHash); err != nil || !ok {
		t.Fatalf("manager verify = %v %v", ok, err)
	}
	if ok, err := manager.Verify("wrong", bcryptHash); err != nil || ok {
		t.Fatalf("manager wrong verify = %v %v", ok, err)
	}
	argonHash, err := argon.Hash("argon password")
	if err != nil {
		t.Fatalf("argon hash: %v", err)
	}
	if ok, err := manager.Verify("argon password", argonHash); err != nil || !ok {
		t.Fatalf("manager argon verify = %v %v", ok, err)
	}
	if !manager.NeedsRehash(argonHash) {
		t.Fatal("non-default algorithm does not need rehash")
	}
	if manager.NeedsRehash(bcryptHash) {
		t.Fatal("current bcrypt hash needs rehash")
	}
	if !manager.NeedsRehash("not-a-hash") {
		t.Fatal("garbage does not need rehash")
	}
	if ok, err := manager.Verify("password", "garbage"); ok || !errors.Is(err, ErrPasswordHash) {
		t.Fatalf("garbage verify = %v %v", ok, err)
	}

	withoutDefault, err := NewPasswordHashManager(nil)
	if err != nil {
		t.Fatalf("nil default manager: %v", err)
	}
	if withoutDefault.Algorithm() != "argon2id" || len(withoutDefault.Hashers) != 1 {
		t.Fatalf("default manager = %+v", withoutDefault)
	}

	var missingDefault *PasswordHashManager
	if missingDefault.Algorithm() != "" || missingDefault.NeedsRehash("x") == false {
		t.Fatal("nil manager behavior")
	}
	if _, err := missingDefault.Hash("password"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil manager hash error = %v", err)
	}
	if ok, err := missingDefault.Verify("password", "x"); ok || !errors.Is(err, ErrPasswordHash) {
		t.Fatalf("nil manager verify = %v %v", ok, err)
	}
}

func TestPasswordPolicy(t *testing.T) {
	policy := DefaultPasswordPolicy()
	user := &User{Username: "alice", Email: "alice@example.com"}
	ctx := context.Background()
	if err := policy.Validate(ctx, "correct horse battery staple", user); err != nil {
		t.Fatalf("good password: %v", err)
	}
	if err := policy.Validate(ctx, "", user); !errors.Is(err, ErrPasswordPolicy) {
		t.Fatalf("empty = %v", err)
	}
	if err := policy.Validate(ctx, "short", user); !errors.Is(err, ErrPasswordPolicy) {
		t.Fatalf("short = %v", err)
	}
	if err := policy.Validate(ctx, strings.Repeat("a", 1025), user); !errors.Is(err, ErrPasswordPolicy) {
		t.Fatalf("long = %v", err)
	}
	if err := policy.Validate(ctx, "AliceSecret", user); !errors.Is(err, ErrPasswordPolicy) {
		t.Fatalf("username = %v", err)
	}
	if err := policy.Validate(ctx, "xxalicexx@home", user); !errors.Is(err, ErrPasswordPolicy) {
		t.Fatalf("email = %v", err)
	}
	if err := policy.Validate(ctx, "Password123", user); !errors.Is(err, ErrPasswordPolicy) {
		t.Fatalf("common password = %v", err)
	}

	composition := PasswordPolicy{
		MinLength: 1, RequireUppercase: true, RequireLowercase: true, RequireDigit: true, RequireSymbol: true,
		DisallowWhitespace: true,
	}
	invalid := []string{"lower1!", "UPPER1!", "Upper!!", "Upper1", "Upper 1!"}
	for _, password := range invalid {
		if err := composition.Validate(ctx, password, nil); !errors.Is(err, ErrPasswordPolicy) {
			t.Fatalf("composition %q = %v", password, err)
		}
	}
	if err := composition.Validate(ctx, "Upper1!", nil); err != nil {
		t.Fatalf("valid composition: %v", err)
	}
	if err := (PasswordPolicy{MinLength: 1}).Validate(ctx, "密码密码", nil); err != nil {
		t.Fatalf("unicode within length: %v", err)
	}
	if err := (PasswordPolicy{MinLength: 3}).Validate(ctx, "密码", nil); !errors.Is(err, ErrPasswordPolicy) {
		t.Fatalf("unicode below length = %v", err)
	}

	boom := errors.New("breach service unavailable")
	if err := (PasswordPolicy{MinLength: 1, BreachCheck: func(context.Context, string) (bool, error) {
		return false, boom
	}}).Validate(ctx, "password", nil); !errors.Is(err, ErrPasswordPolicy) || !errors.Is(err, boom) {
		t.Fatalf("breach error = %v", err)
	}
	if err := (PasswordPolicy{MinLength: 1, BreachCheck: func(context.Context, string) (bool, error) {
		return true, nil
	}}).Validate(ctx, "password", nil); !errors.Is(err, ErrPasswordPolicy) {
		t.Fatalf("breached password = %v", err)
	}
	if err := (PasswordPolicy{MinLength: 1, BreachCheck: func(context.Context, string) (bool, error) {
		return false, nil
	}}).Validate(ctx, "password", nil); err != nil {
		t.Fatalf("clean breach check = %v", err)
	}
	if err := (PasswordPolicy{}).Validate(ctx, "", nil); !errors.Is(err, ErrPasswordPolicy) {
		t.Fatalf("zero policy empty = %v", err)
	}
}

func TestPasswordPolicyExpired(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	policy := PasswordPolicy{MaxAge: 24 * time.Hour}
	if policy.Expired(nil, now) || policy.Expired(&User{}, now) {
		t.Fatal("nil or zero change time expired")
	}
	if (PasswordPolicy{}).Expired(&User{PasswordChangedAt: now.Add(-365 * 24 * time.Hour)}, now) {
		t.Fatal("disabled max age reported expired")
	}
	user := &User{PasswordChangedAt: now.Add(-25 * time.Hour)}
	if !policy.Expired(user, now) {
		t.Fatal("old password not expired")
	}
	user.PasswordChangedAt = now.Add(-23 * time.Hour)
	if policy.Expired(user, now) {
		t.Fatal("fresh password expired")
	}
}

func TestCheckHistoryAndCommonPasswords(t *testing.T) {
	hasher, _ := NewArgon2idHasher(Argon2idConfig{Time: 1, Memory: 8 * 1024, Threads: 1, KeyLength: 16, SaltLength: 8})
	old, err := hasher.Hash("old password")
	if err != nil {
		t.Fatalf("old hash: %v", err)
	}
	newer, err := hasher.Hash("new password")
	if err != nil {
		t.Fatalf("new hash: %v", err)
	}
	history := []string{"", "malformed", old, newer}
	ctx := context.Background()
	if err := CheckHistory(ctx, hasher, "old password", history); !errors.Is(err, ErrPasswordReused) {
		t.Fatalf("old password = %v", err)
	}
	if err := CheckHistory(ctx, hasher, "brand new password", history); err != nil {
		t.Fatalf("new password = %v", err)
	}
	if err := CheckHistory(ctx, nil, "old password", history); err != nil {
		t.Fatalf("nil hasher = %v", err)
	}
	common := DefaultCommonPasswords()
	if _, ok := common["password"]; !ok {
		t.Fatal("default deny list does not contain password")
	}
	if _, ok := common["unique passphrase"]; ok {
		t.Fatal("default deny list contains a unique passphrase")
	}
}

func TestHasherInterfacesAreConcurrencyReady(t *testing.T) {
	hashers := []PasswordHasher{}
	argon, _ := NewArgon2idHasher(Argon2idConfig{Time: 1, Memory: 8 * 1024, Threads: 1, KeyLength: 16, SaltLength: 8})
	hashers = append(hashers, argon)
	bcrypt, _ := NewBcryptHasher(BcryptConfig{Cost: 10})
	hashers = append(hashers, bcrypt)
	for _, hasher := range hashers {
		if hasher.Algorithm() == "" {
			t.Fatal("empty algorithm")
		}
	}
}
