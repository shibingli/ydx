package otp

import (
	"encoding/base32"
	"errors"
	"strings"
	"testing"
	"time"
)

// testSecret encodes raw as an unpadded uppercase base32 shared secret. | testSecret 把 raw 编码为无填充大写 base32 共享密钥。
func testSecret(raw string) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(raw))
}

// TestRFC4226Vectors checks the RFC 4226 Appendix D HOTP vectors. | TestRFC4226Vectors 检查 RFC 4226 附录 D 的 HOTP 向量。
func TestRFC4226Vectors(t *testing.T) {
	t.Parallel()
	secret := testSecret("12345678901234567890")
	vectors := []struct {
		counter uint64
		want    string
	}{
		{0, "755224"},
		{1, "287082"},
		{2, "359152"},
		{3, "969429"},
		{4, "338314"},
		{5, "254676"},
		{6, "287922"},
		{7, "162583"},
		{8, "399871"},
		{9, "520489"},
	}
	for _, vector := range vectors {
		got, err := HOTP(secret, vector.counter, Config{})
		if err != nil {
			t.Fatalf("HOTP(counter=%d): %v | HOTP 失败", vector.counter, err)
		}
		if got != vector.want {
			t.Errorf("HOTP(counter=%d) = %q, want %q | HOTP 向量不匹配", vector.counter, got, vector.want)
		}
		matched, ok, err := ValidateHOTP(secret, got, vector.counter, Config{})
		if err != nil {
			t.Fatalf("ValidateHOTP(counter=%d): %v | ValidateHOTP 失败", vector.counter, err)
		}
		if !ok || matched != vector.counter {
			t.Errorf("ValidateHOTP(counter=%d) = (%d, %v), want (%d, true) | 校验结果不匹配",
				vector.counter, matched, ok, vector.counter)
		}
	}
}

// TestRFC6238Vectors checks the RFC 6238 Appendix B TOTP vectors for all supported hashes and
// eight digits. | TestRFC6238Vectors 检查 RFC 6238 附录 B 中所有受支持哈希与八位数字的 TOTP 向量。
func TestRFC6238Vectors(t *testing.T) {
	t.Parallel()
	vectors := []struct {
		name      string
		rawSecret string
		algorithm Algorithm
		unix      int64
		want      string
	}{
		{"sha1-59", "12345678901234567890", SHA1, 59, "94287082"},
		{"sha1-1111111109", "12345678901234567890", SHA1, 1111111109, "07081804"},
		{"sha1-1111111111", "12345678901234567890", SHA1, 1111111111, "14050471"},
		{"sha1-1234567890", "12345678901234567890", SHA1, 1234567890, "89005924"},
		{"sha1-2000000000", "12345678901234567890", SHA1, 2000000000, "69279037"},
		{"sha1-20000000000", "12345678901234567890", SHA1, 20000000000, "65353130"},
		{"sha256-59", "12345678901234567890123456789012", SHA256, 59, "46119246"},
		{"sha256-1111111109", "12345678901234567890123456789012", SHA256, 1111111109, "68084774"},
		{"sha256-1111111111", "12345678901234567890123456789012", SHA256, 1111111111, "67062674"},
		{"sha256-1234567890", "12345678901234567890123456789012", SHA256, 1234567890, "91819424"},
		{"sha256-2000000000", "12345678901234567890123456789012", SHA256, 2000000000, "90698825"},
		{"sha256-20000000000", "12345678901234567890123456789012", SHA256, 20000000000, "77737706"},
		{"sha512-59", "1234567890123456789012345678901234567890123456789012345678901234", SHA512, 59, "90693936"},
		{"sha512-1111111109", "1234567890123456789012345678901234567890123456789012345678901234", SHA512, 1111111109, "25091201"},
		{"sha512-1111111111", "1234567890123456789012345678901234567890123456789012345678901234", SHA512, 1111111111, "99943326"},
		{"sha512-1234567890", "1234567890123456789012345678901234567890123456789012345678901234", SHA512, 1234567890, "93441116"},
		{"sha512-2000000000", "1234567890123456789012345678901234567890123456789012345678901234", SHA512, 2000000000, "38618901"},
		{"sha512-20000000000", "1234567890123456789012345678901234567890123456789012345678901234", SHA512, 20000000000, "47863826"},
	}
	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			t.Parallel()
			secret := testSecret(vector.rawSecret)
			at := time.Unix(vector.unix, 0).UTC()
			cfg := Config{Digits: 8, Algorithm: vector.algorithm}
			got, err := TOTP(secret, at, cfg)
			if err != nil {
				t.Fatalf("TOTP: %v | TOTP 失败", err)
			}
			if got != vector.want {
				t.Errorf("TOTP = %q, want %q | TOTP 向量不匹配", got, vector.want)
			}
			step, ok, err := ValidateTOTP(secret, got, at, cfg)
			if err != nil {
				t.Fatalf("ValidateTOTP: %v | ValidateTOTP 失败", err)
			}
			if !ok {
				t.Fatalf("ValidateTOTP rejected the RFC vector | ValidateTOTP 拒绝了 RFC 向量")
			}
			if want := TimeStep(at, DefaultPeriod); step != want {
				t.Errorf("ValidateTOTP step = %d, want %d | 时间步不匹配", step, want)
			}
		})
	}
}

// TestHOTPSecretNormalization checks that case, whitespace, hyphens and padding are tolerated.
// | TestHOTPSecretNormalization 检查大小写、空白、连字符与填充都被容忍。
func TestHOTPSecretNormalization(t *testing.T) {
	t.Parallel()
	raw := "12345678901234567890"
	canonical := testSecret(raw)
	padded := base32.StdEncoding.EncodeToString([]byte(raw))
	messy := strings.ToLower(canonical[:4] + " " + canonical[4:12] + "-" + canonical[12:])
	want, err := HOTP(canonical, 7, Config{})
	if err != nil {
		t.Fatalf("HOTP canonical: %v | 规范密钥 HOTP 失败", err)
	}
	for name, secret := range map[string]string{
		"padded": padded,
		"messy":  messy,
		"spaces": " " + canonical + "\n",
	} {
		got, err := HOTP(secret, 7, Config{})
		if err != nil {
			t.Errorf("%s secret: %v | %s 密钥失败", name, err, name)
			continue
		}
		if got != want {
			t.Errorf("%s secret code = %q, want %q | %s 密钥口令不匹配", name, got, want, name)
		}
	}
}

// TestInvalidSecrets checks malformed secret handling. | TestInvalidSecrets 检查非法密钥处理。
func TestInvalidSecrets(t *testing.T) {
	t.Parallel()
	long := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(make([]byte, maxSecretBytes+1))
	tests := []struct {
		name   string
		secret string
	}{
		{"empty", ""},
		{"spaces", "   "},
		{"bad alphabet", "!!!!"},
		{"bad length", "A"},
		{"oversized", long},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := HOTP(tt.secret, 0, Config{}); !errors.Is(err, ErrInvalidSecret) {
				t.Errorf("HOTP error = %v, want ErrInvalidSecret | HOTP 错误应为 ErrInvalidSecret", err)
			}
			if _, err := TOTP(tt.secret, time.Now(), Config{}); !errors.Is(err, ErrInvalidSecret) {
				t.Errorf("TOTP error = %v, want ErrInvalidSecret | TOTP 错误应为 ErrInvalidSecret", err)
			}
			if _, _, err := ValidateHOTP(tt.secret, "123456", 0, Config{}); !errors.Is(err, ErrInvalidSecret) {
				t.Errorf("ValidateHOTP error = %v, want ErrInvalidSecret | ValidateHOTP 错误应为 ErrInvalidSecret", err)
			}
		})
	}
}

// TestConfigNormalize checks defaults and range enforcement. | TestConfigNormalize 检查默认值与范围约束。
func TestConfigNormalize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		cfg     Config
		want    Config
		wantErr bool
	}{
		{
			name: "zero value",
			cfg:  Config{},
			want: Config{Digits: 6, Period: 30 * time.Second, Skew: 0, Algorithm: SHA1, SecretSize: 20},
		},
		{
			name: "explicit values",
			cfg:  Config{Digits: 8, Period: 45 * time.Second, Skew: 2, Algorithm: SHA256, SecretSize: 32},
			want: Config{Digits: 8, Period: 45 * time.Second, Skew: 2, Algorithm: SHA256, SecretSize: 32},
		},
		{
			name: "algorithm aliases",
			cfg:  Config{Algorithm: "sha-512"},
			want: Config{Digits: 6, Period: 30 * time.Second, Algorithm: SHA512, SecretSize: 20},
		},
		{name: "digits too small", cfg: Config{Digits: 5}, wantErr: true},
		{name: "digits too large", cfg: Config{Digits: 11}, wantErr: true},
		{name: "negative period", cfg: Config{Period: -time.Second}, wantErr: true},
		{name: "sub-second period", cfg: Config{Period: 500 * time.Millisecond}, wantErr: true},
		{name: "negative skew", cfg: Config{Skew: -1}, wantErr: true},
		{name: "skew too large", cfg: Config{Skew: MaxSkew + 1}, wantErr: true},
		{name: "unknown algorithm", cfg: Config{Algorithm: "MD5"}, wantErr: true},
		{name: "secret too small", cfg: Config{SecretSize: 9}, wantErr: true},
		{name: "secret too large", cfg: Config{SecretSize: 65}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tt.cfg.Normalize()
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidConfig) {
					t.Fatalf("Normalize error = %v, want ErrInvalidConfig | Normalize 错误应为 ErrInvalidConfig", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Normalize: %v | Normalize 失败", err)
			}
			if got != tt.want {
				t.Errorf("Normalize = %+v, want %+v | Normalize 结果不匹配", got, tt.want)
			}
		})
	}
}

// TestGenerateSecret checks size handling and the encoded form. | TestGenerateSecret 检查长度处理与编码形式。
func TestGenerateSecret(t *testing.T) {
	t.Parallel()
	for _, size := range []int{0, MinSecretSize, DefaultSecretSize, MaxSecretSize} {
		secret, err := GenerateSecret(size)
		if err != nil {
			t.Fatalf("GenerateSecret(%d): %v | GenerateSecret 失败", size, err)
		}
		wantSize := size
		if wantSize == 0 {
			wantSize = DefaultSecretSize
		}
		decoded, err := decodeSecret(secret)
		if err != nil {
			t.Fatalf("GenerateSecret(%d) produced an undecodable secret: %v | 生成的密钥无法解码", size, err)
		}
		if len(decoded) != wantSize {
			t.Errorf("GenerateSecret(%d) decoded size = %d, want %d | 密钥长度不匹配", size, len(decoded), wantSize)
		}
		if secret != strings.ToUpper(secret) {
			t.Errorf("GenerateSecret(%d) is not uppercase | 密钥不是大写", size)
		}
		if strings.Contains(secret, "=") {
			t.Errorf("GenerateSecret(%d) contains padding | 密钥包含填充", size)
		}
	}
	for _, size := range []int{-1, MinSecretSize - 1, MaxSecretSize + 1} {
		if _, err := GenerateSecret(size); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("GenerateSecret(%d) error = %v, want ErrInvalidConfig | 错误应为 ErrInvalidConfig", size, err)
		}
	}
	first, err := GenerateSecret(MaxSecretSize)
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateSecret(MaxSecretSize)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Error("two generated secrets are identical | 两次生成的密钥相同")
	}
}

// TestValidateHOTPWindow checks the counter window and malformed codes. | TestValidateHOTPWindow 检查计数器窗口与非法口令。
func TestValidateHOTPWindow(t *testing.T) {
	t.Parallel()
	secret := testSecret("12345678901234567890")
	code, err := HOTP(secret, 5, Config{})
	if err != nil {
		t.Fatalf("HOTP: %v", err)
	}
	tests := []struct {
		name    string
		code    string
		counter uint64
		skew    int
		want    uint64
		ok      bool
	}{
		{"exact", code, 5, 0, 5, true},
		{"previous counter in window", code, 4, 1, 5, true},
		{"next counter in window", code, 6, 1, 5, true},
		{"outside window", code, 7, 1, 0, false},
		{"below window", code, 3, 0, 0, false},
		{"window at zero", code, 0, 1, 0, false},
		{"padded code", " " + code + " ", 5, 0, 5, true},
		{"too short", code[:5], 5, 3, 0, false},
		{"letters", "abcdef", 5, 3, 0, false},
		{"unicode digits", "１２３４５６", 5, 3, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			matched, ok, err := ValidateHOTP(secret, tt.code, tt.counter, Config{Skew: tt.skew})
			if err != nil {
				t.Fatalf("ValidateHOTP: %v | ValidateHOTP 失败", err)
			}
			if ok != tt.ok || matched != tt.want {
				t.Errorf("ValidateHOTP = (%d, %v), want (%d, %v) | 校验结果不匹配", matched, ok, tt.want, tt.ok)
			}
		})
	}
	if _, _, err := ValidateHOTP(secret, code, 5, Config{Skew: MaxSkew + 1}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("invalid skew error = %v, want ErrInvalidConfig | 非法容差错误应为 ErrInvalidConfig", err)
	}
}

// TestValidateHOTPOverflow checks the top of the uint64 counter range. | TestValidateHOTPOverflow 检查 uint64 计数器上界。
func TestValidateHOTPOverflow(t *testing.T) {
	t.Parallel()
	secret := testSecret("12345678901234567890")
	code, err := HOTP(secret, ^uint64(0), Config{})
	if err != nil {
		t.Fatalf("HOTP: %v", err)
	}
	matched, ok, err := ValidateHOTP(secret, code, ^uint64(0), Config{Skew: 1})
	if err != nil {
		t.Fatalf("ValidateHOTP: %v", err)
	}
	if !ok || matched != ^uint64(0) {
		t.Errorf("ValidateHOTP at max counter = (%d, %v), want (max, true) | 最大计数器校验失败", matched, ok)
	}
}

// TestValidateTOTPWindow checks the time-step window. | TestValidateTOTPWindow 检查时间步窗口。
func TestValidateTOTPWindow(t *testing.T) {
	t.Parallel()
	secret := testSecret("12345678901234567890")
	cfg := Config{}
	at := time.Unix(1111111111, 0).UTC()
	code, err := TOTP(secret, at, cfg)
	if err != nil {
		t.Fatalf("TOTP: %v", err)
	}
	step := TimeStep(at, DefaultPeriod)
	tests := []struct {
		name   string
		at     time.Time
		skew   int
		want   int64
		ok     bool
		codeIn string
	}{
		{"same step", at.Add(28 * time.Second), 0, step, true, code},
		{"next step exact", at.Add(30 * time.Second), 0, 0, false, code},
		{"next step skew", at.Add(30 * time.Second), 1, step + 1, true, ""},
		{"previous step skew", at.Add(-30 * time.Second), 1, step - 1, true, ""},
		{"two steps away", at.Add(60 * time.Second), 1, 0, false, code},
		{"malformed", at, 0, 0, false, "abcdef"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			code := tt.codeIn
			if code == "" {
				var err error
				code, err = TOTP(secret, tt.at, cfg)
				if err != nil {
					t.Fatalf("TOTP: %v", err)
				}
			}
			matched, ok, err := ValidateTOTP(secret, code, tt.at, Config{Skew: tt.skew})
			if err != nil {
				t.Fatalf("ValidateTOTP: %v | ValidateTOTP 失败", err)
			}
			if ok != tt.ok {
				t.Fatalf("ValidateTOTP ok = %v, want %v | 校验结果不匹配", ok, tt.ok)
			}
			if ok && matched != tt.want {
				t.Errorf("ValidateTOTP step = %d, want %d | 时间步不匹配", matched, tt.want)
			}
		})
	}
}

// TestTimeStep checks floor division for positive and negative instants. | TestTimeStep 检查正负时刻的地板除法。
func TestTimeStep(t *testing.T) {
	t.Parallel()
	tests := []struct {
		unix   int64
		period time.Duration
		want   int64
	}{
		{0, 30 * time.Second, 0},
		{29, 30 * time.Second, 0},
		{30, 30 * time.Second, 1},
		{59, 30 * time.Second, 1},
		{-1, 30 * time.Second, -1},
		{-30, 30 * time.Second, -1},
		{-31, 30 * time.Second, -2},
		{100, 0, 3},
		{100, -time.Second, 3},
		// Beyond the UnixNano range (year 2603); regression for the 128-bit division path.
		// | 超出 UnixNano 范围（公元 2603 年）；覆盖 128 位除法路径的回归用例。
		{20000000000, 30 * time.Second, 666666666},
		{20000000000, time.Second, 20000000000},
		{-20000000000, 30 * time.Second, -666666667},
		// Fractional-second periods must still use floor division. | 小数秒时间步仍必须使用地板除法。
		{1, 1500 * time.Millisecond, 0},
		{2, 1500 * time.Millisecond, 1},
		{-2, 1500 * time.Millisecond, -2},
	}
	for _, tt := range tests {
		if got := TimeStep(time.Unix(tt.unix, 0), tt.period); got != tt.want {
			t.Errorf("TimeStep(%d, %s) = %d, want %d | 时间步不匹配", tt.unix, tt.period, got, tt.want)
		}
	}
}

// TestAlgorithmString checks canonical names. | TestAlgorithmString 检查规范名称。
func TestAlgorithmString(t *testing.T) {
	t.Parallel()
	tests := map[Algorithm]string{
		SHA1:                "SHA1",
		"sha-256":           "SHA256",
		Algorithm(""):       "SHA1",
		Algorithm("MD5"):    "MD5",
		Algorithm("sha512"): "SHA512",
	}
	for algorithm, want := range tests {
		if got := algorithm.String(); got != want {
			t.Errorf("Algorithm(%q).String() = %q, want %q | 算法名称不匹配", algorithm, got, want)
		}
	}
}
