package otp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"hash"
	"math/bits"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// The package defaults and accepted ranges. | 包默认值与可接受范围。
const (
	// DefaultDigits is the RFC 4226 default code length. | DefaultDigits 是 RFC 4226 的默认口令长度。
	DefaultDigits = 6
	// MinDigits and MaxDigits bound Config.Digits. RFC 4226 defines six to ten digits. | MinDigits 与 MaxDigits 限定 Config.Digits；RFC 4226 定义六到十位。
	MinDigits = 6
	MaxDigits = 10
	// DefaultPeriod is the RFC 6238 default time step. | DefaultPeriod 是 RFC 6238 的默认时间步。
	DefaultPeriod = 30 * time.Second
	// DefaultSkew is the recommended validation tolerance in steps or counters. It is not applied
	// automatically: a zero Config.Skew means exact matching, which is the safest default.
	// | DefaultSkew 是建议的校验容差（步或计数器）。它不会被自动应用：Config.Skew 为零表示精确
	// 匹配，这是最安全的默认值。
	DefaultSkew = 1
	// MaxSkew bounds Config.Skew so a malformed configuration cannot trigger an unbounded scan.
	// | MaxSkew 限定 Config.Skew，避免错误配置触发无界扫描。
	MaxSkew = 10
	// DefaultSecretSize is the RFC 4226 recommended 160-bit shared secret. | DefaultSecretSize 是 RFC 4226 推荐的 160 位共享密钥。
	DefaultSecretSize = 20
	// MinSecretSize and MaxSecretSize bound GenerateSecret and Config.SecretSize. | MinSecretSize 与 MaxSecretSize 限定 GenerateSecret 与 Config.SecretSize。
	MinSecretSize = 10
	MaxSecretSize = 64
	// DefaultAlgorithm is the RFC 4226 HMAC algorithm. | DefaultAlgorithm 是 RFC 4226 使用的 HMAC 算法。
	DefaultAlgorithm = SHA1
)

// maxSecretBytes bounds the decoded secret accepted by validation to keep hostile input from
// consuming unbounded memory. | maxSecretBytes 限定校验接受的解码后密钥大小，防止恶意输入占用无界内存。
const maxSecretBytes = 1024

// The declared sentinels of this package. | 本包的哨兵错误声明。
//
// Every failure path returns one of them directly or through errs.Detail / errs.Wrap, so callers
// can classify errors with errors.Is instead of matching message text. | 所有失败路径都直接返回
// 其中之一，或经由 errs.Detail / errs.Wrap 包装，因此调用方可用 errors.Is 分类错误而无需匹配文案。
var (
	// ErrInvalidConfig reports a missing, out-of-range or contradictory configuration. | ErrInvalidConfig 表示配置缺失、越界或互相矛盾。
	ErrInvalidConfig = errs.New("otp: invalid configuration | otp：配置非法")
	// ErrInvalidSecret reports an empty, malformed or oversized shared secret. | ErrInvalidSecret 表示共享密钥为空、格式非法或过大。
	ErrInvalidSecret = errs.New("otp: invalid secret | otp：密钥无效")
	// ErrInvalidRequest reports malformed caller input such as an empty replay key. | ErrInvalidRequest 表示调用方输入非法，例如重放保护键为空。
	ErrInvalidRequest = errs.New("otp: invalid request | otp：请求非法")
	// ErrInvalidURI reports a malformed or unsupported otpauth:// URI. | ErrInvalidURI 表示 otpauth:// URI 格式非法或不受支持。
	ErrInvalidURI = errs.New("otp: invalid otpauth URI | otp：otpauth URI 无效")
	// ErrReplay reports a valid one-time code that was already consumed. | ErrReplay 表示一次性口令有效但已被消费。
	ErrReplay = errs.New("otp: one-time code replayed | otp：一次性口令被重放")
	// ErrReplayStore reports a ReplayGuard backend failure. | ErrReplayStore 表示 ReplayGuard 后端故障。
	ErrReplayStore = errs.New("otp: replay guard unavailable | otp：重放保护不可用")
	// ErrRandomSource reports a failure of the operating system random source. | ErrRandomSource 表示操作系统随机源故障。
	ErrRandomSource = errs.New("otp: random source failure | otp：随机源故障")
)

// Algorithm names a hash function used with HMAC by HOTP and TOTP. | Algorithm 命名 HOTP 与 TOTP 通过 HMAC 使用的哈希算法。
type Algorithm string

// The supported HMAC algorithms. | 受支持的 HMAC 算法。
const (
	// SHA1 is HMAC-SHA-1, the RFC 4226 default. | SHA1 是 HMAC-SHA-1，RFC 4226 的默认值。
	SHA1 Algorithm = "SHA1"
	// SHA256 is HMAC-SHA-256. | SHA256 是 HMAC-SHA-256。
	SHA256 Algorithm = "SHA256"
	// SHA512 is HMAC-SHA-512. | SHA512 是 HMAC-SHA-512。
	SHA512 Algorithm = "SHA512"
)

// String returns the canonical uppercase algorithm name. Unknown values are returned uppercased
// without validation. | String 返回规范的算法大写名称。未知值仅转为大写，不做校验。
func (a Algorithm) String() string {
	return string(a.canonical())
}

// canonical normalizes case and tolerated separators ("SHA-1" == "sha1"). An empty value maps to
// the default algorithm. | canonical 规范化大小写与可容忍的分隔符（"SHA-1" == "sha1"）。空值映射
// 为默认算法。
func (a Algorithm) canonical() Algorithm {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(string(a)), "-", ""))
	switch normalized {
	case "", "SHA1":
		return SHA1
	case "SHA256":
		return SHA256
	case "SHA512":
		return SHA512
	}
	return Algorithm(normalized)
}

// valid reports whether a is one of the supported algorithms. | valid 报告 a 是否为受支持的算法之一。
func (a Algorithm) valid() bool {
	switch a {
	case SHA1, SHA256, SHA512:
		return true
	}
	return false
}

// hash returns the hash constructor for a, or nil when a is unsupported. | hash 返回 a 的哈希构造器；a 不受支持时返回 nil。
func (a Algorithm) hash() func() hash.Hash {
	switch a.canonical() {
	case SHA1:
		return sha1.New
	case SHA256:
		return sha256.New
	case SHA512:
		return sha512.New
	}
	return nil
}

// Config controls secret generation, code generation, validation and enrollment URIs. | Config 控制密钥生成、口令生成、校验与登记 URI。
type Config struct {
	// Algorithm is the HMAC hash; zero selects DefaultAlgorithm. | Algorithm 是 HMAC 哈希；零值使用 DefaultAlgorithm。
	Algorithm Algorithm
	// Issuer is the optional service name used by GenerateURI. | Issuer 是 GenerateURI 使用的可选服务名。
	Issuer string
	// AccountName is the optional account label used by GenerateURI. | AccountName 是 GenerateURI 使用的可选账号标签。
	AccountName string
	// Digits is the code length, from MinDigits to MaxDigits; zero selects DefaultDigits.
	// | Digits 是口令长度，取值 MinDigits 到 MaxDigits；零值使用 DefaultDigits。
	Digits int
	// Period is the TOTP time step; zero selects DefaultPeriod and values below one second are
	// rejected. | Period 是 TOTP 时间步；零值使用 DefaultPeriod，小于一秒的值会被拒绝。
	Period time.Duration
	// Skew is the number of adjacent counters or time steps accepted on each side during
	// validation. Zero means exact matching. | Skew 是校验时两侧接受的相邻计数器或时间步数量。
	// 零值表示精确匹配。
	Skew int
	// SecretSize is the GenerateSecret size in bytes when callers pass zero; zero selects
	// DefaultSecretSize. | SecretSize 是调用方传入零时 GenerateSecret 使用的字节数；零值使用
	// DefaultSecretSize。
	SecretSize int
}

// Normalize returns a copy of c with zero values replaced by package defaults and every field
// validated. It never mutates the receiver. | Normalize 返回 c 的副本，把零值替换为包默认值并校验
// 所有字段。它从不修改接收者。
func (c Config) Normalize() (Config, error) {
	out := c
	if out.Digits == 0 {
		out.Digits = DefaultDigits
	}
	if out.Digits < MinDigits || out.Digits > MaxDigits {
		return Config{}, errs.Detail(ErrInvalidConfig,
			"digits %d outside [%d,%d] | 位数 %d 超出 [%d,%d]",
			out.Digits, MinDigits, MaxDigits, out.Digits, MinDigits, MaxDigits)
	}
	if out.Period == 0 {
		out.Period = DefaultPeriod
	}
	if out.Period < time.Second {
		return Config{}, errs.Detail(ErrInvalidConfig,
			"period %s is shorter than one second | 时间步 %s 小于一秒", out.Period, out.Period)
	}
	if out.Skew < 0 || out.Skew > MaxSkew {
		return Config{}, errs.Detail(ErrInvalidConfig,
			"skew %d outside [0,%d] | 容差 %d 超出 [0,%d]", out.Skew, MaxSkew, out.Skew, MaxSkew)
	}
	out.Algorithm = out.Algorithm.canonical()
	if !out.Algorithm.valid() {
		return Config{}, errs.Detail(ErrInvalidConfig,
			"unsupported algorithm %q | 不支持的算法 %q", string(out.Algorithm), string(out.Algorithm))
	}
	if out.SecretSize == 0 {
		out.SecretSize = DefaultSecretSize
	}
	if out.SecretSize < MinSecretSize || out.SecretSize > MaxSecretSize {
		return Config{}, errs.Detail(ErrInvalidConfig,
			"secret size %d outside [%d,%d] | 密钥长度 %d 超出 [%d,%d]",
			out.SecretSize, MinSecretSize, MaxSecretSize, out.SecretSize, MinSecretSize, MaxSecretSize)
	}
	return out, nil
}

// lenient returns c with invalid optional values replaced by defaults instead of errors. It is
// used by GenerateURI, whose signature has no error channel. | lenient 返回 c 的副本，把非法的可选值
// 替换为默认值而不报错。它供没有错误通道的 GenerateURI 使用。
func (c Config) lenient() Config {
	out := c
	if out.Digits < MinDigits || out.Digits > MaxDigits {
		out.Digits = DefaultDigits
	}
	if out.Period < time.Second {
		out.Period = DefaultPeriod
	}
	if canon := out.Algorithm.canonical(); canon.valid() {
		out.Algorithm = canon
	} else {
		out.Algorithm = DefaultAlgorithm
	}
	if out.Skew < 0 || out.Skew > MaxSkew {
		out.Skew = 0
	}
	if out.SecretSize < MinSecretSize || out.SecretSize > MaxSecretSize {
		out.SecretSize = DefaultSecretSize
	}
	return out
}

// GenerateSecret returns a cryptographically random shared secret encoded as RFC 4648 base32
// without padding, in uppercase. A size of zero selects DefaultSecretSize. | GenerateSecret 返回
// 以 RFC 4648 无填充大写 base32 编码的密码学随机共享密钥。size 为零时使用 DefaultSecretSize。
func GenerateSecret(size int) (string, error) {
	if size == 0 {
		size = DefaultSecretSize
	}
	if size < MinSecretSize || size > MaxSecretSize {
		return "", errs.Detail(ErrInvalidConfig,
			"secret size %d outside [%d,%d] | 密钥长度 %d 超出 [%d,%d]",
			size, MinSecretSize, MaxSecretSize, size, MinSecretSize, MaxSecretSize)
	}
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", errs.Wrap(err, ErrRandomSource)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

// HOTP returns the RFC 4226 code for counter under secret and cfg. | HOTP 返回 secret 在 counter 与 cfg 下的 RFC 4226 口令。
func HOTP(secret string, counter uint64, cfg Config) (string, error) {
	c, err := cfg.Normalize()
	if err != nil {
		return "", err
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	return hotpCode(key, counter, c.Digits, c.Algorithm), nil
}

// ValidateHOTP reports whether code matches secret anywhere in the counter window
// [counter-Skew, counter+Skew] and returns the matched counter. A code that is not exactly
// Digits ASCII digits is a non-match and yields (0, false, nil); errors are reserved for invalid
// configuration or secrets. | ValidateHOTP 报告 code 是否匹配 secret 在计数器窗口
// [counter-Skew, counter+Skew] 内的任意值，并返回命中的计数器。不是恰好 Digits 位 ASCII 数字的
// 口令视为不匹配并返回 (0, false, nil)；错误仅用于非法配置或密钥。
func ValidateHOTP(secret, code string, counter uint64, cfg Config) (uint64, bool, error) {
	c, err := cfg.Normalize()
	if err != nil {
		return 0, false, err
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return 0, false, err
	}
	want, ok := parseCodeValue(code, c.Digits)
	if !ok {
		return 0, false, nil
	}
	skew := uint64(c.Skew)
	start := uint64(0)
	if skew <= counter {
		start = counter - skew
	}
	end := counter + skew
	if end < counter {
		end = ^uint64(0)
	}
	matched, ok := validateHOTPWindow(key, want, counter, start, end, c.Digits, c.Algorithm)
	if !ok {
		return 0, false, nil
	}
	return matched, true, nil
}

// TOTP returns the RFC 6238 code for the time step containing at. | TOTP 返回 at 所在时间步的 RFC 6238 口令。
func TOTP(secret string, at time.Time, cfg Config) (string, error) {
	c, err := cfg.Normalize()
	if err != nil {
		return "", err
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	return hotpCode(key, uint64(TimeStep(at, c.Period)), c.Digits, c.Algorithm), nil
}

// ValidateTOTP reports whether code matches secret anywhere in the time-step window
// [step-Skew, step+Skew] and returns the matched step. The step is the count of Period-long
// intervals since the Unix epoch. A malformed code is a non-match and yields (0, false, nil);
// errors are reserved for invalid configuration or secrets. | ValidateTOTP 报告 code 是否匹配
// secret 在时间步窗口 [step-Skew, step+Skew] 内的任意值，并返回命中的时间步。时间步是自 Unix
// 纪元起以 Period 为长度的时间区间序号。格式非法的口令视为不匹配并返回 (0, false, nil)；错误仅用于
// 非法配置或密钥。
func ValidateTOTP(secret, code string, at time.Time, cfg Config) (int64, bool, error) {
	c, err := cfg.Normalize()
	if err != nil {
		return 0, false, err
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return 0, false, err
	}
	want, ok := parseCodeValue(code, c.Digits)
	if !ok {
		return 0, false, nil
	}
	step := TimeStep(at, c.Period)
	if step < 0 {
		step = 0
	}
	skew := int64(c.Skew)
	start := step - skew
	if start < 0 {
		start = 0
	}
	end := step + skew
	if end < step {
		end = maxInt64
	}
	matched, ok := validateTOTPWindow(key, want, step, start, end, c.Digits, c.Algorithm)
	if !ok {
		return 0, false, nil
	}
	return matched, true, nil
}

// validateTOTPWindow scans the inclusive time-step window and returns the matched step. The exact
// step is checked first so the common case performs a single HMAC, then the window is expanded
// outward. | validateTOTPWindow 扫描闭区间时间步窗口并返回命中的步。先检查精确步，使常见情形只需
// 一次 HMAC，然后向外扩展窗口。
func validateTOTPWindow(key []byte, want uint64, center, start, end int64, digits int, algorithm Algorithm) (int64, bool) {
	mac := hmac.New(algorithm.hash(), key)
	modulus := pow10(digits)
	var sum [sha512.Size]byte
	buffer := sum[:0]
	if got := hotpValue(mac, buffer, uint64(center), modulus); constantTimeEqualUint64(got, want) {
		return center, true
	}
	lower, upper := center-start, end-center
	for offset := int64(1); offset <= lower || offset <= upper; offset++ {
		if offset <= lower {
			mac.Reset()
			if got := hotpValue(mac, buffer, uint64(center-offset), modulus); constantTimeEqualUint64(got, want) {
				return center - offset, true
			}
		}
		if offset <= upper {
			mac.Reset()
			if got := hotpValue(mac, buffer, uint64(center+offset), modulus); constantTimeEqualUint64(got, want) {
				return center + offset, true
			}
		}
	}
	return 0, false
}

// TimeStep returns the TOTP time-step index containing at for the given period. A period below
// one second selects DefaultPeriod. The result is the floor of the elapsed nanoseconds divided by
// the period, computed with 128-bit arithmetic so instants outside the UnixNano range still map
// correctly. | TimeStep 返回 at 在给定 period 下所属的 TOTP 时间步序号。period 小于一秒时使用
// DefaultPeriod。结果是已过纳秒数除以时间步的地板值，使用 128 位运算计算，因此超出 UnixNano
// 范围的时刻也能正确映射。
func TimeStep(at time.Time, period time.Duration) int64 {
	if period < time.Second {
		period = DefaultPeriod
	}
	p := uint64(period)
	seconds := at.Unix()
	nanos := uint64(at.Nanosecond())
	if seconds >= 0 {
		high, low := bits.Mul64(uint64(seconds), uint64(time.Second))
		var carry uint64
		low, carry = bits.Add64(low, nanos, 0)
		high += carry
		quotient, _ := bits.Div64(high, low, p)
		return int64(quotient)
	}
	// Negative instants: floor division rounds away from zero, so divide the positive magnitude
	// and round the quotient up. | 负时刻：地板除法向远离零的方向取整，因此对正的幅度做除法并向上取整。
	magnitude := uint64(-(seconds + 1)) + 1
	high, low := bits.Mul64(magnitude, uint64(time.Second))
	var borrow uint64
	low, borrow = bits.Sub64(low, nanos, 0)
	high -= borrow
	quotient, remainder := bits.Div64(high, low, p)
	if remainder != 0 {
		quotient++
	}
	return -int64(quotient)
}

// maxInt64 is math.MaxInt64 without importing math. | maxInt64 是不引入 math 的 math.MaxInt64。
const maxInt64 = int64(^uint64(0) >> 1)

// hotpCode computes one code with RFC 4226 dynamic truncation. key must be non-empty and digits
// must already be validated by Config.Normalize. | hotpCode 使用 RFC 4226 动态截断计算一个口令。
// key 必须非空，digits 必须已经过 Config.Normalize 校验。
func hotpCode(key []byte, counter uint64, digits int, algorithm Algorithm) string {
	mac := hmac.New(algorithm.hash(), key)
	var sum [sha512.Size]byte
	return formatCode(hotpValue(mac, sum[:0], counter, pow10(digits)), digits)
}

// formatCode renders value as exactly digits zero-padded ASCII digits. | formatCode 把 value 渲染
// 为恰好 digits 位、左侧补零的 ASCII 数字。
func formatCode(value uint64, digits int) string {
	var buffer [MaxDigits]byte
	for index := digits - 1; index >= 0; index-- {
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[:digits])
}

// pow10 returns 10^digits for a validated digit count. | pow10 返回已校验位数对应的 10 的幂。
func pow10(digits int) uint64 {
	modulus := uint64(1)
	for index := 0; index < digits; index++ {
		modulus *= 10
	}
	return modulus
}

// hotpValue returns the numeric RFC 4226 code for counter, reusing mac and the digest buffer. The
// caller must pass a freshly created mac for the first value and reset it before each subsequent
// value. | hotpValue 返回 counter 的 RFC 4226 数值口令，并复用 mac 与摘要缓冲区。调用方首次
// 计算必须传入新建的 mac，之后每次计算前必须重置 mac。
func hotpValue(mac hash.Hash, buffer []byte, counter, modulus uint64) uint64 {
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	_, _ = mac.Write(message[:])
	sum := mac.Sum(buffer[:0])
	offset := sum[len(sum)-1] & 0x0f
	value := (uint64(sum[offset])&0x7f)<<24 |
		uint64(sum[offset+1])<<16 |
		uint64(sum[offset+2])<<8 |
		uint64(sum[offset+3])
	return value % modulus
}

// validateHOTPWindow scans the inclusive counter window and returns the matched counter. The
// supplied counter is checked first so the common case performs a single HMAC, then the window is
// expanded outward. | validateHOTPWindow 扫描闭区间计数器窗口并返回命中的计数器。先检查给定的
// 计数器，使常见情形只需一次 HMAC，然后向外扩展窗口。
func validateHOTPWindow(key []byte, want, center, start, end uint64, digits int, algorithm Algorithm) (uint64, bool) {
	mac := hmac.New(algorithm.hash(), key)
	modulus := pow10(digits)
	var sum [sha512.Size]byte
	buffer := sum[:0]
	if got := hotpValue(mac, buffer, center, modulus); constantTimeEqualUint64(got, want) {
		return center, true
	}
	lower, upper := center-start, end-center
	for offset := uint64(1); offset <= lower || offset <= upper; offset++ {
		if offset <= lower {
			mac.Reset()
			if got := hotpValue(mac, buffer, center-offset, modulus); constantTimeEqualUint64(got, want) {
				return center - offset, true
			}
		}
		if offset <= upper {
			mac.Reset()
			if got := hotpValue(mac, buffer, center+offset, modulus); constantTimeEqualUint64(got, want) {
				return center + offset, true
			}
		}
	}
	return 0, false
}

// dynamicTruncate returns the RFC 4226 31-bit dynamic-truncation value for counter. | dynamicTruncate
// 返回 counter 的 RFC 4226 31 位动态截断值。
func dynamicTruncate(key []byte, counter uint64, algorithm Algorithm) uint64 {
	mac := hmac.New(algorithm.hash(), key)
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	_, _ = mac.Write(message[:])
	var sumBuffer [sha512.Size]byte
	sum := mac.Sum(sumBuffer[:0])
	offset := sum[len(sum)-1] & 0x0f
	return (uint64(sum[offset])&0x7f)<<24 |
		uint64(sum[offset+1])<<16 |
		uint64(sum[offset+2])<<8 |
		uint64(sum[offset+3])
}

// parseCodeValue returns the numeric value of a trimmed code when it is exactly digits ASCII
// digits. | parseCodeValue 在去除首尾空白后的代码恰好为 digits 位 ASCII 数字时返回其数值。
func parseCodeValue(code string, digits int) (uint64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != digits {
		return 0, false
	}
	var value uint64
	for index := 0; index < len(code); index++ {
		digit := code[index]
		if digit < '0' || digit > '9' {
			return 0, false
		}
		value = value*10 + uint64(digit-'0')
	}
	return value, true
}

// canonicalSecret uppercases a secret, removes spaces, tabs, newlines and hyphens, and strips
// trailing base32 padding. An already canonical secret is returned unchanged without allocating. |
// canonicalSecret 把密钥转为大写，去掉空格、制表符、换行与连字符，并剥离末尾的 base32 填充。
// 已规范的密钥原样返回，不产生分配。
func canonicalSecret(secret string) string {
	canonical := secret != ""
	for index := 0; index < len(secret); index++ {
		value := secret[index]
		if (value >= 'A' && value <= 'Z') || (value >= '2' && value <= '7') {
			continue
		}
		canonical = false
		break
	}
	if canonical {
		return secret
	}
	var builder strings.Builder
	builder.Grow(len(secret))
	for _, r := range strings.ToUpper(strings.TrimSpace(secret)) {
		switch r {
		case ' ', '\t', '\r', '\n', '-':
			continue
		}
		builder.WriteRune(r)
	}
	return strings.TrimRight(builder.String(), "=")
}

// decodeSecret decodes a base32 shared secret, tolerating case, whitespace, hyphens and padding.
// | decodeSecret 解码 base32 共享密钥，容忍大小写、空白、连字符与填充。
func decodeSecret(secret string) ([]byte, error) {
	cleaned := canonicalSecret(secret)
	if cleaned == "" {
		return nil, errs.Detail(ErrInvalidSecret, "secret is empty | 密钥为空")
	}
	if len(cleaned) > (maxSecretBytes*8+4)/5+16 {
		return nil, errs.Detail(ErrInvalidSecret,
			"secret exceeds %d decoded bytes | 密钥超过 %d 字节的解码上限", maxSecretBytes, maxSecretBytes)
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(cleaned)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidSecret, "base32 decoding failed | base32 解码失败")
	}
	if len(key) == 0 {
		return nil, errs.Detail(ErrInvalidSecret, "secret is empty | 密钥为空")
	}
	if len(key) > maxSecretBytes {
		return nil, errs.Detail(ErrInvalidSecret,
			"decoded secret exceeds %d bytes | 解码后密钥超过 %d 字节", maxSecretBytes, maxSecretBytes)
	}
	return key, nil
}

// constantTimeEqualUint64 compares two uint64 values without data-dependent branches. |
// constantTimeEqualUint64 以无数据相关分支的方式比较两个 uint64。
func constantTimeEqualUint64(a, b uint64) bool {
	high := subtle.ConstantTimeEq(int32(a>>32), int32(b>>32))
	low := subtle.ConstantTimeEq(int32(a), int32(b))
	return high&low == 1
}

// constantTimeEqual compares two short strings without data-dependent early exit. | constantTimeEqual 在无数据相关提前退出情况下比较两个短字符串。
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
