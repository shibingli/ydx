package auth

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"hash"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

// ErrPasswordHash reports an unparsable or unsupported password hash. | ErrPasswordHash 表示无法解析或不支持的口令哈希。
var ErrPasswordHash = errs.New("auth: invalid password hash | auth：口令哈希非法")

// Upper bounds for parameters read from stored hashes. A hash string comes from a database and may
// be attacker-controlled after a compromise, so verifying it must not be able to request unbounded
// CPU or memory. | 从存储哈希读取的参数上限。哈希字符串来自数据库，库被攻破后可能由攻击者控制，
// 因此校验它不得请求无上限的 CPU 或内存。
const (
	maxPBKDF2Iterations = 10_000_000
	maxArgon2Memory     = 256 << 10 // 256 MiB in KiB | 256 MiB，单位 KiB
	maxArgon2Time       = 64
	maxArgon2Threads    = 32
	maxScryptLogN       = 20
	maxScryptR          = 32
	maxScryptP          = 16
	maxScryptMemory     = 256 << 20 // 256 MiB | 256 MiB
	maxSaltLength       = 64
	maxKeyLength        = 128
)

// PasswordHasher encodes and verifies passwords. | PasswordHasher 编码与校验口令。
//
// Implementations must be safe for concurrent use and must never return the plaintext password in an
// error. | 实现必须可并发安全使用，且错误中绝不能返回明文口令。
type PasswordHasher interface {
	// Hash returns an encoded hash of password. | Hash 返回 password 的编码哈希。
	Hash(password string) (string, error)
	// Verify reports whether password matches encoded. | Verify 报告 password 是否匹配 encoded。
	Verify(password, encoded string) (bool, error)
	// NeedsRehash reports whether encoded uses outdated parameters. | NeedsRehash 报告 encoded 是否使用过时参数。
	NeedsRehash(encoded string) bool
	// Algorithm returns the PHC identifier this hasher writes. | Algorithm 返回该哈希器写入的 PHC 标识。
	Algorithm() string
}

// PBKDF2Config configures PBKDF2-HMAC password hashing. | PBKDF2Config 配置 PBKDF2-HMAC 口令哈希。
type PBKDF2Config struct {
	// Iterations is the PBKDF2 work factor; values below 100000 are refused. | Iterations 是 PBKDF2 工作因子；低于 100000 会被拒绝。
	Iterations int
	// SaltLength is the random salt size in bytes; defaults to 16. | SaltLength 是随机盐字节数；默认 16。
	SaltLength int
	// KeyLength is the derived key size in bytes; defaults to 32. | KeyLength 是派生密钥字节数；默认 32。
	KeyLength int
	// Hash selects SHA-256 (default) or SHA-512. | Hash 选择 SHA-256（默认）或 SHA-512。
	Hash string
}

// PBKDF2Hasher implements PasswordHasher with PBKDF2-HMAC. | PBKDF2Hasher 用 PBKDF2-HMAC 实现 PasswordHasher。
type PBKDF2Hasher struct {
	config PBKDF2Config
}

// DefaultPBKDF2Config returns the current recommended PBKDF2 parameters. | DefaultPBKDF2Config 返回当前推荐的 PBKDF2 参数。
func DefaultPBKDF2Config() PBKDF2Config {
	return PBKDF2Config{Iterations: 600000, SaltLength: 16, KeyLength: 32, Hash: "sha256"}
}

// NewPBKDF2Hasher returns a PBKDF2 hasher, applying defaults for zero fields. | NewPBKDF2Hasher 返回 PBKDF2 哈希器，为零值字段应用默认值。
func NewPBKDF2Hasher(config PBKDF2Config) (*PBKDF2Hasher, error) {
	if config.Iterations == 0 {
		config.Iterations = DefaultPBKDF2Config().Iterations
	}
	if config.SaltLength == 0 {
		config.SaltLength = 16
	}
	if config.KeyLength == 0 {
		config.KeyLength = 32
	}
	if config.Hash == "" {
		config.Hash = "sha256"
	}
	config.Hash = strings.ToLower(config.Hash)
	if config.Iterations < 100000 || config.Iterations > maxPBKDF2Iterations {
		return nil, errs.Detail(ErrInvalidConfig, "PBKDF2 iterations %[1]d outside 100000..%[2]d | PBKDF2 迭代次数 %[1]d 超出 100000..%[2]d", config.Iterations, maxPBKDF2Iterations)
	}
	if config.SaltLength < 8 || config.SaltLength > maxSaltLength {
		return nil, errs.Detail(ErrInvalidConfig, "PBKDF2 salt length %[1]d | PBKDF2 盐长度 %[1]d", config.SaltLength)
	}
	if config.KeyLength < 16 || config.KeyLength > maxKeyLength {
		return nil, errs.Detail(ErrInvalidConfig, "PBKDF2 key length %[1]d | PBKDF2 密钥长度 %[1]d", config.KeyLength)
	}
	if config.Hash != "sha256" && config.Hash != "sha512" {
		return nil, errs.Detail(ErrInvalidConfig, "PBKDF2 hash %[1]q | PBKDF2 哈希 %[1]q", config.Hash)
	}
	return &PBKDF2Hasher{config: config}, nil
}

// Algorithm returns "pbkdf2-sha256" or "pbkdf2-sha512". | Algorithm 返回 "pbkdf2-sha256" 或 "pbkdf2-sha512"。
func (h *PBKDF2Hasher) Algorithm() string { return "pbkdf2-" + h.config.Hash }

// hashFunc returns the configured hash constructor. | hashFunc 返回配置的哈希构造器。
func (h *PBKDF2Hasher) hashFunc() func() hash.Hash {
	if h.config.Hash == "sha512" {
		return sha512.New
	}
	return sha256.New
}

// Hash returns an encoded PBKDF2 hash. | Hash 返回编码后的 PBKDF2 哈希。
func (h *PBKDF2Hasher) Hash(password string) (string, error) {
	if password == "" {
		return "", errs.Detail(ErrInvalidRequest, "empty password | 空口令")
	}
	salt := make([]byte, h.config.SaltLength)
	if err := fillRandom(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(h.hashFunc(), password, salt, h.config.Iterations, h.config.KeyLength)
	if err != nil {
		return "", errs.Wrap(err, ErrPasswordHash)
	}
	return "$" + h.Algorithm() + "$i=" + strconv.Itoa(h.config.Iterations) +
		",l=" + strconv.Itoa(h.config.KeyLength) + "$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(key), nil
}

// Verify reports whether password matches encoded. | Verify 报告 password 是否匹配 encoded。
func (h *PBKDF2Hasher) Verify(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "" || parts[1] != h.Algorithm() {
		return false, ErrPasswordHash
	}
	iterations, keyLength, err := parsePBKDF2Params(parts[2])
	if err != nil {
		return false, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, errs.Wrap(err, ErrPasswordHash)
	}
	if len(salt) < 8 || len(salt) > maxSaltLength {
		return false, ErrPasswordHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, errs.Wrap(err, ErrPasswordHash)
	}
	if len(want) != keyLength {
		return false, ErrPasswordHash
	}
	got, err := pbkdf2.Key(h.hashFunc(), password, salt, iterations, keyLength)
	if err != nil {
		return false, errs.Wrap(err, ErrPasswordHash)
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// parsePBKDF2Params parses "i=N,l=N". | parsePBKDF2Params 解析 "i=N,l=N"。
func parsePBKDF2Params(s string) (int, int, error) {
	var iterations, keyLength int
	for _, field := range strings.Split(s, ",") {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			return 0, 0, ErrPasswordHash
		}
		n, err := strconv.Atoi(value)
		if err != nil || n <= 0 {
			return 0, 0, ErrPasswordHash
		}
		switch key {
		case "i":
			iterations = n
		case "l":
			keyLength = n
		default:
			return 0, 0, ErrPasswordHash
		}
	}
	if iterations < 100000 || iterations > maxPBKDF2Iterations || keyLength < 16 || keyLength > maxKeyLength {
		return 0, 0, ErrPasswordHash
	}
	return iterations, keyLength, nil
}

// NeedsRehash reports whether encoded uses parameters weaker than the current configuration. | NeedsRehash 报告 encoded 是否弱于当前配置。
func (h *PBKDF2Hasher) NeedsRehash(encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "" || parts[1] != h.Algorithm() {
		return true
	}
	iterations, keyLength, err := parsePBKDF2Params(parts[2])
	if err != nil {
		return true
	}
	if !validHashMaterial(parts[3], parts[4], keyLength) {
		return true
	}
	return iterations != h.config.Iterations || keyLength != h.config.KeyLength
}

// Argon2idConfig configures Argon2id password hashing. | Argon2idConfig 配置 Argon2id 口令哈希。
type Argon2idConfig struct {
	// Time is the number of passes; defaults to 3. | Time 是迭代轮数；默认 3。
	Time uint32
	// Memory is the memory cost in KiB; defaults to 65536 (64 MiB). | Memory 是内存成本（KiB）；默认 65536（64 MiB）。
	Memory uint32
	// Threads is the parallelism; defaults to 4. | Threads 是并行度；默认 4。
	Threads uint8
	// KeyLength is the derived key size in bytes; defaults to 32. | KeyLength 是派生密钥字节数；默认 32。
	KeyLength uint32
	// SaltLength is the random salt size in bytes; defaults to 16. | SaltLength 是随机盐字节数；默认 16。
	SaltLength int
}

// DefaultArgon2idConfig returns the current recommended Argon2id parameters. | DefaultArgon2idConfig 返回当前推荐的 Argon2id 参数。
func DefaultArgon2idConfig() Argon2idConfig {
	return Argon2idConfig{Time: 3, Memory: 64 * 1024, Threads: 4, KeyLength: 32, SaltLength: 16}
}

// Argon2idHasher implements PasswordHasher with Argon2id. | Argon2idHasher 用 Argon2id 实现 PasswordHasher。
type Argon2idHasher struct {
	config Argon2idConfig
}

// NewArgon2idHasher returns an Argon2id hasher, applying defaults for zero fields. | NewArgon2idHasher 返回 Argon2id 哈希器，为零值字段应用默认值。
func NewArgon2idHasher(config Argon2idConfig) (*Argon2idHasher, error) {
	if config.Time == 0 {
		config.Time = 3
	}
	if config.Memory == 0 {
		config.Memory = 64 * 1024
	}
	if config.Threads == 0 {
		config.Threads = 4
	}
	if config.KeyLength == 0 {
		config.KeyLength = 32
	}
	if config.SaltLength == 0 {
		config.SaltLength = 16
	}
	if config.Time < 1 || config.Time > maxArgon2Time || config.Memory < 8*1024 || config.Memory > maxArgon2Memory ||
		config.Threads < 1 || config.Threads > maxArgon2Threads || config.KeyLength < 16 || config.KeyLength > maxKeyLength {
		return nil, errDetailConfig("Argon2id parameters are out of range | Argon2id 参数超出范围")
	}
	if config.SaltLength < 8 || config.SaltLength > maxSaltLength {
		return nil, errDetailConfig("Argon2id salt length %[1]d | Argon2id 盐长度 %[1]d", config.SaltLength)
	}
	return &Argon2idHasher{config: config}, nil
}

// Algorithm returns "argon2id". | Algorithm 返回 "argon2id"。
func (h *Argon2idHasher) Algorithm() string { return "argon2id" }

// Hash returns an encoded Argon2id hash. | Hash 返回编码后的 Argon2id 哈希。
func (h *Argon2idHasher) Hash(password string) (string, error) {
	if password == "" {
		return "", errs.Detail(ErrInvalidRequest, "empty password | 空口令")
	}
	salt := make([]byte, h.config.SaltLength)
	if err := fillRandom(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, h.config.Time, h.config.Memory, h.config.Threads, h.config.KeyLength)
	return "$argon2id$v=19$m=" + strconv.FormatUint(uint64(h.config.Memory), 10) +
		",t=" + strconv.FormatUint(uint64(h.config.Time), 10) +
		",p=" + strconv.FormatUint(uint64(h.config.Threads), 10) + "$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(key), nil
}

// Verify reports whether password matches encoded. | Verify 报告 password 是否匹配 encoded。
func (h *Argon2idHasher) Verify(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false, ErrPasswordHash
	}
	memory, timeCost, threads, err := parseArgon2Params(parts[3])
	if err != nil {
		return false, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, errs.Wrap(err, ErrPasswordHash)
	}
	if len(salt) < 8 || len(salt) > maxSaltLength {
		return false, ErrPasswordHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, errs.Wrap(err, ErrPasswordHash)
	}
	if len(want) < 16 || len(want) > maxKeyLength {
		return false, ErrPasswordHash
	}
	got := argon2.IDKey([]byte(password), salt, timeCost, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// parseArgon2Params parses "m=N,t=N,p=N". | parseArgon2Params 解析 "m=N,t=N,p=N"。
func parseArgon2Params(s string) (uint32, uint32, uint8, error) {
	var memory, timeCost uint32
	var threads uint8
	for _, field := range strings.Split(s, ",") {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			return 0, 0, 0, ErrPasswordHash
		}
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil || n == 0 {
			return 0, 0, 0, ErrPasswordHash
		}
		switch key {
		case "m":
			memory = uint32(n)
		case "t":
			timeCost = uint32(n)
		case "p":
			if n > 255 {
				return 0, 0, 0, ErrPasswordHash
			}
			threads = uint8(n)
		default:
			return 0, 0, 0, ErrPasswordHash
		}
	}
	if memory < 8*1024 || memory > maxArgon2Memory || timeCost < 1 || timeCost > maxArgon2Time ||
		threads < 1 || threads > maxArgon2Threads {
		return 0, 0, 0, ErrPasswordHash
	}
	return memory, timeCost, threads, nil
}

// NeedsRehash reports whether encoded uses parameters weaker than the current configuration. | NeedsRehash 报告 encoded 是否弱于当前配置。
func (h *Argon2idHasher) NeedsRehash(encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return true
	}
	memory, timeCost, threads, err := parseArgon2Params(parts[3])
	if err != nil {
		return true
	}
	if !validHashMaterial(parts[4], parts[5], 0) {
		return true
	}
	return memory < h.config.Memory || timeCost < h.config.Time || threads < h.config.Threads
}

// BcryptConfig configures bcrypt password hashing. | BcryptConfig 配置 bcrypt 口令哈希。
type BcryptConfig struct {
	// Cost is the bcrypt cost; defaults to 12 and must be between 10 and 31. | Cost 是 bcrypt 成本；默认 12，必须位于 10 到 31。
	Cost int
}

// BcryptHasher implements PasswordHasher with bcrypt for compatibility with existing user tables. | BcryptHasher 用 bcrypt 实现 PasswordHasher，以兼容既有用户表。
type BcryptHasher struct {
	cost int
}

// NewBcryptHasher returns a bcrypt hasher. | NewBcryptHasher 返回 bcrypt 哈希器。
func NewBcryptHasher(config BcryptConfig) (*BcryptHasher, error) {
	if config.Cost == 0 {
		config.Cost = 12
	}
	if config.Cost < 10 || config.Cost > 31 {
		return nil, errDetailConfig("bcrypt cost %[1]d must be between 10 and 31 | bcrypt 成本 %[1]d 必须位于 10 到 31", config.Cost)
	}
	return &BcryptHasher{cost: config.Cost}, nil
}

// Algorithm returns "bcrypt". | Algorithm 返回 "bcrypt"。
func (h *BcryptHasher) Algorithm() string { return "bcrypt" }

// Hash returns an encoded bcrypt hash. | Hash 返回编码后的 bcrypt 哈希。
func (h *BcryptHasher) Hash(password string) (string, error) {
	if len(password) > 72 {
		return "", errs.Detail(ErrInvalidRequest, "bcrypt password exceeds 72 bytes | bcrypt 口令超过 72 字节")
	}
	out, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", errs.Wrap(err, ErrPasswordHash)
	}
	return string(out), nil
}

// Verify reports whether password matches encoded. | Verify 报告 password 是否匹配 encoded。
func (h *BcryptHasher) Verify(password, encoded string) (bool, error) {
	if len(password) > 72 {
		return false, nil
	}
	err := bcrypt.CompareHashAndPassword([]byte(encoded), []byte(password))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	}
	return false, errs.Wrap(err, ErrPasswordHash)
}

// NeedsRehash reports whether encoded uses a lower cost than configured. | NeedsRehash 报告 encoded 的成本是否低于配置。
func (h *BcryptHasher) NeedsRehash(encoded string) bool {
	cost, err := bcrypt.Cost([]byte(encoded))
	return err != nil || cost < h.cost
}

// ScryptConfig configures scrypt password hashing. | ScryptConfig 配置 scrypt 口令哈希。
type ScryptConfig struct {
	// N is the CPU/memory cost; defaults to 1<<15. | N 是 CPU/内存成本；默认 1<<15。
	N int
	// R is the block size; defaults to 8. | R 是块大小；默认 8。
	R int
	// P is the parallelism; defaults to 1. | P 是并行度；默认 1。
	P int
	// KeyLength is the derived key size; defaults to 32. | KeyLength 是派生密钥字节数；默认 32。
	KeyLength int
	// SaltLength is the random salt size; defaults to 16. | SaltLength 是随机盐字节数；默认 16。
	SaltLength int
}

// DefaultScryptConfig returns the current recommended scrypt parameters. | DefaultScryptConfig 返回当前推荐的 scrypt 参数。
func DefaultScryptConfig() ScryptConfig {
	return ScryptConfig{N: 1 << 15, R: 8, P: 1, KeyLength: 32, SaltLength: 16}
}

// ScryptHasher implements PasswordHasher with scrypt. | ScryptHasher 用 scrypt 实现 PasswordHasher。
type ScryptHasher struct {
	config ScryptConfig
}

// NewScryptHasher returns a scrypt hasher, applying defaults for zero fields. | NewScryptHasher 返回 scrypt 哈希器，为零值字段应用默认值。
func NewScryptHasher(config ScryptConfig) (*ScryptHasher, error) {
	def := DefaultScryptConfig()
	if config.N == 0 {
		config.N = def.N
	}
	if config.R == 0 {
		config.R = def.R
	}
	if config.P == 0 {
		config.P = def.P
	}
	if config.KeyLength == 0 {
		config.KeyLength = def.KeyLength
	}
	if config.SaltLength == 0 {
		config.SaltLength = def.SaltLength
	}
	if config.N < 1<<14 || config.N > 1<<maxScryptLogN || config.N&(config.N-1) != 0 ||
		config.R < 8 || config.R > maxScryptR ||
		config.P < 1 || config.P > maxScryptP || config.KeyLength < 16 || config.KeyLength > maxKeyLength ||
		config.SaltLength < 8 || config.SaltLength > maxSaltLength {
		return nil, errDetailConfig("scrypt parameters are out of range | scrypt 参数超出范围")
	}
	if scryptMemory(config.N, config.R) > maxScryptMemory {
		return nil, errDetailConfig("scrypt memory cost exceeds %[1]d bytes | scrypt 内存成本超过 %[1]d 字节", maxScryptMemory)
	}
	return &ScryptHasher{config: config}, nil
}

// Algorithm returns "scrypt". | Algorithm 返回 "scrypt"。
func (h *ScryptHasher) Algorithm() string { return "scrypt" }

// Hash returns an encoded scrypt hash. | Hash 返回编码后的 scrypt 哈希。
func (h *ScryptHasher) Hash(password string) (string, error) {
	if password == "" {
		return "", errs.Detail(ErrInvalidRequest, "empty password | 空口令")
	}
	salt := make([]byte, h.config.SaltLength)
	if err := fillRandom(salt); err != nil {
		return "", err
	}
	key, err := scrypt.Key([]byte(password), salt, h.config.N, h.config.R, h.config.P, h.config.KeyLength)
	if err != nil {
		return "", errs.Wrap(err, ErrPasswordHash)
	}
	return "$scrypt$ln=" + strconv.Itoa(log2(h.config.N)) +
		",r=" + strconv.Itoa(h.config.R) +
		",p=" + strconv.Itoa(h.config.P) + "$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(key), nil
}

// Verify reports whether password matches encoded. | Verify 报告 password 是否匹配 encoded。
func (h *ScryptHasher) Verify(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "scrypt" {
		return false, ErrPasswordHash
	}
	n, r, p, err := parseScryptParams(parts[2])
	if err != nil {
		return false, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, errs.Wrap(err, ErrPasswordHash)
	}
	if len(salt) < 8 || len(salt) > maxSaltLength {
		return false, ErrPasswordHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, errs.Wrap(err, ErrPasswordHash)
	}
	if len(want) < 16 || len(want) > maxKeyLength {
		return false, ErrPasswordHash
	}
	got, err := scrypt.Key([]byte(password), salt, n, r, p, len(want))
	if err != nil {
		return false, errs.Wrap(err, ErrPasswordHash)
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// parseScryptParams parses "ln=N,r=N,p=N". | parseScryptParams 解析 "ln=N,r=N,p=N"。
func parseScryptParams(s string) (int, int, int, error) {
	var ln, r, p int
	for _, field := range strings.Split(s, ",") {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			return 0, 0, 0, ErrPasswordHash
		}
		n, err := strconv.Atoi(value)
		if err != nil || n <= 0 {
			return 0, 0, 0, ErrPasswordHash
		}
		switch key {
		case "ln":
			ln = n
		case "r":
			r = n
		case "p":
			p = n
		default:
			return 0, 0, 0, ErrPasswordHash
		}
	}
	if ln < 14 || ln > maxScryptLogN || r < 1 || r > maxScryptR || p < 1 || p > maxScryptP {
		return 0, 0, 0, ErrPasswordHash
	}
	n := 1 << ln
	if scryptMemory(n, r) > maxScryptMemory {
		return 0, 0, 0, ErrPasswordHash
	}
	return n, r, p, nil
}

// scryptMemory returns the approximate memory cost in bytes for N and r. | scryptMemory 返回 N 与 r 的近似内存成本（字节）。
func scryptMemory(n, r int) uint64 {
	return 128 * uint64(n) * uint64(r)
}

// NeedsRehash reports whether encoded uses parameters weaker than the current configuration. | NeedsRehash 报告 encoded 是否弱于当前配置。
func (h *ScryptHasher) NeedsRehash(encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "scrypt" {
		return true
	}
	n, r, p, err := parseScryptParams(parts[2])
	if err != nil {
		return true
	}
	if !validHashMaterial(parts[3], parts[4], 0) {
		return true
	}
	return n < h.config.N || r < h.config.R || p < h.config.P
}

// validHashMaterial reports whether the encoded salt and key have plausible lengths. When exactKey
// is positive, the decoded key must have exactly that length. | validHashMaterial 报告编码盐与密钥长度
// 是否合理。exactKey 为正时，解码后的密钥长度必须恰好等于它。
func validHashMaterial(encodedSalt, encodedKey string, exactKey int) bool {
	salt, err := base64.RawStdEncoding.DecodeString(encodedSalt)
	if err != nil || len(salt) < 8 || len(salt) > maxSaltLength {
		return false
	}
	key, err := base64.RawStdEncoding.DecodeString(encodedKey)
	if err != nil || len(key) < 16 || len(key) > maxKeyLength {
		return false
	}
	if exactKey > 0 && len(key) != exactKey {
		return false
	}
	return true
}

// log2 returns floor(log2(n)) for n > 0. | log2 返回 n > 0 时的 floor(log2(n))。
func log2(n int) int {
	out := 0
	for n > 1 {
		n >>= 1
		out++
	}
	return out
}

// fillRandom fills b from the operating system random source. | fillRandom 用操作系统随机源填充 b。
func fillRandom(b []byte) error {
	if _, err := rand.Read(b); err != nil {
		return errs.Wrap(err, ErrRandomSource)
	}
	return nil
}

// PasswordHashManager verifies several hash formats and writes one default format. | PasswordHashManager 校验多种哈希格式并写入一种默认格式。
//
// It exists so a migration from bcrypt, scrypt or PBKDF2 to Argon2id can verify old hashes and
// transparently upgrade them after a successful login. | 它使从 bcrypt、scrypt 或 PBKDF2 迁移到
// Argon2id 的过程可以校验旧哈希，并在登录成功后透明升级。
type PasswordHashManager struct {
	// Default is used by Hash. | Default 由 Hash 使用。
	Default PasswordHasher
	// Hashers are tried in order by Verify. | Hashers 由 Verify 按顺序尝试。
	Hashers []PasswordHasher
}

// NewPasswordHashManager returns a manager. When defaultHasher is nil, Argon2id with recommended
// parameters is used. | NewPasswordHashManager 返回管理器。defaultHasher 为空时使用推荐参数的 Argon2id。
func NewPasswordHashManager(defaultHasher PasswordHasher, extra ...PasswordHasher) (*PasswordHashManager, error) {
	if defaultHasher == nil {
		h, err := NewArgon2idHasher(DefaultArgon2idConfig())
		if err != nil {
			return nil, err
		}
		defaultHasher = h
	}
	m := &PasswordHashManager{Default: defaultHasher}
	seen := make(map[string]bool, len(extra)+1)
	for _, h := range append([]PasswordHasher{defaultHasher}, extra...) {
		if h == nil || seen[h.Algorithm()] {
			continue
		}
		seen[h.Algorithm()] = true
		m.Hashers = append(m.Hashers, h)
	}
	return m, nil
}

// Algorithm returns the default algorithm identifier. | Algorithm 返回默认算法标识。
func (m *PasswordHashManager) Algorithm() string {
	if m == nil || m.Default == nil {
		return ""
	}
	return m.Default.Algorithm()
}

// Hash returns a hash in the default format. | Hash 返回默认格式的哈希。
func (m *PasswordHashManager) Hash(password string) (string, error) {
	if m == nil || m.Default == nil {
		return "", errDetailConfig("password hash manager has no default | 口令哈希管理器没有默认算法")
	}
	return m.Default.Hash(password)
}

// Verify tries every configured hasher and reports whether one matches. | Verify 尝试每个配置的哈希器并报告是否有一个匹配。
func (m *PasswordHashManager) Verify(password, encoded string) (bool, error) {
	if m == nil || len(m.Hashers) == 0 {
		return false, ErrPasswordHash
	}
	var lastErr error
	for _, h := range m.Hashers {
		ok, err := h.Verify(password, encoded)
		if err == nil {
			return ok, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = ErrPasswordHash
	}
	return false, lastErr
}

// NeedsRehash reports whether encoded should be replaced by the default format. | NeedsRehash 报告 encoded 是否应替换为默认格式。
func (m *PasswordHashManager) NeedsRehash(encoded string) bool {
	if m == nil || m.Default == nil {
		return true
	}
	if !strings.HasPrefix(encoded, "$") && !strings.HasPrefix(encoded, "$2") {
		return true
	}
	for _, h := range m.Hashers {
		if strings.HasPrefix(encoded, "$"+h.Algorithm()+"$") || (h.Algorithm() == "bcrypt" && isBcryptHash(encoded)) {
			return h.NeedsRehash(encoded) || h.Algorithm() != m.Default.Algorithm()
		}
	}
	return true
}

// isBcryptHash reports whether encoded looks like a bcrypt hash. | isBcryptHash 报告 encoded 是否形如 bcrypt 哈希。
func isBcryptHash(encoded string) bool {
	return strings.HasPrefix(encoded, "$2a$") || strings.HasPrefix(encoded, "$2b$") ||
		strings.HasPrefix(encoded, "$2x$") || strings.HasPrefix(encoded, "$2y$")
}

// PasswordPolicy configures password strength and lifecycle rules. | PasswordPolicy 配置口令强度与生命周期规则。
type PasswordPolicy struct {
	// MinLength is the minimum Unicode code point count; 0 defaults to 8. | MinLength 是最小 Unicode 码点数；0 默认 8。
	MinLength int
	// MaxLength is the maximum byte count; 0 defaults to 1024. | MaxLength 是最大字节数；0 默认 1024。
	MaxLength int
	// RequireUppercase, RequireLowercase, RequireDigit and RequireSymbol add composition rules. | RequireUppercase、RequireLowercase、RequireDigit 与 RequireSymbol 增加组成规则。
	RequireUppercase bool
	RequireLowercase bool
	RequireDigit     bool
	RequireSymbol    bool
	// DisallowWhitespace rejects any Unicode whitespace. | DisallowWhitespace 拒绝任何 Unicode 空白。
	DisallowWhitespace bool
	// DisallowUsername and DisallowEmail reject passwords containing those identifiers. | DisallowUsername 与 DisallowEmail 拒绝包含这些标识的口令。
	DisallowUsername bool
	DisallowEmail    bool
	// MaxAge is the maximum password age; zero disables expiry. | MaxAge 是口令最长有效期；零值禁用过期。
	MaxAge time.Duration
	// History is the number of previous hashes checked for reuse; zero disables the check. | History 是检查复用的历史哈希数；零值禁用检查。
	History int
	// CommonPasswords is an additional case-insensitive deny list. | CommonPasswords 是额外的大小写不敏感拒绝列表。
	CommonPasswords map[string]struct{}
	// BreachCheck optionally checks a password against an external breach corpus. | BreachCheck 可选地对外部泄露语料库检查口令。
	BreachCheck func(ctx context.Context, password string) (bool, error)
}

// DefaultPasswordPolicy returns a NIST SP 800-63B aligned policy. | DefaultPasswordPolicy 返回对齐 NIST SP 800-63B 的策略。
//
// Length is favoured over composition rules, and well-known passwords are rejected. | 该策略偏好长度而非组成规则，并拒绝常见口令。
func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength:          8,
		MaxLength:          1024,
		DisallowUsername:   true,
		DisallowEmail:      true,
		CommonPasswords:    DefaultCommonPasswords(),
		DisallowWhitespace: false,
	}
}

// Validate checks password against the policy for user. | Validate 按策略针对 user 检查 password。
func (p PasswordPolicy) Validate(ctx context.Context, password string, user *User) error {
	if password == "" {
		return errs.Detail(ErrPasswordPolicy, "password is empty | 口令为空")
	}
	if len(password) > p.maxLength() {
		return errs.Detail(ErrPasswordPolicy, "password exceeds %[1]d bytes | 口令超过 %[1]d 字节", p.maxLength())
	}
	if utf8.RuneCountInString(password) < p.minLength() {
		return errs.Detail(ErrPasswordPolicy, "password shorter than %[1]d characters | 口令短于 %[1]d 个字符", p.minLength())
	}
	if p.DisallowWhitespace && strings.IndexFunc(password, unicode.IsSpace) >= 0 {
		return errs.Detail(ErrPasswordPolicy, "password contains whitespace | 口令包含空白")
	}
	var upper, lower, digit, symbol bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			symbol = true
		}
	}
	if p.RequireUppercase && !upper {
		return errs.Detail(ErrPasswordPolicy, "password needs an uppercase letter | 口令需要大写字母")
	}
	if p.RequireLowercase && !lower {
		return errs.Detail(ErrPasswordPolicy, "password needs a lowercase letter | 口令需要小写字母")
	}
	if p.RequireDigit && !digit {
		return errs.Detail(ErrPasswordPolicy, "password needs a digit | 口令需要数字")
	}
	if p.RequireSymbol && !symbol {
		return errs.Detail(ErrPasswordPolicy, "password needs a symbol | 口令需要符号")
	}
	if user != nil {
		lowerPassword := strings.ToLower(password)
		if p.DisallowUsername && user.Username != "" && strings.Contains(lowerPassword, strings.ToLower(user.Username)) {
			return errs.Detail(ErrPasswordPolicy, "password contains the username | 口令包含用户名")
		}
		if p.DisallowEmail && user.Email != "" {
			local, _, _ := strings.Cut(strings.ToLower(user.Email), "@")
			if local != "" && strings.Contains(lowerPassword, local) {
				return errs.Detail(ErrPasswordPolicy, "password contains the email local part | 口令包含邮箱本地部分")
			}
		}
	}
	if p.CommonPasswords != nil {
		if _, bad := p.CommonPasswords[strings.ToLower(password)]; bad {
			return errs.Detail(ErrPasswordPolicy, "password is commonly used | 口令过于常见")
		}
	}
	if p.BreachCheck != nil {
		breached, err := p.BreachCheck(ctx, password)
		if err != nil {
			return errs.Wrap(err, ErrPasswordPolicy)
		}
		if breached {
			return errs.Detail(ErrPasswordPolicy, "password appears in a breach corpus | 口令出现在泄露语料库中")
		}
	}
	return nil
}

// minLength returns the effective minimum length. | minLength 返回有效最小长度。
func (p PasswordPolicy) minLength() int {
	if p.MinLength <= 0 {
		return 8
	}
	return p.MinLength
}

// maxLength returns the effective maximum length. | maxLength 返回有效最大长度。
func (p PasswordPolicy) maxLength() int {
	if p.MaxLength <= 0 {
		return 1024
	}
	return p.MaxLength
}

// Expired reports whether user's password exceeded MaxAge at now. | Expired 报告用户口令在 now 时刻是否超过 MaxAge。
func (p PasswordPolicy) Expired(user *User, now time.Time) bool {
	if p.MaxAge <= 0 || user == nil || user.PasswordChangedAt.IsZero() {
		return false
	}
	return !now.Before(user.PasswordChangedAt.Add(p.MaxAge))
}

// CheckHistory reports ErrPasswordReused when password matches one of the previous hashes. | CheckHistory 在 password 匹配历史哈希之一时返回 ErrPasswordReused。
func CheckHistory(_ context.Context, hasher PasswordHasher, password string, history []string) error {
	if hasher == nil {
		return nil
	}
	for _, encoded := range history {
		if encoded == "" {
			continue
		}
		ok, err := hasher.Verify(password, encoded)
		if err != nil {
			continue
		}
		if ok {
			return ErrPasswordReused
		}
	}
	return nil
}

// DefaultCommonPasswords returns a small built-in deny list of widely used passwords. | DefaultCommonPasswords 返回内置的常见口令拒绝列表。
//
// The list is intentionally short: a production deployment should also configure BreachCheck or a
// larger deny list. | 该列表刻意很短：生产部署还应配置 BreachCheck 或更大的拒绝列表。
func DefaultCommonPasswords() map[string]struct{} {
	words := []string{
		"password", "password1", "password123", "123456", "12345678", "123456789",
		"qwerty", "qwerty123", "abc123", "letmein", "welcome", "admin", "administrator",
		"iloveyou", "monkey", "dragon", "sunshine", "princess", "football", "baseball",
		"master", "shadow", "superman", "michael", "jennifer", "trustno1", "passw0rd",
		"p@ssw0rd", "changeme", "secret", "login", "root", "toor", "test", "guest",
		"111111", "000000", "654321", "666666", "888888", "123123", "1q2w3e4r",
	}
	out := make(map[string]struct{}, len(words))
	for _, word := range words {
		out[word] = struct{}{}
	}
	return out
}
