package nodeid

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

// Identity prefixes make the origin visible in logs and keep ids from being
// mistaken for user input. | 身份前缀让来源在日志中可见，并避免 id 被误认为用户输入。
const (
	idPrefix       = "ydn_"
	instancePrefix = "ydi_"
	deriveDomain   = "yd-nodeid-v1\x00"
)

// fallbackCounter disambiguates fallback ids created in the same nanosecond. |
// fallbackCounter 区分同一纳秒内创建的兜底 id。
var fallbackCounter atomic.Uint64

// derive turns a platform seed into a fixed-length identity. The source name and
// salt are domain separators: the same seed from a different source, or with a
// different salt, yields a different id. | derive 把平台种子转换为定长身份。来源名与盐都是
// 域分隔符：同一份种子来自不同来源、或使用不同盐，都会得到不同 id。
func derive(source Source, seed, salt string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(deriveDomain))
	_, _ = h.Write([]byte(salt))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(source))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(seed))
	sum := h.Sum(nil)
	return idPrefix + hex.EncodeToString(sum[:16])
}

// newRandomID returns a 128-bit random identity. It never returns an empty
// string; a broken entropy source falls back to a hashed clock/pid/counter
// tuple rather than failing startup. | newRandomID 返回 128 位随机身份。它绝不返回空串；
// 熵源故障时回退到时钟/进程号/计数器元组的哈希，而不是让启动失败。
func newRandomID() string {
	return idPrefix + hex.EncodeToString(randomBytes(16))
}

// InstanceID returns a fresh 96-bit per-process identifier. It is not a node
// identity: it changes on every call and is meant for echo filtering and
// claimer leases. | InstanceID 返回新的 96 位每进程标识。它不是节点身份：每次调用都会变化，
// 用于回声过滤与 Claimer 租约。
func InstanceID() string {
	return instancePrefix + hex.EncodeToString(randomBytes(12))
}

// randomBytes fills n bytes from crypto/rand, falling back to a hash of time,
// pid and a counter when the entropy source fails. | randomBytes 从 crypto/rand 填充 n
// 字节；熵源失败时回退到时间、进程号与计数器的哈希。
func randomBytes(n int) []byte {
	out := make([]byte, n)
	if _, err := rand.Read(out); err == nil {
		return out
	}
	counter := fallbackCounter.Add(1)
	seed := strconv.FormatInt(time.Now().UnixNano(), 10) + ":" +
		strconv.Itoa(os.Getpid()) + ":" + strconv.FormatUint(counter, 10)
	sum := sha256.Sum256([]byte(seed))
	copy(out, sum[:])
	return out
}
