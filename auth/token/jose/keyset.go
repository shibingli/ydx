package jose

import (
	"context"
	"crypto/sha256"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// DefaultJWKSMaxAge is the Cache-Control max-age used by KeySet.Handler. | DefaultJWKSMaxAge 是
// KeySet.Handler 使用的 Cache-Control max-age。
const DefaultJWKSMaxAge = time.Hour

// KeySet is a JSON Web Key Set (RFC 7517 §5). | KeySet 是 JSON Web Key Set（RFC 7517 §5）。
//
// A KeySet is not safe for concurrent mutation. Publish it through Cache when keys rotate under
// concurrent readers. | KeySet 不支持并发修改。并发读取期间需要轮换密钥时，请通过 Cache 发布。
type KeySet struct {
	// Keys is the list of keys in the set. | Keys 是集合中的密钥列表。
	Keys []*Key `json:"keys"`
}

// Marshal encodes the key set as JWKS JSON. | Marshal 把密钥集编码为 JWKS JSON。
//
// A set with no keys is encoded with an empty "keys" array, never null. | 空密钥集编码为空的
// "keys" 数组，绝不会是 null。
func (s *KeySet) Marshal() ([]byte, error) {
	type plain KeySet
	var c plain
	if s != nil {
		c = plain(*s)
	}
	if c.Keys == nil {
		c.Keys = []*Key{}
	}
	out, err := json.Marshal(c)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidKey, "encode JWKS | 编码 JWKS")
	}
	return out, nil
}

// ParseKeySet parses a JWKS document. | ParseKeySet 解析 JWKS 文档。
//
// It rejects a key without kty and a set that repeats a non-empty kid, because such a set is
// ambiguous for rotation. Key material itself is validated lazily by Validate / PublicKey /
// PrivateKey. | 它会拒绝缺少 kty 的密钥，以及重复非空 kid 的集合，因为这类集合在轮换时存在歧义。
// 密钥材料本身由 Validate / PublicKey / PrivateKey 延迟校验。
func ParseKeySet(data []byte) (*KeySet, error) {
	var s KeySet
	if err := unmarshal(data, &s); err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidKey, "parse JWKS | 解析 JWKS")
	}
	seen := make(map[string]struct{}, len(s.Keys))
	for i, k := range s.Keys {
		if k == nil {
			return nil, errs.Detail(ErrInvalidKey, "key %[1]d is null | 第 %[1]d 个密钥为 null", i)
		}
		if k.Kty == "" {
			return nil, errs.Detail(ErrInvalidKey, "key %[1]d has no kty | 第 %[1]d 个密钥缺少 kty", i)
		}
		k.withCache()
		if k.Kid == "" {
			continue
		}
		if _, dup := seen[k.Kid]; dup {
			return nil, errs.Detail(ErrDuplicateKey, "kid=%[1]q | kid=%[1]q", k.Kid)
		}
		seen[k.Kid] = struct{}{}
	}
	if s.Keys == nil {
		s.Keys = []*Key{}
	}
	return &s, nil
}

// Key returns the key with the given kid. | Key 返回指定 kid 的密钥。
//
// An empty kid selects the only key when the set holds exactly one key. | 空 kid 在集合恰好只含
// 一个密钥时选择该密钥。
func (s *KeySet) Key(kid string) (*Key, bool) {
	if s == nil {
		return nil, false
	}
	return keyFromSet(s, kid)
}

// Lookup returns the key with the given kid or ErrKeyNotFound. | Lookup 返回指定 kid 的密钥，未
// 找到时返回 ErrKeyNotFound。
func (s *KeySet) Lookup(kid string) (*Key, error) {
	k, ok := s.Key(kid)
	if !ok {
		return nil, errs.Detail(ErrKeyNotFound, "kid=%[1]q | kid=%[1]q", kid)
	}
	return k, nil
}

// Add appends a copy of k to the set. | Add 把 k 的副本追加到集合中。
//
// A nil key, a key without kty and a non-empty kid that already exists are rejected. | nil 密钥、
// 缺少 kty 的密钥以及已存在的非空 kid 都会被拒绝。
func (s *KeySet) Add(k *Key) error {
	if s == nil {
		return ErrInvalidKey
	}
	if k == nil {
		return errs.Detail(ErrInvalidKey, "nil key | 密钥为 nil")
	}
	if k.Kty == "" {
		return errs.Detail(ErrInvalidKey, "key has no kty | 密钥缺少 kty")
	}
	if k.Kid != "" {
		if _, exists := keyFromSet(s, k.Kid); exists {
			return errs.Detail(ErrDuplicateKey, "kid=%[1]q | kid=%[1]q", k.Kid)
		}
	}
	s.Keys = append(s.Keys, k.Clone())
	return nil
}

// Remove deletes every key with the given kid and reports whether any was removed. | Remove 删除
// 所有指定 kid 的密钥，并报告是否删除了任何密钥。
func (s *KeySet) Remove(kid string) bool {
	if s == nil {
		return false
	}
	out := s.Keys[:0]
	removed := false
	for _, k := range s.Keys {
		if k != nil && k.Kid == kid {
			removed = true
			continue
		}
		out = append(out, k)
	}
	s.Keys = out
	return removed
}

// Clone returns a deep copy of the set. | Clone 返回集合的深拷贝。
func (s *KeySet) Clone() *KeySet {
	if s == nil {
		return nil
	}
	c := &KeySet{Keys: make([]*Key, len(s.Keys))}
	for i, k := range s.Keys {
		c.Keys[i] = k.Clone()
	}
	return c
}

// Public returns a deep copy of the set in which every key is reduced to public material. | Public
// 返回集合的深拷贝，其中每个密钥都被缩减为公开材料。
func (s *KeySet) Public() *KeySet {
	if s == nil {
		return nil
	}
	c := &KeySet{Keys: make([]*Key, len(s.Keys))}
	for i, k := range s.Keys {
		if k != nil {
			c.Keys[i] = k.Public()
		}
	}
	return c
}

// Handler returns an http.Handler that publishes the set as application/jwk-set+json. | Handler
// 返回以 application/jwk-set+json 发布该集合的 http.Handler。
//
// The response carries a strong ETag and a Cache-Control max-age of DefaultJWKSMaxAge, and
// If-None-Match is answered with 304. Only GET and HEAD are allowed. Mount it on ydx/router with
// router.HandleRaw or use it directly with net/http. | 响应携带强 ETag 与 DefaultJWKSMaxAge 的
// Cache-Control max-age，并对 If-None-Match 返回 304。仅允许 GET 与 HEAD。可通过
// router.HandleRaw 挂载到 ydx/router，也可直接用于 net/http。
func (s *KeySet) Handler() http.Handler {
	return s.HandlerWithMaxAge(DefaultJWKSMaxAge)
}

// HandlerWithMaxAge is Handler with an explicit cache lifetime. | HandlerWithMaxAge 是使用显式
// 缓存时长的 Handler。
//
// A negative maxAge is encoded as max-age=0. Private key members are never published: every key is
// projected to its public form before serialization, even when the set still holds private material
// for signing. | 负的 maxAge 编码为 max-age=0。私钥成员绝不会被发布：即使集合仍保留用于签名的私钥
// 材料，序列化前也会把每个密钥投影为公开形式。
func (s *KeySet) HandlerWithMaxAge(maxAge time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed | 方法不允许", http.StatusMethodNotAllowed)
			return
		}
		body, err := s.Public().Marshal()
		if err != nil {
			http.Error(w, "key set unavailable | 密钥集不可用", http.StatusInternalServerError)
			return
		}
		sum := sha256.Sum256(body)
		etag := `"` + base64.RawURLEncoding.EncodeToString(sum[:]) + `"`
		h := w.Header()
		h.Set("Content-Type", "application/jwk-set+json")
		h.Set("ETag", etag)
		h.Set("X-Content-Type-Options", "nosniff")
		seconds := int64(maxAge / time.Second)
		if seconds < 0 {
			seconds = 0
		}
		h.Set("Cache-Control", "public, max-age="+strconv.FormatInt(seconds, 10))
		if etagMatches(r.Header.Get("If-None-Match"), etag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		h.Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(body)
	})
}

// etagMatches reports whether an If-None-Match header names etag. | etagMatches 报告
// If-None-Match 头部是否命中 etag。
func etagMatches(header, etag string) bool {
	if header == "" {
		return false
	}
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "*" || part == etag || strings.TrimPrefix(part, "W/") == etag {
			return true
		}
	}
	return false
}

// Cache is a thread-safe, atomically replaceable key set used during key rotation. | Cache 是密钥
// 轮换期间使用的线程安全、可原子替换的密钥集。
//
// Readers observe either the old or the new set, never a partially updated one. Set stores a deep
// copy, so later mutation of the caller's set cannot leak into readers. | 读取方只会观察到旧集合
// 或新集合，绝不会看到部分更新的状态。Set 保存深拷贝，因此调用方随后修改自己的集合不会影响
// 读取方。
type Cache struct {
	mu  sync.RWMutex
	set *KeySet
}

// NewCache returns a cache initialized with the optional set. | NewCache 返回以可选集合初始化的
// 缓存。
func NewCache(initial ...*KeySet) *Cache {
	c := &Cache{}
	if len(initial) > 0 && initial[0] != nil {
		c.set = initial[0].Clone()
	}
	return c
}

// Set replaces the cached set with a deep copy of ks. | Set 用 ks 的深拷贝替换缓存集合。
func (c *Cache) Set(ks *KeySet) {
	var copySet *KeySet
	if ks != nil {
		copySet = ks.Clone()
	}
	c.mu.Lock()
	c.set = copySet
	c.mu.Unlock()
}

// Snapshot returns a deep copy of the cached set, or nil when the cache is empty. | Snapshot 返回
// 缓存集合的深拷贝；缓存为空时返回 nil。
func (c *Cache) Snapshot() *KeySet {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.set.Clone()
}

// Get returns the key with the given kid or ErrKeyNotFound. | Get 返回指定 kid 的密钥，未找到时
// 返回 ErrKeyNotFound。
func (c *Cache) Get(kid string) (*Key, error) {
	c.mu.RLock()
	set := c.set
	c.mu.RUnlock()
	k, ok := set.Key(kid)
	if !ok {
		return nil, errs.Detail(ErrKeyNotFound, "kid=%[1]q | kid=%[1]q", kid)
	}
	return k, nil
}

// Refresh fetches a new set from source and installs it when the fetch succeeds. | Refresh 从
// source 获取新集合并于获取成功时安装。
//
// The fetch runs outside the cache lock, so readers keep using the old set while it is in flight.
// A failed fetch leaves the old set untouched. | 获取过程在缓存锁之外执行，因此读取方在获取期间
// 继续使用旧集合。获取失败时旧集合保持不变。
func (c *Cache) Refresh(ctx context.Context, source KeySetSource) error {
	if source == nil {
		return errs.Detail(ErrInvalidConfig, "nil key set source | 密钥集来源为 nil")
	}
	ks, err := source.Fetch(ctx)
	if err != nil {
		return err
	}
	c.Set(ks)
	return nil
}

// keyFromSet searches set for kid. | keyFromSet 在 set 中查找 kid。
func keyFromSet(set *KeySet, kid string) (*Key, bool) {
	if set == nil {
		return nil, false
	}
	if kid == "" {
		if len(set.Keys) == 1 && set.Keys[0] != nil {
			return set.Keys[0], true
		}
		return nil, false
	}
	for _, k := range set.Keys {
		if k != nil && k.Kid == kid {
			return k, true
		}
	}
	return nil, false
}
