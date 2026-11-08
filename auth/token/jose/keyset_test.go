package jose

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestKeySetOperations(t *testing.T) {
	k1, err := FromHMAC("k1", bytes.Repeat([]byte{0x01}, 32))
	if err != nil {
		t.Fatalf("FromHMAC failed: %v", err)
	}
	k2, err := FromHMAC("k2", bytes.Repeat([]byte{0x02}, 32))
	if err != nil {
		t.Fatalf("FromHMAC failed: %v", err)
	}
	set := &KeySet{}
	if err := set.Add(k1); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	if err := set.Add(k1); !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("duplicate Add error = %v, want ErrDuplicateKey", err)
	}
	if err := set.Add(k2); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	if err := set.Add(nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("nil Add error = %v, want ErrInvalidKey", err)
	}
	if err := set.Add(&Key{}); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("no-kty Add error = %v, want ErrInvalidKey", err)
	}
	if k, ok := set.Key("k1"); !ok || k.Kid != "k1" {
		t.Fatalf("Key(k1) = %v, %v", k, ok)
	}
	if _, err := set.Lookup("missing"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Lookup error = %v, want ErrKeyNotFound", err)
	}
	single := &KeySet{Keys: []*Key{k1}}
	if _, ok := single.Key(""); !ok {
		t.Fatal("empty kid did not select the only key")
	}
	if !set.Remove("k1") {
		t.Fatal("Remove(k1) = false, want true")
	}
	if set.Remove("k1") {
		t.Fatal("second Remove(k1) = true, want false")
	}

	empty, err := (&KeySet{}).Marshal()
	if err != nil {
		t.Fatalf("empty Marshal failed: %v", err)
	}
	if string(empty) != `{"keys":[]}` {
		t.Fatalf("empty Marshal = %s, want {\"keys\":[]}", empty)
	}

	full, err := (&KeySet{Keys: []*Key{k1, k2}}).Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	parsed, err := ParseKeySet(full)
	if err != nil {
		t.Fatalf("ParseKeySet failed: %v", err)
	}
	if len(parsed.Keys) != 2 {
		t.Fatalf("parsed %d keys, want 2", len(parsed.Keys))
	}

	if _, err := ParseKeySet([]byte(`{"keys":[{"kty":"oct","kid":"x","k":"AA"},{"kty":"oct","kid":"x","k":"AQ"}]}`)); !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("duplicate kid error = %v, want ErrDuplicateKey", err)
	}
	if _, err := ParseKeySet([]byte(`{"keys":[{"kid":"x","k":"AA"}]}`)); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("missing kty error = %v, want ErrInvalidKey", err)
	}
	if _, err := ParseKeySet([]byte(`{"keys":null}`)); err != nil {
		t.Fatalf("null keys error = %v", err)
	}

	clone := (&KeySet{Keys: []*Key{k1}}).Clone()
	clone.Keys[0].K = "mutated"
	if k1.K == "mutated" {
		t.Fatal("Clone shares key material")
	}
	if (&KeySet{}).Clone() == nil {
		t.Fatal("Clone of empty set is nil")
	}
	var nilSet *KeySet
	if nilSet.Clone() != nil || nilSet.Public() != nil {
		t.Fatal("nil set copy methods returned non-nil")
	}
	if nilSet.Remove("x") {
		t.Fatal("nil set Remove returned true")
	}
}

func TestKeySetHandler(t *testing.T) {
	key := mustGenerate(t, "EdDSA").Public()
	key.Kid = "published"
	set := &KeySet{Keys: []*Key{key}}
	handler := set.Handler()

	get := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, get)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/jwk-set+json" {
		t.Fatalf("Content-Type = %q", got)
	}
	wantCache := "public, max-age=3600"
	if got := rec.Header().Get("Cache-Control"); got != wantCache {
		t.Fatalf("Cache-Control = %q, want %q", got, wantCache)
	}
	etag := rec.Header().Get("ETag")
	if !strings.HasPrefix(etag, `"`) || !strings.HasSuffix(etag, `"`) {
		t.Fatalf("ETag = %q, want a strong ETag", etag)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing X-Content-Type-Options")
	}
	parsed, err := ParseKeySet(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("ParseKeySet failed: %v", err)
	}
	if len(parsed.Keys) != 1 || parsed.Keys[0].Kid != "published" {
		t.Fatalf("published keys = %+v", parsed.Keys)
	}

	for _, value := range []string{etag, "W/" + etag, "*"} {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
		req.Header.Set("If-None-Match", value)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotModified {
			t.Fatalf("If-None-Match %q status = %d, want 304", value, rec.Code)
		}
		if rec.Body.Len() != 0 {
			t.Fatalf("304 response has a body: %q", rec.Body.String())
		}
	}

	head := httptest.NewRequest(http.MethodHead, "/.well-known/jwks.json", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, head)
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("HEAD status = %d, body len = %d", rec.Code, rec.Body.Len())
	}
	if rec.Header().Get("Content-Length") == "" {
		t.Fatal("HEAD response lacks Content-Length")
	}

	post := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, post)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", rec.Code)
	}
	if rec.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("Allow = %q", rec.Header().Get("Allow"))
	}

	rec = httptest.NewRecorder()
	set.HandlerWithMaxAge(-time.Second).ServeHTTP(rec, get)
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=0" {
		t.Fatalf("negative max age Cache-Control = %q", got)
	}
}

// TestKeySetHandlerNeverPublishesPrivateMaterial proves that the JWKS endpoint projects every key to
// its public form even when the set holds private signing keys. | TestKeySetHandlerNeverPublishesPrivateMaterial
// 证明即使集合持有私钥签名材料，JWKS 端点仍会把每个密钥投影为公开形式。
func TestKeySetHandlerNeverPublishesPrivateMaterial(t *testing.T) {
	// Clone the shared RSA key before changing its kid so other tests keep seeing the original. |
	// 修改 kid 前先克隆共享 RSA 密钥，避免影响其他测试。
	rsaKey := testRSAKey(t).Clone()
	ecKey := mustGenerate(t, "ES256")
	edKey := mustGenerate(t, "EdDSA")
	octKey := mustGenerate(t, "HS256")
	for _, k := range []*Key{rsaKey, ecKey, edKey, octKey} {
		k.Kid = "private-" + k.Kty
	}
	set := &KeySet{Keys: []*Key{rsaKey, ecKey, edKey, octKey}}

	rec := httptest.NewRecorder()
	set.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, member := range []string{`"d":`, `"p":`, `"q":`, `"dp":`, `"dq":`, `"qi":`, `"oth":`} {
		if strings.Contains(body, member) {
			t.Errorf("JWKS 响应泄露私钥成员 %s: %s", member, body)
		}
	}
	if strings.Contains(body, `"k":`) {
		t.Errorf("JWKS 响应泄露 oct 对称密钥: %s", body)
	}
	parsed, err := ParseKeySet(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("ParseKeySet failed: %v", err)
	}
	if len(parsed.Keys) != 3 {
		t.Fatalf("published key count = %d, want 3 (oct omitted): %+v", len(parsed.Keys), parsed.Keys)
	}
	for _, k := range parsed.Keys {
		if k.Kty == KeyTypeOct {
			t.Errorf("JWKS 响应发布了对称密钥 %q", k.Kid)
		}
		if k.D != "" || k.P != "" || k.Q != "" || k.DP != "" || k.DQ != "" || k.QI != "" || len(k.Oth) != 0 {
			t.Errorf("发布的密钥 %q 仍含私钥材料: %+v", k.Kid, k)
		}
	}
	// The projection must not mutate the caller's signing keys. | 该投影不得修改调用方的签名密钥。
	if rsaKey.D == "" || ecKey.D == "" || edKey.D == "" {
		t.Error("处理器修改了集合中的私钥")
	}
}

// TestKeySetHandlerSymmetricOptIn proves that symmetric keys stay out of the default publication
// and appear only through the explicit trusted-channel option. | TestKeySetHandlerSymmetricOptIn
// 证明默认发布不包含对称密钥，只有显式开启可信通道选项时才发布。
func TestKeySetHandlerSymmetricOptIn(t *testing.T) {
	octKey := mustGenerate(t, "HS256")
	octKey.Kid = "internal-oct"
	edKey := mustGenerate(t, "EdDSA").Public()
	edKey.Kid = "public-ed"
	set := &KeySet{Keys: []*Key{edKey, octKey}}

	rec := httptest.NewRecorder()
	set.HandlerWithOptions(HandlerOptions{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=3600" {
		t.Fatalf("default Cache-Control = %q, want public, max-age=3600", got)
	}
	if body := rec.Body.String(); strings.Contains(body, `"k":`) || strings.Contains(body, "internal-oct") {
		t.Fatalf("默认 HandlerWithOptions 发布了对称密钥: %s", body)
	}

	rec = httptest.NewRecorder()
	set.HandlerWithOptions(HandlerOptions{IncludeSymmetricKeys: true, MaxAge: time.Minute}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/internal/jwks.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=60" {
		t.Fatalf("Cache-Control = %q, want public, max-age=60", got)
	}
	if body := rec.Body.String(); !strings.Contains(body, `"k":`) {
		t.Fatalf("IncludeSymmetricKeys 未发布对称密钥: %s", body)
	}
	parsed, err := ParseKeySet(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("ParseKeySet failed: %v", err)
	}
	if len(parsed.Keys) != 2 {
		t.Fatalf("published key count = %d, want 2", len(parsed.Keys))
	}
	if octKey.K == "" {
		t.Fatal("handler 修改了调用方的对称密钥")
	}

	// A malformed key with no kty cannot be classified and might carry "k" or private members; the
	// default projection must drop it instead of serializing it. |
	// 没有 kty 的畸形密钥无法分类，且可能携带 "k" 或私钥成员；默认投影必须丢弃它而不是序列化。
	malformed := &KeySet{Keys: []*Key{{Kid: "no-kty", K: EncodeSegment(testSecretBytes())}}}
	rec = httptest.NewRecorder()
	malformed.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if body := rec.Body.String(); strings.Contains(body, `"k":`) || strings.Contains(body, "no-kty") {
		t.Fatalf("默认投影发布了无法分类的密钥: %s", body)
	}
}

func TestCacheRotationAndRefresh(t *testing.T) {
	k1, _ := FromHMAC("k1", bytes.Repeat([]byte{0x01}, 32))
	k2, _ := FromHMAC("k2", bytes.Repeat([]byte{0x02}, 32))
	set1 := &KeySet{Keys: []*Key{k1}}
	set2 := &KeySet{Keys: []*Key{k2}}

	cache := NewCache(set1)
	if _, err := cache.Get("k1"); err != nil {
		t.Fatalf("Get(k1) failed: %v", err)
	}
	if _, err := cache.Get("k2"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Get(k2) error = %v, want ErrKeyNotFound", err)
	}
	if cache.Snapshot() == nil {
		t.Fatal("Snapshot is nil after NewCache")
	}

	cache.Set(set2)
	if _, err := cache.Get("k1"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Get(k1) after rotation error = %v, want ErrKeyNotFound", err)
	}
	if k, err := cache.Get("k2"); err != nil || k.Kid != "k2" {
		t.Fatalf("Get(k2) after rotation = %v, %v", k, err)
	}

	failing := KeySetSourceFunc(func(context.Context) (*KeySet, error) {
		return nil, ErrFetchFailed
	})
	if err := cache.Refresh(context.Background(), nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Refresh(nil) error = %v, want ErrInvalidConfig", err)
	}
	if err := cache.Refresh(context.Background(), failing); !errors.Is(err, ErrFetchFailed) {
		t.Fatalf("Refresh(failing) error = %v, want ErrFetchFailed", err)
	}
	if _, err := cache.Get("k2"); err != nil {
		t.Fatalf("failed refresh changed the cache: %v", err)
	}
	if err := cache.Refresh(context.Background(), KeySetSourceFunc(func(context.Context) (*KeySet, error) {
		return set1, nil
	})); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}
	if _, err := cache.Get("k1"); err != nil {
		t.Fatalf("Get(k1) after refresh failed: %v", err)
	}

	empty := NewCache(nil)
	if empty.Snapshot() != nil {
		t.Fatal("NewCache(nil) is not empty")
	}
}

func TestCacheConcurrentRotation(t *testing.T) {
	k1, _ := FromHMAC("k1", bytes.Repeat([]byte{0x01}, 32))
	k2, _ := FromHMAC("k2", bytes.Repeat([]byte{0x02}, 32))
	sets := []*KeySet{{Keys: []*Key{k1}}, {Keys: []*Key{k2}}}
	cache := NewCache(sets[0])

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = cache.Get("k1")
					_ = cache.Snapshot()
				}
			}
		}()
	}
	var writers sync.WaitGroup
	for i := 0; i < 4; i++ {
		writers.Add(1)
		go func(n int) {
			defer writers.Done()
			for j := 0; j < 200; j++ {
				cache.Set(sets[(n+j)%2])
				_, _ = cache.Get("k2")
			}
		}(i)
	}
	writers.Wait()
	close(stop)
	readers.Wait()
}
