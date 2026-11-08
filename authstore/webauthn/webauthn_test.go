package webauthn_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	authwebauthn "github.com/shibingli/ydx/auth/mfa/webauthn"
	webauthnstore "github.com/shibingli/ydx/authstore/webauthn"
	"github.com/shibingli/ydx/base64"
)

// testContext is the context shared by the store tests. | testContext 是存储测试共享的上下文。
var testContext = context.Background()

// newStoreOn creates one independent store against an existing miniredis. | newStoreOn 针对已有
// miniredis 创建一个独立的存储。
func newStoreOn(t *testing.T, server *miniredis.Miniredis, prefix string) *webauthnstore.Store {
	t.Helper()
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
	})
	store, err := webauthnstore.New(client, webauthnstore.Options{KeyPrefix: prefix})
	if err != nil {
		t.Fatalf("new store: %v | 创建存储失败", err)
	}
	return store
}

// newPair returns two independent stores sharing one miniredis, modelling two instances.
// | newPair 返回共享同一 miniredis 的两套独立存储，用于模拟两个实例。
func newPair(t *testing.T) (*webauthnstore.Store, *webauthnstore.Store) {
	t.Helper()
	server := miniredis.RunT(t)
	return newStoreOn(t, server, ""), newStoreOn(t, server, "")
}

// sampleCeremony returns a populated ceremony with a fixed challenge and lifetime.
// | sampleCeremony 返回带固定挑战与寿命的完整流程。
func sampleCeremony(expiresAt time.Time) *authwebauthn.Ceremony {
	challenge := []byte("0123456789abcdef0123456789abcdef")
	return &authwebauthn.Ceremony{
		ID:                 base64.RawURLEncoding.EncodeToString(challenge),
		Kind:               authwebauthn.CeremonyRegistration,
		Challenge:          challenge,
		UserID:             "user-1",
		UserHandle:         []byte("handle-1"),
		Username:           "alice",
		DisplayName:        "Alice",
		RPID:               "example.com",
		Origins:            []string{"https://example.com", "https://login.example.com"},
		Algorithms:         []int{authwebauthn.AlgES256, authwebauthn.AlgEdDSA},
		AllowCredentialIDs: [][]byte{[]byte("cred-1"), []byte("cred-2")},
		CredentialName:     "laptop",
		CreatedAt:          time.Now(),
		ExpiresAt:          expiresAt,
	}
}

// sampleCredential returns a valid credential with a deterministic ID and creation time.
// | sampleCredential 返回带确定性 ID 与创建时间的合法凭据。
func sampleCredential(t *testing.T, id string, userID string, createdAt time.Time) *authwebauthn.Credential {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v | 生成密钥失败", err)
	}
	return &authwebauthn.Credential{
		ID:              []byte(id),
		UserID:          userID,
		Username:        userID + "-name",
		UserDisplayName: userID + "-display",
		UserHandle:      []byte("handle-" + userID),
		PublicKey: &authwebauthn.COSEKey{
			Kty: authwebauthn.KeyTypeOKP,
			Kid: []byte("kid-" + id),
			Alg: authwebauthn.AlgEdDSA,
			Crv: authwebauthn.CurveEd25519,
			X:   []byte(publicKey),
		},
		SignCount:      3,
		AAGUID:         [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Transports:     []string{"usb", "nfc"},
		BackupEligible: true,
		BackupState:    false,
		Discoverable:   true,
		Disabled:       false,
		Name:           "laptop",
		CreatedAt:      createdAt,
		LastUsedAt:     createdAt.Add(time.Minute),
	}
}

// TestNewValidation covers constructor validation, the default prefix and interface conformance.
// | TestNewValidation 覆盖构造校验、默认前缀与接口符合性。
func TestNewValidation(t *testing.T) {
	if webauthnstore.DefaultKeyPrefix != "ydx:authstore:webauthn:" {
		t.Fatalf("DefaultKeyPrefix = %q | 默认前缀不正确", webauthnstore.DefaultKeyPrefix)
	}
	if _, err := webauthnstore.New(nil, webauthnstore.Options{}); !errors.Is(err, authwebauthn.ErrInvalidConfig) {
		t.Fatalf("nil client error = %v, want ErrInvalidConfig | nil 客户端错误不符", err)
	}
	server := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
	})
	if _, err := webauthnstore.New(client, webauthnstore.Options{KeyPrefix: "{bad"}); !errors.Is(err, authwebauthn.ErrInvalidConfig) {
		t.Fatalf("brace prefix error = %v, want ErrInvalidConfig | 花括号前缀错误不符", err)
	}
	store, err := webauthnstore.New(client, webauthnstore.Options{})
	if err != nil {
		t.Fatalf("new store: %v | 创建存储失败", err)
	}
	var challenges authwebauthn.ChallengeStore = store
	var credentials authwebauthn.CredentialStore = store
	var backup authwebauthn.BackupStateUpdater = store
	if challenges == nil || credentials == nil || backup == nil {
		t.Fatal("New returned a nil port | New 返回了空端口")
	}
}

// TestNewDoesNotDial verifies that New performs no network round trip. | TestNewDoesNotDial 验证
// New 不进行网络往返。
func TestNewDoesNotDial(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{
		Addr:        "127.0.0.1:1",
		MaxRetries:  -1,
		DialTimeout: 20 * time.Millisecond,
	})
	t.Cleanup(func() {
		_ = client.Close()
	})
	if _, err := webauthnstore.New(client, webauthnstore.Options{}); err != nil {
		t.Fatalf("New dialed: %v | New 不应连接网络", err)
	}
}

// TestKeyLayout verifies the default prefix, the shared hash tag and every length-prefixed key.
// | TestKeyLayout 验证默认前缀、共享哈希标签与全部长度前缀键。
func TestKeyLayout(t *testing.T) {
	server := miniredis.RunT(t)
	store := newStoreOn(t, server, webauthnstore.DefaultKeyPrefix)
	ceremony := sampleCeremony(time.Now().Add(time.Minute))
	if err := store.Put(testContext, ceremony); err != nil {
		t.Fatalf("put challenge: %v | 保存挑战失败", err)
	}
	credential := sampleCredential(t, "cred-layout", "user-layout", time.Now())
	if err := store.Save(testContext, credential); err != nil {
		t.Fatalf("save credential: %v | 保存凭据失败", err)
	}
	tag := "{authstore:webauthn}:"
	challenge := base64.RawURLEncoding.EncodeToString(ceremony.Challenge)
	credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)
	wantChallenge := webauthnstore.DefaultKeyPrefix + tag + "challenge:" +
		strconv.Itoa(len(challenge)) + ":" + challenge
	wantCredential := webauthnstore.DefaultKeyPrefix + tag + "credential:" +
		strconv.Itoa(len(credentialID)) + ":" + credentialID
	wantIndex := webauthnstore.DefaultKeyPrefix + tag + "idx:user:" +
		strconv.Itoa(len(credential.UserID)) + ":" + credential.UserID
	for _, key := range []string{wantChallenge, wantCredential, wantIndex} {
		if !server.Exists(key) {
			t.Fatalf("missing key %q in %v | 缺少键", key, server.Keys())
		}
	}
	members, err := server.Members(wantIndex)
	if err != nil || len(members) != 1 || members[0] != wantCredential {
		t.Fatalf("index members = %v/%v | 用户索引成员不正确", members, err)
	}
}

// TestPrefixIsolation runs two stores with distinct prefixes on one server.
// | TestPrefixIsolation 在同一服务器上运行两套不同前缀的存储。
func TestPrefixIsolation(t *testing.T) {
	server := miniredis.RunT(t)
	first := newStoreOn(t, server, "one:")
	second := newStoreOn(t, server, "two:")
	credential := sampleCredential(t, "cred-iso", "user-iso", time.Now())
	if err := first.Save(testContext, credential); err != nil {
		t.Fatalf("save first: %v | 第一前缀保存失败", err)
	}
	if _, err := second.GetByCredentialID(testContext, credential.ID); !errors.Is(err, authwebauthn.ErrCredentialNotFound) {
		t.Fatalf("second prefix saw first credential: %v | 第二前缀看到了第一前缀的凭据", err)
	}
	if err := second.Save(testContext, credential); err != nil {
		t.Fatalf("save second: %v | 第二前缀保存失败", err)
	}
	if err := first.UpdateSignCount(testContext, credential.ID, 99); err != nil {
		t.Fatalf("update first: %v | 第一前缀更新失败", err)
	}
	got, err := second.GetByCredentialID(testContext, credential.ID)
	if err != nil {
		t.Fatalf("get second: %v | 第二前缀读取失败", err)
	}
	if got.SignCount != credential.SignCount {
		t.Fatalf("second prefix sign count = %d | 前缀之间互相影响", got.SignCount)
	}
	ceremony := sampleCeremony(time.Now().Add(time.Minute))
	if err := first.Put(testContext, ceremony); err != nil {
		t.Fatalf("put first: %v | 第一前缀保存挑战失败", err)
	}
	challenge := base64.RawURLEncoding.EncodeToString(ceremony.Challenge)
	if _, err := second.Consume(testContext, challenge); !errors.Is(err, authwebauthn.ErrChallengeNotFound) {
		t.Fatalf("second prefix consumed first challenge: %v | 第二前缀消费了第一前缀的挑战", err)
	}
	if _, err := first.Consume(testContext, challenge); err != nil {
		t.Fatalf("first prefix consume: %v | 第一前缀消费失败", err)
	}
}

// TestBackendErrorsAreRedacted verifies classification and the absence of addresses.
// | TestBackendErrorsAreRedacted 验证错误分类且不泄露地址。
func TestBackendErrorsAreRedacted(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{
		Addr:        "127.0.0.1:1",
		MaxRetries:  -1,
		DialTimeout: 50 * time.Millisecond,
	})
	t.Cleanup(func() {
		_ = client.Close()
	})
	store, err := webauthnstore.New(client, webauthnstore.Options{})
	if err != nil {
		t.Fatalf("new store: %v | 创建存储失败", err)
	}
	credential := sampleCredential(t, "cred-dead", "user-dead", time.Now())
	ceremony := sampleCeremony(time.Now().Add(time.Minute))
	checks := []struct {
		name string
		err  error
	}{
		{"put", store.Put(testContext, ceremony)},
		{"consume", func() error {
			_, err := store.Consume(testContext, base64.RawURLEncoding.EncodeToString(ceremony.Challenge))
			return err
		}()},
		{"get", func() error {
			_, err := store.GetByCredentialID(testContext, credential.ID)
			return err
		}()},
		{"save", store.Save(testContext, credential)},
		{"sign count", store.UpdateSignCount(testContext, credential.ID, 1)},
		{"backup state", store.UpdateBackupState(testContext, credential.ID, true)},
		{"list", func() error {
			_, err := store.ListByUser(testContext, credential.UserID)
			return err
		}()},
	}
	for _, check := range checks {
		if !errors.Is(check.err, webauthnstore.ErrStoreUnavailable) {
			t.Fatalf("%s error = %v, want ErrStoreUnavailable | 后端错误未映射为存储不可用", check.name, check.err)
		}
		if strings.Contains(check.err.Error(), "127.0.0.1") || strings.Contains(check.err.Error(), ":1") {
			t.Fatalf("%s error leaked the address: %v | 错误泄露了地址", check.name, check.err)
		}
	}
}

// TestConcurrentReadsAreRaceFree exercises concurrent reads under the race detector.
// | TestConcurrentReadsAreRaceFree 在竞态检测器下执行并发读取。
func TestConcurrentReadsAreRaceFree(t *testing.T) {
	first, second := newPair(t)
	credential := sampleCredential(t, "cred-race-read", "user-race-read", time.Now())
	if err := first.Save(testContext, credential); err != nil {
		t.Fatalf("save: %v | 保存失败", err)
	}
	var wg sync.WaitGroup
	var failures atomic.Int64
	for i := 0; i < 32; i++ {
		store := first
		if i%2 == 1 {
			store = second
		}
		wg.Add(1)
		go func(store *webauthnstore.Store) {
			defer wg.Done()
			if _, err := store.GetByCredentialID(testContext, credential.ID); err != nil {
				failures.Add(1)
			}
			if _, err := store.ListByUser(testContext, credential.UserID); err != nil {
				failures.Add(1)
			}
		}(store)
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("read failures = %d | 并发读取失败次数非零", failures.Load())
	}
}
