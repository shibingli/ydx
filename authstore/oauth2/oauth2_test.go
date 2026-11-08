package oauth2_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	"github.com/shibingli/ydx/auth"
	authoauth2 "github.com/shibingli/ydx/auth/protocol/oauth2"
	oauth2store "github.com/shibingli/ydx/authstore/oauth2"
)

// testContext is the background context shared by tests. | testContext 是测试共享的后台上下文。
var testContext = context.Background()

// testTime returns a fixed UTC instant. | testTime 返回固定的 UTC 时刻。
func testTime(year int, month time.Month, day, hour, minute, second int) time.Time {
	return time.Date(year, month, day, hour, minute, second, 0, time.UTC)
}

// newClient returns one independent go-redis client against server. | newClient 针对 server 返回一个
// 独立 go-redis 客户端。
func newClient(t *testing.T, server *miniredis.Miniredis) goredis.UniversalClient {
	t.Helper()
	client := goredis.NewClient(&goredis.Options{
		Addr:        server.Addr(),
		MaxRetries:  -1,
		DialTimeout: 500 * time.Millisecond,
	})
	t.Cleanup(func() {
		_ = client.Close()
	})
	return client
}

// newStoresOn creates one store set on an existing server. | newStoresOn 在已有服务器上创建一套存储。
func newStoresOn(t *testing.T, server *miniredis.Miniredis, options oauth2store.Options) *oauth2store.Stores {
	t.Helper()
	stores, err := oauth2store.New(newClient(t, server), options)
	if err != nil {
		t.Fatalf("new stores: %v | 创建存储失败", err)
	}
	return stores
}

// newPair returns two independent store sets sharing one miniredis, modelling two application
// instances. | newPair 返回共享同一 miniredis 的两套独立存储，模拟两个应用实例。
func newPair(t *testing.T, options oauth2store.Options) (*oauth2store.Stores, *oauth2store.Stores) {
	t.Helper()
	server := miniredis.RunT(t)
	return newStoresOn(t, server, options), newStoresOn(t, server, options)
}

// samplePrincipal returns a fully populated principal. | samplePrincipal 返回字段完整的主体。
func samplePrincipal(subject string) *auth.Principal {
	at := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.FixedZone("CST", 8*3600))
	return &auth.Principal{
		Subject:     subject,
		Issuer:      "https://issuer.example",
		Audience:    []string{"api"},
		ClientID:    "client-1",
		Scopes:      []string{"openid"},
		Roles:       []string{"admin"},
		Attributes:  map[string]string{"dpop_jkt": "thumbprint-1", "tenant": "t1"},
		AuthTime:    at,
		ExpiresAt:   at.Add(time.Hour),
		IssuedAt:    at,
		Email:       subject + "@example.com",
		Username:    subject,
		DisplayName: subject,
	}
}

// sampleCode returns one authorization code with nested mutable data.
// | sampleCode 返回携带嵌套可变数据的授权码。
func sampleCode(hash string, expires time.Time) *authoauth2.AuthorizationCode {
	base := testTime(2026, time.February, 1, 10, 0, 0)
	return &authoauth2.AuthorizationCode{
		CodeHash:            hash,
		ClientID:            "client-1",
		RedirectURI:         "https://client.example/cb",
		RedirectURIProvided: true,
		Scopes:              []string{"openid", "profile"},
		UserID:              "user-1",
		Subject:             "subject-1",
		Nonce:               "nonce-1",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		AuthTime:            base,
		AMR:                 []string{"pwd"},
		Resource:            []string{"https://api.example"},
		Principal:           samplePrincipal("subject-1"),
		CreatedAt:           base,
		ExpiresAt:           expires,
	}
}

// sampleRefresh returns one refresh token. | sampleRefresh 返回一个刷新令牌。
func sampleRefresh(hash, family string, expires time.Time) *authoauth2.RefreshToken {
	base := testTime(2026, time.March, 1, 10, 0, 0)
	return &authoauth2.RefreshToken{
		TokenHash:  hash,
		FamilyID:   family,
		ClientID:   "client-1",
		UserID:     "user-1",
		Subject:    "subject-1",
		Principal:  samplePrincipal("subject-1"),
		Scopes:     []string{"openid", "offline_access"},
		Audience:   []string{"api"},
		AuthTime:   base,
		AMR:        []string{"pwd"},
		CreatedAt:  base,
		ExpiresAt:  expires,
		ParentHash: "parent",
	}
}

// sampleAccess returns one opaque access token. | sampleAccess 返回一个不透明访问令牌。
func sampleAccess(hash string, expires time.Time) *authoauth2.AccessToken {
	base := testTime(2026, time.April, 1, 10, 0, 0)
	return &authoauth2.AccessToken{
		TokenHash: hash,
		ClientID:  "client-1",
		UserID:    "user-1",
		Subject:   "subject-1",
		Principal: samplePrincipal("subject-1"),
		Scopes:    []string{"openid"},
		Audience:  []string{"api"},
		AuthTime:  base,
		AMR:       []string{"pwd"},
		IssuedAt:  base,
		ExpiresAt: expires,
		JTI:       "jti-" + hash,
		GrantID:   "grant-1",
	}
}

// sampleDevice returns one device authorization grant. | sampleDevice 返回一个设备授权许可。
func sampleDevice(code, user, clientID string, expires time.Time) *authoauth2.DeviceCode {
	base := testTime(2026, time.May, 1, 10, 0, 0)
	return &authoauth2.DeviceCode{
		DeviceCodeHash: code,
		UserCode:       user,
		ClientID:       clientID,
		Scopes:         []string{"openid"},
		Audience:       []string{"api"},
		Status:         authoauth2.DevicePending,
		Interval:       5 * time.Second,
		CreatedAt:      base,
		ExpiresAt:      expires,
	}
}

// samplePAR returns one pushed authorization request. | samplePAR 返回一个推送授权请求。
func samplePAR(uri string, expires time.Time) *authoauth2.PARRequest {
	base := testTime(2026, time.June, 1, 10, 0, 0)
	return &authoauth2.PARRequest{
		RequestURI: uri,
		ClientID:   "client-1",
		Params: map[string][]string{
			"scope":         {"openid", "profile"},
			"response_type": {"code"},
		},
		CreatedAt: base,
		ExpiresAt: expires,
	}
}

// sampleClient returns one client registration with nested mutable data.
// | sampleClient 返回携带嵌套可变数据的客户端注册。
func sampleClient(id string) *authoauth2.Client {
	base := testTime(2026, time.July, 1, 10, 0, 0)
	return &authoauth2.Client{
		ID:                          id,
		Name:                        "Client " + id,
		SecretHash:                  "secret-" + id,
		RedirectURIs:                []string{"https://" + id + ".example/cb"},
		GrantTypes:                  []string{"authorization_code", "refresh_token"},
		ResponseTypes:               []string{"code"},
		Scopes:                      []string{"openid", "profile"},
		Public:                      false,
		AccessTokenTTL:              15 * time.Minute,
		RefreshTokenTTL:             24 * time.Hour,
		AuthorizationCodeTTL:        5 * time.Minute,
		JWKS:                        []byte(`{"keys":[]}`),
		PostLogoutRedirectURIs:      []string{"https://" + id + ".example/logout"},
		Contacts:                    []string{id + "@example.com"},
		Metadata:                    map[string]string{"tenant": "t1"},
		CreatedAt:                   base,
		UpdatedAt:                   base,
		RegistrationClientURI:       "https://issuer.example/register/" + id,
		RegistrationAccessTokenHash: "registration-" + id,
	}
}

// TestNewValidation covers constructor validation and the default prefix.
// | TestNewValidation 覆盖构造校验与默认前缀。
func TestNewValidation(t *testing.T) {
	if oauth2store.DefaultKeyPrefix != "ydx:authstore:oauth2:" {
		t.Fatalf("DefaultKeyPrefix = %q | 默认前缀不正确", oauth2store.DefaultKeyPrefix)
	}
	if _, err := oauth2store.New(nil, oauth2store.Options{}); !errors.Is(err, auth.ErrInvalidConfig) {
		t.Fatalf("nil client error = %v, want ErrInvalidConfig | nil 客户端错误不符", err)
	}
	server := miniredis.RunT(t)
	client := newClient(t, server)
	if _, err := oauth2store.New(client, oauth2store.Options{KeyPrefix: "bad{prefix"}); !errors.Is(err, auth.ErrInvalidConfig) {
		t.Fatalf("brace prefix error = %v, want ErrInvalidConfig | 花括号前缀错误不符", err)
	}
	if _, err := oauth2store.New(client, oauth2store.Options{KeyPrefix: "bad}prefix"}); !errors.Is(err, auth.ErrInvalidConfig) {
		t.Fatalf("brace prefix error = %v, want ErrInvalidConfig | 花括号前缀错误不符", err)
	}
	stores, err := oauth2store.New(client, oauth2store.Options{})
	if err != nil {
		t.Fatalf("new stores: %v | 创建存储失败", err)
	}
	if stores.Store == nil || stores.Clients == nil || stores.DPoPNonces == nil ||
		stores.DPoPReplay == nil || stores.Scopes == nil {
		t.Fatal("New returned a nil port | New 返回了空端口")
	}
	var _ authoauth2.Store = stores.Store
	var _ authoauth2.ClientStore = stores.Clients
	var _ authoauth2.DPoPReplayStore = stores.DPoPReplay
	var _ authoauth2.DPoPNonceStore = stores.DPoPNonces
}

// TestNewDoesNotDial verifies that New performs no network round trip.
// | TestNewDoesNotDial 验证 New 不进行网络往返。
func TestNewDoesNotDial(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:1", MaxRetries: -1, DialTimeout: 50 * time.Millisecond})
	t.Cleanup(func() {
		_ = client.Close()
	})
	stores, err := oauth2store.New(client, oauth2store.Options{})
	if err != nil {
		t.Fatalf("New dialed: %v | New 不应连接网络", err)
	}
	if stores.Scopes == nil {
		t.Fatal("New returned no scope registry | New 未返回作用域注册表")
	}
}

// TestStoresMapBackendErrors verifies that every port classifies a closed backend as
// ErrStoreUnavailable. | TestStoresMapBackendErrors 验证每个端口都把已关闭后端归类为
// ErrStoreUnavailable。
func TestStoresMapBackendErrors(t *testing.T) {
	server := miniredis.RunT(t)
	stores := newStoresOn(t, server, oauth2store.Options{})
	server.Close()
	base := testTime(2026, time.August, 1, 10, 0, 0)
	operations := []struct {
		name string
		call func() error
	}{
		{"codes.save", func() error {
			return stores.Store.SaveAuthorizationCode(testContext, sampleCode("h", base.Add(time.Hour)))
		}},
		{"codes.consume", func() error {
			_, err := stores.Store.ConsumeAuthorizationCode(testContext, "h", base)
			return err
		}},
		{"refresh.save", func() error {
			return stores.Store.SaveRefreshToken(testContext, sampleRefresh("r", "f", base.Add(time.Hour)))
		}},
		{"refresh.get", func() error { _, err := stores.Store.GetRefreshToken(testContext, "r"); return err }},
		{"refresh.rotate", func() error {
			_, err := stores.Store.RotateRefreshToken(testContext, "r", sampleRefresh("r2", "f", base.Add(time.Hour)), base)
			return err
		}},
		{"refresh.revoke", func() error { return stores.Store.RevokeRefreshToken(testContext, "r", false) }},
		{"refresh.revoke-subject", func() error {
			_, err := stores.Store.RevokeRefreshTokensForSubject(testContext, "client-1", "subject-1")
			return err
		}},
		{"access.save", func() error { return stores.Store.SaveAccessToken(testContext, sampleAccess("a", base.Add(time.Hour))) }},
		{"access.get", func() error { _, err := stores.Store.GetAccessToken(testContext, "a"); return err }},
		{"access.revoke", func() error { return stores.Store.RevokeAccessToken(testContext, "a") }},
		{"device.save", func() error {
			return stores.Store.SaveDeviceCode(testContext, sampleDevice("d", "u", "client-1", base.Add(time.Hour)))
		}},
		{"device.get-user", func() error { _, err := stores.Store.GetDeviceCodeByUserCode(testContext, "u"); return err }},
		{"device.get", func() error { _, err := stores.Store.GetDeviceCode(testContext, "d"); return err }},
		{"device.update", func() error {
			return stores.Store.UpdateDeviceCode(testContext, sampleDevice("d", "u", "client-1", base.Add(time.Hour)))
		}},
		{"device.poll", func() error { _, _, err := stores.Store.PollDeviceCode(testContext, "d", "client-1", base); return err }},
		{"device.set-status", func() error {
			_, err := stores.Store.SetDeviceCodeStatus(testContext, "u", authoauth2.DeviceDenied, base, nil)
			return err
		}},
		{"par.save", func() error { return stores.Store.SavePAR(testContext, samplePAR("urn:par:1", base.Add(time.Hour))) }},
		{"par.consume", func() error { _, err := stores.Store.ConsumePAR(testContext, "urn:par:1", base); return err }},
		{"cleanup", func() error { return stores.Store.Cleanup(testContext, base) }},
		{"clients.create", func() error { return stores.Clients.CreateClient(testContext, sampleClient("c1")) }},
		{"clients.get", func() error { _, err := stores.Clients.GetClient(testContext, "c1"); return err }},
		{"clients.update", func() error { return stores.Clients.UpdateClient(testContext, sampleClient("c1")) }},
		{"clients.delete", func() error { return stores.Clients.DeleteClient(testContext, "c1") }},
		{"clients.list", func() error { _, err := stores.Clients.ListClients(testContext); return err }},
		{"nonces.issue", func() error { _, err := stores.DPoPNonces.Issue(testContext, base, time.Minute); return err }},
		{"nonces.accept", func() error { _, err := stores.DPoPNonces.Accept(testContext, "n", base); return err }},
		{"replay.accept", func() error {
			_, err := stores.DPoPReplay.Accept(testContext, "jti", base.Add(time.Minute))
			return err
		}},
		{"scopes.reload", func() error { return stores.Scopes.Reload(testContext) }},
	}
	for _, operation := range operations {
		if err := operation.call(); !errors.Is(err, auth.ErrStoreUnavailable) {
			t.Fatalf("%s error = %v, want ErrStoreUnavailable | %s 错误未映射为存储不可用", operation.name, err, operation.name)
		}
	}
}

// TestContextCancellation verifies that a canceled context is returned unchanged.
// | TestContextCancellation 验证取消的上下文被原样返回。
func TestContextCancellation(t *testing.T) {
	stores := newStoresOn(t, miniredis.RunT(t), oauth2store.Options{})
	canceled, cancel := context.WithCancel(testContext)
	cancel()
	if _, err := stores.Store.GetRefreshToken(canceled, "unknown"); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled | 错误未返回上下文取消", err)
	}
	if _, err := stores.Clients.ListClients(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled | 错误未返回上下文取消", err)
	}
	if _, err := stores.DPoPNonces.Issue(canceled, testTime(2026, time.January, 1, 0, 0, 0), time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled | 错误未返回上下文取消", err)
	}
}

// TestPrefixIsolation runs two store sets with distinct prefixes on one server.
// | TestPrefixIsolation 在同一服务器上运行两套不同前缀的存储。
func TestPrefixIsolation(t *testing.T) {
	server := miniredis.RunT(t)
	first := newStoresOn(t, server, oauth2store.Options{KeyPrefix: "one:"})
	second := newStoresOn(t, server, oauth2store.Options{KeyPrefix: "two:"})
	base := testTime(2026, time.September, 1, 10, 0, 0)
	if err := first.Store.SaveAccessToken(testContext, sampleAccess("shared-hash", base.Add(time.Hour))); err != nil {
		t.Fatalf("save first: %v | 第一套保存失败", err)
	}
	if _, err := second.Store.GetAccessToken(testContext, "shared-hash"); !errors.Is(err, authoauth2.ErrInvalidGrant) {
		t.Fatalf("second prefix saw the first token: %v | 第二前缀看到了第一前缀的令牌", err)
	}
	if err := second.Clients.CreateClient(testContext, sampleClient("same-id")); err != nil {
		t.Fatalf("create second: %v | 第二套创建失败", err)
	}
	if _, err := first.Clients.GetClient(testContext, "same-id"); !errors.Is(err, authoauth2.ErrInvalidClient) {
		t.Fatalf("first prefix saw the second client: %v | 第一前缀看到了第二前缀的客户端", err)
	}
}

// TestDeepCopiesAndUTC verifies that reads do not share mutable data with the store and that all
// times come back as UTC. | TestDeepCopiesAndUTC 验证读取不与存储共享可变数据，且所有时间以 UTC 返回。
func TestDeepCopiesAndUTC(t *testing.T) {
	stores := newStoresOn(t, miniredis.RunT(t), oauth2store.Options{})
	base := testTime(2026, time.October, 1, 10, 0, 0)
	access := sampleAccess("deep-access", base.Add(time.Hour))
	issued := access.IssuedAt
	if err := stores.Store.SaveAccessToken(testContext, access); err != nil {
		t.Fatalf("save access: %v | 保存访问令牌失败", err)
	}
	access.Scopes[0] = "mutated-by-caller"
	got, err := stores.Store.GetAccessToken(testContext, "deep-access")
	if err != nil {
		t.Fatalf("get access: %v | 读取访问令牌失败", err)
	}
	if got.Scopes[0] != "openid" {
		t.Fatalf("stored access token aliased the caller slice: %v | 存储的访问令牌与调用方切片共享内存", got.Scopes)
	}
	got.Scopes[0] = "mutated-by-reader"
	got.Principal.Attributes["tenant"] = "mutated"
	again, err := stores.Store.GetAccessToken(testContext, "deep-access")
	if err != nil {
		t.Fatalf("get access again: %v | 再次读取访问令牌失败", err)
	}
	if again.Scopes[0] != "openid" || again.Principal.Attributes["tenant"] != "t1" {
		t.Fatalf("read result aliased store state: %v / %v | 读取结果与存储状态共享内存", again.Scopes, again.Principal.Attributes)
	}
	if again.IssuedAt.Location() != time.UTC || again.Principal.AuthTime.Location() != time.UTC {
		t.Fatalf("times are not UTC: %v / %v | 时间未规范化为 UTC", again.IssuedAt.Location(), again.Principal.AuthTime.Location())
	}
	if !again.IssuedAt.Equal(issued) {
		t.Fatalf("instant changed: %v | 时刻发生变化", again.IssuedAt)
	}

	client := sampleClient("deep-client")
	if err := stores.Clients.CreateClient(testContext, client); err != nil {
		t.Fatalf("create client: %v | 创建客户端失败", err)
	}
	client.Metadata["tenant"] = "mutated-by-caller"
	stored, err := stores.Clients.GetClient(testContext, "deep-client")
	if err != nil {
		t.Fatalf("get client: %v | 读取客户端失败", err)
	}
	if stored.Metadata["tenant"] != "t1" || stored.SecretHash != "secret-deep-client" {
		t.Fatalf("client hidden fields or maps were lost: %+v | 客户端隐藏字段或映射丢失", stored)
	}
	if stored.CreatedAt.Location() != time.UTC {
		t.Fatalf("client time is not UTC: %v | 客户端时间未规范化为 UTC", stored.CreatedAt.Location())
	}
}

// TestTwoInstancesShareState covers cross-instance reads and writes.
// | TestTwoInstancesShareState 覆盖跨实例读写。
func TestTwoInstancesShareState(t *testing.T) {
	first, second := newPair(t, oauth2store.Options{})
	if err := first.Clients.CreateClient(testContext, sampleClient("shared-client")); err != nil {
		t.Fatalf("create: %v | 创建失败", err)
	}
	got, err := second.Clients.GetClient(testContext, "shared-client")
	if err != nil {
		t.Fatalf("cross-instance get: %v | 跨实例读取失败", err)
	}
	if got.ID != "shared-client" {
		t.Fatalf("id = %q | ID 不符", got.ID)
	}
	got.Name = "Updated"
	if err := second.Clients.UpdateClient(testContext, got); err != nil {
		t.Fatalf("cross-instance update: %v | 跨实例更新失败", err)
	}
	back, err := first.Clients.GetClient(testContext, "shared-client")
	if err != nil || back.Name != "Updated" {
		t.Fatalf("first instance did not see the update: %v / %q | 第一实例未看到更新", err, back.Name)
	}
}

// TestConcurrentExactlyOnce verifies single-use guards across two instances.
// | TestConcurrentExactlyOnce 验证跨两个实例的单次使用保护。
func TestConcurrentExactlyOnce(t *testing.T) {
	first, second := newPair(t, oauth2store.Options{})
	base := testTime(2026, time.December, 1, 10, 0, 0)
	const workers = 32

	code := sampleCode("race-code", base.Add(time.Hour))
	if err := first.Store.SaveAuthorizationCode(testContext, code); err != nil {
		t.Fatalf("save code: %v | 保存授权码失败", err)
	}
	var codeWins int
	var codeMu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		stores := first
		if i%2 == 1 {
			stores = second
		}
		wg.Add(1)
		go func(s *oauth2store.Stores) {
			defer wg.Done()
			if _, err := s.Store.ConsumeAuthorizationCode(testContext, "race-code", base); err == nil {
				codeMu.Lock()
				codeWins++
				codeMu.Unlock()
			}
		}(stores)
	}
	wg.Wait()
	if codeWins != 1 {
		t.Fatalf("authorization code consumed %d times, want 1 | 授权码被消费 %d 次，期望 1 次", codeWins, codeWins)
	}

	refresh := sampleRefresh("race-refresh", "race-family", base.Add(time.Hour))
	if err := first.Store.SaveRefreshToken(testContext, refresh); err != nil {
		t.Fatalf("save refresh: %v | 保存刷新令牌失败", err)
	}
	var rotateWins int
	var rotateMu sync.Mutex
	for i := 0; i < workers; i++ {
		stores := first
		if i%2 == 1 {
			stores = second
		}
		wg.Add(1)
		go func(s *oauth2store.Stores, n int) {
			defer wg.Done()
			replacement := sampleRefresh("race-refresh-child-"+string(rune('a'+n%26)), "race-family", base.Add(2*time.Hour))
			ok, err := s.Store.RotateRefreshToken(testContext, "race-refresh", replacement, base)
			if err == nil && ok {
				rotateMu.Lock()
				rotateWins++
				rotateMu.Unlock()
			}
		}(stores, i)
	}
	wg.Wait()
	if rotateWins != 1 {
		t.Fatalf("refresh token rotated %d times, want 1 | 刷新令牌被轮换 %d 次，期望 1 次", rotateWins, rotateWins)
	}

	par := samplePAR("urn:ietf:params:oauth:request_uri:race", base.Add(time.Hour))
	if err := first.Store.SavePAR(testContext, par); err != nil {
		t.Fatalf("save par: %v | 保存推送授权请求失败", err)
	}
	var parWins int
	var parMu sync.Mutex
	for i := 0; i < workers; i++ {
		stores := first
		if i%2 == 1 {
			stores = second
		}
		wg.Add(1)
		go func(s *oauth2store.Stores) {
			defer wg.Done()
			if _, err := s.Store.ConsumePAR(testContext, "urn:ietf:params:oauth:request_uri:race", base); err == nil {
				parMu.Lock()
				parWins++
				parMu.Unlock()
			}
		}(stores)
	}
	wg.Wait()
	if parWins != 1 {
		t.Fatalf("PAR consumed %d times, want 1 | 推送授权请求被消费 %d 次，期望 1 次", parWins, parWins)
	}

	var clientWins int
	var clientMu sync.Mutex
	for i := 0; i < workers; i++ {
		stores := first
		if i%2 == 1 {
			stores = second
		}
		wg.Add(1)
		go func(s *oauth2store.Stores) {
			defer wg.Done()
			if err := s.Clients.CreateClient(testContext, sampleClient("race-client")); err == nil {
				clientMu.Lock()
				clientWins++
				clientMu.Unlock()
			}
		}(stores)
	}
	wg.Wait()
	if clientWins != 1 {
		t.Fatalf("client created %d times, want 1 | 客户端被创建 %d 次，期望 1 次", clientWins, clientWins)
	}
}
