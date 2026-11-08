package oauth2

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
)

func TestServerCleanupExpiredState(t *testing.T) {
	now := flowNow
	nonceStore := NewMemoryDPoPNonceStore()
	verifier := NewDPoPProofVerifier(DPoPVerifierConfig{
		Now:          func() time.Time { return now },
		RequireNonce: true,
	})
	server, client := grantServer(t, func(config *ServerConfig) {
		config.Clock = func() time.Time { return now }
		config.DPoPNonceStore = nonceStore
		config.DPoPVerifier = verifier
	})
	ctx := context.Background()
	store := server.config.Store
	expired := now.Add(-time.Minute)
	live := now.Add(time.Hour)

	if err := store.SaveAuthorizationCode(ctx, &AuthorizationCode{
		CodeHash: auth.HashToken("expired-code"), ClientID: client.ID, ExpiresAt: expired,
	}); err != nil {
		t.Fatalf("save expired code: %v", err)
	}
	if err := store.SaveAuthorizationCode(ctx, &AuthorizationCode{
		CodeHash: auth.HashToken("live-code"), ClientID: client.ID, ExpiresAt: live,
	}); err != nil {
		t.Fatalf("save live code: %v", err)
	}
	if err := store.SaveRefreshToken(ctx, &RefreshToken{
		TokenHash: auth.HashToken("expired-refresh"), ClientID: client.ID, ExpiresAt: expired,
	}); err != nil {
		t.Fatalf("save expired refresh: %v", err)
	}
	if err := store.SaveRefreshToken(ctx, &RefreshToken{
		TokenHash: auth.HashToken("live-refresh"), ClientID: client.ID, ExpiresAt: live,
	}); err != nil {
		t.Fatalf("save live refresh: %v", err)
	}
	if err := store.SaveAccessToken(ctx, &AccessToken{
		TokenHash: auth.HashToken("expired-access"), ClientID: client.ID, ExpiresAt: expired,
	}); err != nil {
		t.Fatalf("save expired access: %v", err)
	}
	if err := store.SaveAccessToken(ctx, &AccessToken{
		TokenHash: auth.HashToken("live-access"), ClientID: client.ID, ExpiresAt: live,
	}); err != nil {
		t.Fatalf("save live access: %v", err)
	}
	if err := store.SaveDeviceCode(ctx, &DeviceCode{
		DeviceCodeHash: auth.HashToken("expired-device"), UserCode: "EXPIRED", ClientID: client.ID,
		Status: DevicePending, ExpiresAt: expired,
	}); err != nil {
		t.Fatalf("save expired device: %v", err)
	}
	if err := store.SaveDeviceCode(ctx, &DeviceCode{
		DeviceCodeHash: auth.HashToken("live-device"), UserCode: "LIVE", ClientID: client.ID,
		Status: DevicePending, ExpiresAt: live,
	}); err != nil {
		t.Fatalf("save live device: %v", err)
	}
	if err := store.SavePAR(ctx, &PARRequest{RequestURI: PARRequestURIPrefix + "expired", ClientID: client.ID, ExpiresAt: expired}); err != nil {
		t.Fatalf("save expired PAR: %v", err)
	}
	if err := store.SavePAR(ctx, &PARRequest{RequestURI: PARRequestURIPrefix + "live", ClientID: client.ID, ExpiresAt: live}); err != nil {
		t.Fatalf("save live PAR: %v", err)
	}

	server.requestURIs.mu.Lock()
	server.requestURIs.entries["urn:expired"] = cachedRequestObject{body: "old", expires: expired}
	server.requestURIs.entries["urn:live"] = cachedRequestObject{body: "new", expires: live}
	server.requestURIs.used["urn:single-use-expired"] = expired
	server.requestURIs.used["urn:single-use-live"] = live
	server.requestURIs.mu.Unlock()

	if _, err := nonceStore.Issue(ctx, now.Add(-10*time.Minute), time.Minute); err != nil {
		t.Fatalf("issue expired server nonce: %v", err)
	}
	liveNonce, err := nonceStore.Issue(ctx, now, time.Hour)
	if err != nil {
		t.Fatalf("issue live server nonce: %v", err)
	}
	verifierStore, ok := verifier.config.Nonces.(*MemoryDPoPNonceStore)
	if !ok {
		t.Fatalf("verifier nonce store = %T", verifier.config.Nonces)
	}
	if _, err := verifierStore.Issue(ctx, now.Add(-10*time.Minute), time.Minute); err != nil {
		t.Fatalf("issue expired verifier nonce: %v", err)
	}
	verifierNonce, err := verifierStore.Issue(ctx, now, time.Hour)
	if err != nil {
		t.Fatalf("issue live verifier nonce: %v", err)
	}

	if err := server.Cleanup(nil); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	if _, err := store.ConsumeAuthorizationCode(ctx, auth.HashToken("expired-code"), now); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expired code survived: %v", err)
	}
	if _, err := store.ConsumeAuthorizationCode(ctx, auth.HashToken("live-code"), now); err != nil {
		t.Fatalf("live code removed: %v", err)
	}
	if _, err := store.GetRefreshToken(ctx, auth.HashToken("expired-refresh")); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expired refresh survived: %v", err)
	}
	if _, err := store.GetRefreshToken(ctx, auth.HashToken("live-refresh")); err != nil {
		t.Fatalf("live refresh removed: %v", err)
	}
	if _, err := store.GetAccessToken(ctx, auth.HashToken("expired-access")); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expired access survived: %v", err)
	}
	if _, err := store.GetAccessToken(ctx, auth.HashToken("live-access")); err != nil {
		t.Fatalf("live access removed: %v", err)
	}
	if _, err := store.GetDeviceCode(ctx, auth.HashToken("expired-device")); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expired device survived: %v", err)
	}
	if _, err := store.GetDeviceCode(ctx, auth.HashToken("live-device")); err != nil {
		t.Fatalf("live device removed: %v", err)
	}
	if _, err := store.ConsumePAR(ctx, PARRequestURIPrefix+"expired", now); err == nil {
		t.Fatal("expired PAR survived")
	}
	if _, err := store.ConsumePAR(ctx, PARRequestURIPrefix+"live", now); err != nil {
		t.Fatalf("live PAR removed: %v", err)
	}

	server.requestURIs.mu.Lock()
	_, expiredEntry := server.requestURIs.entries["urn:expired"]
	_, liveEntry := server.requestURIs.entries["urn:live"]
	_, expiredUse := server.requestURIs.used["urn:single-use-expired"]
	_, liveUse := server.requestURIs.used["urn:single-use-live"]
	server.requestURIs.mu.Unlock()
	if expiredEntry || !liveEntry {
		t.Fatalf("request_uri entries expired=%v live=%v", expiredEntry, liveEntry)
	}
	if expiredUse || !liveUse {
		t.Fatalf("request_uri used expired=%v live=%v", expiredUse, liveUse)
	}

	nonceStore.mu.Lock()
	serverNonceCount := len(nonceStore.nonces)
	nonceStore.mu.Unlock()
	if serverNonceCount != 1 {
		t.Fatalf("server nonce count = %d", serverNonceCount)
	}
	if ok, err := nonceStore.Accept(ctx, liveNonce, now); err != nil || !ok {
		t.Fatalf("live server nonce = %v err=%v", ok, err)
	}
	verifierStore.mu.Lock()
	verifierNonceCount := len(verifierStore.nonces)
	verifierStore.mu.Unlock()
	if verifierNonceCount != 1 {
		t.Fatalf("verifier nonce count = %d", verifierNonceCount)
	}
	if ok, err := verifierStore.Accept(ctx, verifierNonce, now); err != nil || !ok {
		t.Fatalf("live verifier nonce = %v err=%v", ok, err)
	}

	if err := server.Cleanup(ctx); err != nil {
		t.Fatalf("second cleanup: %v", err)
	}
}

func TestServerCleanupSchedulerLifecycle(t *testing.T) {
	server, _ := flowServer(t, nil)
	ctx := context.Background()

	var nilServer *Server
	if err := nilServer.StartCleanup(time.Minute); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil StartCleanup = %v", err)
	}
	nilServer.StopCleanup()
	if err := nilServer.Cleanup(ctx); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil Cleanup = %v", err)
	}

	// Stopping a server that never started is a no-op. | 停止从未启动的服务器是无操作。
	server.StopCleanup()

	if err := server.StartCleanup(time.Hour); err != nil {
		t.Fatalf("StartCleanup: %v", err)
	}
	server.cleanupMu.Lock()
	done := server.cleanupDone
	server.cleanupMu.Unlock()
	if done == nil {
		t.Fatal("StartCleanup did not register a done channel")
	}
	// A second start is a no-op and keeps the running scheduler. | 二次启动是无操作，并保留运行中的调度器。
	if err := server.StartCleanup(time.Minute); err != nil {
		t.Fatalf("second StartCleanup: %v", err)
	}
	server.cleanupMu.Lock()
	if server.cleanupDone != done {
		server.cleanupMu.Unlock()
		t.Fatal("second StartCleanup replaced the running scheduler")
	}
	server.cleanupMu.Unlock()
	server.StopCleanup()
	select {
	case <-done:
	default:
		t.Fatal("cleanup goroutine is still running after StopCleanup")
	}
	// Repeated stops are safe. | 重复停止是安全的。
	server.StopCleanup()

	// A non-positive interval selects the default instead of failing or spinning. | 非正间隔选择默认值，
	// 而不是失败或忙转。
	if err := server.StartCleanup(-time.Second); err != nil {
		t.Fatalf("StartCleanup default interval: %v", err)
	}
	server.StopCleanup()
}

func TestServerCleanupSchedulerRunsImmediately(t *testing.T) {
	now := flowNow
	server, client := grantServer(t, func(config *ServerConfig) {
		config.Clock = func() time.Time { return now }
	})
	ctx := context.Background()
	if err := server.config.Store.SaveAccessToken(ctx, &AccessToken{
		TokenHash: auth.HashToken("scheduled-expired"),
		ClientID:  client.ID,
		ExpiresAt: now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("save expired access: %v", err)
	}
	if err := server.StartCleanup(time.Hour); err != nil {
		t.Fatalf("StartCleanup: %v", err)
	}
	defer server.StopCleanup()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := server.config.Store.GetAccessToken(ctx, auth.HashToken("scheduled-expired")); errors.Is(err, ErrInvalidGrant) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("scheduled cleanup did not remove the expired token")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestServerCleanupConcurrentStartStop(t *testing.T) {
	server, _ := flowServer(t, nil)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if err := server.StartCleanup(time.Millisecond); err != nil {
					t.Errorf("concurrent StartCleanup: %v", err)
					return
				}
				server.StopCleanup()
			}
		}()
	}
	wg.Wait()
	server.StopCleanup()
	server.cleanupMu.Lock()
	defer server.cleanupMu.Unlock()
	if server.cleanupCancel != nil || server.cleanupDone != nil {
		t.Fatalf("scheduler state after stop = %v %v", server.cleanupCancel != nil, server.cleanupDone != nil)
	}
}
