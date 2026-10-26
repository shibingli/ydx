package redisstore

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	"github.com/shibingli/ydx/captcha/core"
	"github.com/shibingli/ydx/captcha/service"
)

func testClient(t *testing.T) (*miniredis.Miniredis, goredis.UniversalClient) {
	t.Helper()
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
		server.Close()
	})
	return server, client
}

func TestStoreAndImageStore(t *testing.T) {
	_, client := testClient(t)
	store, err := NewStore(StoreOptions{Client: client, Prefix: "test:"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := store.Put(ctx, "k", []byte("value"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if ok, err := store.PutIfAbsent(ctx, "k", []byte("other"), time.Minute); err != nil || ok {
		t.Fatalf("PutIfAbsent over existing key: %v %v", ok, err)
	}
	if ok, err := store.DeleteIf(ctx, "k", []byte("other")); err != nil || ok {
		t.Fatalf("mismatched DeleteIf: %v %v", ok, err)
	}
	value, ok, err := store.Get(ctx, "k")
	if err != nil || !ok || string(value) != "value" {
		t.Fatalf("Get: %q %v %v", value, ok, err)
	}
	if ok, err := store.PutIfAbsent(ctx, "nx", []byte("token"), time.Minute); err != nil || !ok {
		t.Fatalf("PutIfAbsent new key: %v %v", ok, err)
	}
	if ok, err := store.DeleteIf(ctx, "nx", []byte("token")); err != nil || !ok {
		t.Fatalf("matching DeleteIf: %v %v", ok, err)
	}
	value, ok, err = store.Take(ctx, "k")
	if err != nil || !ok || string(value) != "value" {
		t.Fatalf("Take: %q %v %v", value, ok, err)
	}
	if _, ok, _ := store.Take(ctx, "k"); ok {
		t.Fatal("Take returned the value twice")
	}

	images, err := NewImageStore(ImageStoreOptions{Client: client, Prefix: "test:"})
	if err != nil {
		t.Fatal(err)
	}
	if err := images.Put(ctx, "img", []byte{1, 2, 3}, "image/png", time.Minute); err != nil {
		t.Fatal(err)
	}
	data, mime, ok, err := images.Get(ctx, "img")
	if err != nil || !ok || mime != "image/png" || len(data) != 3 {
		t.Fatalf("image Get: %v %q %v %v", data, mime, ok, err)
	}
	if err := images.Delete(ctx, "img"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, _ := images.Get(ctx, "img"); ok {
		t.Fatal("image still present")
	}
}

func TestPolicyProviderMissingKeyFailsClosed(t *testing.T) {
	_, client := testClient(t)
	provider, err := NewPolicyProvider(client, "missing-policy")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.LoadPolicy(context.Background()); err == nil {
		t.Fatal("expected missing policy error")
	}
}

func TestPolicyProvider(t *testing.T) {
	_, client := testClient(t)
	provider, err := NewPolicyProvider(client, "policy")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	policy := &core.Policy{Deny: []core.Rule{{IP: "203.0.113.0/24"}}}
	if err := provider.StorePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	loaded, err := provider.LoadPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Deny) != 1 || loaded.Deny[0].IP != "203.0.113.0/24" {
		t.Fatalf("policy = %+v", loaded)
	}
}

func TestErrorsAndRateLimitStore(t *testing.T) {
	if _, err := NewStore(StoreOptions{}); err == nil {
		t.Fatal("expected nil client error")
	}
	if _, err := NewImageStore(ImageStoreOptions{}); err == nil {
		t.Fatal("expected nil client error")
	}
	if _, err := NewPolicyProvider(nil, ""); err == nil {
		t.Fatal("expected nil client error")
	}
	_, client := testClient(t)
	store, err := NewRateLimitStore(client, "")
	if err != nil {
		t.Fatal(err)
	}
	decision, err := store.Allow(context.Background(), "ip", 1, 1)
	if err != nil || !decision.Allowed {
		t.Fatalf("rate limit: %+v %v", decision, err)
	}
	missingStore, err := NewStore(StoreOptions{Client: client})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := missingStore.Get(context.Background(), "missing"); err != nil || ok {
		t.Fatalf("missing key: ok=%v err=%v", ok, err)
	}
}

func TestPolicyBusAppliesSnapshot(t *testing.T) {
	_, client := testClient(t)
	bus, err := NewPolicyBus(client, "policy-events")
	if err != nil {
		t.Fatal(err)
	}
	manager, err := service.New(service.Options{Secret: []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = bus.Watch(ctx, manager)
	}()
	time.Sleep(100 * time.Millisecond)
	if err := bus.Publish(context.Background(), &core.Policy{Deny: []core.Rule{{IP: "203.0.113.8"}}}); err != nil {
		t.Fatal(err)
	}
	provider, err := NewPolicyProvider(client, DefaultPolicyKey)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := provider.LoadPolicy(context.Background())
	if err != nil || len(stored.Deny) != 1 {
		t.Fatalf("published policy was not persisted: %+v %v", stored, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err := manager.Create(context.Background(), core.CreateRequest{Action: "login", Meta: core.Meta{IP: "203.0.113.8"}})
		if err != nil {
			if err.Error() == core.ErrForbidden.Error() {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("policy was not applied; last error %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Watch did not stop")
	}
}
