package ldap

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// poolSearchHandler answers search requests for pool tests. | poolSearchHandler
// 为连接池测试应答搜索请求。
func poolSearchHandler(session *mockSession, message *LDAPMessage) error {
	if _, ok := message.Op.(*SearchRequest); !ok {
		return errors.New("expected search")
	}
	return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess})
}

// TestNewPoolValidation verifies pool construction and nil receivers. | TestNewPoolValidation
// 校验连接池构造与 nil 接收者。
func TestNewPoolValidation(t *testing.T) {
	if _, err := NewPool(Config{URL: "http://example.com"}); !errors.Is(err, ErrInvalidURL) {
		t.Fatalf("invalid scheme error = %v", err)
	}
	if _, err := NewPool(Config{URL: "ldap://example.com", PoolSize: -1}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("negative pool size error = %v", err)
	}
	var pool *Pool
	if _, err := pool.Get(context.Background()); !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("nil pool Get error = %v", err)
	}
	if err := pool.Put(nil); err != nil {
		t.Fatalf("nil pool Put error = %v", err)
	}
	if err := pool.Close(); err != nil {
		t.Fatalf("nil pool Close error = %v", err)
	}
	if stats := pool.Stats(); stats != (PoolStats{}) {
		t.Fatalf("nil pool stats = %+v", stats)
	}
}

// TestPoolGetPutDo verifies borrow, return and combined use. | TestPoolGetPutDo
// 校验借出、归还与组合使用。
func TestPoolGetPutDo(t *testing.T) {
	server := startMockServer(t, poolSearchHandler)
	pool, err := NewPool(Config{URL: server.URL(), PoolSize: 2, MaxIdle: 1, MaxIdleTime: time.Minute})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close()
	if stats := pool.Stats(); stats.Open != 0 || stats.Idle != 0 {
		t.Fatalf("initial stats = %+v", stats)
	}
	first, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stats := pool.Stats(); stats.Open != 1 || stats.Idle != 0 {
		t.Fatalf("checked-out stats = %+v", stats)
	}
	if _, err := first.Search(context.Background(), SearchOptions{Filter: Present("objectClass")}); err != nil {
		t.Fatalf("search: %v", err)
	}
	if err := pool.Put(first); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if stats := pool.Stats(); stats.Open != 1 || stats.Idle != 1 {
		t.Fatalf("idle stats = %+v", stats)
	}
	second, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if second != first {
		t.Fatal("Get did not reuse the idle client")
	}
	if err := pool.Put(second); err != nil {
		t.Fatalf("second Put: %v", err)
	}
	sentinel := errors.New("do failure")
	if err := pool.Do(context.Background(), func(client *Client) error {
		if _, err := client.Search(context.Background(), SearchOptions{Filter: Present("objectClass")}); err != nil {
			return err
		}
		return sentinel
	}); !errors.Is(err, sentinel) {
		t.Fatalf("Do error = %v", err)
	}
	if stats := pool.Stats(); stats.Idle != 1 || stats.Open != 1 {
		t.Fatalf("stats after Do = %+v", stats)
	}
	if err := pool.Do(context.Background(), nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil Do error = %v", err)
	}
	unknown, err := DialURL(context.Background(), server.URL())
	if err != nil {
		t.Fatalf("DialURL unknown: %v", err)
	}
	if err := pool.Put(unknown); err != nil {
		t.Fatalf("Put unknown: %v", err)
	}
	if !unknown.IsClosed() {
		t.Fatal("unknown client was not closed")
	}
	if err := pool.Put(nil); err != nil {
		t.Fatalf("Put nil: %v", err)
	}
}

// TestPoolClose verifies Close semantics. | TestPoolClose 校验 Close 语义。
func TestPoolClose(t *testing.T) {
	server := startMockServer(t, poolSearchHandler)
	pool, err := NewPool(Config{URL: server.URL(), PoolSize: 1})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	client, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if err := pool.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !client.IsClosed() {
		t.Fatal("checked-out client survived Close")
	}
	if _, err := pool.Get(context.Background()); !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("Get after Close error = %v", err)
	}
	if err := pool.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := pool.Put(client); err != nil {
		t.Fatalf("Put after Close: %v", err)
	}
	if stats := pool.Stats(); stats.Open != 0 || stats.Idle != 0 {
		t.Fatalf("stats after Close = %+v", stats)
	}
}

// TestPoolSizeLimit verifies blocking and wakeups at PoolSize. | TestPoolSizeLimit
// 校验 PoolSize 处的阻塞与唤醒。
func TestPoolSizeLimit(t *testing.T) {
	server := startMockServer(t, poolSearchHandler)
	pool, err := NewPool(Config{URL: server.URL(), PoolSize: 1})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close()
	first, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := pool.Get(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked Get error = %v", err)
	}
	waitResult := make(chan error, 1)
	go func() {
		client, err := pool.Get(context.Background())
		if err == nil {
			err = pool.Put(client)
		}
		waitResult <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := pool.Put(first); err != nil {
		t.Fatalf("Put: %v", err)
	}
	select {
	case err := <-waitResult:
		if err != nil {
			t.Fatalf("waiting Get: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting Get was not woken by Put")
	}
}

// TestPoolMaxIdle verifies excess idle clients are discarded. | TestPoolMaxIdle
// 校验超额空闲客户端被丢弃。
func TestPoolMaxIdle(t *testing.T) {
	server := startMockServer(t, poolSearchHandler)
	pool, err := NewPool(Config{URL: server.URL(), PoolSize: 2, MaxIdle: 1})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close()
	first, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}
	second, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if first == second {
		t.Fatal("pool returned the checked-out client twice")
	}
	if err := pool.Put(first); err != nil {
		t.Fatalf("Put first: %v", err)
	}
	if err := pool.Put(second); err != nil {
		t.Fatalf("Put second: %v", err)
	}
	closed := 0
	if first.IsClosed() {
		closed++
	}
	if second.IsClosed() {
		closed++
	}
	if closed != 1 {
		t.Fatalf("closed clients = %d", closed)
	}
	if stats := pool.Stats(); stats.Open != 1 || stats.Idle != 1 {
		t.Fatalf("stats = %+v", stats)
	}
}

// TestPoolDoublePutDoesNotDoubleBorrow verifies that returning the same client
// twice cannot place it in the idle set twice, close it while it is idle, or
// hand it to two borrowers. | TestPoolDoublePutDoesNotDoubleBorrow 校验重复归还同一
// 客户端不会把它两次放入空闲集合、在空闲时将其关闭，或把它同时交给两个借用方。
func TestPoolDoublePutDoesNotDoubleBorrow(t *testing.T) {
	t.Run("excess idle", func(t *testing.T) {
		server := startMockServer(t, poolSearchHandler)
		pool, err := NewPool(Config{URL: server.URL(), PoolSize: 2, MaxIdle: 2, MaxIdleTime: time.Minute})
		if err != nil {
			t.Fatalf("NewPool: %v", err)
		}
		defer pool.Close()
		client, err := pool.Get(context.Background())
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if err := pool.Put(client); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := pool.Put(client); err != nil {
			t.Fatalf("second Put: %v", err)
		}
		if stats := pool.Stats(); stats.Open != 1 || stats.Idle != 1 {
			t.Fatalf("stats after double Put = %+v", stats)
		}
		first, err := pool.Get(context.Background())
		if err != nil {
			t.Fatalf("Get after double Put: %v", err)
		}
		if first != client {
			t.Fatal("Get after double Put did not reuse the idle client")
		}
		second, err := pool.Get(context.Background())
		if err != nil {
			t.Fatalf("second Get after double Put: %v", err)
		}
		if second == first {
			t.Fatal("double Put handed the same client to two borrowers")
		}
		if err := pool.Put(first); err != nil {
			t.Fatalf("Put first: %v", err)
		}
		if err := pool.Put(second); err != nil {
			t.Fatalf("Put second: %v", err)
		}
	})
	t.Run("max idle one", func(t *testing.T) {
		server := startMockServer(t, poolSearchHandler)
		pool, err := NewPool(Config{URL: server.URL(), PoolSize: 1, MaxIdle: 1, MaxIdleTime: time.Minute})
		if err != nil {
			t.Fatalf("NewPool: %v", err)
		}
		defer pool.Close()
		client, err := pool.Get(context.Background())
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if err := pool.Put(client); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := pool.Put(client); err != nil {
			t.Fatalf("second Put: %v", err)
		}
		if stats := pool.Stats(); stats.Open != 1 || stats.Idle != 1 {
			t.Fatalf("stats after double Put = %+v", stats)
		}
		reused, err := pool.Get(context.Background())
		if err != nil {
			t.Fatalf("Get after double Put: %v", err)
		}
		if reused != client {
			t.Fatal("Get after double Put did not reuse the idle client")
		}
		if reused.IsClosed() {
			t.Fatal("double Put closed the idle client")
		}
		if err := pool.Put(reused); err != nil {
			t.Fatalf("final Put: %v", err)
		}
	})
}

// TestPoolPruneExpired verifies Get prunes idle clients past MaxIdleTime. |
// TestPoolPruneExpired 校验 Get 清理超过 MaxIdleTime 的空闲客户端。
func TestPoolPruneExpired(t *testing.T) {
	server := startMockServer(t, poolSearchHandler)
	pool, err := NewPool(Config{URL: server.URL(), PoolSize: 1, MaxIdleTime: time.Minute})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close()
	old, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if err := pool.Put(old); err != nil {
		t.Fatalf("Put: %v", err)
	}
	pool.mu.Lock()
	pool.idle[0].lastUsed = time.Now().Add(-time.Hour)
	pool.mu.Unlock()
	fresh, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("Get after expiry: %v", err)
	}
	if fresh == old {
		t.Fatal("expired client was reused")
	}
	if !old.IsClosed() {
		t.Fatal("expired client was not closed")
	}
	if err := pool.Put(fresh); err != nil {
		t.Fatalf("Put fresh: %v", err)
	}
}

// TestPoolJanitor verifies the background janitor discards idle clients. |
// TestPoolJanitor 校验后台清理器丢弃空闲客户端。
func TestPoolJanitor(t *testing.T) {
	server := startMockServer(t, poolSearchHandler)
	pool, err := NewPool(Config{URL: server.URL(), PoolSize: 1, MaxIdleTime: 100 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close()
	client, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if err := pool.Put(client); err != nil {
		t.Fatalf("Put: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		stats := pool.Stats()
		if stats.Idle == 0 && stats.Open == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("janitor did not prune idle client: %+v", stats)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !client.IsClosed() {
		t.Fatal("janitor did not close the idle client")
	}
}

// TestPoolConcurrentUse verifies bounded concurrent borrowers. | TestPoolConcurrentUse
// 校验有界并发借用。
func TestPoolConcurrentUse(t *testing.T) {
	var active atomic.Int32
	var peak atomic.Int32
	server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
		current := active.Add(1)
		for {
			previous := peak.Load()
			if current <= previous || peak.CompareAndSwap(previous, current) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
		active.Add(-1)
		return poolSearchHandler(session, message)
	})
	const (
		poolSize = 3
		workers  = 24
	)
	pool, err := NewPool(Config{URL: server.URL(), PoolSize: poolSize})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close()
	var wg sync.WaitGroup
	errsCh := make(chan error, workers)
	for index := 0; index < workers; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errsCh <- pool.Do(context.Background(), func(client *Client) error {
				_, err := client.Search(context.Background(), SearchOptions{Filter: Present("objectClass")})
				return err
			})
		}()
	}
	wg.Wait()
	close(errsCh)
	for err := range errsCh {
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	if peak.Load() > poolSize {
		t.Fatalf("peak concurrency = %d", peak.Load())
	}
	if stats := pool.Stats(); stats.Open > poolSize || stats.Idle > poolSize {
		t.Fatalf("stats = %+v", stats)
	}
}

// TestPoolContextCancellation verifies waiting borrowers honor cancellation. |
// TestPoolContextCancellation 校验等待的借用方遵守取消。
func TestPoolContextCancellation(t *testing.T) {
	server := startMockServer(t, poolSearchHandler)
	pool, err := NewPool(Config{URL: server.URL(), PoolSize: 1})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close()
	client, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := pool.Get(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Get canceled error = %v", err)
	}
	if err := pool.Put(client); err != nil {
		t.Fatalf("Put: %v", err)
	}
}

// TestPoolConfigBind verifies pooled clients replay the configured bind. | TestPoolConfigBind
// 校验池客户端重放配置绑定。
func TestPoolConfigBind(t *testing.T) {
	var (
		mu    sync.Mutex
		binds int
	)
	server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
		switch message.Op.(type) {
		case *BindRequest:
			mu.Lock()
			binds++
			mu.Unlock()
			return session.writeSimpleResult(message.MessageID, &BindResponse{Result: LDAPResult{Code: ResultSuccess}})
		case *SearchRequest:
			return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess})
		default:
			return errors.New("unexpected operation")
		}
	})
	pool, err := NewPool(Config{URL: server.URL(), PoolSize: 1, BindDN: "cn=service", BindPassword: "secret"})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close()
	client, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := client.Search(context.Background(), SearchOptions{Filter: Present("objectClass")}); err != nil {
		t.Fatalf("Search: %v", err)
	}
	if err := pool.Put(client); err != nil {
		t.Fatalf("Put: %v", err)
	}
	second, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if second != client {
		t.Fatal("pool did not reuse the bound client")
	}
	mu.Lock()
	count := binds
	mu.Unlock()
	if count != 1 {
		t.Fatalf("binds = %d", count)
	}
	if err := pool.Put(second); err != nil {
		t.Fatalf("second Put: %v", err)
	}
}
