package ldap

import (
	"context"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// PoolStats reports current pool occupancy. | PoolStats 报告当前连接池占用。
type PoolStats struct {
	// Open is the number of open and connecting clients. | Open 是已打开与正在连接的客户端数。
	Open int
	// Idle is the number of reusable idle clients. | Idle 是可复用的空闲客户端数。
	Idle int
}

// idleClient is one reusable client and its last return time. | idleClient 是
// 一个可复用客户端及其最后归还时间。
type idleClient struct {
	client   *Client
	lastUsed time.Time
}

// Pool bounds a set of independent clients, each serialized individually. Get
// borrows a client, Put returns it, and Do combines both. Clients are created
// lazily and re-authenticated from Config. | Pool 限制一组彼此独立的客户端，每个客户端
// 单独串行化。Get 借出客户端，Put 归还，Do 组合两者。客户端按需创建，并按 Config
// 重新认证。
type Pool struct {
	cfg        normalizedConfig
	mu         sync.Mutex
	idle       []idleClient
	all        map[*Client]struct{}
	checkedOut map[*Client]struct{}
	creating   int
	closed     bool
	notify     chan struct{}
	stop       chan struct{}
	janitor    chan struct{}
}

// NewPool validates cfg and creates an empty pool. Connections are established
// lazily by Get. | NewPool 校验 cfg 并创建空池。连接由 Get 按需建立。
func NewPool(cfg Config) (*Pool, error) {
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	pool := &Pool{
		cfg:        normalized,
		all:        make(map[*Client]struct{}),
		checkedOut: make(map[*Client]struct{}),
		notify:     make(chan struct{}),
		stop:       make(chan struct{}),
		janitor:    make(chan struct{}),
	}
	go pool.runJanitor()
	return pool, nil
}

// Get borrows a client, waiting for one when PoolSize clients are in use. The
// client must be returned with Put and must not be closed by the borrower. | Get
// 借出一个客户端；PoolSize 个客户端都在使用时会等待。客户端必须用 Put 归还，借用方不得关闭它。
func (p *Pool) Get(ctx context.Context) (*Client, error) {
	if p == nil {
		return nil, ErrPoolClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, ErrPoolClosed
		}
		expired := p.pruneLocked()
		if len(p.idle) > 0 {
			last := len(p.idle) - 1
			client := p.idle[last].client
			p.idle = p.idle[:last]
			p.checkedOut[client] = struct{}{}
			p.mu.Unlock()
			closeClients(expired)
			return client, nil
		}
		if len(p.all)+p.creating < p.cfg.PoolSize {
			p.creating++
			p.mu.Unlock()
			closeClients(expired)
			client, err := Dial(ctx, p.cfg.Config)
			p.mu.Lock()
			p.creating--
			if err != nil {
				p.broadcastLocked()
				p.mu.Unlock()
				return nil, err
			}
			if p.closed || ctx.Err() != nil {
				waitErr := ctx.Err()
				p.broadcastLocked()
				p.mu.Unlock()
				_ = client.Close()
				if waitErr != nil {
					return nil, waitErr
				}
				return nil, ErrPoolClosed
			}
			p.all[client] = struct{}{}
			p.checkedOut[client] = struct{}{}
			p.mu.Unlock()
			return client, nil
		}
		wait := p.notify
		p.mu.Unlock()
		closeClients(expired)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-wait:
		}
	}
}

// Put returns a borrowed client. Closing, dead, excess, and expired clients are
// discarded. Returning a client that is already idle is a no-op, so a repeated
// Put cannot duplicate it in the idle set. It is safe to Put a client after
// Close, where it is closed. | Put 归还借出的客户端。已关闭、已失效、超额与过期客户端
// 会被丢弃。归还已经空闲的客户端是无操作，因此重复 Put 不会在空闲集合中复制它。Close
// 之后 Put 也安全，此时客户端会被关闭。
func (p *Pool) Put(client *Client) error {
	if p == nil || client == nil {
		return nil
	}
	p.mu.Lock()
	expired := p.pruneLocked()
	if _, borrowed := p.checkedOut[client]; !borrowed {
		_, known := p.all[client]
		p.mu.Unlock()
		closeClients(expired)
		if known {
			// The client is already idle; keep its single idle entry. |
			// 客户端已经空闲；保留其唯一的空闲条目。
			return nil
		}
		return client.Close()
	}
	delete(p.checkedOut, client)
	if p.closed || client.IsClosed() {
		delete(p.all, client)
		p.broadcastLocked()
		p.mu.Unlock()
		closeClients(expired)
		return client.Close()
	}
	if len(p.idle) >= p.cfg.MaxIdle {
		delete(p.all, client)
		p.broadcastLocked()
		p.mu.Unlock()
		closeClients(expired)
		return client.Close()
	}
	p.idle = append(p.idle, idleClient{client: client, lastUsed: time.Now()})
	p.broadcastLocked()
	p.mu.Unlock()
	closeClients(expired)
	return nil
}

// Do borrows a client, invokes fn, and returns the client to the pool. | Do 借出
// 客户端、调用 fn，并把客户端归还池中。
func (p *Pool) Do(ctx context.Context, fn func(*Client) error) error {
	if fn == nil {
		return errs.Detail(ErrInvalidConfig, "nil pool function | 连接池函数为空")
	}
	client, err := p.Get(ctx)
	if err != nil {
		return err
	}
	defer func() {
		_ = p.Put(client)
	}()
	return fn(client)
}

// Stats returns a consistent occupancy snapshot. | Stats 返回一致的占用快照。
func (p *Pool) Stats() PoolStats {
	if p == nil {
		return PoolStats{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return PoolStats{Open: len(p.all) + p.creating, Idle: len(p.idle)}
}

// Close closes idle and checked-out clients, rejects future Get calls, and stops
// the idle janitor. It is safe to call more than once. | Close 关闭空闲与已借出客户端，
// 拒绝后续 Get，并停止空闲清理器。可重复调用。
func (p *Pool) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	clients := make([]*Client, 0, len(p.all))
	for client := range p.all {
		clients = append(clients, client)
	}
	p.all = make(map[*Client]struct{})
	p.checkedOut = make(map[*Client]struct{})
	p.idle = nil
	p.broadcastLocked()
	close(p.stop)
	p.mu.Unlock()
	var first error
	for _, client := range clients {
		if err := client.Close(); err != nil && first == nil {
			first = err
		}
	}
	<-p.janitor
	return first
}

// pruneLocked removes and returns idle clients older than MaxIdleTime. | pruneLocked
// 移除并返回超过 MaxIdleTime 的空闲客户端。
func (p *Pool) pruneLocked() []*Client {
	if len(p.idle) == 0 {
		return nil
	}
	cutoff := time.Now().Add(-p.cfg.MaxIdleTime)
	kept := p.idle[:0]
	var expired []*Client
	for _, entry := range p.idle {
		if entry.lastUsed.Before(cutoff) {
			delete(p.all, entry.client)
			expired = append(expired, entry.client)
			continue
		}
		kept = append(kept, entry)
	}
	p.idle = kept
	if len(expired) > 0 {
		p.broadcastLocked()
	}
	return expired
}

// broadcastLocked wakes every Get waiter. | broadcastLocked 唤醒所有 Get 等待者。
func (p *Pool) broadcastLocked() {
	close(p.notify)
	p.notify = make(chan struct{})
}

// runJanitor periodically discards idle clients. It exits when stop closes. | runJanitor
// 周期性丢弃空闲客户端，stop 关闭时退出。
func (p *Pool) runJanitor() {
	defer close(p.janitor)
	interval := p.cfg.MaxIdleTime / 2
	if interval > time.Minute {
		interval = time.Minute
	}
	if interval < 100*time.Millisecond {
		interval = 100 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
			p.mu.Lock()
			if p.closed {
				p.mu.Unlock()
				return
			}
			expired := p.pruneLocked()
			p.mu.Unlock()
			closeClients(expired)
		}
	}
}

// closeClients closes a slice of discarded clients. Close errors are ignored
// because the connections are already unusable; Pool.Close reports errors for
// clients it owns. | closeClients 关闭一批丢弃的客户端。由于连接已不可用，关闭错误被
// 忽略；Pool.Close 会报告其负责客户端的错误。
func closeClients(clients []*Client) {
	for _, client := range clients {
		_ = client.Close()
	}
}
