package oauth2

import (
	"context"
	"sort"
	"sync"

	"github.com/shibingli/ydx/errs"
)

// ClientStore persists client registrations. | ClientStore 持久化客户端注册。
type ClientStore interface {
	// CreateClient stores a new client and rejects a duplicate ID. | CreateClient 保存新客户端并拒绝重复 ID。
	CreateClient(ctx context.Context, client *Client) error
	// GetClient returns a client by ID. | GetClient 按 ID 返回客户端。
	GetClient(ctx context.Context, id string) (*Client, error)
	// UpdateClient replaces an existing client. | UpdateClient 替换已有客户端。
	UpdateClient(ctx context.Context, client *Client) error
	// DeleteClient removes a client. | DeleteClient 删除客户端。
	DeleteClient(ctx context.Context, id string) error
	// ListClients returns every registered client. | ListClients 返回全部已注册客户端。
	ListClients(ctx context.Context) ([]*Client, error)
}

// MemoryClientStore is a concurrency-safe in-memory ClientStore. | MemoryClientStore 是并发安全的内存 ClientStore。
type MemoryClientStore struct {
	mu      sync.RWMutex
	clients map[string]*Client
}

// NewMemoryClientStore returns a store seeded with clients. | NewMemoryClientStore 返回由 clients 初始化的存储。
func NewMemoryClientStore(clients ...*Client) *MemoryClientStore {
	s := &MemoryClientStore{clients: make(map[string]*Client, len(clients))}
	for _, client := range clients {
		if client != nil && client.ID != "" {
			s.clients[client.ID] = client.clone()
		}
	}
	return s
}

// clone returns a deep copy of a client. | clone 返回客户端深拷贝。
func (c *Client) clone() *Client {
	if c == nil {
		return nil
	}
	out := *c
	out.RedirectURIs = append([]string(nil), c.RedirectURIs...)
	out.GrantTypes = append([]string(nil), c.GrantTypes...)
	out.ResponseTypes = append([]string(nil), c.ResponseTypes...)
	out.Scopes = append([]string(nil), c.Scopes...)
	out.RequestURIs = append([]string(nil), c.RequestURIs...)
	out.TLSClientAuthSANs = append([]string(nil), c.TLSClientAuthSANs...)
	out.JWKS = append([]byte(nil), c.JWKS...)
	out.PostLogoutRedirectURIs = append([]string(nil), c.PostLogoutRedirectURIs...)
	out.Contacts = append([]string(nil), c.Contacts...)
	if len(c.Metadata) > 0 {
		out.Metadata = make(map[string]string, len(c.Metadata))
		for k, v := range c.Metadata {
			out.Metadata[k] = v
		}
	}
	return &out
}

// CreateClient stores a new client. | CreateClient 保存新客户端。
func (s *MemoryClientStore) CreateClient(_ context.Context, client *Client) error {
	if client == nil || client.ID == "" {
		return errs.Detail(ErrInvalidClient, "client id is empty | 客户端标识为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.clients[client.ID]; exists {
		return errs.Detail(ErrInvalidClient, "client %[1]q already exists | 客户端 %[1]q 已存在", client.ID)
	}
	s.clients[client.ID] = client.clone()
	return nil
}

// GetClient returns a client by ID. | GetClient 按 ID 返回客户端。
func (s *MemoryClientStore) GetClient(_ context.Context, id string) (*Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	client, ok := s.clients[id]
	if !ok {
		return nil, errs.Detail(ErrInvalidClient, "unknown client %[1]q | 未知客户端 %[1]q", id)
	}
	return client.clone(), nil
}

// UpdateClient replaces an existing client. | UpdateClient 替换已有客户端。
func (s *MemoryClientStore) UpdateClient(_ context.Context, client *Client) error {
	if client == nil || client.ID == "" {
		return errs.Detail(ErrInvalidClient, "client id is empty | 客户端标识为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.clients[client.ID]; !exists {
		return errs.Detail(ErrInvalidClient, "unknown client %[1]q | 未知客户端 %[1]q", client.ID)
	}
	s.clients[client.ID] = client.clone()
	return nil
}

// DeleteClient removes a client. | DeleteClient 删除客户端。
func (s *MemoryClientStore) DeleteClient(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.clients[id]; !exists {
		return errs.Detail(ErrInvalidClient, "unknown client %[1]q | 未知客户端 %[1]q", id)
	}
	delete(s.clients, id)
	return nil
}

// ListClients returns every registered client ordered by ID. | ListClients 按 ID 返回全部已注册客户端。
func (s *MemoryClientStore) ListClients(_ context.Context) ([]*Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Client, 0, len(s.clients))
	for _, client := range s.clients {
		out = append(out, client.clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
