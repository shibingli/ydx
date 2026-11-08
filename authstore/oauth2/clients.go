package oauth2

import (
	"context"
	"sort"

	authoauth2 "github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/errs"
)

// ClientPager extends authoauth2.ClientStore with cursor pagination. Every Redis client store
// implements it, and any value of this type remains assignable to authoauth2.ClientStore.
// | ClientPager 在 authoauth2.ClientStore 之上增加游标分页。每个 Redis 客户端存储都实现它，该类型
// 的任何值仍可赋值给 authoauth2.ClientStore。
type ClientPager interface {
	authoauth2.ClientStore
	// ListClientsPage returns one ID-ordered page after the exclusive cursor. | ListClientsPage
	// 返回游标之后按 ID 排序的一页，游标本身不包含在结果中。
	ListClientsPage(ctx context.Context, after string, limit int) ([]*authoauth2.Client, string, error)
}

// clientStore is the Redis implementation of authoauth2.ClientStore. | clientStore 是
// authoauth2.ClientStore 的 Redis 实现。
type clientStore struct {
	// base carries the shared client and key namespace. | base 承载共享客户端与键命名空间。
	base
}

var _ ClientPager = (*clientStore)(nil)

// CreateClient stores a new client and rejects a duplicate ID. | CreateClient 保存新客户端并拒绝重复 ID。
func (c *clientStore) CreateClient(ctx context.Context, client *authoauth2.Client) error {
	if client == nil || client.ID == "" {
		return errs.Detail(authoauth2.ErrInvalidClient, "client id is empty | 客户端标识为空")
	}
	data, err := encodeClient(client)
	if err != nil {
		return err
	}
	status, err := c.runInt(ctx, scriptClientCreate, "create client",
		[]string{c.keys.client(client.ID), c.keys.clientsAll()}, string(data), client.ID)
	if err != nil {
		return err
	}
	if status == 1 {
		return errs.Detail(authoauth2.ErrInvalidClient, "client %[1]q already exists | 客户端 %[1]q 已存在", client.ID)
	}
	return nil
}

// GetClient returns a client by ID. | GetClient 按 ID 返回客户端。
func (c *clientStore) GetClient(ctx context.Context, id string) (*authoauth2.Client, error) {
	fields, err := c.hashFields(ctx, c.keys.client(id), "get client")
	if err != nil {
		return nil, err
	}
	if len(fields) == 0 {
		return nil, errs.Detail(authoauth2.ErrInvalidClient, "unknown client %[1]q | 未知客户端 %[1]q", id)
	}
	return decodeClient([]byte(fields[fieldData]))
}

// UpdateClient replaces an existing client. | UpdateClient 替换已有客户端。
func (c *clientStore) UpdateClient(ctx context.Context, client *authoauth2.Client) error {
	if client == nil || client.ID == "" {
		return errs.Detail(authoauth2.ErrInvalidClient, "client id is empty | 客户端标识为空")
	}
	data, err := encodeClient(client)
	if err != nil {
		return err
	}
	status, err := c.runInt(ctx, scriptClientUpdate, "update client",
		[]string{c.keys.client(client.ID)}, string(data))
	if err != nil {
		return err
	}
	if status == 1 {
		return errs.Detail(authoauth2.ErrInvalidClient, "unknown client %[1]q | 未知客户端 %[1]q", client.ID)
	}
	return nil
}

// DeleteClient removes a client. | DeleteClient 删除客户端。
func (c *clientStore) DeleteClient(ctx context.Context, id string) error {
	status, err := c.runInt(ctx, scriptClientDelete, "delete client",
		[]string{c.keys.client(id), c.keys.clientsAll()}, id)
	if err != nil {
		return err
	}
	if status == 1 {
		return errs.Detail(authoauth2.ErrInvalidClient, "unknown client %[1]q | 未知客户端 %[1]q", id)
	}
	return nil
}

// ListClients returns every registered client ordered by ID. | ListClients 按 ID 返回全部已注册客户端。
func (c *clientStore) ListClients(ctx context.Context) ([]*authoauth2.Client, error) {
	values, err := c.runStrings(ctx, scriptClientList, "list clients",
		[]string{c.keys.clientsAll()}, c.keys.clientPrefix())
	if err != nil {
		return nil, err
	}
	clients := make([]*authoauth2.Client, 0, len(values))
	for _, value := range values {
		client, err := decodeClient([]byte(value))
		if err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}
	sort.Slice(clients, func(i, j int) bool { return clients[i].ID < clients[j].ID })
	return clients, nil
}

// ListClientsPage returns one ID-ordered page after the exclusive cursor. An empty cursor starts
// at the first client. The returned cursor is the last ID of the page when more clients follow and
// an empty string on the final page. A non-positive limit uses defaultClientPageSize and a limit
// above maxClientPageSize is clamped. | ListClientsPage 返回游标之后按 ID 排序的一页，游标本身
// 不包含在结果中。空游标从第一个客户端开始。后续仍有客户端时返回的游标是本页最后一个 ID，
// 末页返回空字符串。非正数上限使用 defaultClientPageSize，超过 maxClientPageSize 的上限会被钳制。
func (c *clientStore) ListClientsPage(ctx context.Context, after string, limit int) ([]*authoauth2.Client, string, error) {
	if limit <= 0 {
		limit = defaultClientPageSize
	}
	if limit > maxClientPageSize {
		limit = maxClientPageSize
	}
	all, err := c.ListClients(ctx)
	if err != nil {
		return nil, "", err
	}
	start := sort.Search(len(all), func(i int) bool { return all[i].ID > after })
	end := start + limit
	if end > len(all) {
		end = len(all)
	}
	page := all[start:end]
	next := ""
	if end < len(all) {
		next = all[end-1].ID
	}
	return page, next, nil
}
