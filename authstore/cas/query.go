package cas

import (
	"context"

	authcas "github.com/shibingli/ydx/auth/protocol/cas"
)

// Stats counts the records currently stored by a Stores value. | Stats 统计 Stores 当前保存的记录数量。
type Stats struct {
	// Tickets is the total number of ticket records. | Tickets 是票据记录总数。
	Tickets int64
	// TGT is the number of ticket-granting tickets. | TGT 是票据授予票据数量。
	TGT int64
	// ST is the number of service tickets. | ST 是服务票据数量。
	ST int64
	// PGT is the number of proxy-granting tickets. | PGT 是代理授予票据数量。
	PGT int64
	// PT is the number of proxy tickets. | PT 是代理票据数量。
	PT int64
	// Sessions is the total number of service session records. | Sessions 是服务会话记录总数。
	Sessions int64
}

// Stats returns record counts computed from the store's index sets.
// | Stats 从存储的索引集合计算记录数量。
//
// The counts are read with SCARD, so they are exact for a stable deployment and reflect one
// consistent-enough snapshot under concurrent writes. | 计数通过 SCARD 读取，因此在稳定部署中精确；
// 并发写入下反映的是足够一致的一次快照。
func (s *Stores) Stats(ctx context.Context) (Stats, error) {
	if s == nil || s.tickets == nil {
		return Stats{}, nil
	}
	store := s.tickets
	pipe := store.client.Pipeline()
	tickets := pipe.SCard(ctx, store.keys.ticketsAll())
	tgt := pipe.SCard(ctx, store.keys.ticketsByType(authcas.TicketTGT))
	st := pipe.SCard(ctx, store.keys.ticketsByType(authcas.TicketST))
	pgt := pipe.SCard(ctx, store.keys.ticketsByType(authcas.TicketPGT))
	pt := pipe.SCard(ctx, store.keys.ticketsByType(authcas.TicketPT))
	sessions := pipe.SCard(ctx, store.keys.sessionsAll())
	if _, err := pipe.Exec(ctx); err != nil {
		return Stats{}, store.backend("statistics", err)
	}
	return Stats{
		Tickets:  tickets.Val(),
		TGT:      tgt.Val(),
		ST:       st.Val(),
		PGT:      pgt.Val(),
		PT:       pt.Val(),
		Sessions: sessions.Val(),
	}, nil
}

// TicketQuery selects and pages tickets for ListTickets. | TicketQuery 为 ListTickets 选择并分页票据。
//
// Every non-zero selector is combined with intersection, so a query narrows the result set. Offset
// and Limit page the matching records after they are ordered by issue time and then identifier.
// | 每个非零选择器以交集组合，因此查询会收窄结果集。Offset 与 Limit 在记录按签发时间与标识排序后
// 对其分页。
type TicketQuery struct {
	// Type restricts the result to one ticket type. | Type 把结果限定为单一票据类型。
	Type authcas.TicketType
	// Service restricts the result to tickets bound to one service URL. | Service 把结果限定为绑定到
	// 单个服务 URL 的票据。
	Service string
	// RootTGTID restricts the result to one ticket family. | RootTGTID 把结果限定为单个票据族。
	RootTGTID string
	// UserID restricts the result to tickets of one user. | UserID 把结果限定为单个用户的票据。
	UserID string
	// Offset skips that many matching records; a negative value is treated as zero. |
	// Offset 跳过相应数量的匹配记录；负值视为零。
	Offset int
	// Limit caps the page size; a non-positive value returns every remaining record. |
	// Limit 限制页大小；非正值返回全部剩余记录。
	Limit int
}

// SessionQuery selects and pages service sessions for ListSessions. | SessionQuery 为 ListSessions
// 选择并分页服务会话。
//
// TGTID and User are combined with intersection when both are set. Matches are ordered by issue time
// and then session index. | 同时设置 TGTID 与 User 时按交集组合。匹配记录按签发时间与会话索引排序。
type SessionQuery struct {
	// TGTID restricts the result to sessions rooted at one TGT. | TGTID 把结果限定为单个 TGT 为根的会话。
	TGTID string
	// User restricts the result to sessions of one protocol user or backend user ID. | User 把结果
	// 限定为单个协议用户或后端用户 ID 的会话。
	User string
	// Offset skips that many matching records; a negative value is treated as zero. |
	// Offset 跳过相应数量的匹配记录；负值视为零。
	Offset int
	// Limit caps the page size; a non-positive value returns every remaining record. |
	// Limit 限制页大小；非正值返回全部剩余记录。
	Limit int
}

// ListTickets returns one page of tickets matching query and the total number of matches.
// | ListTickets 返回匹配 query 的一页票据与匹配总数。
func (s *Stores) ListTickets(ctx context.Context, query TicketQuery) ([]*authcas.Ticket, int, error) {
	if s == nil || s.tickets == nil {
		return []*authcas.Ticket{}, 0, nil
	}
	return s.tickets.list(ctx, query)
}

// ListSessions returns one page of service sessions matching query and the total number of matches.
// | ListSessions 返回匹配 query 的一页服务会话与匹配总数。
func (s *Stores) ListSessions(ctx context.Context, query SessionQuery) ([]*authcas.ServiceSession, int, error) {
	if s == nil || s.sessions == nil {
		return []*authcas.ServiceSession{}, 0, nil
	}
	return s.sessions.list(ctx, query)
}

// list implements the extended ticket query over the index sets. | list 在索引集合上实现扩展票据查询。
func (s *ticketStore) list(ctx context.Context, query TicketQuery) ([]*authcas.Ticket, int, error) {
	sets := make([]string, 0, 4)
	if query.Type != "" {
		sets = append(sets, s.keys.ticketsByType(query.Type))
	}
	if query.Service != "" {
		sets = append(sets, s.keys.ticketsByService(query.Service))
	}
	if query.RootTGTID != "" {
		sets = append(sets, s.keys.ticketsByRoot(query.RootTGTID))
	}
	if query.UserID != "" {
		sets = append(sets, s.keys.ticketsByUser(query.UserID))
	}
	members, err := s.candidates(ctx, sets)
	if err != nil {
		return nil, 0, err
	}
	tickets, err := s.loadTickets(ctx, members, func(ticket *authcas.Ticket) bool {
		if query.Type != "" && ticket.Type != query.Type {
			return false
		}
		if query.Service != "" && ticket.Service != query.Service {
			return false
		}
		if query.RootTGTID != "" && ticket.RootTGTID != query.RootTGTID {
			return false
		}
		if query.UserID != "" && ticket.UserID != query.UserID {
			return false
		}
		return true
	})
	if err != nil {
		return nil, 0, err
	}
	return paginateTickets(tickets, query.Offset, query.Limit), len(tickets), nil
}

// candidates returns the members of one set or the intersection of several sets.
// | candidates 返回单个集合的成员或多个集合的交集。
func (s *ticketStore) candidates(ctx context.Context, sets []string) ([]string, error) {
	switch len(sets) {
	case 0:
		members, err := s.client.SMembers(ctx, s.keys.ticketsAll()).Result()
		if err != nil {
			return nil, s.backend("list tickets", err)
		}
		return members, nil
	case 1:
		members, err := s.client.SMembers(ctx, sets[0]).Result()
		if err != nil {
			return nil, s.backend("list tickets", err)
		}
		return members, nil
	default:
		members, err := s.client.SInter(ctx, sets...).Result()
		if err != nil {
			return nil, s.backend("list tickets", err)
		}
		return members, nil
	}
}

// list implements the extended session query over the index sets. | list 在索引集合上实现扩展会话查询。
func (r *sessionRegistry) list(ctx context.Context, query SessionQuery) ([]*authcas.ServiceSession, int, error) {
	sets := make([]string, 0, 2)
	if query.TGTID != "" {
		sets = append(sets, r.keys.sessionsByTGT(query.TGTID))
	}
	if query.User != "" {
		sets = append(sets, r.keys.sessionsByUser(query.User))
	}
	members, err := r.candidates(ctx, sets)
	if err != nil {
		return nil, 0, err
	}
	sessions, err := r.loadSessions(ctx, members, func(session *authcas.ServiceSession) bool {
		if query.TGTID != "" && session.TGTID != query.TGTID {
			return false
		}
		if query.User != "" && !matchesUserSession(session, query.User) {
			return false
		}
		return true
	})
	if err != nil {
		return nil, 0, err
	}
	return paginateSessions(sessions, query.Offset, query.Limit), len(sessions), nil
}

// candidates returns the members of one set or the intersection of both sets.
// | candidates 返回单个集合的成员或两个集合的交集。
func (r *sessionRegistry) candidates(ctx context.Context, sets []string) ([]string, error) {
	switch len(sets) {
	case 0:
		members, err := r.client.SMembers(ctx, r.keys.sessionsAll()).Result()
		if err != nil {
			return nil, r.backend("list service sessions", err)
		}
		return members, nil
	case 1:
		members, err := r.client.SMembers(ctx, sets[0]).Result()
		if err != nil {
			return nil, r.backend("list service sessions", err)
		}
		return members, nil
	default:
		members, err := r.client.SInter(ctx, sets...).Result()
		if err != nil {
			return nil, r.backend("list service sessions", err)
		}
		return members, nil
	}
}

// paginateTickets applies offset and limit to an ordered ticket slice. | paginateTickets 对已排序票据
// 切片应用偏移与数量限制。
func paginateTickets(tickets []*authcas.Ticket, offset, limit int) []*authcas.Ticket {
	start, end := pageBounds(len(tickets), offset, limit)
	page := make([]*authcas.Ticket, end-start)
	copy(page, tickets[start:end])
	return page
}

// paginateSessions applies offset and limit to an ordered session slice. | paginateSessions 对已排序
// 会话切片应用偏移与数量限制。
func paginateSessions(sessions []*authcas.ServiceSession, offset, limit int) []*authcas.ServiceSession {
	start, end := pageBounds(len(sessions), offset, limit)
	page := make([]*authcas.ServiceSession, end-start)
	copy(page, sessions[start:end])
	return page
}

// pageBounds clamps offset and limit to a valid half-open range. | pageBounds 把偏移与数量限制钳制为
// 合法的半开区间。
func pageBounds(total, offset, limit int) (int, int) {
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		offset = total
	}
	end := total
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	return offset, end
}
