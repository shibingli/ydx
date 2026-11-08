package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Extended operation OIDs used by the client. | 客户端使用的扩展操作 OID。
const (
	// OIDStartTLS is the RFC 4511 StartTLS operation. | OIDStartTLS 是 RFC 4511 StartTLS 操作。
	OIDStartTLS = "1.3.6.1.4.1.1466.20037"
	// OIDPasswordModify is the RFC 3062 password modify operation. | OIDPasswordModify 是 RFC 3062 口令修改操作。
	OIDPasswordModify = "1.3.6.1.4.1.4203.1.11.1"
	// OIDWhoAmI is the RFC 4532 Who Am I operation. | OIDWhoAmI 是 RFC 4532 Who Am I 操作。
	OIDWhoAmI = "1.3.6.1.4.1.4203.1.11.3"
	// OIDNoticeOfDisconnection is the RFC 4511 unsolicited disconnect notice. | OIDNoticeOfDisconnection 是 RFC 4511 非请求断开通知。
	OIDNoticeOfDisconnection = "1.3.6.1.4.1.1466.20036"
)

// authKind identifies the credentials retained for connection replay. | authKind
// 标识为重连保留的凭据类型。
type authKind uint8

const (
	authSimple authKind = iota + 1
	authPlain
	authExternal
	authSCRAM
	authNTLM
)

// authState is the effective bound identity. Passwords stay in memory so a
// broken connection can be re-established transparently. | authState 是有效绑定身份。
// 口令保留在内存中，以便透明重建断开的连接。
type authState struct {
	kind     authKind
	dn       string
	password string
	authzID  string
	authcid  string
	scram    SCRAMOptions
	ntlm     NTLMOptions
}

// Client is a serialized LDAP client connection. One request is in flight per
// connection; concurrent calls wait on an internal mutex. Use Pool for parallel
// workloads. | Client 是串行化的 LDAP 客户端连接。每个连接同时只有一个请求在途；并发
// 调用会等待内部互斥锁。并行负载请使用 Pool。
type Client struct {
	cfg  normalizedConfig
	mu   sync.Mutex
	conn *conn
	auth *authState
	dead bool
}

// URL returns the endpoint URL supplied at construction. | URL 返回构造时提供的端点地址。
func (c *Client) URL() string {
	if c == nil {
		return ""
	}
	return c.cfg.URL
}

// IsClosed reports whether Close or Unbind has been called. | IsClosed 报告是否已调用
// Close 或 Unbind。
func (c *Client) IsClosed() bool {
	if c == nil {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dead
}

// TLSConnectionState returns the active TLS state. | TLSConnectionState 返回活动 TLS 状态。
func (c *Client) TLSConnectionState() (tls.ConnectionState, bool) {
	if c == nil {
		return tls.ConnectionState{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil || !c.conn.secure {
		return tls.ConnectionState{}, false
	}
	return c.conn.tlsState, true
}

// Close closes the connection without sending Unbind. It is safe to call more
// than once. | Close 关闭连接且不发送 Unbind，可重复调用。
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dead = true
	c.auth = nil
	var err error
	if c.conn != nil {
		err = c.conn.close()
		c.conn = nil
	}
	c.cfg.BindPassword = ""
	return err
}

// Unbind sends UnbindRequest and closes the connection. It never reconnects. | Unbind
// 发送 UnbindRequest 并关闭连接，绝不重连。
func (c *Client) Unbind(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead {
		return ErrClosed
	}
	c.dead = true
	c.auth = nil
	if c.conn == nil {
		return nil
	}
	stop := watchContext(ctx, c.conn.netConn)
	defer stop()
	if err := c.conn.setDeadline(ctx, c.cfg.Timeout); err != nil {
		_ = c.conn.close()
		c.conn = nil
		return c.transportError(ctx, "unbind", err)
	}
	err := c.conn.writeMessage(&LDAPMessage{
		MessageID: c.conn.nextMessageID(),
		Op:        &UnbindRequest{},
	})
	closeErr := c.conn.close()
	c.conn = nil
	c.cfg.BindPassword = ""
	if err != nil {
		return c.transportError(ctx, "unbind", err)
	}
	return closeErr
}

// Reconnect closes the current connection and establishes a new one, replaying
// the last successful authentication. | Reconnect 关闭当前连接并建立新连接，重放最后
// 一次成功的认证。
func (c *Client) Reconnect(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead {
		return ErrClosed
	}
	if c.conn != nil {
		_ = c.conn.close()
		c.conn = nil
	}
	return c.ensureLocked(ctx, true)
}

// acquire locks the client, reconnects when needed and arms context cancellation.
// The returned release function must be deferred. | acquire 锁定客户端，按需重连并启用
// 上下文取消。返回的 release 函数必须用 defer 调用。
func (c *Client) acquire(ctx context.Context, replay bool) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return nil, ErrClosed
	}
	if err := c.ensureLocked(ctx, replay); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	stop := watchContext(ctx, c.conn.netConn)
	return func() {
		stop()
		c.mu.Unlock()
	}, nil
}

// ensureLocked establishes and authenticates a replacement connection. | ensureLocked
// 建立并认证替换连接。
func (c *Client) ensureLocked(ctx context.Context, replayAuth bool) error {
	if c.dead {
		return ErrClosed
	}
	if c.conn != nil {
		return nil
	}
	next, err := dialTransport(ctx, c.cfg)
	if err != nil {
		return c.dialError(ctx, "connect", err)
	}
	c.conn = next
	if c.cfg.StartTLS {
		if err := c.startTLSLocked(ctx); err != nil {
			c.closeConnLocked()
			return err
		}
	}
	if replayAuth && c.auth != nil {
		if err := c.replayAuthLocked(ctx, c.auth); err != nil {
			c.closeConnLocked()
			return err
		}
	}
	return nil
}

// connectLocked establishes the primary connection. | connectLocked 建立初始连接。
func (c *Client) connectLocked(ctx context.Context) error {
	return c.ensureLocked(ctx, false)
}

// watchContext arms a cancellation watcher that forces a blocked network read to
// return. The returned function waits for the watcher to exit, preventing leaks
// and late deadline writes. | watchContext 启用取消监视器，强制阻塞的网络读取返回。
// 返回函数会等待监视器退出，从而避免泄漏和延迟的期限写入。
func watchContext(ctx context.Context, netConn net.Conn) func() {
	if ctx == nil || ctx.Done() == nil || netConn == nil {
		return func() {}
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			_ = netConn.SetDeadline(time.Unix(1, 0))
		case <-stop:
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}

// sendRequestLocked assigns an ID, encodes the message and writes it. | sendRequestLocked
// 分配 ID、编码消息并写入。
func (c *Client) sendRequestLocked(ctx context.Context, op ProtocolOp, controls []Control) (int, error) {
	if c.conn == nil {
		return 0, ErrClosed
	}
	id := c.conn.nextMessageID()
	if err := c.conn.setDeadline(ctx, c.cfg.Timeout); err != nil {
		c.invalidateConnLocked()
		return 0, c.transportError(ctx, "write", err)
	}
	if err := c.conn.writeMessage(&LDAPMessage{MessageID: id, Op: op, Controls: controls}); err != nil {
		if errors.Is(err, ErrInvalidMessage) || errors.Is(err, ErrInvalidMessageTooLarge) {
			return 0, err
		}
		c.invalidateConnLocked()
		return 0, c.transportError(ctx, "write", err)
	}
	return id, nil
}

// readMessageLocked reads one message and wraps transport failures. | readMessageLocked
// 读取一条消息并包装传输故障。
func (c *Client) readMessageLocked(ctx context.Context) (*LDAPMessage, error) {
	if c.conn == nil {
		return nil, ErrClosed
	}
	if err := c.conn.setDeadline(ctx, c.cfg.Timeout); err != nil {
		c.invalidateConnLocked()
		return nil, c.transportError(ctx, "read", err)
	}
	message, err := c.conn.readMessage()
	if err == nil {
		return message, nil
	}
	if errors.Is(err, ErrProtocolError) || errors.Is(err, ErrInvalidResponse) || errors.Is(err, ErrInvalidMessageTooLarge) || errors.Is(err, ErrUnexpectedResponse) {
		c.invalidateConnLocked()
		return nil, err
	}
	c.invalidateConnLocked()
	return nil, c.transportError(ctx, "read", err)
}

// exchangeLocked performs one request/response exchange, skipping intermediate
// responses. | exchangeLocked 执行一次请求/响应交换，跳过中间响应。
func (c *Client) exchangeLocked(ctx context.Context, op ProtocolOp, controls []Control) (*LDAPMessage, error) {
	id, err := c.sendRequestLocked(ctx, op, controls)
	if err != nil {
		return nil, err
	}
	for {
		message, err := c.readMessageLocked(ctx)
		if err != nil {
			return nil, err
		}
		if message.MessageID == 0 {
			c.invalidateConnLocked()
			return nil, unsolicitedError(message)
		}
		if message.MessageID != id {
			c.invalidateConnLocked()
			return nil, errs.Detail(ErrUnexpectedResponse, "message ID %d, want %d | 消息 ID %d，期望 %d", message.MessageID, id, message.MessageID, id)
		}
		if _, ok := message.Op.(*IntermediateResponse); ok {
			continue
		}
		return message, nil
	}
}

// transportDeadlineSlack covers the scheduling gap between a socket deadline and the context
// timer firing. | transportDeadlineSlack 覆盖套接字期限与上下文计时器触发之间的调度间隙。
const transportDeadlineSlack = 5 * time.Millisecond

// contextCause reports the context error responsible for a transport failure. A socket read
// deadline derived from the context can fire a few microseconds before ctx.Err() becomes
// non-nil, so a timed-out operation whose context deadline has effectively passed is still
// attributed to the context. | contextCause 报告导致传输故障的上下文错误。由上下文派生的套接字
// 读取期限可能比 ctx.Err() 变非 nil 早几微秒，因此上下文期限实际上已过的超时操作仍归因于上下文。
func contextCause(ctx context.Context, err error) error {
	if ctx == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		return nil
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Add(transportDeadlineSlack).Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

// transportError converts a network error and invalidates the connection. | transportError
// 转换网络错误并使连接失效。
func (c *Client) transportError(ctx context.Context, operation string, err error) error {
	if cause := contextCause(ctx, err); cause != nil {
		return errs.WrapDetail(cause, ErrNetwork, "%s canceled | %s 已取消", operation, operation)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return errs.WrapDetail(err, ErrTimeout, "%s timeout | %s 超时", operation, operation)
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return errs.WrapDetail(err, ErrNetwork, "%s: connection ended | %s：连接结束", operation, operation)
	}
	return errs.WrapDetail(err, ErrNetwork, "%s failed | %s 失败", operation, operation)
}

// dialError converts a connection setup failure. | dialError 转换连接建立失败。
func (c *Client) dialError(ctx context.Context, operation string, err error) error {
	if cause := contextCause(ctx, err); cause != nil {
		return errs.WrapDetail(cause, ErrNetwork, "%s canceled | %s 已取消", operation, operation)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return errs.WrapDetail(err, ErrTimeout, "%s timeout | %s 超时", operation, operation)
	}
	return errs.WrapDetail(err, ErrNetwork, "%s failed | %s 失败", operation, operation)
}

// invalidateConnLocked closes the current transport after a desynchronizing
// failure. Authentication state is retained for the next reconnect. | invalidateConnLocked
// 在导致失步的故障后关闭当前传输。认证状态保留给下次重连。
func (c *Client) invalidateConnLocked() {
	if c.conn != nil {
		_ = c.conn.close()
		c.conn = nil
	}
}

// closeConnLocked closes the current transport. | closeConnLocked 关闭当前传输。
func (c *Client) closeConnLocked() {
	c.invalidateConnLocked()
}

// unsolicitedError converts a message-ID-zero notification into an error. | unsolicitedError
// 把消息 ID 为零的通知转换为错误。
func unsolicitedError(message *LDAPMessage) error {
	response, ok := message.Op.(*ExtendedResponse)
	if !ok {
		return errs.Detail(ErrUnexpectedResponse, "unsolicited %T | 非请求消息 %T", message.Op, message.Op)
	}
	if response.Name == OIDNoticeOfDisconnection || response.Result.Code == ResultUnavailable {
		return errs.Detail(ErrUnavailable, "server notice: %s | 服务端通知：%s", response.Result.DiagnosticMessage, response.Result.DiagnosticMessage)
	}
	return errs.Detail(ErrUnexpectedResponse, "unsolicited extended response %q | 非请求扩展响应 %q", response.Name, response.Name)
}

// Bind performs an LDAPv3 simple bind. A non-empty DN with an empty password is
// rejected before any network I/O because servers may treat it as an
// unauthenticated bind. | Bind 执行 LDAPv3 简单绑定。非空 DN 配空口令会在任何网络 I/O
// 之前被拒绝，因为服务端可能把它当作未认证绑定。
func (c *Client) Bind(ctx context.Context, dn, password string) error {
	if dn != "" && password == "" {
		return ErrEmptyPassword
	}
	release, err := c.acquire(ctx, false)
	if err != nil {
		return err
	}
	defer release()
	response, err := c.performSimpleBindLocked(ctx, dn, password)
	if err != nil {
		return err
	}
	if response.Result.Code != ResultSuccess {
		c.auth = nil
		return newResultError("bind", response.Result)
	}
	if dn == "" && password == "" {
		c.auth = nil
		return nil
	}
	c.auth = &authState{kind: authSimple, dn: dn, password: password}
	return nil
}

// BindAnonymous performs an explicit anonymous simple bind. | BindAnonymous 执行显式
// 匿名简单绑定。
func (c *Client) BindAnonymous(ctx context.Context) error {
	return c.Bind(ctx, "", "")
}

// performSimpleBindLocked sends one simple BindRequest without changing the
// replay state. | performSimpleBindLocked 发送一次简单 BindRequest 且不改变重放状态。
func (c *Client) performSimpleBindLocked(ctx context.Context, dn, password string) (*BindResponse, error) {
	message, err := c.exchangeLocked(ctx, &BindRequest{
		Version:        3,
		DN:             dn,
		Authentication: SimpleAuthentication{Password: password},
	}, nil)
	if err != nil {
		return nil, err
	}
	response, ok := message.Op.(*BindResponse)
	if !ok {
		c.invalidateConnLocked()
		return nil, errs.Detail(ErrUnexpectedResponse, "bind returned %T | 绑定返回 %T", message.Op, message.Op)
	}
	return response, nil
}

// replayAuthLocked reapplies the last successful authentication on a new
// connection. | replayAuthLocked 在新连接上重新应用最后一次成功认证。
func (c *Client) replayAuthLocked(ctx context.Context, auth *authState) error {
	if auth == nil {
		return nil
	}
	switch auth.kind {
	case authSimple:
		response, err := c.performSimpleBindLocked(ctx, auth.dn, auth.password)
		if err != nil {
			return err
		}
		return newResultError("bind", response.Result)
	case authPlain:
		return c.performSASLPlainLocked(ctx, auth.authzID, auth.authcid, auth.password)
	case authExternal:
		return c.performSASLExternalLocked(ctx, auth.authzID)
	case authSCRAM:
		return c.performSCRAMLocked(ctx, auth.scram)
	case authNTLM:
		return c.performNTLMLocked(ctx, auth.ntlm)
	default:
		return errs.Detail(ErrInvalidConfig, "unknown authentication replay kind %d | 未知认证重放类型 %d", auth.kind, auth.kind)
	}
}

// StartTLS upgrades the connection with the RFC 4511 StartTLS operation. It must
// precede Bind; TLS parameters default to Config.TLSConfig. | StartTLS 使用 RFC 4511
// StartTLS 操作升级连接。它必须在 Bind 之前调用；TLS 参数默认使用 Config.TLSConfig。
func (c *Client) StartTLS(ctx context.Context, tlsConfig *tls.Config) error {
	release, err := c.acquire(ctx, false)
	if err != nil {
		return err
	}
	defer release()
	if c.conn.secure {
		return nil
	}
	if c.auth != nil {
		return errs.Detail(ErrInvalidConfig, "StartTLS must precede Bind | StartTLS 必须在 Bind 之前")
	}
	cfg := c.cfg
	if tlsConfig != nil {
		cfg.tls = cloneTLSConfig(tlsConfig, c.cfg.endpoint.serverName)
	}
	if err := c.startTLSLockedWith(ctx, cfg); err != nil {
		return err
	}
	return nil
}

// startTLSLocked upgrades using the configured TLS parameters. | startTLSLocked
// 使用配置的 TLS 参数升级。
func (c *Client) startTLSLocked(ctx context.Context) error {
	return c.startTLSLockedWith(ctx, c.cfg)
}

// startTLSLockedWith performs the extended operation and TLS handshake. | startTLSLockedWith
// 执行扩展操作与 TLS 握手。
func (c *Client) startTLSLockedWith(ctx context.Context, cfg normalizedConfig) error {
	if c.conn == nil {
		return ErrClosed
	}
	if c.conn.secure {
		return nil
	}
	stop := watchContext(ctx, c.conn.netConn)
	response, err := c.exchangeLocked(ctx, &ExtendedRequest{Name: OIDStartTLS}, nil)
	stop()
	if err != nil {
		return err
	}
	extended, ok := response.Op.(*ExtendedResponse)
	if !ok {
		c.invalidateConnLocked()
		return errs.Detail(ErrUnexpectedResponse, "StartTLS returned %T | StartTLS 返回 %T", response.Op, response.Op)
	}
	if extended.Result.Code != ResultSuccess {
		return newResultError("StartTLS", extended.Result)
	}
	upgraded, err := upgradeTLS(ctx, c.conn, cfg)
	if err != nil {
		c.invalidateConnLocked()
		return c.dialError(ctx, "starttls handshake", err)
	}
	// upgraded wraps the same socket; closing the old transport would tear it
	// down. | upgraded 包装同一套接字；关闭旧传输会拆掉该连接。
	c.conn = upgraded
	return nil
}

// DefaultMaxPages is the automatic paging limit used when SearchOptions.MaxPages
// is zero. | DefaultMaxPages 是 SearchOptions.MaxPages 为零时使用的自动分页上限。
const DefaultMaxPages = 10000

// SearchOptions configures Search and SearchStream. | SearchOptions 配置 Search 与
// SearchStream。
type SearchOptions struct {
	// BaseDN is the search base. | BaseDN 是搜索基准。
	BaseDN string
	// Scope selects the traversal depth. | Scope 选择遍历深度。
	Scope Scope
	// DerefAliases controls alias handling. | DerefAliases 控制别名处理。
	DerefAliases DerefAliases
	// SizeLimit is the server-side entry limit. | SizeLimit 是服务端条目上限。
	SizeLimit int
	// TimeLimit is the server-side time limit in seconds. | TimeLimit 是服务端时间上限（秒）。
	TimeLimit int
	// TypesOnly requests no attribute values. | TypesOnly 请求不返回属性值。
	TypesOnly bool
	// Filter is required. | Filter 必填。
	Filter Filter
	// Attributes selects attributes; empty requests the server default set. | Attributes
	// 选择属性；为空请求服务端默认集合。
	Attributes []string
	// Controls are attached to every request; automatic paging and sorting append
	// their controls after these. | Controls 附加到每个请求；自动分页与排序会在其后追加控件。
	Controls []Control
	// PageSize enables RFC 2696 automatic paging when positive. | PageSize 为正时启用
	// RFC 2696 自动分页。
	PageSize int
	// MaxPages bounds automatic paging when PageSize is positive. Zero selects
	// DefaultMaxPages; negative values are rejected. The limit protects callers from a
	// server that keeps returning fresh cookies. | MaxPages 在 PageSize 为正时限制自动
	// 分页页数。零值选择 DefaultMaxPages；负值被拒绝。该上限保护调用方免受持续返回新
	// cookie 的服务端影响。
	MaxPages int
	// SortKeys requests server-side sorting (RFC 2891). | SortKeys 请求服务端排序（RFC 2891）。
	SortKeys []SortKey
	// OnReferral overrides Config.ReferralHandler for this search. Referrals are
	// never followed automatically. | OnReferral 为此搜索覆盖 Config.ReferralHandler。
	// 转介绝不会被自动跟随。
	OnReferral ReferralHandler
}

// SearchResult is the complete result of Search. | SearchResult 是 Search 的完整结果。
type SearchResult struct {
	// Entries are matching entries in server order. | Entries 是服务端顺序的匹配条目。
	Entries []*Entry
	// Referrals are search references and result referrals. | Referrals 是搜索引用与结果转介。
	Referrals []string
	// Controls are the final page's response controls. | Controls 是最后一页的响应控件。
	Controls []Control
	// Intermediates are intermediate responses received before completion. | Intermediates
	// 是完成前收到的中间响应。
	Intermediates []*IntermediateResponse
	// Result is the final SearchResultDone result. | Result 是最终 SearchResultDone 结果。
	Result LDAPResult
}

// Search executes a search and returns every entry. When PageSize is positive it
// automatically loops the RFC 2696 paged-results control. | Search 执行搜索并返回全部
// 条目。PageSize 为正时自动循环 RFC 2696 分页结果控件。
func (c *Client) Search(ctx context.Context, options SearchOptions) (*SearchResult, error) {
	return c.search(ctx, options, nil, true)
}

// SearchEntries is Search returning only entries. | SearchEntries 是只返回条目的 Search。
func (c *Client) SearchEntries(ctx context.Context, options SearchOptions) ([]*Entry, error) {
	result, err := c.Search(ctx, options)
	if result == nil {
		return nil, err
	}
	return result.Entries, err
}

// SearchStream streams entries to handler and returns referrals, controls and
// the final result. The handler must not block indefinitely. | SearchStream 把条目流式
// 交给 handler，并返回转介、控件与最终结果。handler 不得无限阻塞。
func (c *Client) SearchStream(ctx context.Context, options SearchOptions, handler func(*Entry) error) (*SearchResult, error) {
	if handler == nil {
		return nil, errs.Detail(ErrInvalidMessage, "nil search handler | 搜索处理函数为空")
	}
	return c.search(ctx, options, handler, false)
}

// search implements Search and SearchStream. | search 实现 Search 与 SearchStream。
func (c *Client) search(ctx context.Context, options SearchOptions, handler func(*Entry) error, collect bool) (*SearchResult, error) {
	if options.PageSize < 0 {
		return nil, errs.Detail(ErrInvalidMessage, "negative page size | 分页大小为负")
	}
	if options.Scope < ScopeBaseObject || options.Scope > ScopeWholeSubtree {
		return nil, errs.Detail(ErrInvalidMessage, "invalid search scope %d | 搜索范围 %d 非法", options.Scope, options.Scope)
	}
	if err := ValidateFilter(options.Filter); err != nil {
		return nil, err
	}
	if options.SizeLimit < 0 || options.TimeLimit < 0 {
		return nil, errs.Detail(ErrInvalidMessage, "negative search limit | 搜索限制为负")
	}
	if options.MaxPages < 0 {
		return nil, errs.Detail(ErrInvalidMessage, "negative page limit | 分页页数上限为负")
	}
	maxPages := options.MaxPages
	if maxPages == 0 {
		maxPages = DefaultMaxPages
	}
	request := &SearchRequest{
		BaseDN:       options.BaseDN,
		Scope:        options.Scope,
		DerefAliases: options.DerefAliases,
		SizeLimit:    options.SizeLimit,
		TimeLimit:    options.TimeLimit,
		TypesOnly:    options.TypesOnly,
		Filter:       options.Filter,
		Attributes:   append([]string(nil), options.Attributes...),
	}
	referralHandler := options.OnReferral
	if referralHandler == nil {
		referralHandler = c.cfg.ReferralHandler
	}
	result := &SearchResult{}
	release, err := c.acquire(ctx, true)
	if err != nil {
		return nil, err
	}
	defer release()
	var cookie []byte
	pages := 0
	seenCookies := make(map[uint64]struct{})
	for {
		if options.PageSize > 0 {
			if pages >= maxPages {
				return result, errs.Detail(ErrPagingLimit, "paged search exceeded %d pages | 分页搜索超过 %d 页", maxPages, maxPages)
			}
			pages++
		}
		controls := append([]Control(nil), options.Controls...)
		if len(options.SortKeys) > 0 {
			controls = replaceControl(controls, SortControl(options.SortKeys...))
		}
		if options.PageSize > 0 {
			controls = replaceControl(controls, PagedResultsControl(options.PageSize, cookie))
		}
		page, pageErr := c.searchOnceLocked(ctx, request, controls, result, handler, collect, referralHandler)
		if page != nil {
			result.Result = page.Result
			result.Controls = page.Controls
			result.Referrals = append(result.Referrals, page.Referrals...)
			result.Intermediates = append(result.Intermediates, page.Intermediates...)
			if collect {
				result.Entries = append(result.Entries, page.Entries...)
			}
		}
		if pageErr != nil {
			return result, pageErr
		}
		if options.PageSize <= 0 {
			return result, nil
		}
		pagedControl, ok := findControl(result.Controls, OIDPagedResults)
		if !ok {
			return result, errs.Detail(ErrPagingUnsupported, "paged search response lacks %s | 分页搜索响应缺少 %s", OIDPagedResults, OIDPagedResults)
		}
		_, nextCookie, err := ParsePagedResultsControl(pagedControl)
		if err != nil {
			return result, err
		}
		if len(nextCookie) == 0 {
			return result, nil
		}
		cookieKey := pagingCookieKey(nextCookie)
		if _, seen := seenCookies[cookieKey]; seen {
			return result, ErrPagingLoop
		}
		seenCookies[cookieKey] = struct{}{}
		cookie = nextCookie
	}
}

// pagingCookieKey hashes an opaque paging cookie so the cycle detector keeps a
// bounded fixed-size record per page even if a server returns large cookies. |
// pagingCookieKey 对不透明分页 cookie 做哈希，使循环检测即使面对超大 cookie 也只为每页
// 保存定长记录。
func pagingCookieKey(cookie []byte) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	hash := uint64(offset64)
	for _, b := range cookie {
		hash ^= uint64(b)
		hash *= prime64
	}
	return hash
}

// searchOnceLocked performs one search request and consumes its response stream.
// | searchOnceLocked 执行一次搜索请求并消费其响应流。
func (c *Client) searchOnceLocked(ctx context.Context, request *SearchRequest, controls []Control, result *SearchResult, handler func(*Entry) error, collect bool, referralHandler ReferralHandler) (*SearchResult, error) {
	page := &SearchResult{}
	id, err := c.sendRequestLocked(ctx, request, controls)
	if err != nil {
		return page, err
	}
	for {
		message, err := c.readMessageLocked(ctx)
		if err != nil {
			return page, err
		}
		if message.MessageID == 0 {
			c.invalidateConnLocked()
			return page, unsolicitedError(message)
		}
		if message.MessageID != id {
			c.invalidateConnLocked()
			return page, errs.Detail(ErrUnexpectedResponse, "message ID %d, want %d | 消息 ID %d，期望 %d", message.MessageID, id, message.MessageID, id)
		}
		switch response := message.Op.(type) {
		case *Entry:
			responseCopy := response
			if collect {
				page.Entries = append(page.Entries, responseCopy)
			}
			if handler != nil {
				if err := handler(responseCopy); err != nil {
					c.invalidateConnLocked()
					return page, err
				}
			}
		case *SearchResultReference:
			page.Referrals = append(page.Referrals, response.URIs...)
			page.Result.Referrals = append(page.Result.Referrals, response.URIs...)
			if referralHandler != nil {
				if err := referralHandler(ctx, append([]string(nil), response.URIs...)); err != nil {
					c.invalidateConnLocked()
					return page, err
				}
			}
		case *IntermediateResponse:
			page.Intermediates = append(page.Intermediates, response)
		case *SearchResultDone:
			page.Result = response.Result
			page.Controls = message.Controls
			page.Referrals = append(page.Referrals, response.Result.Referrals...)
			if referralHandler != nil && len(response.Result.Referrals) > 0 {
				if err := referralHandler(ctx, append([]string(nil), response.Result.Referrals...)); err != nil {
					c.invalidateConnLocked()
					return page, err
				}
			}
			if response.Result.Code != ResultSuccess {
				return page, newResultError("search", response.Result)
			}
			return page, nil
		default:
			c.invalidateConnLocked()
			return page, errs.Detail(ErrUnexpectedResponse, "search returned %T | 搜索返回 %T", message.Op, message.Op)
		}
	}
}

// replaceControl removes existing controls with the same OID and appends control.
// | replaceControl 移除相同 OID 的既有控件并追加 control。
func replaceControl(controls []Control, control Control) []Control {
	filtered := controls[:0]
	for _, existing := range controls {
		if existing.Type != control.Type {
			filtered = append(filtered, existing)
		}
	}
	return append(filtered, control)
}
