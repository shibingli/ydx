package kmip

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
)

// AuthorizationRequest describes one operation for an Authorizer. | AuthorizationRequest 描述供 Authorizer 检查的一次操作。
type AuthorizationRequest struct {
	// Operation is the requested operation. | Operation 是请求的操作。
	Operation Operation
	// ObjectType is the affected object type, or zero when not known. | ObjectType 是受影响的对象类型，未知时为零。
	ObjectType ObjectType
	// UniqueIdentifier is the affected object identifier, or empty when not known. | UniqueIdentifier 是受影响的对象标识符，未知时为空。
	UniqueIdentifier string
	// Credentials holds the credentials sent in the request header. | Credentials 保存请求头中发送的凭据。
	Credentials []Credential
	// RemoteAddr is the client network address. | RemoteAddr 是客户端网络地址。
	RemoteAddr string
}

// Authorizer decides whether a client may perform an operation. | Authorizer 决定客户端是否可以执行操作。
type Authorizer interface {
	// Authorize returns nil to allow the operation or an error to deny it. | Authorize 返回 nil 允许操作，返回错误则拒绝。
	Authorize(ctx context.Context, request AuthorizationRequest) error
}

// AuthorizerFunc adapts a function to an Authorizer. | AuthorizerFunc 把函数适配为 Authorizer。
type AuthorizerFunc func(ctx context.Context, request AuthorizationRequest) error

// Authorize implements Authorizer. | Authorize 实现 Authorizer。
func (f AuthorizerFunc) Authorize(ctx context.Context, request AuthorizationRequest) error {
	if f == nil {
		return nil
	}
	return f(ctx, request)
}

// ServerConfig configures a KMIP Server. | ServerConfig 配置 KMIP Server。
type ServerConfig struct {
	// Address is the TCP listen address; empty means ":5696", the KMIP standard port. | Address 是 TCP 监听地址；为空表示 ":5696"，即 KMIP 标准端口。
	Address string
	// TLSConfig enables TLS when non-nil. | TLSConfig 非空时启用 TLS。
	TLSConfig *tls.Config
	// RequireClientCertificate requests and verifies a client certificate. | RequireClientCertificate 要求并校验客户端证书。
	RequireClientCertificate bool
	// AllowPlaintext permits ListenAndServe without TLS. Tests may set it; production deployments should not. | AllowPlaintext
	// 允许不带 TLS 的 ListenAndServe；测试可设置，生产部署不应设置。
	AllowPlaintext bool
	// Store persists objects; nil uses a new MemoryStore. | Store 持久化对象；为空时使用新的 MemoryStore。
	Store Store
	// Authorizer optionally authorizes every batch item. | Authorizer 可选地授权每个批处理项。
	Authorizer Authorizer
	// Clock supplies the current time; nil uses time.Now. | Clock 提供当前时间；为空时使用 time.Now。
	Clock Clock
	// Logger receives server diagnostics; nil disables logging. Key material and passwords are never logged. | Logger
	// 接收服务器诊断；为空时不记录日志。绝不记录密钥材料与口令。
	Logger *log.Logger
	// MaxRequestSize limits a single encoded request; zero uses DefaultMaxMessageSize. | MaxRequestSize 限制单个编码请求；零值使用 DefaultMaxMessageSize。
	MaxRequestSize int
	// MaxUndoLogBytes limits the memory retained by the per-batch Batch Undo journal; zero uses
	// DefaultMaxUndoLogBytes. A mutating item that would exceed the budget fails without changing the store. |
	// MaxUndoLogBytes 限制每批 Batch Undo 撤销日志保留的内存；零值使用 DefaultMaxUndoLogBytes。会使预算超限的
	// 变更项会失败且不改变存储。
	MaxUndoLogBytes int
	// Limits optionally overrides the TTLV resource limits. | Limits 可选覆盖 TTLV 资源限制。
	Limits Limits
	// ReadTimeout bounds one request read; zero disables the deadline. | ReadTimeout 限制一次请求读取；零值不设截止时间。
	ReadTimeout time.Duration
	// WriteTimeout bounds one response write; zero disables the deadline. | WriteTimeout 限制一次响应写入；零值不设截止时间。
	WriteTimeout time.Duration
	// ShutdownTimeout bounds Close; zero uses five seconds. | ShutdownTimeout 限制 Close 时长；零值使用五秒。
	ShutdownTimeout time.Duration
}

// Server is a KMIP server. It accepts TTLV request messages over TCP or TLS and dispatches batch items. | Server
// 是 KMIP 服务器，通过 TCP 或 TLS 接收 TTLV 请求消息并分发批处理项。
type Server struct {
	cfg       ServerConfig
	limits    Limits
	store     Store
	now       Clock
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	batchMu   sync.Mutex
	undo      *batchUndoLog
	lns       map[net.Listener]struct{}
	conns     map[net.Conn]struct{}
	wg        sync.WaitGroup
	closed    bool
	once      sync.Once
	addr      net.Addr
	maxSize   int
	undoLimit int
}

// NewServer returns a server using cfg. The caller must close it to release listeners and connections. | NewServer
// 返回使用 cfg 的服务器；调用方必须关闭它以释放监听器与连接。
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Store == nil {
		cfg.Store = NewMemoryStore()
	}
	if cfg.Address == "" {
		cfg.Address = ":5696"
	}
	if cfg.MaxRequestSize <= 0 {
		cfg.MaxRequestSize = DefaultMaxMessageSize
	}
	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = 5 * time.Second
	}
	undoLimit := cfg.MaxUndoLogBytes
	if undoLimit <= 0 {
		undoLimit = DefaultMaxUndoLogBytes
	}
	limits := cfg.Limits.normalized()
	if limits.MaxSize > cfg.MaxRequestSize {
		limits.MaxSize = cfg.MaxRequestSize
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg:       cfg,
		limits:    limits,
		store:     cfg.Store,
		now:       clock,
		ctx:       ctx,
		cancel:    cancel,
		lns:       make(map[net.Listener]struct{}),
		conns:     make(map[net.Conn]struct{}),
		maxSize:   cfg.MaxRequestSize,
		undoLimit: undoLimit,
	}, nil
}

// Addr returns the address of the first active listener, or nil. | Addr 返回第一个活动监听器的地址，或 nil。
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}

// ListenAndServe listens on the configured address and serves until Close. TLS is mandatory unless AllowPlaintext is
// set. | ListenAndServe 在配置地址上监听并服务直到 Close；除非设置 AllowPlaintext，否则必须使用 TLS。
func (s *Server) ListenAndServe() error {
	if s.cfg.TLSConfig == nil && !s.cfg.AllowPlaintext {
		return ErrTLSRequired
	}
	var listener net.Listener
	var err error
	if s.cfg.TLSConfig != nil {
		cfg := s.cfg.TLSConfig.Clone()
		if cfg.MinVersion == 0 {
			cfg.MinVersion = tls.VersionTLS12
		}
		if s.cfg.RequireClientCertificate {
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		}
		listener, err = tls.Listen("tcp", s.cfg.Address, cfg)
	} else {
		listener, err = net.Listen("tcp", s.cfg.Address)
	}
	if err != nil {
		return errs.Wrap(err, ErrClosed)
	}
	return s.ServeListener(listener)
}

// ServeListener accepts connections from listener until Close. The server takes ownership of listener. | ServeListener
// 从 listener 接受连接直到 Close；服务器接管 listener。
func (s *Server) ServeListener(listener net.Listener) error {
	if listener == nil {
		return errs.Detail(ErrInvalidRequest, "nil listener | 监听器为 nil")
	}
	if err := s.registerListener(listener); err != nil {
		_ = listener.Close()
		return err
	}
	defer s.unregisterListener(listener)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if s.isClosed() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go func(c net.Conn) {
			if err := s.Serve(c); err != nil && !s.isClosed() && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				s.warn("kmip connection ended | KMIP 连接结束", log.Str("remote", c.RemoteAddr().String()), log.Err(err))
			}
		}(conn)
	}
}

// Serve handles one connection until it is closed or an unrecoverable framing error occurs. The server takes ownership
// of conn and closes it. | Serve 处理单个连接直到连接关闭或出现不可恢复的帧错误；服务器接管并关闭 conn。
func (s *Server) Serve(conn net.Conn) error {
	if conn == nil {
		return errs.Detail(ErrInvalidRequest, "nil connection | 连接为 nil")
	}
	if !s.cfg.AllowPlaintext {
		if _, ok := conn.(*tls.Conn); !ok {
			_ = conn.Close()
			return ErrTLSRequired
		}
	}
	if s.isClosed() {
		_ = conn.Close()
		return ErrClosed
	}
	if !s.registerConn(conn) {
		_ = conn.Close()
		return ErrClosed
	}
	defer func() {
		s.unregisterConn(conn)
		_ = conn.Close()
	}()
	for {
		if s.isClosed() {
			return nil
		}
		if s.cfg.ReadTimeout > 0 {
			// Transport deadlines use wall-clock time; s.now() may be a test clock. | 传输截止时间使用
			// 墙钟时间，s.now() 可能是测试时钟。
			_ = conn.SetReadDeadline(time.Now().Add(s.cfg.ReadTimeout))
		}
		raw, err := readRequest(conn, s.maxSize)
		if err != nil {
			if s.isClosed() || errors.Is(err, io.EOF) {
				return nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return nil
			}
			return err
		}
		request, err := DecodeRequestWithLimits(raw, s.limits)
		if err != nil {
			zeroize(raw)
			return err
		}
		response := s.handleMessage(conn, request)
		data, err := EncodeResponseWithLimits(response, s.limits)
		zeroize(raw)
		if err != nil {
			return err
		}
		limit := request.Header.MaximumResponseSize
		if limit > 0 && len(data) > limit {
			fallback := s.tooLargeResponse(request)
			zeroize(data)
			data, err = EncodeResponseWithLimits(fallback, s.limits)
			if err != nil {
				return err
			}
		}
		if s.cfg.WriteTimeout > 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(s.cfg.WriteTimeout))
		}
		if err := writeAll(conn, data); err != nil {
			zeroize(data)
			return err
		}
		zeroize(data)
	}
}

// Close stops accepting connections, closes active connections and waits for handlers. It is idempotent. | Close
// 停止接受连接、关闭活动连接并等待处理协程；可重复调用。
func (s *Server) Close() error {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		listeners := make([]net.Listener, 0, len(s.lns))
		for listener := range s.lns {
			listeners = append(listeners, listener)
		}
		conns := make([]net.Conn, 0, len(s.conns))
		for conn := range s.conns {
			conns = append(conns, conn)
		}
		s.mu.Unlock()
		s.cancel()
		for _, listener := range listeners {
			_ = listener.Close()
		}
		for _, conn := range conns {
			_ = conn.Close()
		}
		done := make(chan struct{})
		go func() {
			s.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(s.cfg.ShutdownTimeout):
		}
	})
	return nil
}

// handleMessage executes all batch items under the batch continuation policy. Batches are serialized per server so
// that a Batch Undo journal only ever covers the mutations of its own request message. | handleMessage 按批处理继续
// 策略执行全部批处理项。服务器内批处理串行执行，因此 Batch Undo 撤销日志只覆盖本请求消息的变更。
func (s *Server) handleMessage(conn net.Conn, request RequestMessage) ResponseMessage {
	s.batchMu.Lock()
	defer s.batchMu.Unlock()
	now := s.now()
	version := request.Header.ProtocolVersion
	if !version.Valid() {
		version = DefaultProtocolVersion
	}
	response := ResponseMessage{Header: ResponseHeader{
		ProtocolVersion:        version,
		TimeStamp:              now,
		ClientCorrelationValue: request.Header.ClientCorrelationValue,
		ServerCorrelationValue: request.Header.ServerCorrelationValue,
	}}
	unsupportedVersion := !request.Header.ProtocolVersion.Supported()
	if len(request.BatchItems) == 0 {
		response.Header.BatchCount = 0
		return response
	}
	stopOnError := request.Header.BatchErrorContinuationOption == 0 ||
		request.Header.BatchErrorContinuationOption == BatchStop ||
		request.Header.BatchErrorContinuationOption == BatchUndo
	batchUndo := request.Header.BatchErrorContinuationOption == BatchUndo && !unsupportedVersion
	if batchUndo {
		s.undo = newBatchUndoLog(s.undoLimit)
		defer func() {
			s.undo.clear()
			s.undo = nil
		}()
	}
	credentials := credentialsFromHeader(request.Header.Authentication)
	remote := ""
	if conn != nil && conn.RemoteAddr() != nil {
		remote = conn.RemoteAddr().String()
	}
	for i := range request.BatchItems {
		item := request.BatchItems[i]
		if unsupportedVersion {
			err := errs.Detail(ErrUnsupported,
				"protocol version %s is not supported; use KMIP 1.4 or 2.0 | 协议版本 %s 不受支持；请使用 KMIP 1.4 或 2.0",
				request.Header.ProtocolVersion, request.Header.ProtocolVersion)
			response.BatchItems = append(response.BatchItems, failureItem(item, err))
			if stopOnError {
				break
			}
			continue
		}
		if err := s.authorize(item, credentials, remote); err != nil {
			response.BatchItems = append(response.BatchItems, failureItem(item, err))
			if stopOnError {
				if batchUndo {
					_ = s.undoBatch(&response)
				}
				break
			}
			continue
		}
		if s.undo != nil {
			s.undo.beginItem(item.Operation)
		}
		payload, err := s.dispatchForVersion(item, request.Header.ProtocolVersion)
		if err != nil {
			s.warn("kmip operation failed | KMIP 操作失败",
				log.Str("operation", item.Operation.String()),
				log.Err(err))
			response.BatchItems = append(response.BatchItems, failureItem(item, err))
			if stopOnError {
				if batchUndo {
					_ = s.undoBatch(&response)
				}
				break
			}
			continue
		}
		response.BatchItems = append(response.BatchItems, ResponseBatchItem{
			Operation:         item.Operation,
			UniqueBatchItemID: append([]byte(nil), item.UniqueBatchItemID...),
			ResultStatus:      ResultStatusSuccess,
			Payload:           payload,
		})
	}
	response.Header.BatchCount = len(response.BatchItems)
	return response
}

// undoBatch replays the per-batch inverse-operation journal after a failed Batch Undo item. Successful response
// items become Operation Undone and their payloads are dropped so that no key material is exported for an operation
// that was rolled back. When a restore fails, the joined diagnostic is logged and returned, and every successful
// item is reported as a general failure because batch atomicity could not be established. | undoBatch 在 Batch Undo
// 项失败后重放每批逆操作日志。成功的响应项变为 Operation Undone，并丢弃其负载，避免为已回滚的操作导出密钥材料。
// 恢复失败时记录并返回合并诊断，所有成功项都报告为通用失败，因为无法保证批处理原子性。
func (s *Server) undoBatch(response *ResponseMessage) error {
	var rollbackErr error
	if s.undo != nil {
		rollbackErr = s.undo.rollback(s.ctx, s.store)
	}
	if rollbackErr != nil {
		s.warn("kmip batch undo failed | KMIP 批处理撤销失败", log.Err(rollbackErr))
		for i := range response.BatchItems {
			if response.BatchItems[i].ResultStatus != ResultStatusSuccess {
				continue
			}
			response.BatchItems[i].ResultStatus = ResultStatusOperationFailed
			response.BatchItems[i].ResultReason = ResultReasonGeneralFailure
			response.BatchItems[i].ResultMessage = "batch undo failed | 批处理撤销失败: " + rollbackErr.Error()
			response.BatchItems[i].Payload = Item{}
		}
		return rollbackErr
	}
	for i := range response.BatchItems {
		if response.BatchItems[i].ResultStatus != ResultStatusSuccess {
			continue
		}
		response.BatchItems[i].ResultStatus = ResultStatusOperationUndone
		response.BatchItems[i].Payload = Item{}
	}
	return nil
}

// createRecord stores a new record and journals its identifier so Batch Undo can delete it. | createRecord 存储新记录
// 并记录其标识符，使 Batch Undo 能删除它。
func (s *Server) createRecord(record ObjectRecord) error {
	if s.undo != nil {
		if err := s.undo.recordCreate(record.UniqueIdentifier); err != nil {
			return err
		}
	}
	if err := s.store.Create(s.ctx, record); err != nil {
		if s.undo != nil {
			s.undo.dropLast(undoMutationCreate, record.UniqueIdentifier)
		}
		return err
	}
	return nil
}

// updateRecord replaces an existing record. previous must be a deep copy of the record as it was loaded before the
// caller applied its mutation; ownership of previous transfers to the undo journal, or it is zeroized when no
// journal is active. | updateRecord 替换既有记录。previous 必须是调用方应用变更前加载记录的深拷贝；previous 的
// 所有权转移给撤销日志，没有活动日志时则将其清零。
func (s *Server) updateRecord(previous, record ObjectRecord) error {
	if s.undo != nil {
		if err := s.undo.recordUpdate(previous); err != nil {
			zeroizeRecord(&previous)
			return err
		}
	} else {
		zeroizeRecord(&previous)
	}
	if err := s.store.Update(s.ctx, record); err != nil {
		if s.undo != nil {
			s.undo.dropLast(undoMutationUpdate, record.UniqueIdentifier)
		}
		return err
	}
	return nil
}

// discardNewRecord removes a record that was created earlier in the same batch without journaling the removal, and
// drops its create entry. It is the compensating action for a partially applied multi-object operation such as
// Create Key Pair. | discardNewRecord 删除同一批中先前创建且不记录删除操作的记录，并丢弃其创建条目。它是
// Create Key Pair 等多对象操作部分失败时的补偿动作。
func (s *Server) discardNewRecord(uniqueIdentifier string) {
	if err := s.store.Delete(s.ctx, uniqueIdentifier); err != nil && !errors.Is(err, ErrItemNotFound) {
		// Keep the create entry so a later Batch Undo rollback retries the deletion. | 保留创建条目，使后续
		// Batch Undo 回滚可以重试删除。
		return
	}
	if s.undo != nil {
		s.undo.dropLast(undoMutationCreate, uniqueIdentifier)
	}
}

// dispatch executes one operation using KV 1.4 payloads. | dispatch 使用 KV 1.4 负载执行单个操作。
func (s *Server) dispatch(item RequestBatchItem) (Item, error) {
	return s.dispatchForVersion(item, DefaultProtocolVersion)
}

// dispatchForVersion executes one operation using the payload shape of version. | dispatchForVersion 使用 version 的
// 负载形状执行单个操作。
func (s *Server) dispatchForVersion(item RequestBatchItem, version ProtocolVersion) (Item, error) {
	payload := item.Payload
	switch item.Operation {
	case OpCreate:
		request, err := DecodeCreateRequestForVersion(payload, version)
		if err != nil {
			return Item{}, err
		}
		return s.handleCreateForVersion(request, version)
	case OpCreateKeyPair:
		request, err := DecodeCreateKeyPairRequestForVersion(payload, version)
		if err != nil {
			return Item{}, err
		}
		return s.handleCreateKeyPairForVersion(request, version)
	case OpRegister:
		request, err := DecodeRegisterRequestForVersion(payload, version)
		if err != nil {
			return Item{}, err
		}
		return s.handleRegisterForVersion(request, version)
	case OpGet:
		request, err := DecodeGetRequestForVersion(payload, version)
		if err != nil {
			return Item{}, err
		}
		return s.handleGetForVersion(request, version)
	case OpGetAttributes:
		request, err := DecodeGetAttributesRequestForVersion(payload, version)
		if err != nil {
			return Item{}, err
		}
		return s.handleGetAttributesForVersion(request, version)
	case OpGetAttributeList:
		request, err := DecodeGetAttributeListRequest(payload)
		if err != nil {
			return Item{}, err
		}
		return s.handleGetAttributeListForVersion(request, version)
	case OpExport:
		if usesKMIP20Payloads(version) {
			return Item{}, errs.Detail(ErrUnsupported,
				"Export was removed in KMIP 2.0; use Get | KMIP 2.0 已移除 Export；请使用 Get")
		}
		request, err := DecodeExportRequest(payload)
		if err != nil {
			return Item{}, err
		}
		return s.handleExportForVersion(request, version)
	case OpActivate:
		request, err := DecodeActivateRequest(payload)
		if err != nil {
			return Item{}, err
		}
		return s.handleActivate(request)
	case OpRevoke:
		request, err := DecodeRevokeRequest(payload)
		if err != nil {
			return Item{}, err
		}
		return s.handleRevoke(request)
	case OpDestroy:
		request, err := DecodeDestroyRequest(payload)
		if err != nil {
			return Item{}, err
		}
		return s.handleDestroy(request)
	case OpLocate:
		request, err := DecodeLocateRequestForVersion(payload, version)
		if err != nil {
			return Item{}, err
		}
		return s.handleLocate(request)
	case OpDeriveKey:
		request, err := DecodeDeriveKeyRequestForVersion(payload, version)
		if err != nil {
			return Item{}, err
		}
		return s.handleDeriveKeyForVersion(request, version)
	case OpEncrypt:
		request, err := DecodeEncryptRequest(payload)
		if err != nil {
			return Item{}, err
		}
		return s.handleEncrypt(request)
	case OpDecrypt:
		request, err := DecodeDecryptRequest(payload)
		if err != nil {
			return Item{}, err
		}
		return s.handleDecrypt(request)
	case OpSign:
		request, err := DecodeSignRequest(payload)
		if err != nil {
			return Item{}, err
		}
		return s.handleSign(request)
	case OpSignatureVerify:
		request, err := DecodeVerifyRequest(payload)
		if err != nil {
			return Item{}, err
		}
		return s.handleVerify(request)
	case OpMAC:
		request, err := DecodeMACRequest(payload)
		if err != nil {
			return Item{}, err
		}
		return s.handleMAC(request)
	case OpMACVerify:
		request, err := DecodeMACVerifyRequest(payload)
		if err != nil {
			return Item{}, err
		}
		return s.handleMACVerify(request)
	case OpWrapKey:
		request, err := DecodeWrapKeyRequest(payload)
		if err != nil {
			return Item{}, err
		}
		return s.handleWrapKeyForVersion(request, version)
	case OpUnwrapKey:
		request, err := DecodeUnwrapKeyRequestForVersion(payload, version)
		if err != nil {
			return Item{}, err
		}
		return s.handleUnwrapKey(request)
	case OpQuery:
		request, err := DecodeQueryRequest(payload)
		if err != nil {
			return Item{}, err
		}
		return s.handleQuery(request)
	case OpDiscoverVersions:
		request, err := DecodeDiscoverVersionsRequest(payload)
		if err != nil {
			return Item{}, err
		}
		return s.handleDiscoverVersions(request)
	case OpCheck:
		request, err := DecodeCheckRequest(payload)
		if err != nil {
			return Item{}, err
		}
		return s.handleCheck(request)
	default:
		return Item{}, errs.Detail(ErrUnsupported, "operation %s is not supported | 不支持操作 %s", item.Operation, item.Operation)
	}
}

// authorize runs the configured Authorizer for one batch item. | authorize 为单个批处理项运行配置的 Authorizer。
func (s *Server) authorize(item RequestBatchItem, credentials []Credential, remote string) error {
	if s.cfg.Authorizer == nil {
		return nil
	}
	request := AuthorizationRequest{
		Operation:        item.Operation,
		UniqueIdentifier: payloadText(item.Payload, TagUniqueIdentifier),
		ObjectType:       payloadObjectType(item.Payload),
		Credentials:      credentials,
		RemoteAddr:       remote,
	}
	if err := s.cfg.Authorizer.Authorize(s.ctx, request); err != nil {
		if errors.Is(err, ErrPermissionDenied) || errors.Is(err, ErrAuthenticationFailed) {
			return err
		}
		return errs.Wrap(err, ErrPermissionDenied)
	}
	return nil
}

// payloadText extracts the first text value with tag from a payload. | payloadText 从负载提取首个指定标签的文本值。
func payloadText(item Item, tag Tag) string {
	child, ok := item.Child(tag)
	if !ok {
		return ""
	}
	value, err := child.AsTextString()
	if err != nil {
		return ""
	}
	return value
}

// payloadObjectType extracts an Object Type from a payload or a contained managed object. | payloadObjectType
// 从负载或其中包含的受管对象提取 Object Type。
func payloadObjectType(item Item) ObjectType {
	if child, ok := item.Child(TagObjectType); ok {
		if value, err := child.AsEnumeration(); err == nil {
			return ObjectType(value)
		}
	}
	for _, child := range item.Children {
		switch child.Tag {
		case TagSymmetricKey:
			return ObjectTypeSymmetricKey
		case TagPublicKey:
			return ObjectTypePublicKey
		case TagPrivateKey:
			return ObjectTypePrivateKey
		case TagSecretData:
			return ObjectTypeSecretData
		case TagCertificate:
			return ObjectTypeCertificate
		case TagTemplate:
			return ObjectTypeTemplate
		case TagOpaqueObject:
			return ObjectTypeOpaqueObject
		}
	}
	return 0
}

// credentialsFromHeader copies header credentials. | credentialsFromHeader 复制请求头凭据。
func credentialsFromHeader(auth *Authentication) []Credential {
	if auth == nil {
		return nil
	}
	return append([]Credential(nil), auth.Credentials...)
}

// failureItem builds a failed response batch item. | failureItem 构造失败的响应批处理项。
func failureItem(request RequestBatchItem, err error) ResponseBatchItem {
	result := asResultError(err)
	return ResponseBatchItem{
		Operation:         request.Operation,
		UniqueBatchItemID: append([]byte(nil), request.UniqueBatchItemID...),
		ResultStatus:      result.Status,
		ResultReason:      result.Reason,
		ResultMessage:     result.Message,
	}
}

// tooLargeResponse builds a minimal response reporting a response-size overflow. | tooLargeResponse 构造报告响应超限的最小响应。
func (s *Server) tooLargeResponse(request RequestMessage) ResponseMessage {
	response := ResponseMessage{Header: ResponseHeader{
		ProtocolVersion:        request.Header.ProtocolVersion,
		TimeStamp:              s.now(),
		ClientCorrelationValue: request.Header.ClientCorrelationValue,
		ServerCorrelationValue: request.Header.ServerCorrelationValue,
		BatchCount:             1,
	}}
	var item RequestBatchItem
	if len(request.BatchItems) > 0 {
		item = request.BatchItems[0]
	}
	response.BatchItems = []ResponseBatchItem{{
		Operation:         item.Operation,
		UniqueBatchItemID: append([]byte(nil), item.UniqueBatchItemID...),
		ResultStatus:      ResultStatusOperationFailed,
		ResultReason:      ResultReasonResponseTooLarge,
		ResultMessage:     "response exceeds the requested maximum size | 响应超过请求的最大长度",
	}}
	return response
}

// readRequest reads one length-prefixed TTLV request structure. | readRequest 读取一个带长度前缀的 TTLV 请求结构。
func readRequest(conn net.Conn, maxSize int) ([]byte, error) {
	var header [ttlvHeaderSize]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	length := uint64(binary.BigEndian.Uint32(header[4:8]))
	total := length + ttlvHeaderSize
	if maxSize > 0 && total > uint64(maxSize) {
		return nil, errs.Detail(ErrLimitExceeded, "request length %d exceeds limit %d | 请求长度 %d 超过限制 %d", total, maxSize, total, maxSize)
	}
	if Type(header[3]) != TypeStructure {
		return nil, errs.Detail(ErrMalformed, "request message is not a structure | 请求消息不是结构")
	}
	tag := Tag(uint32(header[0])<<16 | uint32(header[1])<<8 | uint32(header[2]))
	if tag != TagRequestMessage {
		return nil, errs.Detail(ErrMalformed, "unexpected request tag 0x%06X | 请求标签 0x%06X 非预期", uint32(tag), uint32(tag))
	}
	raw := make([]byte, total)
	copy(raw, header[:])
	if length > 0 {
		if _, err := io.ReadFull(conn, raw[ttlvHeaderSize:]); err != nil {
			zeroize(raw)
			return nil, err
		}
	}
	return raw, nil
}

// writeAll writes all bytes to conn. | writeAll 向 conn 写入全部字节。
func writeAll(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

// registerListener tracks a listener. | registerListener 跟踪监听器。
func (s *Server) registerListener(listener net.Listener) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	s.lns[listener] = struct{}{}
	if s.addr == nil {
		s.addr = listener.Addr()
	}
	return nil
}

// unregisterListener stops tracking a listener. | unregisterListener 停止跟踪监听器。
func (s *Server) unregisterListener(listener net.Listener) {
	s.mu.Lock()
	delete(s.lns, listener)
	s.mu.Unlock()
}

// registerConn tracks a connection, returning false when the server is closed. | registerConn 跟踪连接；服务器已关闭时返回 false。
func (s *Server) registerConn(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	if _, exists := s.conns[conn]; exists {
		return true
	}
	s.conns[conn] = struct{}{}
	// The wait-group increment happens under the same lock that Close uses to publish closed, so it
	// cannot race with Close's Wait on a zero counter. | 等待组计数与 Close 发布 closed 使用同一把锁，
	// 因此不会与 Close 在计数归零时的 Wait 竞争。
	s.wg.Add(1)
	return true
}

// unregisterConn stops tracking a connection. | unregisterConn 停止跟踪连接。
func (s *Server) unregisterConn(conn net.Conn) {
	s.mu.Lock()
	_, tracked := s.conns[conn]
	if tracked {
		delete(s.conns, conn)
	}
	s.mu.Unlock()
	if tracked {
		s.wg.Done()
	}
}

// isClosed reports whether Close has run. | isClosed 报告 Close 是否已执行。
func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// warn logs a warning when a logger is configured. | warn 在配置日志器时记录警告。
func (s *Server) warn(message string, fields ...log.Field) {
	if s.cfg.Logger != nil {
		s.cfg.Logger.Warn(message, fields...)
	}
}

// SupportedOperations returns the operations implemented by Server, in protocol order. | SupportedOperations
// 按协议顺序返回 Server 实现的操作。
func SupportedOperations() []Operation {
	return []Operation{
		OpCreate, OpCreateKeyPair, OpRegister, OpGet, OpGetAttributes, OpGetAttributeList,
		OpActivate, OpRevoke, OpDestroy, OpExport, OpLocate, OpDeriveKey,
		OpEncrypt, OpDecrypt, OpSign, OpSignatureVerify, OpMAC, OpMACVerify,
		OpWrapKey, OpUnwrapKey, OpQuery, OpDiscoverVersions, OpCheck,
	}
}

// supportedObjectTypes returns the managed object types accepted by the server. | supportedObjectTypes 返回服务器接受的受管对象类型。
func supportedObjectTypes() []ObjectType {
	return []ObjectType{
		ObjectTypeSymmetricKey, ObjectTypePublicKey, ObjectTypePrivateKey,
		ObjectTypeSecretData, ObjectTypeCertificate, ObjectTypeTemplate, ObjectTypeOpaqueObject,
	}
}
