package radius

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// packetBuilder builds one transmission attempt. | packetBuilder 构建一次传输尝试。
type packetBuilder func(attempt int) (raw []byte, requestAuthenticator [16]byte, err error)

// responseVerifier validates a candidate response. Returning ErrAuthenticator marks the candidate
// as unauthenticated: UDP transports silently discard it and keep reading until a valid response or
// the attempt deadline, as RFC 2865 sections 4.2 and 4.4 require, while stream transports report it
// and close the connection as RFC 6613 section 2.6.4 requires. Any other error means the candidate
// cannot be validated structurally; it is returned to the caller so ParsePacket reports the
// protocol error consistently. | responseVerifier 校验候选响应。返回 ErrAuthenticator 表示候选未
// 通过认证：UDP 传输按 RFC 2865 第 4.2 与 4.4 节要求静默丢弃它并继续读取，直到收到合法响应或
// 本次尝试超时；流传输则按 RFC 6613 第 2.6.4 节要求报告错误并关闭连接。其它错误表示候选无法通过
// 结构校验；它会被返回给调用方，由 ParsePacket 一致地报告协议错误。
type responseVerifier func(raw []byte) error

// exchange performs a request/response exchange with retransmission. | exchange 执行带重传的请求/响应交互。
func (c *Client) exchange(ctx context.Context, requestCode Code, build packetBuilder) (*Packet, []byte, [16]byte, error) {
	if err := c.checkClosed(); err != nil {
		return nil, nil, [16]byte{}, err
	}
	attempts := c.cfg.Retries + 1
	if attempts < 1 {
		attempts = 1
	}
	var sharedUDP net.Conn
	if isUDPNetwork(c.cfg.Network) && sharesUDPSourcePort(requestCode) {
		// RFC 5176 section 3.6 requires CoA and Disconnect retransmissions to use the same source
		// port, which also lets the responder's duplicate cache recognize them. One UDP socket is
		// therefore kept for the whole exchange; a late response is still valid because the request
		// bytes are unchanged. Access and accounting attempts use fresh identifiers instead, so they
		// keep dialing a fresh socket and cannot accept a late response to an earlier attempt. |
		// RFC 5176 第 3.6 节要求 CoA 与断开重传使用相同源端口，这也让响应器的重复缓存能够识别
		// 重传。因此整个交互复用同一个 UDP 套接字；由于请求字节未变，迟到的响应仍然有效。访问与
		// 计费尝试改用新的标识符，因此仍为每次尝试新建套接字，不会接受先前尝试的迟到响应。
		conn, _, dialErr := c.dial(ctx, requestCode, c.attemptTimeout(0))
		if dialErr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, nil, [16]byte{}, contextError(ctxErr)
			}
			return nil, nil, [16]byte{}, errs.WrapDetail(dialErr, ErrNetwork, "code %d", uint8(requestCode))
		}
		sharedUDP = conn
		defer func() {
			_ = conn.Close()
		}()
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, nil, [16]byte{}, contextError(err)
		}
		raw, requestAuthenticator, err := build(attempt)
		if err != nil {
			return nil, nil, [16]byte{}, err
		}
		// RFC 2865 sections 4.2 and 4.4 require a client to silently discard a response whose
		// Response Authenticator does not match and to keep waiting for a valid response until
		// the request times out; RFC 2866 section 4 applies the same rule to accounting. Stream
		// transports instead fail the attempt so the connection can be closed. Verification
		// therefore happens inside the read path, while the secret snapshot for this attempt is
		// still alive. | RFC 2865 第 4.2 与 4.4 节要求客户端静默丢弃 Response Authenticator 不匹配
		// 的响应，并继续等待合法响应直到请求超时；RFC 2866 第 4 节对计费作同样规定。流传输则让
		// 本次尝试失败，以便关闭连接。因此校验发生在读取路径内，此时本次尝试的密钥快照仍然有效。
		secret, err := c.secretSnapshot()
		if err != nil {
			return nil, nil, [16]byte{}, err
		}
		verify := func(candidate []byte) error {
			return verifyResponseAuthenticator(candidate, secret, requestAuthenticator)
		}
		var received []byte
		if sharedUDP != nil {
			received, err = c.transmit(ctx, sharedUDP, true, raw, c.attemptTimeout(attempt), verify)
		} else {
			received, err = c.roundTrip(ctx, requestCode, raw, c.attemptTimeout(attempt), verify)
		}
		zeroBytes(secret)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, nil, [16]byte{}, contextError(ctxErr)
			}
			if errors.Is(err, ErrClosed) {
				return nil, nil, [16]byte{}, err
			}
			// Framing, identifier and stream response-authenticator errors describe a protocol
			// failure, not a lost datagram, so retransmitting cannot help. RFC 6613 section
			// 2.6.4 additionally requires closing the stream connection when the Response
			// Authenticator fails validation; returning here discards the connection opened for
			// this attempt. | 分帧、标识符与流传输响应认证符错误属于协议故障而非丢包，重传无济于事。
			// RFC 6613 第 2.6.4 节还要求流连接在 Response Authenticator 校验失败时关闭；在此返回会
			// 丢弃本次尝试打开的连接。
			if errors.Is(err, ErrInvalidResponse) || errors.Is(err, ErrUnexpectedIdentifier) || errors.Is(err, ErrInvalidRequest) || errors.Is(err, ErrAuthenticator) {
				return nil, nil, [16]byte{}, err
			}
			lastErr = err
			continue
		}
		packet, err := ParsePacket(received)
		if err != nil {
			return nil, nil, [16]byte{}, errs.Wrap(err, ErrInvalidResponse)
		}
		if !responseCodeAllowed(requestCode, packet.Code) {
			return nil, nil, [16]byte{}, errs.Detail(ErrUnexpectedCode, "request code %d answered with code %d", uint8(requestCode), uint8(packet.Code))
		}
		return packet, received, requestAuthenticator, nil
	}
	if lastErr == nil {
		return nil, nil, [16]byte{}, errs.Detail(ErrTimeout, "code %d after %d attempt(s)", uint8(requestCode), attempts)
	}
	sentinel := ErrTimeout
	var netErr net.Error
	if !errors.As(lastErr, &netErr) || !netErr.Timeout() {
		sentinel = ErrNetwork
	}
	return nil, nil, [16]byte{}, errs.WrapDetail(lastErr, sentinel, "code %d after %d attempt(s)", uint8(requestCode), attempts)
}

// attemptTimeout returns the per-attempt timeout with exponential backoff. | attemptTimeout 返回
// 带指数退避的单次尝试超时。
func (c *Client) attemptTimeout(attempt int) time.Duration {
	base := c.cfg.Timeout
	if base <= 0 {
		base = DefaultTimeout
	}
	timeout := base
	for i := 0; i < attempt && i < 3; i++ {
		if timeout > time.Duration(1<<62) {
			break
		}
		timeout *= 2
	}
	return timeout
}

// roundTrip dials a fresh connection, writes one request and reads the matching response. | roundTrip
// 建立新连接、写入一次请求并读取匹配的响应。
func (c *Client) roundTrip(ctx context.Context, code Code, payload []byte, timeout time.Duration, verify responseVerifier) ([]byte, error) {
	conn, isUDP, err := c.dial(ctx, code, timeout)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = conn.Close()
	}()
	return c.transmit(ctx, conn, isUDP, payload, timeout, verify)
}

// transmit writes one request on conn and reads the matching response. The caller owns conn. | transmit
// 在 conn 上写入一次请求并读取匹配的响应。conn 由调用方持有。
func (c *Client) transmit(ctx context.Context, conn net.Conn, isUDP bool, payload []byte, timeout time.Duration, verify responseVerifier) ([]byte, error) {
	if len(payload) < 2 {
		return nil, errs.Detail(ErrInvalidRequest, "encoded packet length %d is below 2", len(payload))
	}
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	defer stop()
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	if isUDP {
		return readUDPResponse(conn, payload[1], verify)
	}
	return readStreamResponse(conn, payload[1], verify)
}

// dial opens the transport connection for one request. | dial 为一次请求打开传输连接。
func (c *Client) dial(ctx context.Context, code Code, timeout time.Duration) (net.Conn, bool, error) {
	network := c.cfg.Network
	useTLS := strings.HasPrefix(network, NetworkTLS)
	dialNetwork := network
	if useTLS {
		dialNetwork = "tcp" + strings.TrimPrefix(network, NetworkTLS)
	}
	dialer := &net.Dialer{Timeout: timeout}
	if c.cfg.SourceIP != nil {
		if strings.HasPrefix(dialNetwork, NetworkUDP) {
			dialer.LocalAddr = &net.UDPAddr{IP: c.cfg.SourceIP}
		} else {
			dialer.LocalAddr = &net.TCPAddr{IP: c.cfg.SourceIP}
		}
	}
	address := c.address(code)
	conn, err := dialer.DialContext(ctx, dialNetwork, address)
	if err != nil {
		return nil, false, err
	}
	if !useTLS {
		return conn, strings.HasPrefix(dialNetwork, NetworkUDP), nil
	}
	tlsConfig := &tls.Config{}
	if c.cfg.TLSConfig != nil {
		tlsConfig = c.cfg.TLSConfig.Clone()
	}
	if tlsConfig.ServerName == "" {
		if host, _, splitErr := net.SplitHostPort(address); splitErr == nil {
			tlsConfig.ServerName = host
		}
	}
	if tlsConfig.MinVersion == 0 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	tlsConn := tls.Client(conn, tlsConfig)
	// Bound the TLS handshake by the attempt timeout even when the context has no deadline.
	// | 即使上下文没有截止时间，也用单次尝试超时约束 TLS 握手。
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, false, err
	}
	return tlsConn, false, nil
}

// address returns the server address with the default port applied. | address 返回应用默认端口后的服务器地址。
func (c *Client) address(code Code) string {
	address := strings.TrimSpace(c.cfg.Address)
	host, port, err := net.SplitHostPort(address)
	if err == nil && port != "" {
		return address
	}
	if err != nil {
		host = strings.Trim(address, "[]")
	}
	host = strings.Trim(host, "[]")
	return net.JoinHostPort(host, defaultPort(c.cfg.Network, code))
}

// isUDPNetwork reports whether network selects a UDP transport. | isUDPNetwork 报告 network 是否
// 选择 UDP 传输。
func isUDPNetwork(network string) bool {
	return strings.HasPrefix(network, NetworkUDP)
}

// sharesUDPSourcePort reports whether retransmissions of code must reuse one local UDP socket. RFC
// 5176 section 3.6 requires that for CoA-Request and Disconnect-Request so the responder can detect
// duplicates. | sharesUDPSourcePort 报告 code 的重传是否必须复用同一个本地 UDP 套接字。RFC 5176
// 第 3.6 节对 CoA-Request 与 Disconnect-Request 有此要求，以便响应器检测重复。
func sharesUDPSourcePort(code Code) bool {
	return code == CodeCoARequest || code == CodeDisconnectRequest
}

// defaultPort returns the transport and request default port. | defaultPort 返回传输与请求的默认端口。
//
// UDP access requests use 1812, accounting uses 1813 and the RFC 5176 dynamic authorization
// requests use 3799; TCP and TLS always use 2083. | UDP 访问请求使用 1812，计费使用 1813，
// RFC 5176 动态授权请求使用 3799；TCP 与 TLS 始终使用 2083。
func defaultPort(network string, code Code) string {
	if strings.HasPrefix(network, NetworkUDP) {
		switch code {
		case CodeAccountingRequest:
			return "1813"
		case CodeDisconnectRequest, CodeDisconnectACK, CodeDisconnectNAK,
			CodeCoARequest, CodeCoAACK, CodeCoANAK:
			return "3799"
		default:
			return "1812"
		}
	}
	return "2083"
}

// readUDPResponse reads datagrams until one carries the expected identifier and a valid Response
// Authenticator. Datagrams with another identifier, including late responses to an earlier attempt
// with a fresh identifier, are skipped. Datagrams whose Response Authenticator does not match are
// silently discarded and reading continues, as RFC 2865 section 3 requires. A repeated copy of the
// same response is indistinguishable from the first and is harmless: the first valid datagram wins
// and any later copy is discarded with the socket. | readUDPResponse 读取数据报，直到出现携带预期
// 标识符且 Response Authenticator 合法的一个。标识符不同的数据报会被跳过，包括使用新标识符的
// 先前尝试的迟到响应。Response Authenticator 不匹配的数据报按 RFC 2865 第 3 节要求静默丢弃并
// 继续读取。同一响应的重复副本与首个副本无法区分且无害：首个合法数据报胜出，后续副本随套接字
// 一起丢弃。
func readUDPResponse(conn net.Conn, identifier uint8, verify responseVerifier) ([]byte, error) {
	buf := make([]byte, MaxPacketLength)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n < 2 {
			return nil, errs.Detail(ErrInvalidResponse, "datagram length %d is below 2", n)
		}
		if buf[1] != identifier {
			continue
		}
		// Verify before copying: a discarded datagram stays in the reusable buffer and
		// costs no allocation. | 先校验再复制：被丢弃的数据报留在可复用缓冲区中，不产生分配。
		if verify != nil && errors.Is(verify(buf[:n]), ErrAuthenticator) {
			continue
		}
		out := make([]byte, n)
		copy(out, buf[:n])
		return out, nil
	}
}

// readStreamResponse reads one length-delimited RADIUS packet from a stream. A frame with another
// identifier or a Response Authenticator that fails validation is reported as an error: RFC 6613
// section 2.6.4 requires the stream connection to be closed in both cases, and the caller closes it
// after this attempt ends. | readStreamResponse 从流中读取一个按长度分帧的 RADIUS 报文。标识符
// 不同的帧或 Response Authenticator 校验失败的帧会报告为错误：RFC 6613 第 2.6.4 节要求这两种
// 情况下关闭流连接，调用方会在本次尝试结束后关闭。
func readStreamResponse(conn net.Conn, identifier uint8, verify responseVerifier) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[2:4]))
	if length < HeaderLength || length > MaxPacketLength {
		return nil, errs.Detail(ErrInvalidResponse, "declared length %d is invalid", length)
	}
	buf := make([]byte, length)
	copy(buf, header)
	if _, err := io.ReadFull(conn, buf[4:]); err != nil {
		return nil, err
	}
	if buf[1] != identifier {
		return nil, errs.Detail(ErrUnexpectedIdentifier, "got %d want %d", buf[1], identifier)
	}
	if verify != nil {
		if err := verify(buf); errors.Is(err, ErrAuthenticator) {
			return nil, err
		}
	}
	return buf, nil
}

// responseCodeAllowed reports whether responseCode validly answers requestCode. | responseCodeAllowed
// 报告 responseCode 是否合法地应答 requestCode。
func responseCodeAllowed(requestCode, responseCode Code) bool {
	switch requestCode {
	case CodeAccessRequest:
		return responseCode == CodeAccessAccept || responseCode == CodeAccessReject || responseCode == CodeAccessChallenge
	case CodeAccountingRequest:
		return responseCode == CodeAccountingResponse
	case CodeCoARequest:
		return responseCode == CodeCoAACK || responseCode == CodeCoANAK
	case CodeDisconnectRequest:
		return responseCode == CodeDisconnectACK || responseCode == CodeDisconnectNAK
	default:
		return false
	}
}

// contextError wraps a context error with the matching sentinel. | contextError 用匹配的哨兵包装上下文错误。
func contextError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errs.Wrap(err, ErrTimeout)
	}
	return errs.Wrap(err, ErrCanceled)
}
