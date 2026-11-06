package raft

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/errs"
)

const (
	httpFrameMagic    = "YDRF"
	httpFrameVersion  = byte(1)
	httpFlagHMAC      = byte(1)
	httpSignatureHead = "X-Ydx-Raft-Signature"
	maxFrameMessages  = 1 << 16
	// minMessageWireBytes is the smallest encoded message: protocol version,
	// type, flags and ten one-byte varints. It bounds a claimed batch count
	// before the message slice is allocated. | minMessageWireBytes 是最小编码消息：
	// 协议版本、类型、标志与十个单字节 varint。它在分配消息切片前约束声明的批量数量。
	minMessageWireBytes = 13
)

// HTTPTransportOptions configures the HTTP transport. | HTTPTransportOptions 配置
// HTTP 传输。
type HTTPTransportOptions struct {
	// Client is the outbound HTTP client. Nil uses a private client with a 30s
	// timeout. Supply a client with TLS configuration for HTTPS peers. | Client
	// 是出站 HTTP 客户端。nil 使用带 30 秒超时的私有客户端。为 HTTPS 对端提供带 TLS
	// 配置的客户端。
	Client *http.Client
	// Path is the HTTP endpoint for Raft messages. Default "/raft/message".
	// | Path 是 Raft 消息的 HTTP 端点，默认 "/raft/message"。
	Path string
	// SharedSecret enables HMAC-SHA256 authentication of every frame. Use it
	// together with TLS; HMAC authenticates, TLS encrypts. | SharedSecret 启用每帧
	// HMAC-SHA256 认证。应与 TLS 一起使用；HMAC 负责认证，TLS 负责加密。
	SharedSecret []byte
	// ID is the local node ID. When non-zero, inbound messages addressed to a
	// different ID are rejected. | ID 是本地节点标识。非零时，拒绝收件人不是本地
	// 节点的入站消息。
	ID NodeID
	// MaxBodyBytes caps inbound frame size. Default 64 MiB. Snapshots must fit.
	// | MaxBodyBytes 限制入站帧大小，默认 64 MiB；快照必须能放下。
	MaxBodyBytes int64
	// Queue is the per-peer outbound queue length. Default 64. | Queue 是每对端
	// 出站队列长度，默认 64。
	Queue int
}

// HTTPTransport carries Raft messages as authenticated binary POST bodies. It is
// easy to mount behind existing HTTP servers, TLS terminators and authentication
// middleware. | HTTPTransport 以带认证的二进制 POST 体传递 Raft 消息，易挂载到现有
// HTTP 服务器、TLS 终结器与认证中间件之后。
type HTTPTransport struct {
	client  *http.Client
	peers   map[NodeID]*httpPeer
	handler atomic.Pointer[func(Message)]
	stopCh  chan struct{}
	path    string
	secret  []byte
	id      NodeID
	maxBody int64
	queue   int

	drops atomic.Uint64

	mu        sync.RWMutex
	once      sync.Once
	stopped   atomic.Bool
	ownClient bool
}

// httpPeer owns one ordered outbound queue. | httpPeer 持有一条有序出站队列。
type httpPeer struct {
	ch   chan []Message
	addr string
	id   NodeID
}

// NewHTTPTransport returns a transport with a normalized endpoint path. | NewHTTPTransport
// 返回端点路径已规范化的传输。
func NewHTTPTransport(opts HTTPTransportOptions) (*HTTPTransport, error) {
	if opts.Path == "" {
		opts.Path = "/raft/message"
	}
	if !strings.HasPrefix(opts.Path, "/") {
		opts.Path = "/" + opts.Path
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 64 << 20
	}
	if opts.Queue <= 0 {
		opts.Queue = 64
	}
	if len(opts.SharedSecret) > 0 && len(opts.SharedSecret) < 16 {
		return nil, errs.Detail(ErrInvalidConfig, "shared secret must be at least 16 bytes")
	}
	t := &HTTPTransport{
		id:      opts.ID,
		path:    opts.Path,
		client:  opts.Client,
		secret:  append([]byte(nil), opts.SharedSecret...),
		maxBody: opts.MaxBodyBytes,
		queue:   opts.Queue,
		peers:   make(map[NodeID]*httpPeer),
		stopCh:  make(chan struct{}),
	}
	if t.client == nil {
		t.client = &http.Client{Timeout: 30 * time.Second}
		t.ownClient = true
	}
	return t, nil
}

// Start implements Transport. | Start 实现 Transport。
func (t *HTTPTransport) Start(handler func(Message)) error {
	if t.stopped.Load() {
		return ErrStopped
	}
	h := handler
	t.handler.Store(&h)
	return nil
}

// UpdatePeer implements Transport. | UpdatePeer 实现 Transport。
func (t *HTTPTransport) UpdatePeer(id NodeID, addr string) {
	if id == 0 || addr == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if p, ok := t.peers[id]; ok {
		p.addr = addr
		return
	}
	p := &httpPeer{id: id, addr: addr, ch: make(chan []Message, t.queue)}
	t.peers[id] = p
	go t.peerLoop(p)
}

// Send implements Transport. Messages are grouped by destination and enqueued;
// network I/O never blocks the Raft loop. | Send 实现 Transport。消息按目的地分组
// 入队；网络 I/O 从不阻塞 Raft 循环。
func (t *HTTPTransport) Send(_ context.Context, msgs []Message) error {
	if t.stopped.Load() {
		return ErrStopped
	}
	if len(msgs) == 0 {
		return nil
	}
	groups := make(map[NodeID][]Message, 4)
	for i := range msgs {
		groups[msgs[i].To] = append(groups[msgs[i].To], msgs[i])
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	var firstErr error
	for id, batch := range groups {
		p := t.peers[id]
		if p == nil {
			if firstErr == nil {
				firstErr = errs.Detail(ErrUnknownNode, "http peer %d has no address", id)
			}
			continue
		}
		select {
		case p.ch <- batch:
		default:
			t.drops.Add(uint64(len(batch)))
			if firstErr == nil {
				firstErr = errs.Detail(ErrProposalDropped, "http queue for %d is full", id)
			}
		}
	}
	return firstErr
}

// peerLoop serializes posts to one peer. | peerLoop 串行化发往一个对端的 POST。
func (t *HTTPTransport) peerLoop(p *httpPeer) {
	for {
		select {
		case <-t.stopCh:
			return
		case batch := <-p.ch:
			t.mu.RLock()
			addr := p.addr
			t.mu.RUnlock()
			frame, err := encodeHTTPFrame(batch)
			if err != nil {
				t.drops.Add(uint64(len(batch)))
				continue
			}
			t.post(addr, frame)
		}
	}
}

// post delivers one frame. Failures are left to Raft retransmission. | post 投递
// 一个帧。失败交由 Raft 重传。
func (t *HTTPTransport) post(addr string, frame []byte) {
	url := t.peerURL(addr)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(frame))
	if err != nil {
		t.drops.Add(1)
		return
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if len(t.secret) > 0 {
		req.Header.Set(httpSignatureHead, signFrame(t.secret, frame))
	}
	resp, err := t.client.Do(req)
	if err != nil {
		t.drops.Add(1)
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.drops.Add(1)
	}
}

// peerURL combines an address with the endpoint path. | peerURL 将地址与端点路径组合。
func (t *HTTPTransport) peerURL(addr string) string {
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		return strings.TrimRight(addr, "/") + t.path
	}
	return "http://" + strings.TrimRight(addr, "/") + t.path
}

// Handler returns the inbound HTTP handler. Mount it with net/http or
// router.HandleRaw. | Handler 返回入站 HTTP 处理器，可用 net/http 或
// router.HandleRaw 挂载。
func (t *HTTPTransport) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != t.path {
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, t.maxBody))
		if err != nil {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		if len(t.secret) > 0 {
			sig := r.Header.Get(httpSignatureHead)
			if !hmac.Equal([]byte(sig), []byte(signFrame(t.secret, body))) {
				http.Error(w, "bad signature", http.StatusUnauthorized)
				return
			}
		}
		msgs, err := decodeHTTPFrame(body)
		if err != nil {
			http.Error(w, "bad frame", http.StatusBadRequest)
			return
		}
		h := t.handler.Load()
		if h == nil {
			http.Error(w, "transport not started", http.StatusServiceUnavailable)
			return
		}
		for i := range msgs {
			if t.id != 0 && msgs[i].To != t.id {
				continue
			}
			(*h)(msgs[i])
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// Close implements Transport. | Close 实现 Transport。
func (t *HTTPTransport) Close() error {
	t.once.Do(func() {
		t.stopped.Store(true)
		close(t.stopCh)
		if t.ownClient {
			t.client.CloseIdleConnections()
		}
	})
	return nil
}

// SendImmediate implements ImmediateTransport. Send only groups and enqueues.
// | SendImmediate 实现 ImmediateTransport。Send 只做分组与入队。
func (t *HTTPTransport) SendImmediate() bool { return true }

// Drops returns frames dropped by a full queue, encoding failure or HTTP error.
// | Drops 返回因队列满、编码失败或 HTTP 错误而丢弃的帧数。
func (t *HTTPTransport) Drops() uint64 { return t.drops.Load() }

// FrameLimit reports the maximum inbound body accepted by this transport.
// | FrameLimit 返回该传输可接受的最大入站请求体。
func (t *HTTPTransport) FrameLimit() int64 { return t.maxBody }

// encodeHTTPFrame builds a checksummed, optionally authenticated frame. |
// encodeHTTPFrame 构建带校验和、可选认证的帧。
func encodeHTTPFrame(msgs []Message) ([]byte, error) {
	return encodeHTTPFrameInto(nil, msgs)
}

// encodeHTTPFrameInto appends one frame to dst, avoiding an intermediate
// payload copy on the large snapshot path. | encodeHTTPFrameInto 将一帧追加到 dst，
// 避免大快照路径上的中间负载复制。
func encodeHTTPFrameInto(dst []byte, msgs []Message) ([]byte, error) {
	if len(msgs) > maxFrameMessages {
		return nil, errs.Detail(ErrTooLarge, "http frame messages %d", len(msgs))
	}
	start := len(dst)
	dst = append(dst, make([]byte, 10)...)
	payloadStart := len(dst)
	dst = binary.AppendUvarint(dst, uint64(len(msgs)))
	for i := range msgs {
		data, err := MarshalMessage(msgs[i])
		if err != nil {
			return nil, err
		}
		dst = binary.AppendUvarint(dst, uint64(len(data)))
		dst = append(dst, data...)
	}
	crc := crc32.Checksum(dst[payloadStart:], castagnoli)
	copy(dst[start:start+4], httpFrameMagic)
	dst[start+4] = httpFrameVersion
	dst[start+5] = 0
	binary.LittleEndian.PutUint32(dst[start+6:start+10], crc)
	return dst, nil
}

// decodeHTTPFrame validates framing, checksum and message payloads. | decodeHTTPFrame
// 校验帧结构、校验和与消息载荷。
func decodeHTTPFrame(frame []byte) ([]Message, error) {
	if len(frame) < 4+1+1+4 {
		return nil, errs.Detail(ErrCorrupt, "short http frame")
	}
	if string(frame[:4]) != httpFrameMagic {
		return nil, errs.Detail(ErrCorrupt, "bad http frame magic")
	}
	if frame[4] != httpFrameVersion {
		return nil, errs.Detail(ErrCorrupt, "http frame version %d", frame[4])
	}
	flags := frame[5]
	if flags&^httpFlagHMAC != 0 {
		return nil, errs.Detail(ErrCorrupt, "http frame flags %d", flags)
	}
	wantCRC := binary.LittleEndian.Uint32(frame[6:10])
	payload := frame[10:]
	if crc32.Checksum(payload, castagnoli) != wantCRC {
		return nil, errs.Detail(ErrCorrupt, "http frame CRC mismatch")
	}
	d := decoder{src: payload}
	count := d.uvarint()
	if d.err != nil {
		return nil, d.err
	}
	if count > maxFrameMessages {
		return nil, errs.Detail(ErrTooLarge, "http frame messages %d", count)
	}
	// Reject counts that cannot fit in the remaining payload before allocating
	// the message slice. | 在分配消息切片前拒绝剩余载荷不可能容纳的数量。
	if count > uint64(len(payload)-d.pos)/minMessageWireBytes {
		return nil, errs.Detail(ErrTooLarge, "http frame messages %d for %d bytes",
			count, len(payload)-d.pos)
	}
	msgs := make([]Message, 0, count)
	for i := uint64(0); i < count; i++ {
		length := d.uvarint()
		if d.err != nil {
			return nil, d.err
		}
		if length > maxMessageBytes {
			return nil, errs.Detail(ErrTooLarge, "http message %d bytes", length)
		}
		data := d.take(int(length))
		if d.err != nil {
			return nil, d.err
		}
		m, err := UnmarshalMessage(data)
		if err != nil {
			return nil, err
		}
		msgs = append(msgs, m)
	}
	if d.pos != len(payload) {
		return nil, errs.Detail(ErrCorrupt, "http frame trailing bytes")
	}
	return msgs, nil
}

// signFrame returns a hex HMAC-SHA256. | signFrame 返回十六进制 HMAC-SHA256。
func signFrame(secret, frame []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(frame)
	return hex.EncodeToString(mac.Sum(nil))
}

// String renders the transport kind and local ID. | String 输出传输类型与本地标识。
func (t *HTTPTransport) String() string {
	return fmt.Sprintf("http-transport(%d)", t.id)
}
