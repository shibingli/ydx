package webtransport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

// testTLS builds a self-signed certificate for 127.0.0.1 and the pool that
// trusts it. | testTLS 为 127.0.0.1 构造自签证书与信任它的证书池。
func testTLS(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "yd-wt-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	pool := x509.NewCertPool()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, pool
}

// wtPath is the test endpoint. | wtPath 是测试端点。
const wtPath = "/wt"

// startServer starts a WebTransport server whose handler owns one session. | startServer
// 启动一个 WebTransport 服务端，处理器拥有一个会话。
func startServer(t *testing.T, o Options, handler func(*Session)) (*Server, string, *x509.CertPool) {
	t.Helper()
	tlsConf, pool := testTLS(t)
	o.TLSConfig = tlsConf
	if o.CheckOrigin == nil {
		o.CheckOrigin = func(*http.Request) bool { return true }
	}
	srv, err := New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(wtPath, func(w http.ResponseWriter, r *http.Request) {
		sess, err := srv.Upgrade(w, r)
		if err != nil {
			t.Logf("upgrade: %v", err)
			return
		}
		handler(sess)
		// Returning ends the session, exactly as the contract requires. | 返回即结束会话，
		// 与契约一致。
	})
	srv.H3().Handler = mux
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = pc.Close()
	})
	return srv, "https://" + pc.LocalAddr().String() + wtPath, pool
}

// dialTest opens a client session and the framed channel. | dialTest 打开客户端会话与
// 带帧通道。
func dialTest(t *testing.T, url string, pool *x509.CertPool, o DialOptions) (*Session, *Channel) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if o.TLSClientConfig == nil {
		o.TLSClientConfig = &tls.Config{RootCAs: pool}
	}
	sess, err := Dial(ctx, url, o)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close(0, "test done | 测试结束") })
	ch, err := sess.Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return sess, ch
}

// TestEcho proves the framed channel carries messages in both directions. |
// TestEcho 证明带帧通道可以双向传递消息。
func TestEcho(t *testing.T) {
	_, url, pool := startServer(t, Options{}, func(sess *Session) {
		ch, err := sess.Accept(context.Background())
		if err != nil {
			return
		}
		defer ch.Close()
		for {
			msg, err := ch.Receive()
			if err != nil {
				return
			}
			echo := append([]byte("echo:"), msg...)
			if err := ch.Send(echo); err != nil {
				return
			}
		}
	})

	_, ch := dialTest(t, url, pool, DialOptions{})
	defer ch.Close()
	for _, want := range []string{"hello", "world", "中文"} {
		if err := ch.Send([]byte(want)); err != nil {
			t.Fatalf("Send(%q): %v", want, err)
		}
		got, err := ch.Receive()
		if err != nil {
			t.Fatalf("Receive: %v", err)
		}
		if string(got) != "echo:"+want {
			t.Fatalf("echo = %q, want %q", got, "echo:"+want)
		}
	}
}

// TestDatagram proves unreliable datagrams flow in both directions. | TestDatagram
// 证明不可靠数据报可以双向传递。
func TestDatagram(t *testing.T) {
	got := make(chan string, 1)
	_, url, pool := startServer(t, Options{}, func(sess *Session) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		msg, err := sess.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		got <- string(msg)
		_ = sess.SendDatagram([]byte("pong"))
		<-sess.Context().Done()
	})

	sess, _ := dialTest(t, url, pool, DialOptions{})
	if err := sess.SendDatagram([]byte("ping")); err != nil {
		t.Fatalf("SendDatagram: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reply, err := sess.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatalf("ReceiveDatagram: %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("reply = %q, want pong", reply)
	}
	select {
	case v := <-got:
		if v != "ping" {
			t.Fatalf("server saw %q, want ping", v)
		}
	case <-ctx.Done():
		t.Fatal("server did not receive the datagram | 服务端未收到数据报")
	}
}

// TestMaxMessageSize proves an oversized frame is rejected before allocation. |
// TestMaxMessageSize 证明超大帧在分配之前被拒绝。
func TestMaxMessageSize(t *testing.T) {
	errCh := make(chan error, 1)
	_, url, pool := startServer(t, Options{MaxMessageSize: 8}, func(sess *Session) {
		ch, err := sess.Accept(context.Background())
		if err != nil {
			errCh <- err
			return
		}
		_, err = ch.Receive()
		errCh <- err
	})

	_, ch := dialTest(t, url, pool, DialOptions{})
	defer ch.Close()
	if err := ch.Send([]byte("this message is far too long")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, ErrMessageTooLarge) {
			t.Fatalf("server error = %v, want ErrMessageTooLarge", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not observe the oversized frame | 服务端未观察到超大帧")
	}
}

// TestOriginRejected proves CheckOrigin gates the upgrade. | TestOriginRejected 证明
// CheckOrigin 会拦截升级。
func TestOriginRejected(t *testing.T) {
	_, url, pool := startServer(t, Options{
		CheckOrigin: func(*http.Request) bool { return false },
	}, func(sess *Session) { <-sess.Context().Done() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := Dial(ctx, url, DialOptions{
		TLSClientConfig: &tls.Config{RootCAs: pool},
		Header:          http.Header{"Origin": {"https://evil.example"}},
	})
	if err == nil {
		t.Fatal("Dial succeeded with a rejected origin | Origin 被拒时 Dial 仍成功")
	}
}

// TestServerCloseEndsSessions proves Server.Close terminates live sessions. |
// TestServerCloseEndsSessions 证明 Server.Close 会终止活跃会话。
func TestServerCloseEndsSessions(t *testing.T) {
	set := NewSessionSet()
	srv, url, pool := startServer(t, Options{Tracker: set}, func(sess *Session) {
		<-sess.Context().Done()
	})
	_, ch := dialTest(t, url, pool, DialOptions{})
	defer ch.Close()

	deadline := time.Now().Add(5 * time.Second)
	for set.Len() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := set.Len(); got != 1 {
		t.Fatalf("tracked sessions = %d, want 1", got)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	waitDone(t, ch.Context(), "channel context")
	if got := set.Len(); got != 0 {
		t.Fatalf("tracked sessions after close = %d, want 0", got)
	}
}

// waitDone waits for ctx to end. | waitDone 等待 ctx 结束。
func waitDone(t *testing.T, ctx context.Context, what string) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(10 * time.Second):
		t.Fatalf("%s did not end | %s 未结束", what, what)
	}
}

// TestDialScheme proves Dial rejects non-https URLs before touching the
// network. | TestDialScheme 证明 Dial 在触网之前拒绝非 https 地址。
func TestDialScheme(t *testing.T) {
	if _, err := Dial(context.Background(), "http://example.test/wt", DialOptions{}); !errors.Is(err, ErrScheme) {
		t.Fatalf("Dial(http) error = %v, want ErrScheme", err)
	}
}

// TestNewRequiresTLS proves a server without TLS fails closed. | TestNewRequiresTLS
// 证明缺少 TLS 的服务端失败关闭。
func TestNewRequiresTLS(t *testing.T) {
	if _, err := New(Options{}); !errors.Is(err, ErrTLSRequired) {
		t.Fatalf("New(no TLS) error = %v, want ErrTLSRequired", err)
	}
	if _, err := NewWithH3(nil, Options{}); !errors.Is(err, ErrNilH3) {
		t.Fatalf("NewWithH3(nil) error = %v, want ErrNilH3", err)
	}
}

// TestFrameCodec pins the length-prefixed framing. | TestFrameCodec 固定带长度前缀的帧格式。
func TestFrameCodec(t *testing.T) {
	buf := appendFrame(nil, []byte("abc"))
	buf = appendFrame(buf, []byte("de"))
	r := bytes.NewReader(buf)
	got, err := readFrame(r, nil, 16)
	if err != nil || string(got) != "abc" {
		t.Fatalf("first frame = %q, %v", got, err)
	}
	got, err = readFrame(r, nil, 16)
	if err != nil || string(got) != "de" {
		t.Fatalf("second frame = %q, %v", got, err)
	}
	// A zero-length frame is a heartbeat and must be skipped, not returned. |
	// 零长度帧是心跳，必须被跳过而不是返回。
	heartbeat := append([]byte{0, 0, 0, 0}, appendFrame(nil, []byte("hb"))...)
	if got, err := readFrame(bytes.NewReader(heartbeat), nil, 16); err != nil || string(got) != "hb" {
		t.Fatalf("frame after heartbeat = %q, %v", got, err)
	}
	if _, err := readFrame(bytes.NewReader(appendFrame(nil, make([]byte, 20))), nil, 16); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("oversized frame error = %v, want ErrMessageTooLarge", err)
	}
	if _, err := readFrame(bytes.NewReader([]byte{0, 0, 0, 5, 'a'}), nil, 16); err == nil {
		t.Fatal("truncated frame was accepted | 截断的帧被接受")
	}
}
