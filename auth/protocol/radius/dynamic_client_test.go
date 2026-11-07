package radius

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

// TestDynamicClientIgnoresDuplicateResponses verifies that a repeated response datagram left on the
// socket cannot disturb an exchange: the first matching response wins and the copy is discarded with
// the socket. | TestDynamicClientIgnoresDuplicateResponses 验证套接字上重复的响应数据报不会干扰交互：
// 第一个匹配的响应胜出，副本随套接字一起丢弃。
func TestDynamicClientIgnoresDuplicateResponses(t *testing.T) {
	secret := []byte("testing-secret")
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer listener.Close()

	serverErr := make(chan error, 1)
	go func() {
		buffer := make([]byte, MaxPacketLength)
		_ = listener.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, addr, err := listener.ReadFrom(buffer)
		if err != nil {
			serverErr <- err
			return
		}
		request, err := ParsePacket(buffer[:n])
		if err != nil {
			serverErr <- err
			return
		}
		response, err := signedResponse(request, secret, CodeCoAACK, Attributes{
			NewAttribute(AttrReplyMessage, []byte("duplicated")),
		})
		if err != nil {
			serverErr <- err
			return
		}
		if _, err := listener.WriteTo(response, addr); err != nil {
			serverErr <- err
			return
		}
		if _, err := listener.WriteTo(response, addr); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	client := newTestClient(t, ClientConfig{Address: listener.LocalAddr().String(), Secret: secret})
	response, err := client.SendCoA(context.Background(), &CoARequest{SessionID: "session-1"})
	if err != nil {
		t.Fatalf("SendCoA: %v", err)
	}
	if response.Code != CodeCoAACK || response.ReplyMessage != "duplicated" {
		t.Fatalf("response = %+v", response)
	}
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not finish")
	}
}

// TestDynamicClientRetransmissionReusesSourcePort verifies RFC 5176 section 3.6: every attempt uses
// the same local socket and the request datagram is byte-identical. | TestDynamicClientRetransmissionReusesSourcePort
// 验证 RFC 5176 第 3.6 节：每次尝试使用相同的本地套接字且请求数据报字节一致。
func TestDynamicClientRetransmissionReusesSourcePort(t *testing.T) {
	secret := []byte("testing-secret")
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer listener.Close()

	type observation struct {
		addr net.Addr
		raw  []byte
	}
	observed := make(chan observation, 2)
	serverErr := make(chan error, 1)
	go func() {
		buffer := make([]byte, MaxPacketLength)
		for attempt := 0; attempt < 2; attempt++ {
			_ = listener.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, addr, err := listener.ReadFrom(buffer)
			if err != nil {
				serverErr <- err
				return
			}
			raw := append([]byte(nil), buffer[:n]...)
			observed <- observation{addr: addr, raw: raw}
			if attempt == 0 {
				continue
			}
			request, err := ParsePacket(raw)
			if err != nil {
				serverErr <- err
				return
			}
			response, err := signedResponse(request, secret, CodeDisconnectACK, nil)
			if err != nil {
				serverErr <- err
				return
			}
			if _, err := listener.WriteTo(response, addr); err != nil {
				serverErr <- err
				return
			}
		}
		serverErr <- nil
	}()

	client := newTestClient(t, ClientConfig{
		Address: listener.LocalAddr().String(),
		Secret:  secret,
		Timeout: 120 * time.Millisecond,
		Retries: 1,
	})
	response, err := client.SendDisconnect(context.Background(), &DisconnectRequest{SessionID: "session-1"})
	if err != nil {
		t.Fatalf("SendDisconnect: %v", err)
	}
	if response.Code != CodeDisconnectACK {
		t.Fatalf("response code = %d", response.Code)
	}

	first := <-observed
	second := <-observed
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not finish")
	}
	if first.addr.String() != second.addr.String() {
		t.Fatalf("retransmission source address = %s, want %s", second.addr, first.addr)
	}
	if !bytes.Equal(first.raw, second.raw) {
		t.Fatal("retransmission bytes differ from the first attempt")
	}
	if first.raw[1] != second.raw[1] {
		t.Fatalf("retransmission identifier = %d, want %d", second.raw[1], first.raw[1])
	}
}
