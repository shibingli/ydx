package radius

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestAccessOverTCP(t *testing.T) {
	secret := []byte("testing-secret")
	server := newTCPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
		return signedResponse(request, secret, CodeAccessAccept, Attributes{
			NewAttribute(AttrReplyMessage, []byte("tcp")),
		})
	})
	client := newTestClient(t, ClientConfig{Network: NetworkTCP, Address: server.Addr(), Secret: secret})
	response, err := client.AccessRequest(context.Background(), &AccessRequest{UserName: "alice", Password: "s3cret"})
	if err != nil {
		t.Fatalf("AccessRequest over TCP: %v", err)
	}
	if !response.Accepted() || response.ReplyMessage != "tcp" {
		t.Fatalf("unexpected response: %+v", response)
	}
	request := server.nextRequest(t)
	assertStringAttribute(t, request.packet.Attributes, AttrUserName, "alice")
}

func TestAccessOverTLS(t *testing.T) {
	secret := []byte("testing-secret")
	server, roots := newTLSMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
		return signedResponse(request, secret, CodeAccessAccept, Attributes{
			NewAttribute(AttrReplyMessage, []byte("tls")),
		})
	})
	client := newTestClient(t, ClientConfig{
		Network: NetworkTLS,
		Address: server.Addr(),
		Secret:  secret,
		TLSConfig: &tls.Config{
			RootCAs:    roots,
			ServerName: "radius.test",
		},
	})
	response, err := client.AccessRequest(context.Background(), &AccessRequest{UserName: "alice", Password: "s3cret"})
	if err != nil {
		t.Fatalf("AccessRequest over TLS: %v", err)
	}
	if !response.Accepted() || response.ReplyMessage != "tls" {
		t.Fatalf("unexpected response: %+v", response)
	}
	server.nextRequest(t)
}

func TestStreamRejectsMalformedResponse(t *testing.T) {
	secret := []byte("testing-secret")
	server := newTCPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
		malformed := make([]byte, 10)
		malformed[0] = byte(CodeAccessAccept)
		malformed[1] = request.Identifier
		return malformed, nil
	})
	client := newTestClient(t, ClientConfig{Network: NetworkTCP, Address: server.Addr(), Secret: secret})
	if _, err := client.AccessRequest(context.Background(), &AccessRequest{UserName: "alice"}); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("error = %v, want ErrInvalidResponse", err)
	}
}

func TestStreamRejectsBadMessageAuthenticator(t *testing.T) {
	secret := []byte("testing-secret")
	server := newTCPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
		return signedResponse(request, secret, CodeAccessAccept, nil)
	})
	client := newTestClient(t, ClientConfig{Network: NetworkTCP, Address: server.Addr(), Secret: secret})
	_, err := client.AccessRequest(context.Background(), &AccessRequest{
		Method:      AuthEAP,
		EAPMessages: [][]byte{{1}},
	})
	if !errors.Is(err, ErrMessageAuthenticator) {
		t.Fatalf("error = %v, want ErrMessageAuthenticator", err)
	}
}

func TestClientContextCancellation(t *testing.T) {
	secret := []byte("testing-secret")
	server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
		return nil, nil
	})
	client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret, Timeout: 2 * time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	timer := time.AfterFunc(50*time.Millisecond, cancel)
	defer timer.Stop()
	start := time.Now()
	_, err := client.AccessRequest(ctx, &AccessRequest{UserName: "alice", Password: "s3cret"})
	elapsed := time.Since(start)
	if !errors.Is(err, ErrCanceled) {
		t.Fatalf("error = %v, want ErrCanceled", err)
	}
	if elapsed > time.Second {
		t.Fatalf("cancellation took %v", elapsed)
	}
}

func TestClientContextDeadline(t *testing.T) {
	secret := []byte("testing-secret")
	server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
		return nil, nil
	})
	client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret, Timeout: 2 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := client.AccessRequest(ctx, &AccessRequest{UserName: "alice", Password: "s3cret"})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("error = %v, want ErrTimeout", err)
	}
}

func TestClientAlreadyCanceledContext(t *testing.T) {
	client := newTestClient(t, ClientConfig{Address: "127.0.0.1:1", Secret: []byte("testing-secret")})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.AccessRequest(ctx, &AccessRequest{UserName: "alice"}); !errors.Is(err, ErrCanceled) {
		t.Fatalf("error = %v, want ErrCanceled", err)
	}
}

func TestDefaultPortsAndAddresses(t *testing.T) {
	if port := defaultPort(NetworkUDP, CodeAccessRequest); port != "1812" {
		t.Fatalf("UDP access port = %q", port)
	}
	if port := defaultPort(NetworkUDP, CodeAccountingRequest); port != "1813" {
		t.Fatalf("UDP accounting port = %q", port)
	}
	if port := defaultPort(NetworkTCP, CodeAccessRequest); port != "2083" {
		t.Fatalf("TCP port = %q", port)
	}
	if port := defaultPort(NetworkTLS, CodeAccountingRequest); port != "2083" {
		t.Fatalf("TLS port = %q", port)
	}

	cases := []struct {
		network  string
		code     Code
		address  string
		expected string
	}{
		{network: NetworkUDP, code: CodeAccessRequest, address: "127.0.0.1", expected: "127.0.0.1:1812"},
		{network: NetworkUDP, code: CodeAccountingRequest, address: "127.0.0.1", expected: "127.0.0.1:1813"},
		{network: NetworkUDP, code: CodeAccessRequest, address: "127.0.0.1:9999", expected: "127.0.0.1:9999"},
		{network: NetworkTCP, code: CodeAccessRequest, address: "example.com", expected: "example.com:2083"},
		{network: NetworkTLS, code: CodeAccountingRequest, address: "example.com", expected: "example.com:2083"},
		{network: NetworkUDP, code: CodeAccessRequest, address: "::1", expected: "[::1]:1812"},
		{network: NetworkUDP, code: CodeAccessRequest, address: "[::1]", expected: "[::1]:1812"},
	}
	for _, testCase := range cases {
		client := &Client{cfg: ClientConfig{Network: testCase.network, Address: testCase.address}}
		if address := client.address(testCase.code); address != testCase.expected {
			t.Fatalf("address(%q, %q) = %q, want %q", testCase.network, testCase.address, address, testCase.expected)
		}
	}
}

func TestClientConcurrentRequests(t *testing.T) {
	secret := []byte("testing-secret")
	server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
		return signedResponse(request, secret, CodeAccessAccept, nil)
	})
	client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret, Timeout: time.Second})
	const workers = 16
	const perWorker = 5
	var waitGroup sync.WaitGroup
	failures := make(chan error, workers*perWorker)
	for worker := 0; worker < workers; worker++ {
		waitGroup.Add(1)
		go func(worker int) {
			defer waitGroup.Done()
			for i := 0; i < perWorker; i++ {
				response, err := client.AccessRequest(context.Background(), &AccessRequest{UserName: "alice", Password: "s3cret"})
				if err != nil {
					failures <- err
					return
				}
				if !response.Accepted() {
					failures <- errors.New("unexpected response code")
					return
				}
			}
		}(worker)
	}
	waitGroup.Wait()
	close(failures)
	for err := range failures {
		t.Fatalf("concurrent request: %v", err)
	}
	identifiers := make(map[uint8]struct{})
	for len(server.requests) > 0 {
		request := <-server.requests
		if _, exists := identifiers[request.packet.Identifier]; exists {
			t.Fatalf("duplicate identifier %d", request.packet.Identifier)
		}
		identifiers[request.packet.Identifier] = struct{}{}
	}
	if len(identifiers) != workers*perWorker {
		t.Fatalf("recorded %d requests, want %d", len(identifiers), workers*perWorker)
	}
}

func TestClientNetworkFailure(t *testing.T) {
	client := newTestClient(t, ClientConfig{
		Address: "127.0.0.1:1",
		Secret:  []byte("testing-secret"),
		Timeout: 100 * time.Millisecond,
		Retries: 0,
	})
	_, err := client.AccessRequest(context.Background(), &AccessRequest{UserName: "alice", Password: "s3cret"})
	if !errors.Is(err, ErrNetwork) && !errors.Is(err, ErrTimeout) {
		t.Fatalf("error = %v, want ErrNetwork or ErrTimeout", err)
	}
}
