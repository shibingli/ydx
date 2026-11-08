package radius

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// testMSCHAPv2Lookup resolves the fixed test users used by MS-CHAPv2 server tests. |
// testMSCHAPv2Lookup 解析 MS-CHAPv2 服务器测试使用的固定测试用户。
func testMSCHAPv2Lookup(ctx context.Context, userName string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch userName {
	case "User", "alice":
		return []byte("clientPass"), nil
	case "bob":
		return []byte("s3cret"), nil
	default:
		return nil, ErrEAPUnknownUser
	}
}

func TestMSCHAPv2ServerVerification(t *testing.T) {
	authenticatorChallenge := decodeHex(t, "5b5d7c7d7b3f2f3e3c2c602132262628")
	peerChallenge := decodeHex(t, "21402324255e262a28295f2b3a337c7e")
	response, err := MSCHAPv2Response("User", "clientPass", authenticatorChallenge, peerChallenge, 0x11)
	if err != nil {
		t.Fatalf("MSCHAPv2Response: %v", err)
	}
	result, err := VerifyMSCHAPv2Server("User", "clientPass", authenticatorChallenge, response)
	if err != nil {
		t.Fatalf("VerifyMSCHAPv2Server: %v", err)
	}
	if !result.Succeeded() {
		t.Fatalf("verification failed with reason %v", result.Failure)
	}
	expected, err := MSCHAPv2AuthenticatorResponse("User", "clientPass", authenticatorChallenge, response)
	if err != nil {
		t.Fatalf("MSCHAPv2AuthenticatorResponse: %v", err)
	}
	if !bytes.Equal(result.AuthenticatorResponse, expected) {
		t.Fatalf("AuthenticatorResponse = %q, want %q", result.AuthenticatorResponse, expected)
	}
	if !bytes.Equal(result.AuthenticatorResponse[:2], []byte("S=")) || len(result.AuthenticatorResponse) != 42 {
		t.Fatalf("AuthenticatorResponse = %q, want S= plus 40 hex digits", result.AuthenticatorResponse)
	}
	sendKey, recvKey, err := MSCHAPv2MPPEKeys("clientPass", response)
	if err != nil {
		t.Fatalf("MSCHAPv2MPPEKeys: %v", err)
	}
	if !bytes.Equal(result.MPPESendKey, sendKey) || !bytes.Equal(result.MPPERecvKey, recvKey) {
		t.Fatal("server result MPPE keys do not match RFC 3079 derivation")
	}
	if len(result.MPPESendKey) != 16 || len(result.MPPERecvKey) != 16 {
		t.Fatalf("MPPE key lengths = %d and %d, want 16", len(result.MPPESendKey), len(result.MPPERecvKey))
	}
	if bytes.Equal(result.MPPESendKey, result.MPPERecvKey) {
		t.Fatal("server send and receive MPPE keys must differ")
	}

	wrong, err := VerifyMSCHAPv2Server("User", "wrongPass", authenticatorChallenge, response)
	if err != nil {
		t.Fatalf("VerifyMSCHAPv2Server wrong password: %v", err)
	}
	if wrong.Succeeded() || wrong.Failure != MSCHAPv2FailureBadPassword {
		t.Fatalf("wrong password result = %+v, want %v", wrong, MSCHAPv2FailureBadPassword)
	}
	if len(wrong.MPPESendKey) != 0 || len(wrong.AuthenticatorResponse) != 0 {
		t.Fatal("failed verification returned key material")
	}

	malformed := append([]byte(nil), response...)
	malformed[1] = 1
	invalid, err := VerifyMSCHAPv2Server("User", "clientPass", authenticatorChallenge, malformed)
	if err != nil {
		t.Fatalf("malformed verification error: %v", err)
	}
	if invalid.Failure != MSCHAPv2FailureMalformed {
		t.Fatalf("malformed failure = %v, want %v", invalid.Failure, MSCHAPv2FailureMalformed)
	}

	if _, err := VerifyMSCHAPv2Server("User", "clientPass", make([]byte, 15), response); !errors.Is(err, ErrInvalidAttribute) {
		t.Fatalf("short challenge error = %v, want ErrInvalidAttribute", err)
	}
	if _, err := VerifyMSCHAPv2Server("User", "clientPass", authenticatorChallenge, make([]byte, 49)); !errors.Is(err, ErrInvalidAttribute) {
		t.Fatalf("short response error = %v, want ErrInvalidAttribute", err)
	}
}

func TestMSCHAPv2ServerChallengeLifecycle(t *testing.T) {
	server, err := NewMSCHAPv2Server(MSCHAPv2ServerConfig{
		Lookup:  testMSCHAPv2Lookup,
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewMSCHAPv2Server: %v", err)
	}
	t.Cleanup(func() {
		_ = server.Close()
	})
	challenge, err := server.IssueChallenge(context.Background(), "alice")
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	if len(challenge.Challenge) != 16 || len(challenge.State) < 16 {
		t.Fatalf("challenge = %x, state = %d bytes", challenge.Challenge, len(challenge.State))
	}
	if challenge.UserName != "alice" || !challenge.Expires.After(time.Now()) {
		t.Fatalf("unexpected challenge metadata: %+v", challenge)
	}
	response, err := MSCHAPv2Response("alice", "clientPass", challenge.Challenge, bytes.Repeat([]byte{7}, 16), 9)
	if err != nil {
		t.Fatalf("MSCHAPv2Response: %v", err)
	}
	result, err := server.VerifyResponse(context.Background(), "alice", challenge.State, challenge.Challenge, response)
	if err != nil {
		t.Fatalf("VerifyResponse: %v", err)
	}
	if !result.Succeeded() {
		t.Fatalf("verification failed with reason %v", result.Failure)
	}
	if _, err := server.VerifyResponse(context.Background(), "alice", challenge.State, challenge.Challenge, response); !errors.Is(err, ErrEAPState) {
		t.Fatalf("second VerifyResponse error = %v, want ErrEAPState", err)
	}
	unknownChallenge, err := server.IssueChallenge(context.Background(), "unknown")
	if err != nil {
		t.Fatalf("IssueChallenge unknown user: %v", err)
	}
	unknownResponse, err := MSCHAPv2Response("unknown", "clientPass", unknownChallenge.Challenge, bytes.Repeat([]byte{8}, 16), 10)
	if err != nil {
		t.Fatalf("MSCHAPv2Response unknown: %v", err)
	}
	unknownResult, err := server.VerifyResponse(context.Background(), "unknown", unknownChallenge.State, unknownChallenge.Challenge, unknownResponse)
	if err != nil {
		t.Fatalf("VerifyResponse unknown: %v", err)
	}
	if unknownResult.Failure != MSCHAPv2FailureUnknownUser {
		t.Fatalf("unknown user failure = %v, want %v", unknownResult.Failure, MSCHAPv2FailureUnknownUser)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := server.IssueChallenge(context.Background(), "alice"); !errors.Is(err, ErrServerClosed) {
		t.Fatalf("IssueChallenge after Close = %v, want ErrServerClosed", err)
	}
}

func TestMSCHAPv2ServerConcurrentReplay(t *testing.T) {
	server, err := NewMSCHAPv2Server(MSCHAPv2ServerConfig{
		Lookup:  testMSCHAPv2Lookup,
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewMSCHAPv2Server: %v", err)
	}
	t.Cleanup(func() {
		_ = server.Close()
	})
	challenge, err := server.IssueChallenge(context.Background(), "alice")
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	response, err := MSCHAPv2Response("alice", "clientPass", challenge.Challenge, bytes.Repeat([]byte{9}, 16), 3)
	if err != nil {
		t.Fatalf("MSCHAPv2Response: %v", err)
	}
	const callers = 8
	start := make(chan struct{})
	results := make(chan error, callers)
	var wait sync.WaitGroup
	for index := 0; index < callers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			result, err := server.VerifyResponse(context.Background(), "alice", challenge.State, challenge.Challenge, response)
			if err == nil && !result.Succeeded() {
				err = errors.New("verification did not succeed")
			}
			results <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	succeeded := 0
	stateErrors := 0
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrEAPState):
			stateErrors++
		default:
			t.Fatalf("unexpected concurrent verification error: %v", err)
		}
	}
	if succeeded != 1 || stateErrors != callers-1 {
		t.Fatalf("succeeded=%d stateErrors=%d, want 1 and %d", succeeded, stateErrors, callers-1)
	}
}

func TestAccessServerMSCHAPv2Challenge(t *testing.T) {
	secret := accountingServerSecret()
	mschap, err := NewMSCHAPv2Server(MSCHAPv2ServerConfig{
		Lookup:  testMSCHAPv2Lookup,
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewMSCHAPv2Server: %v", err)
	}
	t.Cleanup(func() {
		_ = mschap.Close()
	})
	authenticator := AccessAuthenticatorFunc(func(ctx context.Context, request *AccessServerRequest) (*AccessServerResult, error) {
		if !request.MSCHAPv2Verified {
			return &AccessServerResult{ReplyMessage: "MS-CHAPv2 verification missing"}, nil
		}
		return &AccessServerResult{Accept: true}, nil
	})
	server := startAccessServer(t, AccessServerConfig{
		Network:       "udp4",
		Address:       "127.0.0.1:0",
		Secret:        secret,
		MSCHAPv2:      mschap,
		Authenticator: authenticator,
		Logger:        testDynamicLogger(),
	})
	client := newTestClient(t, ClientConfig{
		Address:       server.Addr().String(),
		Secret:        secret,
		NASIdentifier: "nas-1",
	})
	response, err := client.AuthenticateMSCHAPv2(context.Background(), "alice", "clientPass", nil)
	if err != nil {
		t.Fatalf("AuthenticateMSCHAPv2: %v", err)
	}
	if !response.Accepted() {
		t.Fatalf("response code = %d, want Access-Accept (reply %q)", response.Code, response.ReplyMessage)
	}

	rejected, err := client.AuthenticateMSCHAPv2(context.Background(), "alice", "wrongPass", nil)
	if err != nil {
		t.Fatalf("AuthenticateMSCHAPv2 wrong password: %v", err)
	}
	if !rejected.Rejected() {
		t.Fatalf("wrong password response code = %d, want Access-Reject", rejected.Code)
	}
	if rejected.MSCHAPv2Error == "" {
		t.Fatal("wrong password rejection lacks MS-CHAP-Error")
	}

	unknown, err := client.AuthenticateMSCHAPv2(context.Background(), "nobody", "clientPass", nil)
	if err != nil {
		t.Fatalf("AuthenticateMSCHAPv2 unknown user: %v", err)
	}
	if !unknown.Rejected() {
		t.Fatalf("unknown user response code = %d, want Access-Reject", unknown.Code)
	}
}
