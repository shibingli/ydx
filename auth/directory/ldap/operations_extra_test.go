package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// stubNetConn is an in-memory transport with injectable failures. | stubNetConn
// 是可注入故障的内存传输。
type stubNetConn struct {
	deadlineErr error
	writeErr    error
	written     []byte
}

// Read implements net.Conn. | Read 实现 net.Conn。
func (c *stubNetConn) Read([]byte) (int, error) { return 0, io.EOF }

// Write implements net.Conn. | Write 实现 net.Conn。
func (c *stubNetConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.written = append(c.written, p...)
	return len(p), nil
}

// Close implements net.Conn. | Close 实现 net.Conn。
func (c *stubNetConn) Close() error { return nil }

// LocalAddr implements net.Conn. | LocalAddr 实现 net.Conn。
func (c *stubNetConn) LocalAddr() net.Addr { return stubNetAddr{} }

// RemoteAddr implements net.Conn. | RemoteAddr 实现 net.Conn。
func (c *stubNetConn) RemoteAddr() net.Addr { return stubNetAddr{} }

// SetDeadline implements net.Conn. | SetDeadline 实现 net.Conn。
func (c *stubNetConn) SetDeadline(time.Time) error { return c.deadlineErr }

// SetReadDeadline implements net.Conn. | SetReadDeadline 实现 net.Conn。
func (c *stubNetConn) SetReadDeadline(time.Time) error { return c.deadlineErr }

// SetWriteDeadline implements net.Conn. | SetWriteDeadline 实现 net.Conn。
func (c *stubNetConn) SetWriteDeadline(time.Time) error { return c.deadlineErr }

// stubNetAddr is a placeholder network address. | stubNetAddr 是占位网络地址。
type stubNetAddr struct{}

// Network implements net.Addr. | Network 实现 net.Addr。
func (stubNetAddr) Network() string { return "stub" }

// String implements net.Addr. | String 实现 net.Addr。
func (stubNetAddr) String() string { return "stub" }

// TestSendRequestFailureBranches verifies encode and transport failures are
// classified without leaking a desynchronized connection. |
// TestSendRequestFailureBranches 校验编码与传输故障被分类且不遗留失步连接。
func TestSendRequestFailureBranches(t *testing.T) {
	ctx := context.Background()
	client := &Client{}
	valid := &BindRequest{Version: 3, Authentication: SimpleAuthentication{Password: "secret"}}
	if _, err := client.sendRequestLocked(ctx, valid, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil connection error = %v", err)
	}
	client.conn = newConn(&stubNetConn{}, false, tls.ConnectionState{}, 1024)
	if _, err := client.sendRequestLocked(ctx, &BindRequest{Version: 2}, nil); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("invalid bind version error = %v", err)
	}
	if client.conn == nil {
		t.Fatal("encoding failure closed the transport")
	}
	client.conn = newConn(&stubNetConn{deadlineErr: errors.New("deadline")}, false, tls.ConnectionState{}, 1024)
	if _, err := client.sendRequestLocked(ctx, valid, nil); !errors.Is(err, ErrNetwork) {
		t.Fatalf("deadline failure error = %v", err)
	}
	if client.conn != nil {
		t.Fatal("deadline failure retained the transport")
	}
	client.conn = newConn(&stubNetConn{writeErr: errors.New("write failed")}, false, tls.ConnectionState{}, 1024)
	if _, err := client.sendRequestLocked(ctx, valid, nil); !errors.Is(err, ErrNetwork) {
		t.Fatalf("write failure error = %v", err)
	}
	if client.conn != nil {
		t.Fatal("write failure retained the transport")
	}
}

// TestReadMessageFailureBranches verifies read transport failures invalidate
// the connection. | TestReadMessageFailureBranches 校验读取传输故障使连接失效。
func TestReadMessageFailureBranches(t *testing.T) {
	client := &Client{}
	if _, err := client.readMessageLocked(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil connection error = %v", err)
	}
	client.conn = newConn(&stubNetConn{deadlineErr: errors.New("deadline")}, false, tls.ConnectionState{}, 1024)
	if _, err := client.readMessageLocked(context.Background()); !errors.Is(err, ErrNetwork) {
		t.Fatalf("deadline failure error = %v", err)
	}
	client.conn = newConn(&stubNetConn{}, false, tls.ConnectionState{}, 1024)
	if _, err := client.readMessageLocked(context.Background()); !errors.Is(err, ErrNetwork) {
		t.Fatalf("EOF error = %v", err)
	}
	if client.conn != nil {
		t.Fatal("read failure retained the transport")
	}
}

// TestProtocolResultAllResponses verifies every response type exposes its result. |
// TestProtocolResultAllResponses 校验每种响应类型都暴露结果。
func TestProtocolResultAllResponses(t *testing.T) {
	responses := []struct {
		op   ProtocolOp
		code ResultCode
	}{
		{&BindResponse{Result: LDAPResult{Code: ResultSuccess}}, ResultSuccess},
		{&SearchResultDone{Result: LDAPResult{Code: ResultSizeLimitExceeded}}, ResultSizeLimitExceeded},
		{&ModifyResponse{Result: LDAPResult{Code: ResultBusy}}, ResultBusy},
		{&AddResponse{Result: LDAPResult{Code: ResultEntryAlreadyExists}}, ResultEntryAlreadyExists},
		{&DeleteResponse{Result: LDAPResult{Code: ResultNoSuchObject}}, ResultNoSuchObject},
		{&ModifyDNResponse{Result: LDAPResult{Code: ResultNamingViolation}}, ResultNamingViolation},
		{&CompareResponse{Result: LDAPResult{Code: ResultCompareTrue}}, ResultCompareTrue},
		{&ExtendedResponse{Result: LDAPResult{Code: ResultUnavailable}}, ResultUnavailable},
	}
	for _, response := range responses {
		result, ok := protocolResult(response.op)
		if !ok || result.Code != response.code {
			t.Fatalf("protocolResult(%T) = %+v, %t, want code %d", response.op, result, ok, response.code)
		}
	}
	if _, ok := protocolResult(&Entry{}); ok {
		t.Fatal("protocolResult accepted a search entry")
	}
}

// TestOperationRejectsUnexpectedResponse verifies mismatched response operations
// invalidate the connection. | TestOperationRejectsUnexpectedResponse 校验不匹配的
// 响应操作使连接失效。
func TestOperationRejectsUnexpectedResponse(t *testing.T) {
	server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
		switch message.Op.(type) {
		case *AddRequest:
			return session.writeSimpleResult(message.MessageID, &ModifyResponse{Result: LDAPResult{Code: ResultSuccess}})
		case *ExtendedRequest:
			return session.writeSimpleResult(message.MessageID, &ModifyResponse{Result: LDAPResult{Code: ResultSuccess}})
		default:
			return errors.New("unexpected operation")
		}
	})
	client, err := DialURL(context.Background(), server.URL())
	if err != nil {
		t.Fatalf("DialURL: %v", err)
	}
	defer client.Close()
	if err := client.Add(context.Background(), "cn=x", nil); !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("Add mismatch = %v", err)
	}
	if client.conn != nil {
		t.Fatal("Add mismatch retained the transport")
	}
	if _, err := client.Extended(context.Background(), "1.2.3", nil); !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("Extended mismatch = %v", err)
	}
	if client.conn != nil {
		t.Fatal("Extended mismatch retained the transport")
	}
}

// TestOperationReturnsResultOnFailure verifies failed writes return the typed
// result alongside the error. | TestOperationReturnsResultOnFailure 校验失败的写操作
// 同时返回类型化结果与错误。
func TestOperationReturnsResultOnFailure(t *testing.T) {
	server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
		if _, ok := message.Op.(*ModifyRequest); !ok {
			return errors.New("expected modify")
		}
		return session.writeSimpleResult(message.MessageID, &ModifyResponse{
			Result: LDAPResult{Code: ResultBusy, DiagnosticMessage: "retry"},
		})
	})
	client, err := DialURL(context.Background(), server.URL())
	if err != nil {
		t.Fatalf("DialURL: %v", err)
	}
	defer client.Close()
	result, err := client.ModifyWithResult(context.Background(), "cn=x", nil)
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("ModifyWithResult error = %v", err)
	}
	if result == nil || result.Result.Code != ResultBusy || result.Result.DiagnosticMessage != "retry" {
		t.Fatalf("ModifyWithResult result = %+v", result)
	}
}
