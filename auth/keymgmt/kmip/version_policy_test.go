package kmip

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestProtocolVersionSupportPolicy verifies that only KMIP 1.4 and 2.0 are accepted on the wire. |
// TestProtocolVersionSupportPolicy 校验线路上仅接受 KMIP 1.4 与 2.0。
func TestProtocolVersionSupportPolicy(t *testing.T) {
	cases := []struct {
		version ProtocolVersion
		want    bool
	}{
		{ProtocolVersion10, false},
		{ProtocolVersion11, false},
		{ProtocolVersion12, false},
		{ProtocolVersion13, false},
		{ProtocolVersion14, true},
		{ProtocolVersion20, true},
		{ProtocolVersion{Major: 2, Minor: 1}, false},
		{ProtocolVersion{Major: 3, Minor: 0}, false},
		{ProtocolVersion{}, false},
	}
	for _, tc := range cases {
		if got := tc.version.Supported(); got != tc.want {
			t.Fatalf("%s.Supported() = %v, want %v | %s.Supported() = %v，期望 %v", tc.version, got, tc.want, tc.version, got, tc.want)
		}
	}
	supported := SupportedProtocolVersions()
	if len(supported) != 2 || supported[0] != ProtocolVersion20 || supported[1] != ProtocolVersion14 {
		t.Fatalf("SupportedProtocolVersions = %v | SupportedProtocolVersions = %v", supported, supported)
	}
}

// TestServerProtocolVersionPolicy verifies acceptance of 1.4 and 2.0 and rejection of 1.0 through 1.3. |
// TestServerProtocolVersionPolicy 校验接受 1.4 与 2.0，拒绝 1.0 至 1.3。
func TestServerProtocolVersionPolicy(t *testing.T) {
	server := newTestServer(t)
	rejected := []ProtocolVersion{ProtocolVersion10, ProtocolVersion11, ProtocolVersion12, ProtocolVersion13,
		{Major: 2, Minor: 1}, {Major: 3, Minor: 0}}
	for _, version := range rejected {
		response := roundTrip(t, server, RequestMessage{
			Header:     RequestHeader{ProtocolVersion: version},
			BatchItems: []RequestBatchItem{{Operation: OpQuery, Payload: mustItem(t, QueryRequest{QueryFunctions: []QueryFunction{QueryFunctionOperations}})}},
		})
		if len(response.BatchItems) != 1 {
			t.Fatalf("%s returned %d items | %s 返回 %d 项", version, len(response.BatchItems), version, len(response.BatchItems))
		}
		item := response.BatchItems[0]
		if !errors.Is(item.Err(), ErrUnsupported) {
			t.Fatalf("%s error = %v, want ErrUnsupported | %s 错误 = %v，期望 ErrUnsupported", version, item.Err(), version, item.Err())
		}
		if item.ResultReason != ResultReasonOperationNotSupported {
			t.Fatalf("%s reason = %s | %s 原因 = %s", version, item.ResultReason, version, item.ResultReason)
		}
	}

	for _, version := range []ProtocolVersion{ProtocolVersion14, ProtocolVersion20} {
		payload := runPlainOpVersionOK(t, server, version, OpQuery,
			QueryRequest{QueryFunctions: []QueryFunction{QueryFunctionOperations}})
		query, err := DecodeQueryResponse(payload)
		if err != nil || len(query.Operations) == 0 {
			t.Fatalf("%s Query = %+v, %v | %s Query = %+v，%v", version, query, err, version, query, err)
		}
	}
}

// TestClientProtocolVersionPolicy verifies client-side dial validation and local Export rejection. |
// TestClientProtocolVersionPolicy 校验客户端拨号校验与本地 Export 拒绝。
func TestClientProtocolVersionPolicy(t *testing.T) {
	for _, version := range []ProtocolVersion{ProtocolVersion10, ProtocolVersion11, ProtocolVersion12, ProtocolVersion13,
		{Major: 2, Minor: 1}, {Major: 3, Minor: 0}} {
		if _, err := DialContext(context.Background(), ClientConfig{
			Address:         "127.0.0.1:1",
			AllowPlaintext:  true,
			ProtocolVersion: version,
		}); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%s DialContext err = %v, want ErrUnsupported | %s DialContext 错误 = %v，期望 ErrUnsupported", version, err, version, err)
		}
	}

	_, address := startTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, version := range []ProtocolVersion{ProtocolVersion14, ProtocolVersion20} {
		client, err := DialContext(ctx, ClientConfig{Address: address, AllowPlaintext: true, ProtocolVersion: version})
		if err != nil {
			t.Fatalf("%s DialContext: %v | %s DialContext：%v", version, err, version, err)
		}
		if _, err := client.Query(ctx, QueryRequest{QueryFunctions: []QueryFunction{QueryFunctionOperations}}); err != nil {
			t.Fatalf("%s Query: %v | %s Query：%v", version, err, version, err)
		}
		if version == ProtocolVersion20 {
			if _, err := client.Export(ctx, ExportRequest{UniqueIdentifier: "uid"}); !errors.Is(err, ErrUnsupported) {
				t.Fatalf("2.0 client Export err = %v, want ErrUnsupported | 2.0 客户端 Export 错误 = %v，期望 ErrUnsupported", err, err)
			}
		}
		if err := client.Close(); err != nil {
			t.Fatalf("%s Close: %v | %s Close：%v", version, err, version, err)
		}
	}
}
