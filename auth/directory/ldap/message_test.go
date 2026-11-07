package ldap

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// roundTripMessage encodes and decodes one LDAP message. | roundTripMessage 编码并
// 解码一条 LDAP 消息。
func roundTripMessage(t *testing.T, message *LDAPMessage) *LDAPMessage {
	t.Helper()
	encoded, err := encodeLDAPMessage(message)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := decodeLDAPMessage(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.MessageID != message.MessageID {
		t.Fatalf("message ID %d, want %d", decoded.MessageID, message.MessageID)
	}
	return decoded
}

// TestMessageRequestRoundTrip verifies request operations survive BER. |
// TestMessageRequestRoundTrip 校验请求操作可通过 BER 往返。
func TestMessageRequestRoundTrip(t *testing.T) {
	t.Run("bind simple", func(t *testing.T) {
		message := roundTripMessage(t, &LDAPMessage{MessageID: 1, Op: &BindRequest{
			Version:        3,
			DN:             "cn=admin,dc=example,dc=com",
			Authentication: SimpleAuthentication{Password: "secret"},
		}})
		request, ok := message.Op.(*BindRequest)
		if !ok {
			t.Fatalf("type %T", message.Op)
		}
		if request.Version != 3 || request.DN != "cn=admin,dc=example,dc=com" {
			t.Fatalf("request = %+v", request)
		}
		if auth, ok := request.Authentication.(SimpleAuthentication); !ok || auth.Password != "secret" {
			t.Fatalf("authentication = %#v", request.Authentication)
		}
	})
	t.Run("bind SASL", func(t *testing.T) {
		message := roundTripMessage(t, &LDAPMessage{MessageID: 2, Op: &BindRequest{
			Version:        3,
			Authentication: SASLAuthentication{Mechanism: "PLAIN", Credentials: []byte{1, 2, 3}},
		}})
		request := message.Op.(*BindRequest)
		auth, ok := request.Authentication.(SASLAuthentication)
		if !ok || auth.Mechanism != "PLAIN" || !bytes.Equal(auth.Credentials, []byte{1, 2, 3}) {
			t.Fatalf("authentication = %#v", request.Authentication)
		}
	})
	t.Run("search", func(t *testing.T) {
		filter := And(Equal("objectClass", "person"), Substrings("cn", "Bar", []string{"ney"}, "ble"))
		message := roundTripMessage(t, &LDAPMessage{MessageID: 3, Op: &SearchRequest{
			BaseDN:       "dc=example,dc=com",
			Scope:        ScopeWholeSubtree,
			DerefAliases: DerefInSearching,
			SizeLimit:    10,
			TimeLimit:    5,
			TypesOnly:    true,
			Filter:       filter,
			Attributes:   []string{"cn", "mail"},
		}})
		request := message.Op.(*SearchRequest)
		if request.BaseDN != "dc=example,dc=com" || request.Scope != ScopeWholeSubtree || request.DerefAliases != DerefInSearching {
			t.Fatalf("request = %+v", request)
		}
		if request.SizeLimit != 10 || request.TimeLimit != 5 || !request.TypesOnly {
			t.Fatalf("limits = %+v", request)
		}
		if !reflect.DeepEqual(request.Attributes, []string{"cn", "mail"}) {
			t.Fatalf("attributes = %v", request.Attributes)
		}
		if request.Filter.String() != filter.String() {
			t.Fatalf("filter = %s", request.Filter)
		}
	})
	t.Run("modify", func(t *testing.T) {
		changes := []ModifyChange{
			{Operation: ModifyAdd, Attribute: Attribute{Type: "mail", Values: []string{"a@example.com"}}},
			{Operation: ModifyDelete, Attribute: Attribute{Type: "description"}},
			{Operation: ModifyReplace, Attribute: Attribute{Type: "cn", Values: []string{"New"}}},
			{Operation: ModifyIncrement, Attribute: Attribute{Type: "loginCount", Values: []string{"1"}}},
		}
		message := roundTripMessage(t, &LDAPMessage{MessageID: 4, Op: &ModifyRequest{DN: "cn=x", Changes: changes}})
		request := message.Op.(*ModifyRequest)
		if !reflect.DeepEqual(request.Changes, changes) {
			t.Fatalf("changes = %#v", request.Changes)
		}
	})
	t.Run("add", func(t *testing.T) {
		attributes := []Attribute{{Type: "objectClass", Values: []string{"top", "person"}}, {Type: "cn", Values: []string{"x"}}}
		message := roundTripMessage(t, &LDAPMessage{MessageID: 5, Op: &AddRequest{DN: "cn=x", Attributes: attributes}})
		request := message.Op.(*AddRequest)
		if request.DN != "cn=x" || !reflect.DeepEqual(request.Attributes, attributes) {
			t.Fatalf("request = %+v", request)
		}
	})
	t.Run("delete", func(t *testing.T) {
		message := roundTripMessage(t, &LDAPMessage{MessageID: 6, Op: &DeleteRequest{DN: "cn=x"}})
		if request := message.Op.(*DeleteRequest); request.DN != "cn=x" {
			t.Fatalf("request = %+v", request)
		}
	})
	t.Run("modify DN", func(t *testing.T) {
		message := roundTripMessage(t, &LDAPMessage{MessageID: 7, Op: &ModifyDNRequest{
			DN: "cn=x,dc=example,dc=com", NewRDN: "cn=y", DeleteOldRDN: true, NewSuperior: "ou=people,dc=example,dc=com",
		}})
		request := message.Op.(*ModifyDNRequest)
		if request.DN != "cn=x,dc=example,dc=com" || request.NewRDN != "cn=y" || !request.DeleteOldRDN || request.NewSuperior != "ou=people,dc=example,dc=com" {
			t.Fatalf("request = %+v", request)
		}
	})
	t.Run("compare", func(t *testing.T) {
		message := roundTripMessage(t, &LDAPMessage{MessageID: 8, Op: &CompareRequest{DN: "cn=x", Attribute: "cn", Value: "x"}})
		request := message.Op.(*CompareRequest)
		if request.DN != "cn=x" || request.Attribute != "cn" || request.Value != "x" {
			t.Fatalf("request = %+v", request)
		}
	})
	t.Run("abandon", func(t *testing.T) {
		message := roundTripMessage(t, &LDAPMessage{MessageID: 9, Op: &AbandonRequest{MessageID: 42}})
		if request := message.Op.(*AbandonRequest); request.MessageID != 42 {
			t.Fatalf("request = %+v", request)
		}
	})
	t.Run("unbind", func(t *testing.T) {
		message := roundTripMessage(t, &LDAPMessage{MessageID: 10, Op: &UnbindRequest{}})
		if _, ok := message.Op.(*UnbindRequest); !ok {
			t.Fatalf("type %T", message.Op)
		}
	})
	t.Run("extended request", func(t *testing.T) {
		message := roundTripMessage(t, &LDAPMessage{MessageID: 11, Op: &ExtendedRequest{Name: OIDWhoAmI, Value: []byte("payload")}})
		request := message.Op.(*ExtendedRequest)
		if request.Name != OIDWhoAmI || string(request.Value) != "payload" {
			t.Fatalf("request = %+v", request)
		}
	})
}

// TestMessageResponseRoundTrip verifies response operations survive BER. |
// TestMessageResponseRoundTrip 校验响应操作可通过 BER 往返。
func TestMessageResponseRoundTrip(t *testing.T) {
	t.Run("bind response", func(t *testing.T) {
		message := roundTripMessage(t, &LDAPMessage{MessageID: 20, Op: &BindResponse{
			Result:                LDAPResult{Code: ResultInvalidCredentials, MatchedDN: "cn=x", DiagnosticMessage: "bad", Referrals: []string{"ldap://other"}},
			ServerSASLCredentials: []byte("challenge"),
		}})
		response := message.Op.(*BindResponse)
		if response.Result.Code != ResultInvalidCredentials || response.Result.MatchedDN != "cn=x" || response.Result.DiagnosticMessage != "bad" {
			t.Fatalf("result = %+v", response.Result)
		}
		if !reflect.DeepEqual(response.Result.Referrals, []string{"ldap://other"}) {
			t.Fatalf("referrals = %v", response.Result.Referrals)
		}
		if string(response.ServerSASLCredentials) != "challenge" {
			t.Fatalf("credentials = %q", response.ServerSASLCredentials)
		}
	})
	t.Run("entry", func(t *testing.T) {
		entry := &Entry{DN: "cn=alice,dc=example,dc=com", Attributes: []Attribute{
			{Type: "cn", Values: []string{"alice"}},
			{Type: "mail", Values: []string{"alice@example.com", "a@example.com"}},
		}}
		message := roundTripMessage(t, &LDAPMessage{MessageID: 21, Op: entry})
		decoded := message.Op.(*Entry)
		if !reflect.DeepEqual(decoded, entry) {
			t.Fatalf("entry = %#v", decoded)
		}
	})
	t.Run("search reference", func(t *testing.T) {
		reference := &SearchResultReference{URIs: []string{"ldap://a/dc=x", "ldap://b/dc=x"}}
		message := roundTripMessage(t, &LDAPMessage{MessageID: 22, Op: reference})
		decoded := message.Op.(*SearchResultReference)
		if !reflect.DeepEqual(decoded, reference) {
			t.Fatalf("reference = %#v", decoded)
		}
	})
	t.Run("search done", func(t *testing.T) {
		done := &SearchResultDone{Result: LDAPResult{Code: ResultSizeLimitExceeded, DiagnosticMessage: "limit"}}
		message := roundTripMessage(t, &LDAPMessage{MessageID: 23, Op: done})
		decoded := message.Op.(*SearchResultDone)
		if decoded.Result.Code != ResultSizeLimitExceeded || decoded.Result.DiagnosticMessage != "limit" {
			t.Fatalf("done = %+v", decoded)
		}
	})
	t.Run("result responses", func(t *testing.T) {
		result := LDAPResult{Code: ResultSuccess}
		cases := []struct {
			op   ProtocolOp
			want ProtocolOp
		}{
			{op: &ModifyResponse{Result: result}, want: &ModifyResponse{}},
			{op: &AddResponse{Result: result}, want: &AddResponse{}},
			{op: &DeleteResponse{Result: result}, want: &DeleteResponse{}},
			{op: &ModifyDNResponse{Result: result}, want: &ModifyDNResponse{}},
			{op: &CompareResponse{Result: result}, want: &CompareResponse{}},
		}
		for _, test := range cases {
			message := roundTripMessage(t, &LDAPMessage{MessageID: 24, Op: test.op})
			if reflect.TypeOf(message.Op) != reflect.TypeOf(test.want) {
				t.Fatalf("type %T, want %T", message.Op, test.want)
			}
			got, ok := protocolResult(message.Op)
			if !ok || got.Code != ResultSuccess {
				t.Fatalf("result = %+v, ok = %t", got, ok)
			}
		}
	})
	t.Run("extended response", func(t *testing.T) {
		message := roundTripMessage(t, &LDAPMessage{MessageID: 25, Op: &ExtendedResponse{
			Result: LDAPResult{Code: ResultSuccess},
			Name:   OIDWhoAmI,
			Value:  []byte("dn:cn=admin"),
		}})
		response := message.Op.(*ExtendedResponse)
		if response.Name != OIDWhoAmI || string(response.Value) != "dn:cn=admin" {
			t.Fatalf("response = %+v", response)
		}
	})
	t.Run("intermediate", func(t *testing.T) {
		message := roundTripMessage(t, &LDAPMessage{MessageID: 26, Op: &IntermediateResponse{Name: "1.2.3", Value: []byte("progress")}})
		response := message.Op.(*IntermediateResponse)
		if response.Name != "1.2.3" || string(response.Value) != "progress" {
			t.Fatalf("response = %+v", response)
		}
	})
}

// TestMessageControlsRoundTrip verifies request controls survive BER. |
// TestMessageControlsRoundTrip 校验请求控件可通过 BER 往返。
func TestMessageControlsRoundTrip(t *testing.T) {
	controls := []Control{
		{Type: OIDManageDsaIT, Criticality: true},
		{Type: OIDPagedResults, Value: PagedResultsControl(100, []byte("cookie")).Value},
		{Type: OIDPostRead, Value: []byte{}},
	}
	message := roundTripMessage(t, &LDAPMessage{MessageID: 30, Op: &SearchRequest{
		BaseDN: "", Scope: ScopeBaseObject, Filter: Present("objectClass"),
	}, Controls: controls})
	if len(message.Controls) != len(controls) {
		t.Fatalf("controls = %#v", message.Controls)
	}
	if message.Controls[0].Type != OIDManageDsaIT || !message.Controls[0].Criticality || message.Controls[0].Value != nil {
		t.Fatalf("control 0 = %#v", message.Controls[0])
	}
	if message.Controls[1].Type != OIDPagedResults || len(message.Controls[1].Value) == 0 {
		t.Fatalf("control 1 = %#v", message.Controls[1])
	}
	if message.Controls[2].Value == nil || len(message.Controls[2].Value) != 0 {
		t.Fatalf("control 2 = %#v", message.Controls[2])
	}
}

// TestControlHelpers verifies control construction and parsing. | TestControlHelpers
// 校验控件构造与解析。
func TestControlHelpers(t *testing.T) {
	t.Run("paged", func(t *testing.T) {
		control := PagedResultsControl(250, []byte{1, 2, 3})
		size, cookie, err := ParsePagedResultsControl(control)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if size != 250 || !bytes.Equal(cookie, []byte{1, 2, 3}) {
			t.Fatalf("size = %d cookie = %x", size, cookie)
		}
		if _, _, err := ParsePagedResultsControl(Control{Type: "1.2.3"}); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("wrong OID error = %v", err)
		}
		if _, _, err := ParsePagedResultsControl(Control{Type: OIDPagedResults}); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("nil value error = %v", err)
		}
	})
	t.Run("sort request", func(t *testing.T) {
		control := SortControl(SortKey{Attribute: "cn"}, SortKey{Attribute: "uid", OrderingRule: "1.2.3", Reverse: true})
		if control.Type != OIDSortRequest || len(control.Value) == 0 {
			t.Fatalf("control = %#v", control)
		}
	})
	t.Run("sort response", func(t *testing.T) {
		encoder := newBEREncoder(32)
		encoder.open(berClassUniversal, berTagSequence)
		encoder.enumerated(3)
		encoder.primitive(berClassContext, 0, []byte("cn"))
		encoder.close()
		result, err := ParseSortResponseControl(Control{Type: OIDSortResponse, Value: encoder.bytes()})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if result.Code != 3 || result.Attribute != "cn" {
			t.Fatalf("result = %+v", result)
		}
		if _, err := ParseSortResponseControl(Control{Type: OIDSortResponse}); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("nil value error = %v", err)
		}
	})
	t.Run("read entry", func(t *testing.T) {
		encoder := newBEREncoder(64)
		encoder.open(berClassUniversal, berTagSequence)
		encoder.text("cn=alice,dc=example,dc=com")
		encoder.open(berClassUniversal, berTagSequence)
		encodePartialAttribute(encoder, Attribute{Type: "cn", Values: []string{"alice"}})
		encoder.close()
		encoder.close()
		for _, oid := range []string{OIDPreRead, OIDPostRead} {
			entry, err := ParseReadEntryControl(Control{Type: oid, Value: encoder.bytes()})
			if err != nil {
				t.Fatalf("%s parse: %v", oid, err)
			}
			if entry.DN != "cn=alice,dc=example,dc=com" || entry.First("cn") != "alice" {
				t.Fatalf("%s entry = %+v", oid, entry)
			}
		}
		if _, err := ParseReadEntryControl(Control{Type: OIDPreRead}); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("nil value error = %v", err)
		}
	})
	t.Run("convenience controls", func(t *testing.T) {
		if control := ManageDsaITControl(); control.Type != OIDManageDsaIT || control.Criticality {
			t.Fatalf("ManageDsaIT = %#v", control)
		}
		if control := ProxyAuthorizationDNControl("cn=admin"); control.Criticality != true || string(control.Value) != "dn:cn=admin" {
			t.Fatalf("proxy = %#v", control)
		}
		if control := ProxyAuthorizationDNControl("u:alice"); string(control.Value) != "u:alice" {
			t.Fatalf("proxy = %#v", control)
		}
		if control := SubentriesControl(true); control.Type != OIDSubentries || !control.Criticality || len(control.Value) == 0 {
			t.Fatalf("subentries = %#v", control)
		}
		if control := PermissiveModifyControl(); control.Type != OIDPermissiveModify {
			t.Fatalf("permissive = %#v", control)
		}
		if control := ShowDeletedControl(); control.Type != OIDShowDeleted || !control.Criticality {
			t.Fatalf("show deleted = %#v", control)
		}
		if control := ShowRecycledControl(); control.Type != OIDShowRecycled || !control.Criticality {
			t.Fatalf("show recycled = %#v", control)
		}
		pre := PreReadControl("cn", "mail")
		if pre.Type != OIDPreRead || !pre.Criticality {
			t.Fatalf("pre-read = %#v", pre)
		}
		post := PostReadControl()
		if post.Type != OIDPostRead || post.Value == nil {
			t.Fatalf("post-read = %#v", post)
		}
	})
	t.Run("matched values", func(t *testing.T) {
		control, err := MatchedValuesControl(Equal("cn", "alice"), Present("mail"))
		if err != nil {
			t.Fatalf("matched values: %v", err)
		}
		if control.Type != OIDMatchedValues || !control.Criticality || len(control.Value) == 0 {
			t.Fatalf("control = %#v", control)
		}
		if _, err := MatchedValuesControl(And(Equal("cn", "a"))); !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("composite error = %v", err)
		}
		if _, err := MatchedValuesControl(nil); !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("nil error = %v", err)
		}
	})
	t.Run("find", func(t *testing.T) {
		controls := []Control{{Type: "a"}, {Type: "b", Criticality: true}}
		control, ok := findControl(controls, "b")
		if !ok || !control.Criticality {
			t.Fatalf("find = %#v, %t", control, ok)
		}
		if _, ok := findControl(controls, "c"); ok {
			t.Fatal("unexpected control")
		}
	})
}

// TestMessageEncodingErrors verifies invalid local messages fail before I/O. |
// TestMessageEncodingErrors 校验非法本地消息在 I/O 前失败。
func TestMessageEncodingErrors(t *testing.T) {
	cases := []struct {
		name  string
		op    ProtocolOp
		match error
	}{
		{name: "nil authentication", op: &BindRequest{Version: 3}, match: ErrInvalidMessage},
		{name: "bind version", op: &BindRequest{Version: 2, Authentication: SimpleAuthentication{}}, match: ErrInvalidMessage},
		{name: "bind unknown authentication", op: &BindRequest{Version: 3, Authentication: &unknownAuthentication{}}, match: ErrInvalidMessage},
		{name: "nil filter", op: &SearchRequest{Scope: ScopeBaseObject}, match: ErrInvalidFilter},
		{name: "scope", op: &SearchRequest{Scope: Scope(9), Filter: Present("cn")}, match: ErrInvalidMessage},
		{name: "deref", op: &SearchRequest{DerefAliases: DerefAliases(9), Filter: Present("cn")}, match: ErrInvalidMessage},
		{name: "negative limit", op: &SearchRequest{SizeLimit: -1, Filter: Present("cn")}, match: ErrInvalidMessage},
		{name: "modify operation", op: &ModifyRequest{Changes: []ModifyChange{{Operation: ModifyOperation(9)}}}, match: ErrInvalidMessage},
		{name: "abandon ID", op: &AbandonRequest{MessageID: 0}, match: ErrInvalidMessage},
		{name: "extended name", op: &ExtendedRequest{}, match: ErrInvalidMessage},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := encodeLDAPMessage(&LDAPMessage{MessageID: 1, Op: test.op})
			if !errors.Is(err, test.match) {
				t.Fatalf("error %v does not match %v", err, test.match)
			}
		})
	}
	if _, err := encodeLDAPMessage(nil); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("nil message error = %v", err)
	}
	if _, err := encodeLDAPMessage(&LDAPMessage{MessageID: 1}); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("nil op error = %v", err)
	}
	for _, id := range []int{-1, 2147483648} {
		if _, err := encodeLDAPMessage(&LDAPMessage{MessageID: id, Op: &UnbindRequest{}}); !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("ID %d error = %v", id, err)
		}
	}
}

// unknownAuthentication is an unsupported Authentication implementation. |
// unknownAuthentication 是不受支持的 Authentication 实现。
type unknownAuthentication struct{}

func (*unknownAuthentication) bindAuthentication() {}

// TestEntryHelpers verifies case-insensitive attribute access and copying. |
// TestEntryHelpers 校验大小写不敏感属性访问与复制。
func TestEntryHelpers(t *testing.T) {
	entry := &Entry{DN: "cn=alice", Attributes: []Attribute{
		{Type: "CN", Values: []string{"alice", "a"}},
		{Type: "mail", Values: []string{"alice@example.com"}},
	}}
	if got := entry.First("cn"); got != "alice" {
		t.Fatalf("First = %q", got)
	}
	values := entry.Get("cn")
	values[0] = "mutated"
	if entry.First("cn") != "alice" {
		t.Fatal("Get returned an aliased slice")
	}
	if !entry.Has("MAIL") || entry.Has("missing") || entry.Has("") {
		t.Fatalf("Has results are wrong")
	}
	entry.Set(Attribute{Type: "Mail", Values: []string{"new@example.com"}})
	if got := entry.First("mail"); got != "new@example.com" {
		t.Fatalf("Set did not replace: %q", got)
	}
	entry.Set(Attribute{Type: "title", Values: []string{"engineer"}})
	if got := entry.First("title"); got != "engineer" {
		t.Fatalf("Set did not append: %q", got)
	}
	var nilEntry *Entry
	if nilEntry.Get("cn") != nil || nilEntry.First("cn") != "" || nilEntry.Has("cn") {
		t.Fatal("nil entry helpers returned data")
	}
	nilEntry.Set(Attribute{Type: "cn"})
}

// TestErrorValues verifies LDAP error classification and redaction. | TestErrorValues
// 校验 LDAP 错误分类与脱敏。
func TestErrorValues(t *testing.T) {
	errorValue := newResultError("bind", LDAPResult{
		Code:              ResultInvalidCredentials,
		MatchedDN:         "dc=example,dc=com",
		DiagnosticMessage: strings.Repeat("d", 600),
		Referrals:         []string{"ldap://other"},
	})
	if !errors.Is(errorValue, ErrInvalidCredentials) {
		t.Fatal("error does not unwrap to ErrInvalidCredentials")
	}
	if !errors.Is(errorValue, &Error{Code: ResultInvalidCredentials}) {
		t.Fatal("error does not match a typed result code")
	}
	if errors.Is(errorValue, &Error{Code: ResultBusy}) {
		t.Fatal("error matched a different result code")
	}
	text := errorValue.Error()
	if !strings.Contains(text, "invalidCredentials") || !strings.Contains(text, "dc=example,dc=com") {
		t.Fatalf("error text = %q", text)
	}
	if !strings.Contains(text, "...") {
		t.Fatalf("long diagnostic was not truncated: %q", text)
	}
	if len(text) > 700 {
		t.Fatalf("error text is too long: %d", len(text))
	}
	if newResultError("bind", LDAPResult{Code: ResultSuccess}) != nil {
		t.Fatal("success produced an error")
	}
	if !errors.Is(sentinelForCode(ResultOther), ErrOther) {
		t.Fatal("unknown result code did not map to ErrOther")
	}
	if sentinelForCode(ResultSuccess) != nil {
		t.Fatal("success mapped to a sentinel")
	}
	var nilError *Error
	if nilError.Error() != "<nil>" || nilError.Unwrap() != nil || nilError.Is(ErrBusy) {
		t.Fatal("nil error methods are wrong")
	}
	if ResultCode(999).String() != "unknown" {
		t.Fatal("unknown result string")
	}
}
