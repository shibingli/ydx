package ldap

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	adTestServiceDN       = "CN=svc,OU=Service,DC=example,DC=com"
	adTestServicePassword = "service-secret"
	adTestUserDN          = "CN=Alice,OU=Users,DC=example,DC=com"
	adTestUserPassword    = "correct-secret"
	adTestBaseDN          = "DC=example,DC=com"
	adTestDirectGroup     = "CN=Direct,OU=Groups,DC=example,DC=com"
	adTestNestedGroup     = "CN=Nested,OU=Groups,DC=example,DC=com"
	adTestMissingGroup    = "CN=Missing,OU=Groups,DC=example,DC=com"
	adTestChainGroup      = "CN=ChainGroup,OU=Groups,DC=example,DC=com"
)

// adSearchRecord captures one search request. | adSearchRecord 记录一次搜索请求。
type adSearchRecord struct {
	base   string
	scope  Scope
	filter string
}

// adMockServer emulates the Active Directory operations used by the facade. |
// adMockServer 模拟门面使用的 Active Directory 操作。
type adMockServer struct {
	t             *testing.T
	server        *mockServer
	mu            sync.Mutex
	serviceBinds  int
	userBinds     int
	searches      []adSearchRecord
	lastUserBind  string
	userPassword  string
	bindSubcode   string
	groupsMode    string
	userEntries   []*Entry
	acceptAnyUser bool
}

// defaultADUserEntry returns a representative user object. | defaultADUserEntry
// 返回具有代表性的用户对象。
func defaultADUserEntry() *Entry {
	fileTime := func(offset time.Duration) string {
		return strconv.FormatInt(adFileTimeOffset+offset.Nanoseconds()/100, 10)
	}
	return &Entry{
		DN: adTestUserDN,
		Attributes: []Attribute{
			{Type: "distinguishedName", Values: []string{adTestUserDN}},
			{Type: "userPrincipalName", Values: []string{"alice@example.com"}},
			{Type: "sAMAccountName", Values: []string{"alice"}},
			{Type: "mail", Values: []string{"alice@example.com"}},
			{Type: "displayName", Values: []string{"Alice Example"}},
			{Type: "memberOf", Values: []string{adTestDirectGroup, adTestMissingGroup}},
			{Type: "userAccountControl", Values: []string{strconv.Itoa(UACNormalAccount | UACDontExpirePassword)}},
			{Type: "pwdLastSet", Values: []string{fileTime(-time.Hour)}},
			{Type: "msDS-UserPasswordExpiryTimeComputed", Values: []string{strconv.FormatInt(adFileTimeNever, 10)}},
			{Type: "lastLogonTimestamp", Values: []string{fileTime(-time.Minute)}},
			{Type: "lockoutTime", Values: []string{"0"}},
			{Type: "whenCreated", Values: []string{"20240101120000.0Z"}},
			{Type: "accountExpires", Values: []string{"0"}},
		},
	}
}

// newADMock starts an AD mock server. Configuration runs before the listener
// starts, so handler reads are not racy. | newADMock 启动 AD 模拟服务端。配置在监听器
// 启动前执行，因此处理器读取不存在竞态。
func newADMock(t *testing.T, configure ...func(*adMockServer)) *adMockServer {
	t.Helper()
	mock := &adMockServer{
		t:            t,
		userPassword: adTestUserPassword,
		groupsMode:   "chain",
		userEntries:  []*Entry{defaultADUserEntry()},
	}
	for _, apply := range configure {
		apply(mock)
	}
	mock.server = startMockServer(t, mock.handle)
	return mock
}

// URL returns the mock endpoint. | URL 返回模拟端点。
func (m *adMockServer) URL() string { return m.server.URL() }

// snapshot returns a consistent counter snapshot. | snapshot 返回一致的计数快照。
func (m *adMockServer) snapshot() (serviceBinds, userBinds, searches int, lastBind, lastFilter string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	searches = len(m.searches)
	if searches > 0 {
		lastFilter = m.searches[searches-1].filter
	}
	return m.serviceBinds, m.userBinds, searches, m.lastUserBind, lastFilter
}

// handle dispatches one mock request. | handle 分派一条模拟请求。
func (m *adMockServer) handle(session *mockSession, message *LDAPMessage) error {
	switch request := message.Op.(type) {
	case *BindRequest:
		return m.handleBind(session, message.MessageID, request)
	case *SearchRequest:
		return m.handleSearch(session, message, request)
	default:
		return errors.New("unexpected Active Directory operation")
	}
}

// handleBind answers service and user binds. | handleBind 应答服务与用户绑定。
func (m *adMockServer) handleBind(session *mockSession, id int, request *BindRequest) error {
	auth, ok := request.Authentication.(SimpleAuthentication)
	if !ok {
		return errors.New("expected simple bind")
	}
	if request.DN == adTestServiceDN {
		m.mu.Lock()
		m.serviceBinds++
		m.mu.Unlock()
		code := ResultSuccess
		if auth.Password != adTestServicePassword {
			code = ResultInvalidCredentials
		}
		return session.writeSimpleResult(id, &BindResponse{Result: LDAPResult{Code: code}})
	}
	m.mu.Lock()
	m.userBinds++
	m.lastUserBind = request.DN
	m.mu.Unlock()
	if !m.acceptAnyUser && request.DN != adTestUserDN {
		return session.writeSimpleResult(id, &BindResponse{Result: LDAPResult{
			Code:              ResultInvalidCredentials,
			DiagnosticMessage: "unexpected user DN",
		}})
	}
	if auth.Password != m.userPassword || m.bindSubcode != "" {
		diagnostic := "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data " + m.bindSubcode + ", v4563"
		return session.writeSimpleResult(id, &BindResponse{Result: LDAPResult{
			Code:              ResultInvalidCredentials,
			DiagnosticMessage: diagnostic,
		}})
	}
	return session.writeSimpleResult(id, &BindResponse{Result: LDAPResult{Code: ResultSuccess}})
}

// handleSearch answers root DSE, user, and group searches. | handleSearch 应答根 DSE、
// 用户与组搜索。
func (m *adMockServer) handleSearch(session *mockSession, message *LDAPMessage, request *SearchRequest) error {
	record := adSearchRecord{base: request.BaseDN, scope: request.Scope, filter: request.Filter.String()}
	m.mu.Lock()
	m.searches = append(m.searches, record)
	m.mu.Unlock()
	switch {
	case request.BaseDN == "" && request.Scope == ScopeBaseObject:
		if err := session.writeEntry(message.MessageID, "", Attribute{Type: "defaultNamingContext", Values: []string{adTestBaseDN}}); err != nil {
			return err
		}
		return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess})
	case strings.Contains(record.filter, ADMatchingRuleInChain):
		if m.groupsMode == "reject" {
			return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultUnwillingToPerform})
		}
		for _, dn := range []string{adTestChainGroup, adTestChainGroup} {
			if err := session.writeEntry(message.MessageID, dn, Attribute{Type: "distinguishedName", Values: []string{dn}}); err != nil {
				return err
			}
		}
		if _, ok := findControl(message.Controls, OIDPagedResults); !ok {
			m.t.Error("group chain search lacks paged-results control")
		}
		return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess}, PagedResultsControl(500, nil))
	case request.BaseDN == adTestDirectGroup:
		if err := session.writeEntry(message.MessageID, adTestDirectGroup, Attribute{Type: "memberOf", Values: []string{adTestNestedGroup}}); err != nil {
			return err
		}
		return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess})
	case request.BaseDN == adTestNestedGroup:
		if err := session.writeEntry(message.MessageID, adTestNestedGroup); err != nil {
			return err
		}
		return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess})
	case request.BaseDN == adTestMissingGroup:
		return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultNoSuchObject})
	case request.BaseDN == adTestBaseDN || request.BaseDN == adTestUserDN:
		for _, entry := range m.userEntries {
			if err := session.writeEntry(message.MessageID, entry.DN, entry.Attributes...); err != nil {
				return err
			}
		}
		return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess})
	default:
		return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultNoSuchObject})
	}
}

// newTestAD constructs an ActiveDirectory facade over mock. | newTestAD 在 mock 上构造
// ActiveDirectory 门面。
func newTestAD(t *testing.T, mock *adMockServer, mutate ...func(*ADConfig)) *ActiveDirectory {
	t.Helper()
	cfg := ADConfig{
		Domain:       "example.com",
		URL:          mock.URL(),
		BindDN:       adTestServiceDN,
		BindPassword: adTestServicePassword,
		Timeout:      5 * time.Second,
		DialTimeout:  5 * time.Second,
	}
	for _, apply := range mutate {
		apply(&cfg)
	}
	ad, err := NewActiveDirectory(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewActiveDirectory: %v", err)
	}
	t.Cleanup(func() {
		_ = ad.Close()
	})
	return ad
}

// TestActiveDirectoryConfiguration verifies construction and validation. |
// TestActiveDirectoryConfiguration 校验构造与验证。
func TestActiveDirectoryConfiguration(t *testing.T) {
	if _, err := NewActiveDirectory(context.Background(), ADConfig{}); !errors.Is(err, ErrADDiscovery) {
		t.Fatalf("empty config error = %v", err)
	}
	if _, err := NewActiveDirectory(context.Background(), ADConfig{URL: "ldap://example.com", BindDN: adTestServiceDN}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("bind DN without password error = %v", err)
	}
	if _, err := NewActiveDirectory(context.Background(), ADConfig{URL: "ldap://example.com", BindPassword: "secret"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("bind password without DN error = %v", err)
	}
	if _, err := NewActiveDirectory(context.Background(), ADConfig{URL: "ldap://example.com", Timeout: -1}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("negative timeout error = %v", err)
	}
	if _, err := NewActiveDirectory(context.Background(), ADConfig{URL: "http://example.com"}); !errors.Is(err, ErrInvalidURL) {
		t.Fatalf("invalid scheme error = %v", err)
	}
	mock := newADMock(t)
	ad := newTestAD(t, mock)
	if ad.Domain() != "example.com" || ad.BaseDN() != adTestBaseDN {
		t.Fatalf("domain/base = %q/%q", ad.Domain(), ad.BaseDN())
	}
	if ad.URL() != mock.URL() {
		t.Fatalf("URL = %q", ad.URL())
	}
	serviceBinds, _, searches, _, _ := mock.snapshot()
	if serviceBinds != 1 || searches != 1 {
		t.Fatalf("service binds = %d searches = %d", serviceBinds, searches)
	}
}

// TestActiveDirectoryExplicitBaseDN verifies base DN overrides skip root DSE. |
// TestActiveDirectoryExplicitBaseDN 校验显式基础 DN 跳过根 DSE。
func TestActiveDirectoryExplicitBaseDN(t *testing.T) {
	mock := newADMock(t)
	ad := newTestAD(t, mock, func(cfg *ADConfig) {
		cfg.Domain = ""
		cfg.BaseDN = "DC=corp,DC=example"
	})
	if ad.BaseDN() != "DC=corp,DC=example" || ad.Domain() != "corp.example" {
		t.Fatalf("domain/base = %q/%q", ad.Domain(), ad.BaseDN())
	}
	_, _, searches, _, _ := mock.snapshot()
	if searches != 0 {
		t.Fatalf("searches = %d", searches)
	}
	root := &ActiveDirectory{}
	if root.Domain() != "" || root.BaseDN() != "" || root.URL() != "" {
		t.Fatalf("zero value getters = %q %q %q", root.Domain(), root.BaseDN(), root.URL())
	}
	if err := root.Close(); err != nil {
		t.Fatalf("zero value Close: %v", err)
	}
}

// TestActiveDirectoryAuthenticate verifies every accepted identity form. |
// TestActiveDirectoryAuthenticate 校验每种可接受的身份形式。
func TestActiveDirectoryAuthenticate(t *testing.T) {
	tests := []struct {
		identity     string
		wantBase     string
		wantScope    Scope
		wantContains []string
	}{
		{identity: "alice", wantBase: adTestBaseDN, wantScope: ScopeWholeSubtree, wantContains: []string{"(sAMAccountName=alice)", "(userPrincipalName=alice@example.com)"}},
		{identity: "EXAMPLE\\alice", wantBase: adTestBaseDN, wantScope: ScopeWholeSubtree, wantContains: []string{"(sAMAccountName=alice)", "(userPrincipalName=alice@EXAMPLE)"}},
		{identity: "alice@example.com", wantBase: adTestBaseDN, wantScope: ScopeWholeSubtree, wantContains: []string{"(userPrincipalName=alice@example.com)", "(sAMAccountName=alice)"}},
		{identity: adTestUserDN, wantBase: adTestUserDN, wantScope: ScopeBaseObject, wantContains: []string{"(objectClass=*)"}},
	}
	for _, test := range tests {
		t.Run(test.identity, func(t *testing.T) {
			mock := newADMock(t)
			ad := newTestAD(t, mock)
			user, err := ad.Authenticate(context.Background(), test.identity, adTestUserPassword)
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			if !user.Authenticated || user.DN != adTestUserDN || user.SAMAccountName != "alice" {
				t.Fatalf("user = %+v", user)
			}
			if user.UPN != "alice@example.com" || user.Mail != "alice@example.com" || user.DisplayName != "Alice Example" {
				t.Fatalf("user fields = %+v", user)
			}
			_, userBinds, searches, lastBind, lastFilter := mock.snapshot()
			if userBinds != 1 || lastBind != adTestUserDN {
				t.Fatalf("user binds = %d last bind = %q", userBinds, lastBind)
			}
			if searches < 2 {
				t.Fatalf("searches = %d", searches)
			}
			var lastRecord adSearchRecord
			mock.mu.Lock()
			lastRecord = mock.searches[len(mock.searches)-1]
			mock.mu.Unlock()
			if lastRecord.base != test.wantBase || lastRecord.scope != test.wantScope {
				t.Fatalf("search = %+v", lastRecord)
			}
			for _, fragment := range test.wantContains {
				if !strings.Contains(lastFilter, fragment) {
					t.Fatalf("filter %s lacks %s", lastFilter, fragment)
				}
			}
		})
	}
}

// TestActiveDirectoryAuthenticateSubcodes verifies AD diagnostic mapping. |
// TestActiveDirectoryAuthenticateSubcodes 校验 AD 诊断码映射。
func TestActiveDirectoryAuthenticateSubcodes(t *testing.T) {
	tests := []struct {
		subcode string
		want    error
	}{
		{subcode: "525", want: ErrInvalidCredentials},
		{subcode: "52e", want: ErrInvalidCredentials},
		{subcode: "530", want: ErrAccountRestricted},
		{subcode: "531", want: ErrAccountRestricted},
		{subcode: "534", want: ErrAccountRestricted},
		{subcode: "532", want: ErrPasswordExpired},
		{subcode: "533", want: ErrAccountDisabled},
		{subcode: "539", want: ErrAccountLocked},
		{subcode: "775", want: ErrAccountLocked},
		{subcode: "701", want: ErrAccountExpired},
		{subcode: "773", want: ErrPasswordMustChange},
	}
	for _, test := range tests {
		t.Run(test.subcode, func(t *testing.T) {
			mock := newADMock(t, func(mock *adMockServer) {
				mock.bindSubcode = test.subcode
			})
			ad := newTestAD(t, mock)
			_, err := ad.Authenticate(context.Background(), "alice", "wrong-secret")
			if !errors.Is(err, ErrInvalidCredentials) || !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if strings.Contains(err.Error(), "wrong-secret") {
				t.Fatalf("error leaks password: %v", err)
			}
		})
	}
}

// TestActiveDirectoryAuthenticateWithoutLookup verifies direct bind fallback. |
// TestActiveDirectoryAuthenticateWithoutLookup 校验直接绑定回退。
func TestActiveDirectoryAuthenticateWithoutLookup(t *testing.T) {
	mock := newADMock(t, func(mock *adMockServer) {
		mock.userEntries = nil
		mock.acceptAnyUser = true
	})
	ad := newTestAD(t, mock)
	user, err := ad.Authenticate(context.Background(), "alice", adTestUserPassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !user.Authenticated || user.SAMAccountName != "alice" || user.UPN != "" || user.DN != "" {
		t.Fatalf("user = %+v", user)
	}
	_, _, _, lastBind, _ := mock.snapshot()
	if lastBind != "alice@example.com" {
		t.Fatalf("bind name = %q", lastBind)
	}
}

// TestActiveDirectoryAuthenticateEmptyPassword verifies no network I/O occurs. |
// TestActiveDirectoryAuthenticateEmptyPassword 校验不发生网络 I/O。
func TestActiveDirectoryAuthenticateEmptyPassword(t *testing.T) {
	mock := newADMock(t)
	ad := newTestAD(t, mock)
	serviceBefore, userBefore, searchesBefore, _, _ := mock.snapshot()
	if _, err := ad.Authenticate(context.Background(), "alice", ""); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("empty password error = %v", err)
	}
	serviceAfter, userAfter, searchesAfter, _, _ := mock.snapshot()
	if serviceBefore != serviceAfter || userBefore != userAfter || searchesBefore != searchesAfter {
		t.Fatalf("network activity: %d/%d/%d -> %d/%d/%d", serviceBefore, userBefore, searchesBefore, serviceAfter, userAfter, searchesAfter)
	}
	if _, err := ad.Authenticate(context.Background(), " ", adTestUserPassword); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("blank identity error = %v", err)
	}
}

// TestActiveDirectoryUserAndGroups verifies lookup and group expansion. |
// TestActiveDirectoryUserAndGroups 校验用户查询与组展开。
func TestActiveDirectoryUserAndGroups(t *testing.T) {
	t.Run("chain", func(t *testing.T) {
		mock := newADMock(t)
		ad := newTestAD(t, mock)
		user, err := ad.User(context.Background(), "alice")
		if err != nil {
			t.Fatalf("User: %v", err)
		}
		if user.DN != adTestUserDN || user.Disabled || !user.Enabled() {
			t.Fatalf("user = %+v", user)
		}
		if len(user.MemberOf) != 2 || user.MemberOf[0] != adTestDirectGroup {
			t.Fatalf("memberOf = %v", user.MemberOf)
		}
		groups, err := ad.Groups(context.Background(), "alice")
		if err != nil {
			t.Fatalf("Groups: %v", err)
		}
		if len(groups) != 1 || groups[0] != adTestChainGroup {
			t.Fatalf("groups = %v", groups)
		}
	})
	t.Run("recursive fallback", func(t *testing.T) {
		mock := newADMock(t, func(mock *adMockServer) {
			mock.groupsMode = "reject"
		})
		ad := newTestAD(t, mock)
		groups, err := ad.Groups(context.Background(), "alice")
		if err != nil {
			t.Fatalf("Groups: %v", err)
		}
		want := []string{adTestDirectGroup, adTestMissingGroup, adTestNestedGroup}
		if len(groups) != len(want) {
			t.Fatalf("groups = %v, want %v", groups, want)
		}
		for index := range want {
			if groups[index] != want[index] {
				t.Fatalf("groups = %v, want %v", groups, want)
			}
		}
	})
	t.Run("unknown user", func(t *testing.T) {
		mock := newADMock(t, func(mock *adMockServer) {
			mock.userEntries = nil
		})
		ad := newTestAD(t, mock)
		if _, err := ad.User(context.Background(), "alice"); !errors.Is(err, ErrNoSuchObject) {
			t.Fatalf("User error = %v", err)
		}
		if _, err := ad.Groups(context.Background(), "alice"); !errors.Is(err, ErrNoSuchObject) {
			t.Fatalf("Groups error = %v", err)
		}
	})
	t.Run("ambiguous user", func(t *testing.T) {
		second := defaultADUserEntry()
		second.DN = "CN=Alice2,OU=Users,DC=example,DC=com"
		mock := newADMock(t, func(mock *adMockServer) {
			mock.userEntries = []*Entry{defaultADUserEntry(), second}
		})
		ad := newTestAD(t, mock)
		if _, err := ad.User(context.Background(), "alice"); !errors.Is(err, ErrAmbiguousUser) {
			t.Fatalf("User error = %v", err)
		}
		if _, err := ad.Authenticate(context.Background(), "alice", adTestUserPassword); !errors.Is(err, ErrAmbiguousUser) {
			t.Fatalf("Authenticate error = %v", err)
		}
	})
}

// TestActiveDirectoryClosedLifecycle verifies operations after Close. |
// TestActiveDirectoryClosedLifecycle 校验关闭后的操作。
func TestActiveDirectoryClosedLifecycle(t *testing.T) {
	mock := newADMock(t)
	ad := newTestAD(t, mock)
	if err := ad.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := ad.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := ad.Authenticate(context.Background(), "alice", adTestUserPassword); !errors.Is(err, ErrClosed) {
		t.Fatalf("Authenticate error = %v", err)
	}
	if _, err := ad.User(context.Background(), "alice"); !errors.Is(err, ErrClosed) {
		t.Fatalf("User error = %v", err)
	}
	if _, err := ad.Groups(context.Background(), "alice"); !errors.Is(err, ErrClosed) {
		t.Fatalf("Groups error = %v", err)
	}
	var nilAD *ActiveDirectory
	if nilAD.Domain() != "" || nilAD.BaseDN() != "" || nilAD.URL() != "" || nilAD.Close() != nil {
		t.Fatal("nil ActiveDirectory getters")
	}
	if _, err := nilAD.User(context.Background(), "alice"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil User error = %v", err)
	}
	if _, err := nilAD.Authenticate(context.Background(), "alice", "secret"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil Authenticate error = %v", err)
	}
	if _, err := nilAD.Groups(context.Background(), "alice"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil Groups error = %v", err)
	}
}

// TestEntryToADUser verifies typed account decoding. | TestEntryToADUser 校验类型化账号解码。
func TestEntryToADUser(t *testing.T) {
	fileTime := func(value time.Time) string {
		return strconv.FormatInt(adFileTimeOffset+value.UnixNano()/100, 10)
	}
	now := time.Now().UTC()
	past := now.Add(-24 * time.Hour)
	entry := &Entry{
		DN: adTestUserDN,
		Attributes: []Attribute{
			{Type: "userPrincipalName", Values: []string{"alice@example.com"}},
			{Type: "sAMAccountName", Values: []string{"alice"}},
			{Type: "mail", Values: []string{"alice@example.com"}},
			{Type: "displayName", Values: []string{"Alice"}},
			{Type: "memberOf", Values: []string{adTestDirectGroup, adTestNestedGroup}},
			{Type: "userAccountControl", Values: []string{strconv.Itoa(UACNormalAccount | UACPasswordExpired)}},
			{Type: "pwdLastSet", Values: []string{"0"}},
			{Type: "msDS-UserPasswordExpiryTimeComputed", Values: []string{fileTime(past)}},
			{Type: "lastLogonTimestamp", Values: []string{fileTime(past)}},
			{Type: "lockoutTime", Values: []string{fileTime(past)}},
			{Type: "whenCreated", Values: []string{"20240101120000.0Z"}},
			{Type: "accountExpires", Values: []string{fileTime(past)}},
		},
	}
	user, err := entryToADUser(entry)
	if err != nil {
		t.Fatalf("entryToADUser: %v", err)
	}
	if user.DN != adTestUserDN || user.UPN != "alice@example.com" || user.SAMAccountName != "alice" {
		t.Fatalf("identity fields = %+v", user)
	}
	if user.Mail != "alice@example.com" || user.DisplayName != "Alice" || len(user.MemberOf) != 2 {
		t.Fatalf("attributes = %+v", user)
	}
	if !user.MustChangePassword || !user.PasswordExpired || !user.Locked || !user.AccountExpired {
		t.Fatalf("status flags = %+v", user)
	}
	if !user.PwdLastSet.IsZero() || user.LockoutTime.IsZero() || user.AccountExpires.IsZero() {
		t.Fatalf("times = %+v", user)
	}
	wantCreated := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	if !user.WhenCreated.Equal(wantCreated) {
		t.Fatalf("whenCreated = %v", user.WhenCreated)
	}
	if user.Enabled() {
		t.Fatal("expired account reports enabled")
	}
	never := &Entry{DN: "cn=never", Attributes: []Attribute{
		{Type: "userAccountControl", Values: []string{strconv.Itoa(UACNormalAccount)}},
		{Type: "accountExpires", Values: []string{strconv.FormatInt(adFileTimeNever, 10)}},
	}}
	neverUser, err := entryToADUser(never)
	if err != nil {
		t.Fatalf("never entry: %v", err)
	}
	if !neverUser.Enabled() || neverUser.AccountExpired || !neverUser.AccountExpires.IsZero() {
		t.Fatalf("never user = %+v", neverUser)
	}
	disabled := &Entry{DN: "cn=disabled", Attributes: []Attribute{
		{Type: "userAccountControl", Values: []string{strconv.Itoa(UACAccountDisabled)}},
	}}
	disabledUser, err := entryToADUser(disabled)
	if err != nil || !disabledUser.Disabled || disabledUser.Enabled() {
		t.Fatalf("disabled user = %+v, %v", disabledUser, err)
	}
	var nilUser *ADUser
	if nilUser.Enabled() {
		t.Fatal("nil user reports enabled")
	}
	if _, err := entryToADUser(nil); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("nil entry error = %v", err)
	}
}

// TestEntryToADUserInvalidAttributes verifies malformed attribute rejection. |
// TestEntryToADUserInvalidAttributes 校验畸形属性拒绝。
func TestEntryToADUserInvalidAttributes(t *testing.T) {
	tests := []struct {
		attribute string
		value     string
	}{
		{attribute: "userAccountControl", value: "abc"},
		{attribute: "pwdLastSet", value: "abc"},
		{attribute: "msDS-UserPasswordExpiryTimeComputed", value: "abc"},
		{attribute: "lastLogonTimestamp", value: "abc"},
		{attribute: "lockoutTime", value: "abc"},
		{attribute: "accountExpires", value: "abc"},
		{attribute: "whenCreated", value: "not-a-time"},
	}
	for _, test := range tests {
		entry := &Entry{DN: "cn=bad", Attributes: []Attribute{{Type: test.attribute, Values: []string{test.value}}}}
		if _, err := entryToADUser(entry); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("%s=%q error = %v", test.attribute, test.value, err)
		}
	}
}

// TestADSubcodeAndMapping verifies diagnostic parsing and sentinel mapping. |
// TestADSubcodeAndMapping 校验诊断码解析与哨兵映射。
func TestADSubcodeAndMapping(t *testing.T) {
	subcodes := []struct {
		diagnostic string
		want       string
	}{
		{diagnostic: "80090308: LdapErr: ... data 52e, v4563", want: "52e"},
		{diagnostic: "DATA 533; comment", want: "533"},
		{diagnostic: "data 775", want: "775"},
		{diagnostic: "no subcode", want: ""},
		{diagnostic: "data ", want: ""},
	}
	for _, test := range subcodes {
		if got := adSubcode(test.diagnostic); got != test.want {
			t.Fatalf("adSubcode(%q) = %q, want %q", test.diagnostic, got, test.want)
		}
	}
	if got := adResultSentinel(ResultInvalidCredentials, "... data 533 ..."); !errors.Is(got, ErrAccountDisabled) {
		t.Fatalf("disabled sentinel = %v", got)
	}
	if got := adResultSentinel(ResultInvalidCredentials, "... data 999 ..."); !errors.Is(got, ErrInvalidCredentials) {
		t.Fatalf("unknown subcode sentinel = %v", got)
	}
	codes := map[ResultCode]error{
		ResultTimeLimitExceeded:   ErrTimeLimitExceeded,
		ResultSizeLimitExceeded:   ErrSizeLimitExceeded,
		ResultReferral:            ErrReferral,
		ResultConstraintViolation: ErrConstraintViolation,
		ResultInsufficientAccess:  ErrInsufficientAccess,
		ResultBusy:                ErrBusy,
		ResultUnavailable:         ErrUnavailable,
		ResultEntryAlreadyExists:  ErrEntryAlreadyExists,
		ResultNoSuchObject:        ErrNoSuchObject,
	}
	for code, want := range codes {
		if got := adResultSentinel(code, ""); !errors.Is(got, want) {
			t.Fatalf("code %d sentinel = %v, want %v", code, got, want)
		}
	}
	if got := adResultSentinel(ResultProtocolError, ""); got != nil {
		t.Fatalf("unmapped sentinel = %v", got)
	}
	if err := mapADError(nil); err != nil {
		t.Fatalf("mapADError nil = %v", err)
	}
	plain := errors.New("plain network failure")
	if got := mapADError(plain); got != plain {
		t.Fatalf("mapADError plain = %v", got)
	}
	resultErr := newResultError("bind", LDAPResult{Code: ResultInvalidCredentials, DiagnosticMessage: "data 532"})
	mapped := mapADError(resultErr)
	if !errors.Is(mapped, ErrPasswordExpired) || !errors.Is(mapped, ErrInvalidCredentials) {
		t.Fatalf("mapped error = %v", mapped)
	}
}

// TestADHelpers verifies domain, time, and identity helpers. | TestADHelpers 校验域、
// 时间与身份辅助函数。
func TestADHelpers(t *testing.T) {
	if got := normalizeADDomain(" Example.COM. "); got != "Example.COM" {
		t.Fatalf("normalizeADDomain = %q", got)
	}
	domains := map[string]string{
		"example.com":    "DC=example,DC=com",
		"example.com.":   "DC=example,DC=com",
		"Example":        "DC=Example",
		"":               "",
		"bad_domain.com": "",
		"-bad.example":   "",
		"bad-.example":   "",
	}
	for domain, want := range domains {
		if got := domainToBaseDN(domain); got != want {
			t.Fatalf("domainToBaseDN(%q) = %q, want %q", domain, got, want)
		}
	}
	bases := map[string]string{
		"DC=example,DC=com":    "example.com",
		"dc=example, dc=com":   "example.com",
		"DC=example,OU=people": "example",
		"OU=people,DC=example": "",
		"":                     "",
		"DC=,DC=com":           "",
	}
	for base, want := range bases {
		if got := baseDNToDomain(base); got != want {
			t.Fatalf("baseDNToDomain(%q) = %q, want %q", base, got, want)
		}
	}
	if validDNSLabel("-bad") || validDNSLabel("bad-") || validDNSLabel("bad_label") || !validDNSLabel("dc1") {
		t.Fatal("validDNSLabel")
	}
	if adFileTime(0) != (time.Time{}) || adFileTime(adFileTimeNever) != (time.Time{}) || adFileTime(adFileTimeOffset-1) != (time.Time{}) {
		t.Fatal("adFileTime sentinel handling")
	}
	if got := adFileTime(adFileTimeOffset); !got.Equal(time.Unix(0, 0).UTC()) {
		t.Fatalf("adFileTime epoch = %v", got)
	}
	created, err := parseADGeneralizedTime("20240101120000.0Z")
	if err != nil || !created.Equal(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("parseADGeneralizedTime = %v, %v", created, err)
	}
	if _, err := parseADGeneralizedTime("bad"); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("invalid time error = %v", err)
	}
	if value, present, err := parseADUint("42", 32); err != nil || !present || value != 42 {
		t.Fatalf("parseADUint = %d, %t, %v", value, present, err)
	}
	if _, present, err := parseADUint("", 32); err != nil || present {
		t.Fatalf("empty parseADUint = %t, %v", present, err)
	}
	if _, _, err := parseADUint("-1", 32); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("negative parseADUint error = %v", err)
	}
	if value, present, err := parseADInt("-5"); err != nil || !present || value != -5 {
		t.Fatalf("parseADInt = %d, %t, %v", value, present, err)
	}
	if _, _, err := parseADInt("x"); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("invalid parseADInt error = %v", err)
	}
	if !looksLikeDN("CN=Alice,DC=example") || looksLikeDN("alice@example.com") || looksLikeDN(`EXAMPLE\alice`) {
		t.Fatal("looksLikeDN")
	}
	groups := dedupeADGroups([]string{"CN=A", "", "cn=a", "CN=B", "CN=A"})
	if len(groups) != 2 || groups[0] != "CN=A" || groups[1] != "CN=B" {
		t.Fatalf("dedupeADGroups = %v", groups)
	}
	if dedupeADGroups(nil) != nil {
		t.Fatal("empty dedupeADGroups is not nil")
	}
	minimal := minimalADUser("alice", "alice@example.com")
	if !minimal.Authenticated || minimal.SAMAccountName != "alice" || minimal.UPN != "" || minimal.DN != "" {
		t.Fatalf("minimal user = %+v", minimal)
	}
	minimal = minimalADUser("alice@example.com", "alice@example.com")
	if minimal.UPN != "alice@example.com" || minimal.SAMAccountName != "alice" {
		t.Fatalf("UPN minimal user = %+v", minimal)
	}
	minimal = minimalADUser(`EXAMPLE\alice`, `EXAMPLE\alice`)
	if minimal.SAMAccountName != "alice" || minimal.UPN != "" {
		t.Fatalf("down-level minimal user = %+v", minimal)
	}
	minimal = minimalADUser(adTestUserDN, adTestUserDN)
	if minimal.DN != adTestUserDN || minimal.SAMAccountName != "" {
		t.Fatalf("DN minimal user = %+v", minimal)
	}
}

// TestADEndpointErrors verifies discovery validation without DNS. | TestADEndpointErrors
// 校验不依赖 DNS 的发现验证。
func TestADEndpointErrors(t *testing.T) {
	if _, err := adEndpointURLs(context.Background(), ADConfig{}, ""); !errors.Is(err, ErrADDiscovery) {
		t.Fatalf("empty discovery error = %v", err)
	}
	urls, err := adEndpointURLs(context.Background(), ADConfig{URL: " ldap://dc1.example.com "}, "")
	if err != nil || len(urls) != 1 || urls[0] != "ldap://dc1.example.com" {
		t.Fatalf("explicit URLs = %v, %v", urls, err)
	}
	if adRetryable(nil) || adRetryable(ErrInvalidConfig) || adRetryable(context.Canceled) {
		t.Fatal("adRetryable accepted a permanent error")
	}
	if !adRetryable(ErrNetwork) {
		t.Fatal("adRetryable rejected a transient error")
	}
	if !adRetryable(newResultError("bind", LDAPResult{Code: ResultBusy})) || adRetryable(newResultError("bind", LDAPResult{Code: ResultUnwillingToPerform})) {
		t.Fatal("adRetryable result classification")
	}
}

// TestADGroupDeduplication verifies chain groups are deduplicated. | TestADGroupDeduplication
// 校验链式组去重。
func TestADGroupDeduplication(t *testing.T) {
	mock := newADMock(t)
	ad := newTestAD(t, mock)
	groups, err := ad.Groups(context.Background(), "alice")
	if err != nil {
		t.Fatalf("Groups: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("groups = %v", groups)
	}
}

// TestADMockServerAddress documents that the mock listener is reachable. |
// TestADMockServerAddress 记录模拟监听器可达。
func TestADMockServerAddress(t *testing.T) {
	mock := newADMock(t)
	if !strings.HasPrefix(mock.URL(), "ldap://127.0.0.1:") {
		t.Fatalf("mock URL = %q", mock.URL())
	}
}
