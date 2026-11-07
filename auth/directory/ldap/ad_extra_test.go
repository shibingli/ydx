package ldap

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestActiveDirectoryDiscoveryFallbacks verifies root DSE fallbacks and error
// handling during construction. | TestActiveDirectoryDiscoveryFallbacks 校验构造期间
// 根 DSE 回退与错误处理。
func TestActiveDirectoryDiscoveryFallbacks(t *testing.T) {
	t.Run("nil context", func(t *testing.T) {
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			if _, ok := message.Op.(*SearchRequest); !ok {
				return errors.New("unexpected operation")
			}
			if err := session.writeEntry(message.MessageID, "",
				Attribute{Type: "defaultNamingContext", Values: []string{adTestBaseDN}}); err != nil {
				return err
			}
			return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess})
		})
		ad, err := NewActiveDirectory(nil, ADConfig{URL: server.URL(), Domain: "example.com"})
		if err != nil {
			t.Fatalf("NewActiveDirectory: %v", err)
		}
		defer ad.Close()
		if ad.BaseDN() != adTestBaseDN {
			t.Fatalf("base DN = %q", ad.BaseDN())
		}
	})
	t.Run("empty root DSE and domain", func(t *testing.T) {
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			if err := session.writeEntry(message.MessageID, ""); err != nil {
				return err
			}
			return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess})
		})
		if _, err := NewActiveDirectory(context.Background(), ADConfig{URL: server.URL()}); !errors.Is(err, ErrADDiscovery) {
			t.Fatalf("empty discovery error = %v", err)
		}
	})
	t.Run("empty root DSE with domain", func(t *testing.T) {
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			if err := session.writeEntry(message.MessageID, ""); err != nil {
				return err
			}
			return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess})
		})
		ad, err := NewActiveDirectory(context.Background(), ADConfig{URL: server.URL(), Domain: "corp.example"})
		if err != nil {
			t.Fatalf("NewActiveDirectory: %v", err)
		}
		defer ad.Close()
		if ad.BaseDN() != "DC=corp,DC=example" || ad.Domain() != "corp.example" {
			t.Fatalf("base/domain = %q/%q", ad.BaseDN(), ad.Domain())
		}
	})
	t.Run("root DSE failure without domain", func(t *testing.T) {
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultNoSuchObject})
		})
		_, err := NewActiveDirectory(context.Background(), ADConfig{URL: server.URL()})
		if !errors.Is(err, ErrADDiscovery) || !errors.Is(err, ErrNoSuchObject) {
			t.Fatalf("root DSE failure = %v", err)
		}
	})
	t.Run("root DSE failure with domain", func(t *testing.T) {
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultNoSuchObject})
		})
		ad, err := NewActiveDirectory(context.Background(), ADConfig{URL: server.URL(), Domain: "corp.example"})
		if err != nil {
			t.Fatalf("NewActiveDirectory: %v", err)
		}
		defer ad.Close()
		if ad.BaseDN() != "DC=corp,DC=example" {
			t.Fatalf("base DN = %q", ad.BaseDN())
		}
	})
}

// TestActiveDirectoryGroupFailurePaths verifies recursive group traversal error
// handling. | TestActiveDirectoryGroupFailurePaths 校验递归组遍历错误处理。
func TestActiveDirectoryGroupFailurePaths(t *testing.T) {
	baseHandler := func(mode string) mockHandler {
		return func(session *mockSession, message *LDAPMessage) error {
			switch request := message.Op.(type) {
			case *BindRequest:
				return session.writeSimpleResult(message.MessageID, &BindResponse{Result: LDAPResult{Code: ResultSuccess}})
			case *SearchRequest:
				if request.BaseDN == "" && request.Scope == ScopeBaseObject {
					if err := session.writeEntry(message.MessageID, "",
						Attribute{Type: "defaultNamingContext", Values: []string{adTestBaseDN}}); err != nil {
						return err
					}
					return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess})
				}
				switch {
				case strings.Contains(request.Filter.String(), ADMatchingRuleInChain):
					return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultUnwillingToPerform})
				case request.BaseDN == adTestDirectGroup || request.BaseDN == adTestMissingGroup:
					if mode == "busy" {
						return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultBusy})
					}
					return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess})
				case request.BaseDN == adTestBaseDN:
					entry := defaultADUserEntry()
					if err := session.writeEntry(message.MessageID, entry.DN, entry.Attributes...); err != nil {
						return err
					}
					return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess})
				default:
					return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultNoSuchObject})
				}
			default:
				return errors.New("unexpected operation")
			}
		}
	}
	t.Run("group lookup failure", func(t *testing.T) {
		server := startMockServer(t, baseHandler("busy"))
		cfg := ADConfig{
			Domain: "example.com", URL: server.URL(),
			BindDN: adTestServiceDN, BindPassword: adTestServicePassword,
		}
		ad, err := NewActiveDirectory(context.Background(), cfg)
		if err != nil {
			t.Fatalf("NewActiveDirectory: %v", err)
		}
		defer ad.Close()
		groups, err := ad.Groups(context.Background(), "alice")
		if !errors.Is(err, ErrBusy) {
			t.Fatalf("group lookup error = %v", err)
		}
		if len(groups) != 1 || groups[0] != adTestDirectGroup {
			t.Fatalf("partial groups = %v", groups)
		}
	})
	t.Run("group vanished between searches", func(t *testing.T) {
		server := startMockServer(t, baseHandler("empty"))
		cfg := ADConfig{
			Domain: "example.com", URL: server.URL(),
			BindDN: adTestServiceDN, BindPassword: adTestServicePassword,
		}
		ad, err := NewActiveDirectory(context.Background(), cfg)
		if err != nil {
			t.Fatalf("NewActiveDirectory: %v", err)
		}
		defer ad.Close()
		groups, err := ad.Groups(context.Background(), "alice")
		if err != nil {
			t.Fatalf("Groups: %v", err)
		}
		if len(groups) != 2 || groups[0] != adTestDirectGroup || groups[1] != adTestMissingGroup {
			t.Fatalf("groups = %v", groups)
		}
	})
	t.Run("closed service connection", func(t *testing.T) {
		ad := newTestAD(t, newADMock(t))
		if err := ad.client.Close(); err != nil {
			t.Fatalf("close service client: %v", err)
		}
		if groups, err := ad.groupsInChain(context.Background(), adTestUserDN); groups != nil || !errors.Is(err, ErrClosed) {
			t.Fatalf("closed groupsInChain = %v, %v", groups, err)
		}
		if entry, err := ad.lookupGroupEntry(context.Background(), adTestDirectGroup); entry != nil || !errors.Is(err, ErrClosed) {
			t.Fatalf("closed lookupGroupEntry = %v, %v", entry, err)
		}
		if groups, err := ad.groupsRecursive(context.Background(), []string{adTestDirectGroup}); len(groups) != 1 ||
			groups[0] != adTestDirectGroup || !errors.Is(err, ErrClosed) {
			t.Fatalf("closed groupsRecursive = %v, %v", groups, err)
		}
	})
}

// TestADIdentityHelperEdges verifies direct bind name derivation without a
// domain. | TestADIdentityHelperEdges 校验无域时的直接绑定名推导。
func TestADIdentityHelperEdges(t *testing.T) {
	ad := &ActiveDirectory{domain: "example.com"}
	if got := ad.directBindName("alice"); got != "alice@example.com" {
		t.Fatalf("domain bind name = %q", got)
	}
	empty := &ActiveDirectory{}
	if got := empty.directBindName("alice"); got != "alice" {
		t.Fatalf("empty domain bind name = %q", got)
	}
	for _, identity := range []string{"alice@example.com", `EXAMPLE\alice`, "CN=Alice,DC=example"} {
		if got := empty.directBindName(identity); got != identity {
			t.Fatalf("direct identity %q = %q", identity, got)
		}
	}
}
