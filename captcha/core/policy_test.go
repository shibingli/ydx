package core

import (
	"net/netip"
	"testing"
)

func TestPolicyDenyBeforeAllow(t *testing.T) {
	snapshot, err := CompilePolicy(&Policy{
		Allow: []Rule{{IP: "203.0.113.0/24"}},
		Deny:  []Rule{{IP: "203.0.113.8", Action: "login"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddr("203.0.113.8")
	decision := snapshot.Evaluate(addr, "", "login", TypeText)
	if !decision.Denied || decision.Allowed {
		t.Fatalf("decision = %+v", decision)
	}
	decision = snapshot.Evaluate(addr, "", "register", TypeText)
	if !decision.Allowed {
		t.Fatalf("allow missing: %+v", decision)
	}
}

func TestPolicyCountryAndInvalidRules(t *testing.T) {
	snapshot, err := CompilePolicy(&Policy{Deny: []Rule{{Country: "CN", Type: TypeSMS}}})
	if err != nil {
		t.Fatal(err)
	}
	decision := snapshot.Evaluate(netip.Addr{}, "CN", "login", TypeSMS)
	if !decision.Denied || !decision.DeniedCountry {
		t.Fatalf("decision = %+v", decision)
	}
	if _, err := CompilePolicy(&Policy{Deny: []Rule{{}}}); err == nil {
		t.Fatal("expected empty rule rejection")
	}
	if _, err := CompilePolicy(&Policy{Deny: []Rule{{IP: "not-an-ip"}}}); err == nil {
		t.Fatal("expected invalid IP rejection")
	}
}
