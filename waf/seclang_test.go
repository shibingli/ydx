package waf

import (
	"errors"
	"testing"
	"testing/fstest"
)

func TestLexLine(t *testing.T) {
	tokens, err := lexLine(`SecRule ARGS "@rx ^a b$" "id:1,msg:'x,y'" # trailing comment`)
	if err != nil {
		t.Fatalf("lexLine: %v", err)
	}
	want := []string{"SecRule", "ARGS", "@rx ^a b$", "id:1,msg:'x,y'"}
	if len(tokens) != len(want) {
		t.Fatalf("tokens = %#v", tokens)
	}
	for index := range want {
		if tokens[index] != want[index] {
			t.Fatalf("token %d = %q, want %q", index, tokens[index], want[index])
		}
	}
}

func TestLexLinePreservesRegexEscapes(t *testing.T) {
	tokens, err := lexLine(`SecRule ARGS "@rx \d+\\w" "id:1"`)
	if err != nil {
		t.Fatalf("lexLine: %v", err)
	}
	if tokens[2] != `@rx \d+\w` {
		t.Fatalf("operator = %q", tokens[2])
	}
}

func TestSplitActionList(t *testing.T) {
	got := splitActionList(`id:1,msg:'a,b',setvar:'tx.x=1',t:urlDecodeUni`)
	want := []string{"id:1", "msg:'a,b'", "setvar:'tx.x=1'", "t:urlDecodeUni"}
	if len(got) != len(want) {
		t.Fatalf("got %#v", got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("action %d = %q, want %q", index, got[index], want[index])
		}
	}
}

func TestSplitVarListWithRegex(t *testing.T) {
	got := splitVarList(`ARGS:/^foo|bar$/|REQUEST_HEADERS:User-Agent|!ARGS:excluded`)
	want := []string{"ARGS:/^foo|bar$/", "REQUEST_HEADERS:User-Agent", "!ARGS:excluded"}
	if len(got) != len(want) {
		t.Fatalf("got %#v", got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("selector %d = %q, want %q", index, got[index], want[index])
		}
	}
}

func TestSplitVarListWithXMLSelectors(t *testing.T) {
	raw := `REQUEST_COOKIES|ARGS|XML:/*|XML://@*|!REQUEST_COOKIES:/^_ga(?:_\w+)?$/`
	got := splitVarList(raw)
	want := []string{"REQUEST_COOKIES", "ARGS", "XML:/*", "XML://@*", `!REQUEST_COOKIES:/^_ga(?:_\w+)?$/`}
	if len(got) != len(want) {
		t.Fatalf("got %#v", got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("selector %d = %q, want %q (all=%#v)", index, got[index], want[index], got)
		}
	}
}

func TestSplitOperator(t *testing.T) {
	negated, name, arg := splitOperator(`!@rx ^a b$`)
	if !negated || name != "@rx" || arg != "^a b$" {
		t.Fatalf("got %v %q %q", negated, name, arg)
	}
	negated, name, arg = splitOperator(`contains`)
	if negated || name != "@rx" || arg != "contains" {
		t.Fatalf("bare pattern got %v %q %q", negated, name, arg)
	}
}

func TestLoadIncludesAndMarkers(t *testing.T) {
	files := fstest.MapFS{
		"main.conf": &fstest.MapFile{Data: []byte(
			"SecRuleEngine On\nInclude inc/*.conf\nSecRule REQUEST_URI \"@contains root\" \"id:2,phase:1,deny\"\n")},
		"inc/rules.conf": &fstest.MapFile{Data: []byte(
			"# comment\nSecRule REQUEST_URI \"@contains included\" \"id:1,phase:1,deny\"\n")},
	}
	bundle, warnings, err := loadLocalSource(Options{RootFS: files, RuleFiles: []string{"main.conf"}})
	if err != nil {
		t.Fatalf("loadLocalSource: %v (warnings=%v)", err, warnings)
	}
	directives, err := parseSecLang(string(bundle.Data), "bundle", parseOptions{Strict: true})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var included *parsedDirective
	var root *parsedDirective
	for index := range directives {
		switch directives[index].Name {
		case "SecRule":
			if directives[index].Args[1] == `@contains included` {
				included = &directives[index]
			}
			if directives[index].Args[1] == `@contains root` {
				root = &directives[index]
			}
		}
	}
	if included == nil || root == nil {
		t.Fatalf("rules not parsed: %#v", directives)
	}
	if included.File != "inc/rules.conf" || included.Line != 2 {
		t.Fatalf("included location = %s:%d", included.File, included.Line)
	}
	if root.File != "main.conf" || root.Line != 3 {
		t.Fatalf("root location = %s:%d", root.File, root.Line)
	}
}

func TestIncludeCycleFails(t *testing.T) {
	files := fstest.MapFS{
		"a.conf": &fstest.MapFile{Data: []byte("Include b.conf\n")},
		"b.conf": &fstest.MapFile{Data: []byte("Include a.conf\n")},
	}
	_, _, err := loadLocalSource(Options{RootFS: files, RuleFiles: []string{"a.conf"}})
	if err == nil {
		t.Fatal("expected include cycle error")
	}
}

func TestUnknownDirectiveStrictAndLenient(t *testing.T) {
	source := "SecTotallyUnknown On\nSecRule REQUEST_URI \"@contains x\" \"id:1,phase:1,deny\"\n"
	if _, err := parseSecLang(source, "test", parseOptions{Strict: true}); err == nil {
		t.Fatal("strict mode accepted unknown directive")
	}
	var warnings []string
	directives, err := parseSecLang(source, "test", parseOptions{
		Strict: false,
		Warn:   func(message string) { warnings = append(warnings, message) },
	})
	if err != nil {
		t.Fatalf("lenient parse: %v", err)
	}
	if len(directives) != 1 || len(warnings) != 1 {
		t.Fatalf("directives=%d warnings=%v", len(directives), warnings)
	}
}

func TestSecDefaultActionPhaseInheritance(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecDefaultAction "phase:1,log,auditlog,pass"`,
		`SecRule REQUEST_URI "@contains inherited" "id:9100,deny,status:403"`,
	}, nil)
	response := serveTest(t, instance, httptestNewRequest("/inherited"))
	if response.Code != 403 {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestRuleUpdateTargetById(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains blocked" "id:9110,phase:1,deny,status:403"`,
		`SecRuleUpdateTargetById 9110 "ARGS:blocked"`,
	}, nil)
	if response := serveTest(t, instance, httptestNewRequest("/blocked")); response.Code != 403 {
		t.Fatalf("URI should still match: %d", response.Code)
	}
	if response := serveTest(t, instance, httptestNewRequest("/?blocked=blocked")); response.Code != 403 {
		t.Fatalf("added ARGS should match: %d", response.Code)
	}
}

func TestRuleRemoveById(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains blocked" "id:9120,phase:1,deny,status:403"`,
		`SecRuleRemoveById 9120`,
		`SecRule REQUEST_URI "@contains other" "id:9121,phase:1,deny,status:403"`,
	}, nil)
	if response := serveTest(t, instance, httptestNewRequest("/blocked")); response.Code != 200 {
		t.Fatalf("removed rule still blocks: %d", response.Code)
	}
	if response := serveTest(t, instance, httptestNewRequest("/other")); response.Code != 403 {
		t.Fatalf("other rule did not block: %d", response.Code)
	}
}

func TestInvalidRuleBuildKeepsStrictError(t *testing.T) {
	_, err := New(Options{
		Directives: []string{`SecRule REQUEST_URI "@rx (" "id:1,phase:1,deny"`},
	})
	if err == nil {
		t.Fatal("expected regex compile error")
	}
	if !errors.Is(err, ErrBuild) {
		t.Fatalf("error = %v", err)
	}
}

func TestLenientSkipsInvalidRule(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@rx (" "id:1,phase:1,deny"`,
		`SecRule REQUEST_URI "@contains ok" "id:2,phase:1,deny,status:403"`,
	}, func(options *Options) { options.Lenient = true })
	if response := serveTest(t, instance, httptestNewRequest("/ok")); response.Code != 403 {
		t.Fatalf("valid rule did not block: %d", response.Code)
	}
}
