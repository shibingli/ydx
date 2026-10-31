package waf

import (
	"errors"
	"testing"
	"testing/fstest"
)

func TestACMatcher(t *testing.T) {
	matcher := newACMatcher([]string{"select", "union", "script"})
	for _, value := range []string{"xx select yy", "union", "script>"} {
		if !matcher.match(value) {
			t.Fatalf("%q should match", value)
		}
	}
	for _, value := range []string{"", "sel", "unio", "java"} {
		if matcher.match(value) {
			t.Fatalf("%q should not match", value)
		}
	}
}

func TestIPMatcher(t *testing.T) {
	matcher, err := parseIPMatcher([]string{"10.0.0.0/8", "192.168.1.1", "2001:db8::/32", "127.0.0.1:8080"})
	if err != nil {
		t.Fatalf("parseIPMatcher: %v", err)
	}
	for _, value := range []string{"10.1.2.3", "192.168.1.1", "2001:db8::1", "127.0.0.1", "::ffff:10.0.0.1"} {
		if !matcher.match(value) {
			t.Fatalf("%q should match", value)
		}
	}
	for _, value := range []string{"11.0.0.1", "192.168.1.2", "2001:db9::1", "not-an-ip"} {
		if matcher.match(value) {
			t.Fatalf("%q should not match", value)
		}
	}
}

func TestByteRanges(t *testing.T) {
	ranges, err := parseByteRanges("9,10,13,32-126")
	if err != nil {
		t.Fatalf("parseByteRanges: %v", err)
	}
	if !ranges.valid("hello\tworld") {
		t.Fatal("printable range should be valid")
	}
	if ranges.valid("hello\x01") {
		t.Fatal("control byte should be invalid")
	}
	if _, err := parseByteRanges("300"); err == nil {
		t.Fatal("out-of-range value accepted")
	}
}

func TestCompileOperatorErrors(t *testing.T) {
	context := compileContext{strict: true}
	if _, err := compileOperator(false, "@nope", "x", context); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported operator error = %v", err)
	}
	if _, err := compileOperator(false, "@rx", "(", context); !errors.Is(err, ErrParse) && !errors.Is(err, ErrUnsupported) {
		t.Fatalf("invalid regex error = %v", err)
	}
}

func TestRegexPrefilterSoundness(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		value   string
		want    bool
	}{
		{"literal-prefix-hit", "abc", "xxabcxx", true},
		{"literal-prefix-miss", "abc", "xxxxx", false},
		{"case-insensitive", "(?i)select", "SELECT 1", true},
		{"alternation", "foo|bar", "BAR", false},
		{"anchor", "^admin", "admin", true},
		{"anchor-miss", "^admin", "not-admin", false},
	}
	for _, test := range tests {
		op, err := compileOperator(false, "@rx", test.pattern, compileContext{strict: true})
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		got, _ := op.eval(nil, test.value, false)
		if got != test.want {
			t.Fatalf("%s: pattern %q value %q = %v, want %v (prefilter=%q)",
				test.name, test.pattern, test.value, got, test.want, op.prefilter)
		}
	}
}

func TestOperatorMacroArgument(t *testing.T) {
	op, err := compileOperator(false, "@within", "%{tx.allowed}", compileContext{strict: true})
	if err != nil {
		t.Fatalf("compileOperator: %v", err)
	}
	tx := &transaction{tx: map[string]txValue{"allowed": {values: []string{"a b c"}}}}
	matched, _ := op.eval(tx, "b", false)
	if !matched {
		t.Fatal("@within macro did not match")
	}
}

func TestDetectOperators(t *testing.T) {
	if ok, _ := detectSQLi("1' OR '1'='1"); !ok {
		t.Fatal("libinjection did not detect SQL injection")
	}
	if !detectXSS("<script>alert(1)</script>") {
		t.Fatal("libinjection did not detect XSS")
	}
}

func TestValidateURLEncoding(t *testing.T) {
	if !validURLEncoding("a%20b%2Fc") {
		t.Fatal("valid encoding rejected")
	}
	if validURLEncoding("a%2") || validURLEncoding("a%zz") || validURLEncoding("a%FF") {
		t.Fatal("invalid encoding accepted")
	}
}

func TestValidationOperatorsMatchInvalidInput(t *testing.T) {
	cases := []struct {
		operator string
		arg      string
		valid    string
		invalid  string
	}{
		{"@validateUtf8Encoding", "", "hello", string([]byte{0xff, 0xfe})},
		{"@validateUrlEncoding", "", "a%20b", "a%zz"},
		{"@validateByteRange", "32-126", "hello", "hello\x01"},
	}
	for _, test := range cases {
		op, err := compileOperator(false, test.operator, test.arg, compileContext{strict: true})
		if err != nil {
			t.Fatalf("%s: %v", test.operator, err)
		}
		if matched, _ := op.eval(nil, test.valid, false); matched {
			t.Fatalf("%s matched valid input", test.operator)
		}
		if matched, _ := op.eval(nil, test.invalid, false); !matched {
			t.Fatalf("%s did not match invalid input", test.operator)
		}
	}
}

func TestPMFromFile(t *testing.T) {
	files := fstest.MapFS{
		"patterns.data": &fstest.MapFile{Data: []byte("# comment\nselect\nunion all\n\n")},
	}
	op, err := compileOperator(false, "@pmFromFile", "patterns.data", compileContext{
		fsys:   files,
		strict: true,
	})
	if err != nil {
		t.Fatalf("compileOperator: %v", err)
	}
	if matched, _ := op.eval(nil, "union all users", false); !matched {
		t.Fatal("pmFromFile did not match")
	}
}

func TestIPMatchFromFile(t *testing.T) {
	files := fstest.MapFS{
		"ips.data": &fstest.MapFile{Data: []byte("10.0.0.0/8\n192.168.0.1\n")},
	}
	op, err := compileOperator(false, "@ipMatchFromFile", "ips.data", compileContext{
		fsys:   files,
		strict: true,
	})
	if err != nil {
		t.Fatalf("compileOperator: %v", err)
	}
	if matched, _ := op.eval(nil, "10.2.3.4", false); !matched {
		t.Fatal("ipMatchFromFile did not match")
	}
}
