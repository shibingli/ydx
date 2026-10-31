package waf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"

	"github.com/shibingli/ydx/log"
)

func TestPhaseTwoRuleWithoutBodyVariables(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_METHOD "@rx ^DELETE$" "id:9700,phase:2,deny,status:405"`,
	}, nil)
	if response := serveTest(t, instance, httptest.NewRequest(http.MethodDelete, "/", nil)); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", response.Code)
	}
}

func TestPhaseFourRuleWithoutBodyVariables(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule RESPONSE_STATUS "@ge 500" "id:9701,phase:4,deny,status:403"`,
	}, nil)
	recorder := httptest.NewRecorder()
	handler := instance.HTTPMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
}

func TestSecRuleEngineDetectionOnlyDirective(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRuleEngine DetectionOnly`,
		`SecRule REQUEST_URI "@contains attack" "id:9702,phase:1,deny,status:403"`,
	}, nil)
	if response := serveTest(t, instance, httptestNewRequest("/attack")); response.Code != 200 {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if stats := instance.Stats(); stats.Detected != 1 || stats.Blocked != 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestSecResponseBodyAccessDirective(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecResponseBodyAccess On`,
		`SecRule RESPONSE_BODY "@contains secret" "id:9703,phase:4,deny,status:403"`,
	}, nil)
	recorder := httptest.NewRecorder()
	handler := instance.HTTPMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		_, _ = rw.Write([]byte("secret"))
	}))
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
}

func TestSecRequestBodyAccessOffDirective(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRequestBodyAccess Off`,
		`SecRule ARGS_POST:payload "@contains attack" "id:9704,phase:2,deny,status:403"`,
	}, nil)
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("payload=attack"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if response := serveTest(t, instance, request); response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
}

func TestDefaultActionTransformInheritance(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecDefaultAction "phase:1,pass,nolog,t:lowercase"`,
		`SecRule REQUEST_URI "@contains attack" "id:9705,deny,status:403"`,
		`SecRule REQUEST_URI "@contains clean" "id:9706,deny,status:403,t:none"`,
	}, nil)
	if response := serveTest(t, instance, httptestNewRequest("/ATTACK")); response.Code != 403 {
		t.Fatalf("inherited transform status = %d", response.Code)
	}
	if response := serveTest(t, instance, httptestNewRequest("/CLEAN")); response.Code != 200 {
		t.Fatalf("t:none status = %d", response.Code)
	}
}

func TestRuleUpdateTargetByTag(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains blocked" "id:9707,phase:1,deny,tag:'demo'"`,
		`SecRuleUpdateTargetByTag demo "ARGS:blocked"`,
	}, nil)
	if response := serveTest(t, instance, httptestNewRequest("/blocked")); response.Code != 403 {
		t.Fatalf("URI status = %d", response.Code)
	}
	if response := serveTest(t, instance, httptestNewRequest("/?blocked=blocked")); response.Code != 403 {
		t.Fatalf("added tag target status = %d", response.Code)
	}
}

func TestRuleUpdateTargetExclusion(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains blocked" "id:9714,phase:1,deny,status:403"`,
		`SecRuleUpdateTargetById 9714 "!REQUEST_URI"`,
	}, nil)
	if response := serveTest(t, instance, httptestNewRequest("/blocked")); response.Code != 200 {
		t.Fatalf("excluded URI status = %d", response.Code)
	}
}

func TestHostHeaderVisibleToRules(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_HEADERS:Host "@contains example.com" "id:9715,phase:1,deny,status:403"`,
	}, nil)
	if response := serveTest(t, instance, httptestNewRequest("/")); response.Code != 403 {
		t.Fatalf("Host status = %d", response.Code)
	}
}

func TestRuleRemoveByTag(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains blocked" "id:9708,phase:1,deny,tag:'remove-me'"`,
		`SecRuleRemoveByTag remove-me`,
		`SecRule REQUEST_URI "@contains other" "id:9709,phase:1,deny"`,
	}, nil)
	if response := serveTest(t, instance, httptestNewRequest("/blocked")); response.Code != 200 {
		t.Fatalf("removed rule status = %d", response.Code)
	}
	if response := serveTest(t, instance, httptestNewRequest("/other")); response.Code != 403 {
		t.Fatalf("other rule status = %d", response.Code)
	}
}

func TestRuleUpdateActionById(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains update" "id:9710,phase:1,pass,nolog"`,
		`SecRuleUpdateActionById 9710 "deny,status:403"`,
	}, nil)
	if response := serveTest(t, instance, httptestNewRequest("/update")); response.Code != 403 {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

func TestIncludeOptionalMissing(t *testing.T) {
	files := fstest.MapFS{
		"main.conf": &fstest.MapFile{Data: []byte(
			"IncludeOptional missing/*.conf\nSecRule REQUEST_URI \"@contains ok\" \"id:9711,phase:1,deny\"\n")},
	}
	bundle, warnings, err := loadLocalSource(Options{RootFS: files, RuleFiles: []string{"main.conf"}})
	if err != nil {
		t.Fatalf("loadLocalSource: %v", err)
	}
	if len(warnings) == 0 {
		t.Fatal("missing optional include produced no warning")
	}
	if len(bundle.Data) == 0 {
		t.Fatal("bundle is empty")
	}
}

func TestStreqOperator(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_METHOD "@streq POST" "id:9716,phase:1,deny,status:405"`,
	}, nil)
	if response := serveTest(t, instance, httptestNewRequest("/")); response.Code != 200 {
		t.Fatalf("GET status = %d", response.Code)
	}
	if response := serveTest(t, instance, httptest.NewRequest(http.MethodPost, "/", nil)); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d", response.Code)
	}
}

func TestSkipAfterAcrossPhases(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains guarded" "id:9717,phase:1,pass,nolog,skipAfter:END"`,
		`SecRule REQUEST_URI "@contains guarded" "id:9718,phase:1,deny,status:403"`,
		`SecRule REQUEST_URI "@contains other" "id:9719,phase:2,pass,nolog"`,
		`SecMarker END`,
	}, nil)
	if response := serveTest(t, instance, httptestNewRequest("/guarded")); response.Code != 200 {
		t.Fatalf("status = %d, want 200", response.Code)
	}
}

func TestSkipAfterMarkerResumesLaterPhaseRules(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains guarded" "id:9740,phase:1,pass,nolog,skipAfter:END-FILE"`,
		`SecRule REQUEST_URI "@contains guarded" "id:9741,phase:1,deny,status:403"`,
		`SecRule REQUEST_URI "@contains guarded" "id:9742,phase:2,pass,nolog"`,
		`SecMarker "END-FILE"`,
		`SecRule REQUEST_URI "@contains guarded" "id:9743,phase:1,deny,status:418"`,
	}, nil)
	if response := serveTest(t, instance, httptestNewRequest("/guarded")); response.Code != 418 {
		t.Fatalf("status = %d, want 418; phase-1 rules after the marker must still run", response.Code)
	}
}

func TestArgsCombinedSize(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule ARGS_COMBINED_SIZE "@gt 5" "id:9720,phase:1,deny,status:403"`,
	}, nil)
	if response := serveTest(t, instance, httptestNewRequest("/?q=hello")); response.Code != 403 {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	if response := serveTest(t, instance, httptestNewRequest("/?q=a")); response.Code != 200 {
		t.Fatalf("small status = %d, want 200", response.Code)
	}
}

func TestCRSAnomalyBlockSemantics(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecDefaultAction "phase:1,pass,nolog"`,
		`SecDefaultAction "phase:2,pass,nolog"`,
		`SecAction "id:9721,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_pl1=0"`,
		`SecAction "id:9722,phase:1,pass,nolog,setvar:tx.critical_anomaly_score=5"`,
		`SecRule ARGS:q "@contains attack" "id:9723,phase:2,block,setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}"`,
		`SecRule TX:inbound_anomaly_score_pl1 "@ge 5" "id:9724,phase:2,deny,status:403"`,
	}, nil)
	response := serveTest(t, instance, httptestNewRequest("/?q=attack"))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

func TestBlockActionUsesDefaultDeny(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecDefaultAction "phase:1,deny,status:406"`,
		`SecRule REQUEST_URI "@contains custom" "id:9725,phase:1,block"`,
	}, nil)
	if response := serveTest(t, instance, httptestNewRequest("/custom")); response.Code != http.StatusNotAcceptable {
		t.Fatalf("status = %d, want 406", response.Code)
	}
}

func TestValidationOperatorsThroughEngine(t *testing.T) {
	cases := []struct {
		name       string
		directives []string
		body       string
		want       int
	}{
		{
			name:       "url-invalid",
			directives: []string{`SecRule REQUEST_BODY "@validateUrlEncoding" "id:9726,phase:2,deny,status:403"`},
			body:       "a=%zz",
			want:       http.StatusForbidden,
		},
		{
			name:       "url-valid",
			directives: []string{`SecRule REQUEST_BODY "@validateUrlEncoding" "id:9727,phase:2,deny,status:403"`},
			body:       "a=%20",
			want:       http.StatusOK,
		},
		{
			name:       "utf8-invalid",
			directives: []string{`SecRule REQUEST_BODY "@validateUtf8Encoding" "id:9728,phase:2,deny,status:403"`},
			body:       "bad\xff",
			want:       http.StatusForbidden,
		},
		{
			name:       "byte-range-invalid",
			directives: []string{`SecRule REQUEST_BODY "@validateByteRange 32-126" "id:9729,phase:2,deny,status:403"`},
			body:       "hello\x01",
			want:       http.StatusForbidden,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			instance := newTestWAF(t, test.directives, nil)
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "text/plain")
			if response := serveTest(t, instance, request); response.Code != test.want {
				t.Fatalf("status = %d, want %d", response.Code, test.want)
			}
		})
	}
}

func TestTransferEncodingVisibleToRules(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_HEADERS:Transfer-Encoding "@contains chunked" "id:9733,phase:1,deny,status:403"`,
	}, nil)
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("a=1"))
	request.ContentLength = -1
	request.TransferEncoding = []string{"chunked"}
	if response := serveTest(t, instance, request); response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

func TestNologRulesDoNotAccumulateEventMatches(t *testing.T) {
	var observed Event
	var hookCalls atomic.Int32
	instance, err := New(Options{
		Directives: []string{
			`SecRule REQUEST_URI "@contains x" "id:9734,phase:1,pass,nolog"`,
			`SecRule REQUEST_URI "@contains x" "id:9735,phase:1,pass,log"`,
		},
		Logger:   log.New(log.Options{Writer: io.Discard, Level: log.ErrorLevel}),
		Observer: func(event Event) { observed = event },
		Hooks: []Hook{HookFunc{HookName: "count", HookPoints: []HookPoint{HookRuleMatch}, Fn: func(*HookContext) error {
			hookCalls.Add(1)
			return nil
		}}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = instance.Close() }()
	serveTest(t, instance, httptestNewRequest("/x"))
	if hookCalls.Load() != 2 {
		t.Fatalf("rule match hooks = %d, want 2", hookCalls.Load())
	}
	if len(observed.Matches) != 1 || observed.Matches[0].RuleID != 9735 {
		t.Fatalf("matches = %+v", observed.Matches)
	}
}

func TestCtlRemoveChainMemberDisablesChain(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains disarm" "id:9730,phase:1,pass,nolog,ctl:ruleRemoveById=9732"`,
		`SecRule REQUEST_URI "@contains attack" "id:9731,phase:1,chain,deny,status:403"`,
		`SecRule REQUEST_METHOD "@streq GET" "id:9732,phase:1"`,
	}, nil)
	if response := serveTest(t, instance, httptestNewRequest("/disarm-attack")); response.Code != 200 {
		t.Fatalf("disarmed chain status = %d, want 200", response.Code)
	}
	if response := serveTest(t, instance, httptestNewRequest("/attack")); response.Code != 403 {
		t.Fatalf("intact chain status = %d, want 403", response.Code)
	}
}

func TestPMAndUrlDecodeUni(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule ARGS:q "@pm select union" "id:9712,phase:1,deny,status:403,t:urlDecodeUni,t:lowercase"`,
	}, nil)
	if response := serveTest(t, instance, httptestNewRequest("/?q=%53ELECT%20x")); response.Code != 403 {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

func TestSecRequestBodyLimitActionDirective(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRequestBodyLimit 10`,
		`SecRequestBodyLimitAction Reject`,
		`SecRule ARGS_POST:payload "@contains attack" "id:9713,phase:2,deny,status:403"`,
	}, nil)
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("payload=attack&more=data"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if response := serveTest(t, instance, request); response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", response.Code)
	}
}
