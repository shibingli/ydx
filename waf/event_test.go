package waf

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// TestEventMatchesBounded pins the event-match memory bound for multiMatch rules. |
// TestEventMatchesBounded 固定多值规则的日志事件内存上限。
func TestEventMatchesBounded(t *testing.T) {
	var matched int
	instance := newTestWAF(t, []string{
		`SecRule ARGS:q "@rx .*" "id:9500,phase:2,pass,log,multiMatch"`,
	}, func(options *Options) {
		options.Observer = func(event Event) {
			matched = len(event.Matches)
		}
	})
	var query strings.Builder
	for index := 0; index < maxEventMatches+64; index++ {
		fmt.Fprintf(&query, "q=v%d&", index)
	}
	response := serveTest(t, instance, httptestNewRequest("/?"+strings.TrimSuffix(query.String(), "&")))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if matched != maxEventMatches {
		t.Fatalf("event matches = %d, want %d", matched, maxEventMatches)
	}
}
