package waf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNamesKeySelectors pins exact-key matching on the *_NAMES collections. | TestNamesKeySelectors
// 固定 *_NAMES 集合上的精确键匹配。
func TestNamesKeySelectors(t *testing.T) {
	t.Run("args", func(t *testing.T) {
		instance := newTestWAF(t, []string{
			`SecRule ARGS_NAMES:q "@streq q" "id:9401,phase:2,deny,status:403"`,
		}, nil)
		response := serveTest(t, instance, httptestNewRequest("/?q=hello"))
		if response.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", response.Code)
		}
	})
	t.Run("headers", func(t *testing.T) {
		instance := newTestWAF(t, []string{
			`SecRule REQUEST_HEADERS_NAMES:X-Test "@streq X-Test" "id:9402,phase:1,deny,status:403"`,
		}, nil)
		request := httptestNewRequest("/")
		request.Header.Set("X-Test", "yes")
		response := serveTest(t, instance, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", response.Code)
		}
	})
	t.Run("cookies", func(t *testing.T) {
		instance := newTestWAF(t, []string{
			`SecRule REQUEST_COOKIES_NAMES:sid "@streq sid" "id:9403,phase:1,deny,status:403"`,
		}, nil)
		request := httptestNewRequest("/")
		request.Header.Set("Cookie", "sid=abc")
		response := serveTest(t, instance, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", response.Code)
		}
	})
}

// TestNamesExclusion verifies ARGS_NAMES exclusions cover GET and POST name values. |
// TestNamesExclusion 验证 ARGS_NAMES 排除项覆盖 GET 与 POST 的名称取值。
func TestNamesExclusion(t *testing.T) {
	directives := []string{
		`SecRule ARGS_NAMES "@rx ^(q|keep)$" "id:9410,phase:2,deny,status:403"`,
		`SecRuleUpdateTargetById 9410 "!ARGS_NAMES:q"`,
	}
	instance := newTestWAF(t, directives, nil)
	if response := serveTest(t, instance, httptestNewRequest("/?q=hello")); response.Code != http.StatusOK {
		t.Fatalf("excluded name status = %d, want 200", response.Code)
	}
	if response := serveTest(t, instance, httptestNewRequest("/?q=hello&keep=1")); response.Code != http.StatusForbidden {
		t.Fatalf("kept name status = %d, want 403", response.Code)
	}
}

// TestKeyedSelectorMultipleValues verifies all matching values still reach the operator when the
// allocation-free path cannot answer with one value. | TestKeyedSelectorMultipleValues 验证无分配
// 路径无法用单值回答时，所有命中取值仍会进入算子。
func TestKeyedSelectorMultipleValues(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule ARGS:q "@streq b" "id:9420,phase:2,deny,status:403"`,
	}, nil)
	response := serveTest(t, instance, httptestNewRequest("/?q=a&q=b"))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

// TestKeyedSelectorCount verifies counted key selectors do not need a filtered slice. |
// TestKeyedSelectorCount 验证计数键选择器无需过滤切片。
func TestKeyedSelectorCount(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule "&ARGS:q" "@eq 2" "id:9421,phase:2,deny,status:403"`,
	}, nil)
	response := serveTest(t, instance, httptestNewRequest("/?q=a&q=b"))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

// TestArgsCombinedSizeCacheInvalidatedByBody verifies a phase-1 read does not cache a body-less
// ARGS_COMBINED_SIZE for phase 2. | TestArgsCombinedSizeCacheInvalidatedByBody 验证阶段 1 的读取
// 不会让阶段 2 继续使用不含正文的 ARGS_COMBINED_SIZE 缓存。
func TestArgsCombinedSizeCacheInvalidatedByBody(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule ARGS_COMBINED_SIZE "@gt 1000" "id:9422,phase:1,pass,nolog"`,
		`SecRule ARGS_COMBINED_SIZE "@gt 10" "id:9423,phase:2,deny,status:403"`,
	}, nil)
	request := httptest.NewRequest(http.MethodPost, "/?q=hello", strings.NewReader("payload=attack"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := serveTest(t, instance, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; combined size cache was not invalidated", response.Code)
	}
}
