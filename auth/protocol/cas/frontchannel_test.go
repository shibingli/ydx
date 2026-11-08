package cas

import (
	"context"
	"errors"
	"html"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// frontChannelResolverFunc adapts a function to FrontChannelLogoutResolver. | frontChannelResolverFunc
// 把函数适配为 FrontChannelLogoutResolver。
type frontChannelResolverFunc func(ctx context.Context, service string) (string, bool)

// FrontChannelLogoutURL calls f. | FrontChannelLogoutURL 调用 f。
func (f frontChannelResolverFunc) FrontChannelLogoutURL(ctx context.Context, service string) (string, bool) {
	return f(ctx, service)
}

// staticRegistryOf returns the static registry backing server. | staticRegistryOf 返回支撑 server 的
// 静态注册表。
func staticRegistryOf(t *testing.T, server *Server) *StaticServiceRegistry {
	t.Helper()
	registry, ok := server.config.ServiceRegistry.(*StaticServiceRegistry)
	if !ok {
		t.Fatalf("ServiceRegistry type = %T, want *StaticServiceRegistry", server.config.ServiceRegistry)
	}
	return registry
}

// registerFrontChannel registers one front-channel logout URL and fails the test on error. |
// registerFrontChannel 登记一个前端登出 URL，出错时终止测试。
func registerFrontChannel(t *testing.T, registry *StaticServiceRegistry, service, logoutURL string) {
	t.Helper()
	if err := registry.SetFrontChannelLogoutURL(service, logoutURL); err != nil {
		t.Fatalf("SetFrontChannelLogoutURL(%q, %q): %v", service, logoutURL, err)
	}
}

// TestFrontChannelLogoutPageRendersRegisteredServices covers multi-service browser logout. |
// TestFrontChannelLogoutPageRendersRegisteredServices 覆盖多服务浏览器登出。
func TestFrontChannelLogoutPageRendersRegisteredServices(t *testing.T) {
	firstService, firstReceiver := newLogoutReceiver(t, http.StatusOK, 0)
	secondService, secondReceiver := newLogoutReceiver(t, http.StatusOK, 0)
	server, registry, store, _ := newSLOServer(t, []string{firstService.URL, secondService.URL})
	static := staticRegistryOf(t, server)
	firstFront := firstService.URL + "/front-channel/logout?sid=1&next=home"
	secondFront := secondService.URL + "/logout"
	registerFrontChannel(t, static, firstService.URL, firstFront)
	registerFrontChannel(t, static, secondService.URL, secondFront)
	handler := newTestRouter(t, server)
	cookie, firstST := loginAndTicket(t, handler, firstService.URL)
	tgt, err := store.Get(t.Context(), cookie.Value)
	if err != nil {
		t.Fatalf("load TGT: %v", err)
	}
	secondST, err := server.issueTicket(t.Context(), TicketST, testPrincipal(), "user-1", secondService.URL, tgt, server.config.ServiceTicketTimeout, false, false)
	if err != nil {
		t.Fatalf("issue second ST: %v", err)
	}
	if registry.Len() != 2 {
		t.Fatalf("sessions = %d, want 2", registry.Len())
	}
	recorder := serve(t, handler, http.MethodGet, "/cas/logout", nil, cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if got := strings.Count(body, "<iframe"); got != 2 {
		t.Fatalf("iframe count = %d, want 2; body: %s", got, body)
	}
	for _, want := range []string{html.EscapeString(firstFront), html.EscapeString(secondFront)} {
		if !strings.Contains(body, want) {
			t.Fatalf("body has no escaped front-channel URL %q: %s", want, body)
		}
	}
	if contentType := recorder.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Fatalf("Content-Type = %q", contentType)
	}
	if recorder.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("X-Frame-Options = %q", recorder.Header().Get("X-Frame-Options"))
	}
	if policy := recorder.Header().Get("Content-Security-Policy"); !strings.Contains(policy, "frame-src") {
		t.Fatalf("Content-Security-Policy = %q, want frame-src", policy)
	}
	if registry.Len() != 0 {
		t.Fatalf("sessions survived logout: %d", registry.Len())
	}
	for _, id := range []string{firstST, secondST.ID} {
		if _, err := store.Get(t.Context(), id); !errors.Is(err, ErrTicketNotFound) {
			t.Fatalf("ticket %q survived logout: %v", id, err)
		}
	}
	if firstReceiver.count() != 1 || secondReceiver.count() != 1 {
		t.Fatalf("back-channel deliveries = %d/%d, want 1/1", firstReceiver.count(), secondReceiver.count())
	}
}

// TestFrontChannelLogoutTargets covers target validation, unregistered URLs and fallback redirects. |
// TestFrontChannelLogoutTargets 覆盖目标校验、未注册 URL 与回退重定向。
func TestFrontChannelLogoutTargets(t *testing.T) {
	service, _ := newLogoutReceiver(t, http.StatusOK, 0)
	server, _, _, _ := newSLOServer(t, []string{service.URL})
	static := staticRegistryOf(t, server)
	front := service.URL + "/front-logout"
	registerFrontChannel(t, static, service.URL, front)
	handler := newTestRouter(t, server)

	if _, ok := static.FrontChannelLogoutURL(t.Context(), "https://unknown.example"); ok {
		t.Fatal("unknown service reported a front-channel URL")
	}
	if err := static.SetFrontChannelLogoutURL("https://unknown.example", front); !errors.Is(err, ErrServiceNotRegistered) {
		t.Fatalf("unregistered service err = %v, want ErrServiceNotRegistered", err)
	}
	if err := static.SetFrontChannelLogoutURL(service.URL, "javascript:alert(1)"); !errors.Is(err, ErrInvalidService) {
		t.Fatalf("script URL err = %v, want ErrInvalidService", err)
	}
	var nilRegistry *StaticServiceRegistry
	if err := nilRegistry.SetFrontChannelLogoutURL(service.URL, front); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil registry err = %v, want ErrInvalidConfig", err)
	}

	cookie, _ := loginAndTicket(t, handler, service.URL)
	target := "/cas/logout?service=" + url.QueryEscape(service.URL)
	recorder := serve(t, handler, http.MethodGet, target, nil, cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if !strings.Contains(body, `href="`+html.EscapeString(service.URL)+`"`) {
		t.Fatalf("body has no escaped continue link to %q: %s", service.URL, body)
	}
	evil := "https://evil.example/steal"
	cookie, _ = loginAndTicket(t, handler, service.URL)
	recorder = serve(t, handler, http.MethodGet, "/cas/logout?service="+url.QueryEscape(evil), nil, cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("unregistered target status = %d, want 200", recorder.Code)
	}
	if location := recorder.Header().Get("Location"); location != "" {
		t.Fatalf("unregistered target redirected to %q", location)
	}
	if strings.Contains(recorder.Body.String(), "evil.example") {
		t.Fatalf("unregistered target leaked into the page: %s", recorder.Body.String())
	}

	// A resolver that returns a non-http URL must not turn into a frame or a redirect. | 返回非
	// http URL 的校验器不得变成框架或重定向。
	rogue, _, _, _ := newSLOServer(t, []string{service.URL}, func(config *ServerConfig) {
		config.FrontChannelLogoutResolver = frontChannelResolverFunc(func(context.Context, string) (string, bool) {
			return "javascript:alert(1)", true
		})
	})
	rogueHandler := newTestRouter(t, rogue)
	rogueCookie, _ := loginAndTicket(t, rogueHandler, service.URL)
	recorder = serve(t, rogueHandler, http.MethodGet, "/cas/logout", nil, rogueCookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("rogue resolver status = %d, want 200", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "javascript:") || strings.Contains(recorder.Body.String(), "<iframe") {
		t.Fatalf("rogue resolver injected a frame: %s", recorder.Body.String())
	}
	if location := recorder.Header().Get("Location"); location != "" {
		t.Fatalf("rogue resolver redirected to %q", location)
	}

	// Without any front-channel URL the registered target is still redirected immediately. | 没有
	// 前端登出 URL 时，已注册目标仍立即重定向。
	plain, _, _, _ := newSLOServer(t, []string{service.URL})
	plainHandler := newTestRouter(t, plain)
	plainCookie, _ := loginAndTicket(t, plainHandler, service.URL)
	recorder = serve(t, plainHandler, http.MethodGet, target, nil, plainCookie)
	if recorder.Code != http.StatusFound || recorder.Header().Get("Location") != service.URL {
		t.Fatalf("plain redirect = %d %q, want 302 %q", recorder.Code, recorder.Header().Get("Location"), service.URL)
	}
}

// TestFrontChannelLogoutPageEscapesHTML covers attribute and link escaping. |
// TestFrontChannelLogoutPageEscapesHTML 覆盖属性与链接转义。
func TestFrontChannelLogoutPageEscapesHTML(t *testing.T) {
	// net/url accepts angle brackets in the query, so this URL exercises escaping of a raw script
	// payload. | net/url 接受查询中的尖括号，因此该 URL 能检验原始脚本载荷的转义。
	service := `https://app.example.com/callback?x=<script>alert(1)</script>`
	server, _, _, _ := newSLOServer(t, []string{service})
	static := staticRegistryOf(t, server)
	front := `https://app.example.com/front-logout?x=<script>alert(1)</script>&y=2`
	registerFrontChannel(t, static, service, front)
	handler := newTestRouter(t, server)
	cookie, _ := loginAndTicket(t, handler, service)
	recorder := serve(t, handler, http.MethodGet, "/cas/logout?service="+url.QueryEscape(service), nil, cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if strings.Contains(body, "<script>") {
		t.Fatalf("raw script payload survived escaping: %s", body)
	}
	for _, want := range []string{"&lt;script&gt;", "&amp;y=2", html.EscapeString(service)} {
		if !strings.Contains(body, want) {
			t.Fatalf("body has no %q: %s", want, body)
		}
	}
}

// TestFrontChannelLogoutServiceLimit covers the frame cap. | TestFrontChannelLogoutServiceLimit 覆盖
// 框架数量上限。
func TestFrontChannelLogoutServiceLimit(t *testing.T) {
	first, _ := newLogoutReceiver(t, http.StatusOK, 0)
	second, _ := newLogoutReceiver(t, http.StatusOK, 0)
	third, _ := newLogoutReceiver(t, http.StatusOK, 0)
	services := []string{first.URL, second.URL, third.URL}
	server, registry, store, _ := newSLOServer(t, services, func(config *ServerConfig) {
		config.MaxFrontChannelLogoutServices = 2
	})
	static := staticRegistryOf(t, server)
	for _, service := range services {
		registerFrontChannel(t, static, service, service+"/front-logout")
	}
	handler := newTestRouter(t, server)
	cookie, _ := loginAndTicket(t, handler, first.URL)
	tgt, err := store.Get(t.Context(), cookie.Value)
	if err != nil {
		t.Fatalf("load TGT: %v", err)
	}
	for _, service := range services[1:] {
		if _, err := server.issueTicket(t.Context(), TicketST, testPrincipal(), "user-1", service, tgt, server.config.ServiceTicketTimeout, false, false); err != nil {
			t.Fatalf("issue ST for %s: %v", service, err)
		}
	}
	if registry.Len() != 3 {
		t.Fatalf("sessions = %d, want 3", registry.Len())
	}
	recorder := serve(t, handler, http.MethodGet, "/cas/logout", nil, cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if got := strings.Count(recorder.Body.String(), "<iframe"); got != 2 {
		t.Fatalf("iframe count = %d, want 2; body: %s", got, recorder.Body.String())
	}
}

// TestFrontChannelLogoutConcurrentUsers covers concurrent browser logouts of independent users. |
// TestFrontChannelLogoutConcurrentUsers 覆盖独立用户的并发浏览器登出。
func TestFrontChannelLogoutConcurrentUsers(t *testing.T) {
	aliceService, aliceReceiver := newLogoutReceiver(t, http.StatusOK, 0)
	bobService, bobReceiver := newLogoutReceiver(t, http.StatusOK, 0)
	server, _, _, _ := newSLOServer(t, []string{aliceService.URL, bobService.URL})
	static := staticRegistryOf(t, server)
	aliceFront := aliceService.URL + "/front-logout?user=alice"
	bobFront := bobService.URL + "/front-logout?user=bob"
	registerFrontChannel(t, static, aliceService.URL, aliceFront)
	registerFrontChannel(t, static, bobService.URL, bobFront)
	handler := newTestRouter(t, server)

	aliceCookie, _ := loginAndTicket(t, handler, aliceService.URL)
	bobRecorder := loginForm(t, handler, "bob", "secret", bobService.URL, nil)
	if bobRecorder.Code != http.StatusFound {
		t.Fatalf("bob login status = %d", bobRecorder.Code)
	}
	bobCookie := tgcFrom(t, bobRecorder)

	bodies := make([]string, 2)
	codes := make([]int, 2)
	var wg sync.WaitGroup
	for index, cookie := range []*http.Cookie{aliceCookie, bobCookie} {
		wg.Add(1)
		go func(index int, cookie *http.Cookie) {
			defer wg.Done()
			recorder := serve(t, handler, http.MethodGet, "/cas/logout", nil, cookie)
			bodies[index] = recorder.Body.String()
			codes[index] = recorder.Code
		}(index, cookie)
	}
	wg.Wait()
	for index, code := range codes {
		if code != http.StatusOK {
			t.Fatalf("logout %d status = %d, want 200", index, code)
		}
	}
	if !strings.Contains(bodies[0], html.EscapeString(aliceFront)) || strings.Contains(bodies[0], html.EscapeString(bobFront)) {
		t.Fatalf("alice page mixed services: %s", bodies[0])
	}
	if !strings.Contains(bodies[1], html.EscapeString(bobFront)) || strings.Contains(bodies[1], html.EscapeString(aliceFront)) {
		t.Fatalf("bob page mixed services: %s", bodies[1])
	}
	if aliceReceiver.count() != 1 || bobReceiver.count() != 1 {
		t.Fatalf("back-channel deliveries = %d/%d, want 1/1", aliceReceiver.count(), bobReceiver.count())
	}
}
