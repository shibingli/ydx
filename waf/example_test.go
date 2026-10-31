package waf_test

import (
	"net/http"
	"time"

	"github.com/shibingli/ydx/router"
	"github.com/shibingli/ydx/waf"
)

// ExampleNew shows the native net/http entry point. | ExampleNew 展示原生 net/http 入口。
func ExampleNew() {
	engine, err := waf.New(waf.Options{
		Directives: []string{
			`SecRule REQUEST_URI "@contains /etc/passwd" "id:9001,phase:1,deny,status:403,msg:'path traversal'"`,
			`SecRule ARGS "@detectSQLi" "id:9002,phase:2,deny,status:403,t:urlDecodeUni,t:lowercase"`,
		},
	})
	if err != nil {
		return
	}
	defer func() { _ = engine.Close() }()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	_ = http.ListenAndServe(":8080", engine.HTTPMiddleware(mux))
}

// ExampleWAF_Middleware shows the YD router entry point. | ExampleWAF_Middleware 展示 YD 路由入口。
func ExampleWAF_Middleware() {
	engine, err := waf.New(waf.Options{
		Directives: []string{
			`SecRule REQUEST_URI "@contains /admin" "id:9010,phase:1,deny,status:403"`,
		},
	})
	if err != nil {
		return
	}
	defer func() { _ = engine.Close() }()

	r := router.New()
	r.Use(engine.Middleware())
	r.GET("/admin", func(c *router.Ctx) {
		c.String(http.StatusOK, "admin")
	})
}

// ExampleWAF_ApplyBundle shows an externally pushed rule bundle. | ExampleWAF_ApplyBundle 展示外部
// 推送的规则包。
func ExampleWAF_ApplyBundle() {
	engine, err := waf.New(waf.Options{
		Directives: []string{`SecRule REQUEST_URI "@contains seed" "id:9020,phase:1,deny"`},
	})
	if err != nil {
		return
	}
	defer func() { _ = engine.Close() }()

	bundle := &waf.Bundle{
		Version: "2026-10-31",
		Data:    []byte(`SecRule REQUEST_URI "@contains pushed" "id:9021,phase:1,deny,status:403"`),
	}
	_ = engine.ApplyBundle(bundle)
}

// ExampleAlertConfig shows email alerting with anti-storm limits. | ExampleAlertConfig 展示带防轰炸
// 限制的邮件报警。
func ExampleAlertConfig() {
	_, err := waf.New(waf.Options{
		Directives: []string{`SecRule REQUEST_URI "@contains attack" "id:9030,phase:1,deny,status:403"`},
		Alerting: waf.AlertConfig{
			Enabled:     true,
			MinSeverity: "WARNING",
			Threshold:   5,
			Window:      time.Minute,
			Cooldown:    10 * time.Minute,
			MinInterval: 30 * time.Second,
			MaxPerHour:  10,
			MaxPerDay:   50,
			NodeID:      "edge-01",
			Email: &waf.EmailConfig{
				Host:     "smtp.example.com",
				Port:     587,
				Username: "waf",
				Password: "test-only-password",
				From:     "waf@example.com",
				To:       []string{"security@example.com"},
			},
		},
	})
	_ = err
}

// ExampleWASMPluginConfig shows a WASM plugin subscription. | ExampleWASMPluginConfig 展示 WASM
// 插件订阅。
func ExampleWASMPluginConfig() {
	config := waf.WASMPluginConfig{
		Name:         "custom-scoring",
		Path:         "plugins/scoring.wasm",
		Timeout:      20 * time.Millisecond,
		MaxInstances: 16,
		FailClosed:   false,
		Points:       []waf.HookPoint{waf.HookRuleMatch, waf.HookBeforePhase},
	}
	_ = config
}

// ExampleWAF_HTTPMiddleware shows request filtering around any handler.
// | ExampleWAF_HTTPMiddleware 展示围绕任意处理器的请求过滤。
func ExampleWAF_HTTPMiddleware() {
	engine, err := waf.New(waf.Options{
		Directives: []string{
			`SecRule REQUEST_METHOD "@rx ^(TRACE|TRACK)$" "id:9040,phase:1,deny,status:405"`,
		},
	})
	if err != nil {
		return
	}
	defer func() { _ = engine.Close() }()

	handler := engine.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	_ = handler
}
