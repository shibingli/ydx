package ai_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/workflow"
	"github.com/shibingli/ydx/workflow/ai"
)

// decisionInput builds one representative decision context. | decisionInput 构建一个代表性决策上下文。
func decisionInput() workflow.DecisionInput {
	return workflow.DecisionInput{
		TenantID: "tn_test",
		Definition: workflow.Definition{
			Key: "leave", Name: "请假",
		},
		Instance: workflow.Instance{
			Title: "年假申请", Category: "leave", InitiatorName: "Alice",
		},
		Variables: map[string]any{"days": 3, "reason": "family"},
	}
}

// TestOpenAIProviders covers the legacy and Responses dialects. | TestOpenAIProviders 覆盖旧版与 Responses 方言。
func TestOpenAIProviders(t *testing.T) {
	cases := []struct {
		name     string
		provider string
		path     string
		response string
	}{
		{
			name: "chat-completions", provider: ai.ProviderOpenAI, path: "/chat/completions",
			response: `{"choices":[{"message":{"content":"{\"decision\":\"approve\",\"reason\":\"ok\",\"confidence\":0.9}"}}]}`,
		},
		{
			name: "responses-output-text", provider: ai.ProviderOpenAIResponses, path: "/responses",
			response: `{"output_text":"{\"decision\":\"reject\",\"reason\":\"no\",\"confidence\":0.8}"}`,
		},
		{
			name: "responses-output", provider: ai.ProviderOpenAIResponses, path: "/responses",
			response: `{"output":[{"content":[{"type":"output_text","text":"{\"decision\":\"approve\",\"reason\":\"nested\",\"confidence\":0.95}"}]}]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var requestBody []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.path {
					t.Errorf("请求路径 = %s, 期望 %s", r.URL.Path, tc.path)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
					t.Errorf("Authorization = %q", got)
				}
				requestBody, _ = io.ReadAll(r.Body)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.response))
			}))
			defer server.Close()
			decider, err := ai.New(ai.Options{
				Enabled: true, Provider: tc.provider, BaseURL: server.URL,
				APIKey: "test-key", Model: "test-model", Client: server.Client(), Timeout: time.Second,
			})
			if err != nil {
				t.Fatalf("构造决策器失败: %v", err)
			}
			result, err := decider.Decide(context.Background(), decisionInput())
			if err != nil {
				t.Fatalf("决策失败: %v", err)
			}
			if result.Decision != workflow.DecisionApprove && result.Decision != workflow.DecisionReject {
				t.Fatalf("决策结果 = %+v", result)
			}
			if len(requestBody) == 0 || !strings.Contains(string(requestBody), "test-model") {
				t.Fatalf("请求体 = %s", requestBody)
			}
		})
	}
}

// TestAnthropicProvider covers the Claude Messages API. | TestAnthropicProvider 覆盖 Claude Messages API。
func TestAnthropicProvider(t *testing.T) {
	var requestBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Errorf("请求路径 = %s", r.URL.Path)
		}
		if got := r.Header.Get("x-api-key"); got != "claude-key" {
			t.Errorf("x-api-key = %q", got)
		}
		if got := r.Header.Get("anthropic-version"); got == "" {
			t.Error("缺少 anthropic-version")
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Anthropic 请求不应发送 Authorization: %q", got)
		}
		requestBody, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"{\"decision\":\"通过\",\"reason\":\"符合制度\",\"confidence\":0.88}"}]}`))
	}))
	defer server.Close()
	decider, err := ai.New(ai.Options{
		Enabled: true, Provider: ai.ProviderAnthropic, BaseURL: server.URL,
		APIKey: "claude-key", Model: "claude-sonnet-5-5", Client: server.Client(), Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("构造 Claude 决策器失败: %v", err)
	}
	result, err := decider.Decide(context.Background(), decisionInput())
	if err != nil {
		t.Fatalf("Claude 决策失败: %v", err)
	}
	if result.Decision != workflow.DecisionApprove || result.Confidence != 0.88 {
		t.Fatalf("Claude 决策 = %+v", result)
	}
	if !strings.Contains(string(requestBody), "max_tokens") || !strings.Contains(string(requestBody), "system") {
		t.Fatalf("Claude 请求体 = %s", requestBody)
	}
}

// TestAIFailureModes covers low confidence, malformed replies and HTTP failures. |
// TestAIFailureModes 覆盖低置信度、非法响应与 HTTP 失败。
func TestAIFailureModes(t *testing.T) {
	responses := map[string]http.HandlerFunc{
		"low": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"decision\":\"approve\",\"reason\":\"unsure\",\"confidence\":0.2}"}}]}`))
		},
		"invalid-json": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"not json"}}]}`))
		},
		"unknown-decision": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"decision\":\"maybe\",\"confidence\":0.9}"}}]}`))
		},
		"status-500": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		},
	}
	for name, handler := range responses {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(handler)
			defer server.Close()
			decider, err := ai.New(ai.Options{
				Enabled: true, Provider: ai.ProviderOpenAI, BaseURL: server.URL,
				APIKey: "k", Model: "m", Client: server.Client(), Timeout: time.Second, MinConfidence: 0.7,
			})
			if err != nil {
				t.Fatalf("构造决策器失败: %v", err)
			}
			result, err := decider.Decide(context.Background(), decisionInput())
			switch name {
			case "low":
				if err != nil || result.Decision != workflow.DecisionNone {
					t.Fatalf("低置信度结果 = %+v, %v", result, err)
				}
			default:
				if err == nil {
					t.Fatalf("%s 应返回错误，实际 = %+v", name, result)
				}
				if !errors.Is(err, ai.ErrResponse) && !errors.Is(err, ai.ErrRequest) {
					t.Fatalf("%s 错误 = %v", name, err)
				}
			}
		})
	}
}

// TestAIDisabledAndEndpointResolution covers construction and URL normalisation. |
// TestAIDisabledAndEndpointResolution 覆盖构造与地址规范化。
func TestAIDisabledAndEndpointResolution(t *testing.T) {
	decider, err := ai.New(ai.Options{Enabled: false})
	if err != nil || decider != nil {
		t.Fatalf("关闭状态 = %v, %v", decider, err)
	}
	if _, err := ai.New(ai.Options{Enabled: true}); !errors.Is(err, ai.ErrDisabled) {
		t.Fatalf("缺少配置错误 = %v", err)
	}
	paths := []struct {
		provider string
		base     string
		want     string
	}{
		{ai.ProviderOpenAI, "https://example.com", "/chat/completions"},
		{ai.ProviderOpenAIResponses, "https://example.com/v1", "/v1/responses"},
		{ai.ProviderAnthropic, "https://example.com", "/v1/messages"},
		{ai.ProviderAnthropic, "https://example.com/v1", "/v1/messages"},
	}
	for _, tc := range paths {
		var gotPath string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"decision\":\"approve\",\"confidence\":0.9}"}}]}`))
		}))
		base := tc.base
		if strings.Contains(base, "example.com") {
			base = server.URL + strings.TrimPrefix(tc.base, "https://example.com")
		}
		decider, err := ai.New(ai.Options{Enabled: true, Provider: tc.provider, BaseURL: base, APIKey: "k", Model: "m", Client: server.Client(), Timeout: time.Second})
		if err != nil {
			server.Close()
			t.Fatalf("构造失败: %v", err)
		}
		_, _ = decider.Decide(context.Background(), decisionInput())
		server.Close()
		if gotPath != tc.want {
			t.Fatalf("%s 路径 = %s, 期望 %s", tc.provider, gotPath, tc.want)
		}
	}
}
