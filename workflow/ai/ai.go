// Package ai implements the optional large-model automatic-approval decider. It speaks the
// legacy OpenAI chat-completions API, the newer OpenAI Responses API and the Anthropic Claude
// Messages API. | Package ai 实现可选的大模型自动审批决策器，支持旧版 OpenAI chat-completions、
// 新版 OpenAI Responses 与 Anthropic Claude Messages 三种 API。
//
// The decider is constructed only when a project configures a base URL, a model and an API key;
// an unconfigured project gets nil and therefore performs no network request at all. A failed,
// timed-out or low-confidence call degrades to manual approval, never to an automatic pass. |
// 只有项目配置了 base URL、模型与 API Key 时才构造决策器；未配置的项目得到 nil，因此完全不发起网络
// 请求。失败、超时或低置信度的调用会退化为人工审批，绝不会自动放行。
package ai

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
	ydlog "github.com/shibingli/ydx/log"
	"github.com/shibingli/ydx/workflow"
)

// Sentinel errors. | 哨兵错误。
var (
	// ErrDisabled reports an incomplete configuration. | ErrDisabled 表示配置不完整。
	ErrDisabled = errs.New("workflow AI decider is disabled | 流程 AI 决策器未启用")
	// ErrRequest reports a failed HTTP call. | ErrRequest 表示 HTTP 调用失败。
	ErrRequest = errs.New("workflow AI request failed | 流程 AI 请求失败")
	// ErrResponse reports a malformed model response. | ErrResponse 表示模型响应格式非法。
	ErrResponse = errs.New("workflow AI response is invalid | 流程 AI 响应非法")
)

// Provider names. | 提供商名称。
const (
	// ProviderOpenAI is the legacy chat-completions API. | ProviderOpenAI 是旧版 chat-completions API。
	ProviderOpenAI = "openai"
	// ProviderOpenAIResponses is the newer Responses API. | ProviderOpenAIResponses 是较新的 Responses API。
	ProviderOpenAIResponses = "openai-responses"
	// ProviderAnthropic is the Claude Messages API. | ProviderAnthropic 是 Claude Messages API。
	ProviderAnthropic = "anthropic"
)

// Options configure the decider. | Options 配置决策器。
type Options struct {
	// Logger receives call failures; nil uses the default logger. | Logger 接收调用失败；nil 使用默认日志器。
	Logger *ydlog.Logger
	// Client overrides the HTTP client for tests. | Client 覆盖测试用 HTTP 客户端。
	Client *http.Client
	// Provider is openai, openai-responses or anthropic; empty infers it from BaseURL. |
	// Provider 取 openai、openai-responses 或 anthropic；空值根据 BaseURL 推断。
	Provider string
	// BaseURL is the API root or a full endpoint URL. | BaseURL 是 API 根或完整端点地址。
	BaseURL string
	// APIKey is the credential and is never logged. | APIKey 是凭据，绝不写入日志。
	APIKey string
	// Model is the model name. | Model 是模型名。
	Model string
	// APIVersion is the Anthropic version header; empty uses 2023-06-01. | APIVersion 是 Anthropic
	// 版本头；空值使用 2023-06-01。
	APIVersion string
	// SystemPrompt overrides the built-in instruction. | SystemPrompt 覆盖内置指令。
	SystemPrompt string
	// MaxTokens bounds the reply; zero uses 512. | MaxTokens 限制回复；零值使用 512。
	MaxTokens int
	// Timeout bounds one call. | Timeout 限制单次调用。
	Timeout time.Duration
	// MinConfidence is the minimum accepted confidence. | MinConfidence 是可接受的最低置信度。
	MinConfidence float64
	// Enabled turns the decider on. | Enabled 开启决策器。
	Enabled bool
}

// Decider is a multi-provider chat-completions decider. | Decider 是多提供商 chat-completions 决策器。
type Decider struct {
	// client is the HTTP client. | client 是 HTTP 客户端。
	client *http.Client
	// log records failures. | log 记录失败。
	log *ydlog.Logger
	// provider selects the request and response dialect. | provider 选择请求与响应方言。
	provider string
	// endpoint is the resolved API URL. | endpoint 是解析后的 API 地址。
	endpoint string
	// apiKey is the credential. | apiKey 是凭据。
	apiKey string
	// apiVersion is the Anthropic version header. | apiVersion 是 Anthropic 版本头。
	apiVersion string
	// model is the model name. | model 是模型名。
	model string
	// systemPrompt is the instruction sent to the model. | systemPrompt 是发送给模型的指令。
	systemPrompt string
	// maxTokens bounds the reply. | maxTokens 限制回复。
	maxTokens int
	// timeout bounds one call. | timeout 限制单次调用。
	timeout time.Duration
	// minConfidence is the minimum accepted confidence. | minConfidence 是可接受的最低置信度。
	minConfidence float64
}

// New builds a decider, or returns nil when the feature is off. | New 构建决策器；功能关闭时返回 nil。
func New(o Options) (*Decider, error) {
	if !o.Enabled {
		return nil, nil
	}
	baseURL := strings.TrimSpace(o.BaseURL)
	model := strings.TrimSpace(o.Model)
	apiKey := strings.TrimSpace(o.APIKey)
	if baseURL == "" || model == "" || apiKey == "" {
		return nil, ErrDisabled
	}
	provider := strings.ToLower(strings.TrimSpace(o.Provider))
	if provider == "" {
		lower := strings.ToLower(baseURL)
		if strings.Contains(lower, "anthropic") || strings.Contains(lower, "claude") {
			provider = ProviderAnthropic
		} else {
			provider = ProviderOpenAI
		}
	}
	endpoint, err := resolveEndpoint(provider, baseURL)
	if err != nil {
		return nil, err
	}
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}
	if o.MaxTokens <= 0 {
		o.MaxTokens = 512
	}
	if o.MinConfidence <= 0 || o.MinConfidence > 1 {
		o.MinConfidence = 0.7
	}
	apiVersion := strings.TrimSpace(o.APIVersion)
	if apiVersion == "" {
		apiVersion = "2023-06-01"
	}
	logger := o.Logger
	if logger == nil {
		logger = ydlog.Default()
	}
	client := o.Client
	if client == nil {
		client = &http.Client{Timeout: o.Timeout}
	}
	systemPrompt := strings.TrimSpace(o.SystemPrompt)
	if systemPrompt == "" {
		systemPrompt = defaultSystemPrompt
	}
	return &Decider{
		provider:      provider,
		endpoint:      endpoint,
		apiKey:        apiKey,
		apiVersion:    apiVersion,
		model:         model,
		maxTokens:     o.MaxTokens,
		timeout:       o.Timeout,
		minConfidence: o.MinConfidence,
		systemPrompt:  systemPrompt,
		client:        client,
		log:           logger,
	}, nil
}

// resolveEndpoint normalises the configured URL for one provider. | resolveEndpoint 为提供商规范化配置地址。
func resolveEndpoint(provider, baseURL string) (string, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	switch provider {
	case ProviderOpenAI:
		if !strings.HasSuffix(endpoint, "/chat/completions") {
			endpoint += "/chat/completions"
		}
	case ProviderOpenAIResponses:
		if !strings.HasSuffix(endpoint, "/responses") {
			endpoint += "/responses"
		}
	case ProviderAnthropic:
		if !strings.HasSuffix(endpoint, "/messages") {
			if strings.HasSuffix(endpoint, "/v1") {
				endpoint += "/messages"
			} else {
				endpoint += "/v1/messages"
			}
		}
	default:
		return "", errs.Detail(ErrDisabled, "unknown AI provider %[1]q | 未知的 AI 提供商 %[1]q", provider)
	}
	if !strings.HasPrefix(endpoint, "https://") && !strings.HasPrefix(endpoint, "http://") {
		return "", errs.Detail(ErrDisabled, "base_url must be an HTTP(S) endpoint | base_url 必须是 HTTP(S) 地址")
	}
	return endpoint, nil
}

// defaultSystemPrompt instructs the model to return strict JSON. | defaultSystemPrompt 指示模型返回严格 JSON。
const defaultSystemPrompt = "You are an enterprise approval assistant. Decide whether the pending approval should pass. " +
	"Reply with one JSON object only: {\"decision\":\"approve|reject\",\"reason\":\"short explanation\",\"confidence\":0.0}. " +
	"Use reject when the request violates policy, lacks information, or you are unsure." +
	" | 你是企业审批助手。判断待审批事项是否应通过。只回复一个 JSON 对象：" +
	"{\"decision\":\"approve|reject\",\"reason\":\"简短说明\",\"confidence\":0.0}。" +
	"违反制度、信息不足或无法确定时选择 reject。"

// chatRequest is the legacy OpenAI request body. | chatRequest 是旧版 OpenAI 请求体。
type chatRequest struct {
	Model          string         `json:"model"`
	ResponseFormat responseFormat `json:"response_format,omitempty"`
	Messages       []chatMessage  `json:"messages"`
	Temperature    float64        `json:"temperature"`
	MaxTokens      int            `json:"max_tokens,omitempty"`
}

// chatMessage is one message. | chatMessage 是一条消息。
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// responseFormat asks for a JSON object. | responseFormat 请求 JSON 对象。
type responseFormat struct {
	Type string `json:"type"`
}

// chatResponse is the legacy OpenAI response body. | chatResponse 是旧版 OpenAI 响应体。
type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

// responsesRequest is the OpenAI Responses API request body. | responsesRequest 是 OpenAI Responses API 请求体。
type responsesRequest struct {
	Model           string        `json:"model"`
	Instructions    string        `json:"instructions"`
	Input           string        `json:"input"`
	Text            responsesText `json:"text,omitempty"`
	Temperature     float64       `json:"temperature"`
	MaxOutputTokens int           `json:"max_output_tokens,omitempty"`
}

// responsesText wraps the response text format. | responsesText 包装响应文本格式。
type responsesText struct {
	Format responsesFormat `json:"format"`
}

// responsesFormat selects a JSON object. | responsesFormat 选择 JSON 对象。
type responsesFormat struct {
	Type string `json:"type"`
}

// responsesResponse is the OpenAI Responses API response body. | responsesResponse 是 OpenAI Responses API 响应体。
type responsesResponse struct {
	OutputText string `json:"output_text"`
	Output     []struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	} `json:"output"`
}

// anthropicMessage is one Claude message. | anthropicMessage 是一条 Claude 消息。
type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// anthropicRequest is the Claude Messages API request body. | anthropicRequest 是 Claude Messages API 请求体。
type anthropicRequest struct {
	Model       string             `json:"model"`
	System      string             `json:"system,omitempty"`
	Messages    []anthropicMessage `json:"messages"`
	MaxTokens   int                `json:"max_tokens"`
	Temperature float64            `json:"temperature"`
}

// anthropicResponse is the Claude Messages API response body. | anthropicResponse 是 Claude Messages API 响应体。
type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}

// decisionPayload is the JSON object the model must return. | decisionPayload 是模型必须返回的 JSON 对象。
type decisionPayload struct {
	Decision   string  `json:"decision"`
	Reason     string  `json:"reason"`
	Confidence float64 `json:"confidence"`
}

// Decide asks the model for one decision. | Decide 向模型请求一个决策。
func (d *Decider) Decide(ctx context.Context, in workflow.DecisionInput) (workflow.DecisionResult, error) {
	if d == nil {
		return workflow.DecisionResult{}, workflow.ErrAIUnavailable
	}
	prompt := buildPrompt(in)
	payload, err := d.request(prompt)
	if err != nil {
		return workflow.DecisionResult{}, err
	}
	callCtx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(callCtx, http.MethodPost, d.endpoint, bytes.NewReader(payload))
	if err != nil {
		return workflow.DecisionResult{}, errs.Wrap(err, ErrRequest)
	}
	request.Header.Set("Content-Type", "application/json")
	if d.provider == ProviderAnthropic {
		request.Header.Set("x-api-key", d.apiKey)
		request.Header.Set("anthropic-version", d.apiVersion)
	} else {
		request.Header.Set("Authorization", "Bearer "+d.apiKey)
	}
	response, err := d.client.Do(request)
	if err != nil {
		// The endpoint may embed credentials; the error is summarised without the URL. |
		// 端点可能含凭据；错误摘要不包含 URL。
		return workflow.DecisionResult{}, errs.Detail(ErrRequest, "request failed | 请求失败")
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return workflow.DecisionResult{}, errs.Wrap(err, ErrResponse)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return workflow.DecisionResult{}, errs.Detail(ErrRequest, "upstream status %[1]d | 上游状态 %[1]d", response.StatusCode)
	}
	content, err := extractContent(d.provider, data)
	if err != nil {
		return workflow.DecisionResult{}, err
	}
	content = stripCodeFence(content)
	var decision decisionPayload
	if err := json.Unmarshal([]byte(content), &decision); err != nil {
		return workflow.DecisionResult{}, errs.Wrap(err, ErrResponse)
	}
	normalized := normalizeDecision(decision.Decision)
	if normalized == "" {
		return workflow.DecisionResult{}, errs.Detail(ErrResponse, "decision value %[1]q is unknown | 决策值 %[1]q 未知", decision.Decision)
	}
	confidence := decision.Confidence
	if confidence <= 0 {
		confidence = 0.5
	}
	if confidence > 1 {
		confidence = 1
	}
	result := workflow.DecisionResult{
		Decision:   normalized,
		Reason:     strings.TrimSpace(decision.Reason),
		Confidence: confidence,
	}
	if confidence < d.minConfidence {
		return workflow.DecisionResult{Decision: workflow.DecisionNone, Reason: result.Reason, Confidence: confidence}, nil
	}
	return result, nil
}

// request renders the provider-specific request body. | request 渲染提供商相关的请求体。
func (d *Decider) request(prompt string) ([]byte, error) {
	var body any
	switch d.provider {
	case ProviderAnthropic:
		body = anthropicRequest{
			Model:       d.model,
			MaxTokens:   d.maxTokens,
			Temperature: 0,
			System:      d.systemPrompt,
			Messages:    []anthropicMessage{{Role: "user", Content: prompt}},
		}
	case ProviderOpenAIResponses:
		body = responsesRequest{
			Model:           d.model,
			Instructions:    d.systemPrompt,
			Input:           prompt,
			Temperature:     0,
			MaxOutputTokens: d.maxTokens,
			Text:            responsesText{Format: responsesFormat{Type: "json_object"}},
		}
	default:
		body = chatRequest{
			Model:          d.model,
			Messages:       []chatMessage{{Role: "system", Content: d.systemPrompt}, {Role: "user", Content: prompt}},
			Temperature:    0,
			MaxTokens:      d.maxTokens,
			ResponseFormat: responseFormat{Type: "json_object"},
		}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, errs.Wrap(err, ErrRequest)
	}
	return payload, nil
}

// extractContent reads the assistant text out of any supported response shape. |
// extractContent 从任一支持的响应形态中读取助手文本。
func extractContent(provider string, data []byte) (string, error) {
	switch provider {
	case ProviderAnthropic:
		var parsed anthropicResponse
		if err := json.Unmarshal(data, &parsed); err != nil {
			return "", errs.Wrap(err, ErrResponse)
		}
		for _, block := range parsed.Content {
			if block.Type == "text" && strings.TrimSpace(block.Text) != "" {
				return block.Text, nil
			}
		}
		return "", ErrResponse
	case ProviderOpenAIResponses:
		var parsed responsesResponse
		if err := json.Unmarshal(data, &parsed); err != nil {
			return "", errs.Wrap(err, ErrResponse)
		}
		if strings.TrimSpace(parsed.OutputText) != "" {
			return parsed.OutputText, nil
		}
		for _, item := range parsed.Output {
			for _, content := range item.Content {
				if content.Type == "output_text" && strings.TrimSpace(content.Text) != "" {
					return content.Text, nil
				}
			}
		}
		return "", ErrResponse
	default:
		var parsed chatResponse
		if err := json.Unmarshal(data, &parsed); err != nil || len(parsed.Choices) == 0 {
			return "", ErrResponse
		}
		return parsed.Choices[0].Message.Content, nil
	}
}

// buildPrompt renders the decision context for the model. | buildPrompt 为模型渲染决策上下文。
func buildPrompt(in workflow.DecisionInput) string {
	var b strings.Builder
	b.WriteString("Process: ")
	b.WriteString(in.Definition.Name)
	b.WriteString(" (")
	b.WriteString(in.Definition.Key)
	b.WriteString(")\nCategory: ")
	b.WriteString(in.Instance.Category)
	b.WriteString("\nInstance: ")
	b.WriteString(in.Instance.Title)
	b.WriteString("\nInitiator: ")
	b.WriteString(in.Instance.InitiatorName)
	if in.Node.Name != "" {
		b.WriteString("\nNode: ")
		b.WriteString(in.Node.Name)
	}
	if in.Rule.Prompt != "" {
		b.WriteString("\nPolicy: ")
		b.WriteString(in.Rule.Prompt)
	}
	if in.Node.AIPrompt != "" {
		b.WriteString("\nNode instruction: ")
		b.WriteString(in.Node.AIPrompt)
	}
	if len(in.Variables) > 0 {
		if data, err := json.Marshal(in.Variables); err == nil {
			b.WriteString("\nVariables: ")
			b.Write(data)
		}
	}
	b.WriteString("\nRespond with the JSON object only.")
	return b.String()
}

// stripCodeFence removes a Markdown code fence around a JSON object. | stripCodeFence 去掉包围 JSON 对象的 Markdown 代码围栏。
func stripCodeFence(content string) string {
	content = strings.TrimSpace(content)
	if strings.HasPrefix(content, "```") {
		if index := strings.IndexByte(content, '\n'); index >= 0 {
			content = content[index+1:]
		}
		content = strings.TrimSuffix(strings.TrimSpace(content), "```")
	}
	return strings.TrimSpace(content)
}

// normalizeDecision maps English and Chinese decision words onto the domain constants. |
// normalizeDecision 把中英文决策词映射到领域常量。
func normalizeDecision(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "approve", "approved", "pass", "passed", "通过", "同意":
		return workflow.DecisionApprove
	case "reject", "rejected", "deny", "denied", "驳回", "拒绝":
		return workflow.DecisionReject
	default:
		return ""
	}
}
