package core

import (
	"context"
	"time"
)

// Provider generates and verifies one visual challenge family. | Provider 生成并验证一个视觉挑战族。
//
// Providers receive only public request data in Generate and the server-side
// Record in Verify. Implementations must be safe for concurrent use and must
// never copy the expected answer into the public Challenge. | 生成器在 Generate 中只接收
// 公开请求数据，在 Verify 中接收服务端 Record。实现必须并发安全，且绝不能把预期答案
// 写入公开 Challenge。
type Provider interface {
	// Type returns the challenge family implemented by the provider. | Type 返回生成器实现的验证码族。
	Type() Type
	// Generate renders a new challenge and returns its opaque answer state. | Generate 渲染新挑战并返回不透明答案状态。
	Generate(ctx context.Context, req GenerateRequest) (*Generated, error)
	// Verify checks one answer against the stored record. | Verify 用已存储记录校验一次答案。
	Verify(ctx context.Context, rec *Record, ans Answer) (CheckResult, error)
}

// GenerateRequest carries the public generation inputs. | GenerateRequest 携带公开生成输入。
type GenerateRequest struct {
	// Now is the manager clock. | Now 是管理器时钟。
	Now time.Time
	// Locale is the normalized prompt locale. | Locale 是规范化后的提示语言。
	Locale string
	// Translate resolves a message key for Locale; nil providers use the fallback text. | Translate 为 Locale 解析消息键；nil 时使用回退文案。
	Translate func(key string, args ...string) string
	// Action is the bound host action. | Action 是绑定的宿主动作。
	Action string
	// Width is the desired image width. | Width 是期望图片宽度。
	Width int
	// Height is the desired image height. | Height 是期望图片高度。
	Height int
}

// localizedPrompt builds a prompt from Translate with English fallbacks. | localizedPrompt 用 Translate 和英文回退构建提示。
func localizedPrompt(req GenerateRequest, textKey, hintKey, fallbackText, fallbackHint string, args ...string) Prompt {
	text := fallbackText
	hint := fallbackHint
	if req.Translate != nil {
		if translated := req.Translate(textKey, args...); translated != "" {
			text = translated
		}
		if translated := req.Translate(hintKey); translated != "" {
			hint = translated
		}
	}
	return Prompt{Text: text, Hint: hint}
}

// Generated is one rendered challenge. | Generated 是一个已渲染挑战。
type Generated struct {
	// Prompt is the localized human instruction. | Prompt 是本地化人工指令。
	Prompt Prompt
	// Images is the image list. | Images 是图片列表。
	Images []ImageData
	// Answer is the opaque server-side answer state. | Answer 是不透明的服务端答案状态。
	Answer []byte
}

// ImageData is one rendered image before it reaches an ImageStore. | ImageData 是进入 ImageStore 前的一张已渲染图片。
type ImageData struct {
	// Name is the semantic image name. | Name 是语义图片名。
	Name string
	// MIME is the image media type. | MIME 是图片媒体类型。
	MIME string
	// Data is the encoded image. | Data 是编码后的图片。
	Data []byte
	// Width is the pixel width. | Width 是像素宽度。
	Width int
	// Height is the pixel height. | Height 是像素高度。
	Height int
}

// CheckResult is a provider verification result. | CheckResult 是生成器验证结果。
type CheckResult struct {
	// Reasons lists stable reason codes. | Reasons 列出稳定原因码。
	Reasons []string
	// BehaviorScore is a 0-100 risk contribution from the interaction. | BehaviorScore 是交互产生的 0-100 风险贡献。
	BehaviorScore int
	// Passed reports whether the answer satisfied the challenge. | Passed 报告答案是否满足挑战。
	Passed bool
}
