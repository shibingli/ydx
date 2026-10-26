package core

import (
	"context"
	"time"
)

// Message is one code delivery request handed to a Sender plugin. | Message 是交给 Sender 插件的一次验证码投递请求。
type Message struct {
	// Data is optional provider template data. | Data 是可选供应商模板变量。
	Data map[string]string
	// Channel is the delivery channel. | Channel 是下发通道。
	Channel Channel
	// To is the full phone number or email address. | To 是完整手机号或邮箱地址。
	To string
	// Code is the plaintext one-time code. | Code 是明文一次性验证码。
	Code string
	// Action is the host action. | Action 是宿主动作。
	Action string
	// Locale is the requested locale. | Locale 是请求语言。
	Locale string
	// Template is an optional provider template identifier. | Template 是可选供应商模板标识。
	Template string
	// ExpiresIn is the remaining validity of the code. | ExpiresIn 是验证码剩余有效期。
	ExpiresIn time.Duration
}

// Sender delivers one-time codes for one channel. | Sender 为一个通道投递一次性验证码。
//
// Implementations must be safe for concurrent use. | 实现必须并发安全。
type Sender interface {
	// Channel reports the channel this sender implements. | Channel 返回该发送器实现的通道。
	Channel() Channel
	// Send delivers one message. | Send 投递一条消息。
	Send(ctx context.Context, msg Message) error
}

// SenderFunc adapts a function to Sender. | SenderFunc 把函数适配为 Sender。
type SenderFunc struct {
	// Fn is the delivery function. | Fn 是投递函数。
	Fn func(ctx context.Context, msg Message) error
	// Ch is the channel implemented by Fn. | Ch 是 Fn 实现的通道。
	Ch Channel
}

// Channel implements Sender. | Channel 实现 Sender。
func (f SenderFunc) Channel() Channel { return f.Ch }

// Send implements Sender. | Send 实现 Sender。
func (f SenderFunc) Send(ctx context.Context, msg Message) error {
	if f.Fn == nil {
		return ErrNoSender
	}
	return f.Fn(ctx, msg)
}
