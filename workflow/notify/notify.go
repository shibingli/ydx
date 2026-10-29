// Package notify provides the built-in notification channels of the workflow engine.
//
// Webhook covers WeCom, DingTalk, Feishu and a generic JSON POST; SMTP covers TLS and STARTTLS delivery;
// LogChannel writes notifications to the framework logger for development. Every channel implements
// workflow.Channel and is delivered through the outbox, so a failed delivery never rolls back an approval.
// | Package notify 提供流程引擎内置的通知渠道。
//
// Webhook 覆盖企业微信、钉钉、飞书与通用 JSON POST；SMTP 覆盖 TLS 与 STARTTLS 投递；LogChannel 把通知
// 写入框架日志，供开发期使用。每个渠道都实现 workflow.Channel，并通过 outbox 投递，因此投递失败绝不会
// 回滚审批事务。
package notify
