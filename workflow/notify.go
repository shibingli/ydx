package workflow

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// normalizeNotificationOptions fills notification defaults. | normalizeNotificationOptions 补齐通知默认值。
func normalizeNotificationOptions(o NotificationOptions) NotificationOptions {
	d := DefaultOptions()
	if strings.TrimSpace(o.Lang) == "" {
		o.Lang = "zh-CN"
	}
	if o.Timeout <= 0 {
		o.Timeout = d.NotificationTimeout
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = d.NotificationRetry
	}
	if o.RetryDelay <= 0 {
		o.RetryDelay = time.Minute
	}
	return o
}

// NotificationOptions tune notification rendering and delivery. | NotificationOptions 调整通知渲染与投递。
type NotificationOptions struct {
	// Lang is the preferred language of the notification body ("zh-CN" or "en"). | Lang 是通知正文的首选语言
	//（zh-CN 或 en）。
	Lang string
	// BaseURL prefixes deep links, for example "https://example.com". | BaseURL 为深链加前缀，例如
	// "https://example.com"。
	BaseURL string
	// Events limits which notification kinds are produced; empty means every kind. | Events
	// 限定产生的通知类型；空表示全部。
	Events []string
	// Timeout bounds one dispatch batch. | Timeout 限制一次投递批次。
	Timeout time.Duration
	// MaxAttempts bounds retries of one notification. | MaxAttempts 限制单条通知的重试次数。
	MaxAttempts int
	// RetryDelay is the base backoff between attempts. | RetryDelay 是两次尝试之间的基础退避。
	RetryDelay time.Duration
}

// Dispatcher fans one notification out to every configured channel. A failing channel never
// prevents the others from running. | Dispatcher 把一条通知扇出到全部已配置渠道。单个渠道失败
// 绝不会阻止其它渠道执行。
type Dispatcher struct {
	// channels is the ordered channel list. | channels 是有序渠道列表。
	channels []Channel
	// timeout bounds one channel call. | timeout 限制单次渠道调用。
	timeout time.Duration
}

// NewDispatcher builds a dispatcher. Empty channels make Send a no-op that reports success,
// which lets a project disable notifications without producing retry loops. | NewDispatcher
// 构建分发器。渠道为空时 Send 是无副作用的成功，使项目可以关闭通知而不产生重试死循环。
func NewDispatcher(timeout time.Duration, channels ...Channel) *Dispatcher {
	if timeout <= 0 {
		timeout = DefaultOptions().NotificationTimeout
	}
	filtered := make([]Channel, 0, len(channels))
	for _, channel := range channels {
		if channel != nil && strings.TrimSpace(channel.Name()) != "" {
			filtered = append(filtered, channel)
		}
	}
	return &Dispatcher{channels: filtered, timeout: timeout}
}

// Channels returns the configured channel names. | Channels 返回已配置的渠道名。
func (d *Dispatcher) Channels() []string {
	if d == nil {
		return nil
	}
	out := make([]string, 0, len(d.channels))
	for _, channel := range d.channels {
		out = append(out, channel.Name())
	}
	return out
}

// Len reports how many channels are configured. | Len 报告已配置的渠道数量。
func (d *Dispatcher) Len() int {
	if d == nil {
		return 0
	}
	return len(d.channels)
}

// Send delivers note to every selected channel. | Send 把 note 投递到全部选中的渠道。
func (d *Dispatcher) Send(ctx context.Context, note Notification) error {
	if d == nil || len(d.channels) == 0 {
		return nil
	}
	selected := selectedChannels(note.Channels)
	var failures []error
	for _, channel := range d.channels {
		name := channel.Name()
		if len(selected) > 0 && !selected[name] {
			continue
		}
		callCtx, cancel := context.WithTimeout(ctx, d.timeout)
		err := channel.Send(callCtx, note)
		cancel()
		if err != nil {
			failures = append(failures, errs.Detail(ErrNotificationFailed, "channel %[1]s: %[2]s | 渠道 %[1]s：%[2]s", name, err.Error()))
		}
	}
	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	return nil
}

// selectedChannels parses the comma-separated channel list of one notification. | selectedChannels
// 解析单条通知的逗号分隔渠道列表。
func selectedChannels(raw string) map[string]bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	out := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		if name := strings.TrimSpace(part); name != "" {
			out[name] = true
		}
	}
	return out
}

// notificationEnabled reports whether an event kind should produce a notification. | notificationEnabled
// 报告某类事件是否应产生通知。
func notificationEnabled(events []string, kind string) bool {
	if len(events) == 0 {
		return true
	}
	for _, event := range events {
		if strings.EqualFold(strings.TrimSpace(event), kind) {
			return true
		}
	}
	return false
}

// NotificationText renders the bilingual title and body of one notification. | NotificationText
// 渲染一条通知的中英双语标题与正文。
func NotificationText(kind, lang, instanceTitle, nodeName, actorName, initiatorName string) (string, string) {
	english := isEnglish(lang)
	title, body := "", ""
	switch kind {
	case NotifyAssigned:
		if english {
			title = "New approval task"
			body = "A task is waiting for you: " + instanceTitle + " at " + nodeName + "."
		} else {
			title = "新的审批待办"
			body = "有一项待办等待处理：" + instanceTitle + "（节点：" + nodeName + "）。"
		}
	case NotifyReminded:
		if english {
			title = "Approval reminder"
			body = "The task " + instanceTitle + " at " + nodeName + " is overdue."
		} else {
			title = "审批催办"
			body = "待办已超期：" + instanceTitle + "（节点：" + nodeName + "）。"
		}
	case NotifyApproved:
		if english {
			title = "Task approved"
			body = actorName + " approved " + instanceTitle + " at " + nodeName + "."
		} else {
			title = "审批已通过"
			body = actorName + " 通过了 " + instanceTitle + " 的节点 " + nodeName + "。"
		}
	case NotifyRejected:
		if english {
			title = "Task rejected"
			body = actorName + " rejected " + instanceTitle + " at " + nodeName + "."
		} else {
			title = "审批被驳回"
			body = actorName + " 驳回了 " + instanceTitle + " 的节点 " + nodeName + "。"
		}
	case NotifyReturned:
		if english {
			title = "Work returned"
			body = instanceTitle + " was returned to " + nodeName + "."
		} else {
			title = "流程已退回"
			body = instanceTitle + " 已退回到节点 " + nodeName + "。"
		}
	case NotifyWithdrawn:
		if english {
			title = "Instance withdrawn"
			body = initiatorName + " withdrew " + instanceTitle + "."
		} else {
			title = "流程已撤回"
			body = initiatorName + " 撤回了 " + instanceTitle + "。"
		}
	case NotifyCompleted:
		if english {
			title = "Instance completed"
			body = instanceTitle + " has finished."
		} else {
			title = "流程已完成"
			body = instanceTitle + " 已结束。"
		}
	case NotifyDelegated:
		if english {
			title = "Task delegated to you"
			body = actorName + " delegated " + instanceTitle + " at " + nodeName + " to you."
		} else {
			title = "收到委派任务"
			body = actorName + " 把 " + instanceTitle + " 的节点 " + nodeName + " 委派给您。"
		}
	default:
		if english {
			title = "Workflow notification"
			body = instanceTitle
		} else {
			title = "流程通知"
			body = instanceTitle
		}
	}
	return title, body
}

// isEnglish reports whether lang names an English locale. | isEnglish 报告 lang 是否为英文语言环境。
func isEnglish(lang string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(lang)), "en")
}

// notificationURL builds a deep link to one instance or task. | notificationURL 构建实例或任务的深链。
func notificationURL(baseURL, path string) string {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	path = "/" + strings.TrimLeft(strings.TrimSpace(path), "/")
	if baseURL == "" {
		return path
	}
	return baseURL + path
}
