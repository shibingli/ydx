package client

import (
	"bufio"
	"io"
	"strconv"
	"strings"
	"time"
)

// Event is one parsed server-sent event. | Event 是一个已解析的服务器发送事件。
type Event struct {
	// ID is the event id, used for Last-Event-ID reconnects. | ID 是事件 id，用于 Last-Event-ID 重连。
	ID string
	// Name is the event type; empty means the default message event. | Name 是事件类型；为空表示默认消息事件。
	Name string
	// Comment carries the last comment line seen before the event. | Comment 携带事件前最后一条注释行。
	Comment string
	// Data is the joined data payload without the trailing newline. | Data 是拼接后的数据载荷（不含末尾换行）。
	Data []byte
	// Retry is the server-suggested reconnect delay. | Retry 是服务器建议的重连延迟。
	Retry time.Duration
}

// EventReaderOption configures an EventReader. | EventReaderOption 配置 EventReader。
type EventReaderOption func(*eventReaderConfig)

// eventReaderConfig is the mutable reader configuration. | eventReaderConfig 是 reader 的可变配置。
type eventReaderConfig struct {
	maxBytes int
}

// WithEventMaxBytes caps one line or event payload; <=0 means 1 MiB. | WithEventMaxBytes 限制单行或单事件载荷；<=0 表示 1 MiB。
func WithEventMaxBytes(n int) EventReaderOption {
	return func(c *eventReaderConfig) {
		if n > 0 {
			c.maxBytes = n
		}
	}
}

// EventReader parses the W3C event stream format. | EventReader 解析 W3C 事件流格式。
type EventReader struct {
	reader  *bufio.Reader
	max     int
	lastErr error
}

// NewEventReader builds a reader and strips a leading UTF-8 BOM. | NewEventReader 构建 reader 并去除开头 UTF-8 BOM。
func NewEventReader(r io.Reader, opts ...EventReaderOption) *EventReader {
	cfg := eventReaderConfig{maxBytes: 1 << 20}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	br := bufio.NewReaderSize(r, 32<<10)
	if prefix, err := br.Peek(3); err == nil && len(prefix) == 3 &&
		prefix[0] == 0xEF && prefix[1] == 0xBB && prefix[2] == 0xBF {
		_, _ = br.Discard(3)
	}
	return &EventReader{reader: br, max: cfg.maxBytes}
}

// Next returns the next dispatched event or io.EOF. | Next 返回下一个分发的事件或 io.EOF。
func (r *EventReader) Next() (Event, error) {
	if r == nil {
		return Event{}, io.EOF
	}
	if r.lastErr != nil {
		return Event{}, r.lastErr
	}
	var data []byte
	var id, name, comment string
	var retry time.Duration
	for {
		line, err := r.readLine()
		if err != nil {
			r.lastErr = err
			return Event{}, err
		}
		if line == "" {
			if len(data) == 0 {
				continue
			}
			if data[len(data)-1] == '\n' {
				data = data[:len(data)-1]
			}
			return Event{ID: id, Name: name, Comment: comment, Data: data, Retry: retry}, nil
		}
		if line[0] == ':' {
			comment = strings.TrimPrefix(line[1:], " ")
			continue
		}
		field, value := splitSSEField(line)
		switch field {
		case "data":
			data = append(data, value...)
			data = append(data, '\n')
			if len(data) > r.max {
				r.lastErr = ErrSSETooLarge
				return Event{}, ErrSSETooLarge
			}
		case "event":
			name = value
		case "id":
			if !strings.ContainsRune(value, 0) {
				id = value
			}
		case "retry":
			if isDigits(value) {
				if millis, err := strconv.Atoi(value); err == nil {
					retry = time.Duration(millis) * time.Millisecond
				}
			}
		}
	}
}

// readLine reads one LF, CRLF or CR terminated line. | readLine 读取一行（LF、CRLF 或 CR 结尾）。
func (r *EventReader) readLine() (string, error) {
	var buf []byte
	for {
		b, err := r.reader.ReadByte()
		if err != nil {
			if err == io.EOF && len(buf) > 0 {
				return string(buf), nil
			}
			return "", err
		}
		switch b {
		case '\n':
			return string(buf), nil
		case '\r':
			if next, err := r.reader.Peek(1); err == nil && len(next) > 0 && next[0] == '\n' {
				_, _ = r.reader.Discard(1)
			}
			return string(buf), nil
		default:
			buf = append(buf, b)
			if len(buf) > r.max {
				return "", ErrSSETooLarge
			}
		}
	}
}

// splitSSEField splits "field: value" at the first colon and strips one space. | splitSSEField 在首个冒号处拆分并去掉一个空格。
func splitSSEField(line string) (string, string) {
	index := strings.IndexByte(line, ':')
	if index < 0 {
		return line, ""
	}
	value := line[index+1:]
	if strings.HasPrefix(value, " ") {
		value = value[1:]
	}
	return line[:index], value
}

// isDigits reports whether s is a non-empty ASCII digit string. | isDigits 报告 s 是否为非空 ASCII 数字串。
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
