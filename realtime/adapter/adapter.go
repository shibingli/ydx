// Package adapter wires the realtime hub to the three transports the framework
// ships. | Package adapter 把实时中枢接到框架自带的三种传输上。
//
// The hub itself stays transport-agnostic; every function here is a one-liner
// that turns a transport connection into a realtime.Sink. | Hub 自身与传输无关；
// 这里的每个函数都是一行代码，把传输连接变成 realtime.Sink。
package adapter

import (
	"github.com/shibingli/ydx/realtime"
	"github.com/shibingli/ydx/sse"
	"github.com/shibingli/ydx/websocket"
	"github.com/shibingli/ydx/webtransport"
)

// WebSocket returns a Sink that writes every broadcast as one text frame. |
// WebSocket 返回把每条广播写成一条文本帧的 Sink。
func WebSocket(c *websocket.Conn) realtime.Sink {
	return func(msg realtime.Message) error {
		return c.WriteMessage(websocket.TextMessage, msg.Body)
	}
}

// WebTransport returns a Sink that writes every broadcast on the session's
// framed channel. | WebTransport 返回把每条广播写到会话带帧通道上的 Sink。
func WebTransport(ch *webtransport.Channel) realtime.Sink {
	return func(msg realtime.Message) error {
		return ch.Send(msg.Body)
	}
}

// SSE returns a Sink that writes every broadcast as one SSE event carrying the
// message id, so a browser that reconnects with Last-Event-ID can tell how far
// it got. | SSE 返回把每条广播写成一条带消息 id 的 SSE 事件的 Sink，浏览器重连时带上
// Last-Event-ID 即可知道读到何处。
func SSE(w *sse.Writer) realtime.Sink {
	return func(msg realtime.Message) error {
		return w.WriteEvent(sse.Event{ID: msg.ID, Data: msg.Body})
	}
}
