// Package sse adapts ydx/sse writers into a client.EventSink for multi-subscriber
// SSE fan-out. | Package sse 把 ydx/sse writer 适配为 client.EventSink，实现多订阅者 SSE 扇出。
//
// Each subscriber owns an sse.Writer and a bounded queue; a slow subscriber drops
// events instead of blocking the primary stream. | 每个订阅者拥有一个 sse.Writer 与有界队列；
// 慢订阅者会丢弃事件而不是阻塞主流。
//
//	fanout := clientsse.NewFanout(clientsse.Options{Queue: 64})
//	defer fanout.Close()
//	sub, err := fanout.Add(w) // in an HTTP handler
//	rule := client.Rule{Pattern: "/events", Mirror: &client.MirrorPolicy{
//		Mode:          client.MirrorTee,
//		TeeEventSinks: []client.EventSink{fanout.Sink()},
//	}}
package sse
