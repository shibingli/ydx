# ydx/client/sse

把 `ydx/sse` 的 `Writer` 适配为 `ydx/client` 的 `EventSink`，用于 SSE tee 镜像的多订阅者扇出。

```go
fanout := clientsse.NewFanout(clientsse.Options{Queue: 64})
defer fanout.Close()

// 在 HTTP 处理器中登记订阅者
sub, err := fanout.Add(w)

// 作为 client.MirrorPolicy.TeeEventSinks 使用
rule := client.Rule{
    Pattern: "/events",
    Mirror: &client.MirrorPolicy{
        Mode:          client.MirrorTee,
        TeeEventSinks: []client.EventSink{fanout.Sink()},
    },
}
```

每个订阅者有独立队列与 `sse.Writer`；慢订阅者按 `DropNewest`/`DropOldest` 丢弃，不阻塞主流。