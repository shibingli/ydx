package adapter

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shibingli/ydx/realtime"
	"github.com/shibingli/ydx/sse"
)

// TestSSEAdapterCarriesIDAndData proves the SSE sink writes both the message id
// (for Last-Event-ID resumption) and the body. | TestSSEAdapterCarriesIDAndData
// 证明 SSE sink 同时写出消息 id（供 Last-Event-ID 续传）与正文。
func TestSSEAdapterCarriesIDAndData(t *testing.T) {
	rec := httptest.NewRecorder()
	w, err := sse.NewWriter(rec, sse.Options{})
	if err != nil {
		t.Fatalf("sse.NewWriter: %v", err)
	}
	defer w.Close()

	sink := SSE(w)
	if err := sink(realtime.Message{ID: "node-a:7", Body: []byte("hello")}); err != nil {
		t.Fatalf("sink: %v", err)
	}
	body := rec.Body.String()
	for _, want := range []string{"id: node-a:7", "data: hello"} {
		if !strings.Contains(body, want) {
			t.Fatalf("SSE body %q lacks %q", body, want)
		}
	}
}
