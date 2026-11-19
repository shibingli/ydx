package client_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	ydxclient "github.com/shibingli/ydx/client"
)

// BenchmarkMultipartUpload compares the buffered 1 MiB path with the streamed
// 8 MiB path. | BenchmarkMultipartUpload 对比 1 MiB 缓冲路径与 8 MiB 流式路径。
func BenchmarkMultipartUpload(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	client, err := ydxclient.New(ydxclient.WithoutCookieJar())
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()
	for _, tc := range []struct {
		name string
		size int
	}{
		{"1MiB", 1 << 20},
		{"8MiB", 8 << 20},
	} {
		b.Run(tc.name, func(b *testing.B) {
			payload := bytes.Repeat([]byte("x"), tc.size)
			b.SetBytes(int64(tc.size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				resp, err := client.Post(context.Background(), srv.URL+"/upload",
					ydxclient.Multipart(nil, ydxclient.MultipartFile{
						Field:  "file",
						Reader: bytes.NewReader(payload),
					}))
				if err != nil {
					b.Fatal(err)
				}
				if err := resp.Discard(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
