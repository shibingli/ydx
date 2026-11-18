package client_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/imroc/req/v3"
	ydxclient "github.com/shibingli/ydx/client"
	"github.com/valyala/fasthttp"
)

var (
	smallBody = []byte(`{"ok":true}`)
	largeBody = bytes.Repeat([]byte("x"), 1<<20)
)

type implementation struct {
	name  string
	get   func() error
	post  func() error
	short func() error
	large func() error
}

func newServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/small":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(smallBody)
		case "/large":
			_, _ = w.Write(largeBody)
		case "/post":
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(smallBody)
		}
	}))
}

func implementations(b *testing.B, base string) []implementation {
	b.Helper()
	smallURL := base + "/small"
	postURL := base + "/post"
	largeURL := base + "/large"

	nativeTransport := &http.Transport{
		MaxIdleConns:        256,
		MaxIdleConnsPerHost: 256,
		ForceAttemptHTTP2:   false,
	}
	native := &http.Client{Transport: nativeTransport}
	b.Cleanup(nativeTransport.CloseIdleConnections)

	ydx, err := ydxclient.New(ydxclient.WithHosts(base), ydxclient.WithoutCookieJar(), ydxclient.WithRewriteAll(true))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = ydx.Close() })

	restyClient := resty.New()
	reqClient := req.C()

	nativeShortTransport := &http.Transport{DisableKeepAlives: true}
	nativeShort := &http.Client{Transport: nativeShortTransport}
	b.Cleanup(nativeShortTransport.CloseIdleConnections)
	ydxShort, err := ydxclient.New(
		ydxclient.WithHosts(base),
		ydxclient.WithConnectionMode(ydxclient.ConnShort),
		ydxclient.WithRewriteAll(true),
		ydxclient.WithoutCookieJar(),
	)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = ydxShort.Close() })
	restyShort := resty.New().SetTransport(&http.Transport{DisableKeepAlives: true})
	reqShort := req.C().DisableKeepAlives()

	getNative := func(client *http.Client) func() error {
		return func() error {
			resp, err := client.Get(smallURL)
			if err != nil {
				return err
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			return resp.Body.Close()
		}
	}
	getYdx := func(client *ydxclient.Client, url string) func() error {
		return func() error {
			resp, err := client.Get(context.Background(), url)
			if err != nil {
				return err
			}
			return resp.Discard()
		}
	}
	getNativeURL := func(client *http.Client, url string) func() error {
		return func() error {
			resp, err := client.Get(url)
			if err != nil {
				return err
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			return resp.Body.Close()
		}
	}

	fastPost := func() error {
		request := fasthttp.AcquireRequest()
		response := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseRequest(request)
		defer fasthttp.ReleaseResponse(response)
		request.SetRequestURI(postURL)
		request.Header.SetMethod(http.MethodPost)
		request.Header.SetContentType("application/json")
		request.SetBody(smallBody)
		return fasthttp.Do(request, response)
	}
	fastShort := func() error {
		request := fasthttp.AcquireRequest()
		response := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseRequest(request)
		defer fasthttp.ReleaseResponse(response)
		request.SetRequestURI(smallURL)
		request.Header.SetMethod(http.MethodGet)
		request.Header.SetConnectionClose()
		return fasthttp.Do(request, response)
	}

	return []implementation{
		{
			name: "native",
			get:  getNative(native),
			post: func() error {
				req, _ := http.NewRequest(http.MethodPost, postURL, bytes.NewReader(smallBody))
				req.Header.Set("Content-Type", "application/json")
				resp, err := native.Do(req)
				if err != nil {
					return err
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				return resp.Body.Close()
			},
			short: getNative(nativeShort),
			large: getNativeURL(native, largeURL),
		},
		{
			name: "ydx",
			get:  getYdx(ydx, smallURL),
			post: func() error {
				resp, err := ydx.Post(context.Background(), postURL, smallBody,
					ydxclient.WithRequestHeader("Content-Type", "application/json"))
				if err != nil {
					return err
				}
				return resp.Discard()
			},
			short: getYdx(ydxShort, smallURL),
			large: getYdx(ydx, largeURL),
		},
		{
			name: "resty",
			get: func() error {
				_, err := restyClient.R().Get(smallURL)
				return err
			},
			post: func() error {
				_, err := restyClient.R().
					SetHeader("Content-Type", "application/json").
					SetBody(smallBody).
					Post(postURL)
				return err
			},
			short: func() error {
				_, err := restyShort.R().Get(smallURL)
				return err
			},
			large: func() error {
				_, err := restyClient.R().Get(largeURL)
				return err
			},
		},
		{
			name: "req",
			get: func() error {
				_, err := reqClient.R().Get(smallURL)
				return err
			},
			post: func() error {
				_, err := reqClient.R().
					SetHeader("Content-Type", "application/json").
					SetBody(smallBody).
					Post(postURL)
				return err
			},
			short: func() error {
				_, err := reqShort.R().Get(smallURL)
				return err
			},
			large: func() error {
				_, err := reqClient.R().Get(largeURL)
				return err
			},
		},
		{
			name: "fasthttp",
			get: func() error {
				_, _, err := fasthttp.Get(nil, smallURL)
				return err
			},
			post:  fastPost,
			short: fastShort,
			large: func() error {
				_, _, err := fasthttp.Get(nil, largeURL)
				return err
			},
		},
	}
}

func benchmarkSequential(b *testing.B, get func() error) {
	b.Helper()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := get(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGET_Small(b *testing.B) {
	srv := newServer()
	defer srv.Close()
	for _, impl := range implementations(b, srv.URL) {
		b.Run(impl.name, func(b *testing.B) {
			benchmarkSequential(b, impl.get)
		})
	}
}

func BenchmarkGET_Parallel(b *testing.B) {
	srv := newServer()
	defer srv.Close()
	for _, impl := range implementations(b, srv.URL) {
		b.Run(impl.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if err := impl.get(); err != nil {
						b.Error(err)
						return
					}
				}
			})
		})
	}
}

func BenchmarkPOST_JSON(b *testing.B) {
	srv := newServer()
	defer srv.Close()
	for _, impl := range implementations(b, srv.URL) {
		b.Run(impl.name, func(b *testing.B) {
			benchmarkSequential(b, impl.post)
		})
	}
}

func BenchmarkGET_1MiB(b *testing.B) {
	srv := newServer()
	defer srv.Close()
	for _, impl := range implementations(b, srv.URL) {
		b.Run(impl.name, func(b *testing.B) {
			b.SetBytes(int64(len(largeBody)))
			benchmarkSequential(b, impl.large)
		})
	}
}

func BenchmarkGET_ShortConn(b *testing.B) {
	srv := newServer()
	defer srv.Close()
	for _, impl := range implementations(b, srv.URL) {
		b.Run(impl.name, func(b *testing.B) {
			benchmarkSequential(b, impl.short)
		})
	}
}

func BenchmarkGET_TLS(b *testing.B) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(smallBody)
	}))
	defer srv.Close()
	url := srv.URL

	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	nativeTransport := &http.Transport{TLSClientConfig: tlsConfig, MaxIdleConnsPerHost: 256}
	native := &http.Client{Transport: nativeTransport}
	defer nativeTransport.CloseIdleConnections()
	ydx, err := ydxclient.New(
		ydxclient.WithHosts(url),
		ydxclient.WithRewriteAll(true),
		ydxclient.WithTLS(ydxclient.TLSConfig{InsecureSkipVerify: true, DisableSystemRoots: true}),
		ydxclient.WithoutCookieJar(),
	)
	if err != nil {
		b.Fatal(err)
	}
	defer ydx.Close()
	restyClient := resty.New().SetTLSClientConfig(tlsConfig)
	reqClient := req.C().EnableInsecureSkipVerify()
	fastClient := &fasthttp.Client{TLSConfig: tlsConfig}

	cases := []struct {
		name string
		get  func() error
	}{
		{"native", func() error {
			resp, err := native.Get(url)
			if err != nil {
				return err
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			return resp.Body.Close()
		}},
		{"ydx", func() error {
			resp, err := ydx.Get(context.Background(), url)
			if err != nil {
				return err
			}
			return resp.Discard()
		}},
		{"resty", func() error { _, err := restyClient.R().Get(url); return err }},
		{"req", func() error { _, err := reqClient.R().Get(url); return err }},
		{"fasthttp", func() error { _, _, err := fastClient.Get(nil, url); return err }},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) { benchmarkSequential(b, tc.get) })
	}
}

func BenchmarkPipeline_Parallel10(b *testing.B) {
	srv := newServer()
	defer srv.Close()
	ydx, err := ydxclient.New(ydxclient.WithHosts(srv.URL), ydxclient.WithBaseURL(srv.URL), ydxclient.WithoutCookieJar())
	if err != nil {
		b.Fatal(err)
	}
	defer ydx.Close()
	nodes := make([]ydxclient.Node, 0, 10)
	for i := 0; i < 10; i++ {
		nodes = append(nodes, ydxclient.Step(fmt.Sprintf("s%d", i)).GET("/small"))
	}
	plan := ydxclient.NewPipeline(ydxclient.PipelineOptions{MaxParallel: 10}, ydxclient.Parallel(nodes...))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := plan.Run(context.Background(), ydx); err != nil {
			b.Fatal(err)
		}
	}
}
