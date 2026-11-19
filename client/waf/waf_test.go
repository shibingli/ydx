package waf

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/shibingli/ydx/client"
	ydxwaf "github.com/shibingli/ydx/waf"
)

func TestGuardBlocksBeforeUpstream(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	engine, err := ydxwaf.New(ydxwaf.Options{Directives: []string{
		`SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny,status:403"`,
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	guard, err := New(Options{Engine: engine})
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.New(client.WithHosts(srv.URL), client.WithGuard(guard))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if _, err := c.Get(context.Background(), srv.URL+"/admin"); !errors.Is(err, client.ErrBlocked) {
		t.Fatalf("want ErrBlocked, got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("upstream hit %d", hits.Load())
	}
	resp, err := c.Get(context.Background(), srv.URL+"/public")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if hits.Load() != 1 {
		t.Fatalf("public hit %d", hits.Load())
	}
}

func TestGuardBodyInspection(t *testing.T) {
	engine, err := ydxwaf.New(ydxwaf.Options{Directives: []string{
		`SecRequestBodyAccess On`,
		`SecRule REQUEST_BODY "@contains secret" "id:2,phase:2,deny,status:403"`,
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	var gotBody atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		gotBody.Store(string(data))
	}))
	defer srv.Close()

	off, err := New(Options{Engine: engine, InspectBody: false})
	if err != nil {
		t.Fatal(err)
	}
	c1, err := client.New(client.WithHosts(srv.URL), client.WithGuard(off))
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	resp, err := c1.Post(context.Background(), srv.URL+"/x", "secret")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotBody.Load() != "secret" {
		t.Fatalf("body %q", gotBody.Load())
	}

	on, err := New(Options{Engine: engine, InspectBody: true})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := client.New(client.WithHosts(srv.URL), client.WithGuard(on))
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if _, err := c2.Post(context.Background(), srv.URL+"/x", "secret"); !errors.Is(err, client.ErrBlocked) {
		t.Fatalf("want ErrBlocked, got %v", err)
	}
}

func TestGuardInspectsCappedChunkedBody(t *testing.T) {
	engine, err := ydxwaf.New(ydxwaf.Options{Directives: []string{
		`SecRequestBodyAccess On`,
		`SecRule REQUEST_BODY "@contains secret" "id:2,phase:2,deny,status:403"`,
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	guard, err := New(Options{Engine: engine, InspectBody: true})
	if err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()
	c, err := client.New(
		client.WithHosts(srv.URL),
		client.WithAccessPolicy(&client.AccessPolicy{MaxRequestBytes: 1024}),
		client.WithGuard(guard),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/x", io.NopCloser(strings.NewReader("secret")))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1
	if _, err := c.Do(req); !errors.Is(err, client.ErrBlocked) {
		t.Fatalf("want ErrBlocked, got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("upstream hit %d", hits.Load())
	}
}

func TestGuardPreservesBodyWhenAllowed(t *testing.T) {
	engine, err := ydxwaf.New(ydxwaf.Options{Directives: []string{
		`SecRequestBodyAccess On`,
		`SecRule REQUEST_BODY "@contains secret" "id:2,phase:2,deny,status:403"`,
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	guard, err := New(Options{Engine: engine, InspectBody: true})
	if err != nil {
		t.Fatal(err)
	}
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		got.Store(string(data))
	}))
	defer srv.Close()
	c, err := client.New(client.WithHosts(srv.URL), client.WithGuard(guard))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Post(context.Background(), srv.URL+"/x", "hello")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if value := got.Load(); value != "hello" {
		t.Fatalf("upstream body %q", value)
	}
}

func TestGuardKeepsRequestTooLargeSentinel(t *testing.T) {
	engine, err := ydxwaf.New(ydxwaf.Options{Directives: []string{
		`SecRequestBodyAccess On`,
		`SecRule REQUEST_URI "@contains /blocked" "id:3,phase:1,deny,status:403"`,
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	guard, err := New(Options{Engine: engine, InspectBody: true})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c, err := client.New(
		client.WithHosts(srv.URL),
		client.WithAccessPolicy(&client.AccessPolicy{MaxRequestBytes: 4}),
		client.WithGuard(guard),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/x", io.NopCloser(strings.NewReader("0123456789")))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1
	if _, err := c.Do(req); !errors.Is(err, client.ErrRequestTooLarge) {
		t.Fatalf("want ErrRequestTooLarge, got %v", err)
	}
}

func TestGuardPreservesLargeBodyWhenAllowed(t *testing.T) {
	engine, err := ydxwaf.New(ydxwaf.Options{Directives: []string{
		`SecRequestBodyAccess On`,
		`SecRule REQUEST_BODY "@contains secret" "id:2,phase:2,deny,status:403"`,
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	guard, err := New(Options{Engine: engine, InspectBody: true})
	if err != nil {
		t.Fatal(err)
	}
	var received atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		received.Store(n)
	}))
	defer srv.Close()
	c, err := client.New(client.WithHosts(srv.URL), client.WithGuard(guard))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	payload := bytes.Repeat([]byte("a"), 2<<20)
	resp, err := c.Post(context.Background(), srv.URL+"/x", payload)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if received.Load() != int64(len(payload)) {
		t.Fatalf("upstream received %d of %d bytes", received.Load(), len(payload))
	}
}

func TestGuardFailOpen(t *testing.T) {
	engine, err := ydxwaf.New(ydxwaf.Options{Directives: []string{
		`SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny,status:403"`,
	}})
	if err != nil {
		t.Fatal(err)
	}
	guard, err := New(Options{Engine: engine, FailOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()
	c, err := client.New(client.WithHosts(srv.URL), client.WithGuard(guard))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), srv.URL+"/admin")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if hits.Load() != 1 {
		t.Fatalf("hits %d", hits.Load())
	}
}
