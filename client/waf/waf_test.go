package waf

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
