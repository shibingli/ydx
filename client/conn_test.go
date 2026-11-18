package client

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestShortAndLongConnections(t *testing.T) {
	newServer := func() (*httptest.Server, *atomic.Int32) {
		var connections atomic.Int32
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			if state == http.StateNew {
				connections.Add(1)
			}
		}
		srv.Start()
		return srv, &connections
	}

	longSrv, longConns := newServer()
	defer longSrv.Close()
	longClient, err := New(WithHosts(longSrv.URL), WithConnectionMode(ConnLong))
	if err != nil {
		t.Fatal(err)
	}
	defer longClient.Close()
	for i := 0; i < 2; i++ {
		resp, err := longClient.Get(context.Background(), longSrv.URL+"/x")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if longConns.Load() != 1 {
		t.Fatalf("long connections %d", longConns.Load())
	}

	shortSrv, shortConns := newServer()
	defer shortSrv.Close()
	shortClient, err := New(WithHosts(shortSrv.URL), WithConnectionMode(ConnShort))
	if err != nil {
		t.Fatal(err)
	}
	defer shortClient.Close()
	for i := 0; i < 2; i++ {
		resp, err := shortClient.Get(context.Background(), shortSrv.URL+"/x")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if shortConns.Load() < 2 {
		t.Fatalf("short connections %d", shortConns.Load())
	}
}

func TestH2C(t *testing.T) {
	var proto atomic.Value
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto.Store(r.Proto)
	}))
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	srv.Config.Protocols = protocols
	srv.Start()
	defer srv.Close()

	c, err := New(WithHosts(srv.URL), WithH2C(true))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), srv.URL+"/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if proto.Load() != "HTTP/2.0" {
		t.Fatalf("proto %v", proto.Load())
	}
}

func TestWarmup(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("method %s", r.Method)
		}
		hits.Add(1)
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Warmup(context.Background(), 3); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 3 {
		t.Fatalf("warmup hits %d", hits.Load())
	}
}
