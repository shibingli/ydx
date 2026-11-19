package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSendBodies(t *testing.T) {
	var gotType, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if _, err := c.Post(context.Background(), srv.URL, map[string]string{"a": "b"}); err != nil {
		t.Fatal(err)
	}
	if gotType != "application/json" || gotBody != `{"a":"b"}` {
		t.Fatalf("json body %q type %q", gotBody, gotType)
	}

	if _, err := c.Put(context.Background(), srv.URL, []byte("raw")); err != nil {
		t.Fatal(err)
	}
	if gotBody != "raw" {
		t.Fatalf("raw body %q", gotBody)
	}

	if _, err := c.Delete(context.Background(), srv.URL, strings.NewReader("stream")); err != nil {
		t.Fatal(err)
	}
	if gotBody != "stream" {
		t.Fatalf("stream body %q", gotBody)
	}
}

func TestRelativeURLUsesFirstHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/user/42" {
			t.Errorf("path %q", r.URL.Path)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), "/api/user/42")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Fatalf("body %q", body)
	}
}

func TestRequestOptions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Token") != "abc" {
			t.Errorf("header %q", r.Header.Get("X-Token"))
		}
		if r.URL.Query().Get("q") != "1" {
			t.Errorf("query %q", r.URL.RawQuery)
		}
	}))
	defer srv.Close()

	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Get(context.Background(), srv.URL,
		WithRequestHeader("X-Token", "abc"),
		WithRequestQuery("q", "1"),
	); err != nil {
		t.Fatal(err)
	}
}

func TestRequestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
	}))
	defer srv.Close()

	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.Get(context.Background(), srv.URL, WithRequestTimeout(10*time.Millisecond))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline exceeded, got %v", err)
	}
}

func TestConnectMethod(t *testing.T) {
	var method string
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		method = req.Method
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
	})
	c, err := New(WithTransport(rt))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Connect(context.Background(), "http://example.com/tunnel", nil); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodConnect {
		t.Fatalf("method %q", method)
	}
}

func TestSendRelativeQueryContainingScheme(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.RequestURI(); got != "/echo?q=http://example.com/a" {
			t.Errorf("request uri %q", got)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	c, err := New(WithBaseURL(srv.URL), WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), "/echo?q=http://example.com/a")
	if err != nil {
		t.Fatalf("relative query with scheme: %v", err)
	}
	data, err := resp.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "ok" {
		t.Fatalf("body %q", data)
	}
}

func TestSendProtocolRelativeKeepsExplicitHost(t *testing.T) {
	var targetHits, defaultHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		_, _ = w.Write([]byte("target"))
	}))
	defer target.Close()
	def := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defaultHits.Add(1)
		_, _ = w.Write([]byte("default"))
	}))
	defer def.Close()
	c, err := New(WithBaseURL(def.URL), WithHosts(def.URL), WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	raw := "//" + target.Listener.Addr().String() + "/x"
	resp, err := c.Get(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	data, err := resp.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "target" || targetHits.Load() != 1 || defaultHits.Load() != 0 {
		t.Fatalf("body %q target=%d default=%d", data, targetHits.Load(), defaultHits.Load())
	}
}
