package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/json"
)

type testReadSeekCloser struct {
	*strings.Reader
	closed bool
}

func (r *testReadSeekCloser) Close() error {
	r.closed = true
	return nil
}

type seekerOnly struct {
	data string
	off  int64
}

func (s *seekerOnly) Read(p []byte) (int, error) {
	if s.off >= int64(len(s.data)) {
		return 0, io.EOF
	}
	n := copy(p, s.data[s.off:])
	s.off += int64(n)
	return n, nil
}

func (s *seekerOnly) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		s.off = offset
	case io.SeekCurrent:
		s.off += offset
	case io.SeekEnd:
		s.off = int64(len(s.data)) + offset
	}
	return s.off, nil
}

func TestPrepareSeekerIsOneShot(t *testing.T) {
	_, getBody, _, err := prepareBody(&seekerOnly{data: "payload"})
	if err != nil {
		t.Fatal(err)
	}
	if getBody != nil {
		t.Fatal("shared seeker must not expose a concurrent replay function")
	}
}

func TestPrepareBodyKinds(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		body, getBody, contentType, err := prepareBody(nil)
		if err != nil {
			t.Fatal(err)
		}
		if body != nil || getBody != nil || contentType != "" {
			t.Fatalf("body=%v getBody=%v type=%q", body, getBody != nil, contentType)
		}
	})

	t.Run("bytes", func(t *testing.T) {
		body, getBody, contentType, err := prepareBody([]byte("raw"))
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(body)
		if string(got) != "raw" || getBody == nil || contentType != "" {
			t.Fatalf("got %q getBody=%v type=%q", got, getBody != nil, contentType)
		}
		replay, _ := getBody()
		again, _ := io.ReadAll(replay)
		if string(again) != "raw" {
			t.Fatalf("replay %q", again)
		}
	})

	t.Run("json", func(t *testing.T) {
		body, getBody, contentType, err := prepareBody(map[string]string{"a": "b"})
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(body)
		if string(got) != `{"a":"b"}` || contentType != "application/json" || getBody == nil {
			t.Fatalf("got %q type=%q getBody=%v", got, contentType, getBody != nil)
		}
	})

	t.Run("reader", func(t *testing.T) {
		nonSeekable := struct{ io.Reader }{strings.NewReader("stream")}
		body, getBody, contentType, err := prepareBody(nonSeekable)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(body)
		if string(got) != "stream" || getBody != nil || contentType != "" {
			t.Fatalf("got %q getBody=%v type=%q", got, getBody != nil, contentType)
		}
	})
}

func TestPrepareBodyPrecedence(t *testing.T) {
	var nilBuf *bytes.Buffer
	body, getBody, contentType, err := prepareBody(nilBuf)
	if err != nil || body != nil || getBody != nil || contentType != "" {
		t.Fatalf("nil buffer: body=%v getBody=%v type=%q err=%v", body, getBody != nil, contentType, err)
	}

	buf := bytes.NewBufferString("buf")
	body, getBody, _, err = prepareBody(buf)
	if err != nil || getBody == nil {
		t.Fatal("bytes.Buffer must be replayable")
	}
	if got, _ := io.ReadAll(body); string(got) != "buf" {
		t.Fatalf("buffer body %q", got)
	}

	rc := io.NopCloser(strings.NewReader("rc"))
	_, getBody, _, err = prepareBody(rc)
	if err != nil || getBody != nil {
		t.Fatal("plain ReadCloser must be one-shot")
	}

	rsc := &testReadSeekCloser{Reader: strings.NewReader("rsc")}
	body, getBody, _, err = prepareBody(rsc)
	if err != nil || getBody != nil {
		t.Fatal("a closer other than *os.File must be one-shot")
	}
	if err := body.Close(); err != nil || !rsc.closed {
		t.Fatalf("Close did not reach the underlying closer: %v", err)
	}

	form := url.Values{"a": {"b"}}
	body, getBody, contentType, err = prepareBody(Form(form))
	if err != nil || contentType != "application/x-www-form-urlencoded" {
		t.Fatalf("form type %q err %v", contentType, err)
	}
	b, _ := io.ReadAll(body)
	if string(b) != "a=b" || getBody == nil {
		t.Fatalf("form body %q getBody=%v", b, getBody != nil)
	}
}

func TestPrepareBodyConcurrentReaderAt(t *testing.T) {
	src := bytes.NewReader([]byte("shared-data"))
	_, getBody, _, err := prepareBody(src)
	if err != nil || getBody == nil {
		t.Fatal("bytes.Reader must be replayable")
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rc, err := getBody()
			if err != nil {
				t.Errorf("getBody: %v", err)
				return
			}
			defer rc.Close()
			got, _ := io.ReadAll(rc)
			if string(got) != "shared-data" {
				t.Errorf("replay %q", got)
			}
		}()
	}
	wg.Wait()
}

func TestPrepareBodyFileOwnership(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "body-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("file-data"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}

	body, getBody, _, err := prepareBody(f)
	if err != nil || getBody == nil {
		t.Fatalf("regular file must be replayable: %v", err)
	}
	got, _ := io.ReadAll(body)
	if string(got) != "file-data" {
		t.Fatalf("primary %q", got)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	replay, err := getBody()
	if err != nil {
		t.Fatal(err)
	}
	defer replay.Close()
	got, _ = io.ReadAll(replay)
	if string(got) != "file-data" {
		t.Fatalf("replay %q", got)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	defer r.Close()
	_, getBody, _, err = prepareBody(r)
	if err != nil || getBody != nil {
		t.Fatal("pipe must be one-shot")
	}
}

func TestPrepareBodyRawMessage(t *testing.T) {
	body, getBody, contentType, err := prepareBody([]byte(`{"a":1}`))
	if err != nil || getBody == nil || contentType != "" {
		t.Fatalf("bytes type=%q getBody=%v err=%v", contentType, getBody != nil, err)
	}
	body, getBody, contentType, err = prepareBody(json.RawMessage(`{"a":1}`))
	if err != nil || getBody == nil || contentType != "application/json" {
		t.Fatalf("json raw type=%q getBody=%v err=%v", contentType, getBody != nil, err)
	}
	got, _ := io.ReadAll(body)
	if string(got) != `{"a":1}` {
		t.Fatalf("json raw body %q", got)
	}
}

func TestSpoolMaxBytes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	defer srv.Close()
	c, err := New(
		WithHosts(srv.URL),
		WithRetry(RetryPolicy{MaxAttempts: 2, Backoff: func(int) time.Duration { return time.Millisecond }}),
		WithSpoolMaxBytes(5),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.Put(context.Background(), srv.URL+"/x", io.NopCloser(strings.NewReader("0123456789")))
	if !errors.Is(err, ErrRequestTooLarge) {
		t.Fatalf("want ErrRequestTooLarge, got %v", err)
	}
}
