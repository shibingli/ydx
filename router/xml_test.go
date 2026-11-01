package router

import (
	"net/http"
	"testing"
)

type xmlTestPayload struct {
	ID   int    `xml:"id,attr"`
	Name string `xml:"name"`
}

// TestCtxXMLUsesYdxXML verifies that Ctx.XML encodes through github.com/shibingli/ydx/xml.
// | TestCtxXMLUsesYdxXML 验证 Ctx.XML 通过 github.com/shibingli/ydx/xml 编码。
func TestCtxXMLUsesYdxXML(t *testing.T) {
	r := New()
	r.GET("/xml", func(c *Ctx) {
		if err := c.XML(http.StatusOK, xmlTestPayload{ID: 7, Name: "Ada"}); err != nil {
			t.Errorf("Ctx.XML: %v", err)
		}
	})
	rec := do(r, http.MethodGet, "/xml", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/xml; charset=utf-8" {
		t.Fatalf("Content-Type = %q", ct)
	}
	want := `<xmlTestPayload id="7"><name>Ada</name></xmlTestPayload>`
	if got := rec.Body.String(); got != want {
		t.Fatalf("body = %q want %q", got, want)
	}
}

// TestCtxXMLErrorLeavesResponseUntouched verifies that encoding errors surface before headers or
// body are written. | TestCtxXMLErrorLeavesResponseUntouched 验证编码错误在写入头部或正文前返回。
func TestCtxXMLErrorLeavesResponseUntouched(t *testing.T) {
	r := New()
	r.GET("/xml", func(c *Ctx) {
		if err := c.XML(http.StatusOK, make(chan int)); err == nil {
			t.Error("expected encoding error")
		}
	})
	rec := do(r, http.MethodGet, "/xml", nil, "")
	if rec.Body.Len() != 0 {
		t.Fatalf("body = %q", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "" {
		t.Fatalf("Content-Type = %q", ct)
	}
}
