package xml

import (
	"bytes"
	stdxml "encoding/xml"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type mItem struct {
	ID   int    `xml:"id,attr"`
	Name string `xml:"name"`
}

type mBasic struct {
	ID    int      `xml:"id,attr"`
	Name  string   `xml:"name"`
	Empty string   `xml:"empty,omitempty"`
	Tags  []string `xml:"tag"`
	Items []mItem  `xml:"item"`
	Note  string   `xml:",chardata"`
}

type mInner struct {
	Inner string `xml:",innerxml"`
	Text  string `xml:",chardata"`
}

type mComment struct {
	Comment string `xml:",comment"`
	Text    string `xml:",chardata"`
}

type mCDATA struct {
	Value string `xml:",cdata"`
}

type mPath struct {
	A string `xml:"x>y>z"`
	B string `xml:"x>w"`
	C string `xml:"x>y>z2,omitempty"`
}

type mEmbedded struct {
	A string `xml:"a"`
}

type mEmbed struct {
	mEmbedded
	B string `xml:"b"`
}

type mPtr struct {
	P    *mItem   `xml:"p"`
	List []*mItem `xml:"list"`
}

type mAttr struct {
	Value string `xml:"value,attr"`
	Plain string `xml:",attr"`
	Skip  string `xml:"-"`
}

type mNS struct {
	Name string `xml:"urn:x name"`
}

type mText struct {
	Value upperText `xml:"value"`
	Attr  upperText `xml:"a,attr"`
}

type upperText string

func (u upperText) MarshalText() ([]byte, error) { return []byte(strings.ToUpper(string(u))), nil }

func checkMarshal[T any](t *testing.T, v T) {
	t.Helper()
	want, wantErr := stdxml.Marshal(v)
	got, gotErr := Marshal(v)
	if (wantErr != nil) != (gotErr != nil) {
		t.Fatalf("Marshal(%T): std err=%v ours err=%v", v, wantErr, gotErr)
	}
	if wantErr == nil && !bytes.Equal(want, got) {
		t.Fatalf("Marshal(%T):\nstd  %q\nours %q", v, want, got)
	}
	wantI, wantIErr := stdxml.MarshalIndent(v, "  ", "\t")
	gotI, gotIErr := MarshalIndent(v, "  ", "\t")
	if (wantIErr != nil) != (gotIErr != nil) {
		t.Fatalf("MarshalIndent(%T): std err=%v ours err=%v", v, wantIErr, gotIErr)
	}
	if wantIErr == nil && !bytes.Equal(wantI, gotI) {
		t.Fatalf("MarshalIndent(%T):\nstd  %q\nours %q", v, wantI, gotI)
	}
}

func TestMarshalMatchesStdlib(t *testing.T) {
	checkMarshal(t, mBasic{ID: 1, Name: "Ada", Tags: []string{"a", "b"}, Items: []mItem{{1, "i1"}, {2, "i2"}}, Note: "note"})
	checkMarshal(t, mBasic{})
	checkMarshal(t, mBasic{Empty: "", Name: "only"})
	checkMarshal(t, mInner{Inner: "<b>raw &amp; text</b>", Text: "ignored"})
	checkMarshal(t, mComment{Comment: "hello", Text: "text"})
	checkMarshal(t, mCDATA{Value: "a]]>b"})
	checkMarshal(t, mPath{A: "1", B: "2"})
	checkMarshal(t, mEmbed{mEmbedded: mEmbedded{A: "A"}, B: "B"})
	checkMarshal(t, mPtr{P: &mItem{1, "p"}, List: []*mItem{{2, "q"}, nil}})
	checkMarshal(t, mAttr{Value: "v", Plain: "p", Skip: "s"})
	checkMarshal(t, mNS{Name: "n"})
	checkMarshal(t, mText{Value: "hi", Attr: "there"})
	checkMarshal(t, []mItem{{1, "a"}, {2, "b"}})
	checkMarshal(t, 42)
	checkMarshal(t, true)
	checkMarshal(t, "text")
	checkMarshal(t, []byte("bytes"))
	checkMarshal(t, []string{"x", "y"})
	checkMarshal[any](t, nil)
}

type marshalTextAttr struct{}

func (marshalTextAttr) MarshalText() ([]byte, error) { return []byte("tm-value"), nil }

type marshalIfaceAttr struct{}

func (marshalIfaceAttr) MarshalXMLAttr(name Name) (Attr, error) {
	return Attr{Name: name, Value: "ma-value"}, nil
}

// TestMarshalAttrInterfaceProbing verifies attribute encoding probes pointers, interfaces,
// encoding.TextMarshaler and MarshalerAttr exactly like encoding/xml. |
// TestMarshalAttrInterfaceProbing 验证属性编码对指针、接口、encoding.TextMarshaler 与
// MarshalerAttr 的探测与 encoding/xml 完全一致。
func TestMarshalAttrInterfaceProbing(t *testing.T) {
	tm := marshalTextAttr{}
	now := time.Date(2026, 11, 8, 1, 2, 3, 0, time.UTC)
	type attrData struct {
		P *time.Time       `xml:"p,attr"`
		A any              `xml:"a,attr"`
		B any              `xml:"b,attr"`
		C []any            `xml:"c,attr"`
		E *marshalTextAttr `xml:"e,attr"`
		F any              `xml:"f,attr"`
	}
	v := attrData{P: &now, A: tm, B: &tm, C: []any{tm, &tm}, E: &tm, F: &marshalTextAttr{}}
	want, wantErr := stdxml.Marshal(v)
	got, gotErr := Marshal(v)
	if (wantErr != nil) != (gotErr != nil) {
		t.Fatalf("attribute interface probing differs: std=%v ours=%v", wantErr, gotErr)
	}
	if string(want) != string(got) {
		t.Errorf("attribute interface output differs:\nstd  %s\nours %s", want, got)
	}
	type withMA struct {
		D marshalIfaceAttr `xml:"d,attr"`
	}
	out, err := Marshal(withMA{})
	if err != nil || !bytes.Contains(out, []byte(`d="ma-value"`)) {
		t.Errorf("MarshalerAttr probing failed: %s %v", out, err)
	}
}

func TestMarshalErrors(t *testing.T) {
	if _, err := Marshal(map[string]string{"a": "b"}); err == nil {
		t.Fatal("expected map error")
	} else {
		var ute *UnsupportedTypeError
		if !errors.As(err, &ute) {
			t.Fatalf("expected UnsupportedTypeError, got %T %v", err, err)
		}
	}
	if _, err := Marshal(make(chan int)); err == nil {
		t.Fatal("expected chan error")
	}
	var bad struct {
		C string `xml:",comment"`
	}
	bad.C = "a--b"
	if _, err := Marshal(bad); err == nil {
		t.Fatal("expected bad comment error")
	}
	var bad2 struct {
		X int `xml:",chardata,omitempty"`
	}
	if _, err := Marshal(bad2); err == nil {
		t.Fatal("expected invalid tag error")
	}
}

type mCustom struct{}

func (mCustom) MarshalXML(e *Encoder, start StartElement) error {
	if err := e.EncodeToken(start); err != nil {
		return err
	}
	if err := e.EncodeToken(CharData("custom")); err != nil {
		return err
	}
	return e.EncodeToken(start.End())
}

type mCustomBad struct{}

func (mCustomBad) MarshalXML(e *Encoder, start StartElement) error {
	if err := e.EncodeToken(start); err != nil {
		return err
	}
	return nil
}

func TestMarshalCustomAndEncoder(t *testing.T) {
	got, err := Marshal(mCustom{})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `<mCustom>custom</mCustom>` {
		t.Fatalf("got %q", got)
	}
	if _, err := Marshal(mCustomBad{}); err == nil {
		t.Fatal("expected unclosed MarshalXML error")
	}

	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	tokens := []Token{
		ProcInst{Target: "xml", Inst: []byte(`version="1.0"`)},
		StartElement{Name: Name{Local: "a"}, Attr: []Attr{{Name: Name{Local: "x"}, Value: `1&2`}}},
		CharData("text<>&"),
		Comment("hello"),
		StartElement{Name: Name{Local: "b"}},
		EndElement{Name: Name{Local: "b"}},
		EndElement{Name: Name{Local: "a"}},
		Directive("DOCTYPE a"),
	}
	for _, tok := range tokens {
		if err := enc.EncodeToken(tok); err != nil {
			t.Fatalf("%T: %v", tok, err)
		}
	}
	if err := enc.Flush(); err != nil {
		t.Fatal(err)
	}
	want := `<?xml version="1.0"?><a x="1&amp;2">text&lt;&gt;&amp;<!--hello--><b></b></a><!DOCTYPE a>`
	if buf.String() != want {
		t.Fatalf("got %q want %q", buf.String(), want)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	if err := enc.EncodeToken(CharData("x")); err == nil {
		t.Fatal("expected closed encoder error")
	}
}

func TestMarshalEscapeText(t *testing.T) {
	var a, b bytes.Buffer
	in := []byte("a<&>\"'\t\n\r�")
	if err := stdxml.EscapeText(&a, in); err != nil {
		t.Fatal(err)
	}
	if err := EscapeText(&b, in); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Fatalf("std %q ours %q", a.String(), b.String())
	}
}

func TestMarshalUnmarshalRoundTrip(t *testing.T) {
	orig := mBasic{ID: 7, Name: "Ada", Tags: []string{"a", "b"}, Items: []mItem{{1, "i1"}}, Note: "n"}
	data, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var stdOut mBasic
	if err := stdxml.Unmarshal(data, &stdOut); err != nil {
		t.Fatalf("std cannot read ours: %v", err)
	}
	var ourOut mBasic
	if err := Unmarshal(data, &ourOut); err != nil {
		t.Fatal(err)
	}
	if stdOut.ID != orig.ID || ourOut.Name != orig.Name || len(ourOut.Items) != 1 {
		t.Fatalf("round trip std=%#v ours=%#v", stdOut, ourOut)
	}
	stdData, err := stdxml.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stdData, data) {
		t.Fatalf("output differs from std: %q vs %q", data, stdData)
	}
}

type mNameTag struct {
	XMLName Name   `xml:"urn:x root"`
	A       string `xml:"a"`
}

type mNameTagStd struct {
	XMLName stdxml.Name `xml:"urn:x root"`
	A       string      `xml:"a"`
}

func TestMarshalXMLName(t *testing.T) {
	got, err := Marshal(mNameTag{A: "v"})
	if err != nil {
		t.Fatal(err)
	}
	want, err := stdxml.Marshal(mNameTagStd{A: "v"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("tag form: ours %q std %q", got, want)
	}

	got, err = Marshal(mNameTag{XMLName: Name{Space: "urn:y", Local: "other"}, A: "v"})
	if err != nil {
		t.Fatal(err)
	}
	want, err = stdxml.Marshal(mNameTagStd{XMLName: stdxml.Name{Space: "urn:y", Local: "other"}, A: "v"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("value form: ours %q std %q", got, want)
	}
}

func TestTagPathError(t *testing.T) {
	typ := reflect.StructOf([]reflect.StructField{
		{Name: "A", Type: reflect.TypeOf(""), Tag: `xml:"x>y"`},
		{Name: "B", Type: reflect.TypeOf(""), Tag: `xml:"x>y"`},
	})
	v := reflect.New(typ).Interface()
	err := Unmarshal([]byte(`<root/>`), v)
	var tpe *TagPathError
	if !errors.As(err, &tpe) {
		t.Fatalf("expected TagPathError, got %T %v", err, err)
	}
}
