//go:build xml_std

// This file is the standard-library backend: setting the xml_std build tag routes raw tokenization
// to encoding/xml while every higher-level API (Token filtering, Parse, Selector, Unmarshal,
// Valid, Marshal) stays shared. | 本文件是标准库后端：设置 xml_std 构建标签后，原始词法分析交给
// encoding/xml，而所有上层 API（Token 过滤、Parse、Selector、Unmarshal、Valid、Marshal）仍共享同一
// 实现。

package xml

import (
	"bytes"
	stdxml "encoding/xml"
	"io"
	"strings"
)

// Backend returns the name of the active XML backend; with the xml_std tag set it is always
// "encoding/xml". | Backend 返回当前生效的 XML 后端名称；设置 xml_std 标签时恒为 "encoding/xml"。
func Backend() string { return "encoding/xml" }

// stdSource adapts encoding/xml's RawToken to rawSource. | stdSource 把 encoding/xml 的 RawToken
// 适配为 rawSource。
type stdSource struct {
	d         *Decoder
	dec       *stdxml.Decoder
	data      []byte
	tee       *teeReader
	switched  bool
	capActive int
	capStart  int64
}

func newRawSourceFromReader(d *Decoder, r io.Reader) rawSource {
	t := &teeReader{r: r}
	return &stdSource{d: d, dec: stdxml.NewDecoder(t), tee: t}
}

func newRawSourceFromBytes(d *Decoder, data []byte) rawSource {
	return &stdSource{d: d, dec: stdxml.NewDecoder(bytes.NewReader(data)), data: data}
}

func (s *stdSource) syncConfig() {
	s.dec.Strict = s.d.Strict
	s.dec.Entity = s.d.Entity
	s.dec.CharsetReader = s.d.CharsetReader
}

func (s *stdSource) nextRaw() (Token, error) {
	s.syncConfig()
	t, err := s.dec.RawToken()
	if err != nil {
		return nil, err
	}
	out := convertStdToken(t)
	if pi, ok := out.(ProcInst); ok && pi.Target == "xml" {
		enc := procInstValue("encoding", string(pi.Inst))
		if enc != "" && !strings.EqualFold(enc, "utf-8") {
			s.switched = true
		}
	}
	if s.tee != nil && s.capActive == 0 {
		s.tee.trim(s.dec.InputOffset())
	}
	return out, nil
}

func (s *stdSource) nextRawEvent() (event, error) {
	for {
		t, err := s.nextRaw()
		if err != nil {
			return event{}, err
		}
		if t == nil {
			continue
		}
		var ev event
		if tokenToEvent(t, &ev) {
			return ev, nil
		}
	}
}

func (s *stdSource) offset() int64 { return s.dec.InputOffset() }

func (s *stdSource) pos() (line, column int) { return s.dec.InputPos() }

func (s *stdSource) beginCapture() captureMark {
	m := captureMark{offset: s.dec.InputOffset(), active: s.capActive}
	s.capActive++
	return m
}

func (s *stdSource) endCapture(m captureMark, endOffset int64) []byte {
	if s.capActive > 0 {
		s.capActive--
	}
	var src []byte
	if s.tee != nil {
		src = s.tee.slice(m.offset, endOffset)
	} else if s.data != nil && m.offset >= 0 && endOffset >= m.offset && endOffset <= int64(len(s.data)) {
		src = s.data[m.offset:endOffset]
	}
	if src == nil {
		return nil
	}
	out := make([]byte, len(src))
	copy(out, src)
	return out
}

func (s *stdSource) bytes() ([]byte, bool) {
	if s.data == nil || s.switched {
		return nil, false
	}
	return s.data, true
}

func convertStdToken(t stdxml.Token) Token {
	switch t := t.(type) {
	case stdxml.StartElement:
		attrs := make([]Attr, len(t.Attr))
		for i, a := range t.Attr {
			attrs[i] = Attr{Name: Name{Space: a.Name.Space, Local: a.Name.Local}, Value: a.Value}
		}
		return StartElement{Name: Name{Space: t.Name.Space, Local: t.Name.Local}, Attr: attrs}
	case stdxml.EndElement:
		return EndElement{Name: Name{Space: t.Name.Space, Local: t.Name.Local}}
	case stdxml.CharData:
		return CharData(append([]byte(nil), t...))
	case stdxml.Comment:
		return Comment(append([]byte(nil), t...))
	case stdxml.ProcInst:
		return ProcInst{Target: t.Target, Inst: append([]byte(nil), t.Inst...)}
	case stdxml.Directive:
		return Directive(append([]byte(nil), t...))
	}
	return nil
}

// teeReader records bytes read from the underlying reader so ,innerxml can be sliced by
// InputOffset. It keeps read-ahead bytes and trims only up to the consumed offset. | teeReader
// 记录底层读取器读到的字节，使 ,innerxml 可以按 InputOffset 切片；它保留预读字节，只裁剪到已消费
// 偏移。
type teeReader struct {
	r    io.Reader
	buf  []byte
	base int64
	read int64
}

func (t *teeReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if n > 0 {
		t.buf = append(t.buf, p[:n]...)
		t.read += int64(n)
	}
	return n, err
}

func (t *teeReader) trim(keepFrom int64) {
	if keepFrom <= t.base {
		return
	}
	drop := int(keepFrom - t.base)
	if drop > len(t.buf) {
		drop = len(t.buf)
	}
	t.buf = append(t.buf[:0], t.buf[drop:]...)
	t.base += int64(drop)
}

func (t *teeReader) slice(from, to int64) []byte {
	if from < t.base || to < from || to > t.read {
		return nil
	}
	start := int(from - t.base)
	end := int(to - t.base)
	if start < 0 || end > len(t.buf) {
		return nil
	}
	return t.buf[start:end]
}
