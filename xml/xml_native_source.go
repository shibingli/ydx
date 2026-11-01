//go:build !xml_std

package xml

import (
	"bytes"
	"io"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/shibingli/ydx/errs"
)

const initialBufferSize = 64 << 10

// source buffers XML input from a byte slice or an io.Reader. | source 缓冲来自字节切片或
// io.Reader 的 XML 输入。
type source struct {
	r   io.Reader
	err error

	data []byte

	capture []byte

	limits Limits
	pos    int
	end    int

	consumed  int64
	line      int
	lineStart int64

	captureActive int
	captureLimit  int

	maxBuffer  int
	eof        bool
	owned      bool
	transcoded bool
	charsetSet bool
}

func newSource(limits Limits) *source {
	return &source{
		line:         1,
		limits:       limits,
		captureLimit: limits.MaxTokenSize,
		maxBuffer:    limits.MaxTokenSize + 64,
	}
}

func newByteSource(d *Decoder, data []byte) (*source, error) {
	s := newSource(d.limits())
	s.data = data
	s.end = len(data)
	s.eof = true
	if err := s.detectBOM(); err != nil {
		return nil, err
	}
	return s, nil
}

func newReaderSource(d *Decoder, r io.Reader) (*source, error) {
	s := newSource(d.limits())
	s.data = make([]byte, initialBufferSize)
	s.r = r
	s.owned = true
	if err := s.ensure(4); err != nil {
		return nil, err
	}
	if err := s.detectBOM(); err != nil {
		return nil, err
	}
	return s, nil
}

// detectBOM handles UTF-16 BOMs by transcoding the stream to UTF-8. A UTF-8 BOM is deliberately
// left in place because encoding/xml returns it as CharData. | detectBOM 通过把流转码为 UTF-8
// 来处理 UTF-16 BOM；UTF-8 BOM 被有意保留，因为 encoding/xml 会把它作为 CharData 返回。
func (s *source) detectBOM() error {
	buf := s.data[s.pos:s.end]
	if len(buf) >= 4 {
		if buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0xFE && buf[3] == 0xFF {
			return errs.Detail(ErrUnsupported, "UTF-32 input is not supported | 不支持 UTF-32 输入")
		}
		if buf[0] == 0xFF && buf[1] == 0xFE && buf[2] == 0x00 && buf[3] == 0x00 {
			return errs.Detail(ErrUnsupported, "UTF-32 input is not supported | 不支持 UTF-32 输入")
		}
	}
	if len(buf) >= 2 && (buf[0] == 0xFE && buf[1] == 0xFF || buf[0] == 0xFF && buf[1] == 0xFE) {
		big := buf[0] == 0xFE
		if s.r == nil {
			out, err := transcodeUTF16(buf[2:], big)
			if err != nil {
				return err
			}
			s.data = out
			s.pos, s.end = 0, len(out)
			s.eof = true
			s.transcoded = true
			return nil
		}
		rest := io.MultiReader(bytes.NewReader(buf[2:]), s.r)
		s.data = make([]byte, initialBufferSize)
		s.pos, s.end = 0, 0
		s.r = &utf16Reader{r: rest, big: big}
		s.eof = false
		s.transcoded = true
	}
	return nil
}

// ensure makes at least n bytes available unless EOF is reached. It compacts and grows the
// internal buffer for reader sources. | ensure 确保至少 n 字节可用（除非已到 EOF）；对读取器源会
// 压缩并按需扩容内部缓冲。
func (s *source) ensure(n int) error {
	if s.err != nil {
		return s.err
	}
	if s.end-s.pos >= n {
		return nil
	}
	if s.r == nil {
		s.eof = true
		return nil
	}
	if s.pos > 0 {
		copy(s.data, s.data[s.pos:s.end])
		s.end -= s.pos
		s.pos = 0
	}
	for s.end-s.pos < n && !s.eof {
		if s.end == len(s.data) {
			newLen := len(s.data) * 2
			if newLen < 64 {
				newLen = 64
			}
			if newLen < n {
				newLen = n
			}
			if newLen > s.maxBuffer {
				return errs.Detail(ErrLimit, "token exceeds MaxTokenSize | token 超过 MaxTokenSize")
			}
			nd := make([]byte, newLen)
			copy(nd, s.data[:s.end])
			s.data = nd
		}
		nr, err := s.r.Read(s.data[s.end:])
		s.end += nr
		switch {
		case err == io.EOF:
			s.eof = true
		case err != nil:
			s.err = err
			return err
		case nr == 0:
			// Give a well-behaved reader another chance without spinning forever.
			if s.end < len(s.data) {
				continue
			}
		}
	}
	return nil
}

func (s *source) available() []byte { return s.data[s.pos:s.end] }

// advance consumes n bytes, updates line/column and capture state. | advance 消费 n 字节，更新
// 行/列与捕获状态。
func (s *source) advance(n int) error {
	if n <= 0 {
		return nil
	}
	if s.pos+n > s.end {
		return &SyntaxError{Msg: "unexpected EOF", Line: s.line}
	}
	if s.captureActive > 0 {
		piece := s.data[s.pos : s.pos+n]
		if len(s.capture)+len(piece) > s.captureLimit {
			s.err = errs.Detail(ErrLimit, "inner XML capture exceeds MaxTokenSize | inner XML 捕获超过 MaxTokenSize")
			return s.err
		}
		s.capture = append(s.capture, piece...)
	}
	base := s.consumed
	piece := s.data[s.pos : s.pos+n]
	for {
		i := bytes.IndexByte(piece, '\n')
		if i < 0 {
			break
		}
		s.line++
		s.lineStart = base + int64(i) + 1
		piece = piece[i+1:]
		base += int64(i) + 1
	}
	s.pos += n
	s.consumed += int64(n)
	return nil
}

func (s *source) offset() int64 { return s.consumed }

func (s *source) posLine() (line, column int) {
	return s.line, int(s.consumed-s.lineStart) + 1
}

func (s *source) beginCapture() captureMark {
	m := captureMark{index: len(s.capture), offset: s.consumed, active: s.captureActive}
	s.captureActive++
	return m
}

func (s *source) endCapture(m captureMark, endOffset int64) []byte {
	end := m.index + int(endOffset-m.offset)
	var out []byte
	if end >= m.index && end <= len(s.capture) {
		out = make([]byte, end-m.index)
		copy(out, s.capture[m.index:end])
	}
	if s.captureActive > 0 {
		s.captureActive--
	}
	if m.active == 0 && s.captureActive == 0 && len(s.capture) > 0 {
		s.capture = nil
	}
	return out
}

// remainingReader returns the unconsumed stream for a CharsetReader. | remainingReader 返回供
// CharsetReader 使用的未消费流。
func (s *source) remainingReader() io.Reader {
	rest := s.data[s.pos:s.end]
	if s.r == nil {
		return bytes.NewReader(rest)
	}
	return io.MultiReader(bytes.NewReader(rest), s.r)
}

// switchToReader replaces the current source with a UTF-8 reader. | switchToReader 用 UTF-8 读取器
// 替换当前源。
func (s *source) switchToReader(r io.Reader) {
	s.data = make([]byte, initialBufferSize)
	s.pos, s.end = 0, 0
	s.r = r
	s.eof = false
	s.owned = true
	s.err = nil
}

// findByteAt returns the index of c at or after from, or -1 at EOF. | findByteAt 返回 from 起
// 首次出现 c 的下标，EOF 时返回 -1。
func (s *source) findByteAt(from int, c byte) (int, error) {
	for {
		if s.err != nil {
			return -1, s.err
		}
		buf := s.data[s.pos:s.end]
		if from < 0 {
			from = 0
		}
		if from < len(buf) {
			if i := indexByteAt(buf, from, c); i >= 0 {
				return i, nil
			}
			from = len(buf)
		}
		if s.r == nil || s.eof {
			return -1, nil
		}
		if err := s.ensure(len(buf) + 64); err != nil {
			return -1, err
		}
	}
}

// findAny2At returns the index of either c1 or c2 at or after from, or -1 at EOF. | findAny2At
// 返回 from 起首次出现 c1 或 c2 的下标，EOF 时返回 -1。
func (s *source) findAny2At(from int, c1, c2 byte) (int, error) {
	for {
		if s.err != nil {
			return -1, s.err
		}
		buf := s.data[s.pos:s.end]
		if from < 0 {
			from = 0
		}
		if from < len(buf) {
			if i := indexAny2At(buf, from, c1, c2); i >= 0 {
				return i, nil
			}
			from = len(buf)
		}
		if s.r == nil || s.eof {
			return -1, nil
		}
		if err := s.ensure(len(buf) + 64); err != nil {
			return -1, err
		}
	}
}

// findAny3At returns the index of any of c1..c3 at or after from, or -1 at EOF. | findAny3At
// 返回 from 起首次出现 c1..c3 之一的下标，EOF 时返回 -1。
func (s *source) findAny3At(from int, c1, c2, c3 byte) (int, error) {
	for {
		if s.err != nil {
			return -1, s.err
		}
		buf := s.data[s.pos:s.end]
		if from < 0 {
			from = 0
		}
		if from < len(buf) {
			if i := indexAny3At(buf, from, c1, c2, c3); i >= 0 {
				return i, nil
			}
			from = len(buf)
		}
		if s.r == nil || s.eof {
			return -1, nil
		}
		if err := s.ensure(len(buf) + 64); err != nil {
			return -1, err
		}
	}
}

// findAny4At returns the index of any of c1..c4 at or after from, or -1 at EOF. | findAny4At
// 返回 from 起首次出现 c1..c4 之一的下标，EOF 时返回 -1。
func (s *source) findAny4At(from int, c1, c2, c3, c4 byte) (int, error) {
	for {
		if s.err != nil {
			return -1, s.err
		}
		buf := s.data[s.pos:s.end]
		if from < 0 {
			from = 0
		}
		if from < len(buf) {
			if i := indexAny4At(buf, from, c1, c2, c3, c4); i >= 0 {
				return i, nil
			}
			from = len(buf)
		}
		if s.r == nil || s.eof {
			return -1, nil
		}
		if err := s.ensure(len(buf) + 64); err != nil {
			return -1, err
		}
	}
}

// findSequence returns the index of seq at or after from, or -1 at EOF. | findSequence 返回 from 起
// 首次出现 seq 的下标，EOF 时返回 -1。
func (s *source) findSequence(from int, seq []byte) (int, error) {
	if len(seq) == 0 {
		return from, nil
	}
	for {
		idx, err := s.findByteAt(from, seq[0])
		if err != nil || idx < 0 {
			return idx, err
		}
		if err := s.ensure(idx + len(seq)); err != nil {
			return -1, err
		}
		buf := s.data[s.pos:s.end]
		if idx+len(seq) <= len(buf) && bytes.Equal(buf[idx:idx+len(seq)], seq) {
			return idx, nil
		}
		if idx+len(seq) > len(buf) {
			return -1, nil
		}
		from = idx + 1
	}
}

// nativeSource adapts the native lexer to rawSource. | nativeSource 把原生词法器适配为 rawSource。
type nativeSource struct {
	s *source
	l *lexer
	d *Decoder
}

func newRawSourceFromBytes(d *Decoder, data []byte) rawSource {
	s, err := newByteSource(d, data)
	if err != nil {
		return &errorSource{err: err}
	}
	ns := &nativeSource{s: s, d: d}
	ns.l = &lexer{s: s, d: d}
	return ns
}

func newRawSourceFromReader(d *Decoder, r io.Reader) rawSource {
	s, err := newReaderSource(d, r)
	if err != nil {
		return &errorSource{err: err}
	}
	ns := &nativeSource{s: s, d: d}
	ns.l = &lexer{s: s, d: d}
	return ns
}

func (n *nativeSource) nextRaw() (Token, error) {
	ev, err := n.nextRawEvent()
	if err != nil {
		return nil, err
	}
	return ev.token(), nil
}

func (n *nativeSource) nextRawEvent() (event, error) {
	var ev event
	if err := n.l.nextRawEvent(&ev); err != nil {
		return event{}, err
	}
	if ev.kind == evProcInst && ev.target == "xml" {
		if err := n.handleXMLDecl(ProcInst{Target: ev.target, Inst: ev.data}); err != nil {
			return event{}, err
		}
	}
	return ev, nil
}

func (n *nativeSource) handleXMLDecl(pi ProcInst) error {
	if n.s.charsetSet {
		return nil
	}
	n.s.charsetSet = true
	content := string(pi.Inst)
	ver := procInstValue("version", content)
	if ver != "" && ver != "1.0" {
		return errs.Detail(ErrUnsupported, "unsupported XML version %q; only 1.0 is supported | 不支持的 XML 版本 %q，仅支持 1.0", ver, ver)
	}
	enc := procInstValue("encoding", content)
	if enc == "" || strings.EqualFold(enc, "utf-8") {
		return nil
	}
	if n.s.transcoded {
		return nil
	}
	if !strings.EqualFold(enc, "utf-16") && !strings.EqualFold(enc, "utf-16le") && !strings.EqualFold(enc, "utf-16be") && n.d.CharsetReader == nil {
		return errs.Detail(ErrUnsupported, "encoding %q declared but Decoder.CharsetReader is nil | 声明了编码 %q 但 Decoder.CharsetReader 为 nil", enc, enc)
	}
	if n.d.CharsetReader != nil {
		r, err := n.d.CharsetReader(enc, n.s.remainingReader())
		if err != nil {
			return errs.WrapDetail(err, ErrUnsupported, "opening charset %q | 打开字符集 %q", enc, enc)
		}
		if r == nil {
			return errs.Detail(ErrUnsupported, "CharsetReader returned a nil Reader for charset %q | CharsetReader 为字符集 %q 返回了 nil Reader", enc, enc)
		}
		n.s.switchToReader(r)
		return nil
	}
	return errs.Detail(ErrUnsupported, "encoding %q requires CharsetReader | 编码 %q 需要 CharsetReader", enc, enc)
}

func (n *nativeSource) offset() int64             { return n.s.offset() }
func (n *nativeSource) pos() (line, column int)   { return n.s.posLine() }
func (n *nativeSource) beginCapture() captureMark { return n.s.beginCapture() }
func (n *nativeSource) endCapture(m captureMark, e int64) []byte {
	return n.s.endCapture(m, e)
}
func (n *nativeSource) bytes() ([]byte, bool) {
	if n.s.r != nil {
		return nil, false
	}
	return n.s.data, true
}

// errorSource returns a construction error on first use. | errorSource 在首次使用时返回构造错误。
type errorSource struct{ err error }

func (e *errorSource) nextRaw() (Token, error)              { return nil, e.err }
func (e *errorSource) nextRawEvent() (event, error)         { return event{}, e.err }
func (e *errorSource) offset() int64                        { return 0 }
func (e *errorSource) pos() (int, int)                      { return 1, 1 }
func (e *errorSource) beginCapture() captureMark            { return captureMark{} }
func (e *errorSource) endCapture(captureMark, int64) []byte { return nil }
func (e *errorSource) bytes() ([]byte, bool)                { return nil, false }

// transcodeUTF16 converts a UTF-16 byte slice (without BOM) to UTF-8. | transcodeUTF16 把不含 BOM
// 的 UTF-16 字节切片转换为 UTF-8。
func transcodeUTF16(b []byte, big bool) ([]byte, error) {
	if len(b)%2 != 0 {
		return nil, &SyntaxError{Msg: "invalid UTF-16 input", Line: 1}
	}
	out := make([]byte, 0, len(b)/2)
	var pending rune = -1
	for i := 0; i < len(b); i += 2 {
		var u uint16
		if big {
			u = uint16(b[i])<<8 | uint16(b[i+1])
		} else {
			u = uint16(b[i+1])<<8 | uint16(b[i])
		}
		if pending >= 0 {
			if u < 0xDC00 || u > 0xDFFF {
				return nil, &SyntaxError{Msg: "invalid UTF-16 surrogate", Line: 1}
			}
			out = utf8.AppendRune(out, utf16.DecodeRune(pending, rune(u)))
			pending = -1
			continue
		}
		switch {
		case u >= 0xD800 && u <= 0xDBFF:
			pending = rune(u)
		case u >= 0xDC00 && u <= 0xDFFF:
			return nil, &SyntaxError{Msg: "invalid UTF-16 surrogate", Line: 1}
		default:
			out = utf8.AppendRune(out, rune(u))
		}
	}
	if pending >= 0 {
		return nil, &SyntaxError{Msg: "invalid UTF-16 surrogate", Line: 1}
	}
	return out, nil
}

// utf16Reader converts a streaming UTF-16 source to UTF-8. | utf16Reader 把流式 UTF-16 源转换为
// UTF-8。
type utf16Reader struct {
	r       io.Reader
	err     error
	raw     []byte
	out     []byte
	pending rune
	big     bool
}

func (u *utf16Reader) Read(p []byte) (int, error) {
	for len(u.out) == 0 {
		if u.err != nil {
			return 0, u.err
		}
		if len(u.raw) < 4096 {
			buf := make([]byte, 4096)
			n, err := u.r.Read(buf)
			if n > 0 {
				u.raw = append(u.raw, buf[:n]...)
			}
			if err != nil {
				u.err = err
			}
		}
		u.decode()
		if len(u.out) == 0 {
			if u.err == io.EOF {
				if len(u.raw) != 0 || u.pending >= 0 {
					u.err = &SyntaxError{Msg: "invalid UTF-16 input", Line: 1}
					return 0, u.err
				}
				return 0, io.EOF
			}
			if u.err != nil && u.err != io.EOF {
				return 0, u.err
			}
		}
	}
	n := copy(p, u.out)
	u.out = u.out[n:]
	return n, nil
}

func (u *utf16Reader) decode() {
	i := 0
	for i+1 < len(u.raw) {
		var v uint16
		if u.big {
			v = uint16(u.raw[i])<<8 | uint16(u.raw[i+1])
		} else {
			v = uint16(u.raw[i+1])<<8 | uint16(u.raw[i])
		}
		if u.pending >= 0 {
			if v < 0xDC00 || v > 0xDFFF {
				u.err = &SyntaxError{Msg: "invalid UTF-16 surrogate", Line: 1}
				return
			}
			u.out = utf8.AppendRune(u.out, utf16.DecodeRune(u.pending, rune(v)))
			u.pending = -1
		} else if v >= 0xD800 && v <= 0xDBFF {
			u.pending = rune(v)
		} else if v >= 0xDC00 && v <= 0xDFFF {
			u.err = &SyntaxError{Msg: "invalid UTF-16 surrogate", Line: 1}
			return
		} else {
			u.out = utf8.AppendRune(u.out, rune(v))
		}
		i += 2
	}
	u.raw = append(u.raw[:0], u.raw[i:]...)
}
