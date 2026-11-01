package base64

import "io"

// NewEncoder returns a new Base64 stream encoder that writes to w. Callers must Close the returned
// writer to flush a partial block, matching encoding/base64. | NewEncoder 返回写入 w 的新 Base64
// 流编码器；调用方必须 Close 以刷新未满块，行为与 encoding/base64 一致。
func NewEncoder(enc *Encoding, w io.Writer) io.WriteCloser {
	return &streamEncoder{enc: enc, w: w}
}

// NewDecoder returns a new Base64 stream decoder reading from r. CR and LF are ignored, matching
// encoding/base64. | NewDecoder 返回从 r 读取的新 Base64 流解码器；忽略 CR 与 LF，行为与
// encoding/base64 一致。
func NewDecoder(enc *Encoding, r io.Reader) io.Reader {
	return &streamDecoder{enc: enc, r: &newlineFilteringReader{wrapped: r}}
}

type streamEncoder struct {
	err  error
	enc  *Encoding
	w    io.Writer
	buf  [3]byte
	nbuf int
	out  [1024]byte
}

func (e *streamEncoder) Write(p []byte) (n int, err error) {
	if e.err != nil {
		return 0, e.err
	}
	if e.nbuf > 0 {
		var i int
		for i = 0; i < len(p) && e.nbuf < 3; i++ {
			e.buf[e.nbuf] = p[i]
			e.nbuf++
		}
		n += i
		p = p[i:]
		if e.nbuf < 3 {
			return n, nil
		}
		e.enc.Encode(e.out[:], e.buf[:])
		if _, e.err = e.w.Write(e.out[:4]); e.err != nil {
			return n, e.err
		}
		e.nbuf = 0
	}
	for len(p) >= 3 {
		nn := len(e.out) / 4 * 3
		if nn > len(p) {
			nn = len(p)
			nn -= nn % 3
		}
		e.enc.Encode(e.out[:], p[:nn])
		if _, e.err = e.w.Write(e.out[:nn/3*4]); e.err != nil {
			return n, e.err
		}
		n += nn
		p = p[nn:]
	}
	copy(e.buf[:], p)
	e.nbuf = len(p)
	n += len(p)
	return n, nil
}

func (e *streamEncoder) Close() error {
	if e.err == nil && e.nbuf > 0 {
		e.enc.Encode(e.out[:], e.buf[:e.nbuf])
		_, e.err = e.w.Write(e.out[:e.enc.EncodedLen(e.nbuf)])
		e.nbuf = 0
	}
	return e.err
}

type streamDecoder struct {
	err     error
	readErr error
	enc     *Encoding
	r       io.Reader
	buf     [1024]byte
	nbuf    int
	out     []byte
	outbuf  [1024 / 4 * 3]byte
}

func (d *streamDecoder) Read(p []byte) (n int, err error) {
	if len(d.out) > 0 {
		n = copy(p, d.out)
		d.out = d.out[n:]
		return n, nil
	}
	if d.err != nil {
		return 0, d.err
	}
	for d.nbuf < 4 && d.readErr == nil {
		nn := len(p) / 3 * 4
		if nn < 4 {
			nn = 4
		}
		if nn > len(d.buf) {
			nn = len(d.buf)
		}
		nn, d.readErr = d.r.Read(d.buf[d.nbuf:nn])
		d.nbuf += nn
	}
	if d.nbuf < 4 {
		if d.enc.isRaw() && d.nbuf > 0 {
			var nw int
			nw, d.err = d.enc.Decode(d.outbuf[:], d.buf[:d.nbuf])
			d.nbuf = 0
			d.out = d.outbuf[:nw]
			n = copy(p, d.out)
			d.out = d.out[n:]
			if n > 0 || len(p) == 0 && len(d.out) > 0 {
				return n, nil
			}
			if d.err != nil {
				return 0, d.err
			}
		}
		d.err = d.readErr
		if d.err == io.EOF && d.nbuf > 0 {
			d.err = io.ErrUnexpectedEOF
		}
		return 0, d.err
	}
	nr := d.nbuf / 4 * 4
	nw := d.nbuf / 4 * 3
	if nw > len(p) {
		nw, d.err = d.enc.Decode(d.outbuf[:], d.buf[:nr])
		d.out = d.outbuf[:nw]
		n = copy(p, d.out)
		d.out = d.out[n:]
	} else {
		n, d.err = d.enc.Decode(p, d.buf[:nr])
	}
	d.nbuf -= nr
	copy(d.buf[:d.nbuf], d.buf[nr:])
	return n, d.err
}

type newlineFilteringReader struct {
	wrapped io.Reader
}

func (r *newlineFilteringReader) Read(p []byte) (int, error) {
	n, err := r.wrapped.Read(p)
	for n > 0 {
		offset := 0
		for i, b := range p[:n] {
			if b != '\r' && b != '\n' {
				if i != offset {
					p[offset] = b
				}
				offset++
			}
		}
		if offset > 0 {
			return offset, err
		}
		n, err = r.wrapped.Read(p)
	}
	return n, err
}
