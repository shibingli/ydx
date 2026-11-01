package xml

import "io"

type chunkReader struct {
	data []byte
	n    int
	pos  int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := r.n
	if n > len(r.data)-r.pos {
		n = len(r.data) - r.pos
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, r.data[r.pos:r.pos+n])
	r.pos += n
	return n, nil
}
