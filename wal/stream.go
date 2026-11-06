package wal

import (
	"context"
	"io"

	"github.com/shibingli/ydx/errs"
)

// streamOptions carries per-stream options. | streamOptions 携带单流选项。
type streamOptions struct {
	chunkSize int
}

// StreamOption customizes AppendStream or Tx.AppendStream. | StreamOption 定制
// AppendStream 或 Tx.AppendStream。
type StreamOption func(*streamOptions)

// StreamChunkSize sets the stream chunk size. | StreamChunkSize 设置流分块大小。
func StreamChunkSize(n int) StreamOption { return func(o *streamOptions) { o.chunkSize = n } }

// AppendStream writes a chunked stream with constant memory. | AppendStream
// 以恒定内存写入一个分块流。
func (w *WAL) AppendStream(ctx context.Context, r io.Reader, opts ...StreamOption) (StreamInfo, error) {
	if w.opts.readOnly {
		return StreamInfo{}, ErrReadOnly
	}
	if ctx == nil {
		ctx = context.Background()
	}
	so := streamOptions{chunkSize: w.opts.streamChunkSize}
	for _, fn := range opts {
		if fn != nil {
			fn(&so)
		}
	}
	if so.chunkSize <= 0 {
		so.chunkSize = w.opts.streamChunkSize
	}
	maxChunk := w.opts.maxRecordBytes - recordHeaderSizeEncrypted - aeadTagSize
	if maxChunk < 1 {
		maxChunk = 1
	}
	if so.chunkSize > maxChunk {
		so.chunkSize = maxChunk
	}
	id, err := newStreamID()
	if err != nil {
		return StreamInfo{}, err
	}
	info := StreamInfo{ID: id}
	buf := make([]byte, so.chunkSize)
	for {
		select {
		case <-ctx.Done():
			return info, ctx.Err()
		default:
		}
		n, rerr := io.ReadFull(r, buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			lsn, err := w.appendStreamRecord(ctx, Record{Flags: FlagStreamChunk, Key: id[:], Data: chunk})
			if err != nil {
				return info, err
			}
			if info.FirstLSN == 0 {
				info.FirstLSN = lsn
			}
			info.LastLSN = lsn
			info.Bytes += uint64(n)
			info.Chunks++
			w.counters.streamChunks.Add(1)
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return info, rerr
		}
	}
	lsn, err := w.appendStreamRecord(ctx, Record{Flags: FlagStreamEnd, Key: id[:]})
	if err != nil {
		return info, err
	}
	if info.FirstLSN == 0 {
		info.FirstLSN = lsn
	}
	info.LastLSN = lsn
	info.Complete = true
	return info, nil
}

// appendStreamRecord appends one stream record while allowing reserved flags. | appendStreamRecord
// 追加一条流记录并允许保留标志。
func (w *WAL) appendStreamRecord(ctx context.Context, rec Record) (uint64, error) {
	if err := w.validateUserRecord(rec, true); err != nil {
		return 0, err
	}
	req := &appendRequest{kind: kindData, recs: []Record{rec}, allowStream: true, done: make(chan appendResult, 1)}
	if err := w.admit(ctx, req, false); err != nil {
		return 0, err
	}
	res := <-req.done
	if res.err != nil {
		return 0, res.err
	}
	if w.indexer != nil {
		w.runIndexer(RecordMeta{LSN: res.lsn, Timestamp: rec.Timestamp, Flags: rec.Flags,
			KeyLen: len(rec.Key), DataLen: len(rec.Data)}, rec.Key, rec.Data)
	}
	return res.lsn, nil
}

// StreamReader decodes one chunked stream. | StreamReader 解码一个分块流。
type StreamReader struct {
	w      *WAL
	info   StreamInfo
	reader *Reader
	buf    []byte
	pos    int
	end    bool
	closed bool
}

// NewStreamReader opens a StreamReader. | NewStreamReader 打开一个 StreamReader。
func (w *WAL) NewStreamReader(info StreamInfo, opts ...ReaderOption) (*StreamReader, error) {
	if info.ID == ([16]byte{}) {
		return nil, errs.Detail(ErrInvalidOptions, "stream ID is zero | 流 ID 为零")
	}
	base := []ReaderOption{From(info.FirstLSN), pinRange()}
	if info.Complete && info.LastLSN > 0 {
		base = append(base, To(info.LastLSN))
	}
	base = append(base, opts...)
	r, err := w.NewReader(base...)
	if err != nil {
		return nil, err
	}
	return &StreamReader{w: w, info: info, reader: r}, nil
}

// Read returns stream bytes until io.EOF. | Read 返回流数据直到 io.EOF。
func (s *StreamReader) Read(p []byte) (int, error) {
	if s.closed {
		return 0, ErrClosed
	}
	if s.end {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if s.pos < len(s.buf) {
			n := copy(p, s.buf[s.pos:])
			s.pos += n
			if s.pos >= len(s.buf) {
				s.buf = s.buf[:0]
				s.pos = 0
			}
			return n, nil
		}
		rec, err := s.reader.Next()
		if err == io.EOF {
			s.end = true
			if s.info.Complete {
				return 0, io.EOF
			}
			return 0, ErrStreamIncomplete
		}
		if err != nil {
			return 0, err
		}
		if string(rec.Key) != string(s.info.ID[:]) {
			continue
		}
		if rec.Flags&FlagStreamEnd != 0 {
			s.end = true
			return 0, io.EOF
		}
		if rec.Flags&FlagStreamChunk == 0 {
			continue
		}
		if len(rec.Data) == 0 {
			continue
		}
		s.buf = append(s.buf[:0], rec.Data...)
		s.pos = 0
	}
}

// Close releases the underlying Reader. | Close 释放底层 Reader。
func (s *StreamReader) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	return s.reader.Close()
}
