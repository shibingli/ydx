package client

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/xml"
)

// JSONBody marks a value that should be encoded as JSON. | JSONBody 标记应按 JSON 编码的值。
type JSONBody struct {
	// Value is the value passed to ydx/json.Marshal. | Value 是传给 ydx/json.Marshal 的值。
	Value any
}

// JSON returns a request body encoded as JSON. | JSON 返回按 JSON 编码的请求正文。
func JSON(v any) JSONBody {
	return JSONBody{Value: v}
}

// MultipartFile is one file part in a multipart body. | MultipartFile 是 multipart 正文中的一个文件分片。
type MultipartFile struct {
	// Field is the form field name. | Field 是表单字段名。
	Field string
	// FileName is the filename sent to the server; empty uses Field. | FileName 是发送给服务器的文件名；为空时使用 Field。
	FileName string
	// ContentType is the part content type; empty uses application/octet-stream. | ContentType 是分片 Content-Type；为空时使用 application/octet-stream。
	ContentType string
	// Reader supplies the file content. | Reader 提供文件内容。
	Reader io.Reader
}

// MultipartBody marks a multipart/form-data request body. File parts are read
// fully into memory while the body is prepared; use a streaming Body for large
// uploads. | MultipartBody 标记 multipart/form-data 请求正文。准备正文时文件分片
// 会完整读入内存；大文件上传请使用流式 Body。
type MultipartBody struct {
	// Fields are regular form fields. | Fields 是普通表单字段。
	Fields url.Values
	// Files are file parts. | Files 是文件分片。
	Files []MultipartFile
}

// Multipart returns a multipart/form-data request body. | Multipart 返回 multipart/form-data 请求正文。
func Multipart(fields url.Values, files ...MultipartFile) MultipartBody {
	return MultipartBody{Fields: fields, Files: files}
}

// XMLBody marks a value that should be encoded as XML. | XMLBody 标记应按 XML 编码的值。
type XMLBody struct {
	// Value is the value passed to ydx/xml.Marshal. | Value 是传给 ydx/xml.Marshal 的值。
	Value any
}

// XML returns a request body encoded as XML. | XML 返回按 XML 编码的请求正文。
func XML(v any) XMLBody {
	return XMLBody{Value: v}
}

// FormBody marks url.Values that should be encoded as a form. | FormBody 标记应按表单编码的 url.Values。
type FormBody struct {
	// Values is the form payload. | Values 是表单载荷。
	Values url.Values
}

// Form returns a request body encoded as application/x-www-form-urlencoded. | Form 返回按 application/x-www-form-urlencoded 编码的请求正文。
func Form(v url.Values) FormBody {
	return FormBody{Values: v}
}

// readerAtSeeker is the interface that permits independent, concurrent replay readers. | readerAtSeeker 是可生成独立并发重放 reader 的接口。
type readerAtSeeker interface {
	io.ReaderAt
	io.Seeker
}

// prepareMultipartBody encodes fields and files into a replayable multipart body. | prepareMultipartBody 把字段与文件编码为可重放的 multipart 正文。
func prepareMultipartBody(body MultipartBody) (io.ReadCloser, func() (io.ReadCloser, error), string, int64, error) {
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)
	for key, values := range body.Fields {
		if key == "" {
			return nil, nil, "", 0, errs.Detail(ErrEncodeBody, "empty multipart field name | 空 multipart 字段名")
		}
		for _, value := range values {
			if err := writer.WriteField(key, value); err != nil {
				return nil, nil, "", 0, errs.Wrap(err, ErrEncodeBody)
			}
		}
	}
	for _, file := range body.Files {
		if file.Field == "" {
			return nil, nil, "", 0, errs.Detail(ErrEncodeBody, "empty multipart field | 空 multipart 字段")
		}
		if file.Reader == nil {
			return nil, nil, "", 0, errs.Detail(ErrEncodeBody, "nil multipart file %q | 空 multipart 文件 %q", file.Field, file.Field)
		}
		name := file.FileName
		if name == "" {
			name = file.Field
		}
		contentType := file.ContentType
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		if strings.ContainsAny(contentType, "\r\n") {
			return nil, nil, "", 0, errs.Detail(ErrEncodeBody, "invalid multipart content type | 非法的 multipart Content-Type")
		}
		disposition := mime.FormatMediaType("form-data", map[string]string{"name": file.Field, "filename": name})
		if disposition == "" {
			return nil, nil, "", 0, errs.Detail(ErrEncodeBody, "invalid multipart field %q | 非法的 multipart 字段 %q", file.Field, file.Field)
		}
		part, err := writer.CreatePart(map[string][]string{
			"Content-Disposition": {disposition},
			"Content-Type":        {contentType},
		})
		if err != nil {
			return nil, nil, "", 0, errs.Wrap(err, ErrEncodeBody)
		}
		if _, err := io.Copy(part, file.Reader); err != nil {
			return nil, nil, "", 0, errs.Wrap(err, ErrEncodeBody)
		}
	}
	if err := writer.Close(); err != nil {
		return nil, nil, "", 0, errs.Wrap(err, ErrEncodeBody)
	}
	data := buffer.Bytes()
	return bytesBody(data), bytesGetBody(data), writer.FormDataContentType(), int64(len(data)), nil
}

// prepareBody classifies a request body into a reader, a replay function and an
// optional content type. The branch order is deliberate: explicit wrappers first,
// then concrete replayable types, then the narrowest interfaces. | prepareBody 把请求正文
// 归类为 reader、重放函数与可选 Content-Type。分支顺序是刻意安排的：先显式包装类型，
// 再具体可重放类型，最后才是更宽的接口。
func prepareBody(v any) (io.ReadCloser, func() (io.ReadCloser, error), string, error) {
	body, getBody, contentType, _, err := prepareBodyInfo(v)
	return body, getBody, contentType, err
}

// prepareBodyInfo also returns the known content length, or -1 when unknown. | prepareBodyInfo
// 还返回已知正文长度，未知时为 -1。
func prepareBodyInfo(v any) (io.ReadCloser, func() (io.ReadCloser, error), string, int64, error) {
	switch body := v.(type) {
	case nil:
		return nil, nil, "", 0, nil
	case JSONBody:
		data, err := json.Marshal(body.Value)
		if err != nil {
			return nil, nil, "", 0, errs.Wrap(err, ErrEncodeBody)
		}
		return bytesBody(data), bytesGetBody(data), "application/json", int64(len(data)), nil
	case MultipartBody:
		return prepareMultipartBody(body)
	case XMLBody:
		data, err := xml.Marshal(body.Value)
		if err != nil {
			return nil, nil, "", 0, errs.Wrap(err, ErrEncodeBody)
		}
		return bytesBody(data), bytesGetBody(data), "application/xml", int64(len(data)), nil
	case FormBody:
		data := []byte(body.Values.Encode())
		return bytesBody(data), bytesGetBody(data), "application/x-www-form-urlencoded", int64(len(data)), nil
	case json.RawMessage:
		return bytesBody(body), bytesGetBody(body), "application/json", int64(len(body)), nil
	case []byte:
		return bytesBody(body), bytesGetBody(body), "", int64(len(body)), nil
	case string:
		return stringBody(body), stringGetBody(body), "", int64(len(body)), nil
	case *bytes.Buffer:
		if body == nil {
			return nil, nil, "", 0, nil
		}
		data := body.Bytes()
		return bytesBody(data), bytesGetBody(data), "", int64(len(data)), nil
	case *os.File:
		if body == nil {
			return nil, nil, "", 0, nil
		}
		return prepareFileBody(body)
	case io.ReadCloser:
		// A closer other than *os.File is owned by the request and is closed after
		// the first send; replaying it would be unsafe, so it stays one-shot. | 除
		// *os.File 外的 Closer 由请求持有并在首次发送后关闭，重放不安全，因此只允许一次性使用。
		return body, nil, "", -1, nil
	case readerAtSeeker:
		return prepareReaderAtBody(body)
	case io.ReadSeeker:
		return prepareSeekerBody(body)
	case io.Reader:
		return io.NopCloser(body), nil, "", -1, nil
	default:
		data, err := json.Marshal(v)
		if err != nil {
			return nil, nil, "", 0, errs.Wrap(err, ErrEncodeBody)
		}
		return bytesBody(data), bytesGetBody(data), "application/json", int64(len(data)), nil
	}
}

// errSpoolDowngrade signals that a body was restored after exceeding the
// in-memory spool limit and should be sent once without retry. | errSpoolDowngrade
// 表示正文超过内存暂存上限后已恢复，应只发送一次而不重试。
var errSpoolDowngrade = errs.New("client: body spool downgraded | client：正文暂存已降级")

// spool is a replayable request body snapshot. | spool 是可重放的请求正文快照。
type spool struct {
	getBody func() (io.ReadCloser, error)
	cleanup func()
	length  int64
	refs    atomic.Int32
	once    sync.Once
}

// retain adds one user of the spool. | retain 增加一个 spool 使用者。
func (s *spool) retain() {
	if s != nil {
		s.refs.Add(1)
	}
}

// release drops one user and cleans up at zero. | release 释放一个使用者，归零时清理。
func (s *spool) release() {
	if s == nil {
		return
	}
	if s.refs.Add(-1) == 0 {
		s.once.Do(s.cleanup)
	}
}

// open returns a body whose Close releases its spool reference. | open 返回关闭时释放 spool 引用的正文。
func (s *spool) open() (io.ReadCloser, error) {
	if s == nil {
		return nil, ErrBodyNotReplayable
	}
	s.retain()
	body, err := s.getBody()
	if err != nil {
		s.release()
		return nil, err
	}
	return &spoolReader{body: body, spool: s}, nil
}

// spoolReader releases the spool when its body is closed. | spoolReader 在正文关闭时释放 spool。
type spoolReader struct {
	body  io.ReadCloser
	spool *spool
	once  sync.Once
}

// Read reads the replay body. | Read 读取重放正文。
func (r *spoolReader) Read(p []byte) (int, error) { return r.body.Read(p) }

// Close closes the body and releases the spool reference. | Close 关闭正文并释放 spool 引用。
func (r *spoolReader) Close() error {
	r.once.Do(func() {
		_ = r.body.Close()
		r.spool.release()
	})
	return nil
}

// spoolBody snapshots a non-replayable request body into memory or a temp file. | spoolBody 把不可重放正文暂存到内存或临时文件。
func (e *engine) spoolBody(req *http.Request) (*spool, error) {
	return e.spoolBodyWith(req, e.opts.SpoolToDisk)
}

// spoolBodyWith snapshots a body with explicit disk permission. | spoolBodyWith 以显式磁盘许可暂存正文。
func (e *engine) spoolBodyWith(req *http.Request, toDisk bool) (*spool, error) {
	if req == nil || req.Body == nil {
		return nil, ErrBodyNotReplayable
	}
	limit := e.opts.SpoolLimit
	max := e.opts.SpoolMaxBytes
	if ap := e.opts.AccessPolicy; ap != nil && ap.MaxRequestBytes > 0 && (max <= 0 || ap.MaxRequestBytes < max) {
		max = ap.MaxRequestBytes
	}
	if limit <= 0 && !toDisk {
		return nil, ErrBodyNotReplayable
	}
	if limit > 0 {
		readLimit := limit
		if max > 0 && max < readLimit {
			readLimit = max
		}
		data, err := io.ReadAll(io.LimitReader(req.Body, saturatingPlusOne(readLimit)))
		if err != nil {
			_ = req.Body.Close()
			return nil, err
		}
		if max > 0 && int64(len(data)) > max {
			_ = req.Body.Close()
			return nil, errs.Detail(ErrRequestTooLarge, "request body exceeds %d bytes | 请求正文超过 %d 字节", max, max)
		}
		if int64(len(data)) <= limit {
			_ = req.Body.Close()
			getBody := func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(data)), nil
			}
			sp := &spool{getBody: getBody, cleanup: func() {}, length: int64(len(data))}
			sp.refs.Store(1)
			return sp, nil
		}
		if !toDisk {
			// Preserve the bytes already read and let the caller downgrade to a
			// single streaming attempt. | 保留已读字节，让调用方降级为单次流式尝试。
			req.Body = &multiReadCloser{Reader: io.MultiReader(bytes.NewReader(data), req.Body), closer: req.Body}
			return nil, errSpoolDowngrade
		}
		return spoolToFile(data, req.Body, max)
	}
	return spoolToFile(nil, req.Body, max)
}

// spoolToFile writes the prefix and remaining body into a temp file. | spoolToFile 把前缀与剩余正文写入临时文件。
func spoolToFile(prefix []byte, rest io.ReadCloser, max int64) (*spool, error) {
	if rest == nil {
		return nil, ErrBodyNotReplayable
	}
	file, err := os.CreateTemp("", "ydx-client-body-*")
	if err != nil {
		_ = rest.Close()
		return nil, err
	}
	name := file.Name()
	cleanup := func() { _ = os.Remove(name) }
	if len(prefix) > 0 {
		if _, err := file.Write(prefix); err != nil {
			_ = file.Close()
			_ = rest.Close()
			cleanup()
			return nil, err
		}
	}
	remaining := int64(-1)
	if max > 0 {
		remaining = max - int64(len(prefix))
		if remaining < 0 {
			_ = file.Close()
			_ = rest.Close()
			cleanup()
			return nil, errs.Detail(ErrRequestTooLarge, "request body exceeds %d bytes | 请求正文超过 %d 字节", max, max)
		}
	}
	var source io.Reader = rest
	if remaining >= 0 {
		source = io.LimitReader(rest, saturatingPlusOne(remaining))
	}
	copied, err := io.Copy(file, source)
	if err != nil {
		_ = file.Close()
		_ = rest.Close()
		cleanup()
		return nil, err
	}
	if remaining >= 0 && copied > remaining {
		_ = file.Close()
		_ = rest.Close()
		cleanup()
		return nil, errs.Detail(ErrRequestTooLarge, "request body exceeds %d bytes | 请求正文超过 %d 字节", max, max)
	}
	_ = rest.Close()
	info, statErr := file.Stat()
	if statErr != nil {
		_ = file.Close()
		cleanup()
		return nil, statErr
	}
	if err := file.Close(); err != nil {
		cleanup()
		return nil, err
	}
	getBody := func() (io.ReadCloser, error) {
		return os.Open(name)
	}
	sp := &spool{getBody: getBody, cleanup: cleanup, length: info.Size()}
	sp.refs.Store(1)
	return sp, nil
}

// prepareFileBody keeps the original file as the primary body and reopens its path
// for each replay, so primary and mirror readers own independent descriptors. | prepareFileBody
// 把原文件作为主正文，并为每次重放按路径重新打开，使主请求与镜像各自持有独立描述符。
func prepareFileBody(f *os.File) (io.ReadCloser, func() (io.ReadCloser, error), string, int64, error) {
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return f, nil, "", -1, nil
	}
	name := f.Name()
	if name == "" {
		return f, nil, "", -1, nil
	}
	offset, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		offset = 0
	}
	getBody := func() (io.ReadCloser, error) {
		next, err := os.Open(name)
		if err != nil {
			return nil, err
		}
		if offset != 0 {
			if _, err := next.Seek(offset, io.SeekStart); err != nil {
				_ = next.Close()
				return nil, err
			}
		}
		return next, nil
	}
	length := info.Size() - offset
	if length < 0 {
		length = -1
	}
	return f, getBody, "", length, nil
}

// prepareReaderAtBody uses ReadAt-based section readers so every replay is
// independent and safe to read concurrently; the primary consumes the original. | prepareReaderAtBody
// 使用基于 ReadAt 的区间 reader，使每次重放相互独立且可并发读取；主请求消费原 reader。
func prepareReaderAtBody(body readerAtSeeker) (io.ReadCloser, func() (io.ReadCloser, error), string, int64, error) {
	offset, size, err := readerRange(body)
	if err != nil {
		return nil, nil, "", 0, err
	}
	length := size - offset
	if length < 0 {
		return nil, nil, "", 0, errs.Detail(ErrBodyNotReplayable, "invalid reader position | 非法的 reader 位置")
	}
	getBody := func() (io.ReadCloser, error) {
		return io.NopCloser(io.NewSectionReader(body, offset, length)), nil
	}
	if reader, ok := body.(io.Reader); ok {
		return wrapReader(reader), getBody, "", length, nil
	}
	primary, err := getBody()
	if err != nil {
		return nil, nil, "", 0, err
	}
	return primary, getBody, "", length, nil
}

// prepareSeekerBody replays by seeking back to the original offset and preserves
// the underlying Close when present; callers needing concurrent readers must spool. | prepareSeekerBody
// 通过 seek 回原偏移重放，并保留底层 Close；需要并发 reader 的调用方必须自行暂存。
func prepareSeekerBody(body io.ReadSeeker) (io.ReadCloser, func() (io.ReadCloser, error), string, int64, error) {
	offset, err := body.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, nil, "", 0, errs.Wrap(err, ErrBodyNotReplayable)
	}
	_ = offset
	// A shared seeker cannot be replayed concurrently (mirror fan-out); treat
	// it as one-shot and let retry spool it. | 共享 seeker 无法并发重放（镜像扇出）；
	// 按一次性处理，由重试负责暂存。
	return wrapReader(body), nil, "", -1, nil
}

// readerRange returns the current offset and total size of a ReaderAt+Seeker. | readerRange 返回 ReaderAt+Seeker 的当前偏移与总大小。
func readerRange(body readerAtSeeker) (offset, size int64, err error) {
	if sizer, ok := body.(interface{ Size() int64 }); ok {
		size = sizer.Size()
		if lener, ok := body.(interface{ Len() int }); ok {
			offset = size - int64(lener.Len())
			if offset >= 0 && offset <= size {
				return offset, size, nil
			}
		}
	}
	offset, err = body.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, 0, errs.Wrap(err, ErrBodyNotReplayable)
	}
	size, err = body.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, 0, errs.Wrap(err, ErrBodyNotReplayable)
	}
	if _, err := body.Seek(offset, io.SeekStart); err != nil {
		return 0, 0, errs.Wrap(err, ErrBodyNotReplayable)
	}
	return offset, size, nil
}

// wrapReader returns r as a ReadCloser without hiding an existing Close. | wrapReader 把 r 转为 ReadCloser，且不隐藏已有的 Close。
func wrapReader(r io.Reader) io.ReadCloser {
	if rc, ok := r.(io.ReadCloser); ok {
		return rc
	}
	return io.NopCloser(r)
}

// bytesBody wraps a byte slice in a reader without copying. | bytesBody 以不复制的方式把字节切片包装为 reader。
func bytesBody(b []byte) io.ReadCloser {
	return io.NopCloser(bytes.NewReader(b))
}

// bytesGetBody returns a replay function over the same byte slice. | bytesGetBody 返回同一字节切片上的重放函数。
func bytesGetBody(b []byte) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(b)), nil
	}
}

// stringBody wraps a string in a reader without converting it to a byte slice. | stringBody 以不复制的方式把字符串包装为 reader。
func stringBody(s string) io.ReadCloser {
	return io.NopCloser(strings.NewReader(s))
}

// stringGetBody returns a replay function over the same string. | stringGetBody 返回同一字符串上的重放函数。
func stringGetBody(s string) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(s)), nil
	}
}
