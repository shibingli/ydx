package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/shibingli/ydx/errs"
)

// stepHeaderFunc computes one header from the current variables. | stepHeaderFunc 从当前变量计算一个请求头。
type stepHeaderFunc struct {
	fn  func(*Vars) string
	key string
}

// StepBuilder builds one HTTP pipeline step. | StepBuilder 构建一个 HTTP Pipeline 步骤。
type StepBuilder struct {
	body        any
	headers     http.Header
	query       url.Values
	bodyFunc    func(*Vars) (io.Reader, error)
	jsonFunc    func(*Vars) any
	urlFunc     func(*Vars) string
	expect      map[int]bool
	when        func(*Vars) bool
	name        string
	method      string
	target      string
	headerFuncs []stepHeaderFunc
	extractors  []Extractor
	timeout     time.Duration
	maxBody     int64
	required    bool
}

// Step creates a pipeline step. | Step 创建一个 Pipeline 步骤。
func Step(name string) *StepBuilder {
	return &StepBuilder{name: name, method: http.MethodGet, required: true}
}

// Method sets the method and target path or URL. | Method 设置方法与目标路径或 URL。
func (s *StepBuilder) Method(method, target string) *StepBuilder {
	s.method = method
	s.target = target
	return s
}

// GET sets a GET target. | GET 设置 GET 目标。
func (s *StepBuilder) GET(target string) *StepBuilder { return s.Method(http.MethodGet, target) }

// HEAD sets a HEAD target. | HEAD 设置 HEAD 目标。
func (s *StepBuilder) HEAD(target string) *StepBuilder { return s.Method(http.MethodHead, target) }

// POST sets a POST target. | POST 设置 POST 目标。
func (s *StepBuilder) POST(target string) *StepBuilder { return s.Method(http.MethodPost, target) }

// PUT sets a PUT target. | PUT 设置 PUT 目标。
func (s *StepBuilder) PUT(target string) *StepBuilder { return s.Method(http.MethodPut, target) }

// PATCH sets a PATCH target. | PATCH 设置 PATCH 目标。
func (s *StepBuilder) PATCH(target string) *StepBuilder { return s.Method(http.MethodPatch, target) }

// DELETE sets a DELETE target. | DELETE 设置 DELETE 目标。
func (s *StepBuilder) DELETE(target string) *StepBuilder { return s.Method(http.MethodDelete, target) }

// OPTIONS sets an OPTIONS target. | OPTIONS 设置 OPTIONS 目标。
func (s *StepBuilder) OPTIONS(target string) *StepBuilder {
	return s.Method(http.MethodOptions, target)
}

// Header adds a static request header. | Header 添加静态请求头。
func (s *StepBuilder) Header(key, value string) *StepBuilder {
	if s.headers == nil {
		s.headers = make(http.Header)
	}
	s.headers.Add(key, value)
	return s
}

// HeaderFunc adds a variable-driven request header. | HeaderFunc 添加变量驱动的请求头。
func (s *StepBuilder) HeaderFunc(key string, fn func(*Vars) string) *StepBuilder {
	s.headerFuncs = append(s.headerFuncs, stepHeaderFunc{key: key, fn: fn})
	return s
}

// Query adds a query parameter. | Query 添加查询参数。
func (s *StepBuilder) Query(key, value string) *StepBuilder {
	if s.query == nil {
		s.query = make(url.Values)
	}
	s.query.Add(key, value)
	return s
}

// JSON sets the request body to a JSON-encoded value. | JSON 把请求正文设为 JSON 编码值。
func (s *StepBuilder) JSON(value any) *StepBuilder {
	s.body = value
	s.jsonFunc = nil
	return s
}

// JSONFunc computes the JSON body from variables. | JSONFunc 从变量计算 JSON 正文。
func (s *StepBuilder) JSONFunc(fn func(*Vars) any) *StepBuilder {
	s.jsonFunc = fn
	return s
}

// Body sets a streaming request body. | Body 设置流式请求正文。
func (s *StepBuilder) Body(reader io.Reader) *StepBuilder {
	s.body = reader
	return s
}

// BodyFunc computes a streaming body from variables. | BodyFunc 从变量计算流式正文。
func (s *StepBuilder) BodyFunc(fn func(*Vars) (io.Reader, error)) *StepBuilder {
	s.bodyFunc = fn
	return s
}

// URLFunc computes the target URL from variables. | URLFunc 从变量计算目标 URL。
func (s *StepBuilder) URLFunc(fn func(*Vars) string) *StepBuilder {
	s.urlFunc = fn
	return s
}

// Timeout bounds the step. | Timeout 限制步骤耗时。
func (s *StepBuilder) Timeout(d time.Duration) *StepBuilder {
	s.timeout = d
	return s
}

// ExpectStatus overrides the accepted status set. | ExpectStatus 覆盖可接受状态集合。
func (s *StepBuilder) ExpectStatus(codes ...int) *StepBuilder {
	s.expect = make(map[int]bool, len(codes))
	for _, code := range codes {
		s.expect[code] = true
	}
	return s
}

// Required marks the step as required or optional. | Required 标记步骤为必需或可选。
func (s *StepBuilder) Required(required bool) *StepBuilder {
	s.required = required
	return s
}

// When skips the step when fn returns false. | When 在 fn 返回 false 时跳过步骤。
func (s *StepBuilder) When(fn func(*Vars) bool) *StepBuilder {
	s.when = fn
	return s
}

// MaxBodyBytes caps the buffered response body. | MaxBodyBytes 限制缓冲的响应正文。
func (s *StepBuilder) MaxBodyBytes(n int64) *StepBuilder {
	s.maxBody = n
	return s
}

// ExtractJSON appends a JSON path extractor. | ExtractJSON 追加 JSON 路径提取器。
func (s *StepBuilder) ExtractJSON(name, path string) *StepBuilder {
	s.extractors = append(s.extractors, ExtractJSON(name, path))
	return s
}

// ExtractHeader appends a header extractor. | ExtractHeader 追加请求头提取器。
func (s *StepBuilder) ExtractHeader(name, header string) *StepBuilder {
	s.extractors = append(s.extractors, ExtractHeader(name, header))
	return s
}

// ExtractStatus appends a status extractor. | ExtractStatus 追加状态码提取器。
func (s *StepBuilder) ExtractStatus(name string) *StepBuilder {
	s.extractors = append(s.extractors, ExtractStatus(name))
	return s
}

// ExtractBody appends a body extractor. | ExtractBody 追加正文提取器。
func (s *StepBuilder) ExtractBody(name string) *StepBuilder {
	s.extractors = append(s.extractors, ExtractBody(name))
	return s
}

// ExtractRegexp appends a regexp capture extractor. | ExtractRegexp 追加正则捕获提取器。
func (s *StepBuilder) ExtractRegexp(name, pattern string, group int) *StepBuilder {
	s.extractors = append(s.extractors, ExtractRegexp(name, pattern, group))
	return s
}

// ExtractFunc appends a custom extractor. | ExtractFunc 追加自定义提取器。
func (s *StepBuilder) ExtractFunc(name string, fn func(*Response, *Vars) error) *StepBuilder {
	s.extractors = append(s.extractors, ExtractFunc(name, fn))
	return s
}

// run implements Node. | run 实现 Node。
func (s *StepBuilder) run(rs *runState) error {
	if s == nil || rs == nil || s.name == "" {
		return errs.Detail(ErrPipelineStep, "empty step | 空步骤")
	}
	vars := rs.shared.vars
	if s.when != nil && !s.when(vars) {
		result := &StepResult{Name: s.name, Skipped: true}
		rs.record(result)
		rs.stepSkip(s.name)
		return nil
	}
	start := time.Now()
	rs.stepStart(s.name)
	ctx := rs.ctx
	var cancel context.CancelFunc
	if s.timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}
	target := s.target
	if s.urlFunc != nil {
		target = s.urlFunc(vars)
	}
	if target == "" {
		return s.finish(rs, start, 0, nil, nil, nil, errs.Detail(ErrPipelineStep, "empty step target | 空步骤目标"))
	}
	body := s.body
	if s.jsonFunc != nil {
		body = s.jsonFunc(vars)
	}
	if s.bodyFunc != nil {
		reader, err := s.bodyFunc(vars)
		if err != nil {
			return s.finish(rs, start, 0, nil, nil, nil, err)
		}
		body = reader
	}
	options := make([]RequestOption, 0, len(s.headers)+len(s.headerFuncs)+len(s.query))
	for key, values := range s.headers {
		for _, value := range values {
			options = append(options, WithRequestHeader(key, value))
		}
	}
	for _, header := range s.headerFuncs {
		if header.fn != nil {
			options = append(options, WithRequestHeader(header.key, header.fn(vars)))
		}
	}
	for key, values := range s.query {
		for _, value := range values {
			options = append(options, WithRequestQuery(key, value))
		}
	}
	if err := rs.acquire(ctx); err != nil {
		return s.finish(rs, start, 0, nil, nil, nil, err)
	}
	resp, err := rs.shared.client.Send(ctx, s.method, target, body, options...)
	rs.release()
	if err != nil {
		return s.finish(rs, start, 0, nil, nil, nil, err)
	}
	maxBody := s.maxBody
	if maxBody <= 0 {
		maxBody = rs.shared.opts.MaxBodyBytes
	}
	if maxBody <= 0 {
		maxBody = 4 << 20
	}
	if isEventStream(resp.Header) {
		_ = resp.Body.Close()
		return s.finish(rs, start, resp.StatusCode, resp.Header, nil, nil, ErrPipelineStream)
	}
	data, err := resp.BytesLimit(maxBody)
	if err != nil {
		if errors.Is(err, ErrResponseTooLarge) {
			err = errs.Detail(ErrPipelineBodyTooLarge, "max %d bytes | 上限 %d 字节", maxBody, maxBody)
		}
		return s.finish(rs, start, resp.StatusCode, resp.Header, nil, nil, err)
	}
	copied := *resp.Response
	copied.Body = io.NopCloser(bytes.NewReader(data))
	copied.ContentLength = int64(len(data))
	result := &StepResult{
		Name:     s.name,
		Status:   resp.StatusCode,
		Headers:  resp.Header.Clone(),
		Body:     data,
		Response: &Response{Response: &copied, Meta: resp.Meta},
		Duration: time.Since(start),
		Attempts: resp.Meta.Attempts,
	}
	if !s.statusOK(resp.StatusCode) {
		result.Err = errs.Detail(ErrPipelineStatus, "status %d | 状态码 %d", resp.StatusCode, resp.StatusCode)
		rs.record(result)
		rs.stepDone(result)
		if s.required {
			return &PipelineError{Step: s.name, Err: result.Err}
		}
		return nil
	}
	for _, extractor := range s.extractors {
		if err := extractor.apply(extractContext{
			Status: resp.StatusCode,
			Header: resp.Header.Clone(),
			Body:   data,
		}, vars); err != nil {
			result.Err = err
			rs.record(result)
			rs.stepDone(result)
			if s.required {
				return &PipelineError{Step: s.name, Err: err}
			}
			return nil
		}
	}
	rs.record(result)
	rs.stepDone(result)
	return nil
}

// finish records a failed step and applies the required policy. | finish 记录失败步骤并应用必需策略。
func (s *StepBuilder) finish(rs *runState, start time.Time, status int, header http.Header, body []byte, response *Response, err error) error {
	result := &StepResult{
		Name:     s.name,
		Status:   status,
		Headers:  header,
		Body:     body,
		Response: response,
		Err:      err,
		Duration: time.Since(start),
	}
	rs.record(result)
	rs.stepDone(result)
	if err != nil && s.required {
		return &PipelineError{Step: s.name, Err: err}
	}
	return nil
}

// statusOK reports whether status is accepted by the step. | statusOK 报告状态码是否被步骤接受。
func (s *StepBuilder) statusOK(status int) bool {
	if len(s.expect) == 0 {
		return status >= 200 && status < 300
	}
	return s.expect[status]
}
