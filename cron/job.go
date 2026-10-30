package cron

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/errs"
)

// idFallback guarantees a unique id even if the operating system random source
// fails; the counter keeps ids from two calls in the same nanosecond distinct. |
// idFallback 在操作系统随机源失败时仍保证 ID 唯一；计数器让同一纳秒内的两次调用互不相同。
var idFallback atomic.Uint64

// newJobID returns a random 96-bit identifier in hex. | newJobID 返回 96 位随机十六进制标识。
func newJobID() string {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return hex.EncodeToString(raw[:])
	}
	return strconv.FormatInt(time.Now().UnixNano(), 36) + "-" + strconv.FormatUint(idFallback.Add(1), 36)
}

// Definition converts a job into its serializable form. | Definition 把任务转换为可序列化形式。
func (j *Job) Definition() Definition {
	definition := Definition{
		ID:            j.ID,
		Name:          j.Name,
		Task:          j.Task,
		Timeout:       j.Timeout,
		Retries:       j.Retries,
		RetryDelay:    j.RetryDelay,
		RetryBackoff:  j.RetryBackoff,
		MaxRetryDelay: j.MaxRetryDelay,
		Jitter:        j.Jitter,
		Singleton:     j.Singleton,
		Disabled:      j.Disabled,
		Overlap:       j.Overlap.normalize(),
	}
	if j.Schedule != nil {
		definition.Expression = j.Schedule.String()
	}
	if spec, ok := j.Schedule.(*Spec); ok && spec != nil {
		definition.Timezone = spec.Location().String()
	}
	if len(j.Metadata) > 0 {
		definition.Metadata = make(map[string]string, len(j.Metadata))
		for key, value := range j.Metadata {
			definition.Metadata[key] = value
		}
	}
	return definition
}

// Job rebuilds a runtime job from the definition without resolving a handler;
// Add and Update resolve it from Task. | Job 从定义重建运行期任务但不解析处理器；
// Add 与 Update 会按 Task 解析。
func (d Definition) Job() (*Job, error) {
	schedule, err := d.Schedule()
	if err != nil {
		return nil, err
	}
	return &Job{
		ID:            d.ID,
		Name:          d.Name,
		Task:          d.Task,
		Schedule:      schedule,
		Metadata:      copyMetadata(d.Metadata),
		Timeout:       d.Timeout,
		Retries:       d.Retries,
		RetryDelay:    d.RetryDelay,
		RetryBackoff:  d.RetryBackoff,
		MaxRetryDelay: d.MaxRetryDelay,
		Jitter:        d.Jitter,
		Singleton:     d.Singleton,
		Disabled:      d.Disabled,
		Overlap:       d.Overlap.normalize(),
	}, nil
}

// Schedule rebuilds the schedule described by the definition. | Schedule 重建定义所描述的调度。
func (d Definition) Schedule() (Schedule, error) {
	loc := time.Local
	if d.Timezone != "" {
		zone, err := time.LoadLocation(d.Timezone)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidDefinition, "time zone %q", d.Timezone)
		}
		loc = zone
	}
	schedule, err := ParseIn(d.Expression, loc)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidDefinition, "%q", d.Expression)
	}
	return schedule, nil
}

// prepareJobInto validates a job, fills its ID, resolves its handler and
// normalizes its policy fields, writing the private copy into dst. Add passes
// the Job embedded in its entry box, so the caller's Job is copied once instead
// of once into a temporary and again into the box. | prepareJobInto 校验任务、
// 补齐 ID、解析处理器并规范化策略字段，把私有副本写入 dst。Add 传入元素块内嵌的 Job，
// 使调用方的 Job 只复制一次，而不是先复制到临时值、再复制进元素块。
func (s *Scheduler) prepareJobInto(job *Job, dst *Job) (Definition, time.Time, error) {
	if job == nil {
		return Definition{}, time.Time{}, ErrNilJob
	}
	if job.Schedule == nil {
		return Definition{}, time.Time{}, ErrNilSchedule
	}

	*dst = *job
	dst.Metadata = copyMetadata(job.Metadata)
	if dst.ID == "" {
		dst.ID = newJobID()
	}
	if dst.Retries < 0 {
		dst.Retries = 0
	}
	if dst.RetryBackoff <= 1 {
		dst.RetryBackoff = 1
	}
	dst.Overlap = dst.Overlap.normalize()

	if dst.Handler == nil {
		if dst.Task == "" {
			return Definition{}, time.Time{}, ErrNilHandler
		}
		handler, ok := s.handler(dst.Task)
		if !ok {
			return Definition{}, time.Time{}, errs.Detail(ErrHandlerNotFound, "%q", dst.Task)
		}
		dst.Handler = handler
	}
	if s.options.Store != nil && dst.Task == "" {
		return Definition{}, time.Time{}, ErrEmptyTask
	}

	definition := dst.Definition()
	if s.options.Store != nil {
		if _, err := definition.Schedule(); err != nil {
			return Definition{}, time.Time{}, err
		}
	}
	next := dst.Schedule.Next(s.now())
	if next.IsZero() && !dst.Disabled {
		return Definition{}, time.Time{}, ErrNoFutureRun
	}
	return definition, next, nil
}

// handler resolves a registered task handler. | handler 解析已注册的任务处理器。
func (s *Scheduler) handler(task string) (Handler, bool) {
	s.handlersMu.RLock()
	handler, ok := s.handlers[task]
	s.handlersMu.RUnlock()
	return handler, ok
}

// copyMetadata clones a metadata map; nil stays nil. | copyMetadata 克隆元数据映射；nil 保持 nil。
func copyMetadata(metadata map[string]string) map[string]string {
	if len(metadata) == 0 {
		return nil
	}
	copied := make(map[string]string, len(metadata))
	for key, value := range metadata {
		copied[key] = value
	}
	return copied
}

// jobDef pairs a runtime job with the definition it was built from. |
// jobDef 把运行期任务与其来源定义配对。
type jobDef struct {
	job        *Job
	definition Definition
}

// restoreJob rebuilds a runtime job from a persisted definition. |
// restoreJob 从持久化定义重建运行期任务。
func (s *Scheduler) restoreJob(definition Definition) (*Job, error) {
	if definition.ID == "" {
		return nil, errs.Detail(ErrInvalidDefinition, "empty id")
	}
	if definition.Task == "" {
		return nil, errs.Detail(ErrInvalidDefinition, "%q has no task", definition.ID)
	}
	handler, ok := s.handler(definition.Task)
	if !ok {
		return nil, errs.Detail(ErrHandlerNotFound, "%q", definition.Task)
	}
	job, err := definition.Job()
	if err != nil {
		return nil, err
	}
	job.Handler = handler
	job.Retries = nonNegative(job.Retries)
	job.RetryBackoff = normalizeBackoff(job.RetryBackoff)
	return job, nil
}

// nonNegative clamps a count to zero. | nonNegative 把计数下限钳制为零。
func nonNegative(value int) int {
	if value < 0 {
		return 0
	}
	return value
}

// normalizeBackoff turns a non-positive or sub-one multiplier into one. |
// normalizeBackoff 把非正或小于一的倍数规范为一。
func normalizeBackoff(value float64) float64 {
	if value <= 1 {
		return 1
	}
	return value
}
