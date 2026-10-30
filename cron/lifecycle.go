package cron

import (
	"context"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Add validates and schedules a job. | Add 校验并调度任务。
//
// A blank ID is generated. When a Store is configured the definition is written
// before the job becomes visible and Task is required. | 空 ID 会自动生成；配置 Store 时，
// 定义先写入存储再对调度可见，且必须提供 Task。
func (s *Scheduler) Add(ctx context.Context, job *Job) error {
	if ctx == nil {
		ctx = context.Background()
	}
	store := s.options.Store
	// Without a Store the operation is a pure in-memory mutation, so s.mu alone
	// serializes it; opMu is only needed to order Store writes with the table. |
	// 没有 Store 时操作是纯内存变更，s.mu 已足够串行化；只有需要让存储写入与任务表
	// 保持顺序时才使用 opMu。
	if store != nil {
		s.opMu.Lock()
		defer s.opMu.Unlock()

		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return ErrSchedulerClosed
		}
		if job != nil && job.ID != "" {
			if _, exists := s.entries[job.ID]; exists {
				s.mu.Unlock()
				return errs.Detail(ErrJobExists, "%q", job.ID)
			}
		}
		s.mu.Unlock()
	}

	// Validate cheaply before allocating the box so a nil job or schedule does not
	// pay for 448 bytes that are immediately discarded. | 先做廉价校验再分配元素块，
	// 避免 nil 任务或调度白付 448 字节。
	if job == nil {
		return ErrNilJob
	}
	if job.Schedule == nil {
		return ErrNilSchedule
	}
	box := new(entryBox)
	definition, next, err := s.prepareJobInto(job, &box.job)
	if err != nil {
		return err
	}
	if store != nil {
		if saveErr := store.Save(ctx, definition); saveErr != nil {
			return errs.WrapDetail(saveErr, ErrStoreFailed, "%q", box.job.ID)
		}
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrSchedulerClosed
	}
	if _, exists := s.entries[box.job.ID]; exists {
		s.mu.Unlock()
		return errs.Detail(ErrJobExists, "%q", box.job.ID)
	}
	box.item.job = &box.job
	box.item.definition = definition
	box.item.index = -1
	item := &box.item
	s.entries[box.job.ID] = item
	if armErr := s.armLocked(item, next, false); armErr != nil {
		delete(s.entries, box.job.ID)
		s.mu.Unlock()
		return armErr
	}
	s.version++
	s.mu.Unlock()

	s.signal()
	job.ID = box.job.ID
	return nil
}

// Update replaces the definition of an existing job while preserving its
// statistics and history. | Update 替换既有任务的定义，同时保留统计与历史。
func (s *Scheduler) Update(ctx context.Context, job *Job) error {
	if job == nil {
		return ErrNilJob
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if job.ID == "" {
		return errs.Detail(ErrJobNotFound, "%q", "")
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrSchedulerClosed
	}
	current, exists := s.entries[job.ID]
	if !exists {
		s.mu.Unlock()
		return errs.Detail(ErrJobNotFound, "%q", job.ID)
	}
	s.mu.Unlock()

	var prepared Job
	definition, next, err := s.prepareJobInto(job, &prepared)
	if err != nil {
		return err
	}
	if s.options.Store != nil {
		if saveErr := s.options.Store.Save(ctx, definition); saveErr != nil {
			return errs.WrapDetail(saveErr, ErrStoreFailed, "%q", prepared.ID)
		}
	}

	s.mu.Lock()
	item, stillThere := s.entries[prepared.ID]
	if !stillThere || item != current {
		s.mu.Unlock()
		return errs.Detail(ErrJobNotFound, "%q", prepared.ID)
	}
	item.job = &prepared
	item.definition = definition
	if prepared.Disabled {
		s.unarmLocked(item)
	} else if armErr := s.armLocked(item, next, true); armErr != nil {
		s.mu.Unlock()
		return armErr
	}
	s.mu.Unlock()

	s.signal()
	return nil
}

// Remove deletes a job and its history. | Remove 删除任务及其历史。
func (s *Scheduler) Remove(ctx context.Context, id string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	store := s.options.Store
	if store == nil {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return ErrSchedulerClosed
		}
		item, exists := s.entries[id]
		if !exists {
			s.mu.Unlock()
			return errs.Detail(ErrJobNotFound, "%q", id)
		}
		delete(s.entries, id)
		s.unarmLocked(item)
		item.removed.Store(true)
		s.version++
		s.mu.Unlock()
		s.signal()
		return nil
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrSchedulerClosed
	}
	item, exists := s.entries[id]
	if !exists {
		s.mu.Unlock()
		return errs.Detail(ErrJobNotFound, "%q", id)
	}
	s.mu.Unlock()

	if err := store.Delete(ctx, id); err != nil {
		return errs.WrapDetail(err, ErrStoreFailed, "%q", id)
	}

	s.mu.Lock()
	if current, ok := s.entries[id]; ok && current == item {
		delete(s.entries, id)
		s.unarmLocked(item)
		item.removed.Store(true)
		s.version++
	}
	s.mu.Unlock()
	s.signal()
	return nil
}

// Pause stops scheduled activation while keeping the definition. |
// Pause 停止计划触发但保留定义。
func (s *Scheduler) Pause(ctx context.Context, id string) error {
	return s.setDisabled(ctx, id, true)
}

// Resume re-enables scheduled activation. | Resume 重新启用计划触发。
func (s *Scheduler) Resume(ctx context.Context, id string) error {
	return s.setDisabled(ctx, id, false)
}

// setDisabled is the shared implementation of Pause and Resume. |
// setDisabled 是 Pause 与 Resume 的共同实现。
func (s *Scheduler) setDisabled(ctx context.Context, id string, disabled bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrSchedulerClosed
	}
	item, exists := s.entries[id]
	if !exists {
		s.mu.Unlock()
		return errs.Detail(ErrJobNotFound, "%q", id)
	}
	if item.job.Disabled == disabled {
		s.mu.Unlock()
		return nil
	}
	nextJob := *item.job
	nextJob.Disabled = disabled
	var next time.Time
	if !disabled {
		next = nextJob.Schedule.Next(s.now())
		if next.IsZero() {
			s.mu.Unlock()
			return ErrNoFutureRun
		}
	}
	s.mu.Unlock()

	definition := nextJob.Definition()
	if s.options.Store != nil {
		if err := s.options.Store.Save(ctx, definition); err != nil {
			return errs.WrapDetail(err, ErrStoreFailed, "%q", id)
		}
	}

	s.mu.Lock()
	if current, ok := s.entries[id]; ok && current == item {
		item.job = &nextJob
		item.definition = definition
		if disabled {
			s.unarmLocked(item)
		} else {
			_ = s.armLocked(item, next, false)
		}
	}
	s.mu.Unlock()
	s.signal()
	return nil
}

// Reload makes the in-memory job table match the Store, applying additions,
// replacements and removals while preserving the statistics of jobs that stay.
// It is how another node picks up a definition written by this one without a
// restart; call it periodically or after an administrative change elsewhere. |
// Reload 使内存任务表与 Store 一致：应用新增、替换与删除，同时保留仍存在任务的统计。
// 其它节点无需重启即可通过它拾取本节点写入的定义；可周期调用或在别处完成管理变更后调用。
//
// Every definition is validated before anything changes, so one bad row leaves
// the running table untouched. Reload requires a Store (ErrNoStore) and reports
// a missing handler before applying any change. | 所有定义先校验再变更，单条坏数据不会污染
// 运行中的任务表。Reload 需要 Store（ErrNoStore），并在应用变更前报告缺失的处理器。
func (s *Scheduler) Reload(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.options.Store == nil {
		return ErrNoStore
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()

	definitions, err := s.options.Store.List(ctx)
	if err != nil {
		return errs.Wrap(err, ErrStoreFailed)
	}
	desired := make(map[string]jobDef, len(definitions))
	for _, definition := range definitions {
		job, restoreErr := s.restoreJob(definition)
		if restoreErr != nil {
			return restoreErr
		}
		desired[job.ID] = jobDef{job: job, definition: definition}
	}

	now := s.now()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrSchedulerClosed
	}
	changed := false
	for id, item := range s.entries {
		if _, keep := desired[id]; !keep {
			delete(s.entries, id)
			s.unarmLocked(item)
			item.removed.Store(true)
			changed = true
		}
	}
	for id, wanted := range desired {
		item, exists := s.entries[id]
		if !exists {
			item = newEntry(wanted.job, wanted.definition)
			s.entries[id] = item
			changed = true
		} else {
			item.job = wanted.job
			item.definition = wanted.definition
		}
		if wanted.job.Disabled {
			s.unarmLocked(item)
			continue
		}
		_ = s.armLocked(item, wanted.job.Schedule.Next(now), false)
	}
	if changed {
		s.version++
	}
	s.mu.Unlock()
	s.signal()
	return nil
}

// Trigger enqueues an immediate run, even when the job is paused. |
// Trigger 立即入队运行，即使任务已暂停。
func (s *Scheduler) Trigger(id string) error {
	s.mu.RLock()
	if s.closed || !s.started || s.exec == nil {
		s.mu.RUnlock()
		return ErrSchedulerNotRunning
	}
	item, exists := s.entries[id]
	if !exists {
		s.mu.RUnlock()
		return errs.Detail(ErrJobNotFound, "%q", id)
	}
	task := runTask{entry: item, job: item.job, trigger: TriggerManual, scheduled: s.now()}
	s.mu.RUnlock()
	return s.enqueue(task)
}
