package cron

import (
	"slices"
	"strings"
	"time"
)

// Get returns a snapshot of one job. | Get 返回单个任务的快照。
func (s *Scheduler) Get(id string) (Snapshot, bool) {
	s.mu.RLock()
	item, exists := s.entries[id]
	if !exists {
		s.mu.RUnlock()
		return Snapshot{}, false
	}
	snapshot := s.snapshotLocked(item)
	s.mu.RUnlock()
	return snapshot, true
}

// List returns snapshots ordered by job id. The id order is cached across calls
// and rebuilt only when jobs are added or removed, so repeated administrative
// listings do not re-sort the whole table. | List 按任务 ID 排序返回快照。
// ID 顺序跨调用缓存，只在新增或删除任务时重建，因此重复的管理列表不必重排整张表。
func (s *Scheduler) List() []Snapshot {
	s.listMu.Lock()
	defer s.listMu.Unlock()

	s.mu.RLock()
	if s.version != s.cacheVersion {
		items := make([]*entry, 0, len(s.entries))
		for _, item := range s.entries {
			items = append(items, item)
		}
		slices.SortFunc(items, func(a, b *entry) int {
			return strings.Compare(a.job.ID, b.job.ID)
		})
		s.sorted = items
		s.cacheVersion = s.version
	}
	snapshots := make([]Snapshot, len(s.sorted))
	for index, item := range s.sorted {
		snapshots[index] = s.snapshotLocked(item)
	}
	s.mu.RUnlock()
	return snapshots
}

// History returns run records, newest first. | History 返回运行记录，最新在前。
func (s *Scheduler) History(id string) []RunRecord {
	s.mu.RLock()
	item, exists := s.entries[id]
	s.mu.RUnlock()
	if !exists {
		return nil
	}
	return item.stats.historyNewestFirst()
}

// Stats aggregates counters over all jobs. | Stats 汇总所有任务的计数器。
func (s *Scheduler) Stats() Stats {
	s.mu.RLock()
	stats := Stats{Jobs: len(s.entries)}
	if s.exec != nil {
		stats.Queued = s.exec.queued()
	}
	for _, item := range s.entries {
		if !item.job.Disabled {
			stats.Enabled++
		}
		if item.running.Load() > 0 {
			stats.Running++
		}
		stats.Runs += item.stats.runs.Load()
		stats.Failures += item.stats.failures.Load()
		stats.Skipped += item.stats.skipped.Load()
		stats.Dropped += item.stats.dropped.Load()
	}
	s.mu.RUnlock()
	return stats
}

// snapshotLocked builds one Snapshot; the caller holds s.mu for reading or
// writing. | snapshotLocked 构建单个快照；调用方持有 s.mu 的读锁或写锁。
func (s *Scheduler) snapshotLocked(item *entry) Snapshot {
	definition := item.definition
	if len(definition.Metadata) > 0 {
		definition.Metadata = copyMetadata(definition.Metadata)
	}
	snapshot := Snapshot{
		Definition:   definition,
		Next:         item.next,
		LastDuration: time.Duration(item.stats.lastDuration.Load()),
		Running:      item.running.Load() > 0,
		Runs:         item.stats.runs.Load(),
		Failures:     item.stats.failures.Load(),
		Skipped:      item.stats.skipped.Load(),
		Dropped:      item.stats.dropped.Load(),
	}
	if nanos := item.stats.lastRun.Load(); nanos != 0 {
		snapshot.LastRun = time.Unix(0, nanos).UTC()
	}
	snapshot.LastError = item.stats.lastError()
	return snapshot
}
