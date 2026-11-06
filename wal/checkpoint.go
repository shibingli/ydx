package wal

import "github.com/shibingli/ydx/errs"

// checkpointJob is an immutable synced-prefix index snapshot. | checkpointJob 是不可变的已同步前缀索引快照。
type checkpointJob struct {
	seg              *segment
	segmentBytes     int64
	lastLSN          uint64
	recordCount      uint64
	minTime          int64
	maxTime          int64
	segmentCRC       uint32
	commitSeq        uint64
	walID            [16]byte
	sparse           []sparseEntry
	keyIndex         map[string][]uint64
	hasKeyIndex      bool
	keyIndexOverflow bool
}

// checkpointLoop writes checkpoint sidecars and MANIFEST kind=3 records. | checkpointLoop
// 写检查点侧车与 MANIFEST kind=3 记录。
func (w *WAL) checkpointLoop() {
	defer w.checkpointWG.Done()
	for {
		select {
		case <-w.checkpointStop:
			return
		case <-w.checkpointNotify:
		}
		w.checkpointMu.Lock()
		job := w.checkpointPending
		w.checkpointPending = nil
		w.checkpointMu.Unlock()
		if job == nil {
			continue
		}
		if err := w.writeCheckpoint(job); err != nil {
			w.counters.checkpointErr.Add(1)
			w.reportAsync(err)
		}
	}
}

// writeCheckpoint writes one checkpoint while excluding the sealer. | writeCheckpoint
// 在排除封段者的前提下写入一个检查点。
func (w *WAL) writeCheckpoint(job *checkpointJob) error {
	seg := job.seg
	seg.checkpointMu.Lock()
	defer seg.checkpointMu.Unlock()
	if seg.currentState() != segmentActive {
		return nil
	}
	s := &sidecar{
		seq:          seg.seq,
		baseLSN:      seg.baseLSN,
		lastLSN:      job.lastLSN,
		recordCount:  job.recordCount,
		segmentBytes: uint64(job.segmentBytes),
		minTime:      job.minTime,
		maxTime:      job.maxTime,
		segmentCRC:   job.segmentCRC,
		walID:        job.walID,
		commitSeq:    job.commitSeq,
		checkpoint:   true,
		hasKeyIndex:  job.hasKeyIndex,
		sparse:       job.sparse,
		keyIndex:     job.keyIndex,
	}
	data := encodeSidecar(s)
	if err := writeFileAtomic(seg.idxPath, data, w.opts.fileMode); err != nil {
		return err
	}
	if !w.manifest.enabled {
		return nil
	}
	return w.manifest.append(manifestRecord{
		kind: manifestKindCheckpoint, seq: seg.seq, baseLSN: seg.baseLSN,
		lastLSN: job.lastLSN, segmentBytes: uint64(job.segmentBytes),
		recordCount: job.recordCount, minTime: job.minTime, maxTime: job.maxTime,
		segmentCRC: job.segmentCRC, idxCRC: checksum(data), walID: job.walID,
		createdNano: seg.createdNano, commitSeq: job.commitSeq,
	})
}

// checkpointError annotates a checkpoint failure. | checkpointError 注解检查点失败。
func checkpointError(err error) error {
	if err == nil {
		return nil
	}
	return errs.Wrap(err, ErrStorage)
}
