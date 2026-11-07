package wal

import "sync/atomic"

// counters holds all monotonic WAL counters. | counters 保存全部单调 WAL 计数器。
type counters struct {
	records           atomic.Uint64
	bytes             atomic.Uint64
	syncs             atomic.Uint64
	syncErrors        atomic.Uint64
	groupBatches      atomic.Uint64
	groupRecords      atomic.Uint64
	compressed        atomic.Uint64
	compressedIn      atomic.Uint64
	compressedOut     atomic.Uint64
	dedupRefs         atomic.Uint64
	dedupSaved        atomic.Uint64
	idemHits          atomic.Uint64
	idemConflicts     atomic.Uint64
	streamChunks      atomic.Uint64
	txnCommits        atomic.Uint64
	txnRollbacks      atomic.Uint64
	txnConflicts      atomic.Uint64
	openTxns          atomic.Int64
	keyIndexOver      atomic.Uint64
	keyIndexRebuild   atomic.Uint64
	keyIndexScans     atomic.Uint64
	checkpointErr     atomic.Uint64
	backupQueued      atomic.Uint64
	backupDone        atomic.Uint64
	backupFailed      atomic.Uint64
	backupSnapshots   atomic.Uint64
	backupSnapshotErr atomic.Uint64
	retentionSkip     atomic.Uint64
	cleanupErrors     atomic.Uint64
	recTruncated      atomic.Int64
	recMissingLSNs    atomic.Uint64
}

// snapshot reads every counter. | snapshot 读取全部计数器。
func (c *counters) snapshot() (s Stats) {
	s.Records = c.records.Load()
	s.Bytes = c.bytes.Load()
	s.Syncs = c.syncs.Load()
	s.SyncErrors = c.syncErrors.Load()
	s.GroupBatches = c.groupBatches.Load()
	s.GroupRecords = c.groupRecords.Load()
	s.CompressedRecords = c.compressed.Load()
	s.CompressedBytesIn = c.compressedIn.Load()
	s.CompressedBytesOut = c.compressedOut.Load()
	s.DedupRefs = c.dedupRefs.Load()
	s.DedupSavedBytes = c.dedupSaved.Load()
	s.IdempotentHits = c.idemHits.Load()
	s.IdempotentConflicts = c.idemConflicts.Load()
	s.StreamChunks = c.streamChunks.Load()
	s.TxnCommits = c.txnCommits.Load()
	s.TxnRollbacks = c.txnRollbacks.Load()
	s.TxnConflicts = c.txnConflicts.Load()
	s.OpenTxns = uint64(c.openTxns.Load())
	s.KeyIndexOverflow = c.keyIndexOver.Load()
	s.KeyIndexRebuilds = c.keyIndexRebuild.Load()
	s.KeyIndexScans = c.keyIndexScans.Load()
	s.CheckpointErrors = c.checkpointErr.Load()
	s.BackupQueued = c.backupQueued.Load()
	s.BackupDone = c.backupDone.Load()
	s.BackupFailed = c.backupFailed.Load()
	s.BackupSnapshots = c.backupSnapshots.Load()
	s.BackupSnapshotErrors = c.backupSnapshotErr.Load()
	s.RetentionSkipped = c.retentionSkip.Load()
	s.CleanupErrors = c.cleanupErrors.Load()
	s.RecoveryTruncatedBytes = c.recTruncated.Load()
	s.RecoveryMissingLSNs = c.recMissingLSNs.Load()
	return s
}
