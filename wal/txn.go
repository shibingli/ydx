package wal

import (
	"context"
	"crypto/rand"
	"io"
	"time"

	"github.com/shibingli/ydx/errs"
)

// txnState is the transaction lifecycle. | txnState 是事务生命周期。
type txnState uint8

const (
	txnActive txnState = iota
	txnCommitting
	txnCommitted
	txnFailed
	txnRolledBack
)

// occState is the serializable conflict window. | occState 是可串行化冲突窗口。
type occState struct {
	versions   map[[32]byte]uint64
	history    []occCommit
	minSeq     uint64
	window     uint64
	maxEntries int
}

// occCommit records the write keys of one committed transaction. | occCommit 记录一个已提交事务的写键。
type occCommit struct {
	seq  uint64
	keys [][32]byte
}

// newOCC builds an empty conflict window. | newOCC 构建空冲突窗口。
func newOCC(window uint64, maxEntries int) *occState {
	return &occState{versions: make(map[[32]byte]uint64), window: window, maxEntries: maxEntries}
}

// version returns the last commit sequence that wrote key. | version 返回最后写入 key 的提交序号。
func (o *occState) version(key [32]byte) uint64 { return o.versions[key] }

// apply records one committed serializable transaction and evicts the old
// window. | apply 记录一个已提交的可串行化事务并淘汰旧窗口。
func (o *occState) apply(seq uint64, keys [][32]byte) {
	if len(keys) > 0 {
		for _, k := range keys {
			o.versions[k] = seq
		}
		o.history = append(o.history, occCommit{seq: seq, keys: keys})
	}
	for len(o.history) > 0 && o.history[0].seq+o.window < seq {
		old := o.history[0]
		o.history = o.history[1:]
		for _, k := range old.keys {
			if o.versions[k] == old.seq {
				delete(o.versions, k)
			}
		}
		if old.seq > o.minSeq {
			o.minSeq = old.seq
		}
	}
	for len(o.versions) > o.maxEntries && len(o.history) > 0 {
		old := o.history[0]
		o.history = o.history[1:]
		for _, k := range old.keys {
			if o.versions[k] == old.seq {
				delete(o.versions, k)
			}
		}
		if old.seq > o.minSeq {
			o.minSeq = old.seq
		}
	}
}

// txnOptions carries per-transaction options. | txnOptions 携带单事务选项。
type txnOptions struct {
	isolation IsolationLevel
}

// TxnOption customizes Begin. | TxnOption 定制 Begin。
type TxnOption func(*txnOptions)

// WithTxnIsolation selects the transaction isolation level. | WithTxnIsolation 选择事务隔离级别。
func WithTxnIsolation(l IsolationLevel) TxnOption {
	return func(o *txnOptions) { o.isolation = l }
}

// txRecord is one buffered transaction record. | txRecord 是一条缓冲的事务记录。
type txRecord struct {
	rec         Record
	allowStream bool
}

// txStream tracks one buffered AppendStream call. | txStream 跟踪一次缓冲的 AppendStream 调用。
type txStream struct {
	info        StreamInfo
	firstRecord int
	lastRecord  int
	endRecord   int
	complete    bool
}

// Tx is a log-level ACID transaction. | Tx 是日志级 ACID 事务。
type Tx struct {
	w            *WAL
	isolation    IsolationLevel
	snapshot     Snapshot
	records      []txRecord
	bytes        int64
	payloadBytes int64
	readKeys     [][32]byte
	writeKeys    [][32]byte
	keySet       map[[32]byte]struct{}
	streams      []*txStream
	timestamps   []int64
	lsns         []uint64
	commitSeq    uint64
	state        txnState
}

// Begin starts a transaction. | Begin 启动一个事务。
func (w *WAL) Begin(ctx context.Context, opts ...TxnOption) (*Tx, error) {
	if w.opts.readOnly {
		return nil, ErrReadOnly
	}
	if err := w.poisonedErr(); err != nil {
		return nil, err
	}
	if w.isClosed() {
		return nil, ErrClosed
	}
	to := txnOptions{isolation: w.opts.defaultIsolation}
	for _, fn := range opts {
		if fn != nil {
			fn(&to)
		}
	}
	if to.isolation > IsolationSerializable {
		return nil, errs.Detail(ErrInvalidOptions, "unknown isolation level %[1]d | 未知隔离级别 %[1]d", to.isolation)
	}
	_ = ctx
	tx := &Tx{
		w:         w,
		isolation: to.isolation,
		snapshot:  w.Snapshot(),
		keySet:    make(map[[32]byte]struct{}),
		state:     txnActive,
	}
	w.counters.openTxns.Add(1)
	return tx, nil
}

// Append buffers one record. | Append 缓冲一条记录。
func (tx *Tx) Append(ctx context.Context, rec Record) error {
	if err := tx.checkActive(); err != nil {
		return err
	}
	if ctx != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
	if err := tx.w.validateUserRecord(rec, false); err != nil {
		return err
	}
	return tx.addRecord(rec, false)
}

// AppendBatch buffers a batch of records. | AppendBatch 缓冲一批记录。
func (tx *Tx) AppendBatch(ctx context.Context, recs []Record) error {
	if err := tx.checkActive(); err != nil {
		return err
	}
	for _, rec := range recs {
		if err := tx.w.validateUserRecord(rec, false); err != nil {
			return err
		}
	}
	for _, rec := range recs {
		if err := tx.addRecord(rec, false); err != nil {
			return err
		}
	}
	return nil
}

// AppendStream buffers a chunked stream and returns its preliminary info. | AppendStream
// 缓冲一个分块流并返回其初步信息。
func (tx *Tx) AppendStream(ctx context.Context, r io.Reader, opts ...StreamOption) (StreamInfo, error) {
	if err := tx.checkActive(); err != nil {
		return StreamInfo{}, err
	}
	so := streamOptions{chunkSize: tx.w.opts.streamChunkSize}
	for _, fn := range opts {
		if fn != nil {
			fn(&so)
		}
	}
	if so.chunkSize <= 0 {
		so.chunkSize = tx.w.opts.streamChunkSize
	}
	id, err := newStreamID()
	if err != nil {
		return StreamInfo{}, err
	}
	s := &txStream{info: StreamInfo{ID: id}, firstRecord: -1, lastRecord: -1, endRecord: -1}
	buf := make([]byte, so.chunkSize)
	for {
		if ctx != nil {
			select {
			case <-ctx.Done():
				return s.info, ctx.Err()
			default:
			}
		}
		n, rerr := io.ReadFull(r, buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			rec := Record{Flags: FlagStreamChunk, Key: id[:], Data: chunk}
			if err := tx.addRecord(rec, true); err != nil {
				return s.info, err
			}
			if s.firstRecord < 0 {
				s.firstRecord = len(tx.records) - 1
			}
			s.lastRecord = len(tx.records) - 1
			s.info.Chunks++
			s.info.Bytes += uint64(n)
			tx.streams = appendStreamOnce(tx.streams, s)
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return s.info, rerr
		}
	}
	end := Record{Flags: FlagStreamEnd, Key: id[:]}
	if err := tx.addRecord(end, true); err != nil {
		return s.info, err
	}
	s.endRecord = len(tx.records) - 1
	s.complete = true
	tx.streams = appendStreamOnce(tx.streams, s)
	return s.info, nil
}

// appendStreamOnce ensures a stream appears exactly once. | appendStreamOnce 保证流只出现一次。
func appendStreamOnce(list []*txStream, s *txStream) []*txStream {
	for _, existing := range list {
		if existing == s {
			return list
		}
	}
	return append(list, s)
}

// addRecord appends one buffered record and enforces capacity. | addRecord 追加一条缓冲记录并检查容量。
func (tx *Tx) addRecord(rec Record, allowStream bool) error {
	cost := int64(txnRecordOverhead + len(rec.Key) + len(rec.Data))
	if tx.bytes+cost > tx.w.opts.txnMaxBytes || uint64(len(tx.records)+1) > tx.w.opts.txnMaxRecords {
		return ErrTxnTooLarge
	}
	tx.records = append(tx.records, txRecord{rec: rec, allowStream: allowStream})
	tx.bytes += cost
	tx.payloadBytes += int64(len(rec.Key) + len(rec.Data))
	return nil
}

// ReadKey declares a key read by a serializable transaction. | ReadKey 声明可串行化事务读取的键。
func (tx *Tx) ReadKey(key []byte) error {
	return tx.declareKey(key, false)
}

// WriteKey declares a key written by a serializable transaction. | WriteKey 声明可串行化事务写入的键。
func (tx *Tx) WriteKey(key []byte) error {
	return tx.declareKey(key, true)
}

// declareKey records one declared key digest. | declareKey 记录一个声明键摘要。
func (tx *Tx) declareKey(key []byte, write bool) error {
	if err := tx.checkActive(); err != nil {
		return err
	}
	digest := digestKeyData(tx.w.hashAlg, key, nil)
	if _, ok := tx.keySet[digest]; !ok {
		if len(tx.keySet) >= tx.w.opts.txnMaxKeys {
			return ErrTxnTooManyKeys
		}
		tx.keySet[digest] = struct{}{}
		if write {
			tx.writeKeys = append(tx.writeKeys, digest)
		} else {
			tx.readKeys = append(tx.readKeys, digest)
		}
		return nil
	}
	if write {
		for _, k := range tx.writeKeys {
			if k == digest {
				return nil
			}
		}
		tx.writeKeys = append(tx.writeKeys, digest)
	}
	return nil
}

// Commit writes the transaction as one logical batch. | Commit 把事务作为一个逻辑批写入。
func (tx *Tx) Commit(ctx context.Context) (TxnInfo, error) {
	if tx.state != txnActive {
		return TxnInfo{}, ErrTxnClosed
	}
	tx.state = txnCommitting
	req := &appendRequest{kind: kindTxnCommit, txn: tx, done: make(chan appendResult, 1)}
	if err := tx.w.admit(ctx, req, false); err != nil {
		tx.state = txnFailed
		tx.w.counters.openTxns.Add(-1)
		return TxnInfo{}, err
	}
	res := <-req.done
	if res.err != nil {
		tx.state = txnFailed
		tx.w.counters.openTxns.Add(-1)
		if res.err == ErrTxnConflict {
			tx.w.counters.txnConflicts.Add(1)
		}
		return TxnInfo{}, res.err
	}
	tx.state = txnCommitted
	tx.w.counters.openTxns.Add(-1)
	tx.w.counters.txnCommits.Add(1)
	info := res.txnInfo
	tx.commitSeq = info.CommitSeq
	if tx.w.indexer != nil {
		for i := range tx.records {
			lsn := uint64(0)
			if i < len(tx.lsns) {
				lsn = tx.lsns[i]
			}
			ts := int64(0)
			if i < len(tx.timestamps) {
				ts = tx.timestamps[i]
			}
			tx.w.runIndexer(RecordMeta{LSN: lsn, Timestamp: ts, TxnID: info.TxnID,
				Flags: tx.records[i].rec.Flags, KeyLen: len(tx.records[i].rec.Key), DataLen: len(tx.records[i].rec.Data)},
				tx.records[i].rec.Key, tx.records[i].rec.Data)
		}
	}
	return info, nil
}

// Rollback discards buffered records. | Rollback 丢弃缓冲的记录。
func (tx *Tx) Rollback() error {
	if tx.state == txnActive {
		tx.state = txnRolledBack
		tx.records = nil
		tx.streams = nil
		tx.w.counters.openTxns.Add(-1)
		tx.w.counters.txnRollbacks.Add(1)
	}
	return nil
}

// Snapshot returns the transaction read snapshot. | Snapshot 返回事务读快照。
func (tx *Tx) Snapshot() Snapshot {
	if tx.isolation == IsolationReadCommitted {
		return tx.w.Snapshot()
	}
	return tx.snapshot
}

// Records calls fn for each buffered record in order. | Records 按顺序对每条缓冲记录调用 fn。
func (tx *Tx) Records(fn func(Record) error) error {
	for i := range tx.records {
		rec := tx.records[i].rec
		if tx.state != txnCommitted {
			rec.LSN, rec.TxnID = 0, 0
		} else {
			if i < len(tx.lsns) {
				rec.LSN = tx.lsns[i]
			}
			rec.TxnID = tx.commitSeq
		}
		if err := fn(rec); err != nil {
			return err
		}
	}
	return nil
}

// checkActive rejects terminal transactions. | checkActive 拒绝终态事务。
func (tx *Tx) checkActive() error {
	if tx.state != txnActive {
		return ErrTxnClosed
	}
	return nil
}

// txnStreamsFinal fills stream LSN ranges after commit. | txnStreamsFinal 在提交后填充流的 LSN 区间。
func txnStreamsFinal(tx *Tx, lsns []uint64) []StreamInfo {
	if len(tx.streams) == 0 {
		return nil
	}
	out := make([]StreamInfo, 0, len(tx.streams))
	for _, s := range tx.streams {
		info := s.info
		info.FirstLSN = 0
		info.LastLSN = 0
		if s.firstRecord >= 0 && s.firstRecord < len(lsns) {
			info.FirstLSN = lsns[s.firstRecord]
		}
		if s.endRecord >= 0 && s.endRecord < len(lsns) {
			info.LastLSN = lsns[s.endRecord]
			info.Complete = true
		}
		if info.FirstLSN == 0 {
			info.FirstLSN = info.LastLSN
		}
		out = append(out, info)
	}
	return out
}

// newStreamID creates a random 16-byte stream ID. | newStreamID 生成随机 16 字节流 ID。
func newStreamID() ([16]byte, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return id, errs.Wrap(err, ErrRandomSource)
	}
	return id, nil
}

// txnRecordOverhead is the per-record buffer cost. | txnRecordOverhead 是每条记录的缓冲开销。
const txnRecordOverhead = 96

// txnCommittedUnixNano is a small helper for tests and callers. | txnCommittedUnixNano 是供测试与调用方使用的小辅助函数。
func txnCommittedUnixNano() int64 { return time.Now().UnixNano() }
