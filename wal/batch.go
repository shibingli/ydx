package wal

import (
	"encoding/binary"
	"time"

	"github.com/shibingli/ydx/errs"
)

// preparedArenaKeep is the largest writer arena retained between batches, in
// records. Larger batches release their arena instead of pinning the peak. |
// preparedArenaKeep 是批次之间保留写入复用区的最大记录数；更大的批次直接丢弃
// 复用区，避免长期占用峰值内存。
const preparedArenaKeep = 4096

// takePrepared returns one zeroed record slot from the writer arena. | takePrepared
// 从写入复用区取一个清零的记录槽位。
func takePrepared(arena []preparedRecord, slot *int) *preparedRecord {
	p := &arena[*slot]
	*slot = *slot + 1
	*p = preparedRecord{}
	return p
}

// releasePrepared clears user-data references from the arena so it does not
// pin caller buffers between batches. | releasePrepared 清空复用区中的用户数据
// 引用，避免它在批次之间钉住调用方缓冲。
func releasePrepared(arena []preparedRecord) {
	for i := range arena {
		arena[i].key = nil
		arena[i].data = nil
		arena[i].payload = nil
		arena[i].parts = [3][]byte{}
	}
}

// preparedRecord is one encoded record waiting for the batch write. | preparedRecord
// 是一条等待批写入的已编码记录。
type preparedRecord struct {
	header     [recordHeaderSizeEncrypted]byte
	nonce      [nonceSize]byte
	headerLen  int
	parts      [3][]byte
	nparts     int
	payload    []byte
	key        []byte
	data       []byte
	size       int
	offset     int64
	lsn        uint64
	txnID      uint64
	timestamp  int64
	flags      uint16
	digest     [32]byte
	ordinary   bool
	isRef      bool
	refOffset  uint64
	codec      byte
	compressed bool
}

// commitBatch validates, plans, writes, and completes one group-commit batch. | commitBatch
// 校验、规划、写入并完成一个组提交批次。
func (w *WAL) commitBatch(reqs []*appendRequest) {
	if len(reqs) == 0 {
		return
	}
	if err := w.poisonedErr(); err != nil {
		completeAll(reqs, appendResult{err: err})
		return
	}
	now := time.Now().UnixNano()
	plans := make([]*reqPlan, len(reqs))
	for i, req := range reqs {
		plans[i] = &reqPlan{req: req, winner: -1}
		req.plan = plans[i]
	}
	// Validate every record before allocating an LSN. | 在分配 LSN 前校验全部记录。
	for _, plan := range plans {
		if err := w.validateRequest(plan.req); err != nil {
			completeAll(reqs, appendResult{err: err})
			return
		}
	}
	// Normalize timestamps and enforce the monotonic promise. | 归一化时间戳并执行单调承诺。
	lastTS := w.lastTimestamp
	for _, plan := range plans {
		req := plan.req
		if req.kind == kindTxnCommit && req.txn != nil {
			if len(req.txn.timestamps) != len(req.txn.records) {
				req.txn.timestamps = make([]int64, len(req.txn.records))
			}
			for i := range req.txn.records {
				ts := req.txn.records[i].rec.Timestamp
				if ts == 0 {
					ts = now
					if w.opts.monotonicTimestamps && ts < lastTS {
						ts = lastTS
					}
				}
				if w.opts.monotonicTimestamps && ts < lastTS {
					completeAll(reqs, appendResult{err: errs.Detail(ErrInvalidRecord, "timestamp moved backwards | 时间戳倒退")})
					return
				}
				if ts > lastTS {
					lastTS = ts
				}
				req.txn.timestamps[i] = ts
			}
			continue
		}
		for i := range req.recs {
			ts := req.recs[i].Timestamp
			if ts == 0 {
				ts = now
				if w.opts.monotonicTimestamps && ts < lastTS {
					ts = lastTS
				}
			}
			if w.opts.monotonicTimestamps && ts < lastTS {
				completeAll(reqs, appendResult{err: errs.Detail(ErrInvalidRecord, "timestamp moved backwards | 时间戳倒退")})
				return
			}
			if ts > lastTS {
				lastTS = ts
			}
			req.recs[i].Timestamp = ts
		}
	}
	// Classify AppendOnce and run transaction OCC before any LSN allocation. | 在分配 LSN 前完成幂等分类与事务 OCC。
	nextCommit := w.commitSeq
	pendingOnce := make(map[[32]byte]int)
	staged := make(map[[32]byte]uint64)
	for i, plan := range plans {
		req := plan.req
		switch req.kind {
		case kindData:
			if !req.once {
				continue
			}
			if len(req.recs) != 1 || w.idem == nil {
				completeAll(reqs, appendResult{err: errs.Detail(ErrInvalidOptions, "AppendOnce requires one record and an idempotency window | AppendOnce 需要一条记录与幂等窗口")})
				return
			}
			rec := req.recs[0]
			keyDigest := digestKeyData(w.hashAlg, req.dedupKey, nil)
			contentDigest := digestKeyData(w.hashAlg, rec.Key, rec.Data)
			plan.keyDigest = keyDigest
			plan.contentDigest = contentDigest
			w.idem.dropIfBefore(keyDigest, w.firstLSN)
			if e, dup, conflict := w.idem.lookup(keyDigest, contentDigest, time.Unix(0, now)); e != nil {
				if dup {
					w.counters.idemHits.Add(1)
					plan.immediate = &appendResult{lsn: e.lsn, duplicate: true}
				} else if conflict {
					w.counters.idemConflicts.Add(1)
					plan.immediate = &appendResult{lsn: e.lsn, err: ErrIdempotencyConflict}
				}
				continue
			}
			if winner, ok := pendingOnce[keyDigest]; ok {
				if plans[winner].contentDigest == contentDigest {
					plan.pendingDup = true
					plan.winner = winner
				} else {
					plan.pendingConflict = true
					plan.winner = winner
				}
				continue
			}
			pendingOnce[keyDigest] = i
			plan.onceWinner = true
		case kindTxnCommit:
			tx := req.txn
			if tx == nil {
				plan.err = ErrTxnClosed
				continue
			}
			if tx.isolation == IsolationSerializable {
				if tx.snapshot.CommitSeq < w.occ.minSeq {
					plan.err = ErrTxnTooOld
					w.counters.txnConflicts.Add(1)
					continue
				}
				conflict := false
				for _, k := range tx.readKeys {
					if w.occ.version(k) > tx.snapshot.CommitSeq || staged[k] > tx.snapshot.CommitSeq {
						conflict = true
						break
					}
				}
				if !conflict {
					for _, k := range tx.writeKeys {
						if w.occ.version(k) > tx.snapshot.CommitSeq || staged[k] > tx.snapshot.CommitSeq {
							conflict = true
							break
						}
					}
				}
				if conflict {
					plan.err = ErrTxnConflict
					w.counters.txnConflicts.Add(1)
					continue
				}
			}
			nextCommit++
			plan.txnSeq = nextCommit
			plan.txnAccepted = true
			if tx.isolation == IsolationSerializable {
				for _, k := range tx.writeKeys {
					staged[k] = nextCommit
				}
			}
		}
	}
	// Decide whether any request will write. | 判断是否存在实际写入。
	hasWrites := false
	totalRecords := 0
	totalControls := 1 // commit marker | 提交标记
	for _, plan := range plans {
		if plan.err != nil || plan.immediate != nil || plan.pendingDup || plan.pendingConflict {
			continue
		}
		switch plan.req.kind {
		case kindTxnCommit:
			hasWrites = true
			totalRecords += len(plan.req.txn.records)
			totalControls++
		default:
			if len(plan.req.recs) > 0 {
				hasWrites = true
				totalRecords += len(plan.req.recs)
			}
		}
	}
	if !hasWrites {
		w.completePlans(plans, nil)
		return
	}
	if err := w.ensureActive(); err != nil {
		w.setPoison(err)
		completeAll(reqs, appendResult{err: err})
		return
	}
	active := w.active
	off := active.size
	baseOff := active.size
	baseCRC := active.crc
	crc := baseCRC
	nextLSN := w.nextLSN
	if cap(w.preparedArena) < totalRecords+totalControls {
		w.preparedArena = make([]preparedRecord, totalRecords+totalControls)
	}
	arena := w.preparedArena[:totalRecords+totalControls]
	slot := 0
	defer func() {
		if cap(arena) > preparedArenaKeep {
			w.preparedArena = nil
			return
		}
		releasePrepared(arena)
	}()
	items := make([]*preparedRecord, 0, totalRecords+totalControls)
	userItems := make([]*preparedRecord, 0, totalRecords)
	userCount := uint64(0)
	lastUserLSN := active.lastLSN
	var minTime, maxTime int64
	haveTime := false
	for _, plan := range plans {
		if plan.err != nil || plan.immediate != nil || plan.pendingDup || plan.pendingConflict {
			continue
		}
		req := plan.req
		switch req.kind {
		case kindData:
			for i := range req.recs {
				lsn := nextLSN
				nextLSN++
				p, err := w.prepareUserRecord(takePrepared(arena, &slot), active, off, req.recs[i], lsn, 0)
				if err != nil {
					w.setPoison(err)
					completeAll(reqs, appendResult{err: err})
					return
				}
				items = append(items, p)
				userItems = append(userItems, p)
				off += int64(p.size)
				crc = appendPreparedCRC(crc, p)
				if plan.writeFirst == 0 {
					plan.writeFirst = lsn
				}
				plan.writeLast = lsn
				userCount++
				lastUserLSN = lsn
				if !haveTime || p.timestamp < minTime {
					minTime = p.timestamp
				}
				if !haveTime || p.timestamp > maxTime {
					maxTime = p.timestamp
				}
				haveTime = true
			}
		case kindTxnCommit:
			tx := req.txn
			tx.lsns = make([]uint64, 0, len(tx.records))
			for i := range tx.records {
				lsn := nextLSN
				nextLSN++
				rec := tx.records[i].rec
				rec.Timestamp = tx.timestamps[i]
				p, err := w.prepareUserRecord(takePrepared(arena, &slot), active, off, rec, lsn, plan.txnSeq)
				if err != nil {
					w.setPoison(err)
					completeAll(reqs, appendResult{err: err})
					return
				}
				items = append(items, p)
				userItems = append(userItems, p)
				off += int64(p.size)
				crc = appendPreparedCRC(crc, p)
				if plan.writeFirst == 0 {
					plan.writeFirst = lsn
				}
				plan.writeLast = lsn
				tx.lsns = append(tx.lsns, lsn)
				userCount++
				lastUserLSN = lsn
				if !haveTime || p.timestamp < minTime {
					minTime = p.timestamp
				}
				if !haveTime || p.timestamp > maxTime {
					maxTime = p.timestamp
				}
				haveTime = true
			}
			ctrlPayload := encodeTxnControlPayload(txnControl{
				kind: txnKindCommit, hashAlg: byte(w.hashAlg), commitSeq: plan.txnSeq,
				firstLSN: plan.writeFirst, lastLSN: plan.writeLast,
				recordCount: uint64(len(tx.records)), bytes: uint64(tx.payloadBytes),
				writeKeys: w.txnWriteKeys(tx),
			})
			p, err := w.prepareControlRecord(takePrepared(arena, &slot), active, off, 0, plan.txnSeq, 0, codecTxnControl, 0, 0, ctrlPayload, now)
			if err != nil {
				w.setPoison(err)
				completeAll(reqs, appendResult{err: err})
				return
			}
			items = append(items, p)
			off += int64(p.size)
			crc = appendPreparedCRC(crc, p)
			plan.txnInfo = TxnInfo{
				TxnID: plan.txnSeq, CommitSeq: plan.txnSeq,
				FirstLSN: plan.writeFirst, LastLSN: plan.writeLast,
				Records: uint64(len(tx.records)), Bytes: uint64(tx.payloadBytes),
				Streams:           txnStreamsFinal(tx, tx.lsns),
				CommittedUnixNano: now,
			}
		}
	}
	// Append the batch commit marker. | 追加批提交标记。
	markerOffset := off
	var markerBuf [markerPayloadSize]byte
	markerPayload := encodeCommitMarkerPayloadInto(markerBuf[:], uint64(markerOffset), lastUserLSN, active.recordCount+userCount, crc)
	marker, err := w.prepareControlRecord(takePrepared(arena, &slot), active, markerOffset, 0, 0, recordFlagCommitMark, codecNone, 0, 0, markerPayload, now)
	if err != nil {
		w.setPoison(err)
		completeAll(reqs, appendResult{err: err})
		return
	}
	items = append(items, marker)
	off += int64(marker.size)
	crc = appendPreparedCRC(crc, marker)

	nparts := 0
	for _, p := range items {
		nparts += p.nparts
	}
	parts := make([][]byte, 0, nparts)
	for _, p := range items {
		for i := 0; i < p.nparts; i++ {
			parts = append(parts, p.parts[i])
		}
	}
	syncNow := w.opts.syncPolicy.Mode == SyncModeAlways
	if err := w.engine.WriteAt(active.f, parts, baseOff, syncNow); err != nil {
		w.setPoison(err)
		completeAll(reqs, appendResult{err: err})
		return
	}
	if syncNow {
		w.counters.syncs.Add(1)
		w.pendingSync = false
	} else {
		w.pendingSync = true
	}
	// Publish state only after a successful write. | 仅在写入成功后发布状态。
	w.nextLSN = nextLSN
	if nextCommit > w.commitSeq {
		w.commitSeq = nextCommit
	}
	w.lastTimestamp = lastTS
	wasEmpty := active.recordCount == 0
	active.metaMu.Lock()
	for _, p := range userItems {
		active.addSparseLocked(p.lsn, p.offset, p.timestamp, w.opts.indexIntervalBytes, defaultIndexRecordsPerEntry)
		if w.opts.keyIndex {
			overflow := false
			active.addKeyLocked(p.key, p.lsn, w.opts.keyIndexMaxEntries, w.opts.keyIndexMaxKeyBytes, &overflow)
			if overflow {
				w.keyIndexOverflow = true
				w.counters.keyIndexOver.Add(1)
			}
		}
		if w.opts.dedupEnabled && p.ordinary {
			w.dedup.add(p.digest, uint64(p.offset))
		}
		if p.isRef {
			active.dedupRefs++
		}
		if p.compressed {
			active.compressed++
		}
		if len(active.offsets) < maxDenseRecords {
			active.offsets = append(active.offsets, uint64(p.offset))
		}
	}
	active.size = off
	active.lastLSN = lastUserLSN
	active.recordCount += userCount
	active.crc = crc
	active.commitSeq = w.commitSeq
	if haveTime {
		if wasEmpty || minTime < active.minTime {
			active.minTime = minTime
		}
		if wasEmpty || maxTime > active.maxTime {
			active.maxTime = maxTime
		}
	}
	active.metaMu.Unlock()
	for _, plan := range plans {
		if !plan.onceWinner || plan.err != nil {
			continue
		}
		w.idem.put(plan.keyDigest, plan.contentDigest, plan.writeLast, time.Unix(0, now))
	}
	for _, plan := range plans {
		if plan.req.kind == kindTxnCommit && plan.txnAccepted && plan.req.txn.isolation == IsolationSerializable {
			w.occ.apply(plan.txnSeq, plan.req.txn.writeKeys)
		}
	}
	for _, p := range userItems {
		w.counters.records.Add(1)
		w.counters.bytes.Add(uint64(len(p.key) + len(p.data)))
		if p.isRef {
			w.counters.dedupRefs.Add(1)
			if len(p.data) > dedupRefBlockSize {
				w.counters.dedupSaved.Add(uint64(len(p.data) - dedupRefBlockSize))
			}
		}
		if p.compressed {
			w.counters.compressed.Add(1)
			w.counters.compressedIn.Add(uint64(len(p.key) + len(p.data)))
			w.counters.compressedOut.Add(uint64(plainPayloadLen(recordHeader{size: uint32(p.size), headerLen: p.headerLen, cipher: p.header[recOffCipher]})))
		}
	}
	w.counters.groupBatches.Add(1)
	w.counters.groupRecords.Add(uint64(len(userItems)))
	w.publishSnapshot(w.commitSeq, lastUserLSN)
	if syncNow {
		w.markSynced()
	}
	w.completePlans(plans, nil)
	w.notifyFollow()
	if active.size >= w.opts.segmentMaxBytes || (w.opts.segmentMaxRecords > 0 && active.recordCount >= w.opts.segmentMaxRecords) {
		if err := w.rotate(); err != nil {
			w.setPoison(err)
		}
	}
}

// validateRequest validates all records in one request. | validateRequest 校验单个请求中的全部记录。
func (w *WAL) validateRequest(req *appendRequest) error {
	switch req.kind {
	case kindData:
		for _, rec := range req.recs {
			if err := w.validateUserRecord(rec, req.allowStream); err != nil {
				return err
			}
		}
	case kindTxnCommit:
		if req.txn == nil {
			return ErrTxnClosed
		}
		for i := range req.txn.records {
			if err := w.validateUserRecord(req.txn.records[i].rec, req.txn.records[i].allowStream); err != nil {
				return err
			}
		}
	default:
		return errs.Detail(ErrInvalidOptions, "unexpected writer data request | 非预期的写入数据请求")
	}
	return nil
}

// txnWriteKeys returns the persisted write-key digests. | txnWriteKeys 返回持久化的写键摘要。
func (w *WAL) txnWriteKeys(tx *Tx) [][txnKeyDigestSize]byte {
	if !w.serializableDurable || tx.isolation != IsolationSerializable {
		return nil
	}
	out := make([][txnKeyDigestSize]byte, len(tx.writeKeys))
	copy(out, tx.writeKeys)
	return out
}

// appendPreparedCRC updates the segment CRC with one prepared record. | appendPreparedCRC
// 用一条已准备记录更新段 CRC。
func appendPreparedCRC(crc uint32, p *preparedRecord) uint32 {
	for i := 0; i < p.nparts; i++ {
		crc = appendCRC(crc, p.parts[i])
	}
	return crc
}

// prepareUserRecord encodes one user record. | prepareUserRecord 编码一条用户记录。
// The caller must have validated rec already; commitBatch performs that check
// once per request before any LSN is allocated. | 调用方必须已校验 rec；
// commitBatch 在分配任何 LSN 之前按请求完成该检查。
func (w *WAL) prepareUserRecord(p *preparedRecord, active *segment, off int64, rec Record, lsn, txnID uint64) (*preparedRecord, error) {
	p.offset, p.lsn, p.txnID, p.timestamp = off, lsn, txnID, rec.Timestamp
	p.key, p.data = rec.Key, rec.Data
	headerFlags := recordHeaderFlags(rec.Flags)
	keyLen, dataLen := uint32(len(rec.Key)), uint32(len(rec.Data))
	var plain []byte
	compressed := false
	codec := codecNone
	isRef := false
	var refOffset uint64
	if w.opts.dedupEnabled && len(rec.Data) >= w.opts.dedup.MinBytes && len(rec.Data) > dedupRefBlockSize {
		p.digest = digestKeyData(w.hashAlg, rec.Key, rec.Data)
		if target, ok := w.dedup.lookup(p.digest); ok && target < uint64(active.size) {
			refPayload := encodeDedupRefPayload(rec.Key, dedupRef{offset: target, hashAlg: byte(w.hashAlg), digest: p.digest})
			plain = refPayload
			isRef = true
			refOffset = target
			headerFlags |= recordFlagDedupRef
		} else {
			p.ordinary = true
		}
	} else {
		p.ordinary = true
	}
	if !isRef && w.opts.compression.enabled() && len(rec.Key)+len(rec.Data) >= w.opts.compression.MinBytes {
		if codecImpl, err := w.opts.compression.lookup(w.opts.compression.Active); err == nil && codecImpl != nil {
			plain = append(plain, rec.Key...)
			plain = append(plain, rec.Data...)
			out, err := safeCompress(codecImpl, nil, plain)
			if err != nil {
				return nil, err
			}
			if len(out) < len(plain) {
				plain = out
				compressed = true
				codec = codecImpl.ID()
				headerFlags |= recordFlagCompressed
			}
		}
	}
	if !isRef && !compressed {
		if w.encrypted {
			plain = make([]byte, 0, len(rec.Key)+len(rec.Data))
			plain = append(plain, rec.Key...)
			plain = append(plain, rec.Data...)
		}
	}
	p.isRef = isRef
	p.refOffset = refOffset
	p.compressed = compressed
	p.codec = codec
	p.ordinary = p.ordinary && !isRef

	var payload []byte
	headerLen := recordHeaderSize
	cipher := cipherNone
	var keyID uint32
	if w.encrypted {
		bk, err := w.bound.key(w.activeKeyID)
		if err != nil {
			return nil, err
		}
		n, err := w.nonce.next()
		if err != nil {
			return nil, err
		}
		p.nonce = n
		headerLen = recordHeaderSizeEncrypted
		headerFlags |= recordFlagEncrypted
		cipher = diskCipher(bk.suite)
		keyID = bk.id
		if plain == nil {
			plain = make([]byte, 0, len(rec.Key)+len(rec.Data))
			plain = append(plain, rec.Key...)
			plain = append(plain, rec.Data...)
		}
		p.headerLen = headerLen
		binaryPutHeader(p.header[:], uint32(headerLen+len(plain)+aeadTagSize), lsn, rec.Timestamp, txnID, keyLen, dataLen, headerFlags, cipher, codec, keyID)
		copy(p.header[recOffNonce:], p.nonce[:])
		aad := buildAAD(w.aadScratch[:0], w.walID, active.seq, off, p.header[4:headerLen])
		payload = bk.aead.Seal(nil, p.nonce[:], plain, aad)
		headerLen = recordHeaderSizeEncrypted
	} else {
		p.headerLen = recordHeaderSize
		if plain != nil {
			binaryPutHeader(p.header[:], uint32(recordHeaderSize+len(plain)), lsn, rec.Timestamp, txnID, keyLen, dataLen, headerFlags, cipher, codec, keyID)
			payload = plain
		} else {
			binaryPutHeader(p.header[:], uint32(recordHeaderSize+len(rec.Key)+len(rec.Data)), lsn, rec.Timestamp, txnID, keyLen, dataLen, headerFlags, cipher, codec, keyID)
		}
	}
	p.size = int(binary.LittleEndian.Uint32(p.header[recOffSize:]))
	p.headerLen = headerLen
	p.payload = payload
	if payload != nil {
		fillRecordCRCParts(p.header[:headerLen], payload)
		p.parts[0], p.parts[1], p.nparts = p.header[:headerLen], payload, 2
	} else {
		fillRecordCRCParts3(p.header[:headerLen], rec.Key, rec.Data)
		p.parts[0], p.parts[1], p.parts[2], p.nparts = p.header[:headerLen], rec.Key, rec.Data, 3
	}
	return p, nil
}

// prepareControlRecord encodes one control record. | prepareControlRecord 编码一条控制记录。
func (w *WAL) prepareControlRecord(p *preparedRecord, active *segment, off int64, lsn, txnID uint64, headerFlags uint16, codec byte, keyLen, dataLen uint32, payload []byte, timestamp int64) (*preparedRecord, error) {
	p.offset, p.lsn, p.txnID, p.timestamp, p.payload = off, lsn, txnID, timestamp, payload
	headerLen := recordHeaderSize
	cipher := cipherNone
	var keyID uint32
	var out []byte
	if w.encrypted {
		bk, err := w.bound.key(w.activeKeyID)
		if err != nil {
			return nil, err
		}
		n, err := w.nonce.next()
		if err != nil {
			return nil, err
		}
		p.nonce = n
		headerLen = recordHeaderSizeEncrypted
		headerFlags |= recordFlagEncrypted
		cipher = diskCipher(bk.suite)
		keyID = bk.id
		p.headerLen = headerLen
		binaryPutHeader(p.header[:], uint32(headerLen+len(payload)+aeadTagSize), lsn, timestamp, txnID, keyLen, dataLen, headerFlags, cipher, codec, keyID)
		copy(p.header[recOffNonce:], p.nonce[:])
		aad := buildAAD(w.aadScratch[:0], w.walID, active.seq, off, p.header[4:headerLen])
		out = bk.aead.Seal(nil, p.nonce[:], payload, aad)
	} else {
		p.headerLen = recordHeaderSize
		binaryPutHeader(p.header[:], uint32(recordHeaderSize+len(payload)), lsn, timestamp, txnID, keyLen, dataLen, headerFlags, cipher, codec, keyID)
		out = payload
	}
	p.size = int(binary.LittleEndian.Uint32(p.header[recOffSize:]))
	p.payload = out
	fillRecordCRCParts(p.header[:headerLen], out)
	p.parts[0], p.parts[1], p.nparts = p.header[:headerLen], out, 2
	return p, nil
}

// headerSize returns the encoded record size. | headerSize 返回编码记录大小。
func (p *preparedRecord) headerSize() uint32 {
	return uint32(p.headerLen) + uint32(len(p.payload))
}

// binaryPutHeader writes the fixed header fields. | binaryPutHeader 写入定长头字段。
func binaryPutHeader(dst []byte, size uint32, lsn uint64, timestamp int64, txnID uint64, keyLen, dataLen uint32, flags uint16, cipher, codec byte, keyID uint32) {
	encodeRecordHeader(dst, size, lsn, timestamp, txnID, keyLen, dataLen, flags, cipher, codec, keyID)
}

// fillRecordCRCParts computes CRC over header[4:] and one payload. | fillRecordCRCParts
// 计算 header[4:] 与单个负载的 CRC。
func fillRecordCRCParts(header, payload []byte) {
	crc := checksum(header[recOffSize:])
	crc = appendCRC(crc, payload)
	binaryPutU32(header[recOffCRC:], crc)
}

// fillRecordCRCParts3 computes CRC over header[4:] and two payload parts. | fillRecordCRCParts3
// 计算 header[4:] 与两个负载分片的 CRC。
func fillRecordCRCParts3(header, key, data []byte) {
	crc := checksum(header[recOffSize:])
	crc = appendCRC(crc, key)
	crc = appendCRC(crc, data)
	binaryPutU32(header[recOffCRC:], crc)
}

// binaryPutU32 writes a little-endian uint32. | binaryPutU32 写入小端 uint32。
func binaryPutU32(dst []byte, v uint32) {
	dst[0] = byte(v)
	dst[1] = byte(v >> 8)
	dst[2] = byte(v >> 16)
	dst[3] = byte(v >> 24)
}

// completePlans completes every request with its planned result. | completePlans
// 用规划结果完成每个请求。
func (w *WAL) completePlans(plans []*reqPlan, override *appendResult) {
	for _, plan := range plans {
		var res appendResult
		switch {
		case override != nil:
			res = *override
		case plan.err != nil:
			res.err = plan.err
		case plan.immediate != nil:
			res = *plan.immediate
		case plan.pendingDup:
			res.lsn = plans[plan.winner].writeLast
			res.duplicate = true
		case plan.pendingConflict:
			res.lsn = plans[plan.winner].writeLast
			res.err = ErrIdempotencyConflict
		case plan.req.kind == kindTxnCommit:
			res.lsn = plan.writeLast
			res.firstLSN = plan.writeFirst
			res.lastLSN = plan.writeLast
			res.txnInfo = plan.txnInfo
			res.timestamps = plan.req.txn.timestamps
		default:
			res.lsn = plan.writeLast
			res.firstLSN = plan.writeFirst
			res.lastLSN = plan.writeLast
			if w.indexer != nil {
				res.timestamps = make([]int64, len(plan.req.recs))
				for i := range plan.req.recs {
					res.timestamps[i] = plan.req.recs[i].Timestamp
				}
			}
		}
		w.completeOne(plan.req, res)
	}
}

// completeAll fails every request with one error. | completeAll 用一个错误完成全部请求。
func completeAll(reqs []*appendRequest, res appendResult) {
	for _, req := range reqs {
		req.complete(res)
	}
}

// complete delivers one result exactly once. | complete 只投递一次结果。
func (req *appendRequest) complete(res appendResult) {
	if req.async && req.future != nil {
		req.future.complete(res)
		return
	}
	if req.done != nil {
		req.done <- res
	}
}

// completeOne delivers one result in the WAL context. | completeOne 在 WAL 上下文投递一个结果。
func (w *WAL) completeOne(req *appendRequest, res appendResult) {
	req.complete(res)
}
