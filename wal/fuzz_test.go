package wal

import (
	"context"
	"os"
	"testing"
)

func fuzzSidecarSeed() []byte {
	sc := &sidecar{
		seq: 1, baseLSN: 1, lastLSN: 1, recordCount: 1, segmentBytes: uint64(segmentHeaderSize) + 64,
		walID: [16]byte{1}, hasKeyIndex: true,
		sparse:   []sparseEntry{{lsn: 1, offset: int64(segmentHeaderSize), timestamp: 1}},
		keyIndex: map[string][]uint64{"k": {1}},
	}
	return encodeSidecar(sc)
}

func fuzzMetaSeed() []byte {
	var slot [metaSlotSize]byte
	encodeMetaSlot(slot[:], metaState{
		generation: 1, nextSeq: 2, nextLSN: 2, createdNano: 1, firstLSN: 1,
		walID: [16]byte{1},
	})
	return slot[:]
}

func fuzzManifestSeed() []byte {
	var rec [manifestHeaderSize]byte
	encodeManifestRecord(rec[:], manifestRecord{
		kind: manifestKindSegment, seq: 1, baseLSN: 1, lastLSN: 1,
		segmentBytes: uint64(segmentHeaderSize) + 48, recordCount: 1, walID: [16]byte{1},
	})
	return rec[:]
}

func fuzzAnchorSeed() []byte {
	return encodeAnchor(anchorState{
		generation: 1, walID: [16]byte{1}, createdNano: 1,
		nextSeq: 2, nextLSN: 2, firstLSN: 1,
	})
}

func fuzzBackupSetSeed() []byte {
	data, err := EncodeBackupSet(BackupSet{
		WalID: [16]byte{1}, CreatedNano: 1, FirstLSN: 1, LastLSN: 1,
		NextLSN: 2, NextSeq: 2,
		Segments: []SegmentMeta{{Seq: 1, BaseLSN: 1, LastLSN: 1, Bytes: uint64(segmentHeaderSize), SegmentCRC: 1, WalID: [16]byte{1}}},
	})
	if err != nil {
		panic(err)
	}
	return data
}

// FuzzDecodeFormats exercises every self-describing on-disk decoder. | FuzzDecodeFormats
// 覆盖所有自描述磁盘格式的解码器。
func FuzzDecodeFormats(f *testing.F) {
	f.Add(fuzzSidecarSeed())
	f.Add(fuzzMetaSeed())
	f.Add(fuzzManifestSeed())
	f.Add(fuzzAnchorSeed())
	f.Add(fuzzBackupSetSeed())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = decodeSidecar(data)
		_, _, _ = decodeMetaSlot(data)
		_, _ = decodeManifestRecord(data)
		_, _, _ = decodeAnchorSlot(data)
		_, _ = DecodeBackupSet(data)
		_, _ = parseRecordHeader(data)
		_, _ = parseTxnControlPayload(data)
		_, _, _ = parseDedupRefPayload(data, 0)
	})
}

// FuzzOpenMutatedSegment feeds arbitrary record bytes into recovery. It must
// never panic; a returned error is the expected outcome for most inputs. |
// FuzzOpenMutatedSegment 把任意记录字节送入恢复流程；绝不能 panic，大多数输入
// 返回错误是预期结果。
func FuzzOpenMutatedSegment(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 48))
	f.Add(make([]byte, 4096))
	f.Fuzz(func(t *testing.T, tail []byte) {
		if len(tail) > 64<<10 {
			tail = tail[:64<<10]
		}
		dir := t.TempDir()
		walID := [16]byte{1}
		seg, err := createSegmentFile(dir, 1, 1, walID, 0o600, 0)
		if err != nil {
			t.Fatal(err)
		}
		seg.closeWriter()
		path := segmentPath(dir, 1)
		fh, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fh.Write(tail); err != nil {
			t.Fatal(err)
		}
		_ = fh.Close()
		w, err := Open(dir, WithAutoRepair(true), WithSyncPolicy(SyncNever()))
		if err != nil {
			return
		}
		_ = w.Verify(context.Background())
		_ = w.Close()
	})
}

// FuzzManifestReplay mutates a valid manifest record stream and replays it. |
// FuzzManifestReplay 变异有效 MANIFEST 记录流并回放。
func FuzzManifestReplay(f *testing.F) {
	f.Add(fuzzManifestSeed())
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			data = data[:64<<10]
		}
		d := newManifestData()
		for off := 0; off+int(manifestHeaderSize) <= len(data); off += int(manifestHeaderSize) {
			r, err := decodeManifestRecord(data[off : off+int(manifestHeaderSize)])
			if err != nil {
				continue
			}
			_ = d.apply(r, t.TempDir())
		}
	})
}
