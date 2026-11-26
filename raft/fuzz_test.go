package raft

import (
	"bytes"
	"io"
	"testing"
)

// FuzzUnmarshalMessage checks that arbitrary wire bytes never panic and that
// accepted messages round-trip through the encoder. | FuzzUnmarshalMessage 检查
// 任意线数据不会 panic，且被接受的消息可经编码器往返。
func FuzzUnmarshalMessage(f *testing.F) {
	seed, _ := MarshalMessage(Message{Type: MsgApp, From: 1, To: 2, Term: 3,
		LogIndex: 4, LogTerm: 2, Commit: 4,
		Entries: []Entry{{Index: 5, Term: 3, Type: EntryNormal, Data: []byte("hello")}}})
	f.Add(seed)
	f.Add([]byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := UnmarshalMessage(data)
		if err != nil {
			return
		}
		encoded, err := MarshalMessage(m)
		if err != nil {
			t.Fatalf("re-marshal: %v", err)
		}
		again, err := UnmarshalMessage(encoded)
		if err != nil {
			t.Fatalf("re-unmarshal: %v", err)
		}
		if again.Type != m.Type || again.From != m.From || again.To != m.To || again.Term != m.Term {
			t.Fatalf("round trip mismatch: %+v vs %+v", again, m)
		}
	})
}

// FuzzDecodeWALBatch checks WAL payload decoding. | FuzzDecodeWALBatch 检查 WAL
// 载荷解码。
func FuzzDecodeWALBatch(f *testing.F) {
	f.Add(encodeWALBatch(nil, PersistBatch{Entries: []Entry{{Index: 1, Term: 1, Type: EntryNormal, Data: []byte("x")}}}))
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if _, err := decodeWALBatch(data); err != nil {
			return
		}
	})
}

// fuzzEncryptor builds a fixed Encryptor for ciphertext fuzz targets. |
// fuzzEncryptor 为密文模糊测试构建固定 Encryptor。
func fuzzEncryptor(f *testing.F) *Encryptor {
	f.Helper()
	enc, err := NewEncryptor(EncryptionOptions{
		Keys: []EncryptionKey{{
			ID: 1, Suite: EncryptionAES256GCM, Bytes: testEncryptionKey(EncryptionAES256GCM, 0x44),
		}},
		ChunkSize: 32,
	})
	if err != nil {
		f.Fatal(err)
	}
	return enc
}

// FuzzDecryptEnvelope checks that arbitrary one-shot ciphertext never panics. |
// FuzzDecryptEnvelope 检查任意一次性密文不会 panic。
func FuzzDecryptEnvelope(f *testing.F) {
	enc := fuzzEncryptor(f)
	sealed, err := enc.Encrypt(nil, []byte("seed"), []byte("aad"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sealed)
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = enc.Decrypt(nil, data, []byte("aad"))
	})
}

// FuzzDecryptStream checks that arbitrary stream bytes never panic. |
// FuzzDecryptStream 检查任意流数据不会 panic。
func FuzzDecryptStream(f *testing.F) {
	enc := fuzzEncryptor(f)
	var buf bytes.Buffer
	writer, err := enc.NewEncryptWriter(&buf, nil)
	if err != nil {
		f.Fatal(err)
	}
	if _, err := writer.Write([]byte("seed payload")); err != nil {
		f.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		f.Fatal(err)
	}
	f.Add(buf.Bytes())
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, data []byte) {
		reader, err := enc.NewDecryptReader(bytes.NewReader(data), nil)
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, reader)
	})
}
