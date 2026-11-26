package raft

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// testStreamEncryptor builds an Encryptor with a small chunk size for streaming
// tests. | testStreamEncryptor 为流式测试构建使用小分块的 Encryptor。
func testStreamEncryptor(t *testing.T, suite EncryptionSuite, chunkSize int) *Encryptor {
	t.Helper()
	enc, err := NewEncryptor(EncryptionOptions{
		Keys:      []EncryptionKey{{ID: 4, Suite: suite, Bytes: testEncryptionKey(suite, 0x5a)}},
		ChunkSize: chunkSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

// TestEncryptStreamRoundTrip verifies every suite streams arbitrary lengths,
// including empty, exact multiples and partial final chunks. |
// TestEncryptStreamRoundTrip 验证每种套件都能流式处理任意长度，包括空流、整数倍与
// 不完整尾块。
func TestEncryptStreamRoundTrip(t *testing.T) {
	const chunkSize = 64
	plain := make([]byte, 0, 1024)
	for i := 0; i < 1024; i++ {
		plain = append(plain, byte(i*7))
	}
	sizes := []int{0, 1, chunkSize - 1, chunkSize, chunkSize + 1, 3 * chunkSize, 1000}
	for _, suite := range testSuites() {
		t.Run(suite.String(), func(t *testing.T) {
			enc := testStreamEncryptor(t, suite, chunkSize)
			aad := []byte("stream-aad")
			for _, size := range sizes {
				var buf bytes.Buffer
				writer, err := enc.NewEncryptWriter(&buf, aad)
				if err != nil {
					t.Fatal(err)
				}
				data := plain[:size]
				for len(data) > 0 {
					n := 7
					if n > len(data) {
						n = len(data)
					}
					if _, err := writer.Write(data[:n]); err != nil {
						t.Fatal(err)
					}
					data = data[n:]
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				reader, err := enc.NewDecryptReader(bytes.NewReader(buf.Bytes()), aad)
				if err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(reader)
				if err != nil {
					t.Fatalf("size %d: %v", size, err)
				}
				if !bytes.Equal(got, plain[:size]) {
					t.Fatalf("size %d round trip mismatch", size)
				}
			}
		})
	}
}

// TestEncryptStreamDetectsTampering verifies modified, truncated and extended
// streams fail authentication instead of returning partial plaintext. |
// TestEncryptStreamDetectsTampering 验证被修改、截断或追加数据的流会认证失败，而不是
// 返回部分明文。
func TestEncryptStreamDetectsTampering(t *testing.T) {
	const chunkSize = 32
	enc := testStreamEncryptor(t, EncryptionAES256GCM, chunkSize)
	aad := []byte("tamper")
	plain := bytes.Repeat([]byte("0123456789abcdef"), 8)
	var buf bytes.Buffer
	writer, err := enc.NewEncryptWriter(&buf, aad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	stream := append([]byte(nil), buf.Bytes()...)

	readAll := func(data []byte, aad []byte) error {
		reader, err := enc.NewDecryptReader(bytes.NewReader(data), aad)
		if err != nil {
			return err
		}
		_, err = io.ReadAll(reader)
		return err
	}

	tampered := append([]byte(nil), stream...)
	tampered[streamHeaderSize+streamChunkHeaderSize+2] ^= 0xff
	if err := readAll(tampered, aad); !errors.Is(err, ErrAuth) {
		t.Fatalf("tampered chunk error = %v, want ErrAuth", err)
	}
	if err := readAll(stream[:len(stream)-1], aad); !errors.Is(err, ErrAuth) {
		t.Fatalf("truncated marker error = %v, want ErrAuth", err)
	}
	if err := readAll(stream[:len(stream)-(streamChunkHeaderSize+encryptionTagSize)], aad); !errors.Is(err, ErrAuth) {
		t.Fatalf("missing marker error = %v, want ErrAuth", err)
	}
	extended := append(append([]byte(nil), stream...), 0)
	if err := readAll(extended, aad); !errors.Is(err, ErrAuth) {
		t.Fatalf("trailing data error = %v, want ErrAuth", err)
	}
	if err := readAll(stream, []byte("other")); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong AAD error = %v, want ErrAuth", err)
	}
	other, err := NewEncryptor(EncryptionOptions{
		Keys: []EncryptionKey{{ID: 4, Suite: EncryptionAES256GCM, Bytes: testEncryptionKey(EncryptionAES256GCM, 0x6b)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := other.NewDecryptReader(bytes.NewReader(stream), aad)
	if err == nil {
		_, err = io.ReadAll(reader)
	}
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong key error = %v, want ErrAuth", err)
	}
}

// TestEncryptStreamHeaderValidation verifies malformed headers are rejected. |
// TestEncryptStreamHeaderValidation 验证非法头部会被拒绝。
func TestEncryptStreamHeaderValidation(t *testing.T) {
	enc := testStreamEncryptor(t, EncryptionAES256GCM, 32)
	var buf bytes.Buffer
	writer, err := enc.NewEncryptWriter(&buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	stream := buf.Bytes()
	if _, err := enc.NewDecryptReader(bytes.NewReader(stream[:streamHeaderSize-1]), nil); err == nil {
		t.Fatal("short header accepted")
	}
	badMagic := append([]byte(nil), stream...)
	badMagic[0] ^= 0xff
	if _, err := enc.NewDecryptReader(bytes.NewReader(badMagic), nil); !errors.Is(err, ErrAuth) {
		t.Fatalf("bad magic error = %v, want ErrAuth", err)
	}
	badSuite := append([]byte(nil), stream...)
	badSuite[13] = 9
	if _, err := enc.NewDecryptReader(bytes.NewReader(badSuite), nil); !errors.Is(err, ErrAuth) {
		t.Fatalf("bad suite error = %v, want ErrAuth", err)
	}
	missing, err := NewEncryptor(EncryptionOptions{
		Keys: []EncryptionKey{{ID: 1, Suite: EncryptionAES256GCM, Bytes: testEncryptionKey(EncryptionAES256GCM, 1)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := missing.NewDecryptReader(bytes.NewReader(stream), nil); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("missing key error = %v, want ErrKeyNotFound", err)
	}
}

// TestEncryptWriterPropagatesErrors verifies write failures are sticky and Close
// does not report success after them. | TestEncryptWriterPropagatesErrors 验证写入
// 失败会保持，Close 不会在其后报告成功。
func TestEncryptWriterPropagatesErrors(t *testing.T) {
	enc := testStreamEncryptor(t, EncryptionAES256GCM, 8)
	if _, err := enc.NewEncryptWriter(&failAfterWriter{after: 0}, nil); err == nil {
		t.Fatal("header write failure was ignored")
	}
	dst := &failAfterWriter{after: streamHeaderSize}
	writer, err := enc.NewEncryptWriter(dst, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(make([]byte, 9)); err == nil {
		t.Fatal("chunk write failure was ignored")
	}
	if err := writer.Close(); err == nil {
		t.Fatal("Close succeeded after a write failure")
	}
}

// failAfterWriter accepts bytes until after is reached. | failAfterWriter 在达到
// after 之前接受写入。
type failAfterWriter struct {
	after int
	n     int
}

// Write implements io.Writer. | Write 实现 io.Writer。
func (w *failAfterWriter) Write(p []byte) (int, error) {
	if w.n >= w.after {
		return 0, io.ErrClosedPipe
	}
	w.n += len(p)
	return len(p), nil
}

// TestEncryptStreamCopy verifies io.Copy drives the streaming API end to end. |
// TestEncryptStreamCopy 验证 io.Copy 能端到端驱动流式 API。
func TestEncryptStreamCopy(t *testing.T) {
	enc := testStreamEncryptor(t, EncryptionSM4GCM, 128)
	plain := bytes.Repeat([]byte("国密 streaming | "), 200)
	var buf bytes.Buffer
	writer, err := enc.NewEncryptWriter(&buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(writer, bytes.NewReader(plain)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := enc.NewDecryptReader(bytes.NewReader(buf.Bytes()), nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("io.Copy round trip mismatch")
	}
}
