package wal

import "github.com/shibingli/ydx/errs"

// Sentinel errors returned by the WAL. | WAL 返回的哨兵错误。
//
// Every sentinel is declared with errs.New so the message is bilingual and
// errors.Is keeps working through every wrapping layer. | 所有哨兵均通过
// errs.New 声明，保证中英文案一致，且经过任意包装层后 errors.Is 仍然有效。
var (
	// ErrClosed reports an operation on a WAL that is already closed. | 表示在已关闭的 WAL 上执行操作。
	ErrClosed = errs.New("wal: closed | wal：已关闭")

	// ErrReadOnly reports a write operation on a read-only WAL. | 表示在只读 WAL 上执行写操作。
	ErrReadOnly = errs.New("wal: read-only | wal：只读模式")

	// ErrQueueFull reports that the bounded append queue is full. | 表示有界追加队列已满。
	ErrQueueFull = errs.New("wal: append queue is full | wal：追加队列已满")

	// ErrRecordTooLarge reports a record larger than MaxRecordBytes. | 表示记录超过 MaxRecordBytes 上限。
	ErrRecordTooLarge = errs.New("wal: record too large | wal：记录过大")

	// ErrInvalidRecord reports a malformed caller-supplied record. | 表示调用方提供的记录非法。
	ErrInvalidRecord = errs.New("wal: invalid record | wal：非法记录")

	// ErrCorrupt reports on-disk data that violates the WAL format or a
	// confirmed high-watermark invariant. | 表示磁盘数据违反 WAL 格式或已确认高水位不变量。
	ErrCorrupt = errs.New("wal: corrupt data | wal：数据损坏")

	// ErrUnsupported reports an unknown format version or an unsupported
	// platform capability. | 表示未知格式版本或不受支持的平台能力。
	ErrUnsupported = errs.New("wal: unsupported | wal：不支持")

	// ErrStorage reports an I/O or synchronization failure. | 表示 I/O 或同步失败。
	ErrStorage = errs.New("wal: storage failure | wal：存储失败")

	// ErrLocked reports that another process holds the directory lock. | 表示其它进程持有目录锁。
	ErrLocked = errs.New("wal: directory is locked | wal：目录已被锁定")

	// ErrInvalidOptions reports mutually exclusive or out-of-range options. | 表示选项冲突或越界。
	ErrInvalidOptions = errs.New("wal: invalid options | wal：非法选项")

	// ErrInvalidKey reports malformed key material or a bad key ring. | 表示密钥材料或密钥环非法。
	ErrInvalidKey = errs.New("wal: invalid key | wal：非法密钥")

	// ErrKeyNotFound reports a record or META key ID missing from the key ring. | 表示记录或 META 使用的密钥 ID 不在密钥环中。
	ErrKeyNotFound = errs.New("wal: key not found | wal：未找到密钥")

	// ErrAuth reports a failed AEAD authentication or a failed KCV check. | 表示 AEAD 认证或 KCV 校验失败。
	ErrAuth = errs.New("wal: authentication failed | wal：认证失败")

	// ErrCipherMismatch reports an encryption policy or cipher suite mismatch. | 表示加密策略或密码套件不匹配。
	ErrCipherMismatch = errs.New("wal: cipher mismatch | wal：密码套件不匹配")

	// ErrCodecMismatch reports a record compressed with a codec that is not
	// registered on this WAL. | 表示记录使用了本 WAL 未注册的压缩算法。
	ErrCodecMismatch = errs.New("wal: compression codec mismatch | wal：压缩算法不匹配")

	// ErrCodecFailure reports a codec that returned an error or panicked. | 表示压缩算法返回错误或发生 panic。
	ErrCodecFailure = errs.New("wal: compression codec failed | wal：压缩算法失败")

	// ErrTooLarge reports a declared length above the 1 GiB format hard limit. | 表示声明长度超过 1 GiB 格式硬上限。
	ErrTooLarge = errs.New("wal: declared length is too large | wal：声明长度过大")

	// ErrTooShort reports a caller buffer too small for ReadInto. | 表示 ReadInto 的调用方缓冲不足。
	ErrTooShort = errs.New("wal: destination buffer is too short | wal：目标缓冲过短")

	// ErrNotFound reports a missing or truncated LSN. | 表示 LSN 不存在或已被截断。
	ErrNotFound = errs.New("wal: record not found | wal：记录不存在")

	// ErrMissingSegment reports a segment that the durable metadata proves
	// existed but whose file or directory entry is gone. | 表示持久元数据证明存在但文件或目录项已丢失的分段。
	ErrMissingSegment = errs.New("wal: segment is missing | wal：分段缺失")

	// ErrStreamIncomplete reports a stream without an end record. | 表示流缺少结束记录。
	ErrStreamIncomplete = errs.New("wal: stream is incomplete | wal：流不完整")

	// ErrRandomSource reports a failure while reading cryptographic randomness. | 表示读取密码学随机数失败。
	ErrRandomSource = errs.New("wal: random source failure | wal：随机源失败")

	// ErrTxnClosed reports an operation on a transaction that already reached
	// a terminal state. | 表示在已进入终态的事务上执行操作。
	ErrTxnClosed = errs.New("wal: transaction is closed | wal：事务已关闭")

	// ErrTxnTooLarge reports a transaction above TxnMaxBytes or TxnMaxRecords. | 表示事务超过 TxnMaxBytes 或 TxnMaxRecords。
	ErrTxnTooLarge = errs.New("wal: transaction is too large | wal：事务过大")

	// ErrTxnTooManyKeys reports a transaction above TxnMaxKeys. | 表示事务声明的键超过 TxnMaxKeys。
	ErrTxnTooManyKeys = errs.New("wal: transaction declares too many keys | wal：事务声明的键过多")

	// ErrTxnConflict reports an optimistic serialization conflict. | 表示乐观并发冲突。
	ErrTxnConflict = errs.New("wal: transaction conflict | wal：事务冲突")

	// ErrTxnTooOld reports a snapshot older than the conflict window. | 表示快照早于冲突窗口。
	ErrTxnTooOld = errs.New("wal: transaction snapshot is too old | wal：事务快照过旧")

	// ErrBackup reports an asynchronous backup failure. | 表示异步备份失败。
	ErrBackup = errs.New("wal: backup failed | wal：备份失败")

	// ErrDedupCorrupt reports a content-dedup reference that cannot be
	// resolved safely. | 表示内容去重引用无法安全解析。
	ErrDedupCorrupt = errs.New("wal: deduplication reference is corrupt | wal：去重引用损坏")

	// ErrIdempotencyConflict reports the same idempotency key used with a
	// different payload. | 表示同一幂等键对应不同内容。
	ErrIdempotencyConflict = errs.New("wal: idempotency key conflict | wal：幂等键冲突")
)
