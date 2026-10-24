package log

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	ydxlog "github.com/shibingli/ydx/log"
)

// The comparison benchmarks keep the record content, level and sink identical across loggers:
// one Info-level JSON record per call, five or eight fields, written to io.Discard. Timestamp
// encodings differ by library and are part of each library's standard configuration; the
// per-module README records that caveat. | 对比基准让所有日志器的记录内容、级别与目的地保持一致：
// 每次调用写一条 Info 级 JSON 记录，5 或 8 个字段，输出到 io.Discard。时间戳编码随库的标准配置
// 而异，各库的差异记录在模块 README 中。

// newZapLogger returns a production-style JSON logger at the requested level. |
// newZapLogger 返回指定级别的生产风格 JSON 日志器。
func newZapLogger(level zapcore.Level) *zap.Logger {
	cfg := zap.NewProductionEncoderConfig()
	cfg.EncodeTime = zapcore.RFC3339NanoTimeEncoder
	core := zapcore.NewCore(zapcore.NewJSONEncoder(cfg), zapcore.AddSync(io.Discard), level)
	return zap.New(core)
}

// newZerologLogger returns a JSON logger at the requested level with a timestamp. |
// newZerologLogger 返回指定级别并带时间戳的 JSON 日志器。
func newZerologLogger(level zerolog.Level) zerolog.Logger {
	return zerolog.New(io.Discard).Level(level).With().Timestamp().Logger()
}

// newSlogLogger returns the standard-library JSON handler at the requested level. |
// newSlogLogger 返回指定级别的标准库 JSON 处理器。
func newSlogLogger(level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: level}))
}

// newLogrusLogger returns a JSON logrus logger at the requested level. |
// newLogrusLogger 返回指定级别的 JSON logrus 日志器。
func newLogrusLogger(level logrus.Level) *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	l.SetLevel(level)
	l.SetFormatter(&logrus.JSONFormatter{})
	return l
}

// benchLog5Compare emits the five-field record with the same values used by the other
// loggers, so the comparison is byte-for-byte equivalent apart from each library's encoding. |
// benchLog5Compare 输出与其它日志器相同取值的五字段记录，使对比除各库编码方式外逐字节等价。
func benchLog5Compare(l *ydxlog.Logger) {
	l.Info("request handled",
		ydxlog.Str("method", benchStrValue),
		ydxlog.Str("path", benchPathValue),
		ydxlog.Int("status", 200),
		ydxlog.Str("request_id", "7f3c1a9e"),
		ydxlog.Dur("took", 1500*time.Microsecond),
	)
}

// benchLog8 emits the same eight-field record as BenchmarkInfo8Fields. |
// benchLog8 输出与 BenchmarkInfo8Fields 相同的八字段记录。
func benchLog8(l *ydxlog.Logger) {
	l.Info("request handled",
		ydxlog.Str("method", benchStrValue),
		ydxlog.Str("path", benchPathValue),
		ydxlog.Int("status", 200),
		ydxlog.Int64("bytes", 4096),
		ydxlog.Bool("cached", true),
		ydxlog.Float64("latency_ms", 12.5),
		ydxlog.Time("at", benchTimeValue),
		ydxlog.Dur("took", 1500*time.Microsecond),
	)
}

// benchZap5 emits the five-field record through zap. | benchZap5 通过 zap 输出五字段记录。
func benchZap5(l *zap.Logger) {
	l.Info("request handled",
		zap.String("method", benchStrValue),
		zap.String("path", benchPathValue),
		zap.Int("status", 200),
		zap.String("request_id", "7f3c1a9e"),
		zap.Duration("took", 1500*time.Microsecond),
	)
}

// benchZap8 emits the eight-field record through zap. | benchZap8 通过 zap 输出八字段记录。
func benchZap8(l *zap.Logger) {
	l.Info("request handled",
		zap.String("method", benchStrValue),
		zap.String("path", benchPathValue),
		zap.Int("status", 200),
		zap.Int64("bytes", 4096),
		zap.Bool("cached", true),
		zap.Float64("latency_ms", 12.5),
		zap.Time("at", benchTimeValue),
		zap.Duration("took", 1500*time.Microsecond),
	)
}

// benchZerolog5 emits the five-field record through zerolog. | benchZerolog5 通过 zerolog 输出五字段记录。
func benchZerolog5(l zerolog.Logger) {
	l.Info().
		Str("method", benchStrValue).
		Str("path", benchPathValue).
		Int("status", 200).
		Str("request_id", "7f3c1a9e").
		Dur("took", 1500*time.Microsecond).
		Msg("request handled")
}

// benchZerolog8 emits the eight-field record through zerolog. | benchZerolog8 通过 zerolog 输出八字段记录。
func benchZerolog8(l zerolog.Logger) {
	l.Info().
		Str("method", benchStrValue).
		Str("path", benchPathValue).
		Int("status", 200).
		Int64("bytes", 4096).
		Bool("cached", true).
		Float64("latency_ms", 12.5).
		Time("at", benchTimeValue).
		Dur("took", 1500*time.Microsecond).
		Msg("request handled")
}

// benchSlog5 emits the five-field record through slog. | benchSlog5 通过 slog 输出五字段记录。
func benchSlog5(l *slog.Logger) {
	l.Info("request handled",
		"method", benchStrValue,
		"path", benchPathValue,
		"status", 200,
		"request_id", "7f3c1a9e",
		"took", 1500*time.Microsecond,
	)
}

// benchSlog8 emits the eight-field record through slog. | benchSlog8 通过 slog 输出八字段记录。
func benchSlog8(l *slog.Logger) {
	l.Info("request handled",
		"method", benchStrValue,
		"path", benchPathValue,
		"status", 200,
		"bytes", 4096,
		"cached", true,
		"latency_ms", 12.5,
		"at", benchTimeValue,
		"took", 1500*time.Microsecond,
	)
}

// benchLogrus5 emits the five-field record through logrus. | benchLogrus5 通过 logrus 输出五字段记录。
func benchLogrus5(l *logrus.Logger) {
	l.WithFields(logrus.Fields{
		"method":     benchStrValue,
		"path":       benchPathValue,
		"status":     200,
		"request_id": "7f3c1a9e",
		"took":       1500 * time.Microsecond,
	}).Info("request handled")
}

// benchLogrus8 emits the eight-field record through logrus. | benchLogrus8 通过 logrus 输出八字段记录。
func benchLogrus8(l *logrus.Logger) {
	l.WithFields(logrus.Fields{
		"method":     benchStrValue,
		"path":       benchPathValue,
		"status":     200,
		"bytes":      4096,
		"cached":     true,
		"latency_ms": 12.5,
		"at":         benchTimeValue,
		"took":       1500 * time.Microsecond,
	}).Info("request handled")
}

// BenchmarkInfoFieldsCompare compares the five-field JSON record across ydx, zap, zerolog, slog
// and logrus. Every logger writes to io.Discard and runs one warm-up call before the timer. |
// BenchmarkInfoFieldsCompare 对比 ydx、zap、zerolog、slog 与 logrus 的五字段 JSON 记录。
// 所有日志器写入 io.Discard，并在计时前执行一次预热。
func BenchmarkInfoFieldsCompare(b *testing.B) {
	b.Run("ydx", func(b *testing.B) {
		l := ydxlog.New(ydxlog.Options{Writer: io.Discard, Level: ydxlog.InfoLevel})
		benchLog5Compare(l)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchLog5Compare(l)
		}
	})
	b.Run("zap", func(b *testing.B) {
		l := newZapLogger(zapcore.InfoLevel)
		benchZap5(l)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchZap5(l)
		}
	})
	b.Run("zerolog", func(b *testing.B) {
		l := newZerologLogger(zerolog.InfoLevel)
		benchZerolog5(l)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchZerolog5(l)
		}
	})
	b.Run("slog", func(b *testing.B) {
		l := newSlogLogger(slog.LevelInfo)
		benchSlog5(l)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchSlog5(l)
		}
	})
	b.Run("logrus", func(b *testing.B) {
		l := newLogrusLogger(logrus.InfoLevel)
		benchLogrus5(l)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchLogrus5(l)
		}
	})
}

// BenchmarkInfo8FieldsCompare compares the eight-field JSON record across the same five loggers.
// The wider record exposes per-field formatting and numeric conversion costs. |
// BenchmarkInfo8FieldsCompare 对同样的五个日志器对比八字段 JSON 记录，更宽的记录会放大逐字段
// 格式化与数值转换成本。
func BenchmarkInfo8FieldsCompare(b *testing.B) {
	b.Run("ydx", func(b *testing.B) {
		l := ydxlog.New(ydxlog.Options{Writer: io.Discard, Level: ydxlog.InfoLevel})
		benchLog8(l)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchLog8(l)
		}
	})
	b.Run("zap", func(b *testing.B) {
		l := newZapLogger(zapcore.InfoLevel)
		benchZap8(l)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchZap8(l)
		}
	})
	b.Run("zerolog", func(b *testing.B) {
		l := newZerologLogger(zerolog.InfoLevel)
		benchZerolog8(l)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchZerolog8(l)
		}
	})
	b.Run("slog", func(b *testing.B) {
		l := newSlogLogger(slog.LevelInfo)
		benchSlog8(l)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchSlog8(l)
		}
	})
	b.Run("logrus", func(b *testing.B) {
		l := newLogrusLogger(logrus.InfoLevel)
		benchLogrus8(l)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchLogrus8(l)
		}
	})
}

// BenchmarkDisabledCompare measures a below-threshold Info call on an Error-level logger.
// The ideal path performs no formatting and no allocation. |
// BenchmarkDisabledCompare 测量 Error 级日志器上低于阈值的 Info 调用，理想路径不做格式化且零分配。
func BenchmarkDisabledCompare(b *testing.B) {
	b.Run("ydx", func(b *testing.B) {
		l := ydxlog.New(ydxlog.Options{Writer: io.Discard, Level: ydxlog.ErrorLevel})
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchLog5Compare(l)
		}
	})
	b.Run("zap", func(b *testing.B) {
		l := newZapLogger(zapcore.ErrorLevel)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchZap5(l)
		}
	})
	b.Run("zerolog", func(b *testing.B) {
		l := newZerologLogger(zerolog.ErrorLevel)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchZerolog5(l)
		}
	})
	b.Run("slog", func(b *testing.B) {
		l := newSlogLogger(slog.LevelError)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchSlog5(l)
		}
	})
	b.Run("logrus", func(b *testing.B) {
		l := newLogrusLogger(logrus.ErrorLevel)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchLogrus5(l)
		}
	})
}

// BenchmarkParallelCompare measures sustained concurrent writers for each logger. |
// BenchmarkParallelCompare 测量每个日志器在持续并发写入下的表现。
func BenchmarkParallelCompare(b *testing.B) {
	b.Run("ydx", func(b *testing.B) {
		// io.Discard is stateless and safe for concurrent writes, so the parallel case uses the
		// documented lock-free writer mode; the serial case above keeps the default lock. |
		// io.Discard 无状态且可安全并发写入，因此并行用例使用文档化的无锁写入模式；上面的串行
		// 用例仍使用默认加锁模式。
		l := ydxlog.New(ydxlog.Options{Writer: io.Discard, Level: ydxlog.InfoLevel, ConcurrentWrites: true})
		benchLog5Compare(l)
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				benchLog5Compare(l)
			}
		})
	})
	b.Run("zap", func(b *testing.B) {
		l := newZapLogger(zapcore.InfoLevel)
		benchZap5(l)
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				benchZap5(l)
			}
		})
	})
	b.Run("zerolog", func(b *testing.B) {
		l := newZerologLogger(zerolog.InfoLevel)
		benchZerolog5(l)
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				benchZerolog5(l)
			}
		})
	})
	b.Run("slog", func(b *testing.B) {
		l := newSlogLogger(slog.LevelInfo)
		benchSlog5(l)
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				benchSlog5(l)
			}
		})
	})
	b.Run("logrus", func(b *testing.B) {
		l := newLogrusLogger(logrus.InfoLevel)
		benchLogrus5(l)
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				benchLogrus5(l)
			}
		})
	})
}
