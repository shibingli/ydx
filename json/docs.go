// Package json provides an adaptive JSON codec abstraction layer. | Package json 提供自适应的 JSON 编解码抽象层。
//
// The same API automatically selects the best backend under different architectures and build tags, with no need for callers to be aware of the underlying implementation: | 同一套 API 在不同架构与构建标签下自动选择最优后端，调用方无需感知底层实现：
//
//   - without the jsonx_std tag: the self-developed native codec on every architecture
//     (see json_native*.go). amd64 uses hand-written SSE2/AVX2/AVX-512BW scan kernels with
//     runtime priority AVX-512BW > AVX2 > SSE2; arm64 uses hand-written NEON scan kernels;
//     other architectures use the portable SWAR/scalar path. No GOEXPERIMENT is required.
//     Backend() returns "yd-native";
//     | 未设置 jsonx_std 标签：所有架构使用自研原生编解码器（见 json_native*.go）。amd64
//     使用手写 SSE2/AVX2/AVX-512BW 扫描内核，并按 AVX-512BW > AVX2 > SSE2 自动择优；arm64
//     使用手写 NEON 扫描内核；其他架构使用可移植 SWAR/标量路径。不需要 GOEXPERIMENT。
//     Backend() 返回 "yd-native"；
//   - with the jsonx_std tag: the standard library encoding/json (troubleshooting and compatibility reference, see jsonx_std.go) | 设置 jsonx_std 标签：标准库 encoding/json（排障与兼容性对照，见 jsonx_std.go）
//
// All backends export exactly the same symbol set, covering the whole encoding/json v1 surface:
// Marshal, Unmarshal, MarshalIndent, Valid, Compact, Indent and HTMLEscape; NewEncoder with
// Encode, SetEscapeHTML and SetIndent; NewDecoder with Decode, UseNumber,
// DisallowUnknownFields, Token, More, Buffered and InputOffset; and the type aliases Number,
// RawMessage, Delim, Token, Marshaler, Unmarshaler together with every encoding/json error type
// (SyntaxError, UnmarshalTypeError, InvalidUnmarshalError, UnsupportedTypeError,
// UnsupportedValueError, MarshalerError, plus the deprecated InvalidUTF8Error and
// UnmarshalFieldError) and the v1/v2 Options helpers. Each backend carries its own build
// constraint, compiling mutually exclusively with unique symbols, so any supported target
// platform can be built directly. | 各后端导出完全相同的符号集，覆盖 encoding/json v1 的全部
// 接口：Marshal、Unmarshal、MarshalIndent、Valid、Compact、Indent、HTMLEscape；NewEncoder
// 及其 Encode、SetEscapeHTML、SetIndent；NewDecoder 及其 Decode、UseNumber、
// DisallowUnknownFields、Token、More、Buffered、InputOffset；以及 Number、RawMessage、Delim、
// Token、Marshaler、Unmarshaler 类型别名和 encoding/json 的全部错误类型（SyntaxError、
// UnmarshalTypeError、InvalidUnmarshalError、UnsupportedTypeError、UnsupportedValueError、
// MarshalerError，以及已弃用的 InvalidUTF8Error、UnmarshalFieldError）与 v1/v2 Options
// 辅助函数。各后端都配备对应的构建约束，互斥编译、符号唯一，因此任何受支持的目标平台都能直接
// 构建。
//
// # v2 API | v2 API
//
// Marshal and Unmarshal take variadic Options. With no options they keep v1 semantics exactly;
// with options they start from DefaultOptionsV2 and apply the options as encoding/json/v2 does.
// Pass DefaultOptionsV1 (alone or joined) to request v1 semantics explicitly. The full v2 surface
// is available: MarshalWrite, UnmarshalRead, MarshalEncode, UnmarshalDecode, every v2 option
// constructor, Marshalers/Unmarshalers with MarshalFunc, MarshalToFunc, UnmarshalFunc and
// UnmarshalFromFunc, plus the SemanticError and ErrUnknownName error identities. |
// Marshal 与 Unmarshal 接受变参 Options。不传选项时完全保持 v1 语义；传入选项时从
// DefaultOptionsV2 开始按 encoding/json/v2 的规则应用。显式需要 v1 语义时传入
// DefaultOptionsV1（单独传入或经 JoinOptions 合并）。完整 v2 接口均可用：MarshalWrite、
// UnmarshalRead、MarshalEncode、UnmarshalDecode，全部 v2 选项构造器，Marshalers/Unmarshalers
// 与 MarshalFunc、MarshalToFunc、UnmarshalFunc、UnmarshalFromFunc，以及 SemanticError 与
// ErrUnknownName 错误标识。
//
//	v2 := []json.Options{json.DefaultOptionsV2()}
//	b, err := json.Marshal(value, v2...)
//
// The v2 semantics are implemented natively by this package, including the default differences
// (no HTML/JS escaping, nil slice as [], nil map as {}, case-sensitive names, duplicate-name and
// invalid-UTF-8 rejection, exact array lengths), the v2 struct tag options (case:ignore,
// case:strict, embed and embedded map/jsontext.Value fallbacks), raw-value canonicalization, and
// the standard SemanticError / SyntacticError types. No v2 semantic work is delegated to the
// standard library engine. | 本包原生实现 v2 语义，包括默认差异（不转义 HTML/JS、nil 切片输出 []、
// nil map 输出 {}、大小写敏感字段名、拒绝重复键与非法 UTF-8、精确数组长度）、v2 结构体标签选项
// （case:ignore、case:strict、embed 与 map/jsontext.Value 嵌入回退）、原始值规范化，以及标准
// SemanticError / SyntacticError 类型。v2 语义不转交标准库引擎执行。
//
// The v2 symbols rely on the encoding/json/v2 and encoding/json/jsontext packages, which are
// enabled by default in Go 1.27. Builds with GOEXPERIMENT=none (or older toolchains) cannot
// reference them; the v1 surface is unaffected. | v2 符号依赖 encoding/json/v2 与
// encoding/json/jsontext 包，它们在 Go 1.27 中默认启用。GOEXPERIMENT=none（或更早工具链）下
// 无法引用这些符号；v1 接口不受影响。
//
// The semantic baseline is encoding/json: strings are HTML-escaped, map keys are output in
// sorted order, []byte goes through StdEncoding base64, time.Time goes through RFC3339Nano,
// and json.Marshaler / json.TextMarshaler / json.RawMessage / omitempty are supported. | 语义基准是
// encoding/json：字符串按 HTML 转义、map 的 key 排序输出、[]byte 走 StdEncoding base64、
// time.Time 走 RFC3339Nano，并兼容 json.Marshaler / json.TextMarshaler / json.RawMessage /
// omitempty。
//
// Typical usage | 典型用法：
//
//	b, err := json.Marshal(v)
//	if err != nil {
//		return err
//	}
//	if err := json.Unmarshal(b, &out); err != nil {
//		return err
//	}
//
// To determine errors stably across backends, combine errors.Is with ErrSyntax / ErrTypeMismatch. | 需要跨后端稳定判定错误时，可用 errors.Is 配合 ErrSyntax / ErrTypeMismatch。
//
// Every error also keeps the encoding/json type: errors.As works with *json.SyntaxError,
// *json.UnmarshalTypeError, *json.InvalidUnmarshalError and the marshal error types under both
// backends, with the same messages and byte offsets as the standard library. On the error path
// only, the native backend may re-parse the failing input with encoding/json to recover that
// type; the success path never does so. | 所有错误同时保留 encoding/json 的类型：在两个后端下，
// errors.As 都能取出 *json.SyntaxError、*json.UnmarshalTypeError、
// *json.InvalidUnmarshalError 及各类编码错误，且文案与字节偏移都与标准库一致。只有在错误路径
// 上，自研后端才可能用 encoding/json 重新解析失败输入以取得该类型；成功路径绝不会这样做。
//
// For services whose payload types are fixed at startup, Prewarm compiles the encoder and decoder
// plans before the first request, so plan construction never lands on a latency-sensitive path.
// Pass a value to warm Marshal for its type and a typed nil pointer to warm Unmarshal for the
// pointed-to type; nested struct, slice, array and map types are warmed recursively. |
// 对于启动期即固定载荷类型的服务，Prewarm 会在首个请求之前编译编解码计划，使计划构建成本不会
// 落在延迟敏感路径上。传入值可预热其类型的 Marshal，传入类型化 nil 指针可预热其指向类型的
// Unmarshal；嵌套结构体、切片、数组与映射类型会递归预热。
//
//	json.Prewarm(User{}, (*User)(nil), (*[]User)(nil))
//
// The import path is github.com/shibingli/ydx/json while the package identifier is json,
// json, matching the directory name. | 导入路径是
// github.com/shibingli/ydx/json，包标识符为 json，与目录名一致。
package json
