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
// All backends export exactly the same symbol set (Marshal / Unmarshal / MarshalIndent / Valid /
// NewEncoder / NewDecoder / Prewarm / Backend), and each carries its own build constraint,
// compiling mutually exclusively with unique symbols, so any supported target platform can be
// built directly. | 各后端导出完全相同的符号集（Marshal / Unmarshal / MarshalIndent / Valid /
// NewEncoder / NewDecoder / Prewarm / Backend），且都配备对应的构建约束，互斥编译、符号唯一，
// 因此任何受支持的目标平台都能直接构建。
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
