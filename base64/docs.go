// Package b64x provides an adaptive Base64 codec abstraction layer that hides the differences between underlying implementations. | Package b64x 提供自适应的 Base64 编解码抽象层，隐藏底层实现的差异。
//
// Backend routing (determined by build tags, fully transparent to callers): | 后端分流（由构建标签决定，对调用方完全透明）：
//
//   - amd64 without the b64x_std tag: the self-developed codec. With
//     GOEXPERIMENT=simd it selects AVX-512 VBMI2/VBMI, baseline AVX-512, or AVX2
//     at runtime; without the experiment it uses the pure-Go scalar kernel.
//     Backend() returns "yd-native"; | amd64 且未指定 b64x_std 标签：自研编解码器。
//     启用 GOEXPERIMENT=simd 时在运行时选择 AVX-512 VBMI2/VBMI、基础 AVX-512 或 AVX2；
//     未启用时使用纯 Go 标量内核。Backend() 返回 "yd-native"；
//   - other architectures that cristalhq supports (386/arm/arm64/riscv64/ppc64le/s390x/...)
//     without the b64x_std tag: github.com/cristalhq/base64, with encoding/base64 for
//     CR/LF-bearing input and for the allocating string form; Backend() returns "cristalhq/base64"; | 其他
//     cristalhq 支持的架构（386/arm/arm64/riscv64/ppc64le/s390x/...）且未指定 b64x_std 标签：使用
//     github.com/cristalhq/base64；含 CR/LF 的输入与分配式字符串入口回退到 encoding/base64；
//     Backend() 返回 "cristalhq/base64"；
//   - architectures without a third-party backend (currently loong64) or with the b64x_std
//     tag set explicitly: the standard library encoding/base64, Backend() returns
//     "encoding/base64". | 没有第三方后端支持的架构（当前为 loong64）或显式指定 b64x_std 标签：
//     使用标准库 encoding/base64，Backend() 返回 "encoding/base64"。
//
// All backends expose exactly the same symbols and semantics: the four encoding variants
// StdEncoding, RawStdEncoding, URLEncoding and RawURLEncoding, plus the Encoding methods
// Encode, Decode, EncodeToString, DecodeString, EncodedLen, DecodedLen, AppendEncode and
// AppendDecode, with length calculations and encoding results byte-for-byte identical to
// encoding/base64. | 所有后端暴露完全相同的符号与语义：StdEncoding、RawStdEncoding、URLEncoding、
// RawURLEncoding 四个编码变体，以及 Encoding 的 Encode、Decode、EncodeToString、DecodeString、
// EncodedLen、DecodedLen、AppendEncode、AppendDecode 方法，长度计算与编码结果均与 encoding/base64
// 逐字节一致。
//
// Zero copy: AppendEncode and AppendDecode reuse the underlying array of the destination
// buffer when its capacity is sufficient, producing no new allocation; DecodeString
// allocates only the result. | 零拷贝：AppendEncode、AppendDecode 在目标缓冲区容量充足时复用其
// 底层数组，不产生新的分配；DecodeString 只分配结果本身。
//
// Differences from encoding/base64 (all backends behave identically): | 与 encoding/base64 的差异
// （所有后端行为一致）：
//
//   - on decode failure Decode returns (0, err); like encoding/base64 it may leave partial
//     output in dst. DecodeString returns (nil, err) and AppendDecode returns dst unchanged.
//     | 解码失败时 Decode 返回 (0, err)；与 encoding/base64 一样，dst 可能留有部分输出。
//     DecodeString 返回 (nil, err)，AppendDecode 原样返回 dst。
//   - when the destination buffer is shorter than DecodedLen(len(src)) it returns
//     ErrShortBuffer instead of panicking out of bounds; | 目标缓冲区长度小于
//     DecodedLen(len(src)) 时返回 ErrShortBuffer，而不是越界 panic；
//   - every illegal-data error can be matched with errors.Is(err, ErrInvalidData), while the
//     underlying error is kept for further matching. | 一切非法数据错误都可用
//     errors.Is(err, ErrInvalidData) 判定，同时保留底层错误供进一步匹配。
//
// Typical usage | 典型用法：
//
//	out := b64x.StdEncoding.AppendEncode(dst[:0], src)
//	data, err := b64x.URLEncoding.DecodeString(token)
package b64x
