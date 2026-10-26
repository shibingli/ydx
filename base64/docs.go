// Package base64 provides an adaptive Base64 codec abstraction layer that hides the differences between underlying implementations. | Package base64 提供自适应的 Base64 编解码抽象层，隐藏底层实现的差异。
//
// Backend routing (determined by build tags, fully transparent to callers): | 后端分流（由构建标签决定，对调用方完全透明）：
//
//   - without the b64x_std tag: the self-developed codec on every architecture. amd64
//     selects hand-written AVX2, AVX-512BW and AVX-512 VBMI kernels at runtime by
//     instruction-set level: encoding uses VBMI > AVX-512BW > AVX2 > scalar, decoding uses
//     AVX-512BW > AVX2 > scalar (the VBMI2 decode kernel was retired because its VPCOMPRESSB
//     pack is slower than the AVX-512BW pack on current hardware); arm64 uses hand-written
//     NEON; other architectures use the pure-Go scalar kernel. No GOEXPERIMENT is required.
//     Backend() returns "yd-native"; |
//     未指定 b64x_std 标签：所有架构使用自研编解码器。amd64 按指令集级别在运行时选择手写
//     AVX2、AVX-512BW、AVX-512 VBMI 内核：编码按 VBMI > AVX-512BW > AVX2 > 标量，解码按
//     AVX-512BW > AVX2 > 标量（VBMI2 解码内核的 VPCOMPRESSB 打包在当前硬件上更慢，已退役）；
//     arm64 使用手写 NEON；其他架构使用纯 Go 标量内核。不需要 GOEXPERIMENT。Backend() 返回
//     "yd-native"；
//   - with the b64x_std tag: the standard library encoding/base64, Backend() returns
//     "encoding/base64". | 指定 b64x_std 标签：使用标准库 encoding/base64，Backend() 返回
//     "encoding/base64"。
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
//	out := base64.StdEncoding.AppendEncode(dst[:0], src)
//	data, err := base64.URLEncoding.DecodeString(token)
package base64
