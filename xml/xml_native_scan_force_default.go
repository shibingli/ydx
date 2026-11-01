//go:build !xml_force_scalar && !xml_std

package xml

// forceScalar is false in normal builds, so architecture init functions may install SIMD
// kernels. | 正常构建中 forceScalar 为 false，架构 init 可以安装 SIMD 内核。
const forceScalar = false
