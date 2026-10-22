//go:build arm64 && goexperiment.simd && !b64x_std && !b64x_force_scalar

package base64

// forceScalar keeps the NEON kernels installed in production builds. | forceScalar 让生产构建
// 保留 NEON 内核。
const forceScalar = false
