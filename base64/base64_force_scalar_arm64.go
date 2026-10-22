//go:build arm64 && goexperiment.simd && !b64x_std && b64x_force_scalar

package base64

// forceScalar disables the NEON kernels for scalar-path differential testing. | forceScalar
// 关闭 NEON 内核，用于标量路径差分测试。
const forceScalar = true
