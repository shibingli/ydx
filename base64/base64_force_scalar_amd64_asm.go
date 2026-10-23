//go:build amd64 && !b64x_std && b64x_force_scalar

package base64

// forceScalar disables the AVX2 kernels for scalar-path differential testing. | forceScalar
// 关闭 AVX2 内核，用于标量路径差分测试。
const forceScalar = true
