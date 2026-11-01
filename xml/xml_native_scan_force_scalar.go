//go:build xml_force_scalar && !xml_std

package xml

// forceScalar selects the portable scalar kernels regardless of the host instruction set. It
// exists for differential testing. | forceScalar 强制使用可移植标量内核而不论主机指令集，用于
// 差分测试。
const forceScalar = true
