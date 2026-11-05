//go:build linux && rdma && arm64

#include "textflag.h"

// func callFn(fn, a1, a2, a3 uintptr) uintptr
//
// AAPCS64 passes the first three integer arguments in X0, X1 and X2. BL
// overwrites X30 (LR), so save the Go caller's LR in the frame and restore it
// before RET. A 16-byte frame keeps SP 16-byte aligned for the C call. |
// AAPCS64 用 X0、X1、X2 传递前三个整数参数。BL 会覆盖 X30（LR），因此先把
// Go 调用方的 LR 保存到栈帧，返回前恢复。16 字节栈帧保证 C 调用时 SP 按
// 16 字节对齐。
TEXT ·callFn(SB), NOSPLIT, $16-40
	MOVD R30, 0(RSP)
	MOVD fn+0(FP), R9
	MOVD a1+8(FP), R0
	MOVD a2+16(FP), R1
	MOVD a3+24(FP), R2
	BL (R9)
	MOVD R0, ret+32(FP)
	MOVD 0(RSP), R30
	RET
