package wal

// crc32cPoly is the reflected Castagnoli polynomial used by CRC32C. |
// crc32cPoly 是 CRC32C 使用的反射 Castagnoli 多项式。
const crc32cPoly = 0x82F63B78

// crc32cPow[i] is the GF(2) operator that advances a CRC by 8<<i zero bytes.
// Building the 64 matrices once makes crc32Combine a few matrix-vector
// multiplications instead of recomputing squares per call; the writer uses it
// on every large record. | crc32cPow[i] 是把 CRC 前移 8<<i 个零字节的 GF(2) 算子。
// 预先构建 64 个矩阵，使 crc32Combine 只需少量矩阵向量乘法，而不必每次调用重新
// 求平方；写入方对每条大记录都会用到它。
var crc32cPow [64][32]uint32

func init() {
	var one [32]uint32
	one[0] = crc32cPoly
	row := uint32(1)
	for n := 1; n < 32; n++ {
		one[n] = row
		row <<= 1
	}
	// The zlib combine starts from the one-bit operator; three squarings give
	// the one-byte operator and each further square doubles the byte count. |
	// zlib 合并从一比特算子开始；三次平方得到一字节算子，之后每次平方使字节数翻倍。
	var two, four [32]uint32
	gf2MatrixSquare(&two, &one)
	gf2MatrixSquare(&four, &two)
	gf2MatrixSquare(&crc32cPow[0], &four)
	for i := 1; i < len(crc32cPow); i++ {
		gf2MatrixSquare(&crc32cPow[i], &crc32cPow[i-1])
	}
}

// crc32Combine returns the CRC-32C of A||B from crc(A), crc(B) and len(B). |
// crc32Combine 由 crc(A)、crc(B) 与 len(B) 返回 A||B 的 CRC-32C。
func crc32Combine(crc1, crc2 uint32, len2 int64) uint32 {
	if len2 <= 0 {
		return crc1
	}
	for i := 0; len2 != 0; i++ {
		if len2&1 != 0 {
			crc1 = gf2MatrixTimes(&crc32cPow[i], crc1)
		}
		len2 >>= 1
	}
	return crc1 ^ crc2
}

// gf2MatrixTimes multiplies one GF(2) matrix by a vector. | gf2MatrixTimes 将
// 一个 GF(2) 矩阵与向量相乘。
func gf2MatrixTimes(mat *[32]uint32, vec uint32) uint32 {
	var sum uint32
	for i := 0; vec != 0; i++ {
		if vec&1 != 0 {
			sum ^= mat[i]
		}
		vec >>= 1
	}
	return sum
}

// gf2MatrixSquare squares one GF(2) matrix. | gf2MatrixSquare 对一个 GF(2) 矩阵求平方。
func gf2MatrixSquare(square, mat *[32]uint32) {
	for n := 0; n < 32; n++ {
		square[n] = gf2MatrixTimes(mat, mat[n])
	}
}
