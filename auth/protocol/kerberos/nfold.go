package kerberos

// gcd returns the greatest common divisor of a and b. | gcd 返回 a 与 b 的最大公约数。
func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// lcm returns the least common multiple of a and b. | lcm 返回 a 与 b 的最小公倍数。
func lcm(a, b int) int {
	if a == 0 || b == 0 {
		return 0
	}
	return a / gcd(a, b) * b
}

// bitAt returns the bit at big-endian position pos. | bitAt 返回大端位置 pos 的位。
func bitAt(data []byte, pos int) byte {
	return (data[pos/8] >> (7 - uint(pos%8))) & 1
}

// setBitOne sets the bit at big-endian position pos. | setBitOne 设置大端位置 pos 的位。
func setBitOne(data []byte, pos int) {
	data[pos/8] |= 1 << (7 - uint(pos%8))
}

// rotateRightBits rotates data right by shift bits. | rotateRightBits 把 data 循环右移
// shift 位。
func rotateRightBits(data []byte, shift int) []byte {
	total := len(data) * 8
	if total == 0 {
		return nil
	}
	shift %= total
	out := make([]byte, len(data))
	if shift == 0 {
		copy(out, data)
		return out
	}
	for i := 0; i < total; i++ {
		if bitAt(data, i) != 0 {
			setBitOne(out, (i+shift)%total)
		}
	}
	return out
}

// onesComplementAdd adds addend to dst in one's-complement arithmetic with
// end-around carry. | onesComplementAdd 以一补数运算把 addend 加到 dst，并执行循环进位。
func onesComplementAdd(dst, addend []byte) {
	carry := uint(0)
	for i := len(dst) - 1; i >= 0; i-- {
		sum := uint(dst[i]) + uint(addend[i]) + carry
		dst[i] = byte(sum)
		carry = sum >> 8
	}
	for carry != 0 {
		for i := len(dst) - 1; i >= 0 && carry != 0; i-- {
			sum := uint(dst[i]) + carry
			dst[i] = byte(sum)
			carry = sum >> 8
		}
	}
}

// nfold implements the RFC 3961 n-fold operation and returns size bytes. | nfold
// 实现 RFC 3961 n-fold 运算并返回 size 字节。
func nfold(input []byte, size int) []byte {
	if size <= 0 || len(input) == 0 {
		return nil
	}
	inputBits := len(input) * 8
	outputBits := size * 8
	length := lcm(inputBits, outputBits)
	replicas := length / inputBits
	stream := make([]byte, 0, length/8)
	for i := 0; i < replicas; i++ {
		stream = append(stream, rotateRightBits(input, 13*i)...)
	}
	out := make([]byte, size)
	addend := make([]byte, size)
	for offset := 0; offset+size <= len(stream); offset += size {
		copy(addend, stream[offset:offset+size])
		onesComplementAdd(out, addend)
	}
	return out
}
