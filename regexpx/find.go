package regexpx

// FindString returns the text of the first match, or the empty string when nothing matches. | FindString
// 返回首个匹配的文本，没有匹配时返回空串。
func (r *Regexp) FindString(s string) string {
	var buf [2]int
	caps, ok, err := r.executeInto(s, 0, 2, -1, false, buf[:])
	if err != nil || !ok {
		return ""
	}
	return s[caps[0]:caps[1]]
}

// FindStringIndex returns the byte offset pair of the first match, or nil when nothing matches. |
// FindStringIndex 返回首个匹配的字节偏移对，没有匹配时返回 nil。
func (r *Regexp) FindStringIndex(s string) []int {
	var buf [2]int
	caps, ok, err := r.executeInto(s, 0, 2, -1, false, buf[:])
	if err != nil || !ok {
		return nil
	}
	return []int{caps[0], caps[1]}
}

// FindStringSubmatch returns the first match and its submatches, or nil when nothing matches. |
// FindStringSubmatch 返回首个匹配及其子匹配，没有匹配时返回 nil。
func (r *Regexp) FindStringSubmatch(s string) []string {
	if r.longest {
		if std := r.stdRegexp(); std != nil {
			return std.FindStringSubmatch(s)
		}
	}
	caps, ok, err := r.execute(s, 0, len(r.names)*2, -1, false)
	if err != nil || !ok {
		return nil
	}
	out := make([]string, len(r.names))
	for i := range out {
		slot := 2 * i
		if caps[slot] >= 0 && caps[slot+1] >= 0 {
			out[i] = s[caps[slot]:caps[slot+1]]
		}
	}
	return out
}

// FindStringSubmatchIndex returns the byte offset pairs of the first match and its submatches. Each
// group contributes two ints, and an unmatched group contributes -1, -1, matching the standard
// library's contract. | FindStringSubmatchIndex 返回首个匹配及其子匹配的字节偏移对。每个分组贡献两个
// 整数；未参与匹配的分组贡献 -1, -1，与标准库约定一致。
func (r *Regexp) FindStringSubmatchIndex(s string) []int {
	if r.longest {
		if std := r.stdRegexp(); std != nil {
			return std.FindStringSubmatchIndex(s)
		}
	}
	caps, ok, err := r.execute(s, 0, len(r.names)*2, -1, false)
	if err != nil || !ok {
		return nil
	}
	return caps
}

// FindStringSubmatchIndexInto is FindStringSubmatchIndex with a caller-provided index buffer. When
// dst has enough capacity the result aliases dst; otherwise a new slice is allocated. The returned
// slice is nil when nothing matches. | FindStringSubmatchIndexInto 是带调用方下标缓冲区的
// FindStringSubmatchIndex。dst 容量足够时结果复用 dst，否则分配新切片。没有匹配时返回 nil。
func (r *Regexp) FindStringSubmatchIndexInto(dst []int, s string) []int {
	width := len(r.names) * 2
	out := intBuffer(dst, width)
	if r.longest {
		if std := r.stdRegexp(); std != nil {
			index := std.FindStringSubmatchIndex(s)
			if index == nil || len(index) > len(out) {
				return nil
			}
			copy(out, index)
			return out[:len(index)]
		}
	}
	caps, ok, err := r.executeInto(s, 0, width, -1, false, out)
	if err != nil || !ok {
		return nil
	}
	if len(caps) != width {
		return nil
	}
	copy(out, caps)
	return out
}

// FindStringSubmatchInto is FindStringSubmatch with a caller-provided string buffer. When dst has
// enough capacity the result aliases dst; otherwise a new slice is allocated. The returned slice is
// nil when nothing matches. | FindStringSubmatchInto 是带调用方字符串缓冲区的 FindStringSubmatch。
// dst 容量足够时结果复用 dst，否则分配新切片。没有匹配时返回 nil。
func (r *Regexp) FindStringSubmatchInto(dst []string, s string) []string {
	width := len(r.names)
	var small [16]int
	var index []int
	if width*2 <= len(small) {
		index = small[:width*2]
	} else {
		index = make([]int, width*2)
	}
	index = r.FindStringSubmatchIndexInto(index, s)
	if index == nil {
		return nil
	}
	out := stringBuffer(dst, width)
	for i := 0; i < width; i++ {
		slot := 2 * i
		if index[slot] >= 0 && index[slot+1] >= 0 {
			out[i] = s[index[slot]:index[slot+1]]
		} else {
			out[i] = ""
		}
	}
	return out
}

// intBuffer returns a width-length buffer aliasing dst when possible. | intBuffer 返回尽可能复用 dst
// 的指定长度缓冲区。
func intBuffer(dst []int, width int) []int {
	if width <= 0 {
		return nil
	}
	if cap(dst) >= width {
		return dst[:width]
	}
	return make([]int, width)
}

// stringBuffer returns a width-length buffer aliasing dst when possible. | stringBuffer 返回尽可能复用
// dst 的指定长度缓冲区。
func stringBuffer(dst []string, width int) []string {
	if width <= 0 {
		return nil
	}
	if cap(dst) >= width {
		return dst[:width]
	}
	return make([]string, width)
}

// FindAllString returns the text of every non-overlapping match. n limits the number of matches; a
// negative n means all matches. | FindAllString 返回每个不重叠匹配的文本。n 限制匹配数量，负数表示全部。
func (r *Regexp) FindAllString(s string, n int) []string {
	out, _ := r.FindAllStringE(s, n)
	return out
}

// FindAllStringE is FindAllString with the engine error exposed. A scan aborted by ErrMatchTimeout
// returns the matches collected before the timeout together with that error. | FindAllStringE 是暴露
// 引擎错误的 FindAllString。被 ErrMatchTimeout 中止的扫描返回超时前已收集的匹配以及该错误。
func (r *Regexp) FindAllStringE(s string, n int) ([]string, error) {
	rows, err := r.findAll(s, n, 2)
	out := make([]string, len(rows))
	for i, row := range rows {
		out[i] = s[row[0]:row[1]]
	}
	return out, err
}

// FindAllStringIndex returns the byte offset pairs of every non-overlapping match. | FindAllStringIndex
// 返回每个不重叠匹配的字节偏移对。
func (r *Regexp) FindAllStringIndex(s string, n int) [][]int {
	out, _ := r.FindAllStringIndexE(s, n)
	return out
}

// FindAllStringIndexE is FindAllStringIndex with the engine error exposed. | FindAllStringIndexE 是暴露
// 引擎错误的 FindAllStringIndex。
func (r *Regexp) FindAllStringIndexE(s string, n int) ([][]int, error) {
	return r.findAll(s, n, 2)
}

// FindAllStringSubmatch returns every non-overlapping match together with its submatches. |
// FindAllStringSubmatch 返回每个不重叠匹配及其子匹配。
func (r *Regexp) FindAllStringSubmatch(s string, n int) [][]string {
	out, _ := r.FindAllStringSubmatchE(s, n)
	return out
}

// FindAllStringSubmatchE is FindAllStringSubmatch with the engine error exposed. |
// FindAllStringSubmatchE 是暴露引擎错误的 FindAllStringSubmatch。
func (r *Regexp) FindAllStringSubmatchE(s string, n int) ([][]string, error) {
	if r.longest {
		if std := r.stdRegexp(); std != nil {
			return std.FindAllStringSubmatch(s, n), nil
		}
	}
	width := len(r.names) * 2
	rows, err := r.findAll(s, n, width)
	out := make([][]string, len(rows))
	for i, caps := range rows {
		row := make([]string, len(r.names))
		for j := range row {
			slot := 2 * j
			if caps[slot] >= 0 && caps[slot+1] >= 0 {
				row[j] = s[caps[slot]:caps[slot+1]]
			}
		}
		out[i] = row
	}
	return out, err
}

// FindAllStringSubmatchIndex returns the byte offset pairs of every match and its submatches. |
// FindAllStringSubmatchIndex 返回每个匹配及其子匹配的字节偏移对。
func (r *Regexp) FindAllStringSubmatchIndex(s string, n int) [][]int {
	out, _ := r.FindAllStringSubmatchIndexE(s, n)
	return out
}

// FindAllStringSubmatchIndexE is FindAllStringSubmatchIndex with the engine error exposed. |
// FindAllStringSubmatchIndexE 是暴露引擎错误的 FindAllStringSubmatchIndex。
func (r *Regexp) FindAllStringSubmatchIndexE(s string, n int) ([][]int, error) {
	if r.longest {
		if std := r.stdRegexp(); std != nil {
			return std.FindAllStringSubmatchIndex(s, n), nil
		}
	}
	return r.findAll(s, n, len(r.names)*2)
}

// Find returns the first match in b. | Find 返回 b 中的首个匹配。
func (r *Regexp) Find(b []byte) []byte {
	index := r.FindIndex(b)
	if index == nil {
		return nil
	}
	return b[index[0]:index[1]]
}

// FindIndex returns the byte offset pair of the first match in b. | FindIndex 返回 b 中首个匹配的字节
// 偏移对。
func (r *Regexp) FindIndex(b []byte) []int {
	return r.FindStringIndex(bytesToString(b))
}

// FindSubmatch returns the first match and its submatches in b. | FindSubmatch 返回 b 中首个匹配及其
// 子匹配。
func (r *Regexp) FindSubmatch(b []byte) [][]byte {
	if r.longest {
		if std := r.stdRegexp(); std != nil {
			return std.FindSubmatch(b)
		}
	}
	index := r.FindSubmatchIndex(b)
	if index == nil {
		return nil
	}
	out := make([][]byte, len(index)/2)
	for i := range out {
		if index[2*i] >= 0 {
			out[i] = b[index[2*i]:index[2*i+1]]
		}
	}
	return out
}

// FindSubmatchIndex returns the byte offset pairs of the first match and its submatches in b. |
// FindSubmatchIndex 返回 b 中首个匹配及其子匹配的字节偏移对。
func (r *Regexp) FindSubmatchIndex(b []byte) []int {
	if r.longest {
		if std := r.stdRegexp(); std != nil {
			return std.FindSubmatchIndex(b)
		}
	}
	return r.FindStringSubmatchIndex(bytesToString(b))
}

// FindSubmatchIndexInto is FindSubmatchIndex with a caller-provided index buffer. | FindSubmatchIndexInto
// 是带调用方下标缓冲区的 FindSubmatchIndex。
func (r *Regexp) FindSubmatchIndexInto(dst []int, b []byte) []int {
	return r.FindStringSubmatchIndexInto(dst, bytesToString(b))
}

// FindSubmatchInto is FindSubmatch with a caller-provided slice buffer. When dst has enough
// capacity the result aliases dst; otherwise a new slice is allocated. | FindSubmatchInto 是带调用方
// 切片缓冲区的 FindSubmatch。dst 容量足够时结果复用 dst，否则分配新切片。
func (r *Regexp) FindSubmatchInto(dst [][]byte, b []byte) [][]byte {
	width := len(r.names)
	var small [16]int
	var index []int
	if width*2 <= len(small) {
		index = small[:width*2]
	} else {
		index = make([]int, width*2)
	}
	index = r.FindSubmatchIndexInto(index, b)
	if index == nil {
		return nil
	}
	if width == 0 {
		return nil
	}
	if cap(dst) < width {
		dst = make([][]byte, width)
	} else {
		dst = dst[:width]
	}
	for i := 0; i < width; i++ {
		slot := 2 * i
		if index[slot] >= 0 && index[slot+1] >= 0 {
			dst[i] = b[index[slot]:index[slot+1]]
		} else {
			dst[i] = nil
		}
	}
	return dst
}

// FindAll returns every non-overlapping match in b. | FindAll 返回 b 中每个不重叠匹配。
func (r *Regexp) FindAll(b []byte, n int) [][]byte {
	index := r.FindAllIndex(b, n)
	out := make([][]byte, len(index))
	for i, pair := range index {
		out[i] = b[pair[0]:pair[1]]
	}
	return out
}

// FindAllIndex returns the byte offset pairs of every non-overlapping match in b. | FindAllIndex 返回 b
// 中每个不重叠匹配的字节偏移对。
func (r *Regexp) FindAllIndex(b []byte, n int) [][]int {
	return r.FindAllStringIndex(bytesToString(b), n)
}

// FindAllSubmatch returns every non-overlapping match and its submatches in b. | FindAllSubmatch 返回 b
// 中每个不重叠匹配及其子匹配。
func (r *Regexp) FindAllSubmatch(b []byte, n int) [][][]byte {
	if r.longest {
		if std := r.stdRegexp(); std != nil {
			return std.FindAllSubmatch(b, n)
		}
	}
	index := r.FindAllSubmatchIndex(b, n)
	out := make([][][]byte, len(index))
	for i, row := range index {
		groups := make([][]byte, len(row)/2)
		for j := range groups {
			if row[2*j] >= 0 {
				groups[j] = b[row[2*j]:row[2*j+1]]
			}
		}
		out[i] = groups
	}
	return out
}

// FindAllSubmatchIndex returns the byte offset pairs of every match and its submatches in b. |
// FindAllSubmatchIndex 返回 b 中每个匹配及其子匹配的字节偏移对。
func (r *Regexp) FindAllSubmatchIndex(b []byte, n int) [][]int {
	if r.longest {
		if std := r.stdRegexp(); std != nil {
			return std.FindAllSubmatchIndex(b, n)
		}
	}
	return r.FindAllStringSubmatchIndex(bytesToString(b), n)
}
