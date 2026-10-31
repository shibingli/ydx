package regexpx

import (
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

// runeStream is a RuneReader captured as UTF-8 text plus the byte offsets reported by ReadRune.
// The regexp engine matches the text, and inputOffset maps text byte offsets back to the reader's
// reported byte positions. | runeStream 把 RuneReader 捕获为 UTF-8 文本以及 ReadRune 上报的字节偏移。
// 正则引擎匹配文本，inputOffset 把文本字节偏移映射回 reader 上报的字节位置。
type runeStream struct {
	text         string
	inputOffsets []int // reported offsets at rune boundaries | 符文边界处的上报偏移
	textOffsets  []int // UTF-8 offsets at rune boundaries | 符文边界处的 UTF-8 偏移
}

// readRuneStream consumes reader. Any read error is treated as end of input, matching
// regexp.inputReader; this lets a match found before the error still be returned. | readRuneStream
// 消费 reader。任何读取错误都按输入结束处理，与 regexp.inputReader 一致；因此错误发生前已成立的
// 匹配仍可返回。
func readRuneStream(reader io.RuneReader) (runeStream, bool) {
	if reader == nil {
		return runeStream{}, false
	}
	var b strings.Builder
	inputOffsets := []int{0}
	textOffsets := []int{0}
	pos := 0
	for {
		r, size, err := reader.ReadRune()
		if err != nil || size == 0 {
			break
		}
		if size < 0 {
			size = 0
		}
		b.WriteRune(r)
		pos += size
		inputOffsets = append(inputOffsets, pos)
		textOffsets = append(textOffsets, b.Len())
	}
	return runeStream{
		text:         b.String(),
		inputOffsets: inputOffsets,
		textOffsets:  textOffsets,
	}, true
}

// inputOffset maps one UTF-8 text offset to the reader's reported byte offset. | inputOffset 把一个
// UTF-8 文本偏移映射为 reader 上报的字节偏移。
func (s runeStream) inputOffset(textByte int) int {
	if textByte < 0 {
		return -1
	}
	index := sort.SearchInts(s.textOffsets, textByte)
	if index >= len(s.textOffsets) {
		index = len(s.textOffsets) - 1
	}
	return s.inputOffsets[index]
}

// mapIndex maps every text offset in match, preserving -1 entries. | mapIndex 映射 match 中的每个文本
// 偏移，并保留 -1 项。
func (s runeStream) mapIndex(match []int) []int {
	if match == nil {
		return nil
	}
	out := make([]int, len(match))
	for i, v := range match {
		out[i] = s.inputOffset(v)
	}
	return out
}

// findReaderFixed handles a fixed-length pattern without begin/end/word/line assertions or
// backtracking by testing each complete rune window as it arrives. The first-byte set skips
// windows that cannot start a match. | findReaderFixed 处理无开头/结尾/词/行断言且无回溯的定长模式：
// 每个完整的符文窗口到达时测试一次，首字节集合跳过不可能开始的窗口。
func (r *Regexp) findReaderFixed(reader io.RuneReader, submatch bool) ([]int, bool) {
	if reader == nil {
		return nil, false
	}
	info := r.prog.info
	length := info.minLen
	if length <= 0 || length != info.maxLen || info.anchored ||
		info.hasBeginAssert || info.hasEndAssert || info.hasWordBoundary ||
		info.hasLineAnchor || info.hasBacktrack {
		return nil, false
	}
	runes := make([]rune, length)
	sizes := make([]int, length)
	buf := make([]byte, 0, length*4)
	inputOffsets := make([]int, length+1)
	textOffsets := make([]int, length+1)
	next := 0
	count := 0
	total := 0
	windowBytes := 0
	for {
		ch, size, err := reader.ReadRune()
		if err != nil || size == 0 {
			return nil, true
		}
		if size < 0 {
			size = 0
		}
		if count == length {
			windowBytes -= sizes[next]
		} else {
			count++
		}
		runes[next] = ch
		sizes[next] = size
		windowBytes += size
		total += size
		next = (next + 1) % length
		if count < length {
			continue
		}

		buf = buf[:0]
		inputOffsets[0] = total - windowBytes
		textOffsets[0] = 0
		for j := 0; j < length; j++ {
			index := (next + j) % length
			buf = utf8.AppendRune(buf, runes[index])
			inputOffsets[j+1] = inputOffsets[j] + sizes[index]
			textOffsets[j+1] = len(buf)
		}
		if info.firstBytesOK && !info.firstBytes.has(buf[0]) {
			continue
		}
		if !submatch {
			if r.MatchString(bytesToString(buf)) {
				return []int{inputOffsets[0], inputOffsets[length]}, true
			}
			continue
		}
		match := r.FindStringSubmatchIndex(bytesToString(buf))
		if match == nil {
			continue
		}
		stream := runeStream{
			text:         bytesToString(buf),
			inputOffsets: inputOffsets,
			textOffsets:  textOffsets,
		}
		return stream.mapIndex(match), true
	}
}
