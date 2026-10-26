package challenge

import (
	_ "embed"
	"encoding/binary"
	"sync"

	"github.com/shibingli/ydx/errs"
)

// glyphSize is the width and height of one embedded glyph mask. | glyphSize 是一张嵌入字形掩码的宽高。
const glyphSize = 32

// glyphMagic is the glyph atlas magic. | glyphMagic 是字形图集魔数。
const glyphMagic = "YDXG"

// glyphVersion is the supported glyph atlas version. | glyphVersion 是支持的字形图集版本。
const glyphVersion = 1

// glyphBytes is the number of alpha bytes in one glyph. | glyphBytes 是一张字形掩码的阿尔法字节数。
const glyphBytes = glyphSize * glyphSize

//go:embed fontdata/glyphs.bin
var glyphData []byte

// glyphMask is one 32x32 alpha mask. | glyphMask 是一张 32x32 阿尔法掩码。
type glyphMask struct {
	alpha [glyphBytes]byte
}

// glyphAtlas is the parsed immutable glyph table. | glyphAtlas 是解析后的不可变字形表。
type glyphAtlas struct {
	masks  map[rune]glyphMask
	runes  []rune
	digits []rune
	latin  []rune
	han    []rune
}

var (
	glyphsOnce sync.Once
	glyphs     *glyphAtlas
	glyphsErr  error
)

// loadGlyphs parses the embedded atlas once. | loadGlyphs 只解析一次嵌入图集。
func loadGlyphs() (*glyphAtlas, error) {
	glyphsOnce.Do(func() {
		glyphs, glyphsErr = parseGlyphs(glyphData)
	})
	return glyphs, glyphsErr
}

// parseGlyphs decodes the binary atlas format. | parseGlyphs 解码二进制图集格式。
func parseGlyphs(data []byte) (*glyphAtlas, error) {
	if len(data) < 8 || string(data[:4]) != glyphMagic {
		return nil, errs.Detail(ErrAssets, "invalid glyph magic | 非法字形魔数")
	}
	version := binary.LittleEndian.Uint16(data[4:6])
	if version != glyphVersion {
		return nil, errs.Detail(ErrAssets, "unsupported glyph version %d | 不支持的字形版本 %d", version, version)
	}
	count := int(binary.LittleEndian.Uint16(data[6:8]))
	if count <= 0 || count > 4096 {
		return nil, errs.Detail(ErrAssets, "invalid glyph count %d | 非法字形数量 %d", count, count)
	}
	need := 8 + count*(4+glyphBytes)
	if len(data) < need {
		return nil, errs.Detail(ErrAssets, "truncated glyph atlas | 字形图集被截断")
	}
	out := &glyphAtlas{
		masks: make(map[rune]glyphMask, count),
		runes: make([]rune, 0, count),
	}
	offset := 8
	for i := 0; i < count; i++ {
		r := rune(binary.LittleEndian.Uint32(data[offset : offset+4]))
		offset += 4
		var mask glyphMask
		copy(mask.alpha[:], data[offset:offset+glyphBytes])
		offset += glyphBytes
		out.masks[r] = mask
		out.runes = append(out.runes, r)
		switch {
		case r >= '0' && r <= '9':
			out.digits = append(out.digits, r)
		case r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z':
			out.latin = append(out.latin, r)
		default:
			out.han = append(out.han, r)
		}
	}
	if len(out.runes) == 0 {
		return nil, errs.Detail(ErrAssets, "empty glyph atlas | 空字形图集")
	}
	return out, nil
}

// glyphFor returns the mask for one rune. | glyphFor 返回一个字符的掩码。
func (a *glyphAtlas) glyphFor(r rune) (glyphMask, bool) {
	mask, ok := a.masks[r]
	return mask, ok
}
