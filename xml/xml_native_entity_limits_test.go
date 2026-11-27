//go:build !xml_std

package xml

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// TestEntityExpansionBudgetCountsEachByteOnce pins that nested entity expansion is charged
// once per produced byte, not once per nesting level, so a document within the configured
// budget is accepted regardless of how its entities are nested. |
// TestEntityExpansionBudgetCountsEachByteOnce 固定嵌套实体展开按产出字节计费一次，而不是
// 每层嵌套重复计费；预算内的文档不应因嵌套结构被拒绝。
func TestEntityExpansionBudgetCountsEachByteOnce(t *testing.T) {
	value := strings.Repeat("x", 30)
	doc := `<!DOCTYPE a [<!ENTITY b "` + value + `"><!ENTITY a "&b;&b;">]><a>&a;</a>`
	d := NewDecoderBytes([]byte(doc))
	d.Limits = Limits{MaxEntityExpansion: 100}
	var text strings.Builder
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("token: %v | 解析失败：%v", err, err)
		}
		if data, ok := tok.(CharData); ok {
			text.Write(data)
		}
	}
	if got, want := text.String(), value+value; got != want {
		t.Fatalf("text = %q, want %q | 文本不符", got, want)
	}
}

// TestEntityExpansionBudgetStillChargesNestedOutput pins that the exactly-once accounting does
// not weaken the limit: nested output beyond the budget is still rejected. |
// TestEntityExpansionBudgetStillChargesNestedOutput 固定「只计费一次」不会放宽上限：超出预算的
// 嵌套产出仍被拒绝。
func TestEntityExpansionBudgetStillChargesNestedOutput(t *testing.T) {
	value := strings.Repeat("x", 30)
	doc := `<!DOCTYPE a [<!ENTITY b "` + value + `"><!ENTITY a "&b;&b;">]><a>&a;</a>`
	d := NewDecoderBytes([]byte(doc))
	d.Limits = Limits{MaxEntityExpansion: 50}
	var err error
	for err == nil {
		_, err = d.Token()
	}
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("err = %v, want ErrLimit | 期望 ErrLimit", err)
	}
}

// TestDecoderBoundsInternedNames pins that a stream of unique names cannot grow the decoder's
// interned-name cache without bound. | TestDecoderBoundsInternedNames 固定唯一名称流不会让解码器
// 的名称缓存无界增长。
func TestDecoderBoundsInternedNames(t *testing.T) {
	var doc strings.Builder
	doc.WriteString("<r>")
	for i := 0; i < maxInternedNames+64; i++ {
		fmt.Fprintf(&doc, "<n%d/>", i)
	}
	doc.WriteString("</r>")
	d := NewDecoderBytes([]byte(doc.String()))
	for {
		if _, err := d.Token(); err != nil {
			break
		}
	}
	source, ok := d.src.(*nativeSource)
	if !ok {
		t.Fatalf("source = %T, want *nativeSource | 数据源类型不符", d.src)
	}
	if got := len(source.l.names); got > maxInternedNames {
		t.Fatalf("interned names = %d, want <= %d | 名称缓存未受限", got, maxInternedNames)
	}
}

// TestDecoderRetainsSingleDTD pins that declarations from a repeated DOCTYPE directive are not
// accumulated, keeping retained entity state bounded by one directive. |
// TestDecoderRetainsSingleDTD 固定重复 DOCTYPE 指令的声明不会累积，保留的实体状态以一个指令为限。
func TestDecoderRetainsSingleDTD(t *testing.T) {
	doc := `<!DOCTYPE a [<!ENTITY first "one">]>` +
		`<!DOCTYPE a [<!ENTITY second "two">]><a>&first;</a>`
	d := NewDecoderBytes([]byte(doc))
	var text strings.Builder
	for {
		tok, err := d.Token()
		if err != nil {
			break
		}
		if data, ok := tok.(CharData); ok {
			text.Write(data)
		}
	}
	if got := text.String(); got != "one" {
		t.Fatalf("text = %q, want %q | 首个 DTD 的实体未展开", got, "one")
	}
	source, ok := d.src.(*nativeSource)
	if !ok {
		t.Fatalf("source = %T, want *nativeSource | 数据源类型不符", d.src)
	}
	if _, exists := source.l.entities["second"]; exists {
		t.Fatal("second DOCTYPE declarations were retained | 第二个 DOCTYPE 的声明被保留")
	}
}
