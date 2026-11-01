package xml

import (
	"fmt"
	"strconv"
	"strings"
)

// corpusXML is a small document covering attributes, namespaces, CDATA, entities, comments,
// nested elements and predicates. | corpusXML 覆盖属性、命名空间、CDATA、实体、注释、嵌套元素与谓词。
const corpusXML = `<?xml version="1.0"?>
<catalog xmlns:x="urn:x">
  <!-- catalog comment -->
  <book id="b1" lang="en">
    <title>A &amp; B</title>
    <price>10.5</price>
    <x:tag>T</x:tag>
    <desc><![CDATA[c<d]]></desc>
  </book>
  <book id="b2">
    <title>Second</title>
    <price>20</price>
  </book>
</catalog>`

// benchData builds a ~1.7 MB catalog document with 8000 records. | benchData 构建约 1.7 MB、含
// 8000 条记录的 catalog 文档。
func benchData() []byte {
	var b strings.Builder
	b.Grow(2 << 20)
	b.WriteString("<catalog>")
	for i := 0; i < 8000; i++ {
		b.WriteString(`<book id="b`)
		b.WriteString(strconv.Itoa(i))
		b.WriteString(`"><title>Title &amp; Number `)
		b.WriteString(strconv.Itoa(i))
		b.WriteString(`</title><author>Author Name</author><price>19.99</price><year>2024</year><note>Some fairly long note text for the record with &lt;escaped&gt; content.</note></book>`)
	}
	b.WriteString("</catalog>")
	return []byte(b.String())
}

// benchTitles returns the title of every book in benchData. | benchTitles 返回 benchData 中每本书的
// 标题。
func benchTitles() []string {
	out := make([]string, 8000)
	for i := range out {
		out[i] = fmt.Sprintf("Title & Number %d", i)
	}
	return out
}
