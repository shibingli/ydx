package regexpx_test

import (
	"fmt"

	"github.com/shibingli/ydx/regexpx"
)

// ExampleRegexp_FindStringSubmatchInto demonstrates reusing caller-owned submatch storage. |
// ExampleRegexp_FindStringSubmatchInto 演示复用调用方持有的子匹配存储。
func ExampleRegexp_FindStringSubmatchInto() {
	re := regexpx.MustCompile(`(?P<key>[a-z]+)=(?P<value>[0-9]+)`)
	var storage [8]string
	groups := re.FindStringSubmatchInto(storage[:0], "page=42&limit=10")
	fmt.Println(groups[0], groups[1], groups[2])
	// Output: page=42 page 42
}

// ExampleRegexp_FindStringSubmatchIndexInto demonstrates reusing caller-owned index storage. |
// ExampleRegexp_FindStringSubmatchIndexInto 演示复用调用方持有的索引存储。
func ExampleRegexp_FindStringSubmatchIndexInto() {
	re := regexpx.MustCompile(`([a-z]+)-([0-9]+)`)
	var storage [16]int
	index := re.FindStringSubmatchIndexInto(storage[:0], "abc-123")
	fmt.Println(index)
	// Output: [0 7 0 3 4 7]
}

// ExampleRegexp_FindSubmatchInto demonstrates byte-slice submatch storage. |
// ExampleRegexp_FindSubmatchInto 演示字节切片子匹配存储。
func ExampleRegexp_FindSubmatchInto() {
	re := regexpx.MustCompile(`(?P<key>[a-z]+)=(?P<value>[0-9]+)`)
	var storage [8][]byte
	groups := re.FindSubmatchInto(storage[:0], []byte("page=42"))
	fmt.Println(string(groups[1]), string(groups[2]))
	// Output: page 42
}
