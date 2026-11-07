package cn

import (
	"errors"
	"strings"
	"testing"
)

func TestMaskName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"张三", "张*"},
		{"张小明", "张*明"},
		{"欧阳娜娜", "欧**娜"},
		{"李", "*"},
		{"", ""},
		{" 王小明 ", "王*明"},
		{"Alice", "A***e"},
		{"😀ab😀", "😀**😀"},
	}
	for _, tc := range cases {
		if got := MaskName(tc.in); got != tc.want {
			t.Fatalf("MaskName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestMaskEmail(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"alice@example.com", "a***e@example.com"},
		{"ab@x.cn", "a*@x.cn"},
		{"a@x.cn", "*@x.cn"},
		{"张三@例子.中国", "张*@例子.中国"},
		{"alice", "a***e"},
		{"alice@", "a****@"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := MaskEmail(tc.in); got != tc.want {
			t.Fatalf("MaskEmail(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestMaskGeneric(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"a", "*"},
		{"ab", "a*"},
		{"abc", "a*c"},
		{"1234567890", "1********0"},
		{"张小明", "张*明"},
		{"😀abc😀", "😀***😀"},
	}
	for _, tc := range cases {
		if got := MaskGeneric(tc.in); got != tc.want {
			t.Fatalf("MaskGeneric(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeChineseName(t *testing.T) {
	t.Parallel()
	valid := map[string]string{
		" 张三 ":      "张三",
		"　张三　":      "张三",
		"阿依古丽·买买提":  "阿依古丽·买买提",
		"Mary Jane": "Mary Jane",
		"李":         "李",
		string(rune(0x200B)) + "张三" + string(rune(0xFEFF)): "张三",
	}
	for in, want := range valid {
		got, err := NormalizeChineseName(in)
		if err != nil {
			t.Fatalf("NormalizeChineseName(%q) returned error: %v", in, err)
		}
		if got != want {
			t.Fatalf("NormalizeChineseName(%q) = %q, want %q", in, got, want)
		}
	}

	invalidName := []string{"", "   ", "张\n三", strings.Repeat("李", maxNameRunes+1)}
	for _, in := range invalidName {
		if _, err := NormalizeChineseName(in); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("NormalizeChineseName(%q) error = %v, want ErrInvalidName", in, err)
		}
	}
	placeholders := []string{"test", "ANONYMOUS", "null", "测试", "匿名用户", "暂无", "***", "-"}
	for _, in := range placeholders {
		if _, err := NormalizeChineseName(in); !errors.Is(err, ErrPlaceholderName) {
			t.Fatalf("NormalizeChineseName(%q) error = %v, want ErrPlaceholderName", in, err)
		}
	}
}
