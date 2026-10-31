package regexpx

import (
	"io"
	stdregexp "regexp"
	"strings"
	"testing"

	ydx "github.com/shibingli/ydx/regexpx"
)

var (
	sinkAny    any
	sinkBytes  []byte
	sinkString string
	sinkBool   bool
	sinkInts   []int
)

var (
	expandPat   = `(a)(b)(c)(d)`
	expandRe    = ydx.MustCompile(expandPat)
	expandStd   = stdregexp.MustCompile(expandPat)
	expandSrc   = "abcd"
	expandMatch = expandRe.FindStringSubmatchIndex(expandSrc)
	expandStdM  = expandStd.FindStringSubmatchIndex(expandSrc)
	expandTmpl  = `$1$2-$3${4}`
)

func BenchmarkCopy(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkAny = expandRe.Copy()
	}
}

func BenchmarkStdCopy(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkAny = expandStd.Copy()
	}
}

func BenchmarkExpandString(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkBytes = expandRe.ExpandString(nil, expandTmpl, expandSrc, expandMatch)
	}
}

func BenchmarkStdExpandString(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkBytes = expandStd.ExpandString(nil, expandTmpl, expandSrc, expandStdM)
	}
}

var (
	replacePat = `a+`
	replaceRe  = ydx.MustCompile(replacePat)
	replaceStd = stdregexp.MustCompile(replacePat)
	replaceSrc = strings.Repeat("a b ", 4096)
)

func BenchmarkReplaceAllString(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkString = replaceRe.ReplaceAllString(replaceSrc, `$0X`)
	}
}

func BenchmarkStdReplaceAllString(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkString = replaceStd.ReplaceAllString(replaceSrc, `$0X`)
	}
}

func BenchmarkReplaceAllLiteralString(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkString = replaceRe.ReplaceAllLiteralString(replaceSrc, `$0X`)
	}
}

func BenchmarkStdReplaceAllLiteralString(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkString = replaceStd.ReplaceAllLiteralString(replaceSrc, `$0X`)
	}
}

var (
	exactPat = `abc`
	exactRe  = ydx.MustCompile(exactPat)
	exactStd = stdregexp.MustCompile(exactPat)
	exactIn  = strings.Repeat("x", 4096) + "abc"
	runPat   = `\w+`
	runRe    = ydx.MustCompile(runPat)
	runStd   = stdregexp.MustCompile(runPat)
	runIn    = strings.Repeat("word ", 4096)
	wildPat  = `(?s).*needle.*`
	wildRe   = ydx.MustCompile(wildPat)
	wildStd  = stdregexp.MustCompile(wildPat)
	wildIn   = strings.Repeat("x", 4096) + "needle" + strings.Repeat("y", 4096)
	linPat   = `\d{4}-\d{2}-\d{2}`
	linRe    = ydx.MustCompile(linPat)
	linStd   = stdregexp.MustCompile(linPat)
	linIn    = strings.Repeat("x", 4096) + "2026-10-31"
	dfaPat   = `^[a-z]+$`
	dfaRe    = ydx.MustCompile(dfaPat)
	dfaStd   = stdregexp.MustCompile(dfaPat)
	dfaIn    = strings.Repeat("a", 4096)
)

func init() {
	exactRe.Longest()
	exactStd.Longest()
	runRe.Longest()
	runStd.Longest()
	wildRe.Longest()
	wildStd.Longest()
	linRe.Longest()
	linStd.Longest()
	dfaRe.Longest()
	dfaStd.Longest()
}

func BenchmarkLongestExact(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkString = exactRe.FindString(exactIn)
	}
}

func BenchmarkStdLongestExact(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkString = exactStd.FindString(exactIn)
	}
}

func BenchmarkLongestRun(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkString = runRe.FindString(runIn)
	}
}

func BenchmarkStdLongestRun(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkString = runStd.FindString(runIn)
	}
}

func BenchmarkLongestWild(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkString = wildRe.FindString(wildIn)
	}
}

func BenchmarkStdLongestWild(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkString = wildStd.FindString(wildIn)
	}
}

func BenchmarkLongestLinear(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkString = linRe.FindString(linIn)
	}
}

func BenchmarkStdLongestLinear(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkString = linStd.FindString(linIn)
	}
}

func BenchmarkLongestDFA(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkBool = dfaRe.MatchString(dfaIn)
	}
}

func BenchmarkStdLongestDFA(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkBool = dfaStd.MatchString(dfaIn)
	}
}

type runeReader struct {
	n     int
	total int
	r     rune
}

func (r *runeReader) ReadRune() (rune, int, error) {
	if r.n >= r.total {
		return 0, 0, io.EOF
	}
	r.n++
	return r.r, 1, nil
}

var (
	readerPat = `a`
	readerRe  = ydx.MustCompile(readerPat)
	readerStd = stdregexp.MustCompile(readerPat)
)

func BenchmarkMatchReaderEarly(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkBool = readerRe.MatchReader(&runeReader{total: 100000, r: 'a'})
	}
}

func BenchmarkStdMatchReaderEarly(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkBool = readerStd.MatchReader(&runeReader{total: 100000, r: 'a'})
	}
}

func BenchmarkFindReaderIndexEarly(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkInts = readerRe.FindReaderIndex(&runeReader{total: 100000, r: 'a'})
	}
}

func BenchmarkStdFindReaderIndexEarly(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkInts = readerStd.FindReaderIndex(&runeReader{total: 100000, r: 'a'})
	}
}

var (
	lookPat = `a(?=a)|aa`
	lookRe  = ydx.MustCompile(lookPat)
	lookIn  = strings.Repeat("a", 2048)
)

func BenchmarkLongestLookahead(b *testing.B) {
	lookRe.Longest()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkString = lookRe.FindString(lookIn)
	}
}

var (
	prefixPat = `(?P<x>abc)`
	prefixRe  = ydx.MustCompile(prefixPat)
	prefixStd = stdregexp.MustCompile(prefixPat)
)

func BenchmarkLiteralPrefix(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkString, _ = prefixRe.LiteralPrefix()
	}
}

func BenchmarkStdLiteralPrefix(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkString, _ = prefixStd.LiteralPrefix()
	}
}
