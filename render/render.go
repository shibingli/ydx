package render

import (
	"errors"
	"html/template"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"

	"github.com/spf13/afero"

	"github.com/shibingli/ydx/afs"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
)

// LayoutKey is the data key that selects the whole-page layout for one render. The app facade
// falls back to its configured default layout when the key is absent or empty, so a portal and a
// management area can share one template engine while each wraps its pages in its own skeleton. |
// LayoutKey 是为单次渲染选择整页布局的数据键。键缺失或为空时，应用门面回退到配置的默认布局，
// 因此门户与管理区可以共用一个模板引擎，同时各自用自己的骨架包裹页面。
const LayoutKey = "Layout"

// isEscapeError reports whether err came from html/template's context computation. | isEscapeError
// 报告 err 是否来自 html/template 的上下文计算。
//
// Execution with nil data can also fail for ordinary reasons (a method on a nil value); only the
// context/escape diagnostics may poison the program. | 用 nil 数据执行也可能因普通原因失败（例如
// nil 值上的方法）；只有上下文/转义诊断才能使程序失效。
func isEscapeError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "context") || strings.Contains(msg, "escape")
}

// Sentinel errors. | 哨兵错误。
var (
	// ErrNoTemplates reports that the scan found no template files. | ErrNoTemplates 表示扫描未找到任何模板文件。
	ErrNoTemplates = errs.New("no templates found | 未找到任何模板文件")
	// ErrTemplateNotFound reports an unknown template name. | ErrTemplateNotFound 表示模板名不存在。
	ErrTemplateNotFound = errs.New("template not found | 模板不存在")
	// ErrNilFS reports a missing filesystem. | ErrNilFS 表示未提供文件系统。
	ErrNilFS = errs.New("nil filesystem | 文件系统为 nil")
)

// Options configures an Engine. | Options 配置渲染引擎。
type Options struct {
	// AssetFS is the filesystem rooted at the "/static" URL prefix, used by the asset
	// helper; nil means the helper resolves paths against the template filesystem.
	// | AssetFS 是根为 "/static" URL 前缀的文件系统，供 asset 助手解析；为空表示按模板文件系统解析。
	AssetFS afero.Fs
	// Funcs are extra template functions, merged over the defaults. | Funcs 是额外的模板函数，会覆盖同名默认函数。
	Funcs template.FuncMap
	// Root is the directory scanned for templates; empty means "templates". | Root 是模板扫描目录，空表示 "templates"。
	Root string
	// LeftDelim and RightDelim override the default action delimiters. | LeftDelim 与 RightDelim 覆盖默认的动作分隔符。
	LeftDelim  string
	RightDelim string
	// Exts lists the file extensions to parse; empty means [".html", ".gotmpl"]. | Exts 列出参与解析的扩展名，空表示 [".html", ".gotmpl"]。
	Exts []string
	// Production makes the asset helper prefer the ".min.js" / ".min.css" sibling of
	// a referenced file and hash that sibling; false keeps the source file.
	// | Production 使 asset 助手优先使用被引用文件的 .min.js / .min.css 同族文件并对其取哈希；false 使用源码。
	Production bool
	// Dev disables caching so edits take effect immediately. | Dev 关闭缓存，使改动立即生效。
	Dev bool
}

// normalize fills the defaults of Options. | normalize 填充 Options 的默认值。
func (o Options) normalize() Options {
	if o.Root == "" {
		o.Root = "templates"
	}
	o.Root = normalizeRoot(o.Root)
	if len(o.Exts) == 0 {
		o.Exts = []string{".html", ".gotmpl"}
	}
	return o
}

// maxBufferHint caps the initial output buffer guess. | maxBufferHint 限制初始输出缓冲的预估上限。
const maxBufferHint = 64 << 10

// engineState is one immutable snapshot of compiled entry programs. | engineState 是一次不可变的入口程序快照。
type engineState struct {
	programs map[string]*program
	known    map[string]bool
	funcs    template.FuncMap
	names    []string
}

// Engine renders templates from a filesystem. | Engine 从文件系统渲染模板。
//
// It is safe for concurrent use: renders read one immutable snapshot through an
// atomic pointer and allocate their state per call. Like any type holding a
// sync.Pool it must not be copied after first use; pass the pointer around.
// | 可安全并发使用：渲染经原子指针读取一份不可变快照，并按调用分配各自状态。
// 与任何持有 sync.Pool 的类型一样，首次使用后不得复制；请传递指针。
type Engine struct {

	// bufPool reuses output buffers of any grown capacity. | bufPool 复用任意增长后容量的输出缓冲。
	bufPool sync.Pool

	fsys  afero.Fs
	state atomic.Pointer[engineState]

	opts Options

	// loadMu serializes reloads in Dev mode. | loadMu 在 Dev 模式下串行化重载。
	loadMu sync.Mutex
}

// maxRetainedBuffer bounds the capacity an engine keeps in its buffer pool.
// | maxRetainedBuffer 限制引擎缓冲池保留的单个缓冲容量。
const maxRetainedBuffer = 1 << 20

// Buffer is an engine-owned output buffer. | Buffer 是引擎持有的输出缓冲。
//
// B is the current slice. A caller that lets RenderAppend grow it must assign
// the returned slice back to B so ReleaseBuffer retains the grown capacity.
// | B 是当前切片。调用方若让 RenderAppend 增长缓冲，必须把返回的切片写回 B，
// ReleaseBuffer 才能保留增长后的容量。
type Buffer struct {
	B []byte
}

// AcquireBuffer returns a zero-length buffer with at least hint capacity. | AcquireBuffer 返回长度为零、容量至少为 hint 的缓冲。
//
// The buffer comes from the engine's own pool, so a page that grows to tens of
// kilobytes is reused instead of reallocated on every request. Callers must
// return it with ReleaseBuffer once the response has been written. | 缓冲来自引擎自身的池，
// 因此增长到几十 KB 的页面会被复用而不是每请求重新分配。调用方在响应写完后必须用
// ReleaseBuffer 归还。
func (e *Engine) AcquireBuffer(hint int) *Buffer {
	if v := e.bufPool.Get(); v != nil {
		b := v.(*Buffer)
		if cap(b.B) >= hint {
			b.B = b.B[:0]
			return b
		}
	}
	if hint < 4096 {
		hint = 4096
	}
	return &Buffer{B: make([]byte, 0, hint)}
}

// ReleaseBuffer returns a buffer acquired from this engine. | ReleaseBuffer 归还从本引擎获取的缓冲。
func (e *Engine) ReleaseBuffer(b *Buffer) {
	if b == nil || cap(b.B) > maxRetainedBuffer {
		return
	}
	b.B = b.B[:0]
	e.bufPool.Put(b)
}

// New loads every template under the configured root. | New 加载配置根目录下的全部模板。
func New(fsys afero.Fs, o Options) (*Engine, error) {
	if fsys == nil {
		return nil, ErrNilFS
	}
	e := &Engine{fsys: fsys, opts: o.normalize()}
	if !e.opts.Dev {
		if err := e.load(); err != nil {
			return nil, err
		}
	}
	return e, nil
}

// Filesystem returns the underlying filesystem. | Filesystem 返回底层文件系统。
func (e *Engine) Filesystem() afero.Fs { return e.fsys }

// Options returns a copy of the normalized options. | Options 返回规范化配置的副本。
//
// Funcs is copied too: returning the map itself would let a caller mutate the engine (and race
// with Dev-mode reloads) through a value it only meant to inspect. | Funcs 也会复制：返回映射本身
// 会让调用方通过一个本意只用于查看的值修改引擎（并与 Dev 模式重载竞争）。
func (e *Engine) Options() Options {
	opts := e.opts
	if opts.Funcs != nil {
		funcs := make(template.FuncMap, len(opts.Funcs))
		for k, v := range opts.Funcs {
			funcs[k] = v
		}
		opts.Funcs = funcs
	}
	return opts
}

// FuncMap returns the effective template functions. | FuncMap 返回生效的模板函数表。
func (e *Engine) FuncMap() template.FuncMap {
	out := template.FuncMap{}
	for k, v := range e.funcMap() {
		out[k] = v
	}
	return out
}

// Clone returns an independent engine sharing the same filesystem and options. | Clone 返回共享文件系统与配置的独立引擎。
func (e *Engine) Clone() *Engine {
	opts := e.opts
	if opts.Funcs != nil {
		funcs := make(template.FuncMap, len(opts.Funcs))
		for k, v := range opts.Funcs {
			funcs[k] = v
		}
		opts.Funcs = funcs
	}
	c := &Engine{fsys: e.fsys, opts: opts}
	if !c.opts.Dev {
		_ = c.load()
	}
	return c
}

// AddFunc registers (or replaces) a template function and reloads. | AddFunc 注册（或替换）模板函数并重新加载。
//
// It returns a new Engine so shared instances are never mutated in place. | 返回新引擎，避免就地修改共享实例。
func (e *Engine) AddFunc(name string, fn any) *Engine {
	c := e.Clone()
	if c.opts.Funcs == nil {
		c.opts.Funcs = template.FuncMap{}
	}
	c.opts.Funcs[name] = fn
	if !c.opts.Dev {
		if err := c.load(); err != nil {
			// The signature cannot return an error; log loudly instead of handing back an engine
			// that silently lacks the function. | 签名无法返回错误；大声记录，而不是交回一个静默
			// 缺少该函数的引擎。
			log.Default().Error("render: reload after AddFunc failed | render：AddFunc 之后重新加载失败", log.Err(err))
		}
	}
	return c
}

// Names returns the sorted template file names. | Names 返回排序后的模板文件名字列表。
func (e *Engine) Names() []string {
	st := e.state.Load()
	if st == nil {
		return nil
	}
	out := make([]string, len(st.names))
	copy(out, st.names)
	return out
}

// templateFile pairs a template name with the path it is read from. | templateFile 把模板名与读取路径配对。
type templateFile struct {
	name string
	path string
}

// funcMap returns the merged default and caller functions. | funcMap 返回默认函数与调用方函数的合并结果。
func (e *Engine) funcMap() template.FuncMap {
	m := funcsFor(e.fsys, e.opts.AssetFS, e.opts.Production)
	for k, v := range e.opts.Funcs {
		m[k] = v
	}
	return m
}

// load parses, escapes and compiles every entry of the template tree. | load 解析、转义并编译模板树的每个入口。
func (e *Engine) load() error {
	files, err := e.collect()
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return errs.Detail(ErrNoTemplates, "root=%[1]s | 根目录=%[1]s", e.opts.Root)
	}

	funcs := e.funcMap()
	owned := make(map[string]bool, len(e.opts.Funcs))
	for name, fn := range funcs {
		if _, derr := funcValue(name, fn); derr != nil {
			return derr
		}
		if !validFuncName(name) {
			return errs.Detail(ErrInvalidFunc, "function=%[1]s | 函数=%[1]s", name)
		}
	}
	for name := range e.opts.Funcs {
		owned[name] = true
	}

	tmpl := template.New("yd").Funcs(funcs)
	if e.opts.LeftDelim != "" || e.opts.RightDelim != "" {
		tmpl = tmpl.Delims(e.opts.LeftDelim, e.opts.RightDelim)
	}
	names := make([]string, 0, len(files))
	for _, f := range files {
		b, rerr := afero.ReadFile(e.fsys, f.path)
		if rerr != nil {
			return errs.WrapDetail(rerr, ErrReadTemplate, "path=%[1]s | 路径=%[1]s", f.path)
		}
		if _, perr := tmpl.New(f.name).Parse(string(b)); perr != nil {
			return errs.WrapDetail(perr, ErrParseTemplate, "name=%[1]s | 名称=%[1]s", f.name)
		}
		names = append(names, f.name)
	}
	sort.Strings(names)

	entries := knownNames(tmpl.Templates())
	st := &engineState{
		programs: make(map[string]*program, len(entries)),
		known:    make(map[string]bool, len(entries)),
		names:    names,
		funcs:    funcs,
	}
	for _, name := range entries {
		st.known[name] = true
	}
	for _, name := range entries {
		// Each entry escapes in a private clone: a context error in one entry must
		// not poison the parse tree another entry still needs. | 每个入口在独立克隆中转义：
		// 某个入口的上下文错误不得污染其它入口仍需使用的解析树。
		clone, cerr := tmpl.Clone()
		if cerr != nil {
			st.programs[name] = &program{err: errs.Wrap(cerr, ErrCloneTemplate)}
			continue
		}
		if execErr := clone.ExecuteTemplate(io.Discard, name, nil); execErr != nil && isEscapeError(execErr) {
			// The forced pass is where html/template computes contexts. Swallowing its error made
			// New report success for a template whose branches end in different contexts, and the
			// first render failed later with an unactionable message. | 强制转义遍正是
			// html/template 计算上下文的时机。吞掉它的错误会让 New 对「分支结束于不同上下文」的
			// 模板报告成功，首次渲染才以无法定位问题的文案失败。
			st.programs[name] = &program{err: errs.Wrap(execErr, ErrExecuteTemplate)}
			continue
		}
		ht := clone.Lookup(name)
		if ht == nil || ht.Tree == nil {
			st.programs[name] = &program{err: errs.Detail(ErrParseTemplate, "name=%[1]s | 名称=%[1]s", name)}
			continue
		}
		prog, cerr := compileProgram(clone, name, funcs, owned)
		if errors.Is(cerr, errDerivedContext) {
			st.programs[name] = &program{fallback: &fallbackProgram{
				master:  tmpl,
				escaped: clone,
				funcs:   funcs,
				owned:   owned,
				name:    name,
			}}
			continue
		}
		if cerr != nil {
			return cerr
		}
		st.programs[name] = prog
	}
	e.state.Store(st)
	return nil
}

// collect walks the root and returns matching templates in a stable order. | collect 遍历根目录并按稳定顺序返回匹配的模板。
func (e *Engine) collect() ([]templateFile, error) {
	var files []templateFile
	err := afs.Walk(e.fsys, e.opts.Root, func(p string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel := toSlash(p)
		base := path.Base(rel)
		if strings.HasPrefix(base, ".") || strings.HasPrefix(base, "_") {
			return nil
		}
		if !e.matchExt(rel) {
			return nil
		}
		files = append(files, templateFile{name: trimRoot(rel, e.opts.Root), path: rel})
		return nil
	})
	if err != nil {
		return nil, errs.Wrap(err, ErrWalkTemplates)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	return files, nil
}

// matchExt reports whether p has a configured template extension. | matchExt 报告 p 是否具有配置的模板扩展名。
func (e *Engine) matchExt(p string) bool {
	for _, ext := range e.opts.Exts {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

// programFor returns the compiled entry program for name. | programFor 返回 name 对应的已编译入口程序。
func (e *Engine) programFor(name string) (*program, error) {
	st := e.state.Load()
	if st == nil {
		return nil, ErrTemplateNotFound
	}
	p, ok := st.programs[name]
	if !ok {
		return nil, errs.Detail(ErrTemplateNotFound, "name=%[1]s | 名称=%[1]s", name)
	}
	if p.err != nil {
		return nil, p.err
	}
	return p, nil
}

// Render executes the named template into w. | Render 把指定名称的模板渲染到 w。
//
// A translator injected into a map[string]any data value under TranslatorKey
// (see Translator) is bound to `tr` for this execution only, and an authority
// injected under AuthzKey (see Authz) is bound to `can`, `hasRole`, `perm` and
// `role` the same way. | 通过 TranslatorKey 键注入 map[string]any 型数据的译者（见 Translator）
// 仅对本次执行绑定到 `tr`；通过 AuthzKey 注入的判定主体（见 Authz）以同样的方式绑定到
// `can`、`hasRole`、`perm` 与 `role`。
func (e *Engine) Render(w io.Writer, name string, data any) error {
	if e.opts.Dev {
		if err := e.reload(); err != nil {
			return err
		}
	}
	p, err := e.programFor(name)
	if err != nil {
		return err
	}
	if p.fallback != nil {
		return p.fallback.fallback(w, unwrapData(data))
	}
	buf := e.AcquireBuffer(p.sizeHint)
	out, err := p.exec(buf.B, unwrapData(data), translatorFrom(data), authzFrom(data))
	buf.B = out
	if err != nil {
		e.ReleaseBuffer(buf)
		return err
	}
	_, werr := w.Write(out)
	e.ReleaseBuffer(buf)
	if werr != nil {
		return werr
	}
	return nil
}

// RenderAppend renders name and appends the result to dst. | RenderAppend 渲染 name 并把结果追加到 dst。
//
// It is the zero-copy counterpart of Render for callers that already own a
// buffer, such as the app facade composing a fragment and its layout. On error
// dst is returned unchanged beyond its original length. | 它是 Render 的零拷贝版本，
// 供已经持有缓冲的调用方（例如把片段与布局组合起来的 app 门面）使用。出错时 dst 只保留
// 原有内容。RenderAppend 会返回追加后的新切片。
func (e *Engine) RenderAppend(dst []byte, name string, data any) ([]byte, error) {
	if e.opts.Dev {
		if err := e.reload(); err != nil {
			return dst, err
		}
	}
	p, err := e.programFor(name)
	if err != nil {
		return dst, err
	}
	if p.fallback != nil {
		return p.fallback.fallbackAppend(dst, unwrapData(data))
	}
	start := len(dst)
	hint := p.sizeHint
	if hint > maxBufferHint {
		hint = maxBufferHint
	}
	if hint > 0 {
		dst = slices.Grow(dst, hint)
	}
	out, err := p.exec(dst, unwrapData(data), translatorFrom(data), authzFrom(data))
	if err != nil {
		return dst[:start], err
	}
	return out, nil
}

// reload serializes and performs a Dev-mode reload. | reload 串行执行 Dev 模式的重载。
func (e *Engine) reload() error {
	e.loadMu.Lock()
	defer e.loadMu.Unlock()
	return e.load()
}

// unwrapData follows text/template and applies the template to the concrete
// value inside a reflect.Value. | unwrapData 遵循 text/template：若数据是 reflect.Value，
// 则作用于其内部的具体值。
func unwrapData(data any) any {
	if rv, ok := data.(reflect.Value); ok && rv.IsValid() {
		return rv.Interface()
	}
	return data
}

// Exists reports whether a template name is known. | Exists 报告模板名是否为已知模板。
func (e *Engine) Exists(name string) bool {
	if e.opts.Dev {
		_ = e.reload()
	}
	st := e.state.Load()
	return st != nil && st.known[name]
}

// UsesFallback reports whether name is executed by the standard-library fallback.
// | UsesFallback 报告 name 是否由标准库回退执行器执行。
//
// The compiled executor handles every ordinary template; html/template occasionally derives
// a context clone that is only reachable through its internal name space, and those entries
// fall back to html/template. This diagnostic is read-only and exists so framework template
// sets can assert across package boundaries that they stay on the fast path. | 编译执行器
// 处理所有普通模板；html/template 偶尔会派生出只能经内部命名空间访问的上下文克隆，这些入口回退到
// html/template。该诊断是只读的，用于让框架模板集在跨包场景下断言仍处于快速路径。
//
// Unknown names, entries that failed to load, and a missing state all report true (fail
// closed), so a typo cannot silently pass a fast-path guard. | 未知名称、加载失败的条目以及状态
// 缺失一律返回 true（失败关闭），因此拼写错误不会让快速路径守卫静默通过。
func (e *Engine) UsesFallback(name string) bool {
	if e.opts.Dev {
		_ = e.reload()
	}
	st := e.state.Load()
	if st == nil {
		return true
	}
	p, ok := st.programs[name]
	if !ok || p == nil || p.err != nil {
		return true
	}
	return p.fallback != nil
}

// validFuncName reports whether name is a valid template function identifier.
// | validFuncName 报告 name 是否为合法的模板函数标识符。
func validFuncName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		switch {
		case r == '_':
		case i == 0 && unicode.IsLetter(r):
		case i > 0 && (unicode.IsLetter(r) || unicode.IsDigit(r)):
		default:
			return false
		}
	}
	return true
}

// toSlash converts a filesystem path to slash form. | toSlash 把文件系统路径转换为斜杠形式。
func toSlash(p string) string { return filepath.ToSlash(p) }

// normalizeRoot makes a template root slash-separated without destroying an absolute prefix. | normalizeRoot
// 把模板根规范为斜杠分隔，同时不破坏绝对路径前缀。
//
// The older implementation trimmed every leading separator, which turned "/srv/app/templates" into
// the relative "srv/app/templates" (and a UNC root into a different tree). Only "./" segments and
// trailing separators are removed here; a leading "/" or a drive root survives. | 旧实现裁掉所有前导
// 分隔符，把 "/srv/app/templates" 变成相对的 "srv/app/templates"（UNC 根也会变成另一棵树）。这里只去掉
// "./" 段与末尾分隔符，开头的 "/" 或盘符根都会保留。
func normalizeRoot(root string) string {
	root = filepath.ToSlash(root)
	for strings.HasPrefix(root, "./") {
		root = root[2:]
	}
	trimmed := strings.TrimRight(root, "/")
	if trimmed == "" {
		if strings.HasPrefix(root, "/") {
			return "/"
		}
		return "."
	}
	// A drive root such as "C:/" loses its slash in TrimRight but must stay absolute. | "C:/" 这类
	// 盘符根会在 TrimRight 中丢掉斜杠，但必须保持绝对。
	if len(trimmed) == 2 && trimmed[1] == ':' {
		return trimmed + "/"
	}
	return trimmed
}

// trimRoot strips the scan root prefix so template names stay portable. | trimRoot 去掉扫描根前缀，使模板名保持可移植。
func trimRoot(p, root string) string {
	p = toSlash(p)
	root = toSlash(root)
	if root == "" || root == "." {
		return strings.TrimPrefix(p, "./")
	}
	return strings.TrimPrefix(strings.TrimPrefix(p, root), "/")
}
