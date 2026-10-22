package repotest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// repositoryRoot walks up from the current directory until it finds the ydx workspace markers.
// | repositoryRoot 从当前目录向上查找，直到发现 ydx 工作区标记。
func repositoryRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v | 获取工作目录失败", err)
	}
	for {
		if fileExists(filepath.Join(dir, "errs", "go.mod")) && fileExists(filepath.Join(dir, "middleware", "go.mod")) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("ydx repository root not found | 未找到 ydx 仓库根目录")
		}
		dir = parent
	}
}

// fileExists reports whether path names a regular file. | fileExists 报告 path 是否为普通文件。
func fileExists(name string) bool {
	info, err := os.Stat(name)
	return err == nil && !info.IsDir()
}

// walkFiles returns every regular file below root as a slash-separated relative path.
// | walkFiles 以斜杠分隔的相对路径返回 root 下的所有普通文件。
func walkFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".yd", ".bench", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, name)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v | 遍历失败", root, err)
	}
	return files
}

// moduleDirs returns the repository-relative directory of every go.mod.
// | moduleDirs 返回每个 go.mod 的仓库相对目录。
func moduleDirs(files []string) []string {
	var dirs []string
	for _, rel := range files {
		if path.Base(rel) != "go.mod" {
			continue
		}
		dir := path.Dir(rel)
		if dir == "." {
			dir = ""
		}
		dirs = append(dirs, dir)
	}
	return dirs
}

// under reports whether rel is dir or lives below it. | under 报告 rel 是否等于 dir 或位于其下。
func under(rel, dir string) bool {
	return rel == dir || strings.HasPrefix(rel, dir+"/")
}

// isTestFile reports whether rel is a Go test file. | isTestFile 报告 rel 是否为 Go 测试文件。
func isTestFile(rel string) bool {
	return strings.HasSuffix(rel, "_test.go")
}

// goFiles filters the walked files down to Go source files. | goFiles 把遍历结果过滤为 Go 源文件。
func goFiles(files []string) []string {
	var out []string
	for _, rel := range files {
		if strings.HasSuffix(rel, ".go") {
			out = append(out, rel)
		}
	}
	return out
}

// parseFile parses one Go file with imports and comments. | parseFile 解析一个 Go 文件（含导入与注释）。
func parseFile(t *testing.T, file *token.FileSet, name string) *ast.File {
	t.Helper()
	parsed, err := parser.ParseFile(file, name, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v | 解析失败", name, err)
	}
	return parsed
}

// importPath returns the unquoted import path of one import spec. | importPath 返回导入说明的原始路径。
func importPath(t *testing.T, spec *ast.ImportSpec) string {
	t.Helper()
	value, err := strconv.Unquote(spec.Path.Value)
	if err != nil {
		t.Fatalf("unquote import %s: %v | 导入路径解析失败", spec.Path.Value, err)
	}
	return value
}

// TestEveryModuleShipsDocsAndSum requires docs.go, go.mod and go.sum in every module root.
// | TestEveryModuleShipsDocsAndSum 要求每个模块根目录都带有 docs.go、go.mod 与 go.sum。
func TestEveryModuleShipsDocsAndSum(t *testing.T) {
	root := repositoryRoot(t)
	files := walkFiles(t, root)
	dirs := moduleDirs(files)
	if len(dirs) == 0 {
		t.Fatal("no modules found | 未发现任何模块")
	}
	for _, dir := range dirs {
		for _, name := range []string{"docs.go", "go.mod", "go.sum"} {
			rel := path.Join(dir, name)
			if !fileExists(filepath.Join(root, filepath.FromSlash(rel))) {
				t.Errorf("module %q is missing %s | 模块 %q 缺少 %s", dir, name, dir, name)
			}
		}
	}
}

// TestModulePathsMatchDirectories requires each go.mod module path to mirror its directory.
// | TestModulePathsMatchDirectories 要求每个 go.mod 的模块路径与目录一致。
func TestModulePathsMatchDirectories(t *testing.T) {
	root := repositoryRoot(t)
	files := walkFiles(t, root)
	for _, dir := range moduleDirs(files) {
		want := "github.com/shibingli/ydx"
		if dir != "" {
			want += "/" + dir
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(dir), "go.mod"))
		if err != nil {
			t.Fatalf("read %s/go.mod: %v | 读取 go.mod 失败", dir, err)
		}
		var got string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "module ") {
				got = strings.TrimSpace(strings.TrimPrefix(line, "module "))
				break
			}
		}
		if got != want {
			t.Errorf("module %q declares %q, want %q | 模块路径与目录不一致", dir, got, want)
		}
	}
}

// TestPackageNamesMatchDirectories requires every product package name to equal its directory name.
// Benchmark modules are excluded: they use a <component>bench package name to keep the package under
// test as an unaliased import. | TestPackageNamesMatchDirectories 要求每个产品包的包名等于目录名。
// 基准模块除外：它们使用 <component>bench 包名，使被测包可以不加别名导入。
func TestPackageNamesMatchDirectories(t *testing.T) {
	root := repositoryRoot(t)
	fset := token.NewFileSet()
	for _, rel := range goFiles(walkFiles(t, root)) {
		if under(rel, "benchmarks") || under(rel, "repotest") {
			continue
		}
		file := parseFile(t, fset, filepath.Join(root, filepath.FromSlash(rel)))
		dir := path.Dir(rel)
		want := path.Base(dir)
		if dir == "." {
			want = "ydx"
		}
		if file.Name.Name != want && !(isTestFile(rel) && file.Name.Name == want+"_test") {
			t.Errorf("%s: package %q, want %q | 包名与目录不一致", rel, file.Name.Name, want)
		}
	}
}

// TestNoYDImports forbids any dependency on the yd repository from ydx.
// | TestNoYDImports 禁止 ydx 依赖 yd 仓库。
func TestNoYDImports(t *testing.T) {
	root := repositoryRoot(t)
	fset := token.NewFileSet()
	for _, rel := range goFiles(walkFiles(t, root)) {
		file := parseFile(t, fset, filepath.Join(root, filepath.FromSlash(rel)))
		for _, spec := range file.Imports {
			imported := importPath(t, spec)
			if imported == "github.com/shibingli/yd" || strings.HasPrefix(imported, "github.com/shibingli/yd/") {
				t.Errorf("%s imports %q | ydx 不得依赖 yd", rel, imported)
			}
		}
	}
}

// TestNoDirectEncodingOrRegexpImports requires the wrapper packages to be the only import sites for
// the stdlib JSON, Base64 and regexp implementations. Tests and benchmark modules may use the
// stdlib directly as an oracle. | TestNoDirectEncodingOrRegexpImports 要求只有包装包可以直接导入
// 标准库 JSON、Base64 与 regexp 实现。测试与基准模块可以把标准库当作对照实现直接使用。
func TestNoDirectEncodingOrRegexpImports(t *testing.T) {
	root := repositoryRoot(t)
	fset := token.NewFileSet()
	for _, rel := range goFiles(walkFiles(t, root)) {
		if isTestFile(rel) || under(rel, "benchmarks") {
			continue
		}
		file := parseFile(t, fset, filepath.Join(root, filepath.FromSlash(rel)))
		for _, spec := range file.Imports {
			imported := importPath(t, spec)
			switch imported {
			case "encoding/json":
				if !under(rel, "json") {
					t.Errorf("%s imports encoding/json directly | 必须使用 json 包装包", rel)
				}
			case "encoding/base64":
				if !under(rel, "base64") {
					t.Errorf("%s imports encoding/base64 directly | 必须使用 base64 包装包", rel)
				}
			case "regexp", "github.com/dlclark/regexp2":
				if !under(rel, "regexpx") {
					t.Errorf("%s imports %s directly | 必须使用 regexpx 包装包", rel, imported)
				}
			case "log":
				t.Errorf("%s imports the standard log package | 必须使用 log 包", rel)
			}
		}
	}
}

// TestNoFmtErrorfOutsideErrs requires sentinel errors instead of fmt.Errorf in product code.
// | TestNoFmtErrorfOutsideErrs 要求产品代码使用哨兵错误而不是 fmt.Errorf。
func TestNoFmtErrorfOutsideErrs(t *testing.T) {
	root := repositoryRoot(t)
	fset := token.NewFileSet()
	for _, rel := range goFiles(walkFiles(t, root)) {
		if isTestFile(rel) || under(rel, "benchmarks") || under(rel, "errs") || under(rel, "repotest") {
			continue
		}
		file := parseFile(t, fset, filepath.Join(root, filepath.FromSlash(rel)))
		fmtName := ""
		for _, spec := range file.Imports {
			if importPath(t, spec) != "fmt" {
				continue
			}
			switch {
			case spec.Name == nil:
				fmtName = "fmt"
			case spec.Name.Name == "_" || spec.Name.Name == ".":
				continue
			default:
				fmtName = spec.Name.Name
			}
		}
		if fmtName == "" {
			continue
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			if ident.Name == fmtName && selector.Sel.Name == "Errorf" {
				t.Errorf("%s calls fmt.Errorf | 必须使用 errs 哨兵错误", rel)
			}
			return true
		})
	}
}

// TestNoDirectPanic forbids panic except for the recover rethrow inside a function literal.
// | TestNoDirectPanic 禁止直接 panic，唯一例外是函数字面量内 recover 之后的重新抛出。
func TestNoDirectPanic(t *testing.T) {
	root := repositoryRoot(t)
	fset := token.NewFileSet()
	for _, rel := range goFiles(walkFiles(t, root)) {
		if isTestFile(rel) || under(rel, "benchmarks") || under(rel, "repotest") {
			continue
		}
		file := parseFile(t, fset, filepath.Join(root, filepath.FromSlash(rel)))
		walkWithRecover(file, false, func(node ast.Node, allowed bool) {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return
			}
			ident, ok := call.Fun.(*ast.Ident)
			if !ok || ident.Name != "panic" || allowed {
				return
			}
			t.Errorf("%s calls panic outside a recover rethrow | 仅允许 recover 块内重新抛出 panic", rel)
		})
	}
}

// walkWithRecover visits node and reports whether a panic is inside a function literal that calls
// recover. | walkWithRecover 遍历节点，并报告 panic 是否位于调用 recover 的函数字面量内。
func walkWithRecover(node ast.Node, allowed bool, visit func(ast.Node, bool)) {
	ast.Inspect(node, func(child ast.Node) bool {
		if child == nil {
			return true
		}
		if literal, ok := child.(*ast.FuncLit); ok {
			walkWithRecover(literal.Body, allowed || containsRecover(literal.Body), visit)
			return false
		}
		visit(child, allowed)
		return true
	})
}

// containsRecover reports whether body contains a recover call. | containsRecover 报告函数体是否调用 recover。
func containsRecover(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		if found {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if ok && ident.Name == "recover" {
			found = true
			return false
		}
		return true
	})
	return found
}

// TestNoForeignKeys forbids database-level relations and GORM relation tags.
// | TestNoForeignKeys 禁止数据库级关系与 GORM 关系标签。
func TestNoForeignKeys(t *testing.T) {
	root := repositoryRoot(t)
	for _, rel := range walkFiles(t, root) {
		if under(rel, "repotest") {
			continue
		}
		switch path.Ext(rel) {
		case ".go", ".sql":
		default:
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read %s: %v | 读取失败", rel, err)
		}
		source := string(data)
		for _, marker := range []string{
			"FOREIGN KEY",
			"foreignKey:",
			"references:",
			"many2many:",
			"polymorphic:",
		} {
			if strings.Contains(source, marker) {
				t.Errorf("%s contains %q | 禁止数据库级关系", rel, marker)
			}
		}
	}
}

// TestNoCgoSQLiteDriver forbids the cgo-based SQLite driver in every module.
// | TestNoCgoSQLiteDriver 禁止所有模块引入基于 cgo 的 SQLite 驱动。
func TestNoCgoSQLiteDriver(t *testing.T) {
	root := repositoryRoot(t)
	for _, rel := range walkFiles(t, root) {
		if path.Base(rel) != "go.mod" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read %s: %v | 读取失败", rel, err)
		}
		if strings.Contains(string(data), "mattn/go-sqlite3") {
			t.Errorf("%s requires mattn/go-sqlite3 | 禁止 cgo SQLite 驱动", rel)
		}
	}
}

// TestBenchmarksStayInBenchmarkModules requires every Benchmark function outside repotest to live
// in a benchmarks module. | TestBenchmarksStayInBenchmarkModules 要求 repotest 之外的所有基准函数都位于
// benchmarks 模块中。
func TestBenchmarksStayInBenchmarkModules(t *testing.T) {
	root := repositoryRoot(t)
	fset := token.NewFileSet()
	for _, rel := range goFiles(walkFiles(t, root)) {
		if under(rel, "benchmarks") || under(rel, "repotest") {
			continue
		}
		file := parseFile(t, fset, filepath.Join(root, filepath.FromSlash(rel)))
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				continue
			}
			if strings.HasPrefix(fn.Name.Name, "Benchmark") {
				t.Errorf("%s declares %s outside benchmarks/ | 基准必须放在独立 benchmarks 模块中", rel, fn.Name.Name)
			}
		}
	}
}
