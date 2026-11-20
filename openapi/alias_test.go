package openapi

import (
	"testing"

	"github.com/spf13/afero"
)

// aliasHandlerSource is a handler fixture whose annotations use the Go type name instead of
// the @Name component name. | aliasHandlerSource 是处理器夹具，其注解使用 Go 类型名而非
// @Name 组件名。
const aliasHandlerSource = `package api

// ListRecords lists records. | ListRecords 列出记录。
//
// @Summary List records | 列出记录
// @Tags records
// @Produce json
// @Success 200 {object} userRecord "record | 记录"
// @Router /records [get]
func ListRecords() {}

// ListQualifiedRecords lists records through a package qualified token. | ListQualifiedRecords
// 通过带包限定的类型标记列出记录。
//
// @Summary List qualified records | 列出限定记录
// @Tags records
// @Produce json
// @Success 200 {array} model.userRecord "records | 记录列表"
// @Router /records/qualified [get]
func ListQualifiedRecords() {}

// GetUnknown returns a type that carries no type annotation. | GetUnknown 返回一个没有任何
// 类型注解的类型。
//
// @Summary Get unknown | 获取未知类型
// @Tags records
// @Produce json
// @Success 200 {object} model.Unknown "unknown | 未知"
// @Router /records/unknown [get]
func GetUnknown() {}
`

// aliasTypeSource is a type fixture whose @Name differs from its Go type name. |
// aliasTypeSource 是 @Name 与 Go 类型名不同的类型夹具。
const aliasTypeSource = "package model\n\n" +
	"// userRecord is the storage record. | userRecord 是存储记录。\n" +
	"//\n" +
	"// @Name PublicRecord\n" +
	"// @Description Public record projection. | 公开记录投影。\n" +
	"type userRecord struct {\n" +
	"\t// Name is the record name. | Name 为记录名。\n" +
	"\tName string `json:\"name\"`\n" +
	"}\n"

// newAliasFS builds a memory file system holding the alias fixtures. | newAliasFS 构造存放别名
// 夹具的内存文件系统。
func newAliasFS(t *testing.T) afero.Fs {
	t.Helper()
	fs := afero.NewMemMapFs()
	if err := afero.WriteFile(fs, "/api/handlers.go", []byte(aliasHandlerSource), 0o644); err != nil {
		t.Fatalf("write handler fixture: %v | 写入处理器夹具失败", err)
	}
	if err := afero.WriteFile(fs, "/model/types.go", []byte(aliasTypeSource), 0o644); err != nil {
		t.Fatalf("write type fixture: %v | 写入类型夹具失败", err)
	}
	return fs
}

// TestBuildResolvesGoTypeAliasesToAnnotatedNames verifies that references written with the Go
// type name, bare or package qualified, are rewritten onto the @Name component and that
// references without any annotation are materialized instead of staying dangling. |
// TestBuildResolvesGoTypeAliasesToAnnotatedNames 验证以 Go 类型名（裸名或带包限定）书写的
// 引用会被改写到 @Name 组件，且没有任何注解的引用会被补齐而不是保持悬空。
func TestBuildResolvesGoTypeAliasesToAnnotatedNames(t *testing.T) {
	fs := newAliasFS(t)
	types, err := ParseTypeAnnotations(fs, []string{"/model"})
	if err != nil {
		t.Fatalf("ParseTypeAnnotations: %v | 解析类型注解失败", err)
	}
	if sa := types.Schemas["PublicRecord"]; sa.GoName != "userRecord" || sa.Package != "model" {
		t.Fatalf("schema annotation = %+v | 应记录 Go 名与包名", sa)
	}
	annots, err := ParseAnnotations(fs, []string{"/api"})
	if err != nil {
		t.Fatalf("ParseAnnotations: %v | 解析处理器注解失败", err)
	}
	routes := []Route{
		{Method: "GET", Path: "/records"},
		{Method: "GET", Path: "/records/qualified"},
		{Method: "GET", Path: "/records/unknown"},
	}
	doc := FromRoutesWithAnnotations(routes, Info{Title: "Demo", Version: "1.0.0"},
		Options{TypeAnnotations: types}, annots, nil)

	if doc.Components.Schemas["PublicRecord"] == nil {
		t.Fatalf("missing @Name component | 缺少 @Name 组件: %v", sortedKeys(doc.Components.Schemas))
	}
	if _, ok := doc.Components.Schemas["userRecord"]; ok {
		t.Fatalf("Go type name must not be registered as a component | Go 类型名不应注册为组件")
	}

	bare := operationResponseSchema(t, doc, "/records", "200")
	if bare.Ref != "#/components/schemas/PublicRecord" {
		t.Fatalf("bare ref = %q | 裸 Go 名引用应改写到 @Name 组件", bare.Ref)
	}
	qualified := operationResponseSchema(t, doc, "/records/qualified", "200")
	if qualified.Items == nil || qualified.Items.Ref != "#/components/schemas/PublicRecord" {
		t.Fatalf("array items = %+v | 带包限定的数组元素引用应改写到 @Name 组件", qualified.Items)
	}
	if doc.Components.Schemas["model.Unknown"] == nil {
		t.Fatalf("unresolved reference must be materialized | 无法解析的引用应补齐占位组件")
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("Validate: %v | 生成文档不应含悬空引用", err)
	}
}

// operationResponseSchema returns the JSON schema of one operation response. | operationResponseSchema
// 返回单个操作响应的 JSON Schema。
func operationResponseSchema(t *testing.T, doc *Document, path, code string) *Schema {
	t.Helper()
	item, ok := doc.Paths[path]
	if !ok || item.Get == nil {
		t.Fatalf("path %q missing | 缺少路径 %q", path, path)
	}
	response, ok := item.Get.Responses[code]
	if !ok {
		t.Fatalf("response %q missing on %q | %q 缺少响应 %q", code, path, path, code)
	}
	media, ok := response.Content["application/json"]
	if !ok || media.Schema == nil {
		t.Fatalf("response %q of %q lost its schema | %q 的响应 %q 丢失 Schema", code, path, path, code)
	}
	return media.Schema
}
