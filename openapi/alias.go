package openapi

import (
	"strings"

	"github.com/shibingli/ydx/log"
)

// typeAlias maps one Go type reference onto the component name registered by @Name. | typeAlias
// 把一个 Go 类型引用映射到以 @Name 注册的组件名。
type typeAlias struct {
	// Name is the annotated component name. | Name 为注解组件名。
	Name string
	// Ambiguous reports that several annotated names claim the same Go reference, so the
	// reference must not be rewritten. | Ambiguous 表示同一个 Go 引用被多个注解名占用，因此
	// 不得改写该引用。
	Ambiguous bool
}

// addTypeAlias records the Go type name and package qualified name of an annotated type so
// that references written with the Go name can be resolved onto the @Name component. | addTypeAlias
// 记录注解类型的 Go 名与带包限定的名字，使以 Go 名书写的引用能解析到 @Name 组件。
func (b *Builder) addTypeAlias(goName, packageName, annotated string) {
	if b == nil || goName == "" || annotated == "" || goName == annotated {
		// A type whose @Name equals its Go name needs no alias: the bare component name
		// already matches, and package qualified references fall back to the bare name. | @Name
		// 与 Go 名相同的类型无需别名：裸组件名已经匹配，带包限定的引用会回退到裸名。
		return
	}
	if b.aliases == nil {
		b.aliases = map[string]typeAlias{}
	}
	b.recordTypeAlias(goName, annotated)
	if packageName = strings.TrimSpace(packageName); packageName != "" {
		b.recordTypeAlias(packageName+"."+goName, annotated)
	}
}

// recordTypeAlias stores one alias key and marks it ambiguous on conflicting targets. |
// recordTypeAlias 保存单个别名键，目标冲突时标记为歧义。
func (b *Builder) recordTypeAlias(key, annotated string) {
	if key == "" || annotated == "" {
		return
	}
	existing, ok := b.aliases[key]
	if !ok {
		b.aliases[key] = typeAlias{Name: annotated}
		return
	}
	if existing.Name != annotated {
		existing.Ambiguous = true
		b.aliases[key] = existing
	}
}

// resolveSchemaAliases rewrites component references that still use Go type names onto the
// @Name components and materializes empty schemas for references that no annotation could
// resolve. | resolveSchemaAliases 把仍使用 Go 类型名的组件引用改写到 @Name 组件，并为任何注解
// 都无法解析的引用补齐空 Schema。
//
// It only runs when aliases exist, so documents built without renamed type annotations keep
// strict reference validation. | 仅在存在别名时运行，因此没有重命名类型注解的文档仍保持严格的
// 引用校验。
func (b *Builder) resolveSchemaAliases() {
	if b.doc == nil || len(b.aliases) == 0 {
		return
	}
	schemas := b.doc.Components.Schemas
	rewrite := func(schema *Schema) {
		if schema == nil {
			return
		}
		schema.Ref = resolveSchemaRef(schema.Ref, schemas, b.aliases)
		if schema.Discriminator != nil {
			for value, ref := range schema.Discriminator.Mapping {
				schema.Discriminator.Mapping[value] = resolveSchemaRef(ref, schemas, b.aliases)
			}
		}
	}
	walkDocumentSchemas(b.doc, rewrite)

	missing := map[string]bool{}
	collect := func(schema *Schema) {
		if schema == nil {
			return
		}
		if name, ok := unresolvedComponentName(schema.Ref, schemas); ok {
			missing[name] = true
		}
		if schema.Discriminator != nil {
			for _, ref := range schema.Discriminator.Mapping {
				if name, ok := unresolvedComponentName(ref, schemas); ok {
					missing[name] = true
				}
			}
		}
	}
	walkDocumentSchemas(b.doc, collect)
	if len(missing) == 0 {
		return
	}
	if b.doc.Components.Schemas == nil {
		b.doc.Components.Schemas = map[string]*Schema{}
		schemas = b.doc.Components.Schemas
	}
	for name := range missing {
		// An empty schema accepts any value: the reference stays readable while the missing
		// type annotation remains visible in the document as a placeholder component. | 空
		// Schema 接受任意取值：引用保持可读，缺失的类型注解会以占位组件的形式留在文档中。
		schemas[name] = &Schema{}
	}
	log.Default().Debug("openapi: materialized unresolved schema references | openapi：已补齐无法解析的 Schema 引用",
		log.Int("count", len(missing)))
}

// resolveSchemaRef resolves one reference through the alias maps. Exact component names win;
// then the Go name alias; finally the bare name of a package qualified reference. | resolveSchemaRef
// 依次通过别名映射解析引用：先看精确组件名，再看 Go 名别名，最后看带包限定引用的裸名。
func resolveSchemaRef(ref string, schemas map[string]*Schema, aliases map[string]typeAlias) string {
	name, ok := componentName(ref)
	if !ok || hasSchema(schemas, name) {
		return ref
	}
	if target, ok := aliasTarget(aliases, name); ok && hasSchema(schemas, target) {
		return refPrefix + target
	}
	if dot := strings.LastIndexByte(name, '.'); dot >= 0 {
		bare := name[dot+1:]
		if hasSchema(schemas, bare) {
			return refPrefix + bare
		}
		if target, ok := aliasTarget(aliases, bare); ok && hasSchema(schemas, target) {
			return refPrefix + target
		}
	}
	return ref
}

// unresolvedComponentName reports the component name of a local reference that the document
// does not define. | unresolvedComponentName 报告文档未定义的本地引用所指向的组件名。
func unresolvedComponentName(ref string, schemas map[string]*Schema) (string, bool) {
	name, ok := componentName(ref)
	if !ok || hasSchema(schemas, name) {
		return "", false
	}
	return name, true
}

// componentName extracts the component name from a local schema reference. | componentName
// 从本地 Schema 引用中提取组件名。
func componentName(ref string) (string, bool) {
	if !strings.HasPrefix(ref, refPrefix) {
		return "", false
	}
	name := strings.TrimPrefix(ref, refPrefix)
	if name == "" {
		return "", false
	}
	return name, true
}

// hasSchema reports whether the component map defines a non-nil schema under name. | hasSchema
// 报告组件映射是否在 name 下定义了非空 Schema。
func hasSchema(schemas map[string]*Schema, name string) bool {
	schema, ok := schemas[name]
	return ok && schema != nil
}

// aliasTarget returns the unambiguous alias target of key. | aliasTarget 返回 key 的无歧义别名目标。
func aliasTarget(aliases map[string]typeAlias, key string) (string, bool) {
	alias, ok := aliases[key]
	if !ok || alias.Ambiguous || alias.Name == "" {
		return "", false
	}
	return alias.Name, true
}

// walkDocumentSchemas visits every schema reachable from doc. | walkDocumentSchemas 访问 doc 中
// 可达的每个 Schema。
func walkDocumentSchemas(doc *Document, visit func(*Schema)) {
	if doc == nil || visit == nil {
		return
	}
	for _, schema := range doc.Components.Schemas {
		walkSchema(schema, visit)
	}
	for _, parameter := range doc.Components.Parameters {
		if parameter != nil {
			walkParameterSchemas(*parameter, visit)
		}
	}
	for _, response := range doc.Components.Responses {
		if response == nil {
			continue
		}
		walkContentSchemas(response.Content, visit)
		for _, header := range response.Headers {
			walkHeaderSchemas(header, visit)
		}
	}
	for _, body := range doc.Components.RequestBodies {
		if body != nil {
			walkContentSchemas(body.Content, visit)
		}
	}
	for _, header := range doc.Components.Headers {
		walkHeaderSchemas(header, visit)
	}
	for _, callback := range doc.Components.Callbacks {
		for _, item := range callback {
			walkPathItemSchemas(item, visit)
		}
	}
	for _, item := range doc.Components.PathItems {
		walkPathItemSchemas(item, visit)
	}
	for _, item := range doc.Webhooks {
		walkPathItemSchemas(item, visit)
	}
	for _, item := range doc.Paths {
		walkPathItemSchemas(item, visit)
	}
}
