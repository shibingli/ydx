// Package challenge renders the built-in captcha challenge families.
// | Package challenge 渲染内置验证码题型。
package challenge

import "github.com/shibingli/ydx/captcha/core"

// NewBuiltins constructs the built-in providers enabled by options. | NewBuiltins 构建选项启用的内置生成器。
func NewBuiltins(o core.Options) []core.Provider {
	enabled := make(map[core.Type]struct{}, len(o.Types))
	for _, typ := range o.Types {
		enabled[typ] = struct{}{}
	}
	providers := make([]core.Provider, 0, len(o.Types))
	if _, ok := enabled[core.TypeText]; ok {
		providers = append(providers, newTextProvider(o.TextLength))
	}
	if _, ok := enabled[core.TypeClickText]; ok {
		providers = append(providers, newClickTextProvider())
	}
	if _, ok := enabled[core.TypeClickIcon]; ok {
		providers = append(providers, newClickIconProvider())
	}
	if _, ok := enabled[core.TypeSlide]; ok {
		providers = append(providers, newSlideProvider())
	}
	if _, ok := enabled[core.TypeScratch]; ok {
		providers = append(providers, newScratchProvider())
	}
	if _, ok := enabled[core.TypeSemantic]; ok {
		providers = append(providers, newSemanticProvider())
	}
	if _, ok := enabled[core.TypeRotate]; ok {
		providers = append(providers, newRotateProvider())
	}
	return providers
}
