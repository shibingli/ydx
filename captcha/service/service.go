// Package service owns the captcha Manager lifecycle and request flows.
// | Package service 负责验证码 Manager 生命周期与业务流程。
package service

// New validates options and builds a Manager. | New 校验选项并构建 Manager。
func New(o Options) (*Manager, error) {
	return newManager(o)
}
