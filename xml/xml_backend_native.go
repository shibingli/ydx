//go:build !xml_std

package xml

// Backend returns the name of the active XML backend; without the xml_std build tag it is always
// "yd-native". | Backend 返回当前生效的 XML 后端名称；未设置 xml_std 构建标签时恒为 "yd-native"。
func Backend() string { return "yd-native" }
