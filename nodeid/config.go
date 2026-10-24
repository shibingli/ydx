package nodeid

import (
	"strings"

	"github.com/shibingli/ydx/config"
)

// OptionsFromConfig reads the node section of the layered configuration. |
// OptionsFromConfig 读取分层配置的 node 段。
//
// Keys: | 配置键：
//
//	node.id                    explicit identity (wins over every seed) | 显式身份（优先于所有种子）
//	node.id_file               identity file path | 身份文件路径
//	node.require_persistent    reject ephemeral identity or storage | 拒绝临时身份或临时存储
//	node.allow_shared_seed     allow host seeds inside containers | 允许容器使用宿主种子
//	node.salt                  salt mixed into derived identities | 混入推导身份的盐
//
// Create is not a configuration key: the application wiring decides whether a
// missing file may be created, while a library default stays read-only. A nil
// Config yields zero Options. | Create 不是配置键：创建缺失文件由应用接线决定，库的默认行为
// 保持只读。Config 为 nil 时返回零值 Options。
func OptionsFromConfig(c *config.Config) Options {
	if c == nil {
		return Options{}
	}
	return Options{
		ConfigID:          strings.TrimSpace(c.GetString("node.id")),
		File:              strings.TrimSpace(c.GetString("node.id_file")),
		RequirePersistent: c.GetBool("node.require_persistent"),
		AllowSharedSeed:   c.GetBool("node.allow_shared_seed"),
		Salt:              c.GetString("node.salt"),
	}
}
