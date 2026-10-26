# nodeid — 稳定且部署内唯一的节点身份

`github.com/shibingli/ydx/nodeid` 解析节点身份：首次启动从最佳平台种子推导一个值，写入
持久身份文件，此后只读取该文件。身份跟着磁盘走，而不是跟着主板走，因此能跨重启、系统
升级、硬件替换、虚机/容器迁移保持不变。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/nodeid` |
| 包名 | `nodeid` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |
| 最大 ID 长度 | 64 字节（`MaxIDLength`） |

## 功能

- `Resolve(ctx, Options)`：按优先级解析节点身份。
- `Ephemeral()`：返回不持久化的随机身份，用于测试或无法准备存储的场景。
- `Validate(id)`：校验字符集与长度。
- `DefaultFile()`：返回平台默认身份文件路径。
- `IsDurable(path)`：判断路径是否位于持久存储。
- `DetectEnvironment()`：识别物理机、虚机、容器或 Kubernetes。
- `OptionsFromConfig`：读取 `node.*` 配置段。

优先级（高 → 低）：

1. 显式配置 `node.id` / `YD_NODE_ID`；
2. 持久身份文件 `node.id_file`；
3. 平台种子（machine-id、SMBIOS UUID、Windows MachineGuid、IOPlatformUUID），
   返回前先持久化；
4. 随机 id，尽可能持久化。

## 特性

- **持久优先**：首次解析后以文件为准；改写盐值也不会改变已创建的 id。
- **容器感知**：容器共享宿主机的 SMBIOS，并可能继承镜像中的 `/etc/machine-id`，
  因此默认跳过宿主相关种子；仅在单容器主机上开启 `AllowSharedSeed`。
- **持久性检查**：`IsDurable` 识别临时存储；`RequirePersistent` 在身份文件位于临时
  文件系统时直接失败，避免“看似持久、容器重建即丢失”。
- **唯一性 Claim**：磁盘克隆、虚机快照与镜像层可能复制身份文件，本地无法证明唯一；
  `Options.Claimer` 可用 Redis `SET NX PX` 等部署级租约做唯一性校验。
- **创建竞争安全**：多个进程同时创建身份文件时，以先写入者的值为准。
- **可解释来源**：`Identity.Source` 记录 config/file/machine-id/smbios/platform/random，
  `Warning` 给出双语运维提示。
- **安全字符集**：只允许 ASCII 字母、数字、`.`、`-`、`_`，可直接用于日志、Redis 键与
  请求头；`:`、空白与路径分隔符被拒绝。

## 快速开始

```go
package main

import (
	"context"
	"fmt"

	"github.com/shibingli/ydx/nodeid"
)

func main() {
	identity, err := nodeid.Resolve(context.Background(), nodeid.Options{
		Create:            true,
		RequirePersistent: true,
		File:              "/var/lib/myapp/node-id",
	})
	if err != nil {
		fmt.Println("resolve node identity:", err)
		return
	}
	fmt.Printf("id=%s source=%s env=%s stable=%v\n",
		identity.ID, identity.Source, identity.Environment, identity.Stable)
}
```

配置驱动：

```go
opts := nodeid.OptionsFromConfig(cfg) // 读取 node.id / node.id_file 等配置
identity, err := nodeid.Resolve(ctx, opts)
```

使用 Claimer 保证部署内唯一：

```go
type redisClaimer struct{ rdb redis.UniversalClient }

func (c redisClaimer) Claim(ctx context.Context, id, instance string) error {
	ok, err := c.rdb.SetNX(ctx, "node-claim:"+id, instance, time.Minute).Result()
	if err != nil {
		return err
	}
	if !ok {
		return nodeid.ErrDuplicate
	}
	return nil
}
```

## 应用场景

- **多机缓存失效**：缓存节点用稳定 ID 标识自己，避免重启后被当成新节点。
- **实时中枢**：`realtime` 用 NodeID 丢弃本节点已投递的消息。
- **集群成员身份**：节点身份跨重启稳定，便于注册中心与审计关联。
- **容器/虚机迁移**：身份随持久卷迁移，而不是随主板或实例 ID 变化。
- **实例唯一性校验**：用 Claimer 防止克隆磁盘导致两个副本共用身份。
- **测试与临时任务**：`Ephemeral()` 提供不落盘的随机身份。

## 性能指标

本模块没有独立基准；所有成本都在启动期：

- `Resolve` 最多读取一次配置、一次身份文件或一次平台种子，然后做一次可选 Claim。
- `Validate` 对不超过 64 字节的 ID 做一次线性扫描，无正则、无反射。
- `DetectEnvironment` 读取少量平台文件/环境变量，只在启动期调用。
- `IsDurable` 做一次路径/挂载判断，不在请求路径使用。
- Claimer 的网络往返由调用方实现决定；Redis 租约通常是一次 RTT。

> `Resolve` 每个进程只应调用一次并复用结果；重复调用会让 Claimer 看到多次声明，
> 同一 ID 配不同 Instance 可能被误判为重复。

## 第三方依赖与鸣谢

| 依赖 | 版本 | 许可证 | 用途 |
|---|---|---|---|
| `golang.org/x/sys` | v0.49.0 | BSD-3-Clause | Windows 注册表读取 MachineGuid |

仓库内依赖：`config`、`errs`。配置读取使用 `spf13/afero`（Apache-2.0，经 `config` 间接引入）。

## 相关模块

- [`realtime`](../realtime/README.md)：使用节点身份过滤本节点消息。
- [`cache`](../cache/README.md)：多机失效事件需要节点身份。
- [`config`](../config/README.md)：`node.*` 配置段。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
