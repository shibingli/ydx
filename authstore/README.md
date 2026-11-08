# authstore — auth 多实例共享存储（Redis）

`github.com/shibingli/ydx/authstore` 为 `github.com/shibingli/ydx/auth` 工具集提供多实例共享持久化。
模块本身只承载文档；每个子包在 Redis 上完整实现对应 auth 包的 Store/Registry/Replay/Challenge/State
接口，无桩、无本地降级。

| 子包 | 实现的端口 |
|---|---|
| `authstore/redis` | `auth.UserStore`、`SessionStore`、`IdentityStore`、`CredentialStore`、`AuditStore`、`TokenStore` |
| `authstore/oauth2` | `oauth2.Store`、`ClientStore`（含分页扩展）、`DPoPNonceStore`、`DPoPReplayStore`、`ScopeRegistry` |
| `authstore/oidc` | `oidc.LogoutReplayStore` |
| `authstore/saml` | `saml.Store`、`ArtifactStore`、`AssertionReplayStore` |
| `authstore/cas` | `cas.TicketStore`、`cas.ServiceSessionRegistry` |
| `authstore/scim` | `scim.Store`、`scim.UserVersionReplacer`、`scim.GroupVersionReplacer` |
| `authstore/rbac` | `rbac.Store` |
| `authstore/kms` | `kms.Store` |
| `authstore/kmip` | `kmip.Store` |
| `authstore/federation` | `federation.StateStore` |
| `authstore/wsfed` | `wsfed.RequestStore` |
| `authstore/otp` | `otp.ReplayGuard` |
| `authstore/webauthn` | `webauthn.ChallengeStore`、`CredentialStore`、`BackupStateUpdater` |

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/authstore` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |
| 默认键前缀 | `ydx:authstore:<子包>:` |
| 依赖方向 | authstore → auth，auth 不反向依赖 authstore |
| 测试 | miniredis，两客户端多实例，默认运行 |

## 快速开始

### 使用已有 go-redis 客户端

```go
import (
    "context"

    goredis "github.com/redis/go-redis/v9"

    "github.com/shibingli/ydx/auth"
    authredis "github.com/shibingli/ydx/authstore/redis"
)

func openAuth(client goredis.UniversalClient) (*auth.Service, error) {
    stores, err := authredis.New(client, authredis.Options{
        KeyPrefix: "myapp:auth:", // 空值使用 ydx:authstore:
    })
    if err != nil {
        return nil, err
    }
    // 客户端由调用方拥有，进程退出时由调用方关闭。
    return auth.New(auth.Config{Stores: stores.Auth()})
}
```

### 使用 ydx/redis 打开连接

`NewFromOptions` 不重新实现连接逻辑，而是调用 `ydx/redis.Open` 与 `ydx/redis.Health`：

```go
stores, err := authredis.NewFromOptions(ctx, ydxredis.Options{
    Mode:      ydxredis.ModeSingle,
    Addr:      "127.0.0.1:6379",
    Password:  cfg.RedisPassword,
    KeyPrefix: "myapp:auth:",
}, authredis.Options{})
if err != nil {
    return err
}
defer stores.Close() // 只关闭 NewFromOptions 打开的客户端
```

也可以自行 `ydxredis.Open` 后把客户端交给 `authredis.New`，此时仍需自行关闭客户端。

## 多实例语义

- **唯一性原子化**：用户名、邮箱、手机号、`(provider, subject)` 与凭据 ID 的检查与写入在同一个
  Lua 脚本内完成。两个实例并发创建相同标识时，恰有一个成功，另一个得到
  `auth.ErrUserExists` / `auth.ErrIdentityExists` / `auth.ErrCredentialExists`。
- **令牌单次消费**：`ConsumeToken` 由 Lua 脚本原子检查「不存在 / 已用 / 已过期」并标记已用。
  N 个 goroutine 或 N 个实例并发消费同一令牌时恰有一个成功，其余得到 `auth.ErrTokenUsed`。
- **会话与成员索引**：会话创建、更新、删除与用户索引迁移在同一脚本内完成；更新使用
  compare-and-set 守卫，交错写入会重试而不是留下错误索引。
- **审计只追加**：`RecordAudit` 用 Redis 自增序号标识记录，同一事件 ID 追加两次仍保留两条；
  列表按事件时间与 ID 排序，支持过滤、分页、总数与倒序。
- **深拷贝**：所有值在写入边界 JSON 序列化、读取边界反序列化，返回对象与调用方、与其它实例
  都不共享 map / slice / 指针。
- **UTC**：写入与读出时所有非零时间统一转换为 UTC，零值保持规范零值。
- **错误不泄露**：Redis 后端故障统一返回 `auth.ErrStoreUnavailable` 与固定文案，不携带地址、
  DSN 或凭据；上下文取消与超时原样返回。

## Redis 键布局

前缀之后的第一段是哈希标签，保证单个脚本访问的所有键位于同一 Cluster 槽位。前缀不得包含
`{` 或 `}`。默认前缀 `ydx:authstore:` 下：

```text
ydx:authstore:{authstore:users}:all                    用户 ID 集合
ydx:authstore:{authstore:users}:user:<id>              hash：data/username/email/phone
ydx:authstore:{authstore:users}:idx:username:<name>    用户名唯一索引
ydx:authstore:{authstore:users}:idx:email:<mail>       邮箱唯一索引
ydx:authstore:{authstore:users}:idx:phone:<number>     手机号唯一索引

ydx:authstore:{authstore:sessions}:all                 会话 ID 集合
ydx:authstore:{authstore:sessions}:session:<id>        hash：data/user/期限字段
ydx:authstore:{authstore:sessions}:user:<userID>       用户会话 ID 集合

ydx:authstore:{authstore:identities}:identity:<len>:<provider><subject>  hash：data/user
ydx:authstore:{authstore:identities}:user:<userID>     身份键集合

ydx:authstore:{authstore:credentials}:credential:<id>  hash：data/user
ydx:authstore:{authstore:credentials}:user:<userID>    凭据 ID 集合

ydx:authstore:{authstore:audits}:seq                   追加序号
ydx:authstore:{authstore:audits}:events                hash：序号 -> 事件 JSON
ydx:authstore:{authstore:audits}:index                 有序集合：序号按时间评分

ydx:authstore:{authstore:tokens}:token:<len>:<purpose><hash>            hash：data/user/used/期限字段
ydx:authstore:{authstore:tokens}:user:<len>:<purpose><userID>           令牌键集合
```

`<len>:` 前缀使任意 provider、subject、purpose 与 hash 字节都无歧义。

## API

- `New(client goredis.UniversalClient, options Options) (*Stores, error)`：不进行网络往返；
  客户端归调用方所有。
- `NewFromOptions(ctx, conn ydxredis.Options, options Options) (*Stores, error)`：用
  `ydx/redis` 打开并探活，返回归本模块所有的存储，必须调用 `Close`。
- `Stores.Auth() auth.Stores`：取出可直接传给 `auth.New` 的端口集合。
- `Stores.Close() error`：仅关闭 `NewFromOptions` 打开的客户端；幂等。
- `Options.KeyPrefix`：键命名空间；空值使用 `DefaultKeyPrefix`。

## 边界

- 审计列表会扫描审计索引并在内存中过滤，事件量极大时应按外部归档策略控制保留量。
- 分页与过滤语义与 auth 内存实现一致：`Limit <= 0` 表示不截断，`Offset` 从零开始。
- Redis 本身的一致性边界：脚本保证单次操作原子，但不提供跨多次调用的快照隔离；
  `ListUsers`、`ListAudit` 等列表操作在并发写入期间可能看到操作开始与结束之间的混合状态。
