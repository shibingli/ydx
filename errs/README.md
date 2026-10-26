# errs — 声明式哨兵错误与上下文包装

`github.com/shibingli/ydx/errs` 是 ydx 的统一错误入口。它把错误在包级声明一次，所有失败
路径引用同一份声明，并通过 `Detail` / `Wrap` / `WrapDetail` 附加细节；调用方始终可以用
`errors.Is` / `errors.As` 做稳定判定，而不依赖错误文案匹配。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/errs` |
| 包名 | `errs` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |

## 功能

- 用 `errs.New` 声明包级哨兵错误，文案统一为「English | 中文」双语格式。
- 用 `errs.Detail` 为哨兵附加格式化细节，替代 `fmt.Errorf("%w: ...")`。
- 用 `errs.Wrap` 把底层错误与哨兵保留在同一条错误链上。
- 用 `errs.WrapDetail` 同时完成包装与细节附加。
- 对 `nil` 输入保持 `nil` 语义，可直接写在 `return` 语句中。

## 特性

- **稳定判定**：`Detail` 返回的错误实现 `Unwrap() error`，`Wrap` / `WrapDetail` 实现
  `Unwrap() []error`，因此 `errors.Is(err, ErrX)` 与 `errors.As` 在任意包装层都成立。
- **双分支错误链**：`Wrap` 同时暴露底层错误与哨兵，调用方既能匹配业务哨兵，也能匹配
  `context.Canceled`、`fs.ErrNotExist` 等底层原因。
- **零反射**：不引入反射、不解析调用栈，热路径只做错误值组合。
- **统一文案**：错误声明集中在包级，便于审计、翻译和对外错误码映射。
- **控制器边界**：本包刻意不提供泛型 `As[T]` 等额外封装，避免对非 `error` 类型 panic；
  调用方直接使用标准库的 `errors.Is` / `errors.As` / `errors.Join`。

## 快速开始

```go
package user

import (
	"errors"

	"github.com/shibingli/ydx/errs"
)

var (
	ErrNotFound = errs.New("user not found | 用户不存在")
	ErrInvalid  = errs.New("invalid user input | 用户输入非法")
)

func Load(id string) (*User, error) {
	if id == "" {
		return nil, errs.Detail(ErrInvalid, "empty id | 空 id")
	}
	u, err := repo.Find(id)
	if err != nil {
		return nil, errs.Wrap(err, ErrNotFound)
	}
	return u, nil
}

func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}
```

## 应用场景

- **HTTP API 错误映射**：处理器按哨兵错误映射状态码（`ErrNotFound` → 404，
  `ErrInvalid` → 400），不解析错误字符串。
- **分层服务**：仓储层包装底层驱动错误，服务层继续附加业务哨兵，接口层统一判定。
- **国际化**：双语声明让错误文案可直接进入日志、审计或前端提示；需要按语言输出时由
  `i18n` / `render` 层负责翻译，`errs` 只负责稳定身份。
- **可观测性**：`log.Err(err)` 记录完整错误链，同时保留哨兵身份供指标聚合。

## 性能指标

本模块没有独立基准；其成本结构在设计上非常固定：

- `errs.New` 只在包初始化或声明期执行一次，等价于 `errors.New`。
- `Detail` 每次调用创建一个 `detailError` 并格式化细节，适合失败路径，不适合逐请求成功路径。
- `Wrap` / `WrapDetail` 每次调用创建一个 `wrapError`；`WrapDetail` 额外格式化细节。
- `errors.Is` 的遍历深度等于错误链长度；本包不会额外复制错误链。
- 全路径不使用反射、不读取环境变量、不分配全局状态。

> 失败路径的分配与文案格式化成本通常远低于一次 I/O 或数据库调用；不要在成功热路径上
> 为了“预构造错误”而增加分配。

## 第三方依赖与鸣谢

本模块只依赖 Go 标准库，没有第三方运行时依赖，也没有需要鸣谢的外部实现。

## 相关模块

- [`log`](../log/README.md)：`log.Err` 直接接收本包错误并保留错误链。
- [`middleware/recovery`](../middleware/recovery/README.md)：把 panic 转为不泄露内部细节的 500。
- [`i18n`](../i18n/README.md)：需要按语言输出错误文案时，以哨兵身份为键查目录。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
