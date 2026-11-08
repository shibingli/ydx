package saml

import "github.com/shibingli/ydx/errs"

// ErrStoreUnavailable reports that the Redis backend could not complete an operation. The detail
// text is fixed and never contains an address, DSN or credential. | ErrStoreUnavailable 表示 Redis
// 后端无法完成操作。细节文案固定，绝不包含地址、DSN 或凭据。
var ErrStoreUnavailable = errs.New("saml store: backend unavailable | saml 存储：后端不可用")

// ErrConflict reports that an optimistic compare-and-set update kept losing races and was
// abandoned. | ErrConflict 表示乐观比较并交换更新持续竞争失败并已放弃。
var ErrConflict = errs.New("saml store: concurrency conflict | saml 存储：并发冲突")
