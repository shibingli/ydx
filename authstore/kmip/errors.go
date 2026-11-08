package kmip

import "github.com/shibingli/ydx/errs"

// ErrStoreUnavailable reports that the Redis backend could not complete an operation, or that a
// stored record is corrupt. The attached detail text is fixed and never contains an address, DSN,
// credential or key material. | ErrStoreUnavailable 表示 Redis 后端无法完成操作，或已存记录损坏。
// 附加的细节文案固定，绝不包含地址、DSN、凭据或密钥材料。
var ErrStoreUnavailable = errs.New("kmip store: backend unavailable | kmip 存储：后端不可用")

// ErrConflict reports that an optimistic compare-and-set update kept losing races and was
// abandoned after the configured number of retries. | ErrConflict 表示乐观比较并交换更新在配置的
// 重试次数内持续竞争失败并已放弃。
var ErrConflict = errs.New("kmip store: concurrency conflict | kmip 存储：并发冲突")
