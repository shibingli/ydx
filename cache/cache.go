package cache

import (
	"math/rand/v2"
	"time"

	"github.com/shibingli/ydx/cache/local"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
	"github.com/shibingli/ydx/nodeid"
)

// Declared sentinel errors, testable with errors.Is. | 已声明的哨兵错误，可用 errors.Is 判定。
var (
	// ErrInvalidOptions indicates an unusable Manager or cache option. | ErrInvalidOptions 表示 Manager 或缓存选项不可用。
	ErrInvalidOptions = errs.New("cachex: invalid options | cachex：非法选项")
	// ErrClosed indicates the manager or the namespace was closed. | ErrClosed 表示管理器或命名空间已关闭。
	ErrClosed = errs.New("cachex: cache closed | cachex：缓存已关闭")
	// ErrInvalidNamespace indicates a namespace that is empty, too long or contains ':' or control bytes. | ErrInvalidNamespace 表示命名空间为空、过长或含 ':' 或控制字节。
	ErrInvalidNamespace = errs.New("cachex: invalid namespace | cachex：非法命名空间")
	// ErrNamespaceInUse indicates the same namespace was opened twice on one Manager. | ErrNamespaceInUse 表示同一管理器上重复打开了命名空间。
	ErrNamespaceInUse = errs.New("cachex: namespace already in use | cachex：命名空间已被占用")
	// ErrEmptyKey indicates an empty cache key. | ErrEmptyKey 表示缓存键为空。
	ErrEmptyKey = errs.New("cachex: empty key | cachex：空键")
	// ErrInvalidKey indicates a key contains a NUL byte. | ErrInvalidKey 表示键包含 NUL 字节。
	ErrInvalidKey = errs.New("cachex: invalid key | cachex：非法键")
	// ErrKeyTooLong indicates a key that cannot fit the L1 ring. | ErrKeyTooLong 表示键无法放进 L1 环形缓冲区。
	ErrKeyTooLong = errs.New("cachex: key too long | cachex：键过长")
	// ErrNilLoader indicates a nil loader was passed to GetOrLoad. | ErrNilLoader 表示传给 GetOrLoad 的 loader 为 nil。
	ErrNilLoader = errs.New("cachex: nil loader | cachex：loader 为 nil")
	// ErrNilView indicates a nil callback was passed to View. | ErrNilView 表示传给 View 的回调为 nil。
	ErrNilView = errs.New("cachex: nil view callback | cachex：视图回调为 nil")
	// ErrNotFound is the loader contract for "the value does not exist". | ErrNotFound 是 loader 表示「值不存在」的契约。
	ErrNotFound = errs.New("cachex: value not found | cachex：值不存在")
	// ErrEncode indicates a value could not be serialized. | ErrEncode 表示值无法序列化。
	ErrEncode = errs.New("cachex: encode failed | cachex：序列化失败")
	// ErrDecode indicates a payload could not be deserialized. | ErrDecode 表示载荷无法反序列化。
	ErrDecode = errs.New("cachex: decode failed | cachex：反序列化失败")
	// ErrRemote indicates the remote (L2) store failed. | ErrRemote 表示远端（L2）存储失败。
	ErrRemote = errs.New("cachex: remote store failed | cachex：远端存储失败")
	// ErrNilRemote indicates a nil remote was passed to a constructor. | ErrNilRemote 表示构造器收到 nil 远端。
	ErrNilRemote = errs.New("cachex: nil remote store | cachex：远端存储为 nil")
	// ErrNilClient indicates a nil redis client was passed to NewRedisRemote. | ErrNilClient 表示 NewRedisRemote 收到 nil 客户端。
	ErrNilClient = errs.New("cachex: nil redis client | cachex：Redis 客户端为 nil")
)

// Internal sentinels used to classify an L1 view without allocating. | 内部哨兵，用于在不分配的情况下对 L1 视图分类。
var (
	errNegativeEntry  = errs.New("cachex: negative entry | cachex：负缓存条目")
	errTombstoneEntry = errs.New("cachex: tombstone entry | cachex：墓碑条目")
	errCorruptEntry   = errs.New("cachex: corrupt envelope | cachex：损坏的信封")
)

// Defaults applied by NewManager when an option leaves a field empty. | NewManager 在选项留空时施加的默认值。
const (
	// DefaultPrefix is the Redis key prefix used when RedisOptions.Prefix is empty. | DefaultPrefix 是 RedisOptions.Prefix 为空时使用的 Redis 键前缀。
	DefaultPrefix = "yd:cache:"
	// DefaultLease is the L1 revalidation lease used when Options.Lease is zero. | DefaultLease 是 Options.Lease 为零时使用的 L1 重新确认租约。
	DefaultLease = 30 * time.Second
	// DefaultLoadTimeout is the shared loader ceiling used when Options.LoadTimeout is zero. | DefaultLoadTimeout 是 Options.LoadTimeout 为零时使用的共享加载上限。
	DefaultLoadTimeout = 30 * time.Second
	// DefaultEventBuffer is the subscriber queue length used when Options.EventBuffer is zero. | DefaultEventBuffer 是 Options.EventBuffer 为零时使用的订阅队列长度。
	DefaultEventBuffer = 256
	// DefaultTombstoneTTL is the delete-marker lifetime used when Options.TombstoneTTL is zero. | DefaultTombstoneTTL 是 Options.TombstoneTTL 为零时使用的删除标记存活时间。
	DefaultTombstoneTTL = time.Hour
	// defaultHealthInterval probes the Redis subscription. | defaultHealthInterval 探测 Redis 订阅。
	defaultHealthInterval = 30 * time.Second
)

// Options is the plain settings struct behind Manager. | Options 是 Manager 背后的纯设置结构。
type Options struct {
	// Remote is the optional L2 store; nil means local-only. | Remote 是可选的 L2 存储；nil 表示仅本地缓存。
	Remote Remote
	// Logger receives operational warnings; nil means log.Default(). | Logger 接收运行告警；nil 表示 log.Default()。
	Logger *log.Logger
	// NodeID identifies this process in events; empty means a random identifier. | NodeID 在事件中标识本进程；空值表示随机生成。
	NodeID string
	// Local configures the L1 ring cache. | Local 配置 L1 环形缓存。
	Local local.Options
	// Lease bounds how long an L1 entry may live before it is revalidated from L2. | Lease 限制 L1 条目在被 L2 重新确认前的最长存活时间。
	Lease time.Duration
	// LoadTimeout bounds one shared GetOrLoad body. | LoadTimeout 限制单次共享 GetOrLoad 的时长。
	LoadTimeout time.Duration
	// EventBuffer is the subscriber queue length; when it fills, events are dropped. | EventBuffer 是订阅者队列长度；填满时事件被丢弃。
	EventBuffer int
	// TombstoneTTL is how long an L2 delete marker blocks stale CAS write-backs. | TombstoneTTL 是 L2 删除标记阻止陈旧 CAS 回填的时长。
	TombstoneTTL time.Duration
	// FailOpen keeps reads working when L2 is unavailable; write failures are still reported. | FailOpen 使 L2 不可用时读仍可用；写失败仍会上报。
	FailOpen bool
}

// Option mutates Options during NewManager. | Option 在 NewManager 期间修改 Options。
type Option func(*Options)

// WithOptions replaces every field with o, including Remote; apply WithRemote after it.
// | WithOptions 用 o 替换全部字段（含 Remote）；请在它之后调用 WithRemote。
func WithOptions(o Options) Option {
	return func(dst *Options) { *dst = o }
}

// WithRemote attaches the L2 store; passing nil keeps the manager local-only. | WithRemote 挂载 L2 存储；传 nil 则管理器仅使用本地缓存。
func WithRemote(r Remote) Option {
	return func(o *Options) { o.Remote = r }
}

// WithLease overrides the L1 revalidation lease. | WithLease 覆盖 L1 重新确认租约。
func WithLease(d time.Duration) Option {
	return func(o *Options) { o.Lease = d }
}

// WithLoadTimeout overrides the shared load timeout. | WithLoadTimeout 覆盖共享加载超时。
func WithLoadTimeout(d time.Duration) Option {
	return func(o *Options) { o.LoadTimeout = d }
}

// WithEventBuffer overrides the subscriber queue length. | WithEventBuffer 覆盖订阅者队列长度。
func WithEventBuffer(n int) Option {
	return func(o *Options) { o.EventBuffer = n }
}

// WithFailOpen selects the L2 read failure policy. | WithFailOpen 选择 L2 读失败策略。
func WithFailOpen(open bool) Option {
	return func(o *Options) { o.FailOpen = open }
}

// WithNodeID overrides the process identifier used in events. | WithNodeID 覆盖事件中使用的进程标识。
func WithNodeID(id string) Option {
	return func(o *Options) { o.NodeID = id }
}

// WithLogger overrides the operational logger. | WithLogger 覆盖运行日志器。
func WithLogger(l *log.Logger) Option {
	return func(o *Options) { o.Logger = l }
}

// WithLocalOptions overrides the L1 ring settings. | WithLocalOptions 覆盖 L1 环形缓存设置。
func WithLocalOptions(l local.Options) Option {
	return func(o *Options) { o.Local = l }
}

// WithTombstoneTTL overrides how long a delete marker guards against stale write-backs. | WithTombstoneTTL 覆盖删除标记防止陈旧回填的时长。
func WithTombstoneTTL(d time.Duration) Option {
	return func(o *Options) { o.TombstoneTTL = d }
}

// Stats is a point-in-time view of one Raw namespace plus its local cache. | Stats 是一个 Raw 命名空间及其本地缓存的时间点视图。
type Stats struct {
	// Hits counts lookups answered from L1 or L2. | Hits 统计由 L1 或 L2 答复的查询。
	Hits uint64
	// Misses counts lookups that found nothing. | Misses 统计未找到任何值的查询。
	Misses uint64
	// Negatives counts negative entries that answered a lookup. | Negatives 统计以负缓存答复的查询。
	Negatives uint64
	// RemoteHits counts values that came from L2. | RemoteHits 统计来自 L2 的值。
	RemoteHits uint64
	// RemoteMisses counts L2 misses. | RemoteMisses 统计 L2 未命中。
	RemoteMisses uint64
	// RemoteErrors counts L2 failures. | RemoteErrors 统计 L2 失败。
	RemoteErrors uint64
	// Loads counts loader invocations. | Loads 统计 loader 调用次数。
	Loads uint64
	// LoadErrors counts loader failures. | LoadErrors 统计 loader 失败次数。
	LoadErrors uint64
	// Sets counts successful writes. | Sets 统计成功写入次数。
	Sets uint64
	// Deletes counts successful deletes. | Deletes 统计成功删除次数。
	Deletes uint64
	// CASLost counts write-backs rejected by a concurrent invalidation. | CASLost 统计被并发失效拒绝的回填。
	CASLost uint64
	// Invalidations counts L1 keys invalidated by remote events across the manager. | Invalidations 统计整个管理器内被远端事件失效的 L1 键数。
	Invalidations uint64
	// EventsDropped counts subscriber events dropped because the queue was full, across the manager. | EventsDropped 统计整个管理器内因队列满而丢弃的订阅事件。
	EventsDropped uint64
	// Local is the shared L1 snapshot. | Local 是共享 L1 快照。
	Local local.Stats
}

// withDefaults fills every zero field. | withDefaults 填充所有零值字段。
func (o Options) withDefaults() Options {
	if o.Lease < 0 {
		o.Lease = 0
	}
	if o.LoadTimeout <= 0 {
		o.LoadTimeout = DefaultLoadTimeout
	}
	if o.EventBuffer <= 0 {
		o.EventBuffer = DefaultEventBuffer
	}
	if o.TombstoneTTL <= 0 {
		o.TombstoneTTL = DefaultTombstoneTTL
	}
	if o.Logger == nil {
		o.Logger = log.Default()
	}
	if o.NodeID == "" {
		o.NodeID = newNodeID()
	}
	return o
}

// newNodeID returns a fresh per-process event source. It is an instance id,
// not the stable node identity: two processes (even on one host) must not ignore
// each other's invalidation events. | newNodeID 返回新的每进程事件来源。它是实例 id，
// 不是稳定节点身份：两个进程（即使同一主机）不得互相忽略对方的失效事件。
func newNodeID() string { return nodeid.InstanceID() }

// jittered adds a random duration in [0, jitter) to ttl. | jittered 给 ttl 叠加 [0, jitter) 内的随机时长。
func jittered(ttl, jitter time.Duration) time.Duration {
	if ttl <= 0 || jitter <= 0 {
		return ttl
	}
	return ttl + rand.N(jitter)
}

// minDuration returns the smaller positive duration, treating <=0 as "unbounded". | minDuration 返回较小的正时长，把 <=0 视为「无界」。
func minDuration(a, b time.Duration) time.Duration {
	switch {
	case a <= 0:
		return b
	case b <= 0:
		return a
	case a < b:
		return a
	default:
		return b
	}
}
