package nodeid

import (
	"context"
	"errors"
	"io/fs"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// MaxIDLength bounds an explicit or generated identity in bytes. | MaxIDLength 限制显式或生成身份
// 的字节长度。
const MaxIDLength = 64

// Declared sentinel errors, testable with errors.Is. | 已声明的哨兵错误，可用 errors.Is 判定。
var (
	// ErrInvalidID indicates an identity outside the allowed alphabet or length. |
	// ErrInvalidID 表示身份超出允许的字符集或长度。
	ErrInvalidID = errs.New("nodeid: invalid node id | nodeid：非法的节点 ID")
	// ErrNoIdentity indicates that no configured, persisted or derivable identity exists. |
	// ErrNoIdentity 表示既没有配置、也没有持久化或可推导的身份。
	ErrNoIdentity = errs.New("nodeid: no node identity available | nodeid：没有可用的节点身份")
	// ErrIdentityFile indicates a read, write or permission failure on the identity file. |
	// ErrIdentityFile 表示身份文件的读取、写入或权限失败。
	ErrIdentityFile = errs.New("nodeid: identity file failed | nodeid：身份文件操作失败")
	// ErrCorrupt indicates an identity file that does not contain exactly one valid id. |
	// ErrCorrupt 表示身份文件没有恰好包含一个合法 id。
	ErrCorrupt = errs.New("nodeid: identity file is corrupt | nodeid：身份文件已损坏")
	// ErrNeedsProvisioning indicates that a durable identity was required but no durable
	// location was available. | ErrNeedsProvisioning 表示要求持久身份，但没有可用的持久位置。
	ErrNeedsProvisioning = errs.New("nodeid: durable node identity required | nodeid：需要持久化的节点身份")
	// ErrDuplicate indicates that a claimer rejected the identity because another live
	// instance already holds it. | ErrDuplicate 表示 Claimer 拒绝了该身份，因为另一个活动实例
	// 已占用它。
	ErrDuplicate = errs.New("nodeid: identity is already active | nodeid：身份已被另一个活动实例占用")
)

// Source records where the resolved identity came from. | Source 记录解析出的身份来源。
type Source string

const (
	// SourceConfig is an explicitly configured identity. | SourceConfig 是显式配置的身份。
	SourceConfig Source = "config"
	// SourceFile is an identity read from or written to the persistent file. |
	// SourceFile 是从持久文件读取或写入持久文件的身份。
	SourceFile Source = "file"
	// SourceMachineID is a seed derived from the operating-system machine id. |
	// SourceMachineID 是来自操作系统 machine-id 的种子。
	SourceMachineID Source = "machine-id"
	// SourceSMBIOS is a seed derived from SMBIOS/DMI hardware identifiers. |
	// SourceSMBIOS 是来自 SMBIOS/DMI 硬件标识的种子。
	SourceSMBIOS Source = "smbios"
	// SourcePlatform is a seed from another platform-specific identifier (Windows
	// MachineGuid, macOS IOPlatformUUID). | SourcePlatform 是其它平台专属标识（Windows
	// MachineGuid、macOS IOPlatformUUID）的种子。
	SourcePlatform Source = "platform"
	// SourceRandom is a random identity with no stable seed. | SourceRandom 是没有稳定种子的
	// 随机身份。
	SourceRandom Source = "random"
)

// Environment describes where the process runs. | Environment 描述进程的运行环境。
type Environment string

const (
	// EnvironmentPhysical is a bare-metal host. | EnvironmentPhysical 是物理主机。
	EnvironmentPhysical Environment = "physical"
	// EnvironmentVirtual is a virtual machine. | EnvironmentVirtual 是虚拟机。
	EnvironmentVirtual Environment = "virtual"
	// EnvironmentContainer is a container that is not managed by Kubernetes. |
	// EnvironmentContainer 是非 Kubernetes 管理的容器。
	EnvironmentContainer Environment = "container"
	// EnvironmentKubernetes is a Kubernetes pod. | EnvironmentKubernetes 是 Kubernetes Pod。
	EnvironmentKubernetes Environment = "kubernetes"
)

// Identity is the resolved node identity and its provenance. | Identity 是解析出的节点身份及其来源。
type Identity struct {
	// ID is the validated identity, at most MaxIDLength bytes. | ID 是校验后的身份，最多
	// MaxIDLength 字节。
	ID string
	// Instance is a per-process identifier used by claimers. | Instance 是 Claimer 使用的
	// 每进程标识。
	Instance string
	// Source records how ID was obtained. | Source 记录 ID 的获取方式。
	Source Source
	// Environment records physical, virtual, container or Kubernetes. | Environment 记录
	// 物理、虚机、容器或 Kubernetes。
	Environment Environment
	// Persistent reports whether the identity file is on storage that survives
	// container or instance recreation. Explicit identities are always persistent. |
	// Persistent 报告身份文件是否位于能跨容器/实例重建存活的存储上。显式身份始终为持久。
	Persistent bool
	// Stable reports whether the same ID is expected on the next start with the same
	// storage and seed. | Stable 报告在相同存储与种子下，下次启动是否应得到同一 ID。
	Stable bool
	// Warning is a bilingual operator-facing sentence, empty when nothing is unusual. |
	// Warning 是面向运维的双语提示，没有异常时为空。
	Warning string
}

// Claimer verifies deployment-wide uniqueness of a resolved identity. | Claimer 校验解析出的身份
// 在部署内唯一。
//
// Claim is called once after resolution. A non-nil error rejects the identity;
// return ErrDuplicate when another live instance already holds it. The
// implementation owns the lease: it should use a TTL and renew it for the
// process lifetime, then release it on shutdown. | Claim 在解析后调用一次。非 nil 错误拒绝
// 该身份；另一个活动实例已占用时返回 ErrDuplicate。租约由实现负责：应使用 TTL 并在进程生命周期内
// 续期，退出时释放。
type Claimer interface {
	// Claim reserves id for instance. | Claim 为 instance 预留 id。
	Claim(ctx context.Context, id, instance string) error
}

// Options configures Resolve. | Options 配置 Resolve。
type Options struct {
	// ConfigID is an explicitly configured identity and wins over every other
	// source. It is validated but not rewritten. | ConfigID 是显式配置的身份，优先于其它所有
	// 来源；只校验，不改写。
	ConfigID string
	// File is the identity file; empty uses DefaultFile. | File 是身份文件；为空时使用
	// DefaultFile。
	File string
	// Create permits writing a new identity file when none exists. | Create 允许在文件不存在时
	// 写入新的身份文件。
	Create bool
	// RequirePersistent rejects an ephemeral identity or storage. | RequirePersistent 拒绝
	// 临时身份或临时存储。
	RequirePersistent bool
	// AllowSharedSeed permits host-derived seeds inside containers. Use it only when
	// one container owns the host; otherwise replicas collide. | AllowSharedSeed 允许容器
	// 使用宿主相关的种子。仅当一台主机只运行一个容器时使用；否则副本会冲突。
	AllowSharedSeed bool
	// Salt is mixed into derived identities. Changing it changes derived ids; the
	// persisted file is authoritative once created. | Salt 混入推导过程。修改它会改变推导出的
	// id；文件一旦创建即以文件为准。
	Salt string
	// Claimer, when non-nil, validates uniqueness after resolution. | Claimer 非 nil 时在解析后
	// 校验唯一性。
	Claimer Claimer
	// Instance overrides the per-process claim identifier; empty generates one. |
	// Instance 覆盖每进程的 Claim 标识；为空时自动生成。
	Instance string
}

// Resolve returns the identity for this process, creating and persisting one when
// Options.Create is set. It never returns an empty ID with a nil error. |
// Resolve 返回本进程的身份；Options.Create 为真时会创建并持久化。它绝不会在返回 nil 错误时
// 给出空 ID。
func Resolve(ctx context.Context, o Options) (Identity, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	env := DetectEnvironment()
	instance := strings.TrimSpace(o.Instance)
	if instance == "" {
		instance = InstanceID()
	}

	if id := strings.TrimSpace(o.ConfigID); id != "" {
		if err := Validate(id); err != nil {
			return Identity{}, err
		}
		out := Identity{
			ID: id, Instance: instance, Source: SourceConfig, Environment: env,
			Persistent: true, Stable: true,
		}
		if err := claim(ctx, o.Claimer, out); err != nil {
			return Identity{}, err
		}
		return out, nil
	}

	file := strings.TrimSpace(o.File)
	if file == "" {
		var err error
		file, err = DefaultFile()
		if err != nil {
			return Identity{}, err
		}
	}

	id, readErr := readIdentity(file)
	switch {
	case readErr == nil:
		durable := IsDurable(file)
		out := Identity{
			ID: id, Instance: instance, Source: SourceFile, Environment: env,
			Persistent: durable, Stable: true,
		}
		if !durable {
			out.Warning = "identity file is on ephemeral storage; a recreated container or instance gets a new id | 身份文件位于临时存储；容器或实例重建后会得到新 id"
			if o.RequirePersistent {
				return Identity{}, errs.Detail(ErrNeedsProvisioning, "file %[1]q is not durable | 文件 %[1]q 不是持久存储", file)
			}
		}
		if err := claim(ctx, o.Claimer, out); err != nil {
			return Identity{}, err
		}
		return out, nil
	case !errors.Is(readErr, fs.ErrNotExist):
		return Identity{}, errs.WrapDetail(readErr, ErrIdentityFile, "read %[1]q | 读取 %[1]q", file)
	}

	if !o.Create {
		return Identity{}, errs.Detail(ErrNoIdentity, "file %[1]q does not exist and Create is false | 文件 %[1]q 不存在且未允许创建", file)
	}
	// Refuse before writing: a durable identity must not leave a stray file on a
	// temporary filesystem that will disappear with the container. | 在写入前拒绝：持久身份
	// 不能把一个会随容器消失的临时文件留在临时文件系统上。
	if o.RequirePersistent && !IsDurable(file) {
		return Identity{}, errs.Detail(ErrNeedsProvisioning, "file %[1]q is not durable | 文件 %[1]q 不是持久存储", file)
	}

	source, seed, seeded := platformSeedFunc(env, o.AllowSharedSeed)
	generated := newRandomID()
	if seeded {
		generated = derive(source, seed, o.Salt)
	}
	written, writeErr := writeIdentity(file, generated)
	if writeErr != nil {
		if o.RequirePersistent {
			return Identity{}, errs.WrapDetail(writeErr, ErrNeedsProvisioning, "cannot persist %[1]q | 无法持久化 %[1]q", file)
		}
		out := Identity{
			ID: generated, Instance: instance, Source: source, Environment: env,
			Persistent: false, Stable: seeded,
			Warning: "identity could not be persisted; a random id changes on restart | 身份无法持久化；随机 id 在重启后会变化",
		}
		if seeded {
			out.Warning = "identity could not be persisted; it is re-derived from the platform seed on each start | 身份无法持久化；每次启动都会从平台种子重新推导"
		}
		if err := claim(ctx, o.Claimer, out); err != nil {
			return Identity{}, err
		}
		return out, nil
	}
	if written != generated {
		// Another process won the creation race; its value is authoritative. |
		// 另一个进程赢得了创建竞争，以它的值为准。
		generated = written
	}
	durable := IsDurable(file)
	out := Identity{
		ID: generated, Instance: instance, Source: source, Environment: env,
		Persistent: durable, Stable: true,
	}
	if !durable {
		out.Warning = "identity file is on ephemeral storage; a recreated container or instance gets a new id | 身份文件位于临时存储；容器或实例重建后会得到新 id"
		if o.RequirePersistent {
			return Identity{}, errs.Detail(ErrNeedsProvisioning, "file %[1]q is not durable | 文件 %[1]q 不是持久存储", file)
		}
	}
	if err := claim(ctx, o.Claimer, out); err != nil {
		return Identity{}, err
	}
	return out, nil
}

// Ephemeral returns a random identity that is not persisted. It is the safe
// fallback for a library or test that cannot provision storage, and it is never
// equal to another call. | Ephemeral 返回不持久化的随机身份。它是无法准备存储的库或测试的安全
// 回退，且每次调用都不同。
func Ephemeral() Identity {
	return Identity{
		ID: newRandomID(), Instance: InstanceID(), Source: SourceRandom,
		Environment: DetectEnvironment(), Persistent: false, Stable: false,
		Warning: "ephemeral identity; ids change on restart | 临时身份；重启后 id 会变化",
	}
}

// Validate checks that id is usable as a node identity. Allowed bytes are ASCII
// letters, digits, '.', '-' and '_' (1..MaxIDLength). The colon is reserved by
// message ids; whitespace and path separators are rejected so the value is safe
// in logs, Redis keys and headers. | Validate 检查 id 是否可作为节点身份。允许 ASCII 字母、
// 数字、'.'、'-' 与 '_'（1..MaxIDLength）。冒号被消息 id 保留；空白与路径分隔符被拒绝，确保该值
// 可安全用于日志、Redis 键与请求头。
func Validate(id string) error {
	if id == "" {
		return errs.Detail(ErrInvalidID, "empty id | 空 id")
	}
	if len(id) > MaxIDLength {
		return errs.Detail(ErrInvalidID, "id length %[1]d exceeds %[2]d | id 长度 %[1]d 超过 %[2]d", len(id), MaxIDLength)
	}
	if id == "." || id == ".." {
		return errs.Detail(ErrInvalidID, "%q is reserved | %q 是保留值", id, id)
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '-', c == '_':
		default:
			return errs.Detail(ErrInvalidID, "character %[1]q at %[2]d is not allowed | 第 %[2]d 个字符 %[1]q 不允许", c, i)
		}
	}
	return nil
}

// claim runs the optional uniqueness check. | claim 执行可选的唯一性校验。
func claim(ctx context.Context, c Claimer, id Identity) error {
	if c == nil {
		return nil
	}
	if err := c.Claim(ctx, id.ID, id.Instance); err != nil {
		if errors.Is(err, ErrDuplicate) {
			return errs.WrapDetail(err, ErrDuplicate, "id %[1]q instance %[2]q | id %[1]q 实例 %[2]q", id.ID, id.Instance)
		}
		return errs.Wrap(err, ErrIdentityFile)
	}
	return nil
}
