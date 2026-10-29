package workflow

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
	ydlog "github.com/shibingli/ydx/log"
)

// errAIDeferred is the internal control signal that aborts one transaction so the AI decider can
// run outside it. It never escapes Service.WithTx. | errAIDeferred 是中止一次事务、让 AI 决策器在
// 事务之外运行的内部控制信号，它不会逃出 Service.WithTx。
var errAIDeferred = errs.New("workflow AI decision deferred | 流程 AI 决策已延后")

const (
	// aiDecisionTimeout bounds one decider call made outside the database transaction. |
	// aiDecisionTimeout 限制一次在数据库事务之外发起的决策调用。
	aiDecisionTimeout = 30 * time.Second
	// maxAIDecisionsPerTx bounds how many decider calls one public operation may trigger. The
	// limit turns a pathological rule chain into ErrLimit instead of an unbounded loop. |
	// maxAIDecisionsPerTx 限制一次公开操作最多触发多少次决策调用；病态的规则链会转为 ErrLimit，
	// 而不是无限循环。
	maxAIDecisionsPerTx = 16
)

// aiDecisionKey identifies one rule evaluation inside one instance. | aiDecisionKey 标识某个实例内的一次规则求值。
type aiDecisionKey struct {
	// TenantID, InstanceID, NodeID and RuleID form the stable identity. | TenantID、InstanceID、
	// NodeID 与 RuleID 构成稳定标识。
	TenantID   string
	InstanceID string
	NodeID     string
	RuleID     string
}

// aiDecisionEntry is the cached outcome for one key. | aiDecisionEntry 是一个键的缓存结果。
type aiDecisionEntry struct {
	// result is the decider's answer when skip is false. | skip 为 false 时 result 是决策器的答案。
	result DecisionResult
	// hash binds the entry to the exact decision input; a changed input forces a fresh call. |
	// hash 把缓存绑定到确切的决策输入；输入变化会强制重新调用。
	hash [sha256.Size]byte
	// skip reports that the rule must fall through to manual approval. | skip 表示该规则应退化为人工审批。
	skip bool
}

// aiDeferral is the control-flow error carrying one pending decision. | aiDeferral 承载一次待决决策的控制流错误。
type aiDeferral struct {
	// key identifies the rule evaluation. | key 标识本次规则求值。
	key aiDecisionKey
	// input is what the decider receives. | input 是决策器收到的输入。
	input DecisionInput
	// hash fingerprints input. | hash 是 input 的指纹。
	hash [sha256.Size]byte
}

// Error returns the internal sentinel text. | Error 返回内部哨兵文案。
func (d *aiDeferral) Error() string { return errAIDeferred.Error() }

// Is makes errors.Is(err, errAIDeferred) true without exposing the payload. |
// Is 让 errors.Is(err, errAIDeferred) 成立，同时不暴露载荷。
func (d *aiDeferral) Is(target error) bool { return target == errAIDeferred }

// Unwrap exposes the sentinel. | Unwrap 暴露哨兵错误。
func (d *aiDeferral) Unwrap() error { return errAIDeferred }

// aiDecisionCarrier lets evaluateAuto read decisions cached by aiDeferringStore. |
// aiDecisionCarrier 让 evaluateAuto 读取 aiDeferringStore 缓存的决策。
type aiDecisionCarrier interface {
	// lookupAIDecision returns a cached decision only when the input hash still matches. |
	// lookupAIDecision 仅在输入指纹仍然匹配时返回缓存决策。
	lookupAIDecision(key aiDecisionKey, hash [sha256.Size]byte) (aiDecisionEntry, bool)
}

// aiDecisionStore decorates the transaction-bound store with the retry cache. |
// aiDecisionStore 为事务绑定的存储附加重试缓存。
type aiDecisionStore struct {
	Store
	// decisions is shared across every retry of one logical operation. | decisions 在一次逻辑操作的每次重试间共享。
	decisions map[aiDecisionKey]aiDecisionEntry
}

// lookupAIDecision implements aiDecisionCarrier. | lookupAIDecision 实现 aiDecisionCarrier。
func (s *aiDecisionStore) lookupAIDecision(key aiDecisionKey, hash [sha256.Size]byte) (aiDecisionEntry, bool) {
	entry, ok := s.decisions[key]
	if !ok || entry.hash != hash {
		return aiDecisionEntry{}, false
	}
	return entry, true
}

// aiDeferringStore runs AI deciders between transactions instead of inside them. Holding row
// locks (and on SQLite the single writer slot) for the duration of an external HTTP call would
// stall every other workflow action, so a deferred decision rolls the transaction back, calls the
// decider without any lock, and replays the callback with the cached answer. | aiDeferringStore
// 在事务之间而不是事务之内运行 AI 决策器。若在外部 HTTP 调用期间持有行锁（SQLite 上还占着唯一的
// 写者位置），其它流程动作都会停摆；因此延后决策会先回滚事务，再在不持锁的情况下调用决策器，
// 最后带着缓存答案重放回调。
type aiDeferringStore struct {
	Store
	// svc supplies the decider, logger and options. | svc 提供决策器、日志与选项。
	svc *Service
}

// WithTx retries the callback after each deferred AI decision. | WithTx 在每次延后的 AI 决策之后重试回调。
func (s *aiDeferringStore) WithTx(ctx context.Context, fn func(Store) error) error {
	decisions := make(map[aiDecisionKey]aiDecisionEntry, 1)
	calls := 0
	for {
		err := s.Store.WithTx(ctx, func(st Store) error {
			return fn(&aiDecisionStore{Store: st, decisions: decisions})
		})
		var deferred *aiDeferral
		if !errors.As(err, &deferred) {
			return err
		}
		calls++
		if calls > maxAIDecisionsPerTx {
			return errs.Detail(ErrLimit, "one operation requested more than %[1]d AI decisions | 单次操作请求的 AI 决策超过 %[1]d 次", maxAIDecisionsPerTx)
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		decisions[deferred.key] = s.decide(ctx, deferred)
	}
}

// decide calls the decider outside any transaction and never lets a panic escape. | decide 在任何事务
// 之外调用决策器，且绝不让 panic 逃逸。
func (s *aiDeferringStore) decide(ctx context.Context, req *aiDeferral) (entry aiDecisionEntry) {
	entry = aiDecisionEntry{hash: req.hash, skip: true}
	if s.svc == nil || s.svc.decider == nil {
		return entry
	}
	defer func() {
		if rec := recover(); rec != nil {
			s.svc.log.Error("workflow AI decider panicked, the node stays manual | 流程 AI 决策器 panic，节点保持人工审批", ydlog.Any("panic", rec))
			entry = aiDecisionEntry{hash: req.hash, skip: true}
		}
	}()
	callCtx, cancel := context.WithTimeout(ctx, aiDecisionTimeout)
	defer cancel()
	result, err := s.svc.decider.Decide(callCtx, req.input)
	if err != nil {
		s.svc.log.Warn("workflow AI decider failed, the node stays manual | 流程 AI 决策失败，节点保持人工审批", ydlog.Err(err))
		return entry
	}
	entry.result = result
	entry.skip = false
	return entry
}

// deferredAIDecision reports whether a cached decision exists for the current transaction. |
// deferredAIDecision 报告当前事务是否存在可用的缓存决策。
func deferredAIDecision(st Store, key aiDecisionKey, hash [sha256.Size]byte) (aiDecisionEntry, bool) {
	carrier, ok := st.(aiDecisionCarrier)
	if !ok {
		return aiDecisionEntry{}, false
	}
	return carrier.lookupAIDecision(key, hash)
}

// aiInputHash fingerprints the complete decider input. The design and BPMN strings are excluded:
// they are immutable for a published version, already represented by its checksum, and hashing
// them would allocate a copy of the whole document on every decision. | aiInputHash 为完整的决策
// 输入生成指纹。设计串与 BPMN 串被排除：它们在已发布版本上不可变、已由校验和代表，哈希它们会在每次
// 决策时分配整份文档的副本。
func aiInputHash(input DecisionInput) ([sha256.Size]byte, error) {
	input.Instance.Variables = ""
	input.Version.Design = ""
	input.Version.BPMN = ""
	data, err := json.Marshal(input)
	if err != nil {
		return [sha256.Size]byte{}, errs.Wrap(err, ErrInvalidInput)
	}
	return sha256.Sum256(data), nil
}
