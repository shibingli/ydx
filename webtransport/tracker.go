package webtransport

import "sync"

// Tracker tracks live sessions so an external lifecycle owner can terminate
// every one of them in a single call. | Tracker 追踪活跃会话，使外部生命周期持有者能
// 一次性终止全部会话。
//
// The interface is defined here rather than importing the framework's lifecycle
// package, mirroring ydx/websocket: the registry implements this contract, not
// the other way round. | 该接口定义在此处而不是引入框架的 lifecycle 包，与
// ydx/websocket 一致：是注册表实现本契约，而不是反过来。
type Tracker interface {
	// Track registers a live session and returns an idempotent untrack function;
	// the session calls it automatically from Close. | Track 登记一个活跃会话并返回
	// 幂等的取消登记函数；会话会在 Close 中自动调用它。
	Track(s *Session) (untrack func())
	// CloseAll terminates every tracked session with the given application error
	// code and reason. | CloseAll 以给定应用错误码与原因终止全部已登记会话。
	CloseAll(code uint32, reason string)
}

// SessionSet is the default in-process Tracker. | SessionSet 是默认的进程内 Tracker。
//
// Every method is safe for concurrent use; CloseAll walks a snapshot and never
// holds the lock while a session is being written to. | 所有方法均可安全并发使用；
// CloseAll 遍历快照，且在不写会话时绝不持锁。
type SessionSet struct {
	sessions map[*Session]struct{}
	mu       sync.Mutex
}

// NewSessionSet creates an empty session set. | NewSessionSet 创建一个空会话集合。
func NewSessionSet() *SessionSet {
	return &SessionSet{sessions: make(map[*Session]struct{}, 8)}
}

// Track implements Tracker. | Track 实现 Tracker。
func (s *SessionSet) Track(sess *Session) (untrack func()) {
	if sess == nil {
		return func() {}
	}
	s.mu.Lock()
	s.sessions[sess] = struct{}{}
	s.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			delete(s.sessions, sess)
			s.mu.Unlock()
		})
	}
}

// CloseAll implements Tracker. | CloseAll 实现 Tracker。
func (s *SessionSet) CloseAll(code uint32, reason string) {
	s.mu.Lock()
	sessions := make([]*Session, 0, len(s.sessions))
	for sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	clear(s.sessions)
	s.mu.Unlock()

	for _, sess := range sessions {
		_ = sess.Close(code, reason)
	}
}

// Len returns the number of tracked sessions. | Len 返回已登记的会话数量。
func (s *SessionSet) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}
