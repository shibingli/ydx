package rbac

import "context"

// Reset removes every role, assignment and policy atomically, including all per-subject indexes.
// | Reset 原子删除所有角色、分配与策略，包括全部按主体索引。
func (s *Store) Reset(ctx context.Context) error {
	ctx = normalizeContext(ctx)
	if err := s.ensure(); err != nil {
		return err
	}
	if err := checkContext(ctx); err != nil {
		return err
	}
	_, err := s.runInt(ctx, scriptReset, "reset",
		[]string{
			s.keys.roles(),
			s.keys.roleParents(),
			s.keys.assignments(),
			s.keys.assignmentExpiry(),
			s.keys.assignmentSubjects(),
			s.keys.policies(),
		},
		s.keys.assignmentSubjectPrefix(),
	)
	return err
}
