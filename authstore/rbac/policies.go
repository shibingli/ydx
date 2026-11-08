package rbac

import (
	"context"
	"errors"

	goredis "github.com/redis/go-redis/v9"

	authrbac "github.com/shibingli/ydx/auth/authz/rbac"
	"github.com/shibingli/ydx/errs"
)

// AddPolicy validates and normalizes a policy, then stores it atomically while rejecting a
// duplicate identifier. | AddPolicy 校验并规范化策略，然后在拒绝重复标识的前提下原子保存。
func (s *Store) AddPolicy(ctx context.Context, policy authrbac.Policy) error {
	ctx = normalizeContext(ctx)
	if err := s.ensure(); err != nil {
		return err
	}
	if err := checkContext(ctx); err != nil {
		return err
	}
	normalized, err := normalizePolicy(policy)
	if err != nil {
		return err
	}
	data, err := encodePolicy(normalized)
	if err != nil {
		return err
	}
	code, err := s.runInt(ctx, scriptPolicyAdd, "add policy",
		[]string{s.keys.policies()}, normalized.ID, string(data),
	)
	if err != nil {
		return err
	}
	switch code {
	case 0:
		return nil
	case 1:
		return errs.Detail(authrbac.ErrPolicyExists, "policy %q | 策略 %q", normalized.ID, normalized.ID)
	default:
		return errs.Detail(ErrStoreUnavailable, "add policy returned %d | 添加策略返回 %d", code, code)
	}
}

// RemovePolicy removes one policy by identifier. | RemovePolicy 按标识删除单条策略。
func (s *Store) RemovePolicy(ctx context.Context, id string) error {
	ctx = normalizeContext(ctx)
	if err := s.ensure(); err != nil {
		return err
	}
	if err := checkContext(ctx); err != nil {
		return err
	}
	code, err := s.runInt(ctx, scriptPolicyRemove, "remove policy",
		[]string{s.keys.policies()}, id,
	)
	if err != nil {
		return err
	}
	switch code {
	case 0:
		return nil
	case 1:
		return errs.Detail(authrbac.ErrPolicyNotFound, "policy %q | 策略 %q", id, id)
	default:
		return errs.Detail(ErrStoreUnavailable, "remove policy returned %d | 删除策略返回 %d", code, code)
	}
}

// GetPolicy returns a deep copy of one policy. | GetPolicy 返回一条策略的深拷贝。
func (s *Store) GetPolicy(ctx context.Context, id string) (authrbac.Policy, error) {
	ctx = normalizeContext(ctx)
	if err := s.ensure(); err != nil {
		return authrbac.Policy{}, err
	}
	if err := checkContext(ctx); err != nil {
		return authrbac.Policy{}, err
	}
	data, err := s.client.HGet(ctx, s.keys.policies(), id).Result()
	if errors.Is(err, goredis.Nil) {
		return authrbac.Policy{}, errs.Detail(authrbac.ErrPolicyNotFound, "policy %q | 策略 %q", id, id)
	}
	if err != nil {
		return authrbac.Policy{}, s.backend("get policy", err)
	}
	return decodePolicy([]byte(data))
}

// ListPolicies returns deep copies of every policy sorted by identifier.
// | ListPolicies 按标识返回所有策略的深拷贝。
func (s *Store) ListPolicies(ctx context.Context) ([]authrbac.Policy, error) {
	ctx = normalizeContext(ctx)
	if err := s.ensure(); err != nil {
		return nil, err
	}
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	stored, err := s.client.HGetAll(ctx, s.keys.policies()).Result()
	if err != nil {
		return nil, s.backend("list policies", err)
	}
	policies := make([]authrbac.Policy, 0, len(stored))
	for _, data := range stored {
		policy, err := decodePolicy([]byte(data))
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}
	sortPolicies(policies)
	return policies, nil
}
