package oidc

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// TestProviderCleanupDelegation verifies Provider forwards cleanup lifecycle and single-pass calls
// to the embedded OAuth server and validates nil receivers. | TestProviderCleanupDelegation 校验
// Provider 把清理生命周期与单次清理调用转发给内嵌 OAuth 服务器，并校验 nil 接收者。
func TestProviderCleanupDelegation(t *testing.T) {
	ctx := context.Background()
	fixture := newOIDCFixture(t, false)

	var nilProvider *Provider
	if err := nilProvider.StartCleanup(time.Minute); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil StartCleanup = %v | nil StartCleanup = %v", err, err)
	}
	nilProvider.StopCleanup()
	if err := nilProvider.Cleanup(ctx); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil Cleanup = %v | nil Cleanup = %v", err, err)
	}

	bare := &Provider{}
	if err := bare.StartCleanup(time.Minute); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("provider without OAuth StartCleanup = %v | 无 OAuth 的 StartCleanup = %v", err, err)
	}
	bare.StopCleanup()
	if err := bare.Cleanup(ctx); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("provider without OAuth Cleanup = %v | 无 OAuth 的 Cleanup = %v", err, err)
	}

	if err := fixture.provider.Cleanup(ctx); err != nil {
		t.Fatalf("single cleanup = %v | 单次清理 = %v", err, err)
	}
	if err := fixture.provider.StartCleanup(time.Hour); err != nil {
		t.Fatalf("StartCleanup = %v | StartCleanup = %v", err, err)
	}
	// A second start keeps the same running scheduler. | 二次启动保留同一个运行中的调度器。
	if err := fixture.provider.StartCleanup(time.Minute); err != nil {
		t.Fatalf("second StartCleanup = %v | 二次 StartCleanup = %v", err, err)
	}
	fixture.provider.StopCleanup()
	// Repeated stops are no-ops. | 重复停止是无操作。
	fixture.provider.StopCleanup()

	if err := fixture.provider.StartCleanup(0); err != nil {
		t.Fatalf("default interval StartCleanup = %v | 默认间隔 StartCleanup = %v", err, err)
	}
	fixture.provider.StopCleanup()
}

// TestProviderCleanupConcurrent verifies concurrent lifecycle and cleanup calls are race free and
// leave no scheduler running. | TestProviderCleanupConcurrent 校验并发生命周期与清理调用无数据竞争，
// 且不残留运行中的调度器。
func TestProviderCleanupConcurrent(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if err := fixture.provider.StartCleanup(time.Millisecond); err != nil {
					t.Errorf("concurrent StartCleanup: %v", err)
					return
				}
				if err := fixture.provider.Cleanup(context.Background()); err != nil {
					t.Errorf("concurrent Cleanup: %v", err)
					return
				}
				fixture.provider.StopCleanup()
			}
		}()
	}
	wg.Wait()
	fixture.provider.StopCleanup()
}
