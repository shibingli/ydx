package rdma

import "testing"

// TestConnConfigZeroKeepsLegacyDefaults proves every new ConnConfig field keeps
// the historical behavior at its zero value. | TestConnConfigZeroKeepsLegacyDefaults
// 证明每个新增 ConnConfig 字段在零值时保持历史行为。
func TestConnConfigZeroKeepsLegacyDefaults(t *testing.T) {
	cfg := DefaultConnConfig()
	if err := cfg.normalize(); err != nil {
		t.Fatalf("normalize(default) = %v | 默认配置不应报错", err)
	}
	if cfg.CQPollBudget != 0 || cfg.SpinBeforeGosched != 0 || cfg.DeadlineCheckSpins != 0 || cfg.BusyPoll || cfg.PrePostRecv != 0 || cfg.QPAccess != 0 {
		t.Fatalf("new ConnConfig fields changed by normalize: %+v | 新增字段被 normalize 改写", cfg)
	}
	c := &Conn{cfg: cfg}
	if got := c.pollBudget(); got != cfg.MaxBatch {
		t.Fatalf("pollBudget = %d, want MaxBatch %d | 轮询预算应回落为 MaxBatch", got, cfg.MaxBatch)
	}
	if got := c.yieldSpins(); got != 4096 {
		t.Fatalf("yieldSpins = %d, want 4096 | 让出前自旋应回落为 4096", got)
	}
	if got := c.deadlineSpins(); got != 1024 {
		t.Fatalf("deadlineSpins = %d, want 1024 | 截止检查间隔应回落为 1024", got)
	}
	if c.mayYield(4095) || !c.mayYield(4096) {
		t.Fatalf("mayYield thresholds changed | 让出阈值不符合历史行为")
	}
	if !c.deadlineDue(1024) || c.deadlineDue(1023) {
		t.Fatalf("deadlineDue thresholds changed | 截止检查阈值不符合历史行为")
	}
}

// TestConnConfigTuningApplies proves the optional small-message knobs take
// effect without altering the defaults. | TestConnConfigTuningApplies 证明可选
// 小消息参数生效且不改变默认值。
func TestConnConfigTuningApplies(t *testing.T) {
	cfg := DefaultConnConfig()
	cfg.CQPollBudget = 256
	cfg.SpinBeforeGosched = 65536
	cfg.DeadlineCheckSpins = 4096
	cfg.BusyPoll = true
	cfg.PrePostRecv = 8
	if err := cfg.normalize(); err != nil {
		t.Fatalf("normalize(tuned) = %v | 调优配置不应报错", err)
	}
	c := &Conn{cfg: cfg}
	if got := c.pollBudget(); got != 256 {
		t.Fatalf("pollBudget = %d, want 256 | 轮询预算未生效", got)
	}
	if got := c.yieldSpins(); got != 65536 {
		t.Fatalf("yieldSpins = %d, want 65536 | 让出阈值未生效", got)
	}
	if c.mayYield(1 << 20) {
		t.Fatalf("BusyPoll did not disable yielding | BusyPoll 未禁用让出")
	}
	if !c.deadlineDue(4096) || c.deadlineDue(2048) {
		t.Fatalf("deadlineDue interval not applied | 截止检查间隔未生效")
	}
}

// TestConnConfigRejectsInvalidTuning proves invalid tuning values fail loudly.
// | TestConnConfigRejectsInvalidTuning 证明非法调优值会显式报错。
func TestConnConfigRejectsInvalidTuning(t *testing.T) {
	base := DefaultConnConfig()
	cases := []struct {
		name   string
		mutate func(*ConnConfig)
	}{
		{"negative poll budget", func(c *ConnConfig) { c.CQPollBudget = -1 }},
		{"negative spin", func(c *ConnConfig) { c.SpinBeforeGosched = -1 }},
		{"negative deadline", func(c *ConnConfig) { c.DeadlineCheckSpins = -1 }},
		{"one pre-post", func(c *ConnConfig) { c.PrePostRecv = 1 }},
		{"negative pre-post", func(c *ConnConfig) { c.PrePostRecv = -2 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			if err := cfg.normalize(); err == nil {
				t.Fatalf("normalize(%s) = nil, want error | 非法调优值应报错", tc.name)
			}
		})
	}
}
