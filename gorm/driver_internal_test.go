package gorm

import "testing"

// TestDriverKindRecognizesDM verifies that dm and its long spelling select the DM dialect while
// unknown names still resolve to the empty string callers must reject. | TestDriverKindRecognizesDM
// 验证 dm 及其长拼写都选择 DM 方言，未知名称仍解析为调用方必须拒绝的空串。
func TestDriverKindRecognizesDM(t *testing.T) {
	cases := map[string]string{
		"dm":       DriverDM,
		"DM":       DriverDM,
		" dameng ": DriverDM,
		"Dameng":   DriverDM,
		"":         DriverSQLite,
		"sqlite":   DriverSQLite,
		"mysql":    DriverMySQL,
		"postgres": DriverPostgres,
		"oracle":   "",
	}
	for name, want := range cases {
		if got := driverKind(name); got != want {
			t.Fatalf("driverKind(%q) = %q, want %q | 驱动名解析不符", name, got, want)
		}
	}
}

// TestDialectorForDM verifies that the DM dialector is built without contacting a server and reports
// the driver name GORM's error classification relies on. | TestDialectorForDM 验证 DM 方言无需连接
// 服务端即可构造，并报告 GORM 错误分类所依赖的驱动名。
func TestDialectorForDM(t *testing.T) {
	d, err := dialectorFor(DriverDM, "dm://SYSDBA:pw@127.0.0.1:5236")
	if err != nil {
		t.Fatalf("dialectorFor(dm) failed | 构造 DM 方言失败: %v", err)
	}
	if got := d.Name(); got != DriverDM {
		t.Fatalf("dialector name = %q, want %q | 方言名不符", got, DriverDM)
	}
}
