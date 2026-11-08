//go:build !linux && !windows

package webauthn

import (
	"time"

	"github.com/shibingli/ydx/errs"
)

// openPlatformTPM reports that this platform has no TPM transport. | openPlatformTPM 报告该平台没有 TPM
// 传输。
func openPlatformTPM(options TPMOptions, timeout time.Duration) (TPM, error) {
	_ = options
	_ = timeout
	return nil, errs.Detail(ErrUnsupported, "no TPM transport is implemented for this platform | 此平台未实现 TPM 传输")
}
