module github.com/shibingli/ydx/benchmarks/base64

go 1.27.3

require (
	github.com/cloudwego/base64x v0.1.7
	github.com/cristalhq/base64 v0.1.2
	github.com/shibingli/ydx/base64 v0.1.11
)

// cloudwego/base64x v0.1.7 requests sonic/loader v0.5.1, which aborts on Go 1.27.3.
// v0.5.2 is pinned here so the JIT benchmark can run; see README.md.
require (
	github.com/bytedance/sonic/loader v0.5.2 // indirect
	github.com/klauspost/cpuid/v2 v2.2.9 // indirect
	github.com/shibingli/ydx/errs v0.1.4 // indirect
	github.com/shibingli/ydx/sysinfo v0.1.4 // indirect
	golang.org/x/sys v0.22.0 // indirect
)
