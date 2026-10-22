module github.com/shibingli/ydx/log

go 1.27.2

require (
	github.com/shibingli/ydx/base64 v0.1.0
	github.com/shibingli/ydx/errs v0.1.0
	github.com/shibingli/ydx/json v0.1.0
	github.com/shibingli/ydx/sysinfo v0.1.0
)

require (
	github.com/cristalhq/base64 v0.1.2 // indirect
	github.com/goccy/go-json v0.11.2 // indirect
)

replace github.com/shibingli/ydx/base64 => ../base64

replace github.com/shibingli/ydx/errs => ../errs

replace github.com/shibingli/ydx/json => ../json

replace github.com/shibingli/ydx/sysinfo => ../sysinfo
