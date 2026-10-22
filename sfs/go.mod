module github.com/shibingli/ydx/sfs

go 1.27.2

require (
	github.com/shibingli/ydx/errs v0.1.0
	github.com/spf13/afero v1.15.0
)

require golang.org/x/text v0.43.0 // indirect

replace github.com/shibingli/ydx/errs => ../errs
