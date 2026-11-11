module github.com/shibingli/ydx/websocket

go 1.27.4

require (
	github.com/coder/websocket v1.8.15
	github.com/klauspost/compress v1.20.4
	// Keep v0.64.1: webtransport-go v0.13.0 is incompatible with quic-go v0.65.0's
	// http3.HTTPStreamer.HTTPStream signature, and MVS would select v0.65.0 for apps
	// that also depend on ydx/realtime or ydx/webtransport. | webtransport-go v0.13.0
	// 尚不兼容 quic-go v0.65.0 的 HTTPStream 签名；同时引用 realtime/webtransport 的
	// 消费方会被 MVS 选到 v0.65.0，因此本模块也固定 v0.64.1。
	github.com/quic-go/quic-go v0.64.1
	github.com/shibingli/ydx/base64 v0.1.15
	github.com/shibingli/ydx/errs v0.1.6
	github.com/shibingli/ydx/json v0.1.20
	github.com/shibingli/ydx/log v0.1.14
	github.com/shibingli/ydx/protocol v0.1.7
	github.com/shibingli/ydx/regexpx v0.1.14
	github.com/shibingli/ydx/router v0.1.16
	github.com/shibingli/ydx/sysinfo v0.1.6
	golang.org/x/net v0.62.0
)

require (
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/shibingli/ydx/afs v0.1.8 // indirect
	github.com/shibingli/ydx/xml v0.1.3 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/text v0.44.0 // indirect
)
