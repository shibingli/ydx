module github.com/shibingli/ydx/webtransport

go 1.27.4

require (
	// quic-go v0.65.0 changes http3.HTTPStreamer.HTTPStream to return (*Stream, error);
	// webtransport-go v0.13.0 does not support that signature yet. Keep v0.64.1 until a
	// compatible webtransport-go release is available. | quic-go v0.65.0 将
	// http3.HTTPStreamer.HTTPStream 改为返回 (*Stream, error)，webtransport-go v0.13.0
	// 尚不兼容；在有兼容版本前固定 v0.64.1。
	github.com/quic-go/quic-go v0.64.1
	github.com/quic-go/webtransport-go v0.13.0
	github.com/shibingli/ydx/errs v0.1.6
)

require (
	github.com/dunglas/httpsfv v1.1.2 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/text v0.44.0 // indirect
)
