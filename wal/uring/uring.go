package uring

// Options configures the io_uring engine. | Options 配置 io_uring 引擎。
type Options struct {
	// QueueDepth is the submission/completion queue depth (default 256). |
	// QueueDepth 是提交/完成队列深度（默认 256）。
	QueueDepth int
	// SetupFlags are extra io_uring_setup flags. Leave zero for the portable
	// default; SQPOLL and other privileged flags are the caller's choice. |
	// SetupFlags 是额外的 io_uring_setup flags。默认留零以获得可移植行为；
	// SQPOLL 等特权 flag 由调用方自行承担。
	SetupFlags uint32
}

// Option customizes New. | Option 定制 New。
type Option func(*Options)

// WithQueueDepth sets the ring depth. Values below 2 or above 4096 are
// clamped. | WithQueueDepth 设置 ring 深度；小于 2 或大于 4096 会被裁剪。
func WithQueueDepth(n int) Option { return func(o *Options) { o.QueueDepth = n } }

// WithSetupFlags sets extra io_uring_setup flags. | WithSetupFlags 设置额外的
// io_uring_setup flags。
func WithSetupFlags(flags uint32) Option { return func(o *Options) { o.SetupFlags = flags } }

// normalize fills defaults and clamps the depth. | normalize 填充默认值并裁剪深度。
func (o *Options) normalize() {
	if o.QueueDepth == 0 {
		o.QueueDepth = 256
	}
	if o.QueueDepth < 2 {
		o.QueueDepth = 2
	}
	if o.QueueDepth > 4096 {
		o.QueueDepth = 4096
	}
}
