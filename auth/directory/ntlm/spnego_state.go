package ntlm

// SPNEGOState tracks the position of a client-side or acceptor-side SPNEGO
// exchange. | SPNEGOState 跟踪客户端或接受方 SPNEGO 交换所处的位置。
type SPNEGOState uint8

const (
	// SPNEGOStateInitial means no token has been exchanged. | SPNEGOStateInitial
	// 表示尚未交换令牌。
	SPNEGOStateInitial SPNEGOState = iota
	// SPNEGOStateInProgress means the initial token or challenge has been sent
	// and the exchange is waiting for the peer. | SPNEGOStateInProgress 表示已发送
	// 初始令牌或挑战，正在等待对端。
	SPNEGOStateInProgress
	// SPNEGOStateCompleted means the exchange finished successfully. |
	// SPNEGOStateCompleted 表示交换成功完成。
	SPNEGOStateCompleted
	// SPNEGOStateFailed means the exchange was rejected and cannot continue. |
	// SPNEGOStateFailed 表示交换被拒绝且无法继续。
	SPNEGOStateFailed
)

// String returns a stable name for the SPNEGO state. | String 返回 SPNEGO 状态的稳定名称。
func (s SPNEGOState) String() string {
	switch s {
	case SPNEGOStateInitial:
		return "initial"
	case SPNEGOStateInProgress:
		return "in-progress"
	case SPNEGOStateCompleted:
		return "completed"
	case SPNEGOStateFailed:
		return "failed"
	default:
		return "unknown"
	}
}
