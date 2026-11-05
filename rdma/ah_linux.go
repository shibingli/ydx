//go:build linux && rdma && (amd64 || arm64)

package rdma

// Close destroys the address handle. | Close 销毁地址句柄。
func (a *AH) Close() error {
	if a == nil || !a.closed.CompareAndSwap(false, true) {
		return nil
	}
	if a.state != nil && a.state.ah != nil {
		a.state.api.removeAH(a.state.ah)
		a.state.ah = nil
	}
	return nil
}
