//go:build linux && rdma && (amd64 || arm64)

package rdma

// Close destroys the address handle. | Close 销毁地址句柄。
func (a *AH) Close() error {
	if a == nil {
		return nil
	}
	a.closeMu.Lock()
	defer a.closeMu.Unlock()
	if a.closed.Load() {
		return a.closeErr
	}
	a.closed.Store(true)
	if a.state != nil && a.state.ah != nil {
		if rc := a.state.api.removeAH(a.state.ah); rc != 0 {
			a.closed.Store(false)
			a.closeErr = errnoError("destroy address handle", rc)
			return a.closeErr
		}
		a.state.ah = nil
	}
	a.closeErr = nil
	a.dev.releaseChild()
	return nil
}
