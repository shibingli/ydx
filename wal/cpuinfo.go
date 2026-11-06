package wal

import "runtime"

// detectEngineInfo returns platform capabilities. | detectEngineInfo 返回平台能力。
func detectEngineInfo() EngineInfo {
	info := EngineInfo{
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		DirSyncDurable: runtime.GOOS != "windows",
		Reflink:        runtime.GOOS == "linux" || runtime.GOOS == "darwin",
	}
	detectCPU(&info)
	return info
}
