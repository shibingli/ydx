package nodeid

import (
	"os"
	"strings"
)

// environmentPaths and environmentEnv are variables so tests can simulate every
// environment without touching the host. | environmentPaths 与 environmentEnv 是变量，测试
// 因此可以模拟各种环境而不触碰宿主机。
var (
	kubernetesEnv       = "KUBERNETES_SERVICE_HOST"
	kubernetesTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	containerEnv        = "container"
	containerMarkers    = []string{"/.dockerenv", "/run/.containerenv"}
	initCgroupPath      = "/proc/1/cgroup"
	platformFactsFunc   = platformFacts
	platformSeedFunc    = platformSeed
)

// environmentFacts is the raw evidence used to classify the runtime. | environmentFacts 是
// 用于判定运行环境的原始证据。
type environmentFacts struct {
	Kubernetes      bool
	ContainerMarker bool
	ContainerEnv    string
	Cgroup          string
	Vendor          string
	Product         string
}

// DetectEnvironment classifies the current process. Detection is advisory: an
// unknown virtual machine is reported as physical rather than guessed. | DetectEnvironment
// 对当前进程分类。检测是建议性的：无法识别的虚机按物理机报告，而不是猜测。
func DetectEnvironment() Environment {
	vendor, product := platformFactsFunc()
	return classifyEnvironment(environmentFacts{
		Kubernetes:      strings.TrimSpace(os.Getenv(kubernetesEnv)) != "" || fileExists(kubernetesTokenPath),
		ContainerMarker: anyFileExists(containerMarkers),
		ContainerEnv:    strings.TrimSpace(os.Getenv(containerEnv)),
		Cgroup:          readTrim(initCgroupPath),
		Vendor:          vendor,
		Product:         product,
	})
}

// classifyEnvironment is the pure decision table. | classifyEnvironment 是纯判定表。
func classifyEnvironment(f environmentFacts) Environment {
	switch {
	case f.Kubernetes:
		return EnvironmentKubernetes
	case f.ContainerMarker || f.ContainerEnv != "" || looksContainerCgroup(f.Cgroup):
		return EnvironmentContainer
	case looksVirtual(f.Vendor + " " + f.Product):
		return EnvironmentVirtual
	default:
		return EnvironmentPhysical
	}
}

// looksContainerCgroup reports whether a cgroup path names a container runtime. |
// looksContainerCgroup 报告 cgroup 路径是否属于某个容器运行时。
func looksContainerCgroup(cgroup string) bool {
	value := strings.ToLower(cgroup)
	for _, marker := range []string{
		"docker", "containerd", "kubepods", "podman", "libpod", "lxc", "garden", "sandbox",
	} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

// looksVirtual reports whether DMI vendor/product names a hypervisor. | looksVirtual 报告
// DMI 厂商/产品名是否指向虚拟机监控器。
func looksVirtual(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"qemu", "kvm", "vmware", "virtualbox", "innotek", "xen", "hyper-v",
		"virtual machine", "amazon ec2", "google compute", "openstack",
		"parallels", "bhyve", "bochs",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// fileExists reports whether path names a readable file. | fileExists 报告 path 是否为可读文件。
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// anyFileExists reports whether any path exists. | anyFileExists 报告是否有任一 path 存在。
func anyFileExists(paths []string) bool {
	for _, path := range paths {
		if fileExists(path) {
			return true
		}
	}
	return false
}

// readTrim reads a small text file and trims surrounding whitespace. Missing or
// unreadable files are reported as an empty string: callers treat absence as
// "this source is unavailable". | readTrim 读取小文本文件并去掉首尾空白。文件缺失或不可读时
// 返回空串：调用方把缺失视为「该来源不可用」。
func readTrim(path string) string {
	if path == "" {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 4096 {
		return ""
	}
	return strings.TrimSpace(string(raw))
}
