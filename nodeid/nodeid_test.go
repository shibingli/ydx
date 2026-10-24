package nodeid

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fixedEnvironment pins the runtime classification for a test. | fixedEnvironment 为测试固定
// 运行环境判定。
func fixedEnvironment(t *testing.T, env Environment) {
	t.Helper()
	t.Setenv(kubernetesEnv, "")
	t.Setenv(containerEnv, "")
	oldToken, oldMarkers, oldCgroup, oldFacts := kubernetesTokenPath, containerMarkers, initCgroupPath, platformFactsFunc
	t.Cleanup(func() {
		kubernetesTokenPath = oldToken
		containerMarkers = oldMarkers
		initCgroupPath = oldCgroup
		platformFactsFunc = oldFacts
	})
	kubernetesTokenPath = filepath.Join(t.TempDir(), "missing-token")
	containerMarkers = nil
	initCgroupPath = ""
	platformFactsFunc = func() (string, string) { return "", "" }
	switch env {
	case EnvironmentKubernetes:
		t.Setenv(kubernetesEnv, "10.0.0.1")
	case EnvironmentContainer:
		marker := filepath.Join(t.TempDir(), "container-marker")
		if err := os.WriteFile(marker, nil, 0o600); err != nil {
			t.Fatalf("write marker: %v", err)
		}
		containerMarkers = []string{marker}
	case EnvironmentVirtual:
		platformFactsFunc = func() (string, string) { return "QEMU", "Standard PC" }
	}
}

// fixedSeed overrides the platform seed for a test. | fixedSeed 为测试覆盖平台种子。
func fixedSeed(t *testing.T, source Source, seed string, ok bool) {
	t.Helper()
	old := platformSeedFunc
	platformSeedFunc = func(Environment, bool) (Source, string, bool) { return source, seed, ok }
	t.Cleanup(func() { platformSeedFunc = old })
}

// TestValidate pins the accepted alphabet and length. | TestValidate 固定允许的字符集与长度。
func TestValidate(t *testing.T) {
	valid := []string{"node-a", "ydn_0123456789abcdef", "A.b_c-1", "n"}
	for _, id := range valid {
		if err := Validate(id); err != nil {
			t.Fatalf("Validate(%q) = %v, want nil", id, err)
		}
	}
	invalid := []string{"", "a b", "a:b", "a/b", "a|b", "a\nb", ".", "..", strings.Repeat("a", MaxIDLength+1), "节点"}
	for _, id := range invalid {
		if err := Validate(id); !errors.Is(err, ErrInvalidID) {
			t.Fatalf("Validate(%q) = %v, want ErrInvalidID", id, err)
		}
	}
}

// TestDeriveIsStableAndSeparated proves the same inputs give the same id and
// that salt and source are domain separators. | TestDeriveIsStableAndSeparated 证明相同输入
// 得到相同 id，且盐与来源是域分隔符。
func TestDeriveIsStableAndSeparated(t *testing.T) {
	first := derive(SourceMachineID, "seed", "salt")
	if first != derive(SourceMachineID, "seed", "salt") {
		t.Fatal("derive is not deterministic | derive 不是确定性的")
	}
	if first == derive(SourceMachineID, "seed", "other") {
		t.Fatal("salt did not separate the identity | 盐没有分隔身份")
	}
	if first == derive(SourceSMBIOS, "seed", "salt") {
		t.Fatal("source did not separate the identity | 来源没有分隔身份")
	}
	if !strings.HasPrefix(first, idPrefix) || len(first) != len(idPrefix)+32 {
		t.Fatalf("derived id = %q, want prefix %q and 32 hex chars", first, idPrefix)
	}
}

// TestResolveHonoursEnvID proves the environment override works without a
// Config object. | TestResolveHonoursEnvID 证明没有 Config 时环境变量覆盖同样生效。
func TestResolveHonoursEnvID(t *testing.T) {
	fixedEnvironment(t, EnvironmentPhysical)
	t.Setenv(EnvID, "env-node")
	identity, err := Resolve(context.Background(), Options{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if identity.ID != "env-node" || identity.Source != SourceConfig || !identity.Stable {
		t.Fatalf("identity = %+v", identity)
	}
}

// TestResolveExplicitConfigWins proves configuration beats every other source. |
// TestResolveExplicitConfigWins 证明配置优先于其它所有来源。
func TestResolveExplicitConfigWins(t *testing.T) {
	fixedEnvironment(t, EnvironmentPhysical)
	fixedSeed(t, SourceMachineID, "seed", true)
	file := filepath.Join(t.TempDir(), "node-id")
	if err := os.WriteFile(file, []byte("from-file\n"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	identity, err := Resolve(context.Background(), Options{ConfigID: "node-a", File: file, Create: true})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if identity.ID != "node-a" || identity.Source != SourceConfig || !identity.Persistent || !identity.Stable {
		t.Fatalf("identity = %+v", identity)
	}
	if raw, _ := os.ReadFile(file); strings.TrimSpace(string(raw)) != "from-file" {
		t.Fatalf("explicit identity rewrote the file: %q", raw)
	}
}

// TestResolveReadsPersistedFile proves the file is authoritative after creation. |
// TestResolveReadsPersistedFile 证明文件创建后即为权威来源。
func TestResolveReadsPersistedFile(t *testing.T) {
	fixedEnvironment(t, EnvironmentPhysical)
	fixedSeed(t, SourceMachineID, "seed", true)
	file := filepath.Join(t.TempDir(), "node-id")
	if err := os.WriteFile(file, []byte("persisted-node\n"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	identity, err := Resolve(context.Background(), Options{File: file, Create: true})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if identity.ID != "persisted-node" || identity.Source != SourceFile || !identity.Stable {
		t.Fatalf("identity = %+v", identity)
	}
}

// TestResolveCreatesAndReuses proves first boot derives and persists, and the
// next boot reads the same id instead of re-deriving. | TestResolveCreatesAndReuses
// 证明首次启动推导并持久化，下次启动读取同一 id 而不是重新推导。
func TestResolveCreatesAndReuses(t *testing.T) {
	fixedEnvironment(t, EnvironmentPhysical)
	fixedSeed(t, SourceMachineID, "machine-1", true)
	file := filepath.Join(t.TempDir(), "nested", "node-id")

	first, err := Resolve(context.Background(), Options{File: file, Create: true})
	if err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	if first.Source != SourceMachineID || !strings.HasPrefix(first.ID, idPrefix) {
		t.Fatalf("first identity = %+v", first)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if strings.TrimSpace(string(raw)) != first.ID {
		t.Fatalf("file = %q, want %q", raw, first.ID)
	}

	second, err := Resolve(context.Background(), Options{File: file, Create: true})
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if second.ID != first.ID || second.Source != SourceFile {
		t.Fatalf("second identity = %+v, want id %q from file", second, first.ID)
	}
}

// TestResolveCorruptFile proves a damaged file is reported, never silently
// replaced. | TestResolveCorruptFile 证明损坏文件会被报告，绝不会被静默替换。
func TestResolveCorruptFile(t *testing.T) {
	fixedEnvironment(t, EnvironmentPhysical)
	cases := map[string]string{
		"empty":     "",
		"two lines": "a\nb\n",
		"bad char":  "node id",
		"too long":  strings.Repeat("a", MaxIDLength+1) + "\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "node-id")
			if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
				t.Fatalf("write file: %v", err)
			}
			_, err := Resolve(context.Background(), Options{File: file, Create: true})
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Resolve error = %v, want ErrCorrupt", err)
			}
			if raw, _ := os.ReadFile(file); string(raw) != content {
				t.Fatalf("corrupt file was modified: %q", raw)
			}
		})
	}
}

// TestResolveNoCreate proves read-only resolution does not invent a file. |
// TestResolveNoCreate 证明只读解析不会凭空创建文件。
func TestResolveNoCreate(t *testing.T) {
	fixedEnvironment(t, EnvironmentPhysical)
	file := filepath.Join(t.TempDir(), "node-id")
	if _, err := Resolve(context.Background(), Options{File: file}); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("Resolve error = %v, want ErrNoIdentity", err)
	}
	if _, err := os.Stat(file); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("identity file was created: %v", err)
	}
}

// TestResolveRequiresDurableStorage proves RequirePersistent rejects a file on
// the temporary filesystem, even when it could be written. | TestResolveRequiresDurableStorage
// 证明 RequirePersistent 会拒绝临时文件系统上的身份文件，即使写入本身可行。
func TestResolveRequiresDurableStorage(t *testing.T) {
	fixedEnvironment(t, EnvironmentPhysical)
	fixedSeed(t, SourceMachineID, "seed", true)
	file := filepath.Join(t.TempDir(), "node-id")
	if IsDurable(file) {
		t.Skipf("test temp directory is classified as durable: %s", file)
	}
	if _, err := Resolve(context.Background(), Options{File: file, Create: true, RequirePersistent: true}); !errors.Is(err, ErrNeedsProvisioning) {
		t.Fatalf("Resolve error = %v, want ErrNeedsProvisioning", err)
	}
	if _, err := os.Stat(file); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("rejected identity still wrote a file: %v", err)
	}
}

// TestResolveUsesClaimer proves a claimer can reject a cloned identity. |
// TestResolveUsesClaimer 证明 Claimer 可以拒绝克隆的身份。
func TestResolveUsesClaimer(t *testing.T) {
	fixedEnvironment(t, EnvironmentPhysical)
	claimer := &recordingClaimer{err: ErrDuplicate}
	_, err := Resolve(context.Background(), Options{ConfigID: "node-a", Claimer: claimer, Instance: "instance-1"})
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("Resolve error = %v, want ErrDuplicate", err)
	}
	if claimer.id != "node-a" || claimer.instance != "instance-1" {
		t.Fatalf("claim = (%q, %q)", claimer.id, claimer.instance)
	}

	ok := &recordingClaimer{}
	identity, err := Resolve(context.Background(), Options{ConfigID: "node-b", Claimer: ok})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if identity.Instance == "" || ok.instance != identity.Instance {
		t.Fatalf("identity instance = %q, claim instance = %q", identity.Instance, ok.instance)
	}
}

// TestResolveConcurrentCreation proves racing processes converge on one id. |
// TestResolveConcurrentCreation 证明竞争的进程最终收敛到同一个 id。
func TestResolveConcurrentCreation(t *testing.T) {
	fixedEnvironment(t, EnvironmentPhysical)
	fixedSeed(t, SourceMachineID, "seed", true)
	file := filepath.Join(t.TempDir(), "node-id")

	const workers = 8
	ids := make(chan string, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			identity, err := Resolve(context.Background(), Options{File: file, Create: true})
			if err != nil {
				errs <- err
				return
			}
			ids <- identity.ID
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		t.Fatalf("Resolve: %v", err)
	}
	var first string
	for id := range ids {
		if first == "" {
			first = id
			continue
		}
		if id != first {
			t.Fatalf("racing resolves returned %q and %q", first, id)
		}
	}
	if first == "" {
		t.Fatal("no identity resolved | 没有解析出身份")
	}
}

// TestClassifyEnvironment pins the environment decision table. | TestClassifyEnvironment
// 固定环境判定表。
func TestClassifyEnvironment(t *testing.T) {
	cases := []struct {
		name  string
		facts environmentFacts
		want  Environment
	}{
		{"kubernetes wins | Kubernetes 优先", environmentFacts{Kubernetes: true, ContainerMarker: true}, EnvironmentKubernetes},
		{"marker | 标记文件", environmentFacts{ContainerMarker: true}, EnvironmentContainer},
		{"container env | 容器环境变量", environmentFacts{ContainerEnv: "docker"}, EnvironmentContainer},
		{"cgroup | cgroup", environmentFacts{Cgroup: "12:devices:/docker/abc"}, EnvironmentContainer},
		{"vm | 虚机", environmentFacts{Vendor: "QEMU", Product: "Standard PC"}, EnvironmentVirtual},
		{"physical | 物理机", environmentFacts{Vendor: "Dell Inc.", Product: "PowerEdge"}, EnvironmentPhysical},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyEnvironment(tc.facts); got != tc.want {
				t.Fatalf("classify = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestHostSeedAllowed pins the container seed policy. | TestHostSeedAllowed 固定容器种子策略。
func TestHostSeedAllowed(t *testing.T) {
	if hostSeedAllowed(EnvironmentContainer, false) || hostSeedAllowed(EnvironmentKubernetes, false) {
		t.Fatal("containers must not use host seeds by default | 容器默认不得使用宿主种子")
	}
	if !hostSeedAllowed(EnvironmentContainer, true) || !hostSeedAllowed(EnvironmentVirtual, false) {
		t.Fatal("allowShared or non-container environments must permit the seed | allowShared 或非容器环境必须允许种子")
	}
}

// TestDefaultFileHonoursEnvironment proves the file path can be overridden
// without config. | TestDefaultFileHonoursEnvironment 证明无需配置即可覆盖文件路径。
func TestDefaultFileHonoursEnvironment(t *testing.T) {
	want := filepath.Join(t.TempDir(), "custom-node-id")
	t.Setenv(FileEnv, want)
	got, err := DefaultFile()
	if err != nil {
		t.Fatalf("DefaultFile: %v", err)
	}
	if got != want {
		t.Fatalf("DefaultFile = %q, want %q", got, want)
	}
}

// TestEphemeralIdsAreUnique proves the fallback and instance ids never collide
// in a short run. | TestEphemeralIdsAreUnique 证明兜底与实例 id 在短时间运行中不会碰撞。
func TestEphemeralIdsAreUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		identity := Ephemeral()
		if !strings.HasPrefix(identity.ID, idPrefix) || identity.Stable || identity.Persistent {
			t.Fatalf("ephemeral identity = %+v", identity)
		}
		if seen[identity.ID] {
			t.Fatalf("duplicate ephemeral id %q", identity.ID)
		}
		seen[identity.ID] = true
		instance := InstanceID()
		if !strings.HasPrefix(instance, instancePrefix) || seen[instance] {
			t.Fatalf("instance id = %q", instance)
		}
		seen[instance] = true
	}
}

// recordingClaimer records the claim and returns a fixed error. | recordingClaimer 记录
// Claim 并返回固定错误。
type recordingClaimer struct {
	id       string
	instance string
	err      error
}

func (c *recordingClaimer) Claim(_ context.Context, id, instance string) error {
	c.id, c.instance = id, instance
	return c.err
}
