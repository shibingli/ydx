package raft

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	db "github.com/lni/dragonboat/v4"
	"github.com/lni/dragonboat/v4/client"
	dbconfig "github.com/lni/dragonboat/v4/config"
	"github.com/lni/dragonboat/v4/logger"
	dbsm "github.com/lni/dragonboat/v4/statemachine"
)

// quietLogger discards Dragonboat's lifecycle logging. | quietLogger 丢弃 Dragonboat
// 生命周期日志。
type quietLogger struct{}

// SetLevel implements logger.ILogger. | SetLevel 实现 logger.ILogger。
func (quietLogger) SetLevel(logger.LogLevel) {}

// Debugf implements logger.ILogger. | Debugf 实现 logger.ILogger。
func (quietLogger) Debugf(string, ...any) {}

// Infof implements logger.ILogger. | Infof 实现 logger.ILogger。
func (quietLogger) Infof(string, ...any) {}

// Warningf implements logger.ILogger. | Warningf 实现 logger.ILogger。
func (quietLogger) Warningf(string, ...any) {}

// Errorf implements logger.ILogger. | Errorf 实现 logger.ILogger。
func (quietLogger) Errorf(string, ...any) {}

// Panicf implements logger.ILogger. | Panicf 实现 logger.ILogger。
func (quietLogger) Panicf(string, ...any) {}

// init silences Dragonboat logging before any benchmark starts. | init 在基准开始前
// 静默 Dragonboat 日志。
func init() {
	logger.SetLoggerFactory(func(string) logger.ILogger { return quietLogger{} })
}

// dbFSM is a zero-cost Dragonboat state machine. | dbFSM 是零成本 Dragonboat
// 状态机。
type dbFSM struct{}

// Update implements dbsm.IStateMachine. | Update 实现 dbsm.IStateMachine。
func (*dbFSM) Update(dbsm.Entry) (dbsm.Result, error) { return dbsm.Result{}, nil }

// Lookup implements dbsm.IStateMachine. | Lookup 实现 dbsm.IStateMachine。
func (*dbFSM) Lookup(any) (any, error) { return nil, nil }

// SaveSnapshot implements dbsm.IStateMachine. | SaveSnapshot 实现 dbsm.IStateMachine。
func (*dbFSM) SaveSnapshot(io.Writer, dbsm.ISnapshotFileCollection, <-chan struct{}) error {
	return nil
}

// RecoverFromSnapshot implements dbsm.IStateMachine. | RecoverFromSnapshot 实现
// dbsm.IStateMachine。
func (*dbFSM) RecoverFromSnapshot(io.Reader, []dbsm.SnapshotFile, <-chan struct{}) error {
	return nil
}

// Close implements dbsm.IStateMachine. | Close 实现 dbsm.IStateMachine。
func (*dbFSM) Close() error { return nil }

// dbCluster is an in-process Dragonboat v4 cluster. | dbCluster 是进程内
// Dragonboat v4 集群。
type dbCluster struct {
	hosts []*db.NodeHost
}

// reserveTCPAddr reserves a loopback TCP port and releases it for Dragonboat.
// | reserveTCPAddr 预留一个回环 TCP 端口后释放给 Dragonboat。
func reserveTCPAddr(tb testing.TB) string {
	tb.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("reserve port: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		tb.Fatalf("release port: %v", err)
	}
	return addr
}

// newDBCluster starts size Dragonboat NodeHosts with one shard. | newDBCluster
// 启动 size 个 Dragonboat NodeHost 与一个分片。
func newDBCluster(b *testing.B, size int) (*dbCluster, *db.NodeHost) {
	b.Helper()
	dir := b.TempDir()
	addrs := make([]string, size)
	for i := range addrs {
		addrs[i] = reserveTCPAddr(b)
	}
	members := make(map[uint64]db.Target, size)
	for i := range addrs {
		members[uint64(i+1)] = addrs[i]
	}
	c := &dbCluster{hosts: make([]*db.NodeHost, size)}
	for i := 0; i < size; i++ {
		cfg := dbconfig.NodeHostConfig{
			NodeHostID:     fmt.Sprintf("00000000-0000-0000-0000-%012d", i+1),
			RaftAddress:    addrs[i],
			ListenAddress:  addrs[i],
			NodeHostDir:    fmt.Sprintf("%s/nh-%d", dir, i+1),
			RTTMillisecond: 5,
			Expert:         dbconfig.GetDefaultExpertConfig(),
		}
		nh, err := db.NewNodeHost(cfg)
		if err != nil {
			c.close()
			b.Fatalf("dragonboat nodehost %d: %v", i+1, err)
		}
		c.hosts[i] = nh
		cc := dbconfig.Config{
			ReplicaID:       uint64(i + 1),
			ShardID:         1,
			CheckQuorum:     true,
			PreVote:         true,
			ElectionRTT:     10,
			HeartbeatRTT:    2,
			SnapshotEntries: 1 << 30,
			MaxInMemLogSize: 256 << 20,
		}
		if err := nh.StartReplica(members, false, func(uint64, uint64) dbsm.IStateMachine {
			return &dbFSM{}
		}, cc); err != nil {
			c.close()
			b.Fatalf("dragonboat start replica %d: %v", i+1, err)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var leader *db.NodeHost
		count := 0
		for i, nh := range c.hosts {
			id, _, ok, err := nh.GetLeaderID(1)
			if err == nil && ok && id == uint64(i+1) {
				leader = nh
				count++
			}
		}
		if count == 1 {
			return c, leader
		}
		time.Sleep(10 * time.Millisecond)
	}
	c.close()
	b.Fatal("dragonboat leader not elected")
	return nil, nil
}

// close shuts down every NodeHost. | close 关闭所有 NodeHost。
func (c *dbCluster) close() {
	for _, nh := range c.hosts {
		if nh != nil {
			nh.Close()
		}
	}
}

// dbProposer implements proposer. | dbProposer 实现 proposer。
type dbProposer struct {
	nh      *db.NodeHost
	session *client.Session
	seq     atomic.Uint64
}

// propose implements proposer. | propose 实现 proposer。
func (p *dbProposer) propose(ctx context.Context, size int) error {
	_, err := p.nh.SyncPropose(ctx, p.session, payload(p.seq.Add(1), size))
	return err
}

// newDBProposer builds a no-op-session proposer for the leader host. | newDBProposer
// 为领导者主机构建无会话提案器。
func newDBProposer(nh *db.NodeHost) *dbProposer {
	return &dbProposer{nh: nh, session: nh.GetNoOPSession(1)}
}

// BenchmarkDragonboatSingleNodePropose measures Dragonboat's single-node path.
// | BenchmarkDragonboatSingleNodePropose 测量 Dragonboat 单节点路径。
func BenchmarkDragonboatSingleNodePropose(b *testing.B) {
	b.StopTimer()
	c, leader := newDBCluster(b, 1)
	defer c.close()
	b.StartTimer()
	runSequential(b, newDBProposer(leader))
	b.StopTimer()
}

// BenchmarkDragonboatSingleNodeParallel measures Dragonboat single-node parallel
// proposals. | BenchmarkDragonboatSingleNodeParallel 测量 Dragonboat 单节点并行
// 提案。
func BenchmarkDragonboatSingleNodeParallel(b *testing.B) {
	b.StopTimer()
	c, leader := newDBCluster(b, 1)
	defer c.close()
	b.StartTimer()
	runParallel(b, newDBProposer(leader))
	b.StopTimer()
}

// BenchmarkDragonboatThreeNodePropose measures Dragonboat three-node replication.
// | BenchmarkDragonboatThreeNodePropose 测量 Dragonboat 三节点复制。
func BenchmarkDragonboatThreeNodePropose(b *testing.B) {
	b.StopTimer()
	c, leader := newDBCluster(b, 3)
	defer c.close()
	b.StartTimer()
	runSequential(b, newDBProposer(leader))
	b.StopTimer()
}

// BenchmarkDragonboatThreeNodeParallel measures Dragonboat three-node parallel
// replication. | BenchmarkDragonboatThreeNodeParallel 测量 Dragonboat 三节点并行
// 复制。
func BenchmarkDragonboatThreeNodeParallel(b *testing.B) {
	b.StopTimer()
	c, leader := newDBCluster(b, 3)
	defer c.close()
	b.StartTimer()
	runParallel(b, newDBProposer(leader))
	b.StopTimer()
}
