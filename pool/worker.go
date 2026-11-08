package pool

import (
	"context"
	"runtime"
)

// take removes one job from the home ring or the fallback ring. | take 从 home 环或
// fallback 环取出一个作业。
func (e *engine[J]) take(home uint64) (J, bool) {
	if j, ok := e.shards[home].tryDequeue(); ok {
		return j, true
	}
	if j, ok := e.fallback.tryDequeue(); ok {
		return j, true
	}
	var zero J
	return zero, false
}

// steal removes one job from another shard. | steal 从其它分片取出一个作业。
func (e *engine[J]) steal(home uint64) (J, bool) {
	n := uint64(len(e.shards))
	for i := uint64(1); i < n; i++ {
		idx := (home + i) & e.shardMask
		if j, ok := e.shards[idx].tryDequeue(); ok {
			return j, true
		}
	}
	var zero J
	return zero, false
}

// findAny attempts the home/fallback rings and then every other shard. | findAny 先尝试
// home/fallback 环，再尝试所有其它分片。
func (e *engine[J]) findAny(home uint64) (J, bool) {
	if j, ok := e.take(home); ok {
		return j, true
	}
	return e.steal(home)
}

// process runs one job and marks it finished. | process 执行一个作业并标记完成。
func (e *engine[J]) process(w *workerState, j J) {
	w.running.Store(true)
	e.run(w, j)
	w.running.Store(false)
	e.completed(w)
}

// consumeHandoff handles a job delivered directly to an idle worker. | consumeHandoff
// 处理直接交给空闲 worker 的作业。
func (e *engine[J]) consumeHandoff(w *workerState, j J) {
	e.spaceSignal()
	if e.closed.Load() {
		if e.graceful.Load() {
			e.process(w, j)
			return
		}
		e.discard(j)
		e.discardedN.Add(1)
		e.pendingDone()
		return
	}
	e.process(w, j)
}

// work is the worker loop. | work 是 worker 主循环。
func (e *engine[J]) work(w *workerState, home uint64) {
	defer func() {
		e.mu.Lock()
		e.removeWorkerLocked(w)
		e.mu.Unlock()
		e.wg.Done()
	}()

	spins := 0
	for {
		if e.closed.Load() {
			e.finishClosed(w, home)
			return
		}
		if len(e.handoff) > 0 {
			select {
			case j := <-e.handoff:
				e.consumeHandoff(w, j)
				spins = 0
				continue
			default:
			}
		}
		if j, ok := e.take(home); ok {
			e.spaceSignal()
			e.process(w, j)
			spins = 0
			continue
		}
		if spins < e.cfg.spinCount {
			spins++
			if spins&15 == 0 {
				runtime.Gosched()
			}
			continue
		}
		if j, ok := e.steal(home); ok {
			e.spaceSignal()
			e.process(w, j)
			spins = 0
			continue
		}
		if e.park(w, home) {
			return
		}
		spins = 0
	}
}

// handleClosedJob runs or discards one job dequeued after close. | handleClosedJob
// 在关闭后执行或丢弃一个出队作业。
func (e *engine[J]) handleClosedJob(w *workerState, j J, graceful bool) {
	e.spaceSignal()
	if graceful {
		e.process(w, j)
		return
	}
	e.discard(j)
	e.discardedN.Add(1)
	e.pendingDone()
}

// drainClosed empties the handoff channel and every ring. | drainClosed 清空 handoff
// 通道与所有环。
func (e *engine[J]) drainClosed(w *workerState, home uint64, graceful bool) {
	for {
		select {
		case j := <-e.handoff:
			e.handleClosedJob(w, j, graceful)
			continue
		default:
		}
		j, ok := e.findAny(home)
		if !ok {
			return
		}
		e.handleClosedJob(w, j, graceful)
	}
}

// finishClosed drains the queues after close, running or discarding according to mode.
// Workers stay available until submissions are sealed, so a submitter that was
// admitted just before close can still publish its job to a worker. | finishClosed
// 在关闭后排空队列，按关闭模式执行或丢弃。worker 会一直可用到提交封闭，因此刚好在关闭
// 前获准的提交仍能把作业发布给 worker。
func (e *engine[J]) finishClosed(w *workerState, home uint64) {
	graceful := e.graceful.Load()
	for {
		e.drainClosed(w, home, graceful)
		// Publish accumulated completions before deciding whether the drain is
		// finished: the pending-zero transition is what seals the queues. | 在判断
		// 排空是否结束前发布累计完成数：封闭队列依赖 pending 归零的转换。
		e.flushLocalDone(w)
		if e.submissionsSealed() {
			// No submission can publish after the seal. Drain once more to catch
			// work published before it but missed by the scan above, then exit.
			// | 封闭后不再有提交能发布作业。再排空一次以捕获封闭前发布但未被上面的扫描
			// 看到的作业，然后退出。
			e.drainClosed(w, home, graceful)
			return
		}
		// Register as sleeping before rechecking so a concurrent publish either
		// becomes visible to the scan below or leaves a wake token. | 先登记休眠再复查，
		// 使并发发布要么被下面的扫描看到，要么留下唤醒令牌。
		e.sleepers.Add(1)
		select {
		case j := <-e.handoff:
			e.sleepers.Add(-1)
			e.handleClosedJob(w, j, graceful)
			continue
		default:
		}
		if j, ok := e.findAny(home); ok {
			e.sleepers.Add(-1)
			e.handleClosedJob(w, j, graceful)
			continue
		}
		if e.submissionsSealed() {
			e.sleepers.Add(-1)
			continue
		}
		select {
		case j := <-e.handoff:
			e.sleepers.Add(-1)
			e.handleClosedJob(w, j, graceful)
		case <-e.wake:
			e.sleepers.Add(-1)
		case <-e.sealCh:
			e.sleepers.Add(-1)
		}
	}
}

// park registers as sleeping, rechecks for work, and waits for a signal. | park 登记为
// 休眠、重新检查工作并等待信号。
func (e *engine[J]) park(w *workerState, home uint64) bool {
	defer e.flushLocalDone(w)
	e.mu.Lock()
	if len(e.workers) > e.target {
		e.removeWorkerLocked(w)
		e.mu.Unlock()
		return true
	}
	e.mu.Unlock()

	e.sleepers.Add(1)
	e.flushLocalDone(w)
	if j, ok := e.findAny(home); ok {
		e.sleepers.Add(-1)
		e.spaceSignal()
		e.process(w, j)
		return false
	}
	select {
	case j := <-e.handoff:
		e.sleepers.Add(-1)
		e.consumeHandoff(w, j)
		return false
	case <-e.wake:
		e.sleepers.Add(-1)
		if e.closed.Load() {
			return false
		}
		if j, ok := e.findAny(home); ok {
			e.spaceSignal()
			e.process(w, j)
		}
		return false
	case <-e.stop:
		e.sleepers.Add(-1)
		return false
	}
}

// removeWorkerLocked removes w from the live set and folds its counters into the
// engine totals. It is idempotent. | removeWorkerLocked 把 w 移出存活集合并把其计数并入
// 引擎总计；它是幂等的。
func (e *engine[J]) removeWorkerLocked(w *workerState) {
	if w.retired.Swap(true) {
		return
	}
	e.flushLocalDone(w)
	if n := w.processed.Load(); n > 0 {
		e.totalProcessed.Add(n)
	}
	if n := w.failed.Load(); n > 0 {
		e.totalFailed.Add(n)
	}
	if n := w.panicked.Load(); n > 0 {
		e.totalPanicked.Add(n)
	}
	for i, x := range e.workers {
		if x == w {
			e.workers = append(e.workers[:i], e.workers[i+1:]...)
			e.workerN.Add(-1)
			break
		}
	}
}

// resize changes the live worker count. Growth is immediate; shrink happens as
// workers next become idle. | resize 调整存活 worker 数。扩容立即生效，缩容在 worker
// 下次空闲时生效。
func (e *engine[J]) resize(n int) error {
	if n < 1 {
		n = 1
	}
	e.mu.Lock()
	if e.closing.Load() {
		e.mu.Unlock()
		return ErrPoolClosed
	}
	e.target = n
	for len(e.workers) < n {
		w := &workerState{id: e.nextID}
		e.nextID++
		e.workers = append(e.workers, w)
		e.workerN.Add(1)
		e.wg.Add(1)
		go e.work(w, uint64(w.id)&e.shardMask)
	}
	needWake := len(e.workers) > n
	e.mu.Unlock()
	if needWake {
		e.wakeAll()
	}
	return nil
}

// beginClose starts closing exactly once. The graceful flag is stored before the
// closed flag so workers observing closed also observe the correct mode. When no
// task or submission is pending the queues are sealed immediately; otherwise the
// transition to zero pending seals them, because a close then forbids any new
// publication. | beginClose 只启动一次关闭。graceful 在 closed 之前写入，使观察到
// closed 的 worker 也能观察到正确的模式。若没有待处理任务或在途提交，立即封闭队列；
// 否则由 pending 归零的转换封闭队列，因为此时关闭已禁止任何新的发布。
func (e *engine[J]) beginClose(graceful bool) {
	if !e.closing.CompareAndSwap(false, true) {
		return
	}
	e.graceful.Store(graceful)
	e.closed.Store(true)
	if e.pending.Load() == 0 {
		e.sealSubmissions()
	}
	e.stopOnce.Do(func() { close(e.stop) })
	e.spaceMu.Lock()
	e.spaceCond.Broadcast()
	e.spaceMu.Unlock()
}

// close stops the engine and waits for every worker to exit. | close 停止引擎并等待所有
// worker 退出。
func (e *engine[J]) close(graceful bool) {
	e.beginClose(graceful)
	<-e.done
	e.drainDiscard()
}

// shutdown stops the engine gracefully and waits for the drain or ctx expiry. |
// shutdown 优雅停止引擎，等待排空或 ctx 到期。
func (e *engine[J]) shutdown(ctx context.Context) error {
	e.beginClose(true)
	if ctx == nil {
		ctx = context.Background()
	}
	// Completion takes precedence when both done and ctx expiry are ready, so a
	// shutdown that already drained never reports a deadline error. | 当排空与 ctx
	// 到期同时就绪时优先报告完成，使已经排空的关闭不会误报超时。
	select {
	case <-e.done:
		e.drainDiscard()
		return nil
	default:
	}
	select {
	case <-e.done:
		e.drainDiscard()
		return nil
	case <-ctx.Done():
		select {
		case <-e.done:
			e.drainDiscard()
			return nil
		default:
		}
		return ctx.Err()
	}
}

// drainDiscard removes and discards any job left by a submission racing with close.
// | drainDiscard 清除并丢弃与关闭竞争而残留的作业。
func (e *engine[J]) drainDiscard() {
	for {
		select {
		case j := <-e.handoff:
			e.discard(j)
			e.discardedN.Add(1)
			e.pendingDone()
			continue
		default:
		}
		j, ok := e.findAny(0)
		if !ok {
			return
		}
		e.discard(j)
		e.discardedN.Add(1)
		e.pendingDone()
	}
}
