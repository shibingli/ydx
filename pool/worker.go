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

// finishClosed drains the queues after close, running or discarding according to mode.
// | finishClosed 在关闭后排空队列，按关闭模式执行或丢弃。
func (e *engine[J]) finishClosed(w *workerState, home uint64) {
	graceful := e.graceful.Load()
	for {
		select {
		case j := <-e.handoff:
			e.spaceSignal()
			if graceful {
				e.process(w, j)
			} else {
				e.discard(j)
				e.discardedN.Add(1)
				e.pendingDone()
			}
			continue
		default:
		}
		j, ok := e.findAny(home)
		if !ok {
			return
		}
		e.spaceSignal()
		if graceful {
			e.process(w, j)
			continue
		}
		e.discard(j)
		e.discardedN.Add(1)
		e.pendingDone()
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
// closed flag so workers observing closed also observe the correct mode. |
// beginClose 只启动一次关闭。graceful 在 closed 之前写入，使观察到 closed 的 worker 也能
// 观察到正确的模式。
func (e *engine[J]) beginClose(graceful bool) {
	if !e.closing.CompareAndSwap(false, true) {
		return
	}
	e.graceful.Store(graceful)
	e.closed.Store(true)
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
	select {
	case <-e.done:
		e.drainDiscard()
		return nil
	case <-ctx.Done():
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
