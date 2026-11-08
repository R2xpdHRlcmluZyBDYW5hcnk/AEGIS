package console

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strconv"
	"sync"
)

type work struct {
	ctx context.Context
	run func()
}
type Pool struct {
	jobs    chan work
	stop    chan struct{}
	wg      sync.WaitGroup
	once    sync.Once
	Workers int
}

func WorkerCount() int {
	n := min(4, runtime.GOMAXPROCS(0))
	if value, err := strconv.Atoi(os.Getenv("IPS_CPU_WORKERS")); err == nil && value > 0 {
		n = min(n, value)
	}
	return max(1, n)
}
func NewPool(workers int) *Pool {
	workers = bounded(workers, 1, 4)
	p := &Pool{jobs: make(chan work, workers*2), stop: make(chan struct{}), Workers: workers}
	for range workers {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for {
				select {
				case <-p.stop:
					return
				case w := <-p.jobs:
					if w.ctx.Err() == nil {
						w.run()
					}
				}
			}
		}()
	}
	return p
}
func (p *Pool) Submit(ctx context.Context, run func()) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.stop:
		return errors.New("计算服务正在关闭")
	case p.jobs <- work{ctx, run}:
		return nil
	}
}
func (p *Pool) Close() { p.once.Do(func() { close(p.stop); p.wg.Wait() }) }

// Results retain source order. Callers never share mutable records across workers.
func parallelMap[T any, R any](ctx context.Context, p *Pool, source []T, fn func(T) (R, error)) ([]R, error) {
	type answer struct {
		value R
		err   error
	}
	pending := make([]chan answer, 0, p.Workers)
	out := make([]R, 0, len(source))
	next := 0
	for next < len(source) || len(pending) > 0 {
		for next < len(source) && len(pending) < p.Workers {
			item := source[next]
			ch := make(chan answer, 1)
			if err := p.Submit(ctx, func() { v, err := fn(item); ch <- answer{v, err} }); err != nil {
				return nil, err
			}
			pending = append(pending, ch)
			next++
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-p.stop:
			return nil, errors.New("计算服务正在关闭")
		case result := <-pending[0]:
			if result.err != nil {
				return nil, result.err
			}
			out = append(out, result.value)
			pending = pending[1:]
		}
	}
	return out, nil
}
