package console

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"sync"
	"time"
)

type overviewEntry struct {
	params                                  url.Values
	value                                   []byte
	changed                                 chan struct{}
	access, updated, next                   time.Time
	revision, recentVersion, networkVersion uint64
	refreshing                              bool
	waiters                                 int
	err                                     error
}

// One coalescing scheduler owns the bounded pending set. Completed JSON is
// immutable and can be served without a SQL slot or the resident database lock.
type OverviewSnapshots struct {
	app                      *App
	mu                       sync.Mutex
	entries                  map[string]*overviewEntry
	wake                     chan struct{}
	generation, epoch        uint64
	bytes                    int64
	limit                    int
	budget                   int64
	current                  context.CancelFunc
	builds, hits             uint64
	refreshAfter, retryAfter time.Duration
	costRatio                int
	compute                  func(context.Context, url.Values) (Object, error)
}

func defaultOverviewParams() url.Values { return url.Values{"scope": {"cache"}, "view": {"panel"}} }

func NewOverviewSnapshots(app *App) *OverviewSnapshots {
	n := &OverviewSnapshots{app: app, entries: map[string]*overviewEntry{}, wake: make(chan struct{}, 1), limit: 8 * WorkerCount(), budget: max(64<<10, app.Config.PreloadBytes/8), refreshAfter: 2 * time.Second, retryAfter: 5 * time.Second, costRatio: 3}
	n.compute = func(ctx context.Context, params url.Values) (Object, error) {
		return app.execute(context.WithValue(ctx, overviewParallelKey{}, true), "overview", params)
	}
	n.resetLocked()
	return n
}

func copyValues(params url.Values) url.Values {
	copy := url.Values{}
	for key, values := range params {
		copy[key] = append([]string(nil), values...)
	}
	return copy
}

func (n *OverviewSnapshots) signal() {
	select {
	case n.wake <- struct{}{}:
	default:
	}
}

func (n *OverviewSnapshots) notify(e *overviewEntry) {
	close(e.changed)
	e.changed = make(chan struct{})
}

func (n *OverviewSnapshots) resetLocked() {
	if n.current != nil {
		n.current()
		n.current = nil
	}
	for _, entry := range n.entries {
		n.notify(entry)
	}
	n.entries = map[string]*overviewEntry{}
	n.bytes = 0
	n.generation = n.app.Store.Generation.Load()
	n.epoch++
	p := defaultOverviewParams()
	n.entries[p.Encode()] = &overviewEntry{params: p, changed: make(chan struct{}), access: time.Now()}
}

func (n *OverviewSnapshots) Invalidate() {
	n.mu.Lock()
	n.resetLocked()
	n.mu.Unlock()
	n.signal()
}

func (n *OverviewSnapshots) evictLocked(except *overviewEntry) bool {
	var oldest string
	found := false
	var stamp time.Time
	for key, entry := range n.entries {
		if entry == except || entry.refreshing || entry.waiters != 0 || key == defaultOverviewParams().Encode() {
			continue
		}
		if !found || entry.access.Before(stamp) {
			oldest, stamp, found = key, entry.access, true
		}
	}
	if !found {
		return false
	}
	n.bytes -= int64(len(n.entries[oldest].value))
	n.notify(n.entries[oldest])
	delete(n.entries, oldest)
	return true
}

func (n *OverviewSnapshots) Read(ctx context.Context, params url.Values) (Object, error) {
	key := params.Encode()
	if len(key) > 16<<10 {
		return nil, errors.New("概览查询参数过长")
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n.mu.Lock()
		if n.generation != n.app.Store.Generation.Load() {
			n.resetLocked()
		}
		entry := n.entries[key]
		if entry == nil {
			for len(n.entries) >= n.limit {
				if !n.evictLocked(nil) {
					n.mu.Unlock()
					return nil, errors.New("概览统计任务已满，请稍后重试")
				}
			}
			entry = &overviewEntry{params: copyValues(params), changed: make(chan struct{})}
			n.entries[key] = entry
		}
		entry.access = time.Now()
		if len(entry.value) > 0 {
			data, updated, failure, refreshing, generation, epoch := entry.value, entry.updated, entry.err, entry.refreshing, n.generation, n.epoch
			n.hits++
			n.mu.Unlock()
			n.signal()
			var result Object
			if err := decode(data, &result); err != nil {
				return nil, err
			}
			delete(result, "read_state")
			delete(result, "error")
			if result["source"] == "memory" {
				if state := n.app.Recent.ReadState(); state != nil {
					result["read_state"] = state
				}
			}
			if failure != nil {
				result["read_state"] = Object{"status": "stale", "as_of": float64(updated.UnixNano()) / 1e9, "error": "概览统计刷新失败"}
			}
			for k, value := range n.app.Runtime(ctx) {
				result[k] = value
			}
			result["overview_state"] = Object{"as_of": float64(updated.UnixNano()) / 1e9, "updating": refreshing}
			result["ingest_lag_bytes"] = n.app.Store.Lag()
			if message := n.app.Store.Error(); message != "" {
				result["error"] = message
			}
			n.mu.Lock()
			valid := generation == n.app.Store.Generation.Load() && epoch == n.epoch
			n.mu.Unlock()
			if valid {
				return result, nil
			}
			continue
		}
		if entry.err != nil && !entry.refreshing && time.Now().Before(entry.next) {
			err := entry.err
			n.mu.Unlock()
			return nil, err
		}
		changed := entry.changed
		entry.waiters++
		n.mu.Unlock()
		n.signal()
		select {
		case <-ctx.Done():
		case <-n.app.ctx.Done():
		case <-changed:
		}
		n.mu.Lock()
		entry.waiters--
		n.mu.Unlock()
		if n.app.ctx.Err() != nil {
			return nil, n.app.ctx.Err()
		}
	}
}

func (n *OverviewSnapshots) nextJob() (string, *overviewEntry, uint64, uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.generation != n.app.Store.Generation.Load() {
		n.resetLocked()
	}
	now := time.Now()
	key := ""
	var selected *overviewEntry
	for candidate, entry := range n.entries {
		if entry.refreshing || now.Before(entry.next) {
			continue
		}
		if candidate != defaultOverviewParams().Encode() && now.Sub(entry.access) > time.Minute && entry.waiters == 0 {
			continue
		}
		resident := entry.params.Get("scope") == "cache" && entry.params.Get("from") == "" && entry.params.Get("to") == "" && entry.params.Get("all") != "1"
		if resident && !n.app.Recent.Ready() && n.app.Recent.Error() == "" {
			continue
		}
		if len(entry.value) > 0 && entry.err == nil && entry.revision == n.app.Store.Revision.Load() && entry.recentVersion == n.app.Recent.Version.Load() && entry.networkVersion == n.app.Network.Version.Load() && now.Sub(entry.updated) < 30*time.Second {
			continue
		}
		if selected == nil || (entry.waiters > 0 && selected.waiters == 0) || ((entry.waiters > 0) == (selected.waiters > 0) && entry.next.Before(selected.next)) {
			selected, key = entry, candidate
		}
	}
	if selected != nil {
		selected.refreshing = true
	}
	return key, selected, n.generation, n.epoch
}

func (n *OverviewSnapshots) refresh(ctx context.Context, key string, entry *overviewEntry, generation, epoch uint64) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	n.mu.Lock()
	if n.entries[key] != entry || generation != n.generation || epoch != n.epoch {
		n.mu.Unlock()
		return
	}
	n.current = cancel
	n.mu.Unlock()
	started := time.Now()
	revision, version, networkVersion := n.app.Store.Revision.Load(), n.app.Recent.Version.Load(), n.app.Network.Version.Load()
	value, err := n.compute(ctx, entry.params)
	var payload []byte
	if err == nil {
		payload, err = json.Marshal(value)
	}
	if err == nil && int64(len(payload)) > n.budget {
		err = errors.New("概览结果超过缓存预算")
	}
	elapsed := time.Since(started)
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.entries[key] != entry || generation != n.app.Store.Generation.Load() || epoch != n.epoch {
		return
	}
	n.current = nil
	entry.refreshing = false
	n.builds++
	entry.err = err
	entry.next = time.Now().Add(max(n.refreshAfter, time.Duration(n.costRatio)*elapsed))
	if err != nil {
		entry.next = time.Now().Add(max(n.retryAfter, time.Duration(n.costRatio)*elapsed))
	} else {
		for n.bytes-int64(len(entry.value))+int64(len(payload)) > n.budget {
			if !n.evictLocked(entry) {
				entry.err = errors.New("概览快照缓存预算已满")
				break
			}
		}
		if entry.err == nil {
			n.bytes += int64(len(payload)) - int64(len(entry.value))
			entry.value, entry.updated, entry.revision, entry.recentVersion, entry.networkVersion = payload, time.Now(), revision, version, networkVersion
		}
	}
	if entry.err != nil {
		entry.next = time.Now().Add(max(n.retryAfter, time.Duration(n.costRatio)*elapsed))
	}
	n.notify(entry)
}

func (n *OverviewSnapshots) Run(ctx context.Context) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		key, entry, generation, epoch := n.nextJob()
		if entry != nil {
			n.refresh(ctx, key, entry, generation, epoch)
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-n.wake:
		case <-ticker.C:
		}
	}
}

func (n *OverviewSnapshots) Status() Object {
	n.mu.Lock()
	defer n.mu.Unlock()
	ready, updating := false, false
	for key, entry := range n.entries {
		updating = updating || entry.refreshing
		if key == defaultOverviewParams().Encode() {
			ready = len(entry.value) > 0 && n.generation == n.app.Store.Generation.Load()
		}
	}
	return Object{"ready": ready, "updating": updating, "entries": len(n.entries), "bytes": n.bytes, "builds": int64(n.builds), "cache_hits": int64(n.hits), "parallel_reader_budget": WorkerCount(), "resident_image_enabled": n.app.Config.snapshotDir != ""}
}
