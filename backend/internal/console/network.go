package console

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type networkEntry struct {
	low, high             float64
	parts                 []string
	args                  []any
	params                url.Values
	access, updated, next time.Time
	value                 Object
	err                   string
	queued                bool
	generation            uint64
	bytes                 int64
}
type NetworkSnapshots struct {
	app     *App
	mu      sync.Mutex
	entries map[string]*networkEntry
	queue   chan string
	bytes   int64
	Version atomic.Uint64
}

func NewNetworkSnapshots(app *App) *NetworkSnapshots {
	return &NetworkSnapshots{app: app, entries: map[string]*networkEntry{}, queue: make(chan string, 8*WorkerCount())}
}
func emptyNetwork(value any) Object {
	r := Object{}
	for _, key := range strings.Fields("records flows dns tls addresses bytes bidirectional one_way newest source_count destination_count") {
		r[key] = value
	}
	for _, key := range strings.Fields("applications protocols dns_names tls_names sources event_types log_sources log_destinations") {
		r[key] = []Object{}
	}
	r["available"] = false
	r["status"] = "preparing"
	r["partial"] = true
	return r
}
func (n *NetworkSnapshots) Get(low, high float64, parts []string, args []any, params url.Values) Object {
	p := url.Values{}
	for k, v := range params {
		p[k] = append([]string{}, v...)
	}
	key := p.Encode()
	if params.Get("to") == "" && params.Get("from") == "" {
		key = "rolling:" + key
	} else {
		key = fmt.Sprintf("%g:%g:%s", low, high, key)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	entry := n.entries[key]
	if entry == nil || entry.generation != n.app.Store.Generation.Load() {
		if entry != nil {
			n.bytes -= entry.bytes
			delete(n.entries, key)
		}
		if len(n.entries) >= cap(n.queue) {
			var oldest string
			var stamp time.Time
			for k, v := range n.entries {
				if !v.queued && (oldest == "" || v.access.Before(stamp)) {
					oldest, stamp = k, v.access
				}
			}
			if oldest != "" {
				n.bytes -= n.entries[oldest].bytes
				delete(n.entries, oldest)
			} else {
				return Object{"status": "busy", "error": "网络统计任务已满，请稍后重试", "available": false}
			}
		}
		entry = &networkEntry{generation: n.app.Store.Generation.Load()}
		n.entries[key] = entry
	}
	entry.low, entry.high, entry.parts, entry.args, entry.params, entry.access = low, high, append([]string{}, parts...), append([]any{}, args...), p, time.Now()
	if !entry.queued && time.Now().After(entry.next) {
		select {
		case n.queue <- key:
			entry.queued = true
		default:
		}
	}
	if entry.value != nil {
		result := clone(entry.value)
		result["computed_at"] = float64(entry.updated.UnixNano()) / 1e9
		if entry.err != "" {
			result["status"] = "stale"
			result["error"] = entry.err
		}
		return result
	}
	r := emptyNetwork(nil)
	if entry.err != "" {
		r["status"] = "error"
		r["error"] = entry.err
	}
	return r
}
func (n *NetworkSnapshots) Invalidate() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.entries = map[string]*networkEntry{}
	n.bytes = 0
	n.Version.Add(1)
}
func (n *NetworkSnapshots) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.mu.Lock()
			for key, entry := range n.entries {
				if !entry.queued && time.Since(entry.access) < 60*time.Second && time.Now().After(entry.next) {
					select {
					case n.queue <- key:
						entry.queued = true
					default:
					}
				}
			}
			n.mu.Unlock()
		case key := <-n.queue:
			n.mu.Lock()
			entry := n.entries[key]
			if entry == nil {
				n.mu.Unlock()
				continue
			}
			low, high, parts, args, generation := entry.low, entry.high, append([]string{}, entry.parts...), append([]any{}, entry.args...), entry.generation
			n.mu.Unlock()
			start := time.Now()
			g, err := n.app.Store.Snapshot(ctx, false)
			var value Object
			if err == nil {
				value, err = networkSummary(ctx, g, low, high, parts, args)
				g.Close()
			}
			elapsed := time.Since(start)
			n.mu.Lock()
			if current := n.entries[key]; current == entry && generation == n.app.Store.Generation.Load() {
				entry.queued = false
				entry.next = time.Now().Add(max(30*time.Second, 3*elapsed))
				if err == nil {
					payload, e := json.Marshal(value)
					if e != nil || int64(len(payload)) > n.app.Config.PreloadBytes/8 {
						entry.err = "网络统计结果超过缓存预算"
					}
					if e == nil && int64(len(payload)) <= n.app.Config.PreloadBytes/8 {
						for n.bytes-entry.bytes+int64(len(payload)) > n.app.Config.PreloadBytes/8 {
							oldest := ""
							var stamp time.Time
							for candidate, v := range n.entries {
								if v != entry && !v.queued && v.bytes > 0 && (oldest == "" || v.access.Before(stamp)) {
									oldest, stamp = candidate, v.access
								}
							}
							if oldest == "" {
								break
							}
							n.bytes -= n.entries[oldest].bytes
							delete(n.entries, oldest)
						}
						if n.bytes-entry.bytes+int64(len(payload)) > n.app.Config.PreloadBytes/8 {
							entry.err = "网络统计缓存预算已满"
							n.mu.Unlock()
							continue
						}
						n.bytes += int64(len(payload)) - entry.bytes
						entry.bytes = int64(len(payload))
						entry.value = value
						entry.updated = time.Now()
						entry.err = ""
						n.Version.Add(1)
					}
				} else {
					entry.err = "网络统计刷新失败"
					entry.next = time.Now().Add(max(5*time.Second, 3*elapsed))
				}
			}
			n.mu.Unlock()
		}
	}
}

func (n *NetworkSnapshots) Health() (string, string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, entry := range n.entries {
		if time.Since(entry.access) < 60*time.Second && entry.err != "" {
			return "warning", entry.err
		}
	}
	return "ok", "后台统计正常"
}
