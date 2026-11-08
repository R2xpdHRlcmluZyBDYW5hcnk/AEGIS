package console

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type cachedResponse struct {
	value                []byte
	revision, generation uint64
	expires              time.Time
	access               time.Time
}
type App struct {
	Config                         Config
	Store                          *Store
	Pool                           *Pool
	Sessions                       *Sessions
	Started                        time.Time
	ctx                            context.Context
	cancel                         context.CancelFunc
	wg                             sync.WaitGroup
	panelSlots, logSlots, allSlots chan struct{}
	cacheMu                        sync.Mutex
	cache                          map[string]cachedResponse
	cacheBytes                     int64
	Network                        *NetworkSnapshots
	Recent                         *RecentEvents
	Overview                       *OverviewSnapshots
	Assistant                      *Assistant
	mutation                       sync.Mutex
	historySlot                    chan struct{}
}

func NewApp(parent context.Context, cfg Config) (*App, error) {
	ctx, cancel := context.WithCancel(parent)
	pool := NewPool(WorkerCount())
	store, err := NewStore(cfg.EventDB, cfg.Stream, pool)
	if err != nil {
		pool.Close()
		cancel()
		return nil, err
	}
	a := &App{Config: cfg, Store: store, Pool: pool, Sessions: NewSessions(cfg.SessionTTL), Started: time.Now(), ctx: ctx, cancel: cancel, panelSlots: make(chan struct{}, 1), logSlots: make(chan struct{}, max(1, cfg.ReadWorkers-1)), allSlots: make(chan struct{}, cfg.ReadWorkers), cache: map[string]cachedResponse{}}
	a.Network = NewNetworkSnapshots(a)
	a.historySlot = make(chan struct{}, 1)
	a.Recent, err = NewRecentEvents(a)
	if err != nil {
		store.Close()
		pool.Close()
		cancel()
		return nil, err
	}
	a.Assistant = NewAssistant(a)
	a.Overview = NewOverviewSnapshots(a)
	for _, run := range []func(context.Context){store.Run, a.Network.Run, a.Recent.Run, a.Overview.Run} {
		a.wg.Add(1)
		go func(run func(context.Context)) { defer a.wg.Done(); run(ctx) }(run)
	}
	return a, nil
}
func (a *App) Close() { a.cancel(); a.wg.Wait(); a.Recent.Close(); a.Store.Close(); a.Pool.Close() }
func (a *App) Health() Object {
	result := Object{"ok": true, "uptime": int64(time.Since(a.Started).Seconds()), "ingest_lag_bytes": a.Store.Lag(), "recent_ingest_lag_bytes": a.Store.RecentLag(), "recent_events_range": a.Recent.Range(), "event_db_ready": a.Store.Error() == "", "overview_ready": a.Recent.Ready(), "sqlite_version": sqliteVersion(a.ctx, a.Store.Readers), "backend": "go", "go_version": runtime.Version(), "cpu_workers": a.Pool.Workers}
	result["recent_events_error"] = a.Recent.Error()
	result["recent_events_diagnostics"] = a.Recent.Diagnostics()
	if a.Overview != nil {
		result["overview_snapshot"] = a.Overview.Status()
	}
	return result
}
func BuildInfo() Object {
	db, err := sql.Open("aegis-sqlite", ":memory:")
	version := ""
	if err == nil {
		version = sqliteVersion(context.Background(), db)
		db.Close()
	}
	return Object{"backend": "go", "go_version": runtime.Version(), "sqlite_version": version, "target": runtime.GOOS + "-" + runtime.GOARCH}
}
func (a *App) Read(ctx context.Context, name string, params url.Values) (Object, error) {
	if name == "overview" && a.Overview != nil && params.Get("format") != "csv" {
		return a.Overview.Read(ctx, params)
	}
	if name == "hunt" && params.Get("source") == "file" {
		select {
		case a.historySlot <- struct{}{}:
			defer func() { <-a.historySlot }()
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			return nil, errors.New("历史补查正在执行，请稍后重试")
		}
		return a.fileHistory(ctx, params)
	}
	var lane chan struct{} = a.logSlots
	if name == "overview" {
		lane = a.panelSlots
	}
	select {
	case lane <- struct{}{}:
		defer func() { <-lane }()
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-a.ctx.Done():
		return nil, errors.New("服务正在关闭")
	}
	select {
	case a.allSlots <- struct{}{}:
		defer func() { <-a.allSlots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	generation := a.Store.Generation.Load()
	revision := a.Store.Revision.Load()
	key := name + "?" + params.Encode()
	cacheable := params.Get("format") != "csv" && name != "record" && name != "incident" && name != "session_events" && params.Get("source") != "file" && params.Get("source") != "memory"
	if cacheable {
		a.cacheMu.Lock()
		cached, ok := a.cache[key]
		a.cacheMu.Unlock()
		if ok && cached.generation == generation && cached.revision == revision && time.Now().Before(cached.expires) {
			var result Object
			if decode(cached.value, &result) == nil {
				if name == "overview" {
					if state := a.Recent.ReadState(); state != nil {
						result["read_state"] = state
					}
				}
				result["ingest_lag_bytes"] = a.Store.Lag()
				if err := a.Store.Error(); err != "" {
					result["error"] = err
				}
				return result, nil
			}
		}
	}
	result, err := a.execute(ctx, name, params)
	if err != nil {
		return nil, err
	}
	if generation != a.Store.Generation.Load() {
		return nil, errors.New("历史数据已切换，请重新查询")
	}
	if name == "hunt" || name == "events" || name == "incidents" {
		result["ingest_lag_bytes"] = a.Store.Lag()
	}
	if writeError := a.Store.Error(); writeError != "" {
		result["error"] = writeError
	}
	if cacheable && object(result["read_state"])["status"] != "stale" {
		data, err := json.Marshal(result)
		if err == nil && int64(len(data)) <= a.Config.PreloadBytes/8 {
			a.cacheMu.Lock()
			if old, ok := a.cache[key]; ok {
				a.cacheBytes -= int64(len(old.value))
			}
			for len(a.cache) > 0 && (len(a.cache) >= 128 || a.cacheBytes+int64(len(data)) > a.Config.PreloadBytes/8) {
				var oldest string
				var stamp time.Time
				for k, v := range a.cache {
					if oldest == "" || v.access.Before(stamp) {
						oldest, stamp = k, v.access
					}
				}
				a.cacheBytes -= int64(len(a.cache[oldest].value))
				delete(a.cache, oldest)
			}
			a.cache[key] = cachedResponse{data, revision, generation, time.Now().Add(2 * time.Second), time.Now()}
			a.cacheBytes += int64(len(data))
			a.cacheMu.Unlock()
		}
	}
	return result, nil
}
func (a *App) execute(ctx context.Context, name string, params url.Values) (Object, error) {
	if name == "record" {
		return a.Store.Record(ctx, params.Get("key"))
	}
	low, high, err := rangeParams(params, 60, now())
	if name == "overview" {
		low, high, err = rangeParams(params, 1440, now())
	}
	if err != nil {
		return nil, err
	}
	if params.Get("all") == "1" {
		var lo, hi sql.NullFloat64
		if err = a.Store.Readers.QueryRowContext(ctx, "SELECT MIN(ts),MAX(ts) FROM events").Scan(&lo, &hi); err != nil {
			return nil, err
		}
		low, high = lo.Float64/1000, hi.Float64/1000
	}
	if name == "session_events" {
		id := params.Get("session_id")
		if !sessionValid(id) {
			return nil, errors.New("会话 ID 无效")
		}
		g, err := a.Store.Snapshot(ctx, true)
		if err != nil {
			return nil, err
		}
		defer g.Close()
		limit, err := intParam(params, "limit", 50, 1, 100)
		if err != nil {
			return nil, err
		}
		offset, err := intParam(params, "offset", 0, 0, math.MaxInt32)
		if err != nil {
			return nil, err
		}
		total, events, err := search(ctx, g, 0, now()+5, []string{"session_id=?"}, []any{id}, limit, offset, true, true, false)
		return Object{"session_id": id, "total": total, "events": events, "offset": offset, "limit": limit}, err
	}
	cacheScope := name == "overview" && params.Get("scope") == "cache" && params.Get("from") == "" && params.Get("to") == "" && params.Get("all") != "1"
	var g *Snapshot
	var release func()
	if name == "hunt" && params.Get("source") == "db" {
		g, err = a.Store.Snapshot(ctx, true)
		if g != nil {
			release = g.Close
		}
	} else if name == "hunt" && params.Get("source") == "memory" {
		var ok bool
		g, release, ok = a.Recent.Snapshot(ctx, low, high, true)
		if !ok {
			return Object{"total": 0, "events": []Object{}, "query": params.Get("q"), "source": "memory", "warming": true, "truncated": false}, nil
		}
	} else {
		if name == "overview" && ctx.Value(overviewParallelKey{}) == true && a.Config.snapshotDir != "" {
			if cacheScope {
				g, release, err = a.Recent.waitFrozenSnapshot(ctx)
			} else {
				var ok bool
				g, release, ok, err = a.Recent.frozenSnapshot(ctx, low, high, false)
				if err == nil && !ok {
					g, release, err = a.querySource(ctx, false, low, high)
				}
			}
		} else {
			g, release, err = a.querySource(ctx, cacheScope, low, high)
		}
	}
	if err != nil {
		return nil, err
	}
	defer release()
	switch name {
	case "hunt", "events":
		parts, args, err := eventFilter(params, name == "hunt")
		if err != nil {
			return nil, err
		}
		limit, err := intParam(params, "limit", 50, 1, 500)
		if params.Get("format") == "csv" {
			limit, err = intParam(params, "limit", 10000, 1, 10000)
		}
		if err != nil {
			return nil, err
		}
		offset, err := intParam(params, "offset", 0, 0, math.MaxInt32)
		if err != nil {
			return nil, err
		}
		total, events, err := search(ctx, g, low, high, parts, args, limit, offset, params.Get("view") == "list" && params.Get("format") != "csv", false, false)
		source := "db"
		if g.recent {
			source = "memory"
		}
		return Object{"total": total, "events": events, "query": params.Get("q"), "source": source, "range": []float64{low, high}, "truncated": false, "error": nil}, err
	case "incidents":
		return incidents(ctx, g, params, low, high, "", 3)
	case "incident":
		return incidentDetail(ctx, g, params, low, high)
	case "aggregate":
		parts, args, err := eventFilter(params, false)
		if err != nil {
			return nil, err
		}
		return securitySummary(ctx, g, low, high, parts, args, false, params.Get("type"), 8)
	case "overview":
		if a.Recent.Owns(g) && cacheScope {
			low, high = g.bounds[0], g.bounds[1]
		}
		parts, args, err := overviewFilter(params, low, high)
		if err != nil {
			return nil, err
		}
		minutes := max(1, int(math.Ceil((high-low)/60)))
		bucket := 1
		switch {
		case minutes <= 15:
			bucket = 1
		case minutes <= 60:
			bucket = 2
		case minutes <= 360:
			bucket = 15
		default:
			bucket = max(60, int(math.Ceil(float64(minutes)/720)))
		}
		security, recent, series, network, err := overviewSummary(ctx, g, low, high, bucket, parts, args)
		if err != nil {
			return nil, err
		}
		if !a.Recent.Owns(g) {
			network = a.Network.Get(low, high, parts, args, params)
		}
		runtimeData := a.Runtime(ctx)
		result := Object{"ts": now(), "source": "db", "series": series, "coverage": int64(max(0, now()-number(security["oldest"]))), "security": security, "network": network, "sensor": Object{"ingest_lag_bytes": a.Store.Lag(), "error": a.Store.Error(), "scope": "Snort 配置的采集范围", "limitations": "可见性取决于采集位置、双向流量和协议加密"}, "window": minutes, "range": []float64{low, high}, "bucket": bucket, "top": Object{"signatures": security["signatures"], "sources": network["log_sources"], "destinations": network["log_destinations"]}, "recent": recent, "events_total": a.Recent.Count()}
		if a.Recent.Owns(g) {
			result["events_total"] = g.count
			result["source"] = "memory"
			if state := a.Recent.ReadState(); state != nil {
				result["read_state"] = state
			}
		}
		for k, v := range runtimeData {
			result[k] = v
		}
		if params.Get("view") == "panel" {
			compact := Object{}
			for _, k := range strings.Fields("total alerts drops high sources_count destinations_count") {
				compact[k] = security[k]
			}
			result["security"] = compact
			delete(result, "coverage")
			delete(result, "sensor")
			delete(result, "events_total")
		}
		return result, nil
	}
	return nil, errors.New("未知查询类型")
}
func (a *App) querySource(ctx context.Context, cacheScope bool, low, high float64) (*Snapshot, func(), error) {
	if cacheScope {
		return a.Recent.WaitSnapshot(ctx)
	}
	if recent, release, ok := a.Recent.Snapshot(ctx, low, high, cacheScope); ok {
		return recent, release, nil
	}
	g, err := a.Store.Snapshot(ctx, true)
	if err != nil {
		return nil, nil, err
	}
	return g, g.Close, nil
}
func overviewFilter(params url.Values, low, high float64) ([]string, []any, error) {
	parts, args := []string{}, []any{}
	sessionFilter := func(predicate string, values []any) {
		parts = append(parts, "(session_id IN (SELECT session_id FROM events WHERE ts>=? AND ts<=? AND "+predicate+" AND COALESCE(session_id,'')!='') OR (COALESCE(session_id,'')='' AND "+predicate+"))")
		args = append(args, low*1000, high*1000)
		args = append(args, values...)
		args = append(args, values...)
	}
	for key, column := range map[string]string{"src": "src", "dst": "dst", "sig": "sig", "proto": "proto", "dns": "dnsname", "sni": "sni", "type": "type"} {
		value, present := params[key]
		missing := params.Get("missing_"+key) == "1"
		if !present && !missing {
			continue
		}
		s := ""
		if len(value) > 0 {
			s = value[0]
		}
		if len(s) > 1024 {
			return nil, nil, errors.New("概览筛选过长")
		}
		predicate := "COALESCE(" + column + ",'')=?"
		if key == "src" || key == "dst" || key == "proto" {
			if key == "proto" {
				predicate = "LOWER(COALESCE(proto,''))=?"
				s = strings.ToLower(s)
			}
			parts = append(parts, predicate)
			args = append(args, s)
		} else {
			sessionFilter(predicate, []any{s})
		}
	}
	if value, ok := params["app"]; ok || params.Get("missing_app") == "1" {
		app := ""
		if len(value) > 0 {
			app = strings.ToLower(value[0])
		}
		clause := `(session_id IN (SELECT session_id FROM (SELECT session_id,FIRST_VALUE(COALESCE(app,'')) OVER(PARTITION BY session_id ORDER BY (app NOT IN ('','unknown','failed')) DESC,(COALESCE(app,'')!='') DESC,(type='session') DESC,ts DESC,id DESC) name FROM events WHERE ts>=? AND ts<=? AND COALESCE(session_id,'')!='') WHERE LOWER(name)=?) OR (COALESCE(session_id,'')='' AND LOWER(COALESCE(app,''))=?))`
		parts = append(parts, clause)
		args = append(args, low*1000, high*1000, app, app)
	}
	if detection := params.Get("detection"); detection != "" {
		predicate := map[string]string{"alerts": detectionSQL, "high": "(" + detectionSQL + " AND sev=1)", "drops": blockedSQL}[detection]
		if predicate == "" {
			return nil, nil, errors.New("检测筛选无效")
		}
		sessionFilter(predicate, nil)
	}
	if sid := params.Get("sid"); sid != "" {
		n, err := strconv.ParseInt(sid, 10, 64)
		if err != nil || n <= 0 {
			return nil, nil, errors.New("SID 无效")
		}
		sessionFilter("sid=?", []any{n})
	}
	if connection := params.Get("connection"); connection != "" {
		if connection != "1" {
			return nil, nil, errors.New("连接筛选无效")
		}
		parts = append(parts, "(COALESCE(session_id,'')!='' OR type='flow')")
	}
	return parts, args, nil
}
func (a *App) CacheStats() Object {
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	rss, peak := processMemory(os.Getpid())
	return Object{"responses": Object{"entries": len(a.cache), "bytes": a.cacheBytes}, "budget_bytes": a.Config.PreloadBytes, "recent_events_bytes": a.Recent.Bytes(), "recent_events_range": a.Recent.Range(), "recent_events_error": a.Recent.Error(), "read_workers": a.Config.ReadWorkers, "statistics_batch_size": 1024, "statistics_duty_percent": 20, "record_buffer_bytes": 0, "process_rss_bytes": rss, "process_peak_bytes": peak, "go_heap_bytes": memory.HeapAlloc, "cpu_workers": a.Pool.Workers}
}
func (a *App) Invalidate() {
	a.cacheMu.Lock()
	a.cache = map[string]cachedResponse{}
	a.cacheBytes = 0
	a.cacheMu.Unlock()
	a.Network.Invalidate()
	if a.Overview != nil {
		a.Overview.Invalidate()
	}
}

var _ = fmt.Sprint
var _ = sort.Slice
var _ = os.ErrNotExist
