package console

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	sqlite "github.com/mattn/go-sqlite3"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type RecentEvents struct {
	app          *App
	db           *sql.DB
	anchor       *sql.Conn
	mu           sync.Mutex
	bounds       atomic.Value
	bytes, count atomic.Int64
	ready        atomic.Bool
	generation   uint64
	cursor       int64
	historyMax   int64
	beforeTS     float64
	beforeID     int64
	warming      bool
	initialized  bool
	lastError    atomic.Value
	lastFailure  atomic.Value
	lastSuccess  atomic.Int64
	rebuilds     atomic.Uint64
	Version      atomic.Uint64
}

var errRecentBusy = errors.New("recent refresh busy")

func NewRecentEvents(app *App) (*RecentEvents, error) {
	db, anchor, err := newRecentDatabase(app.Config.PreloadBytes)
	if err != nil {
		return nil, err
	}
	r := &RecentEvents{app: app, db: db, anchor: anchor, warming: true}
	r.bounds.Store([2]float64{})
	r.lastError.Store("")
	r.lastFailure.Store(Object{})
	return r, nil
}
func newRecentDatabase(budget int64) (*sql.DB, *sql.Conn, error) {
	db, err := sql.Open("aegis-recent-sqlite", "file:recent-"+token()+"?mode=memory&cache=shared&_busy_timeout=1000")
	if err != nil {
		return nil, nil, err
	}
	// One lifetime connection owns the named memory database. The sole worker
	// connection may be discarded by database/sql when a request is cancelled.
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	anchor, err := db.Conn(context.Background())
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	for _, s := range []string{fmt.Sprintf("PRAGMA max_page_count=%d", budget/4096), eventSchema(), "CREATE INDEX idx_recent_ts ON events(ts)", "CREATE INDEX idx_recent_type_ts ON events(type,ts)", "CREATE INDEX idx_recent_session_ts ON events(session_id,ts) WHERE session_id IS NOT NULL"} {
		if _, err = anchor.ExecContext(context.Background(), s); err != nil {
			anchor.Close()
			db.Close()
			return nil, nil, err
		}
	}
	return db, anchor, nil
}
func (r *RecentEvents) Close()        { r.anchor.Close(); r.db.Close() }
func (r *RecentEvents) Ready() bool   { return r.ready.Load() }
func (r *RecentEvents) Error() string { return text(r.lastError.Load()) }
func (r *RecentEvents) Diagnostics() Object {
	return Object{"rebuilds": r.rebuilds.Load(), "last_failure": clone(object(r.lastFailure.Load()))}
}
func (r *RecentEvents) ReadState() Object {
	if r.Error() == "" {
		return nil
	}
	return Object{"status": "stale", "as_of": float64(r.lastSuccess.Load()) / 1e9, "error": r.Error()}
}
func (r *RecentEvents) Bytes() int64 { return r.bytes.Load() }
func (r *RecentEvents) Count() int64 { return r.count.Load() }
func (r *RecentEvents) Bounds() (float64, float64) {
	bounds := r.bounds.Load().([2]float64)
	return bounds[0], bounds[1]
}
func (r *RecentEvents) Range() any {
	if !r.Ready() {
		return nil
	}
	low, high := r.Bounds()
	return []float64{low, high}
}
func (r *RecentEvents) Owns(g *Snapshot) bool { return g.recent }
func (r *RecentEvents) WaitSnapshot(ctx context.Context) (*Snapshot, func(), error) {
	for {
		if snapshot, release, ok := r.Snapshot(ctx, 0, 0, true); ok {
			return snapshot, release, nil
		}
		if message := r.Error(); message != "" {
			return nil, nil, errors.New(message)
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, nil, ctx.Err()
		case <-timer.C:
		}
	}
}
func (r *RecentEvents) Snapshot(ctx context.Context, low, high float64, overview bool) (*Snapshot, func(), bool) {
	if !r.ready.Load() || !r.mu.TryLock() {
		return nil, nil, false
	}
	lo, hi := r.Bounds()
	if r.generation != r.app.Store.Generation.Load() || (!overview && (low < lo || high > hi)) {
		r.mu.Unlock()
		return nil, nil, false
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		r.mu.Unlock()
		return nil, nil, false
	}
	g := &Snapshot{main: tx, ctx: ctx, recent: true}
	return g, func() { g.Close(); r.mu.Unlock() }, true
}
func (r *RecentEvents) insert(ctx context.Context, rows []Object, evict bool) error {
	names := append([]string{"id"}, columnNames()...)
	sqlText := "INSERT OR IGNORE INTO events (" + strings.Join(names, ",") + ") VALUES (" + strings.TrimSuffix(strings.Repeat("?,", len(names)), ",") + ")"
	for _, row := range rows {
		values := make([]any, len(names))
		for i, name := range names {
			values[i] = row[name]
		}
		for attempts := 0; ; attempts++ {
			result, err := r.db.ExecContext(ctx, sqlText, values...)
			if err == nil {
				n, _ := result.RowsAffected()
				r.count.Add(n)
				break
			}
			var e sqlite.Error
			if !errors.As(err, &e) || e.Code != sqlite.ErrFull {
				return err
			}
			if !evict || attempts > 64 {
				return err
			}
			pruned, err := r.db.ExecContext(ctx, "DELETE FROM events WHERE id IN (SELECT id FROM events WHERE (ts,id)<(?,?) ORDER BY ts,id LIMIT 128)", row["ts"], row["id"])
			if err != nil {
				return err
			}
			n, _ := pruned.RowsAffected()
			r.count.Add(-n)
			if n == 0 {
				if r.count.Load() > 0 {
					// A late record older than every resident event remains on disk.
					break
				}
				return errors.New("单条事件超过常驻池容量")
			}
		}
	}
	return nil
}
func (r *RecentEvents) refresh(ctx context.Context) error {
	if !r.mu.TryLock() {
		return errRecentBusy
	}
	defer r.mu.Unlock()
	if r.generation != r.app.Store.Generation.Load() {
		if _, err := r.db.ExecContext(ctx, "DELETE FROM events"); err != nil {
			return err
		}
		r.generation = r.app.Store.Generation.Load()
		r.warming = true
		r.cursor = 0
		r.historyMax = 0
		r.initialized = false
		r.beforeID = 0
		r.beforeTS = 0
		r.count.Store(0)
		r.ready.Store(false)
	}
	if !r.initialized {
		if err := r.app.Store.Readers.QueryRowContext(ctx, "SELECT COALESCE(MAX(id),0) FROM events").Scan(&r.cursor); err != nil {
			return err
		}
		r.initialized = true
		r.historyMax = r.cursor
	}
	// Follow committed new events before spending the refresh budget on history.
	forward, err := queryRows(ctx, r.app.Store.Readers, "SELECT * FROM events WHERE id>? ORDER BY id LIMIT 128", r.cursor)
	if err != nil {
		return err
	}
	if len(forward) > 0 {
		if err = r.insert(ctx, forward, true); err != nil {
			return err
		}
		r.cursor = integer(forward[len(forward)-1]["id"])
		r.Version.Add(1)
	}
	if r.warming && len(forward) < 128 && r.app.Store.Lag() <= 8<<20 {
		where := " WHERE id<=?"
		args := []any{r.historyMax}
		if r.beforeID > 0 {
			where += " AND (ts,id)<(?,?)"
			args = append(args, r.beforeTS, r.beforeID)
		}
		rows, err := queryRows(ctx, r.app.Store.Readers, "SELECT * FROM events"+where+" ORDER BY ts DESC,id DESC LIMIT 128", args...)
		if err != nil {
			return err
		}
		if err = r.insert(ctx, rows, false); err != nil {
			var e sqlite.Error
			if r.warming && errors.As(err, &e) && e.Code == sqlite.ErrFull {
				r.warming = false
			} else {
				return err
			}
		}
		if len(rows) > 0 && r.warming {
			last := rows[len(rows)-1]
			r.beforeTS = number(last["ts"])
			r.beforeID = integer(last["id"])
		}
		if len(rows) > 0 {
			r.Version.Add(1)
		}
		if len(rows) < 128 {
			r.warming = false
		}
	}
	if r.count.Load() > 0 {
		var lo, hi float64
		if err = r.db.QueryRowContext(ctx, "SELECT ts/1000.0 FROM events ORDER BY ts,id LIMIT 1").Scan(&lo); err != nil {
			return err
		}
		if err = r.db.QueryRowContext(ctx, "SELECT ts/1000.0 FROM events ORDER BY ts DESC,id DESC LIMIT 1").Scan(&hi); err != nil {
			return err
		}
		r.bounds.Store([2]float64{lo, hi})
		r.ready.Store(true)
	} else if !r.warming {
		r.ready.Store(true)
	}
	var pages, size int64
	r.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages)
	r.db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&size)
	r.bytes.Store(pages * size)
	return nil
}
func (r *RecentEvents) recoverBuffer(ctx context.Context) {
	if ctx.Err() != nil || !r.mu.TryLock() {
		return
	}
	defer r.mu.Unlock()
	var tables int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='events'").Scan(&tables)
	if ctx.Err() != nil {
		return
	}
	if err != nil || tables != 1 {
		db, anchor, e := newRecentDatabase(r.app.Config.PreloadBytes)
		if e != nil {
			r.ready.Store(false)
			return
		}
		oldDB, oldAnchor := r.db, r.anchor
		r.db, r.anchor = db, anchor
		oldAnchor.Close()
		oldDB.Close()
		r.generation = r.app.Store.Generation.Load()
		r.cursor, r.historyMax, r.beforeID = 0, 0, 0
		r.beforeTS = 0
		r.initialized, r.warming = false, true
		r.count.Store(0)
		r.bytes.Store(0)
		r.bounds.Store([2]float64{})
		r.ready.Store(false)
		r.rebuilds.Add(1)
		r.Version.Add(1)
		return
	}
	// A source-side transient error must not discard a usable resident snapshot.
	var count int64
	var low, high sql.NullFloat64
	if err = r.db.QueryRowContext(ctx, "SELECT COUNT(*),MIN(ts)/1000.0,MAX(ts)/1000.0 FROM events").Scan(&count, &low, &high); err != nil {
		r.ready.Store(false)
		return
	}
	r.count.Store(count)
	r.bounds.Store([2]float64{low.Float64, high.Float64})
	if count > 0 || !r.warming {
		r.ready.Store(true)
	}
}
func (r *RecentEvents) refreshOnce(ctx context.Context) error {
	err := r.refresh(ctx)
	if errors.Is(err, errRecentBusy) {
		return nil
	}
	if err != nil {
		diagnostic := Object{"kind": "refresh"}
		var failure sqlite.Error
		if errors.As(err, &failure) {
			diagnostic = Object{"kind": "sqlite", "code": int(failure.Code), "extended_code": int(failure.ExtendedCode)}
		}
		r.lastFailure.Store(diagnostic)
		r.lastError.Store("最近事件缓冲刷新失败")
		r.recoverBuffer(ctx)
	} else {
		r.lastError.Store("")
		r.lastSuccess.Store(time.Now().UnixNano())
	}
	return err
}
func (r *RecentEvents) Run(ctx context.Context) {
	for {
		started := time.Now()
		err := r.refreshOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		cooldown := max(100*time.Millisecond, 3*time.Since(started))
		if err != nil {
			cooldown = max(cooldown, 5*time.Second)
		}
		timer := time.NewTimer(cooldown)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
