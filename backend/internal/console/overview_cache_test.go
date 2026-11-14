package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sqlite "github.com/mattn/go-sqlite3"
)

func overviewTestApp(t *testing.T) *App {
	t.Helper()
	store, parent := testStore(t)
	ctx, cancel := context.WithCancel(parent)
	app := &App{Store: store, ctx: ctx, Config: Config{PreloadBytes: 8 << 20, snapshotDir: t.TempDir(), ReadWorkers: WorkerCount(), ManagerSocket: t.TempDir() + "/manager.sock"}, panelSlots: make(chan struct{}, 1), allSlots: make(chan struct{}, WorkerCount()), logSlots: make(chan struct{}, max(1, WorkerCount()-1))}
	app.Network = NewNetworkSnapshots(app)
	var err error
	app.Recent, err = NewRecentEvents(app)
	if err != nil {
		t.Fatal(err)
	}
	if err = app.Recent.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); app.Recent.Close() })
	return app
}

func startOverview(t *testing.T, app *App) *OverviewSnapshots {
	t.Helper()
	if app.Overview == nil {
		app.Overview = NewOverviewSnapshots(app)
	}
	n := app.Overview
	n.refreshAfter, n.retryAfter, n.costRatio = time.Millisecond, time.Millisecond, 0
	ctx, cancel := context.WithCancel(app.ctx)
	done := make(chan struct{})
	go func() { defer close(done); n.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	return n
}

func overviewValue(n int64) Object {
	return Object{"source": "memory", "security": Object{"alerts": n}, "recent": []Object{{"sig": fmt.Sprint(n)}}}
}

func waitOverview(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("overview state did not advance")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestOverviewSnapshotSurvivesIngestionAndBlockedRefresh(t *testing.T) {
	app := overviewTestApp(t)
	n := NewOverviewSnapshots(app)
	app.Overview = n
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int64
	n.compute = func(ctx context.Context, _ url.Values) (Object, error) {
		v := calls.Add(1)
		if v == 2 {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return overviewValue(v), nil
	}
	startOverview(t, app)
	first, err := app.Read(t.Context(), "overview", defaultOverviewParams())
	if err != nil || integer(object(first["security"])["alerts"]) != 1 {
		t.Fatal(first, err)
	}
	app.Store.Revision.Add(1) // A committed ingestion revision must not discard JSON.
	n.signal()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("refresh did not start")
	}
	app.Recent.mu.Lock()
	app.panelSlots <- struct{}{}
	for range cap(app.allSlots) {
		app.allSlots <- struct{}{}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	cached, err := app.Read(ctx, "overview", defaultOverviewParams())
	cancel()
	app.Recent.mu.Unlock()
	<-app.panelSlots
	for range cap(app.allSlots) {
		<-app.allSlots
	}
	if err != nil || integer(object(cached["security"])["alerts"]) != 1 || object(cached["overview_state"])["updating"] != true {
		t.Fatal("cached overview waited on SQL or ingestion", cached, err)
	}
	object(cached["security"])["alerts"] = 999
	unchanged, err := app.Read(t.Context(), "overview", defaultOverviewParams())
	if err != nil || integer(object(unchanged["security"])["alerts"]) != 1 {
		t.Fatal("caller modified shared JSON", err)
	}
	close(release)
	waitOverview(t, func() bool {
		v, e := app.Read(t.Context(), "overview", defaultOverviewParams())
		return e == nil && integer(object(v["security"])["alerts"]) == 2
	})
	if calls.Load() != 2 {
		t.Fatal("ordinary reads duplicated refresh jobs", calls.Load())
	}
}

func TestOverviewStreamSharesResidentSnapshotAfterClearingTimeFilter(t *testing.T) {
	app := overviewTestApp(t)
	n := NewOverviewSnapshots(app)
	app.Overview = n
	n.compute = func(_ context.Context, params url.Values) (Object, error) {
		if from := params.Get("from"); from != "" {
			return Object{"range": []float64{number(from), number(params.Get("to"))}}, nil
		}
		return Object{"range": []float64{100, 200 + float64(app.Recent.Version.Load())}}, nil
	}
	startOverview(t, app)
	handler := NewHTTPHandler(app)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	rest := defaultOverviewParams()
	stream := copyValues(rest)
	stream.Set("topic", "overview")
	read := func(params url.Values) []any {
		t.Helper()
		value, err := handler.streamPayload(ctx, "overview", params)
		if err != nil {
			t.Fatal(err)
		}
		return value["range"].([]any)
	}
	initial := read(stream)
	filter := copyValues(stream)
	filter.Set("from", "150")
	filter.Set("to", "160")
	if got := read(filter); number(got[0]) != 150 || number(got[1]) != 160 {
		t.Fatal("time filter was lost", got)
	}
	filter.Del("topic")
	if value, err := app.Read(ctx, "overview", filter); err != nil || number(value["range"].([]any)[0]) != 150 {
		t.Fatal("REST time filter did not match stream", value, err)
	}
	if entries := integer(n.Status()["entries"]); entries != 2 {
		t.Fatalf("REST and SSE should share the default and filtered entries, got %d", entries)
	}
	app.Recent.Version.Add(1)
	n.signal()
	var latest []any
	waitOverview(t, func() bool {
		value, err := app.Read(ctx, "overview", rest)
		if err != nil {
			t.Fatal(err)
		}
		latest = value["range"].([]any)
		return number(latest[1]) > number(initial[1])
	})
	if got := read(stream); !slices.Equal(got, latest) {
		t.Fatal("clearing the filter did not resume the latest resident range", got, latest)
	}
	if stream.Get("topic") != "overview" {
		t.Fatal("stream dispatch mutated the caller's parameters")
	}
}

func TestOverviewColdCancellationCoalescesAndFilterDoesNotBorrowOtherSnapshot(t *testing.T) {
	app := overviewTestApp(t)
	n := NewOverviewSnapshots(app)
	app.Overview = n
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int64
	n.compute = func(ctx context.Context, p url.Values) (Object, error) {
		calls.Add(1)
		if p.Get("src") == "192.0.2.99" {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return overviewValue(99), nil
		}
		return overviewValue(1), nil
	}
	startOverview(t, app)
	if _, err := app.Read(t.Context(), "overview", defaultOverviewParams()); err != nil {
		t.Fatal(err)
	}
	filter := defaultOverviewParams()
	filter.Set("src", "192.0.2.99")
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	value, err := app.Read(ctx, "overview", filter)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || value != nil {
		t.Fatal("new filter borrowed the default snapshot", value, err)
	}
	<-started
	close(release)
	value, err = app.Read(t.Context(), "overview", filter)
	if err != nil || integer(object(value["security"])["alerts"]) != 99 {
		t.Fatal("cancelled client killed shared work", value, err)
	}
	if calls.Load() != 2 {
		t.Fatal("duplicate cold refresh", calls.Load())
	}
}

func TestOverviewFailedRefreshKeepsSnapshotAndGenerationRejectsLateWork(t *testing.T) {
	app := overviewTestApp(t)
	n := NewOverviewSnapshots(app)
	app.Overview = n
	var calls atomic.Int64
	n.compute = func(context.Context, url.Values) (Object, error) {
		if calls.Add(1) == 2 {
			return nil, errors.New("fixture aggregation failure")
		}
		return overviewValue(calls.Load()), nil
	}
	startOverview(t, app)
	if _, err := app.Read(t.Context(), "overview", defaultOverviewParams()); err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	n.retryAfter = time.Hour
	n.mu.Unlock()
	app.Store.Revision.Add(1)
	n.signal()
	waitOverview(t, func() bool { return integer(n.Status()["builds"]) >= 2 })
	value, err := app.Read(t.Context(), "overview", defaultOverviewParams())
	if err != nil || integer(object(value["security"])["alerts"]) != 1 || object(value["read_state"])["status"] != "stale" {
		t.Fatal("failed refresh erased successful snapshot", value, err)
	}
	// A failed result is retryable and must clear its warning on recovery.
	n.mu.Lock()
	n.entries[defaultOverviewParams().Encode()].next = time.Time{}
	n.mu.Unlock()
	n.signal()
	waitOverview(t, func() bool {
		v, e := app.Read(t.Context(), "overview", defaultOverviewParams())
		return e == nil && v["read_state"] == nil && integer(object(v["security"])["alerts"]) == 3
	})
}

func TestOverviewGenerationAndExplicitInvalidationDiscardCompletedAndInFlightData(t *testing.T) {
	for _, generationChange := range []bool{false, true} {
		t.Run(fmt.Sprint(generationChange), func(t *testing.T) {
			app := overviewTestApp(t)
			n := NewOverviewSnapshots(app)
			app.Overview = n
			started, release := make(chan struct{}), make(chan struct{})
			var calls atomic.Int64
			n.compute = func(ctx context.Context, _ url.Values) (Object, error) {
				v := calls.Add(1)
				if v == 2 {
					close(started)
					select {
					case <-release:
					case <-app.ctx.Done():
						return nil, ctx.Err()
					}
				}
				return overviewValue(v), nil
			}
			startOverview(t, app)
			if _, err := app.Read(t.Context(), "overview", defaultOverviewParams()); err != nil {
				t.Fatal(err)
			}
			app.Store.Revision.Add(1)
			n.signal()
			<-started
			if generationChange {
				app.Store.Generation.Add(1)
			} else {
				app.Invalidate()
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
			v, err := app.Read(ctx, "overview", defaultOverviewParams())
			cancel()
			if v != nil || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("cleared history returned an old snapshot", v, err)
			}
			close(release)
			v, err = app.Read(t.Context(), "overview", defaultOverviewParams())
			if err != nil || integer(object(v["security"])["alerts"]) != 3 {
				t.Fatal("late old work replaced the new generation", v, err)
			}
		})
	}
}

func TestResidentParallelQueriesShareFrozenRowsAndKeepResultOrder(t *testing.T) {
	app := overviewTestApp(t)
	record, err := ParseEvent(syntheticEvent("alert"))
	if err != nil {
		t.Fatal(err)
	}
	if err = app.Store.insert(t.Context(), []*Prepared{record}, Cursor{}); err != nil {
		t.Fatal(err)
	}
	if err = app.Recent.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	g, release, ok, freezeError := app.Recent.frozenSnapshot(t.Context(), 0, 0, true)
	if freezeError != nil {
		t.Fatal(freezeError)
	}
	if !ok {
		t.Fatal("resident snapshot unavailable")
	}
	defer release()
	workers := len(g.helpers) + 1
	if workers != WorkerCount() {
		t.Fatal("resident SQL ignored service allocation", workers, WorkerCount())
	}
	entered := make(chan struct{}, workers)
	gate := make(chan struct{})
	var active, peak atomic.Int64
	for _, conn := range g.connections {
		if err = conn.Raw(func(raw any) error {
			return raw.(*sqlite.SQLiteConn).RegisterFunc("overview_probe", func(v int64) int64 {
				count := active.Add(1)
				for old := peak.Load(); count > old && !peak.CompareAndSwap(old, count); old = peak.Load() {
				}
				if v < int64(workers) {
					entered <- struct{}{}
					<-gate
				}
				active.Add(-1)
				return v
			}, false)
		}); err != nil {
			t.Fatal(err)
		}
	}
	queries := []statement{}
	for i := 0; i < workers*2; i++ {
		queries = append(queries, statement{"SELECT overview_probe(?) n,COUNT(*) total FROM events", []any{i}})
	}
	done := make(chan struct{})
	var values [][]Object
	var failure error
	go func() { defer close(done); values, failure = g.Many(queries) }()
	for range workers {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			close(gate)
			<-done
			t.Fatal("independent SQL did not run in parallel")
		}
	}
	if err = app.Recent.refresh(t.Context()); err != nil {
		t.Fatal("frozen readers blocked resident refresh", err)
	}
	close(gate)
	<-done
	if failure != nil || peak.Load() != int64(workers) {
		t.Fatal("parallel group failed", failure, peak.Load())
	}
	for i, rows := range values {
		if integer(rows[0]["n"]) != int64(i) || integer(rows[0]["total"]) != 1 {
			t.Fatal("parallel rows changed order or revision", i, rows)
		}
	}
}

func TestOverviewCacheBoundsParameterQueueAndBytes(t *testing.T) {
	app := overviewTestApp(t)
	n := NewOverviewSnapshots(app)
	n.limit = 3
	app.Overview = n
	for i := 0; i < 8; i++ {
		ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
		_, err := n.Read(ctx, url.Values{"src": {fmt.Sprint(i)}})
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		if len(n.entries) > 3 {
			t.Fatal("unbounded pending snapshot queue")
		}
	}
	if _, err := n.Read(t.Context(), url.Values{"sig": {strings.Repeat("x", 17<<10)}}); err == nil {
		t.Fatal("oversized parameters entered cache")
	}
	n.Invalidate()
	n.budget = 128
	n.compute = func(context.Context, url.Values) (Object, error) {
		return Object{"large": strings.Repeat("x", 256)}, nil
	}
	startOverview(t, app)
	if _, err := n.Read(t.Context(), defaultOverviewParams()); err == nil {
		t.Fatal("oversized result exceeded cache budget")
	}
	if n.bytes > n.budget {
		t.Fatal("snapshot byte budget exceeded")
	}
}

func TestOverviewFiltersApplyToLatestLogsFromTheSameImage(t *testing.T) {
	app := overviewTestApp(t)
	base := float64(int64(now()) - 300)
	prepared := []*Prepared{}
	for group := 0; group < 2; group++ {
		for i, kind := range []string{"alert", "drop", "dns", "tls", "http", "flow", "session"} {
			name, proto, service := "alpha.test", "TCP", "http"
			if group == 1 {
				name, proto, service = "beta.test", "UDP", "dns"
			}
			row := Object{"timestamp": utc(base + float64(group*100+i)), "event_type": kind, "src_ip": fmt.Sprintf("192.0.2.%d", group+1), "dest_ip": fmt.Sprintf("198.51.100.%d", group+1), "proto": proto, "app_proto": service, "snort_native": Object{"session_id": strings.Repeat("a", 32) + fmt.Sprintf(":%016x", group+1)}, "alert": Object{"gid": 1, "signature_id": 1001 + group, "signature": fmt.Sprintf("Needle %d", group+1), "severity": group + 1, "action": "allowed"}, "dns": Object{"rrname": name, "type": "response"}, "tls": Object{"sni": name}, "http": Object{"hostname": name}, "flow": Object{"pkts_toserver": 2, "pkts_toclient": 1, "bytes_toserver": 100, "bytes_toclient": 50}}
			if kind == "drop" {
				object(row["alert"])["action"] = "blocked"
			}
			data, _ := json.Marshal(row)
			record, err := ParseEvent(data)
			if err != nil || record == nil {
				t.Fatal("invalid filter fixture", kind, err)
			}
			prepared = append(prepared, record)
		}
	}
	if err := app.Store.insert(t.Context(), prepared, Cursor{}); err != nil {
		t.Fatal(err)
	}
	if err := app.Recent.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	startOverview(t, app)
	for name, filter := range map[string]url.Values{
		"source": {"src": {"192.0.2.1"}}, "destination": {"dst": {"198.51.100.1"}},
		"protocol": {"proto": {"tcp"}}, "signature": {"sig": {"Needle 1"}}, "sid": {"sid": {"1001"}},
		"dns": {"dns": {"alpha.test"}}, "tls": {"sni": {"alpha.test"}}, "application": {"app": {"http"}},
		"high": {"detection": {"high"}}, "time": {"from": {fmt.Sprint(base)}, "to": {fmt.Sprint(base + 20)}},
		"combined": {"src": {"192.0.2.1"}, "proto": {"tcp"}, "dns": {"alpha.test"}},
	} {
		t.Run(name, func(t *testing.T) {
			p := defaultOverviewParams()
			for k, v := range filter {
				p[k] = v
			}
			result, err := app.Read(t.Context(), "overview", p)
			if err != nil {
				t.Fatal(err)
			}
			data, _ := json.Marshal(result["recent"])
			var logs []Object
			if err = json.Unmarshal(data, &logs); err != nil {
				t.Fatal(err)
			}
			if len(logs) != 7 || integer(object(result["network"])["records"]) != 7 {
				t.Fatal("statistics and latest logs use different filters", name, len(logs), result["network"])
			}
			for _, row := range logs {
				if row["src"] != "192.0.2.1" {
					t.Fatal("another filter's log leaked into the snapshot", name, row["src"])
				}
			}
			if integer(object(result["security"])["alerts"]) != 2 {
				t.Fatal("filtered security did not use the same cohort", result["security"])
			}
		})
	}
	p := defaultOverviewParams()
	p.Set("src", "192.0.2.99")
	result, err := app.Read(t.Context(), "overview", p)
	if err != nil || len(result["recent"].([]any)) != 0 || integer(object(result["network"])["records"]) != 0 {
		t.Fatal("empty filter reused another result", result, err)
	}
}

func TestFrozenResidentImageRemainsImmutableDuringIngestionAndIsReleased(t *testing.T) {
	app := overviewTestApp(t)
	g, release, ok, err := app.Recent.frozenSnapshot(t.Context(), 0, 0, true)
	if err != nil || !ok {
		t.Fatal(err)
	}
	path := app.Recent.image.path
	if _, err = g.main.ExecContext(t.Context(), "DELETE FROM events"); err == nil {
		release()
		t.Fatal("frozen reader accepted writes")
	}
	row, err := ParseEvent(syntheticEvent("alert"))
	if err != nil {
		t.Fatal(err)
	}
	if err = app.Store.insert(t.Context(), []*Prepared{row}, Cursor{}); err != nil {
		t.Fatal(err)
	}
	if err = app.Recent.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = g.main.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM events").Scan(&count); err != nil || count != 0 {
		t.Fatal("frozen rows changed during ingestion", count, err)
	}
	if app.Recent.Count() != 1 {
		t.Fatal("ingestion was blocked by immutable readers")
	}
	release()
	next, closeNext, ok, err := app.Recent.frozenSnapshot(t.Context(), 0, 0, true)
	if err != nil || !ok {
		t.Fatal(err)
	}
	closeNext()
	_ = next
	if _, err = os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("superseded image leaked", err)
	}
}
