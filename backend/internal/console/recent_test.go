package console

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestRecentBufferReceivesFirstRowsAfterEmptyStartup(t *testing.T) {
	store, ctx := testStore(t)
	app := &App{Store: store, Config: Config{PreloadBytes: 8 << 20}}
	recent, err := NewRecentEvents(app)
	if err != nil {
		t.Fatal(err)
	}
	defer recent.Close()
	app.Recent = recent
	if err = recent.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if !recent.Ready() || recent.Count() != 0 {
		t.Fatal("empty cache initialization failed")
	}
	record, err := ParseEvent(syntheticEvent("alert"))
	if err != nil {
		t.Fatal(err)
	}
	if err = store.insert(ctx, []*Prepared{record}, Cursor{}); err != nil {
		t.Fatal(err)
	}
	if err = recent.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	low, high := recent.Bounds()
	if recent.Count() != 1 || low <= 0 || high != low {
		t.Fatal("first records were skipped after an empty startup", recent.Count(), low, high)
	}
}

func TestRecentFollowsNewRowsWhileHistoryIsBacklogged(t *testing.T) {
	store, ctx := testStore(t)
	file, err := os.OpenFile(store.Stream, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Truncate(9 << 20); err != nil {
		t.Fatal(err)
	}
	file.Close()
	old, err := ParseEvent(syntheticEvent("alert"))
	if err != nil {
		t.Fatal(err)
	}
	if err = store.insert(ctx, []*Prepared{old}, Cursor{}); err != nil {
		t.Fatal(err)
	}
	app := &App{Store: store, Config: Config{PreloadBytes: 8 << 20}}
	app.Recent, err = NewRecentEvents(app)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Recent.Close()
	if err = app.Recent.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if app.Recent.Count() != 0 {
		t.Fatal("historical prewarm competed with ingestion backlog")
	}
	fresh, err := ParseEvent(syntheticEvent("dns"))
	if err != nil {
		t.Fatal(err)
	}
	if err = store.insert(ctx, []*Prepared{fresh}, Cursor{}); err != nil {
		t.Fatal(err)
	}
	if err = app.Recent.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if app.Recent.Count() != 1 || !app.Recent.Ready() {
		t.Fatal("new records waited for history to catch up")
	}
}

func TestRecentWarmupPrioritizesNewlyCommittedEvents(t *testing.T) {
	store, ctx := testStore(t)
	app := &App{Store: store, Config: Config{PreloadBytes: 8 << 20}}
	recent, err := NewRecentEvents(app)
	if err != nil {
		t.Fatal(err)
	}
	defer recent.Close()
	app.Recent = recent
	var raw Object
	if err = decode(syntheticEvent("alert"), &raw); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Add(-time.Hour)
	var history []*Prepared
	for i := range 300 {
		raw["timestamp"] = stamp.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)
		data, _ := json.Marshal(raw)
		record, err := ParseEvent(data)
		if err != nil {
			t.Fatal(err)
		}
		history = append(history, record)
	}
	if err = store.insert(ctx, history, Cursor{}); err != nil {
		t.Fatal(err)
	}
	if err = recent.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if !recent.warming {
		t.Fatal("history prewarm completed unexpectedly")
	}
	raw["timestamp"] = stamp.Add(2 * time.Hour).Format(time.RFC3339Nano)
	data, _ := json.Marshal(raw)
	fresh, err := ParseEvent(data)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.insert(ctx, []*Prepared{fresh}, Cursor{}); err != nil {
		t.Fatal(err)
	}
	if err = recent.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	_, high := recent.Bounds()
	if high < float64(stamp.Add(2*time.Hour).Unix()) || recent.cursor != 301 {
		t.Fatal("new event waited behind historical prewarm")
	}
}

func TestCacheOverviewWaitsForBusyResidentSnapshot(t *testing.T) {
	store, ctx := testStore(t)
	app := &App{Store: store, Config: Config{PreloadBytes: 8 << 20, ManagerSocket: t.TempDir() + "/control.sock"}}
	app.Network = NewNetworkSnapshots(app)
	var err error
	app.Recent, err = NewRecentEvents(app)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Recent.Close()
	if err = app.Recent.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	app.Recent.mu.Lock()
	type reply struct {
		data Object
		err  error
	}
	done := make(chan reply, 1)
	go func() {
		data, err := app.execute(ctx, "overview", url.Values{"scope": {"cache"}})
		done <- reply{data, err}
	}()
	select {
	case <-done:
		app.Recent.mu.Unlock()
		t.Fatal("busy cache fell back to disk statistics")
	case <-time.After(30 * time.Millisecond):
	}
	app.Recent.mu.Unlock()
	select {
	case got := <-done:
		if got.err != nil || got.data["source"] != "memory" || object(got.data["network"])["available"] != true {
			t.Fatal("resident overview unavailable", got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("overview did not resume when cache became available")
	}
	if len(app.Network.entries) != 0 {
		t.Fatal("resident request scheduled a disk network query")
	}
	app.Recent.mu.Lock()
	defer app.Recent.mu.Unlock()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err = app.Recent.WaitSnapshot(cancelled); err != context.Canceled {
		t.Fatal("cache wait ignored cancellation", err)
	}
}

func TestOverviewHonorsExplicitRangeAndUsesCacheOnlyWhenRequested(t *testing.T) {
	store, ctx := testStore(t)
	app := &App{Store: store, Config: Config{PreloadBytes: 8 << 20, ManagerSocket: t.TempDir() + "/manager.sock"}}
	app.Network = NewNetworkSnapshots(app)
	recent, err := NewRecentEvents(app)
	if err != nil {
		t.Fatal(err)
	}
	defer recent.Close()
	app.Recent = recent
	record, err := ParseEvent(syntheticEvent("alert"))
	if err != nil {
		t.Fatal(err)
	}
	if err = store.insert(ctx, []*Prepared{record}, Cursor{}); err != nil {
		t.Fatal(err)
	}
	if err = recent.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	low, high := recent.Bounds()
	result, err := app.execute(ctx, "overview", url.Values{"scope": {"cache"}})
	if err != nil || integer(object(result["security"])["total"]) != 1 || result["source"] != "memory" {
		t.Fatal("cache scope did not use the resident range", result, err)
	}
	if len(app.Network.entries) != 0 {
		t.Fatal("resident overview queued an unnecessary disk query")
	}
	from, to := low-3600, high-1800
	result, err = app.execute(ctx, "overview", url.Values{"scope": {"cache"}, "from": {strconv.FormatFloat(from, 'f', 6, 64)}, "to": {strconv.FormatFloat(to, 'f', 6, 64)}})
	if err != nil || integer(object(result["security"])["total"]) != 0 {
		t.Fatal("explicit range was overridden by the resident cache", result, err)
	}
	got := result["range"].([]float64)
	if got[0] != from || got[1] != to {
		t.Fatal("explicit range changed", got, from, to)
	}
}
