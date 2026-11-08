package console

import (
	"context"
	"database/sql"
	"math/rand/v2"
	"net/url"
	"testing"
	"time"
)

func TestRecentCacheSurvivesCancelledSnapshot(t *testing.T) {
	store, ctx := testStore(t)
	app := &App{Store: store, Config: Config{PreloadBytes: 1 << 20}}
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
	for range 12 {
		request, cancel := context.WithCancel(ctx)
		snapshot, release, ok := recent.Snapshot(request, 0, 0, true)
		if !ok {
			cancel()
			t.Fatal("resident snapshot unavailable")
		}
		var count int
		if err = snapshot.main.QueryRowContext(request, "SELECT COUNT(*) FROM events").Scan(&count); err != nil || count != 1 {
			cancel()
			release()
			t.Fatal(count, err)
		}
		cancel()
		// Let database/sql perform its cancellation rollback before returning the lease.
		time.Sleep(5 * time.Millisecond)
		release()
		if err = recent.refresh(ctx); err != nil {
			t.Fatal("cancelled request destroyed the resident cache", err)
		}
		if err = recent.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events").Scan(&count); err != nil || count != 1 {
			t.Fatal("resident records disappeared after cancellation", count, err)
		}
		var tempStore int
		if err = recent.db.QueryRowContext(ctx, "PRAGMA temp_store").Scan(&tempStore); err != nil || tempStore != 2 {
			t.Fatal("replacement connection lost memory-only temporary storage", tempStore, err)
		}
		if recent.db.Stats().OpenConnections > 2 {
			t.Fatal("cancelled snapshots leaked database connections")
		}
	}
}

func TestRecentCacheRebuildsAfterLosingItsSchema(t *testing.T) {
	store, ctx := testStore(t)
	app := &App{Store: store, Config: Config{PreloadBytes: 1 << 20}}
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
	if err = recent.refreshOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = recent.db.ExecContext(ctx, "DROP TABLE events"); err != nil {
		t.Fatal(err)
	}
	if err = recent.refreshOnce(ctx); err == nil {
		t.Fatal("cache schema loss was not detected")
	}
	if recent.rebuilds.Load() != 1 || recent.Ready() {
		t.Fatal("missing schema did not trigger a bounded rebuild")
	}
	if err = recent.refreshOnce(ctx); err != nil {
		t.Fatal("cache did not recover from schema loss", err)
	}
	if recent.Error() != "" || !recent.Ready() || recent.Count() != 1 {
		t.Fatal("cache recovery did not restore the latest records")
	}
}

func TestRecentRetainsSnapshotOnSourceFailureAndClearsWarning(t *testing.T) {
	store, ctx := testStore(t)
	app := &App{Store: store, Config: Config{PreloadBytes: 1 << 20, ManagerSocket: t.TempDir() + "/control.sock"}, ctx: ctx, panelSlots: make(chan struct{}, 1), allSlots: make(chan struct{}, 4), logSlots: make(chan struct{}, 3), cache: map[string]cachedResponse{}}
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
	if err = recent.refreshOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = app.Read(ctx, "overview", url.Values{"scope": {"cache"}}); err != nil {
		t.Fatal(err)
	}
	original := store.Readers
	broken, err := sql.Open("aegis-sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer broken.Close()
	store.Readers = &eventDatabase{DB: broken}
	defer func() { store.Readers = original }()
	if err = recent.refreshOnce(ctx); err == nil {
		t.Fatal("source failure not detected")
	}
	data, err := app.Read(ctx, "overview", url.Values{"scope": {"cache"}})
	if err != nil || object(data["read_state"])["status"] != "stale" || integer(object(data["security"])["total"]) != 1 {
		t.Fatal("source failure destroyed the last usable overview", err)
	}
	app.Invalidate()
	data, err = app.Read(ctx, "overview", url.Values{"scope": {"cache"}})
	if err != nil || object(data["read_state"])["status"] != "stale" || len(app.cache) != 0 {
		t.Fatal("stale results were cached as a fresh response", err)
	}
	store.Readers = original
	if err = recent.refreshOnce(ctx); err != nil {
		t.Fatal(err)
	}
	data, err = app.Read(ctx, "overview", url.Values{"scope": {"cache"}})
	if err != nil || data["read_state"] != nil || recent.Error() != "" {
		t.Fatal("overview warning did not clear after recovery", err)
	}
}

func TestRecentEvictionStaysWithinCapacity(t *testing.T) {
	store, ctx := testStore(t)
	app := &App{Store: store, Config: Config{PreloadBytes: 1 << 20}}
	recent, err := NewRecentEvents(app)
	if err != nil {
		t.Fatal(err)
	}
	defer recent.Close()
	random := rand.New(rand.NewPCG(1, 2))
	for batch := range 24 {
		rows := make([]Object, 128)
		for i := range rows {
			raw := make([]byte, 2048)
			for j := range raw {
				raw[j] = byte(random.Uint32())
			}
			id := int64(batch*128 + i + 1)
			rows[i] = Object{"id": id, "ts": id * 1000, "type": "flow", "raw": raw}
		}
		if err = recent.insert(ctx, rows, true); err != nil {
			t.Fatal("bounded cache stopped accepting new records", err)
		}
	}
	var count, pages, size int64
	if err = recent.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events").Scan(&count); err != nil {
		t.Fatal(err)
	}
	recent.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages)
	recent.db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&size)
	if count != recent.Count() || count == 0 || count >= 24*128 || pages*size > app.Config.PreloadBytes {
		t.Fatal("cache eviction violated count or memory budget", count, recent.Count(), pages*size)
	}
}
