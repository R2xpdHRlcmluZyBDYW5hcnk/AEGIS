package console

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Opt-in real-data checks accept only a developer-owned copy, never a router path.
func TestLocalCopiedEventPipeline(t *testing.T) {
	root := os.Getenv("AEGIS_GO_LOCAL_DATA")
	if root == "" {
		t.Skip("local copied logs not requested")
	}
	if !filepath.IsAbs(root) || !strings.HasPrefix(filepath.Clean(root), filepath.Clean(os.TempDir())+string(os.PathSeparator)) {
		t.Fatal("copied data must be in the developer's temporary directory")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	logs := filepath.Join(t.TempDir(), "snort")
	if err := os.MkdirAll(logs, 0700); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(filepath.Join(root, "native"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(root, "native", file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		// Tail transfers may start or finish inside a record.
		start, end := strings.IndexByte(string(data), '\n'), strings.LastIndexByte(string(data), '\n')
		if start < 0 || end <= start {
			continue
		}
		if err = os.WriteFile(filepath.Join(logs, file.Name()), data[start+1:end+1], 0600); err != nil {
			t.Fatal(err)
		}
	}
	s, _ := testStore(t)
	instance := filepath.Join(t.TempDir(), "instance.json")
	if err = writeJSON(instance, Object{"epoch": strings.Repeat("d", 32), "started": 1}); err != nil {
		t.Fatal(err)
	}
	b, err := NewBridge(logs, s.Stream, filepath.Join(t.TempDir(), "offsets.json"), instance, s.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Run(ctx, true); err != nil {
		t.Fatal(err)
	}
	for more := true; more; {
		more, err = s.Ingest(ctx)
		if err != nil {
			t.Fatal(err)
		}
	}
	var rows int
	if err = s.Readers.QueryRowContext(ctx, "SELECT COUNT(*) FROM events").Scan(&rows); err != nil || rows == 0 {
		t.Fatal("no copied events ingested", rows, err)
	}
	a := &App{Store: s, Config: Config{PreloadBytes: 32 << 20, ManagerSocket: filepath.Join(t.TempDir(), "control.sock")}}
	a.Network = NewNetworkSnapshots(a)
	a.Recent, err = NewRecentEvents(a)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Recent.Close()
	for i := 0; i < 100; i++ {
		if err = a.Recent.refresh(ctx); err != nil {
			t.Fatal(err)
		}
		if !a.Recent.warming {
			break
		}
	}
	overview, err := a.execute(ctx, "overview", url.Values{"scope": {"cache"}, "view": {"panel"}})
	if err != nil {
		t.Fatal(err)
	}
	network := object(overview["network"])
	if network["available"] != true || integer(network["records"]) == 0 || integer(network["flows"]) == 0 {
		t.Fatal("network counters unavailable")
	}
	low, high := a.Recent.Bounds()
	g, err := s.Snapshot(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	total, _, err := search(ctx, g, low, high, nil, nil, 50, 0, true, false, false)
	if err != nil || total == 0 {
		t.Fatal("copied event search returned empty", err)
	}
	inc, err := incidents(ctx, g, url.Values{}, 0, high+1, "", 3)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("copied pipeline rows=%d rejected=%d flows=%d dns=%d tls=%d incidents=%d", rows, b.state.Rejected, integer(network["flows"]), integer(network["dns"]), integer(network["tls"]), integer(inc["total"]))
}

func TestLocalCopiedDatabaseOverview(t *testing.T) {
	root := os.Getenv("AEGIS_GO_LOCAL_DATA")
	if root == "" {
		t.Skip("local copied database not requested")
	}
	if !filepath.IsAbs(root) || !strings.HasPrefix(filepath.Clean(root), filepath.Clean(os.TempDir())+string(os.PathSeparator)) {
		t.Fatal("expected local temporary copy")
	}
	stream := filepath.Join(t.TempDir(), "events.json")
	os.WriteFile(stream, nil, 0600)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	app, err := NewApp(ctx, Config{EventDB: filepath.Join(root, "snort-ndr.db"), Stream: stream, PreloadBytes: 512 << 20, ReadWorkers: 4, SessionTTL: time.Hour, ManagerSocket: filepath.Join(t.TempDir(), "control.sock")})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	deadline := time.Now().Add(10 * time.Second)
	for !app.Recent.Ready() && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	started := time.Now()
	data, err := app.Read(ctx, "overview", url.Values{"scope": {"cache"}, "view": {"panel"}})
	if err != nil {
		t.Fatal(err)
	}
	n := object(data["network"])
	t.Logf("copied DB source=%s network=%s ready=%v records=%d elapsed=%s recent_error=%t", text(data["source"]), text(n["status"]), n["available"], integer(n["records"]), time.Since(started), app.Recent.Error() != "")
	if n["available"] != true {
		t.Fatal("resident overview did not return network statistics")
	}
	var latestAlert sql.NullFloat64
	if err = app.Store.Readers.QueryRowContext(ctx, "SELECT MAX(ts)/1000.0 FROM events WHERE type IN ('alert','drop') AND "+detectionSQL).Scan(&latestAlert); err != nil {
		t.Fatal(err)
	}
	if latestAlert.Valid {
		params := url.Values{"from": {strconv.FormatFloat(latestAlert.Float64-3600, 'f', 6, 64)}, "to": {strconv.FormatFloat(latestAlert.Float64+1, 'f', 6, 64)}}
		for _, name := range []string{"hunt", "incidents"} {
			result, err := app.Read(ctx, name, params)
			if err != nil || integer(result["total"]) == 0 {
				t.Fatal("known populated historical range returned empty", name, err)
			}
			t.Logf("copied DB %s populated historical total=%d", name, integer(result["total"]))
		}
	}
}
