package console

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	ctx := t.Context()
	pool := NewPool(4)
	dir := t.TempDir()
	stream := filepath.Join(dir, "events.json")
	if err := os.WriteFile(stream, nil, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(filepath.Join(dir, "events.db"), stream, pool)
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close(); pool.Close() })
	return s, ctx
}
func syntheticEvent(kind string) []byte {
	data, _ := json.Marshal(Object{"timestamp": "2026-11-07T00:00:00.123456Z", "event_type": kind, "src_ip": "192.0.2.1", "dest_ip": "198.51.100.1", "src_port": 12345, "dest_port": 443, "proto": "TCP", "alert": Object{"signature": "Synthetic indicator", "signature_id": 1001, "severity": 1, "action": "allowed"}, "flow": Object{"pkts_toserver": 2, "pkts_toclient": 3, "bytes_toserver": 100, "bytes_toclient": 200, "state": "closed"}})
	return data
}
func TestNativeStoreCommitAndResume(t *testing.T) {
	s, ctx := testStore(t)
	line := append(syntheticEvent("alert"), '\n')
	if err := os.WriteFile(s.Stream, line, 0600); err != nil {
		t.Fatal(err)
	}
	more, err := s.Ingest(ctx)
	if err != nil || more {
		t.Fatalf("ingest: %v %v", more, err)
	}
	if s.Lag() != 0 {
		t.Fatal("cursor not committed")
	}
	g, err := s.Snapshot(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	total, rows, err := search(ctx, g, 0, now()+5, nil, nil, 50, 0, true, false, false)
	g.Close()
	if err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("search %v %d %d", err, total, len(rows))
	}
	detail, err := s.Record(ctx, text(rows[0]["record_id"]))
	if err != nil || text(object(detail["record"])["sig"]) != "Synthetic indicator" {
		t.Fatalf("detail %v", err)
	}
	if _, err = s.Record(ctx, strings.Split(text(rows[0]["record_id"]), ":")[0]+":"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("accepted another record identity")
	}
	s.started = false
	if _, err = s.Ingest(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = s.Readers.QueryRow("SELECT COUNT(*) FROM events").Scan(&count); err != nil || count != 1 {
		t.Fatal("replay duplicated event", err, count)
	}
	if version := sqliteVersion(ctx, s.Readers); version != "3.54.1" {
		t.Fatalf("unexpected SQLite %s", version)
	}
}

func TestMissingCheckpointDoesNotSkipRetainedHistory(t *testing.T) {
	s, ctx := testStore(t)
	f, err := os.Create(s.Stream)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(append(syntheticEvent("alert"), '\n')); err != nil {
		t.Fatal(err)
	}
	padding := []byte(strings.Repeat(" ", (1<<20)-1) + "\n")
	for range 33 {
		if _, err = f.Write(padding); err != nil {
			t.Fatal(err)
		}
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Ingest(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = s.Readers.QueryRowContext(ctx, "SELECT COUNT(*) FROM events").Scan(&count); err != nil || count != 1 {
		t.Fatal("bootstrap skipped retained evidence before the tail window", count, err)
	}
}
func TestNetworkAndSummaryContracts(t *testing.T) {
	s, ctx := testStore(t)
	records := []*Prepared{}
	for _, kind := range []string{"alert", "flow", "dns"} {
		p, err := ParseEvent(syntheticEvent(kind))
		if err != nil || p == nil {
			t.Fatal(err)
		}
		records = append(records, p)
	}
	if err := s.insert(ctx, records, Cursor{}); err != nil {
		t.Fatal(err)
	}
	g, err := s.Snapshot(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	network, err := networkSummary(ctx, g, 0, now()+5, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if integer(network["records"]) != 3 || integer(network["flows"]) != 1 || integer(network["bytes"]) != 300 {
		t.Fatalf("network %#v", network)
	}
	summary, err := securitySummary(ctx, g, 0, now()+5, nil, nil, true, "all", 5)
	if err != nil {
		t.Fatal(err)
	}
	if integer(summary["total"]) != 1 || integer(summary["alerts"]) != 1 {
		t.Fatal(summary)
	}
	series, err := securitySeries(ctx, g, now()-60, now(), 1, nil, nil)
	if err != nil || len(series) < 1 {
		t.Fatal(err)
	}
}
func TestSearchGrammarAndInjectionBoundary(t *testing.T) {
	for _, query := range []string{`src:"192.0.2.1" AND sport:[1 TO 65535]`, `NOT (type:alert OR type:drop)`, `sig:"a*b"`, `flow:>9007199254740993`, `src:"2001:db8::1"`, `type:(alert OR drop)`} {
		node, err := ParseHunt(query)
		if err != nil {
			t.Fatalf("parse %q: %v", query, err)
		}
		sql, args, err := compileHunt(node, true)
		if err != nil || len(sql) == 0 || len(args) == 0 {
			t.Fatalf("compile %q: %v %s", query, err, sql)
		}
	}
	for _, query := range []string{`unknown:foo`, `sig:foo OR`, `type:(alert`, `flow:9007199254740993junk`, `src:1 and dst:2`, `sig:foo^2`} {
		if _, err := ParseHunt(query); err == nil {
			t.Fatalf("accepted %q", query)
		}
	}
	node, err := ParseHunt(`sig:"'); DROP TABLE events; --"`)
	if err != nil {
		t.Fatal(err)
	}
	sql, args, err := compileHunt(node, false)
	if err != nil || strings.Contains(sql, "DROP") || len(args) != 1 {
		t.Fatal("search value crossed SQL boundary")
	}
}
func TestPasswordAndCancelledPool(t *testing.T) {
	hash, err := PasswordHash("synthetic-test-password")
	if err != nil {
		t.Fatal(err)
	}
	c := Config{PasswordPBKDF: hash}
	if !c.VerifyPassword("synthetic-test-password") || c.VerifyPassword("wrong") {
		t.Fatal("password verification")
	}
	if (Config{}).VerifyPassword("") {
		t.Fatal("unconfigured password accepted")
	}
	p := NewPool(2)
	defer p.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = parallelMap(ctx, p, []int{1, 2, 3}, func(v int) (int, error) { return v, nil })
	if err == nil {
		t.Fatal("cancelled work executed")
	}
}
func TestJSONExactInteger(t *testing.T) {
	var value Object
	if err := decode([]byte(`{"id":9007199254740993}`), &value); err != nil {
		t.Fatal(err)
	}
	if integer(value["id"]) != 9007199254740993 {
		t.Fatal("integer precision lost")
	}
	if err := decode([]byte(`{} {}`), &value); err == nil {
		t.Fatal("accepted trailing JSON")
	}
	if pythonFloat(1700000000) != "1700000000.0" {
		t.Fatal("legacy event key representation")
	}
}
func TestPoolOutputOrder(t *testing.T) {
	p := NewPool(4)
	defer p.Close()
	values, err := parallelMap(t.Context(), p, []int{3, 2, 1}, func(v int) (int, error) { time.Sleep(time.Duration(v) * time.Millisecond); return v, nil })
	if err != nil || len(values) != 3 || values[0] != 3 || values[2] != 1 {
		t.Fatal(values, err)
	}
}
