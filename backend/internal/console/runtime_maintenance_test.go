package console

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func quicTestRow(frame int, reverse, hello bool, port int) string {
	row := make([]string, len(quicCaptureFields))
	row[0] = strconv.Itoa(frame)
	row[1] = strconv.Itoa(1700000000 + frame)
	row[2], row[4], row[5], row[7] = "192.0.2.10", strconv.Itoa(port), "198.51.100.20", "443"
	row[8], row[9] = "108", "0"
	row[10], row[11] = strings.Repeat("bb", 8), strings.Repeat("aa", 8)
	row[12] = "0x00000001"
	if reverse {
		row[2], row[5] = row[5], row[2]
		row[4], row[7] = row[7], row[4]
		row[10], row[11] = row[11], row[10]
	}
	if hello {
		row[13], row[14], row[15] = "1", "example.test", "h3"
	}
	var out bytes.Buffer
	writer := csv.NewWriter(&out)
	writer.Comma = '\t'
	writer.Write(row)
	writer.Flush()
	return out.String()
}

func TestQuicNativePipelineKeepsOrderAndVisibleDirection(t *testing.T) {
	source := quicTestRow(1, false, true, 45000) + quicTestRow(2, true, false, 45000) + quicTestRow(3, false, false, 45001)
	var previous []byte
	for _, workers := range []int{1, 4} {
		events := []Object{}
		tracker := newQuicTracker(func(value Object) error {
			data, _ := json.Marshal(value)
			var copy Object
			decode(data, &copy)
			events = append(events, copy)
			return nil
		})
		tracker.prefix = strings.Repeat("a", 32)
		if err := readQuicObservations(t.Context(), strings.NewReader(source), tracker, workers); err != nil {
			t.Fatal(err)
		}
		if err := tracker.close("observer_stopped"); err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(events)
		if previous != nil && !bytes.Equal(data, previous) {
			t.Fatal("parallel parse reordered evidence")
		}
		previous = data
		last := object(events[len(events)-1]["data"])
		if integer(last["a_packets"]) != 2 || integer(last["b_packets"]) != 1 || len(array(last["paths"])) != 2 || last["sni"] != "example.test" {
			t.Fatal(last)
		}
		raw, _ := json.Marshal(events[len(events)-1])
		prepared, err := ParseEvent(raw)
		if err != nil || prepared == nil || prepared.Record["type"] != "quic" || prepared.Record["sni"] != "example.test" {
			t.Fatal(err, prepared)
		}
	}
}

func TestQuicDecoderResetCapacityAndOutputFailure(t *testing.T) {
	events := []Object{}
	tracker := newQuicTracker(func(value Object) error { events = append(events, value); return nil })
	tracker.capacity = 1
	p, _ := parseQuicPacket(quicTestRow(1, false, true, 45000))
	if err := tracker.observe(p); err != nil {
		t.Fatal(err)
	}
	p.frame = 2
	p.connection = "1"
	tracker.observe(p)
	p.frame = 1
	p.connection = ""
	tracker.observe(p)
	if len(tracker.states) != 0 {
		t.Fatal("non-QUIC reset marker ignored")
	}
	p.frame = 2
	p.connection = "0"
	tracker.observe(p)
	tracker.close("observer_stopped")
	ids := map[string]bool{}
	for _, event := range events {
		ids[text(object(event["data"])["session_id"])] = true
	}
	if len(ids) != 3 {
		t.Fatal("reset reused source identity", ids)
	}
	input, writer := io.Pipe()
	defer writer.Close()
	go func() { writer.Write([]byte(quicTestRow(1, false, true, 45000))) }()
	failed := newQuicTracker(func(Object) error { return errors.New("write failure") })
	done := make(chan error, 1)
	go func() { done <- readQuicObservations(t.Context(), input, failed, 4) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("output failure hidden")
		}
	case <-time.After(2 * time.Second):
		input.Close()
		t.Fatal("pipeline did not cancel")
	}
}

func TestHomeNetKeepsManualPrefixesAndRollsBackFailedReload(t *testing.T) {
	root := t.TempDir()
	r := homeNetRuntime{home: filepath.Join(root, "home-net.lua"), state: filepath.Join(root, "state.json"), config: filepath.Join(root, "snort.lua"), validation: filepath.Join(root, "validation")}
	source := "HOME_NET = '[192.0.2.0/24,2001:db8:1::/64]'\n"
	os.WriteFile(r.home, []byte(source), 0644)
	os.WriteFile(r.config, []byte("include '"+r.home+"'\n"), 0600)
	writeJSON(r.state, []string{"2001:db8:1::/64"})
	r.addresses = func(context.Context, string) ([]byte, error) {
		return []byte(`[{"addr_info":[{"scope":"global","local":"2001:db8:2::1","prefixlen":64}]}]`), nil
	}
	r.validate = func(ctx context.Context, path string) error {
		if !strings.Contains(readText(path), "home-net-") {
			t.Fatal("candidate not isolated")
		}
		return nil
	}
	calls := 0
	r.reload = func(ctx context.Context) error {
		calls++
		if calls == 1 {
			return errors.New("reload failed")
		}
		if ctx.Err() != nil {
			t.Fatal("rollback reused failed context")
		}
		return nil
	}
	if _, err := r.refresh(t.Context(), "eth0"); err == nil || calls != 2 || readText(r.home) != source {
		t.Fatal("HOME_NET rollback failed", err, calls)
	}
	r.reload = func(context.Context) error { return nil }
	changed, err := r.refresh(t.Context(), "eth0")
	if err != nil || !changed || readText(r.home) != "HOME_NET = '[192.0.2.0/24,2001:db8:2::/64]'\n" {
		t.Fatal(readText(r.home), err)
	}
	if changed, err = r.refresh(t.Context(), "eth0"); err != nil || changed {
		t.Fatal("unchanged prefix reloaded", err)
	}
}

func TestRecoveryIndexRebuildSealsOriginalsAndPreservesValues(t *testing.T) {
	root := t.TempDir()
	snapshot := filepath.Join(root, "snapshot")
	original := filepath.Join(snapshot, "original")
	os.MkdirAll(original, 0700)
	source := filepath.Join(original, "events.db")
	db, err := recoveryDatabase(source, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE events(id INTEGER PRIMARY KEY,ts NUMERIC,payload TEXT,blob BLOB); INSERT INTO events VALUES(7,1.25,CAST(X'6100ff27' AS TEXT),X''); CREATE INDEX idx_ts ON events(ts); CREATE TABLE settings(id INTEGER PRIMARY KEY AUTOINCREMENT,value TEXT); INSERT INTO settings(value) VALUES('retained'); PRAGMA user_version=13;`)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := digestFile(source)
	info, _ := os.Stat(source)
	writeJSON(filepath.Join(snapshot, "snapshot.json"), Object{"database_path": "/var/lib/ips-web/events.db", "files": Object{"events.db": Object{"bytes": info.Size(), "sha256": hash}}})
	report, err := RecoverEventDatabase(t.Context(), snapshot, filepath.Join(root, "recovered"), "", "", true)
	if err != nil || report["all_table_values_preserved"] != true || report["activation_performed"] != false {
		t.Fatal(report, err)
	}
	if current, _ := digestFile(source); current != hash {
		t.Fatal("sealed source changed")
	}
	result, err := sql.Open("aegis-sqlite", recoveryDSN(filepath.Join(root, "recovered/candidate.db"), true))
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	var payload []byte
	var version int
	if err = result.QueryRow("SELECT CAST(payload AS BLOB) FROM events WHERE id=7").Scan(&payload); err != nil || !bytes.Equal(payload, []byte{'a', 0, 255, '\''}) {
		t.Fatal(payload, err)
	}
	result.QueryRow("PRAGMA user_version").Scan(&version)
	if version != 13 {
		t.Fatal(version)
	}
	if _, err = RecoverEventDatabase(t.Context(), snapshot, filepath.Join(snapshot, "unsafe"), "", "", true); err == nil {
		t.Fatal("output inside source accepted")
	}
	os.WriteFile(source, []byte("tampered"), 0600)
	if _, err = RecoverEventDatabase(t.Context(), snapshot, filepath.Join(root, "bad"), "", "", true); err == nil {
		t.Fatal("unsealed source accepted")
	}
}

func TestRecoverySQLStreamingPreservesDamagedTextAndRejectsIncompleteSQL(t *testing.T) {
	db, err := recoveryDatabase(filepath.Join(t.TempDir(), "events.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.Exec("CREATE TABLE events(id,payload)")
	input := bytes.NewReader([]byte("INSERT INTO events VALUES(1,'a\x00\xff''b\nnext');\n"))
	err = relayRecoveredSQL(input, func(statement []byte) error { _, err := db.Exec(string(statement)); return err })
	if err != nil {
		t.Fatal(err)
	}
	var value []byte
	if err = db.QueryRow("SELECT CAST(payload AS BLOB) FROM events").Scan(&value); err != nil || !bytes.Equal(value, []byte("a\x00\xff'b\nnext")) {
		t.Fatal(value, err)
	}
	if err = relayRecoveredSQL(strings.NewReader("INSERT INTO events VALUES('unfinished"), func([]byte) error { return nil }); err == nil {
		t.Fatal("partial recovery accepted")
	}
	if err = relayRecoveredSQL(strings.NewReader(".shell unexpected\n"), func([]byte) error { return nil }); err == nil {
		t.Fatal("shell directive accepted")
	}
}

func TestNftLibraryReadOnlyABI(t *testing.T) {
	_, err, available := nftLibraryCommand("list table inet aegis_absent_readonly_fixture", true)
	if !available {
		t.Skip("system libnftables unavailable; CLI fallback remains enabled")
	}
	if err == nil {
		t.Fatal("absent test table unexpectedly exists")
	}
}

func TestRecoveryWithVerifiedSQLiteCLI(t *testing.T) {
	cli := os.Getenv("AEGIS_SQLITE_CLI")
	if cli == "" {
		t.Skip("verified local recovery tool not provided")
	}
	root := t.TempDir()
	snapshot := filepath.Join(root, "snapshot")
	original := filepath.Join(snapshot, "original")
	os.MkdirAll(original, 0700)
	source := filepath.Join(original, "events.db")
	db, err := recoveryDatabase(source, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("CREATE TABLE events(id INTEGER PRIMARY KEY,ts NUMERIC,payload TEXT); INSERT INTO events VALUES(1,1.25,CAST(X'6100ff27' AS TEXT)); CREATE TABLE settings(id INTEGER PRIMARY KEY AUTOINCREMENT,value TEXT); INSERT INTO settings(value) VALUES('retained');")
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := digestFile(source)
	info, _ := os.Stat(source)
	writeJSON(filepath.Join(snapshot, "snapshot.json"), Object{"database_path": "/var/lib/ips-web/events.db", "files": Object{"events.db": Object{"bytes": info.Size(), "sha256": hash}}})
	report, err := RecoverEventDatabase(t.Context(), snapshot, filepath.Join(root, "recovered"), cli, "", false)
	if err != nil || integer(object(report["table_counts"])["events"]) != 1 {
		t.Fatal(report, err)
	}
	if current, _ := digestFile(source); current != hash {
		t.Fatal("page recovery changed original")
	}
}
