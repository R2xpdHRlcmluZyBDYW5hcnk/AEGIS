package console

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func postgresTestStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	address := os.Getenv("AEGIS_TEST_POSTGRES_URL")
	if address == "" {
		t.Skip("use build_tools/test_postgresql.py for isolated PostgreSQL regressions")
	}
	u, err := url.Parse(address)
	if err != nil || u.User.Username() != "aegis_test" || u.Path != "/aegis" || !strings.HasPrefix(u.Query().Get("host"), "/tmp/") {
		t.Fatal("refusing a non-test PostgreSQL instance")
	}
	db, err := sql.Open("pgx", address)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(t.Context(), "DROP SCHEMA IF EXISTS aegis CASCADE"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	pool := NewPool(4)
	dir := t.TempDir()
	stream := filepath.Join(dir, "events.json")
	if err = os.WriteFile(stream, nil, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewPostgresStore(filepath.Join(dir, "events.db"), stream, address, pool)
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close(); pool.Close() })
	return s, t.Context()
}

func TestPostgresBatchResumeAndRollback(t *testing.T) {
	s, ctx := postgresTestStore(t)
	if s.Ready() {
		t.Fatal("unverified ingestion was marked ready")
	}
	line := append(syntheticEvent("alert"), '\n')
	if err := os.WriteFile(s.Stream, line, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ingest(ctx); err != nil {
		t.Fatal(err)
	}
	if !s.Ready() {
		t.Fatal("committed ingestion was not marked ready")
	}
	var count int
	if err := s.Readers.QueryRowContext(ctx, "SELECT COUNT(*) FROM events").Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	s.started = false
	s.cursor = Cursor{}
	if _, err := s.Ingest(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Readers.QueryRowContext(ctx, "SELECT COUNT(*) FROM events").Scan(&count); err != nil || count != 1 {
		t.Fatal("duplicate replay", count, err)
	}
	before := s.cursor
	if _, err := s.Writer.ExecContext(ctx, "ALTER TABLE events ADD CONSTRAINT reject_dns CHECK(type<>'dns')"); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(s.Stream, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(append(syntheticEvent("dns"), '\n'))
	f.Close()
	if _, err = s.Ingest(ctx); err == nil {
		t.Fatal("rejected transaction succeeded")
	}
	if s.Ready() {
		t.Fatal("failed ingestion was marked ready")
	}
	if s.cursor != before {
		t.Fatal("cursor advanced after a failed insert")
	}
	var saved string
	if err = s.Writer.QueryRowContext(ctx, "SELECT value FROM event_state WHERE key='stream_cursor'").Scan(&saved); err != nil {
		t.Fatal(err)
	}
	var committed Cursor
	decode([]byte(saved), &committed)
	if committed != before {
		t.Fatal("persistent cursor changed on failure")
	}
	if _, err = s.Writer.ExecContext(ctx, "ALTER TABLE events DROP CONSTRAINT reject_dns"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Ingest(ctx); err != nil {
		t.Fatal(err)
	}
	if err = s.Readers.QueryRowContext(ctx, "SELECT COUNT(*) FROM events").Scan(&count); err != nil || count != 2 {
		t.Fatal(count, err)
	}
	if _, err = s.Readers.ExecContext(ctx, "DELETE FROM events"); err == nil {
		t.Fatal("reader modified protected events")
	}
	var statementTimeout, idleTimeout string
	if err = s.Readers.QueryRowContext(ctx, "SELECT current_setting('statement_timeout'),current_setting('idle_in_transaction_session_timeout')").Scan(&statementTimeout, &idleTimeout); err != nil || statementTimeout != "0" || idleTimeout != "0" {
		t.Fatal("background query lifetime was limited", statementTimeout, idleTimeout, err)
	}
	interrupted, interrupt := context.WithTimeout(ctx, 100*time.Millisecond)
	defer interrupt()
	if _, err = s.Readers.ExecContext(interrupted, "SELECT pg_sleep(10)"); err == nil || interrupted.Err() == nil {
		t.Fatal("running background query ignored cancellation", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = s.Readers.QueryContext(cancelled, "SELECT * FROM events"); err == nil {
		t.Fatal("cancelled request ran")
	}
}

func TestPostgresCopiesNumericAndBooleanTextWithoutChangingEvidence(t *testing.T) {
	s, ctx := postgresTestStore(t)
	var raw Object
	decode(syntheticEvent("alert"), &raw)
	raw["snort_native"] = Object{"tenant_id": 0, "session_limited": true}
	object(raw["alert"])["signature"] = "Synthetic\x00indicator"
	data, _ := json.Marshal(raw)
	record, err := ParseEvent(data)
	if err != nil || record == nil {
		t.Fatal(err)
	}
	if err = s.insertBatch(ctx, []*Prepared{record}, nil); err != nil {
		t.Fatal(err)
	}
	rows, err := queryRows(ctx, s.Readers, "SELECT * FROM events")
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	if rows[0]["tenant_id"] != "0" || rows[0]["session_limited"] != "1" {
		t.Fatal("text affinity was not preserved")
	}
	evidence, err := decompress(rows[0]["raw"].([]byte))
	if err != nil || string(evidence) != string(data) {
		t.Fatal("raw evidence changed")
	}
	if strings.Contains(text(rows[0]["sig"]), "\x00") {
		t.Fatal("NUL entered a PostgreSQL text value")
	}
}

func TestPostgresQueryAndColumnstoreContracts(t *testing.T) {
	s, ctx := postgresTestStore(t)
	records := []*Prepared{}
	for i, kind := range []string{"alert", "drop", "flow", "dns", "tls"} {
		var raw Object
		decode(syntheticEvent(kind), &raw)
		raw["flow_id"] = i + 1
		raw["timestamp"] = utc(now() - 3*3600 + float64(i))
		raw["snort_native"] = Object{"session_id": strings.Repeat("a", 32) + ":0000000000000001"}
		object(raw["alert"])["metadata"] = Object{"mitre_tactic_id": []any{"TA0001"}, "mitre_technique_name": []any{"PowerShell"}}
		data, _ := json.Marshal(raw)
		p, err := ParseEvent(data)
		if err != nil || p == nil {
			t.Fatal(err)
		}
		records = append(records, p)
	}
	if err := s.insertBatch(ctx, records, nil); err != nil {
		t.Fatal(err)
	}
	g, err := s.Snapshot(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	low, high := now()-24*3600, now()+1
	total, rows, err := search(ctx, g, low, high, nil, nil, 50, 0, true, false, false)
	if err != nil || total != 5 || len(rows) != 5 {
		t.Fatal("search", total, err)
	}
	if _, err = securitySummary(ctx, g, low, high, nil, nil, true, "", 8); err != nil {
		t.Fatal("security", err)
	}
	if _, err = networkSummary(ctx, g, low, high, nil, nil); err != nil {
		t.Fatal("network", err)
	}
	if _, err = securitySeries(ctx, g, low, high, 60, nil, nil); err != nil {
		t.Fatal("series", err)
	}
	if _, err = incidents(ctx, g, url.Values{}, low, high, "", 8); err != nil {
		t.Fatal("incidents", err)
	}
	for _, query := range []string{"NOT type:dns", "src:192.0.2.0/24", "sig:*indicator*", "mitre_tactic_id:TA0001", "mitre_technique_name:*shell*", "sport:>=1000", "NOT app:*"} {
		node, e := ParseHunt(query)
		if e != nil {
			t.Fatal(e)
		}
		part, args, e := compileHunt(node, true)
		if e != nil {
			t.Fatal(e)
		}
		if _, _, e = search(ctx, g, low, high, []string{part}, args, 50, 0, true, false, false); e != nil {
			t.Fatal(query, e)
		}
	}
	g.Close()
	if _, err = s.Record(ctx, text(rows[0]["record_id"])); err != nil {
		t.Fatal("record", err)
	}
	chunks, err := queryRows(ctx, s.Readers, "SELECT chunk_schema,chunk_name FROM timescaledb_information.chunks WHERE hypertable_schema='aegis' AND hypertable_name='events'")
	if err != nil {
		t.Fatal(err)
	}
	for _, chunk := range chunks {
		name := text(chunk["chunk_schema"]) + "." + text(chunk["chunk_name"])
		if _, err = s.Writer.ExecContext(ctx, "CALL convert_to_columnstore($1::regclass)", name); err != nil {
			t.Fatal("columnstore", err)
		}
	}
	if err = s.insertBatch(ctx, records, nil); err != nil {
		t.Fatal("compressed chunk replay", err)
	}
	var count int
	if err = s.Readers.QueryRowContext(ctx, "SELECT COUNT(*) FROM events").Scan(&count); err != nil || count != 5 {
		t.Fatal("compressed events changed", count, err)
	}
	if _, err = s.Stats(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Writer.ExecContext(ctx, "SELECT pg_sleep(0)"); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresSQLParametersAreNotInterpolated(t *testing.T) {
	q := eventSQL("SELECT '?' AS literal,ts FROM events WHERE ts>=? AND sig=?", true)
	if !strings.Contains(q, "'?' AS literal") || !strings.Contains(q, "sig=$2") || !strings.Contains(q, "event_time >= to_timestamp($1") {
		t.Fatal(q)
	}
	if eventSQL("SELECT 'a.ts=e.ts'", true) != "SELECT 'a.ts=e.ts'" {
		t.Fatal("mirror predicate changed quoted text")
	}
}

func TestPostgresIncidentPagesWithMirroredHistory(t *testing.T) {
	s, ctx := postgresTestStore(t)
	stamp := float64(time.Now().Unix()-1800) * 1000
	// Many records share a session, with nullable mirror fields and a separate
	// suppressed enforcement record. Page enrichment must retain both contracts.
	_, err := s.Writer.ExecContext(ctx, `INSERT INTO events(event_key,event_time,ts,type,session_id,sev,sid,sig,gid,action,alert_suppressed)
SELECT repeat(md5(g::text||':'||k::text||':'||v::text),2),to_timestamp(($1::double precision+g*10+k)/1000),$1::double precision+g*10+k,
CASE WHEN v=0 THEN 'alert' ELSE 'drop' END,repeat('a',32)||':'||lpad(to_hex(g),16,'0'),1,k,'Signature '||k,1,
CASE WHEN v=2 THEN 'blocked' ELSE 'allowed' END,CASE WHEN v=2 THEN 1 ELSE 0 END
FROM generate_series(1,1000) g CROSS JOIN generate_series(1,4) k CROSS JOIN generate_series(0,2) v`, stamp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Writer.ExecContext(ctx, "ANALYZE events"); err != nil {
		t.Fatal(err)
	}
	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	g, err := s.Snapshot(queryCtx, true)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	started := time.Now()
	result, err := incidents(queryCtx, g, url.Values{"offset": {"50"}}, stamp/1000-1, stamp/1000+11, "", 3)
	if err != nil {
		t.Fatal(err)
	}
	rows := result["incidents"].([]Object)
	if integer(result["total"]) != 1000 || len(rows) != 50 {
		t.Fatal("page cardinality", result["total"], len(rows))
	}
	for _, row := range rows {
		if integer(row["alert_count"]) != 4 || integer(row["signature_count"]) != 4 || row["action"] != "blocked" || len(row["signatures"].([]Object)) != 3 {
			t.Fatal("batched enrichment changed incident evidence")
		}
	}
	var planJSON []byte
	if err = g.main.QueryRowContext(queryCtx, "EXPLAIN (ANALYZE,FORMAT JSON) SELECT COUNT(*)"+securitySource(" WHERE ts>=? AND ts<=? AND type IN ('alert','drop')", true), stamp-1, stamp+11000).Scan(&planJSON); err != nil {
		t.Fatal(err)
	}
	var plan any
	if err = json.Unmarshal(planJSON, &plan); err != nil {
		t.Fatal(err)
	}
	indexedMirror := false
	var inspect func(any)
	inspect = func(value any) {
		switch node := value.(type) {
		case map[string]any:
			condition := text(node["Index Cond"])
			if strings.Contains(condition, "session_id = e.session_id") && strings.Contains(condition, "ts = e.ts") {
				indexedMirror = true
			}
			for _, child := range node {
				inspect(child)
			}
		case []any:
			for _, child := range node {
				inspect(child)
			}
		}
	}
	inspect(plan)
	if !indexedMirror {
		t.Fatal("mirror lookup did not use session and timestamp index conditions")
	}
	t.Logf("sessions=1000 history_rows=12000 page_rows=%d elapsed=%s", len(rows), time.Since(started))
}

func TestPostgresExternalReplay(t *testing.T) {
	path := os.Getenv("AEGIS_LOCAL_EVENT_REPLAY")
	if path == "" {
		t.Skip("local event copy not requested")
	}
	if !filepath.IsAbs(path) || !strings.HasPrefix(filepath.Clean(path), "/tmp/aegis-event-replay-") {
		t.Fatal("event replay must use a dedicated system temporary directory")
	}
	s, ctx := postgresTestStore(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("local event copy unavailable")
	}
	if len(data) > 8<<20 {
		t.Fatal("event replay exceeds byte budget")
	}
	edge := bytesLastNewline(data)
	if edge < 0 {
		t.Fatal("no complete event records")
	}
	records, err := s.prepareBlock(ctx, boundedEventBlock(data[:edge+1], 1000))
	if err != nil {
		t.Fatalf("event preparation failed (%T)", err)
	}
	t.Logf("prepared_records=%d", len(records))
	types := map[string]string{}
	for _, record := range records {
		for i, name := range columnNames() {
			value := record.Values[i]
			if value != nil && !numericColumns[name] && name != "raw" {
				if _, ok := value.(string); !ok {
					types[name] = fmt.Sprintf("%T", value)
				}
			}
		}
	}
	t.Logf("non_string_text_types=%v", types)
	if err = s.insertBatch(ctx, records, nil); err != nil {
		t.Fatalf("event COPY replay failed (%T)", err)
	}
	var count int64
	if err = s.Readers.QueryRowContext(ctx, "SELECT COUNT(*) FROM events").Scan(&count); err != nil || count == 0 {
		t.Fatal("local replay did not persist events")
	}
	g, err := s.Snapshot(ctx, true)
	if err != nil {
		t.Fatalf("replay snapshot failed (%T)", err)
	}
	defer g.Close()
	if _, err = networkSummary(ctx, g, 0, now()+1, nil, nil); err != nil {
		t.Fatalf("replay network query failed (%T)", err)
	}
	if _, err = securitySummary(ctx, g, 0, now()+1, nil, nil, true, "", 8); err != nil {
		t.Fatalf("replay security query failed (%T)", err)
	}
	if _, err = incidents(ctx, g, url.Values{}, 0, now()+1, "", 3); err != nil {
		t.Fatalf("replay incident query failed (%T)", err)
	}
	t.Logf("persisted_records=%d", count)
}

func TestPostgresHistorySwitchPreservesSettingsAndCanRollBack(t *testing.T) {
	s, ctx := postgresTestStore(t)
	line := append(syntheticEvent("alert"), '\n')
	os.WriteFile(s.Stream, line, 0600)
	if _, err := s.Ingest(ctx); err != nil {
		t.Fatal(err)
	}
	address, path, stream, pool := s.DatabaseURL, s.Path, s.Stream, s.Pool
	if err := writeJSON(path+".settings.json", Object{"cap_mib": 128}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	archive, err := resetPostgresHistory(ctx, address, stream)
	if err != nil || !postgresArchive.MatchString(archive) {
		t.Fatal(archive, err)
	}
	fresh, err := NewPostgresStore(path, stream, address, pool)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Cap != 128<<20 {
		t.Fatal("capacity setting was lost")
	}
	if _, err = fresh.Ingest(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = fresh.Readers.QueryRowContext(ctx, "SELECT COUNT(*) FROM events").Scan(&count); err != nil || count != 0 {
		t.Fatal("retired stream replayed", count, err)
	}
	fresh.Close()
	if err = restorePostgresHistory(ctx, address, archive); err != nil {
		t.Fatal(err)
	}
	restored, err := NewPostgresStore(path, stream, address, pool)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if err = restored.Readers.QueryRowContext(ctx, "SELECT COUNT(*) FROM events").Scan(&count); err != nil || count != 1 {
		t.Fatal("rollback lost events", count, err)
	}
}
