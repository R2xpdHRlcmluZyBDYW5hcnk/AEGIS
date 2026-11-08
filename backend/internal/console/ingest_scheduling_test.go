package console

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRecentIngestDoesNotSkipOrderedHistory(t *testing.T) {
	s, ctx := testStore(t)
	f, err := os.Create(s.Stream)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(append(syntheticEvent("alert"), '\n'))
	padding := []byte(strings.Repeat(" ", (1<<20)-1) + "\n")
	for range 10 {
		if _, err = f.Write(padding); err != nil {
			t.Fatal(err)
		}
	}
	f.Write(append(syntheticEvent("dns"), '\n'))
	f.WriteString("partial")
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if err = s.IngestRecent(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = s.Readers.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='dns'").Scan(&count); err != nil || count != 1 {
		t.Fatal("recent records waited behind history", count, err)
	}
	if s.cursor.Offset != 0 {
		t.Fatal("recent ingestion advanced the history cursor")
	}
	var saved string
	if err = s.Readers.QueryRowContext(ctx, "SELECT value FROM event_state WHERE key='stream_cursor'").Scan(&saved); err != sql.ErrNoRows {
		t.Fatal("recent ingestion persisted a history checkpoint", err)
	}
	// A crash discards the in-memory recent cursor; replay must remain idempotent.
	s.recentCursor = Cursor{}
	if err = s.IngestRecent(ctx); err != nil {
		t.Fatal(err)
	}
	for more := true; more; {
		more, err = s.Ingest(ctx)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err = s.Readers.QueryRowContext(ctx, "SELECT COUNT(*) FROM events").Scan(&count); err != nil || count != 2 {
		t.Fatal("history replay lost or duplicated records", count, err)
	}
	info, _ := os.Stat(s.Stream)
	if s.cursor.Offset != info.Size()-int64(len("partial")) {
		t.Fatal("checkpoint covered an incomplete line")
	}
}

func TestHistoryTransactionIsBoundedToThousandLines(t *testing.T) {
	s, ctx := testStore(t)
	var record Object
	if err := decode(syntheticEvent("alert"), &record); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(s.Stream)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 1003 {
		record["flow_id"] = i + 1
		if err = json.NewEncoder(f).Encode(record); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()
	more, err := s.Ingest(ctx)
	if err != nil || !more {
		t.Fatal(more, err)
	}
	var count int
	if err = s.Readers.QueryRowContext(ctx, "SELECT COUNT(*) FROM events").Scan(&count); err != nil || count != 1000 {
		t.Fatal("history transaction exceeded its row budget", count, err)
	}
	more, err = s.Ingest(ctx)
	if err != nil || more {
		t.Fatal(more, err)
	}
	if err = s.Readers.QueryRowContext(ctx, "SELECT COUNT(*) FROM events").Scan(&count); err != nil || count != 1003 {
		t.Fatal("bounded batches skipped records", count, err)
	}
}

func TestIngestReadFailureIsVisibleAndRecovers(t *testing.T) {
	s, _ := testStore(t)
	if err := os.Rename(s.Stream, s.Stream+".saved"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(2 * time.Second)
	for s.Error() == "" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s.Error() == "" {
		t.Fatal("read failure was reported as healthy")
	}
	if err := os.Rename(s.Stream+".saved", s.Stream); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for s.Error() != "" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s.Error() != "" {
		t.Fatal("read state did not recover after the source returned")
	}
}
