package console

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type historyFixture struct {
	root, state, web, database, checkpoint string
	runtime                                historyRuntime
	active                                 map[string]bool
	writers                                map[string]*os.File
	calls                                  [][]string
	job                                    string
}

func newHistoryFixture(t *testing.T) *historyFixture {
	t.Helper()
	f := &historyFixture{root: filepath.Join(t.TempDir(), "logs"), state: t.TempDir(), web: t.TempDir(), active: map[string]bool{}, writers: map[string]*os.File{}, job: strings.Repeat("a", 32)}
	for _, dir := range []string{filepath.Join(f.root, "snort"), filepath.Join(f.root, "events")} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	f.database, f.checkpoint = filepath.Join(f.web, "snort-ndr.db"), filepath.Join(t.TempDir(), "offsets.json")
	for _, path := range []string{f.database, f.checkpoint, filepath.Join(f.root, "events/events.json"), filepath.Join(f.web, "settings.json")} {
		if err := os.WriteFile(path, []byte("old history\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"0_file_connector_ndr_transmit", "0_alert_json.txt", "0_ndr_session.json"} {
		path := filepath.Join(f.root, "snort", name)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			t.Fatal(err)
		}
		file.WriteString("old raw history\n")
		f.writers[path] = file
	}
	t.Cleanup(func() {
		for _, file := range f.writers {
			file.Close()
		}
	})
	for _, unit := range []string{"ips-web", "ips-event-bridge", "ips-quic-observer", "ips-log-maintenance.timer", "snort-home-net.timer"} {
		f.active[unit] = true
	}
	f.runtime = historyRuntime{
		root: f.root, web: f.web, checkpoint: f.checkpoint,
		identity: func() (string, int, error) { return "same detector", os.Getpid(), nil },
		manager:  func(ctx context.Context, op string, body Object) (any, error) { return Object{"ok": true}, ctx.Err() },
		ready:    func(context.Context) bool { return true },
	}
	f.runtime.command = func(ctx context.Context, timeout time.Duration, args ...string) (string, error) {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		f.calls = append(f.calls, append([]string{}, args...))
		for _, arg := range args {
			if arg == "ips" {
				t.Fatal("history reset touched the detection service")
			}
		}
		switch args[1] {
		case "is-active":
			if !f.active[args[len(args)-1]] {
				return "", errors.New("inactive")
			}
		case "stop", "start":
			for _, unit := range args[2:] {
				if _, tracked := f.active[unit]; tracked {
					f.active[unit] = args[1] == "start"
				}
			}
		case "show":
			return "0\n", nil
		}
		return "", nil
	}
	f.runtime.engine = func(ctx context.Context, command string, timeout time.Duration) (string, error) {
		switch command {
		case "help()":
			return "snort.reopen_logs()", nil
		case "reopen_logs()":
			if readText(f.database) != "old history\n" {
				t.Fatal("event database changed before log handoff")
			}
			for path, old := range f.writers {
				old.WriteString("flushed old buffer\n")
				old.Close()
				next, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0644)
				if err != nil {
					return "", err
				}
				next.WriteString("new traffic\n")
				f.writers[path] = next
			}
			return "NDR_LOGS_REOPENED threads=4", nil
		case "show_config_generation()":
			return "configuration id: 1", nil
		default:
			t.Fatal("history reset paused or reconfigured the engine", command)
		}
		return "", nil
	}
	if err := writeJSON(filepath.Join(f.state, "history-reset.json"), Object{"id": f.job, "scope": "all", "state": "queued"}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *historyFixture) run(ctx context.Context) error {
	return runHistoryReset(ctx, f.state, f.job, f.runtime)
}

func TestLiveHistoryResetPreservesDetectorAndNewLogTraffic(t *testing.T) {
	f := newHistoryFixture(t)
	if err := f.run(t.Context()); err != nil {
		t.Fatal(err)
	}
	for path := range f.writers {
		if readText(path) != "new traffic\n" {
			t.Fatal("new traffic removed or old buffered traffic leaked")
		}
	}
	if fileExists(f.checkpoint) {
		t.Fatal("old bridge checkpoint survived")
	}
	if readText(filepath.Join(f.web, "settings.json")) != "old history\n" {
		t.Fatal("settings changed")
	}
	db, err := sql.Open("aegis-sqlite", f.database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var epoch string
	if err = db.QueryRow("SELECT value FROM event_state WHERE key='clear_epoch'").Scan(&epoch); err != nil || epoch == "" {
		t.Fatal("new event generation missing", err)
	}
	var state Object
	readJSON(filepath.Join(f.state, "history-reset.json"), &state)
	if state["state"] != "done" || state["engine_preserved"] != true {
		t.Fatal("reset not confirmed", state)
	}
	if backups, _ := filepath.Glob(filepath.Join(f.root, ".history-reset-*")); len(backups) != 0 {
		t.Fatal("retired logs retained after successful full clear")
	}
	if backups, _ := filepath.Glob(filepath.Join(f.web, "history-backup-*")); len(backups) != 0 {
		t.Fatal("old database retained after successful full clear")
	}
	for unit, active := range f.active {
		if !active {
			t.Fatal("service or timer not restored", unit)
		}
	}
}

func TestHistoryResetRejectsOldEngineBeforeStoppingServices(t *testing.T) {
	f := newHistoryFixture(t)
	f.runtime.engine = func(context.Context, string, time.Duration) (string, error) { return "old shell", nil }
	if err := f.run(t.Context()); err == nil {
		t.Fatal("unsupported engine accepted")
	}
	if len(f.calls) != 0 || readText(f.database) != "old history\n" {
		t.Fatal("unsupported engine changed running state or history")
	}
}

func TestHistoryResetRejectsCoveredStorageBeforeStoppingServices(t *testing.T) {
	f := newHistoryFixture(t)
	f.runtime.validate = func() error { return errors.New("covered storage") }
	if err := f.run(t.Context()); err == nil {
		t.Fatal("covered log storage accepted")
	}
	if len(f.calls) != 0 || readText(f.database) != "old history\n" {
		t.Fatal("storage failure affected services or history")
	}
}

func TestHistoryResetDoesNotUnlinkUnreleasedWriter(t *testing.T) {
	f := newHistoryFixture(t)
	engine := f.runtime.engine
	f.runtime.engine = func(ctx context.Context, command string, timeout time.Duration) (string, error) {
		if command == "reopen_logs()" {
			return "NDR_LOGS_REOPENED threads=4", nil
		}
		return engine(ctx, command, timeout)
	}
	if err := f.run(t.Context()); err == nil || !strings.Contains(err.Error(), "仍持有旧日志") {
		t.Fatal("unreleased descriptor accepted", err)
	}
	if readText(f.database) != "old history\n" {
		t.Fatal("database erased before writer confirmation")
	}
	for _, file := range f.writers {
		info, err := file.Stat()
		if err != nil || info.Size() == 0 {
			t.Fatal("old evidence lost", err)
		}
	}
	for unit, active := range f.active {
		if !active {
			t.Fatal("failure did not restore service", unit)
		}
	}
}

func TestHistoryResetFailureAndCancellationRecoverWithFreshContext(t *testing.T) {
	for _, fault := range []string{"stop", "reopen", "identity", "cancel"} {
		t.Run(fault, func(t *testing.T) {
			f := newHistoryFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			command, engine, identity := f.runtime.command, f.runtime.engine, f.runtime.identity
			if fault == "stop" {
				f.runtime.command = func(ctx context.Context, timeout time.Duration, args ...string) (string, error) {
					if len(args) > 2 && args[1] == "stop" && args[2] == "ips-web" {
						return "", errors.New("synthetic stop failure")
					}
					return command(ctx, timeout, args...)
				}
			}
			f.runtime.engine = func(ctx context.Context, request string, timeout time.Duration) (string, error) {
				if request == "reopen_logs()" && fault == "reopen" {
					return "NDR_LOGS_REOPEN_FAILED", nil
				}
				if request == "reopen_logs()" && fault == "cancel" {
					cancel()
					return "", ctx.Err()
				}
				return engine(ctx, request, timeout)
			}
			calls := 0
			f.runtime.identity = func() (string, int, error) {
				calls++
				if fault == "identity" && calls > 1 {
					return "replaced detector", os.Getpid(), nil
				}
				return identity()
			}
			if err := f.run(ctx); err == nil {
				t.Fatal("fault accepted")
			}
			if readText(f.database) != "old history\n" {
				t.Fatal("failed operation erased event database")
			}
			var state Object
			readJSON(filepath.Join(f.state, "history-reset.json"), &state)
			if state["state"] != "failed" {
				t.Fatal("failure status missing")
			}
			for unit, active := range f.active {
				if !active {
					t.Fatal("service not recovered", unit)
				}
			}
		})
	}
}

func TestHistoryDatabaseMoveFailurePreservesUnmovedWAL(t *testing.T) {
	f := newHistoryFixture(t)
	for _, suffix := range []string{"-wal", "-shm", ".summary.db"} {
		os.WriteFile(f.database+suffix, []byte("original"), 0600)
	}
	move := func(from, to string) error {
		if strings.HasSuffix(from, "-wal") {
			return errors.New("synthetic move failure")
		}
		return os.Rename(from, to)
	}
	if _, err := switchHistoryDatabase(f.database, filepath.Join(f.root, "events/events.json"), f.web, move); err == nil {
		t.Fatal("failed move accepted")
	}
	if readText(f.database) != "old history\n" {
		t.Fatal("original database not restored")
	}
	for _, suffix := range []string{"-wal", "-shm", ".summary.db"} {
		if readText(f.database+suffix) != "original" {
			t.Fatal("unmoved database member lost", suffix)
		}
	}
}

func TestHistoryMaintenanceLeaseRequiresRootAndSingleStart(t *testing.T) {
	m := testManager(t)
	id := strings.Repeat("b", 32)
	m.paused = true
	writeJSON(filepath.Join(m.state, "history-reset.json"), Object{"id": id, "state": "queued"})
	request := Object{"operation": "history-reset-begin", "job": id}
	if _, err := m.Dispatch(t.Context(), request, false); err == nil {
		t.Fatal("non-root maintenance accepted")
	}
	if _, err := m.Dispatch(t.Context(), request, true); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Dispatch(t.Context(), request, true); err == nil {
		t.Fatal("duplicate maintenance worker accepted")
	}
}

func TestHistoryResetRejectsSymlinkBeforeStoppingServices(t *testing.T) {
	for _, target := range []string{"native", "checkpoint", "wal"} {
		t.Run(target, func(t *testing.T) {
			f := newHistoryFixture(t)
			path := filepath.Join(f.root, "snort/1_alert_json.txt")
			if target == "checkpoint" {
				path = f.checkpoint
				os.Remove(path)
			}
			if target == "wal" {
				path = f.database + "-wal"
			}
			if err := os.Symlink(filepath.Join(f.web, "settings.json"), path); err != nil {
				t.Fatal(err)
			}
			if err := f.run(t.Context()); err == nil {
				t.Fatal("unsafe history target accepted")
			}
			if len(f.calls) != 0 || readText(f.database) != "old history\n" || readText(filepath.Join(f.web, "settings.json")) != "old history\n" {
				t.Fatal("unsafe target affected services or protected state")
			}
		})
	}
}

func TestHistoryResetDoesNotReportDoneWhenMaintenanceReleaseFails(t *testing.T) {
	f := newHistoryFixture(t)
	finish := 0
	f.runtime.manager = func(ctx context.Context, op string, body Object) (any, error) {
		if op == "history-reset-finish" {
			finish++
			if finish == 1 {
				return nil, errors.New("synthetic manager outage")
			}
		}
		return Object{"ok": true}, nil
	}
	if err := f.run(t.Context()); err == nil {
		t.Fatal("maintenance failure hidden")
	}
	var value Object
	readJSON(filepath.Join(f.state, "history-reset.json"), &value)
	if value["state"] != "failed" || finish != 2 {
		t.Fatal("maintenance failure status or release retry missing")
	}
}

func TestBridgeKeepsVerifiedCursorAcrossEngineRestart(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "snort")
	os.Mkdir(logs, 0700)
	instance := filepath.Join(root, "instance.json")
	writeJSON(instance, Object{"epoch": strings.Repeat("c", 32), "started": 1})
	source := filepath.Join(logs, "0_file_connector_ndr_transmit")
	line := "{\"ts\":1794009600,\"trans_id\":1,\"query\":\"old.example.test\"}\n"
	os.WriteFile(source, []byte(line), 0600)
	pool := NewPool(4)
	defer pool.Close()
	output, checkpoint := filepath.Join(root, "events.json"), filepath.Join(root, "offsets.json")
	bridge, err := NewBridge(logs, output, checkpoint, instance, pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bridge.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(source, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	file.WriteString(strings.ReplaceAll(line, "old.example.test", "unread.example.test"))
	file.Close()
	writeJSON(instance, Object{"epoch": strings.Repeat("d", 32), "started": now() + 10})
	bridge, err = NewBridge(logs, output, checkpoint, instance, pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bridge.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	text := readText(output)
	if strings.Count(text, "old.example.test") != 1 || strings.Count(text, "unread.example.test") != 1 {
		t.Fatal("engine restart replayed consumed records or skipped pending input")
	}
	// Old engines may truncate and rapidly regrow the same inode. The tail
	// digest must still invalidate a cursor even when the new file is longer.
	replacement := strings.ReplaceAll(line, "old.example.test", "replacement.example.test")
	os.WriteFile(source, []byte(replacement+replacement), 0600)
	writeJSON(instance, Object{"epoch": strings.Repeat("e", 32), "started": now() + 20})
	if _, err = bridge.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if strings.Count(readText(output), "replacement.example.test") != 2 {
		t.Fatal("stale cross-epoch cursor survived truncate-and-regrow")
	}
}

func TestHistoryResetAcceptsSystemdPrivateStateAliasOnly(t *testing.T) {
	root := t.TempDir()
	actual := filepath.Join(root, "private", "web")
	alias := filepath.Join(root, "web")
	os.MkdirAll(actual, 0700)
	if err := os.Symlink(actual, alias); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(alias, "snort-ndr.db")
	os.WriteFile(database, []byte("old database"), 0600)
	stream := filepath.Join(root, "events.json")
	os.WriteFile(stream, nil, 0600)
	backup, err := resetHistoryDatabaseAt(database, stream, alias)
	if err != nil {
		t.Fatal("valid systemd state alias rejected", err)
	}
	if readText(filepath.Join(backup, "snort-ndr.db")) != "old database" {
		t.Fatal("database backup missing")
	}
	if err = removeHistoryDatabaseBackup(backup, alias); err != nil {
		t.Fatal(err)
	}
	if !fileExists(database) {
		t.Fatal("new database deleted with backup")
	}
	other := filepath.Join(root, "other")
	os.Mkdir(other, 0700)
	os.Remove(alias)
	os.Symlink(other, alias)
	if _, err = historyMembersAt(database, alias); err == nil {
		t.Fatal("arbitrary state directory redirection accepted")
	}
}
