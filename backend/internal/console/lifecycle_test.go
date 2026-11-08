package console

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testManager(t *testing.T) *RuleManager {
	t.Helper()
	root := t.TempDir()
	live := liveRulePaths(root)
	for _, p := range append([]string{live.Config, filepath.Join(live.Data, "rules/snort.rules")}, func() []string {
		a := []string{}
		for _, p := range live.controls {
			a = append(a, p)
		}
		return a
	}()...) {
		data := []byte{}
		if p == live.controls["BAN_STORE"] {
			data = []byte("[]")
		}
		if err := atomicWrite(p, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	m, err := NewRuleManager(t.Context(), filepath.Join(root, "state"), filepath.Join(root, "control.sock"), root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m
}
func editManager(t *testing.T, m *RuleManager, path string, body Object) Object {
	t.Helper()
	value, err := m.Dispatch(t.Context(), Object{"operation": "mutate", "method": "POST", "path": path, "body": body}, false)
	if err != nil {
		t.Fatal(err)
	}
	return object(value)
}
func TestDraftsAtomicityPersistenceAndRollback(t *testing.T) {
	m := testManager(t)
	original := "alert ip any any -> any any (msg:\"original\"; sid:123; rev:1;)\n"
	if err := atomicWrite(filepath.Join(m.live.Data, "rules/snort.rules"), []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	editManager(t, m, "/api/rules/disable", Object{"values": []any{"sid:123"}})
	if len(configured(m.live.controls["DISABLE_CONF"])) != 0 {
		t.Fatal("draft changed live config")
	}
	draft, err := newDrafts(m.live, m.state)
	if err != nil || !draft.Dirty || len(configured(draft.paths.controls["DISABLE_CONF"])) != 1 {
		t.Fatal("pending configuration did not survive restart", err)
	}
	before := readText(m.drafts.paths.controls["DISABLE_CONF"])
	_, err = m.Dispatch(t.Context(), Object{"operation": "mutate", "method": "POST", "path": "/api/rules/batch-delete", "body": Object{"paths": []any{"/api/rules/disable/sid:123", "/api/hunt/rules/999"}}}, false)
	if err == nil || readText(m.drafts.paths.controls["DISABLE_CONF"]) != before {
		t.Fatal("partial batch mutation was not rolled back")
	}
	backup, err := newRuleBackup(m, strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	if err = m.drafts.Promote(); err != nil {
		t.Fatal(err)
	}
	if len(configured(m.live.controls["DISABLE_CONF"])) != 1 {
		t.Fatal("draft promotion failed")
	}
	if err = backup.Restore(m); err != nil {
		t.Fatal(err)
	}
	if readText(filepath.Join(m.live.Data, "rules/snort.rules")) != original || len(configured(m.live.controls["DISABLE_CONF"])) != 0 || !m.drafts.Dirty {
		t.Fatal("live rollback or pending preservation failed")
	}
	if err = backup.Close(m.state); err != nil {
		t.Fatal(err)
	}
	editManager(t, m, "/api/rules/pending/discard", Object{})
	if m.drafts.Dirty {
		t.Fatal("discard did not clear pending")
	}
}
func TestApplyFailureRestoresLiveRules(t *testing.T) {
	m := testManager(t)
	prefix := t.TempDir()
	t.Setenv("SNORT_ENGINE_PREFIX", prefix)
	if err := atomicWrite(filepath.Join(prefix, "bin/snort"), []byte("#!/bin/sh\nprintf 'validation refused\\n'\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	original := "alert ip any any -> any any (msg:\"original\"; sid:123; rev:1;)\n"
	atomicWrite(filepath.Join(m.live.Data, "rules/snort.rules"), []byte(original), 0600)
	editManager(t, m, "/api/rules/disable", Object{"value": "sid:123"})
	var calls int
	m.engineOverride = func(context.Context, string, time.Duration) (any, error) {
		calls++
		return nil, errors.New("unexpected reload")
	}
	result := editManager(t, m, "/api/actions/apply", Object{})
	if result["ok"] != true {
		t.Fatal(result)
	}
	m.jobs.Wait()
	status := m.jobs.Status()
	if integer(status["rc"]) != 1 || status["state"] != "done" || calls != 0 || readText(filepath.Join(m.live.Data, "rules/snort.rules")) != original || !m.drafts.Dirty {
		t.Fatal("failed validation did not preserve live and pending state", status)
	}
	paths, _ := filepath.Glob(filepath.Join(m.state, "transaction-*"))
	if len(paths) != 0 {
		t.Fatal("successfully restored transaction not cleaned")
	}
}
func TestOperationLogsKeepUTF8Boundaries(t *testing.T) {
	m := testManager(t)
	id := strings.Repeat("b", 32)
	path, _ := m.jobs.logPath(id)
	raw := append(bytes.Repeat([]byte("x"), 65535), []byte("汉🦊\n")...)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	first, err := m.jobs.Log(id, 0)
	if err != nil || integer(first["next_offset"]) != 65535 {
		t.Fatal(first, err)
	}
	second, err := m.jobs.Log(id, integer(first["next_offset"]))
	if err != nil || text(first["text"])+text(second["text"]) != string(raw) || second["eof"] != true {
		t.Fatal("UTF-8 pagination corrupted log", err)
	}
	for _, bad := range []string{"../../passwd", "", "bad"} {
		if _, err = m.jobs.Log(bad, -1); err == nil {
			t.Fatal("invalid log request accepted")
		}
	}
}
func TestBridgeDurableReplayRotationAndSparseRecovery(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	os.MkdirAll(logs, 0700)
	instance := filepath.Join(root, "instance.json")
	writeJSON(instance, Object{"epoch": strings.Repeat("c", 32), "started": 1})
	source := filepath.Join(logs, "0_file_connector_ndr_transmit")
	line := []byte("{\"ts\":1794009600,\"trans_id\":1,\"query\":\"example.test\"}\n")
	os.WriteFile(source, append(append([]byte("bad\n"), line...), []byte("partial")...), 0600)
	pool := NewPool(4)
	defer pool.Close()
	output, checkpoint := filepath.Join(root, "events.json"), filepath.Join(root, "offsets.json")
	bridge, err := NewBridge(logs, output, checkpoint, instance, pool)
	if err != nil {
		t.Fatal(err)
	}
	if err = bridge.Run(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if bridge.state.Rejected != 1 || bridge.state.Files[filepath.Base(source)].Offset != int64(4+len(line)) {
		t.Fatal("partial line checkpoint advanced")
	}
	before := readText(output)
	recovered, err := NewBridge(logs, output, checkpoint, instance, pool)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := recovered.Poll(t.Context()); err != nil || count != 0 || readText(output) != before {
		t.Fatal("replayed committed input", count, err)
	}
	f, err := os.OpenFile(source, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.Truncate(0)
	f.Seek(2<<20, 0)
	f.Write(line)
	f.Close()
	if err = recovered.Run(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if recovered.state.Sparse == 0 || strings.Count(readText(output), "example.test") != 2 {
		t.Fatal("copytruncate sparse gap lost record")
	}
	torn, err := os.OpenFile(output, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	torn.WriteString("torn")
	torn.Close()
	if _, err = NewBridge(logs, output, checkpoint, instance, pool); err != nil || !strings.HasSuffix(readText(output), "\n") {
		t.Fatal("output tail recovery failed", err)
	}
}
func TestHTTPAuthenticationQueriesAndSources(t *testing.T) {
	root := t.TempDir()
	stream := filepath.Join(root, "events.json")
	os.WriteFile(stream, append(syntheticEvent("alert"), '\n'), 0600)
	hash, err := PasswordHash("fixture-password")
	if err != nil {
		t.Fatal(err)
	}
	static := filepath.Join(root, "static")
	atomicWrite(filepath.Join(static, "index.html"), []byte("<title>fixture</title>"), 0600)
	cfg := Config{User: "admin", PasswordPBKDF: hash, StaticDir: static, EventDB: filepath.Join(root, "events.db"), Stream: stream, ReadWorkers: 4, PreloadBytes: 8 << 20, SessionTTL: time.Hour}
	app, err := NewApp(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	server := httptest.NewServer(NewHTTPHandler(app))
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(path string) Object {
		t.Helper()
		res, err := client.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			data, _ := io.ReadAll(res.Body)
			t.Fatalf("%s status=%d %s", path, res.StatusCode, data)
		}
		var value Object
		if err = json.NewDecoder(res.Body).Decode(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	res, err := client.Get(server.URL + "/api/hunt")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("unauthorized query accepted")
	}
	res, err = client.PostForm(server.URL+"/login", url.Values{"username": {"admin"}, "password": {"fixture-password"}})
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 302 || len(jar.Cookies(func() *url.URL { u, _ := url.Parse(server.URL); return u }())) == 0 {
		t.Fatal("login failed")
	}
	deadline := time.Now().Add(5 * time.Second)
	for app.Store.Lag() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("background ingest did not finish")
		}
		time.Sleep(5 * time.Millisecond)
	}
	for _, path := range []string{"/api/hunt?all=1&source=db", "/api/events?all=1", "/api/incidents?all=1", "/api/overview?all=1", "/api/aggregate?all=1", "/api/db/stats", "/api/hunt/schema", "/api/cache/stats"} {
		get(path)
	}
	file := get("/api/hunt?source=file&from=1794009600&to=1794009601")
	if integer(file["total"]) != 1 || file["source"] != "file" {
		t.Fatal("file search parity", file)
	}
	req, _ := http.NewRequest("POST", server.URL+"/api/db/settings", strings.NewReader(`{"cap_mib":64}`))
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode < 400 {
		t.Fatal("missing CSRF header accepted")
	}
	req, _ = http.NewRequest("POST", server.URL+"/api/db/settings", strings.NewReader(`{"cap_mib":64}`))
	req.Header.Set("X-Requested-With", "ips-web")
	req.Header.Set("Origin", "https://untrusted.example")
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatal("untrusted origin accepted")
	}
}
func TestConcurrentReadSnapshotsStayConsistent(t *testing.T) {
	s, ctx := testStore(t)
	record, err := ParseEvent(syntheticEvent("alert"))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.insert(ctx, []*Prepared{record}, Cursor{}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g, err := s.Snapshot(ctx, true)
			if err != nil {
				t.Error(err)
				return
			}
			defer g.Close()
			rows, err := g.Many([]statement{{"SELECT COUNT(*) n FROM events", nil}, {"SELECT COUNT(*) n FROM events", nil}})
			if err != nil || integer(rows[0][0]["n"]) != integer(rows[1][0]["n"]) {
				t.Error("inconsistent parallel snapshots", err)
			}
		}()
	}
	wg.Wait()
}
func TestManagerBrowserReadContractAndUntrustedKeys(t *testing.T) {
	m := testManager(t)
	for _, item := range []struct {
		name   string
		params Object
	}{{"app.rules_search", Object{"q": "", "browse": "1", "limit": "50", "offset": "0", "exclude": "disable"}}, {"rule_groups_search", Object{"q": "", "exclude": "suppress"}}, {"app.rules_page", Object{"tab": "catalog", "limit": "50", "offset": "0"}}, {"app.sources_catalog", Object{}}} {
		if _, err := m.Dispatch(t.Context(), Object{"operation": "read", "name": item.name, "args": []any{}, "kwargs": item.params}, false); err != nil {
			t.Fatal(item.name, err)
		}
	}
	for _, request := range []Object{{"operation": "read", "name": "governance_state", "args": []any{}, "kwargs": Object{"path": "/etc/shadow"}}, {"operation": "read", "name": "app.__dict__", "args": []any{}, "kwargs": Object{}}, {"operation": "ping", "command": "id"}, {"operation": "maintenance", "enabled": true}} {
		if _, err := m.Dispatch(t.Context(), request, false); err == nil {
			t.Fatal("untrusted manager operation accepted", request["operation"])
		}
	}
}
func TestDropRemovalClearsPairedRejectAndGroupIncludesExplicitSIDs(t *testing.T) {
	m := testManager(t)
	editManager(t, m, "/api/rules/reject", Object{"value": "sid:123"})
	if len(configured(m.drafts.paths.controls["DROP_CONF"])) != 1 || len(configured(m.drafts.paths.controls["MODIFY_CONF"])) != 1 {
		t.Fatal("reject pair missing")
	}
	if _, err := m.Dispatch(t.Context(), Object{"operation": "mutate", "method": "DELETE", "path": "/api/rules/drop/sid:123", "body": Object{}}, false); err != nil {
		t.Fatal(err)
	}
	if len(configured(m.drafts.paths.controls["DROP_CONF"])) != 0 || len(configured(m.drafts.paths.controls["MODIFY_CONF"])) != 0 {
		t.Fatal("orphan reject modifier survived deletion")
	}
	editManager(t, m, "/api/rules/suppress-groups", Object{"groups": []any{"group:fixture"}, "sids": []any{"123"}})
	if len(suppressions(m.drafts.paths)) != 1 {
		t.Fatal("explicit signature suppressed together with group was lost")
	}
}
