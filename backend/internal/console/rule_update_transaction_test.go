package console

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fixtureRuleDownloads(t *testing.T, handler http.Handler) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig.ServerName = server.Certificate().DNSNames[0]
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	previous := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections(); server.Close() })
}

func TestRuleJobPublishesReadableEmptyLogBeforeWorkerOutput(t *testing.T) {
	m := testManager(t)
	prefix := t.TempDir()
	t.Setenv("SNORT_ENGINE_PREFIX", prefix)
	fixtureBuiltinEngine(t, prefix, false)
	m.engineOverride = func(context.Context, string, time.Duration) (any, error) { return Object{"confirmed": true}, nil }
	// Keep the worker at the promotion gate while the UI reads the new status.
	m.mu.Lock()
	result, err := m.jobs.Start("apply", "manual", "")
	if err != nil {
		m.mu.Unlock()
		t.Fatal(err)
	}
	id := text(result["job_id"])
	page, logErr := m.jobs.Log(id, 0)
	status := m.jobs.Status()
	path, _ := m.jobs.logPath(id)
	info, statErr := os.Stat(path)
	m.mu.Unlock()
	m.jobs.Wait()
	if logErr != nil || text(page["text"]) != "" || integer(page["next_offset"]) != 0 || page["eof"] != true || status["state"] != "running" || status["log_bytes"] == nil || integer(status["log_bytes"]) != 0 {
		t.Fatal("new task must expose a normal empty log while waiting", logErr, status)
	}
	if statErr != nil || info.Mode().Perm() != 0600 {
		t.Fatal("operation log permissions incorrect", statErr)
	}
	done := m.jobs.Status()
	if integer(done["rc"]) != 0 || integer(done["log_bytes"]) == 0 || integer(object(done["recent_manual"])["log_bytes"]) != integer(done["log_bytes"]) {
		t.Fatal("log size did not follow completed output", done)
	}
	if _, err := m.jobs.Log(strings.Repeat("e", 32), 0); err == nil {
		t.Fatal("unknown logs must still fail")
	}
}

func TestRuleJobRejectsStartWhenLogCannotBeCreated(t *testing.T) {
	m := testManager(t)
	root := filepath.Join(m.state, "operation-logs")
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(root, []byte("fixture blocked directory"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := m.jobs.Start("apply", "manual", "")
	transactions, _ := filepath.Glob(filepath.Join(m.state, "transaction-*"))
	if err == nil || m.jobs.Busy() || len(m.jobs.records) != 0 || len(transactions) != 0 {
		t.Fatal("failed log initialization published a task or retained a transaction", err)
	}
}

func TestRuleJobRejectsStartWhenStatusCannotBePersisted(t *testing.T) {
	m := testManager(t)
	if err := os.Mkdir(filepath.Join(m.state, "operation-logs/index.json"), 0700); err != nil {
		t.Fatal(err)
	}
	_, err := m.jobs.Start("apply", "manual", "")
	transactions, _ := filepath.Glob(filepath.Join(m.state, "transaction-*"))
	logs, _ := filepath.Glob(filepath.Join(m.state, "operation-logs/*.log"))
	if err == nil || m.jobs.Busy() || m.jobs.Status()["state"] != "idle" || len(m.jobs.records) != 0 || len(transactions) != 0 || len(logs) != 0 {
		t.Fatal("failed status persistence left a phantom running task", err)
	}
}

func ruleTransactionFiles(m *RuleManager) (map[string]string, error) {
	files := map[string]string{}
	for _, root := range []string{filepath.Join(m.live.Data, "rules"), m.live.Sources} {
		tree, err := privateTree(root)
		if err != nil {
			return nil, err
		}
		for name, data := range tree {
			files[filepath.Join(root, name)] = string(data)
		}
	}
	for _, file := range append([]string{m.live.groupsFile()}, func() []string {
		out := []string{}
		for _, path := range m.live.controls {
			out = append(out, path)
		}
		return out
	}()...) {
		data, err := os.ReadFile(file)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		files[file] = string(data)
	}
	return files, nil
}

// Exercise the real HTTPS downloader, archive compiler, draft transaction and
// command validation. Only the download peer and Snort process are synthetic.
func TestRuleUpdateAppliesDraftsAndRollsBackFailures(t *testing.T) {
	for _, mode := range []string{"success", "download-failure", "validation-failure", "reload-failure", "rollback-failure", "appid-current", "appid-change", "appid-reload-failure", "scheduled"} {
		t.Run(mode, func(t *testing.T) {
			m := testManager(t)
			prefix := t.TempDir()
			t.Setenv("SNORT_ENGINE_PREFIX", prefix)
			binary := filepath.Join(prefix, "bin/snort")
			if err := atomicWrite(binary, []byte("#!/bin/sh\n[ \"$1\" = '-T' ] || exit 2\nprintf validated > \"$0.validated\"\n[ ! -f \"$0.refuse\" ]\n"), 0700); err != nil {
				t.Fatal(err)
			}
			if mode == "validation-failure" {
				atomicWrite(binary+".refuse", nil, 0600)
			}
			old := "alert tcp any any -> any 443 (msg:\"active original\"; sid:41; rev:1;)\n"
			atomicWrite(filepath.Join(m.live.Data, "rules/snort.rules"), []byte(old), 0600)
			writeJSON(filepath.Join(m.live.Sources, "custom-active.json"), Object{"name": "custom/active", "enabled": true, "format": "rules", "label": "Active fixture", "url": "https://example.test/old.rules", "token": ""})
			if err := saveBans(m.live, []Object{}); err != nil {
				t.Fatal(err)
			}
			if err := m.drafts.Reset(); err != nil {
				t.Fatal(err)
			}
			archive, err := rulesArchive(map[string][]byte{
				"lightspd/rules/3.0.0.0/fixture.rules":                  []byte("alert tcp any any -> any 443 (msg:\"policy action\"; sid:201; rev:1;)\nalert tcp any any -> any 443 (msg:\"disabled\"; sid:202; rev:1;)\nalert tcp any any -> any 443 (msg:\"user action\"; sid:203; rev:1;)\n"),
				"lightspd/rules/3.0.0.0/rulestates-security-ips.states": []byte("block (gid:1; sid:201; enable;)\nblock (gid:1; sid:202; enable;)\nalert (gid:1; sid:203; enable;)\n"),
			})
			if err != nil {
				t.Fatal(err)
			}
			appid, err := rulesArchive(map[string][]byte{"odp/lua/fixture.lua": []byte("-- synthetic detector\n"), "odp/appMapping.data": []byte("fixture\n")})
			if err != nil {
				t.Fatal(err)
			}
			appidChanged := mode == "appid-change" || mode == "appid-reload-failure"
			appidCurrent := mode == "appid-current"
			appRoot := filepath.Join(m.live.Data, "appid")
			bundled := filepath.Join(prefix, "share/appid/odp")
			if appidChanged || appidCurrent {
				os.MkdirAll(bundled, 0700)
				os.MkdirAll(appRoot, 0700)
				if err := os.Symlink(bundled, filepath.Join(appRoot, "odp")); err != nil {
					t.Fatal(err)
				}
			}
			if appidCurrent {
				hash := md5.Sum(appid)
				if err := writeJSON(filepath.Join(appRoot, "update.json"), Object{"md5": hex.EncodeToString(hash[:])}); err != nil {
					t.Fatal(err)
				}
			}
			var oldRequests, newRequests, appidDownloads atomic.Int32
			fixtureRuleDownloads(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/old.rules":
					oldRequests.Add(1)
					w.Write([]byte("alert tcp any any -> any 443 (msg:\"refreshed active\"; sid:41; rev:2;)\n"))
				case "/rules/Talos_LightSPD.tar.gz":
					newRequests.Add(1)
					if mode == "download-failure" {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					w.Write(archive)
				case "/rules/Talos_LightSPD.tar.gz.md5":
					hash := md5.Sum(archive)
					w.Write([]byte(hex.EncodeToString(hash[:])))
				case "/downloads":
					w.Write([]byte(`<a href="/downloads/openappid/1">fixture</a>`))
				case "/downloads/openappid/md5s":
					hash := md5.Sum(appid)
					w.Write([]byte(hex.EncodeToString(hash[:]) + "  snort-openappid.tar.gz\n"))
				case "/downloads/openappid/1":
					appidDownloads.Add(1)
					w.Write(appid)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			before, err := ruleTransactionFiles(m)
			if err != nil {
				t.Fatal(err)
			}
			for _, change := range []struct {
				path string
				body Object
			}{
				{"/api/rules/source/config", Object{"name": "snort/lightspd", "oinkcode": strings.Repeat("a", 40), "ips_policy": "security"}},
				{"/api/rules/source", Object{"name": "custom/active", "enable": false}},
				{"/api/rules/source", Object{"name": "snort/lightspd", "enable": true}},
				{"/api/rules/disable", Object{"value": "sid:202"}},
				{"/api/rules/action", Object{"selector": "sid:203", "action": "reject"}},
				{"/api/rules/suppress", Object{"sids": []any{"201"}}},
				{"/api/hunt/rules", Object{"rule": `alert tcp any any -> any 443 (msg:"pending manual"; sid:9900101; rev:1;)`}},
				{"/api/bans", Object{"target": "192.0.2.99"}},
			} {
				editManager(t, m, change.path, change.body)
			}
			draft, err := privateTree(m.drafts.root)
			if err != nil {
				t.Fatal(err)
			}
			calls := []string{}
			m.engineOverride = func(_ context.Context, operation string, _ time.Duration) (any, error) {
				if !fileExists(binary + ".validated") {
					return nil, errors.New("reload preceded validation")
				}
				calls = append(calls, operation)
				if len(calls) == 1 && (mode == "reload-failure" || mode == "rollback-failure" || mode == "appid-reload-failure") || mode == "rollback-failure" {
					return nil, errors.New("fixture reload refused")
				}
				if strings.Contains(mode, "failure") {
					current, err := ruleTransactionFiles(m)
					if err != nil || !reflect.DeepEqual(current, before) {
						return nil, errors.New("restoring reload saw un-restored files")
					}
				}
				return Object{"confirmed": true}, nil
			}
			if mode == "scheduled" {
				m.mu.Lock()
				_, err = m.jobs.Start("update", "scheduled", "")
				m.mu.Unlock()
			} else {
				editManager(t, m, "/api/actions/update", Object{})
			}
			if err != nil {
				t.Fatal(err)
			}
			m.jobs.Wait()
			failed := strings.Contains(mode, "failure")
			if (integer(m.jobs.Status()["rc"]) != 0) != failed {
				t.Fatal("unexpected update result", m.jobs.Status())
			}
			if mode == "scheduled" {
				if oldRequests.Load() != 1 || newRequests.Load() != 0 || !strings.Contains(readText(filepath.Join(m.live.Data, "rules/snort.rules")), "refreshed active") {
					t.Fatal("scheduled update did not use active sources")
				}
			} else if newRequests.Load() != 1 || oldRequests.Load() != 0 {
				t.Fatal("manual update did not use pending sources")
			}
			if failed || mode == "scheduled" {
				after, err := privateTree(m.drafts.root)
				if err != nil || !m.drafts.Dirty || !reflect.DeepEqual(draft, after) {
					t.Fatal("pending draft was lost or changed", err)
				}
			} else {
				if m.drafts.Dirty || m.jobs.Status()["pending"] != false || m.drafts.SourcesChanged() {
					t.Fatal("successful manual update did not clear pending edits")
				}
				raw := readText(filepath.Join(m.live.Data, "rules/snort.rules"))
				if !strings.Contains(raw, "block tcp any any -> any 443 (msg:\"policy action\"") || !strings.Contains(raw, "# block tcp any any -> any 443 (msg:\"disabled\"") || !strings.Contains(raw, "reject tcp any any -> any 443 (msg:\"user action\"") || strings.Contains(raw, "active original") {
					t.Fatal("updated source, IPS policy or user controls not applied")
				}
				if len(manualRules(m.live)) != 1 || len(loadBans(m.live)) != 1 || !strings.Contains(readText(m.live.controls["SUPPRESS_LUA"]), "gid = 1, sid = 201") {
					t.Fatal("manual, ban or suppression draft was not applied")
				}
			}
			if failed {
				after, err := ruleTransactionFiles(m)
				if err != nil || !reflect.DeepEqual(before, after) {
					t.Fatal("failed update did not restore original rules and configuration", err)
				}
			}
			wanted := []string{"ruleset-reload-rules"}
			switch mode {
			case "download-failure", "validation-failure":
				wanted = nil
			case "reload-failure", "rollback-failure":
				wanted = []string{"ruleset-reload-rules", "ruleset-reload-rules"}
			case "appid-change":
				wanted = []string{"appid-reload-detectors", "ruleset-reload-rules"}
			case "appid-reload-failure":
				wanted = []string{"appid-reload-detectors", "appid-reload-detectors", "ruleset-reload-rules"}
			}
			if !slices.Equal(calls, wanted) {
				t.Fatal("unexpected reload order", calls)
			}
			if appidChanged {
				target, err := os.Readlink(filepath.Join(appRoot, "odp"))
				if err != nil || (target != bundled) == failed {
					t.Fatal("OpenAppID pointer did not follow transaction outcome", err)
				}
			}
			if appidChanged || appidCurrent {
				id := text(m.jobs.Status()["id"])
				logPath, err := m.jobs.logPath(id)
				if err != nil {
					t.Fatal(err)
				}
				log := readText(logPath)
				var expectedDownloads int32
				if appidChanged {
					expectedDownloads = 1
				}
				if appidDownloads.Load() != expectedDownloads ||
					strings.Contains(log, "OpenAppID 检测器已是最新，跳过下载") != appidCurrent ||
					strings.Contains(log, "发现新版 OpenAppID 检测器，开始下载") != appidChanged ||
					strings.Contains(log, "OpenAppID 检测器已热重载") != (appidChanged && !failed) {
					t.Fatal("OpenAppID log does not describe the transaction outcome", log)
				}
			}
			transactions, _ := filepath.Glob(filepath.Join(m.state, "transaction-*"))
			if mode == "rollback-failure" {
				if len(transactions) != 1 || !m.paused {
					t.Fatal("failed rollback did not retain recovery material and pause writes")
				}
				m.engineOverride = func(context.Context, string, time.Duration) (any, error) { return Object{"confirmed": true}, nil }
				if err := m.jobs.Recover(); err != nil || m.paused || !m.drafts.Dirty {
					t.Fatal("retained transaction did not recover", err)
				}
			} else if len(transactions) != 0 || m.paused {
				t.Fatal("completed transaction left recovery material or paused writes")
			}
		})
	}
}
