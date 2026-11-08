package console

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Opt-in local fixture. It is absent from production executables and never reads
// router state, starts detection, downloads sources, or invokes an engine socket.
func TestBrowserFixture(t *testing.T) {
	static, stop := os.Getenv("AEGIS_GO_FIXTURE_STATIC"), os.Getenv("AEGIS_GO_FIXTURE_STOP")
	if static == "" || stop == "" {
		t.Skip("local browser fixture not requested")
	}
	root, err := os.MkdirTemp("", "aegis-go-browser-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	engine := filepath.Join(root, "fixture-engine")
	t.Setenv("SNORT_ENGINE_PREFIX", engine)
	fixtureBuiltinEngine(t, engine, false)
	live := liveRulePaths(root)
	for key, p := range live.controls {
		data := []byte{}
		if key == "BAN_STORE" {
			data = []byte("[]")
		}
		if err = atomicWrite(p, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	atomicWrite(live.Config, nil, 0600)
	rules := []string{}
	for i := 0; i < 125; i++ {
		rules = append(rules, fmt.Sprintf(`alert tcp any any -> any any (msg:"Fixture signature %03d"; sid:%d; rev:1;)`, i, 2100000+i))
	}
	atomicWrite(filepath.Join(live.Data, "rules/snort.rules"), []byte(strings.Join(rules, "\n")+"\n"), 0600)
	archive, err := rulesArchive(map[string][]byte{"rules/fixture.rules": []byte(strings.Join(rules, "\n") + "\n")})
	if err != nil {
		t.Fatal(err)
	}
	fixtureRuleDownloads(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/downloads/community/snort3-community-rules.tar.gz":
			w.Write(archive)
		case "/downloads/community/snort3-community-rules.tar.gz.md5":
			sum := md5.Sum(archive)
			w.Write([]byte(hex.EncodeToString(sum[:])))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	key := sourceKey("snort/community")
	atomicWrite(filepath.Join(live.Cache, key+"-rules.tar.gz"), archive, 0600)
	writeJSON(filepath.Join(live.Cache, "sources.json"), Object{key: Object{"source": "snort/community", "enabled": true}})
	atomicWrite(filepath.Join(live.Sources, "snort-community.yaml"), []byte("source: snort/community\n"), 0600)
	socket := filepath.Join(root, "control.sock")
	manager, err := NewRuleManager(ctx, filepath.Join(root, "manager"), socket, root)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	manager.engineOverride = func(context.Context, string, time.Duration) (any, error) { return Object{"confirmed": true}, nil }
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	defer func() { listener.Close(); workers.Wait() }()
	go func() {
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() { defer workers.Done(); manager.handleRPC(ctx, conn, uint32(os.Getgid())) }()
		}
	}()
	hash, err := PasswordHash("preview-only")
	if err != nil {
		t.Fatal(err)
	}
	stream := filepath.Join(root, "events.json")
	f, err := os.Create(stream)
	if err != nil {
		t.Fatal(err)
	}
	stamp := now()
	session := strings.Repeat("a", 32) + ":0000000000000001"
	for i, kind := range []string{"alert", "alert", "drop", "dns", "tls", "http", "flow", "session"} {
		event := Object{"timestamp": utc(stamp - float64(i*30)), "event_type": kind, "src_ip": "192.0.2.10", "dest_ip": "198.51.100.4", "src_port": 51000, "dest_port": 443, "proto": "TCP", "app_proto": "tls", "snort_native": Object{"session_id": session}, "alert": Object{"gid": 1, "signature_id": 2100000 + i, "signature": "Fixture suspicious activity", "severity": i%3 + 1, "action": "allowed"}, "dns": Object{"type": "response", "rrname": "example.test", "rrtype": "A", "answers": []Object{{"rdata": "198.51.100.4"}}}, "tls": Object{"sni": "example.test", "version": "TLSv1.3"}, "http": Object{"hostname": "example.test", "url": "/fixture", "http_method": "GET", "status": 200}, "flow": Object{"pkts_toserver": 2, "pkts_toclient": 1, "bytes_toserver": 100, "bytes_toclient": 200, "state": "SF"}}
		if kind == "drop" {
			object(event["alert"])["action"] = "blocked"
		}
		if kind == "dns" {
			event["src_ip"] = "192.0.2.20"
		}
		json.NewEncoder(f).Encode(event)
	}
	// Suppression removes alert evidence from detection views, while a real
	// blocking action remains visible in enforcement views and raw history.
	json.NewEncoder(f).Encode(Object{"engine": "snort3", "kind": "notice", "data": Object{
		"ts": stamp - 5, "session_id": session, "gid": 119, "sid": 261, "priority": 1,
		"msg": "Fixture suppressed block", "action": "block", "alert_suppressed": true,
		"proto": "TCP", "id.orig_h": "192.0.2.10", "id.orig_p": 51000, "id.resp_h": "198.51.100.4", "id.resp_p": 443,
	}})
	json.NewEncoder(f).Encode(Object{"event_type": "alert", "timestamp": utc(stamp - 10),
		"src_ip": "192.0.2.10", "src_port": 51000, "dest_ip": "198.51.100.4", "dest_port": 443, "proto": "TCP",
		"snort_native": Object{"session_id": session},
		"alert":        Object{"gid": 119, "signature_id": 262, "signature": "Fixture suppressed alert", "severity": 1, "action": "allowed", "alert_suppressed": 1},
	})
	f.Close()
	cfg := Config{User: "admin", PasswordPBKDF: hash, StaticDir: static, EventDB: filepath.Join(root, "events.db"), Stream: stream, ManagerSocket: socket, ReadWorkers: 4, PreloadBytes: 16 << 20, SessionTTL: time.Hour, Raw: Object{"local_llm": Object{"enabled": false}}}
	cfg.snapshotDir = filepath.Join(root, "snapshots")
	if err = os.Mkdir(cfg.snapshotDir, 0700); err != nil {
		t.Fatal(err)
	}
	app, err := NewApp(ctx, cfg)
	// The fixture copies only synthetic records in its developer-owned temp tree.
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	manager.runtime = Object{"schema": 1, "engine": Object{"version": "fixture", "dump-counters": Object{"decoder": Object{"pkts": 1000, "bytes": 50000}, "ips": Object{"accepted": 998, "blocked": 2, "drop_reason": Object{"rules": 2}}}, "ruleset-stats": Object{"rules_loaded": 125, "rules_loaded_source": "rule_files", "rules_failed": 0, "rules_skipped": 0}, "running-mode": "inline", "capture-mode": "NFQ"}, "service": Object{"state": "active", "memory": 64 << 20, "uptime": 1000}, "queue_listeners": Object{"packets": 1000, "bytes": 50000, "listeners_known": true, "count": 4, "queue_total": 0, "kernel_drops": 0, "user_drops": 0, "queues": []Object{}}, "rates": Object{"pps": 1, "mbps": .1, "fps": 0}, "telemetry": Object{"error": ""}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			payload := manager.Runtime()
			payload["published"] = now()
			payload["telemetry"] = Object{"as_of": now(), "error": ""}
			payload["reload_state"] = manager.jobs.ReloadState()
			payload["update_status"] = manager.jobs.Status()
			payload["history_reset"] = Object{"state": "idle"}
			data, _ := json.Marshal(payload)
			atomicWrite(filepath.Join(root, "status.json"), data, 0640)
			select {
			case <-ctx.Done():
				return
			case <-time.After(250 * time.Millisecond):
			}
		}
	}()
	defer func() { cancel(); <-done }()
	port := os.Getenv("AEGIS_GO_FIXTURE_PORT")
	if port == "" {
		port = "19096"
	}
	if _, err = strconv.Atoi(port); err != nil {
		t.Fatal(err)
	}
	httpListener, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: NewHTTPHandler(app), ReadHeaderTimeout: 5 * time.Second}
	defer server.Close()
	go server.Serve(httpListener)
	t.Log("native fixture ready")
	for !fileExists(stop) {
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}
