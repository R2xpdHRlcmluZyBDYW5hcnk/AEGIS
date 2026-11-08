package console

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const engineSocket = "/run/snort/control.sock"

var engineFailure = regexp.MustCompile(`(?i)fail|error|restart required`)

func engineCommand(ctx context.Context, command string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", engineSocket)
	if err != nil {
		return "", errors.New("引擎控制通道暂不可用")
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()
	reader := bufio.NewReaderSize(conn, 65536)
	read := func() (string, error) {
		out := []byte{}
		for len(out) <= 8<<20 {
			part, err := reader.ReadBytes(' ')
			out = append(out, part...)
			if bytes.Contains(out, []byte("o\")~ ")) {
				return string(out), nil
			}
			if err != nil {
				return "", errors.New("引擎控制响应中断")
			}
		}
		return "", errors.New("引擎控制响应超过上限")
	}
	if _, err = read(); err != nil {
		return "", err
	}
	if _, err = io.WriteString(conn, command+"\n"); err != nil {
		return "", err
	}
	return read()
}
func (m *RuleManager) engineCall(ctx context.Context, operation string, timeout time.Duration) (any, error) {
	if m.engineOverride != nil {
		return m.engineOverride(ctx, operation, timeout)
	}
	m.engineGate.Lock()
	defer m.engineGate.Unlock()
	return m.engineOperation(ctx, operation, timeout)
}
func (m *RuleManager) engineOperation(ctx context.Context, operation string, timeout time.Duration) (any, error) {
	command := func(s string) (string, error) { return engineCommand(ctx, s, timeout) }
	switch operation {
	case "ruleset-reload-rules":
		before, err := command("show_config_generation()")
		if err != nil {
			return nil, err
		}
		reply, err := command("reload_config()")
		if err != nil || engineFailure.MatchString(reply) {
			return nil, errors.New("引擎配置重载失败")
		}
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			after, err := command("show_config_generation()")
			if err != nil {
				return nil, err
			}
			if before != after {
				return Object{"confirmed": true}, nil
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
		}
		return nil, errors.New("引擎配置代次未推进")
	case "appid-reload-detectors":
		reply, err := command("appid.reload_detectors()")
		if err != nil || regexp.MustCompile(`(?i)fail|error|pending|retry`).MatchString(reply) || !strings.Contains(reply, "swapping detectors configuration") {
			return nil, errors.New("引擎未确认检测器重载")
		}
		return Object{"confirmed": true}, nil
	case "dump-counters":
		reply, err := command(`dump_stats("json")`)
		if err != nil {
			return nil, err
		}
		start := strings.IndexByte(reply, '{')
		if start < 0 {
			return nil, errors.New("引擎统计响应无效")
		}
		decoder := json.NewDecoder(strings.NewReader(reply[start:]))
		decoder.UseNumber()
		var data Object
		if err = decoder.Decode(&data); err != nil {
			return nil, errors.New("引擎统计响应无效")
		}
		return engineCounters(data), nil
	case "version":
		if _, err := command("show_config_generation()"); err != nil {
			return nil, err
		}
		var manifest Object
		if err := readJSON(filepath.Join(enginePrefix(), "engine-manifest.json"), &manifest); err != nil {
			return nil, err
		}
		return object(object(manifest["sources"])["snort"])["version"], nil
	case "running-mode":
		return "inline", nil
	case "capture-mode":
		return "NFQ", nil
	case "uptime", "ruleset-reload-time":
		return nil, nil
	case "ruleset-stats":
		if _, err := command("show_config_generation()"); err != nil {
			return nil, err
		}
		rows, err := m.metadata.Load(ctx)
		if err != nil {
			return nil, err
		}
		return Object{"rules_loaded": len(rows), "rules_loaded_source": "rule_files", "rules_failed": nil, "rules_skipped": nil}, nil
	}
	return nil, errors.New("不支持的引擎操作")
}
func engineCounters(data Object) Object {
	groups := Object{}
	for _, section := range array(data["sections"]) {
		for _, raw := range array(object(section)["groups"]) {
			group := object(raw)
			name := text(group["name"])
			values := object(groups[name])
			for _, raw := range array(group["counters"]) {
				c := object(raw)
				values[text(c["name"])] = c["value"]
			}
			groups[name] = values
		}
	}
	daq, actions := object(groups["daq"]), object(groups["ips_actions"])
	observed := func(group, key string) any {
		if _, ok := groups[group]; !ok {
			return nil
		}
		return get(object(groups[group]), key, 0)
	}
	return Object{"native": groups, "decoder": Object{"pkts": get(daq, "received", 0), "bytes": get(daq, "rx_bytes", 0)}, "capture": Object{"kernel_drops": get(daq, "dropped", 0)}, "inspection": Object{"decoder_discards": observed("codec", "discards"), "tcp_gaps": observed("stream_tcp", "gaps"), "tcp_invalid_ack": observed("stream_tcp", "invalid_ack"), "tcp_max_bytes": observed("stream_tcp", "exceeded_max_bytes"), "tcp_max_segs": observed("stream_tcp", "exceeded_max_segs"), "event_limit": observed("detection", "event_limit")}, "ips": Object{"accepted": get(daq, "allow", 0), "blocked": integer(daq["block"]) + integer(daq["blacklist"]), "rejected": get(actions, "reject", 0), "drop_reason": Object{"rules": integer(actions["block"]) + integer(actions["drop"])}}, "flow": Object{"memuse": nil}, "tcp": Object{"reassembly_memuse": nil, "memory": object(groups["stream_tcp"])["memory"]}}
}
func commandOutput(ctx context.Context, timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	configureCommand(cmd)
	var out bytes.Buffer
	writer := &boundedLogWriter{max: 16 << 20, write: func(b []byte) { out.Write(b) }}
	cmd.Stdout = writer
	cmd.Stderr = writer
	err := cmd.Run()
	if writer.exceeded {
		return "", errors.New("命令输出超过上限")
	}
	return strings.ToValidUTF8(out.String(), "�"), err
}
func serviceSnapshot(ctx context.Context) Object {
	out, _ := commandOutput(ctx, 5*time.Second, "systemctl", "show", "ips", "--property", "ActiveState,SubState,NRestarts,ActiveEnterTimestamp")
	unit := Object{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			unit[k] = v
		}
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(readText("/run/snort/snort.pid")))
	result := Object{"state": get(unit, "ActiveState", "unknown"), "sub": get(unit, "SubState", ""), "restarts": integer(unit["NRestarts"]), "since": get(unit, "ActiveEnterTimestamp", ""), "pid": 0, "uptime": nil, "cpu_seconds": nil, "memory": nil}
	if pid <= 0 {
		return result
	}
	if _, err := os.Stat("/proc/" + strconv.Itoa(pid)); err != nil {
		return result
	}
	result["pid"] = pid
	stat := readText("/proc/" + strconv.Itoa(pid) + "/stat")
	end := strings.LastIndexByte(stat, ')')
	if end >= 0 {
		fields := strings.Fields(stat[end+1:])
		boot := strings.Fields(readText("/proc/uptime"))
		if len(fields) > 19 && len(boot) > 0 {
			hz := float64(100)
			if output, err := commandOutput(ctx, time.Second, "getconf", "CLK_TCK"); err == nil && number(strings.TrimSpace(output)) > 0 {
				hz = number(strings.TrimSpace(output))
			}
			result["uptime"] = int64(max(0, number(boot[0])-number(fields[19])/hz))
			result["cpu_seconds"] = (number(fields[11]) + number(fields[12])) / hz
		}
	}
	rss, _ := processMemory(pid)
	result["memory"] = rss
	return result
}
func processMemory(pid int) (int64, int64) {
	rss, peak := int64(0), int64(0)
	for _, line := range strings.Split(readText("/proc/"+strconv.Itoa(pid)+"/status"), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] == "VmRSS:" {
			rss = integer(fields[1]) * 1024
		}
		if fields[0] == "VmHWM:" {
			peak = integer(fields[1]) * 1024
		}
	}
	return rss, peak
}
func queueListeners() Object {
	data, err := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
	if err != nil {
		return Object{"queues": []Object{}, "listeners_known": false, "queue_total": nil, "kernel_drops": nil, "user_drops": nil}
	}
	queues := []Object{}
	var total, drops, user int64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		id, err := strconv.Atoi(fields[0])
		if err != nil || id < 0 || id > 3 || integer(fields[1]) == 0 {
			continue
		}
		backlog, kd, ud := integer(fields[2]), integer(fields[5]), integer(fields[6])
		total += backlog
		drops += kd
		user += ud
		queues = append(queues, Object{"id": id, "backlog": backlog, "kernel_drops": kd, "user_drops": ud})
	}
	return Object{"queues": queues, "count": len(queues), "queue_total": total, "kernel_drops": drops, "user_drops": user, "listeners_known": true, "listeners_at": now()}
}
func queueCounter(table Object) (any, any) {
	for _, entry := range array(table["nftables"]) {
		expressions := array(object(object(entry)["rule"])["expr"])
		queued := false
		var counter Object
		for _, e := range expressions {
			v := object(e)
			if v["queue"] != nil {
				queued = true
			}
			if v["counter"] != nil {
				counter = object(v["counter"])
			}
		}
		if queued && counter != nil {
			return counter["packets"], counter["bytes"]
		}
	}
	return nil, nil
}
func (m *RuleManager) Runtime() Object {
	m.runtimeMu.RLock()
	defer m.runtimeMu.RUnlock()
	return clone(m.runtime)
}
func (m *RuleManager) sampleRuntime(ctx context.Context) {
	pluginError := m.ensureSessionLoaded(ctx)
	if err := m.maybeRefreshPolicies(); pluginError == nil {
		pluginError = err
	}
	service := serviceSnapshot(ctx)
	table := Object{}
	if out, err := commandOutput(ctx, 3*time.Second, "nft", "-j", "list", "table", "inet", "ips"); err == nil {
		decode([]byte(out), &table)
	}
	queue := queueListeners()
	stamp := now()
	queue["ts"] = stamp
	queue["packets"], queue["bytes"] = queueCounter(table)
	m.mu.Lock()
	paused := m.paused
	m.mu.Unlock()
	busy := m.jobs.Busy()
	previous := m.Runtime()
	engine := object(previous["engine"])
	telemetry := clone(object(previous["telemetry"]))
	if pluginError != nil {
		telemetry["error"] = pluginError.Error()
	}
	telemetry["updating"] = busy
	if !busy && !paused && m.engineGate.TryLock() {
		sample := Object{}
		var err error
		for _, op := range []string{"dump-counters", "version", "ruleset-stats", "running-mode", "capture-mode", "uptime", "ruleset-reload-time"} {
			sample[op], err = m.engineOperation(ctx, op, 2*time.Second)
			if err != nil {
				break
			}
		}
		m.engineGate.Unlock()
		if err == nil && pluginError == nil {
			engine = sample
			telemetry["as_of"] = stamp
			telemetry["error"] = ""
		} else if err != nil {
			telemetry["error"] = err.Error()
		}
	}
	if queue["packets"] == nil {
		decoder := object(object(engine["dump-counters"])["decoder"])
		queue["packets"], queue["bytes"] = decoder["pkts"], decoder["bytes"]
	}
	rates := Object{"pps": 0.0, "mbps": 0.0, "fps": 0.0}
	old := object(previous["queue_listeners"])
	elapsed := stamp - number(old["ts"])
	if elapsed >= .5 && old["packets"] != nil && queue["packets"] != nil {
		if delta := number(queue["packets"]) - number(old["packets"]); delta >= 0 {
			rates["pps"] = delta / elapsed
		}
		if delta := number(queue["bytes"]) - number(old["bytes"]); delta >= 0 {
			rates["mbps"] = delta * 8 / elapsed / 1e6
		}
	}
	m.runtimeMu.Lock()
	m.runtime = Object{"schema": 1, "published": stamp, "engine": engine, "service": service, "queue_table": table, "queue_listeners": queue, "rates": rates, "telemetry": telemetry}
	m.runtimeMu.Unlock()
}
func (m *RuleManager) RuntimeLoop(ctx context.Context) {
	// Sampling and publication are independent. Busy or unresponsive engines never
	// prevent a current job/status snapshot reaching the unprivileged Web process.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			m.sampleRuntime(ctx)
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	}()
	defer func() { <-done }()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		value := m.Runtime()
		value["schema"] = 1
		value["published"] = now()
		value["update_status"] = m.jobs.Status()
		value["reload_state"] = m.jobs.ReloadState()
		var history Object
		readJSON(filepath.Join(m.state, "history-reset.json"), &history)
		value["history_reset"] = history
		data, err := json.Marshal(value)
		if err == nil && len(data) <= rpcResponseLimit {
			atomicWrite(filepath.Join(filepath.Dir(m.socket), "status.json"), data, 0640)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (m *RuleManager) SystemPayload(ctx context.Context) Object {
	value := m.Runtime()
	engine := object(value["engine"])
	host, _ := os.Hostname()
	storage := Object{"disk": Object{}, "logs": []Object{}}
	root := os.Getenv("IPS_LOG_STORAGE_ROOT")
	if root == "" {
		root = "/var/lib/ips-snort-logs"
	}
	var stat syscall.Statfs_t
	if syscall.Statfs(root, &stat) == nil {
		total, free := uint64(stat.Blocks)*uint64(stat.Bsize), uint64(stat.Bavail)*uint64(stat.Bsize)
		storage["disk"] = Object{"total": total, "used": total - uint64(stat.Bfree)*uint64(stat.Bsize), "free": free}
	}
	paths := []string{filepath.Join(root, "events/events.json")}
	for _, pattern := range []string{"*file_connector_ndr_transmit", "*alert_json.txt"} {
		matches, _ := filepath.Glob(filepath.Join(root, "snort", pattern))
		paths = append(paths, matches...)
	}
	logs := []Object{}
	for _, path := range paths[:min(128, len(paths))] {
		if info, err := os.Stat(path); err == nil {
			logs = append(logs, Object{"name": filepath.Base(path), "size": info.Size(), "mtime": info.ModTime().Unix()})
		}
	}
	storage["logs"] = logs
	service := object(value["service"])
	components := []Object{}
	state, message := "ok", "检测服务正常"
	if service["state"] != "active" {
		state, message = "error", "检测服务未运行"
	}
	components = append(components, Object{"id": "engine", "name": "检测引擎", "state": state, "message": message, "at": now()})
	if text(object(value["telemetry"])["error"]) != "" {
		components = append(components, Object{"id": "telemetry", "name": "运行状态", "state": "warning", "message": object(value["telemetry"])["error"], "at": now()})
	}
	return Object{"telemetry": value["telemetry"], "components": components, "host": host, "version": "1.0", "service": service, "ruleset": engine["ruleset-stats"], "queue": value["queue_listeners"], "rates": value["rates"], "counters": engine["dump-counters"], "storage": storage, "engine": Object{"version": engine["version"], "uptime": present(engine["uptime"], service["uptime"]), "running_mode": engine["running-mode"], "capture_mode": engine["capture-mode"], "reload_time_ms": nil, "error": object(value["telemetry"])["error"]}, "reload": m.jobs.ReloadState(), "go": Object{"version": runtime.Version(), "workers": WorkerCount()}}
}
