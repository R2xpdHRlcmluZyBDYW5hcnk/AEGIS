package console

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const resetState = "/var/lib/ips-snort-rule-manager"
const resetWebState = "/var/lib/ips-snort-web"
const resetConfig = "/etc/ips-snort-web.conf"

var historyNames = regexp.MustCompile(`^(?:[0-9]+_)?(?:file_connector_ndr_transmit|alert_json\.txt|quic_observer\.json|ndr_session\.json|events?\.json)(?:\.[0-9]+(?:\.gz)?)?$`)
var streamNames = regexp.MustCompile(`^events\.json(?:\.[0-9]+(?:\.gz)?)?$`)
var historyArchive = regexp.MustCompile(`^\.response-[0-9]{8}T[0-9]{6}-[0-9]+(?:-failed)?$`)

func (m *RuleManager) StartHistoryReset(scope string) (Object, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.paused || m.jobs.Busy() {
		return nil, errors.New("规则或维护任务正在执行")
	}
	if m.state != resetState {
		return nil, errors.New("历史维护只支持独立服务布局")
	}
	var previous Object
	readJSON(filepath.Join(m.state, "history-reset.json"), &previous)
	if previous["state"] == "queued" || previous["state"] == "running" {
		return nil, errors.New("历史清空任务正在执行")
	}
	id := token()[:32]
	value := Object{"id": id, "state": "queued", "scope": scope, "phase": "等待开始", "started": now(), "finished": 0, "error": ""}
	if err := writeJSON(filepath.Join(m.state, "history-reset.json"), value); err != nil {
		return nil, err
	}
	if err := atomicWrite(filepath.Join(m.state, "maintenance"), []byte("history-reset\n"), 0600); err != nil {
		return nil, err
	}
	m.paused = true
	program, err := os.Executable()
	if err == nil {
		_, err = commandOutput(m.ctx, 10*time.Second, "systemd-run", "--quiet", "--collect", "--unit=ips-history-reset-"+id[:12], "--on-active=2s", "--timer-property=AccuracySec=1s", "--timer-property=RemainAfterElapse=no", program, "history-reset", "--run", "--job", id, "--state-dir", m.state)
	}
	if err != nil {
		value["state"], value["phase"], value["finished"], value["error"] = "failed", "未开始", now(), "无法启动历史清空任务"
		writeJSON(filepath.Join(m.state, "history-reset.json"), value)
		os.Remove(filepath.Join(m.state, "maintenance"))
		m.paused = false
		return nil, errors.New("无法启动历史清空任务")
	}
	return Object{"ok": true, "pending": true, "reset_id": id}, nil
}
func historyMembers(database string) ([]string, error) {
	if database != filepath.Join(resetWebState, "snort-ndr.db") {
		return nil, errors.New("事件库清理目标不符合安装布局")
	}
	paths := []string{}
	for _, suffix := range []string{"", "-wal", "-shm", ".summary.db", ".summary.db-wal", ".summary.db-shm"} {
		p := database + suffix
		info, err := os.Lstat(p)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if info != nil && !info.Mode().IsRegular() {
			return nil, errors.New("事件库成员类型异常")
		}
		resolved, err := filepath.EvalSymlinks(filepath.Dir(p))
		if err != nil || resolved != resetWebState {
			return nil, errors.New("事件库目录被替换")
		}
		paths = append(paths, p)
	}
	return paths, nil
}
func resetHistoryDatabase(database, stream string) (string, error) {
	targets, err := historyMembers(database)
	if err != nil {
		return "", err
	}
	var cutoff any
	if info, e := os.Lstat(stream); e == nil {
		if !info.Mode().IsRegular() {
			return "", errors.New("事件流类型异常")
		}
		dev, ino := fileIdentity(info)
		cutoff = Object{"device": dev, "inode": ino, "offset": info.Size()}
	} else if !errors.Is(e, os.ErrNotExist) {
		return "", e
	}
	owner, err := os.Stat(database)
	if errors.Is(err, os.ErrNotExist) {
		owner, err = os.Stat(resetWebState)
	}
	if err != nil {
		return "", err
	}
	backup, err := os.MkdirTemp(resetWebState, "history-backup-"+time.Now().UTC().Format("20060102T150405")+"-")
	if err != nil {
		return "", err
	}
	moved := []string{}
	success := false
	defer func() {
		if !success {
			for _, suffix := range []string{"", "-wal", "-shm"} {
				os.Remove(database + suffix)
			}
			for _, p := range moved {
				os.Rename(filepath.Join(backup, filepath.Base(p)), p)
			}
		}
	}()
	for _, p := range targets {
		if fileExists(p) {
			if err = os.Rename(p, filepath.Join(backup, filepath.Base(p))); err != nil {
				return "", err
			}
			moved = append(moved, p)
		}
	}
	db, err := sql.Open("aegis-sqlite", "file:"+database+"?_auto_vacuum=incremental")
	if err != nil {
		return "", err
	}
	if _, err = db.Exec("CREATE TABLE event_state(key TEXT PRIMARY KEY,value TEXT NOT NULL)"); err == nil {
		raw, _ := json.Marshal(cutoff)
		_, err = db.Exec("INSERT INTO event_state VALUES('clear_epoch',?),('stream_cutoff',?)", token()[:32], string(raw))
	}
	closeErr := db.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	if err = os.Chmod(database, owner.Mode().Perm()); err != nil {
		return "", err
	}
	if err = copyOwnership(owner, database); err != nil {
		return "", err
	}
	if err = syncDirectory(backup); err != nil {
		return "", err
	}
	if err = syncDirectory(resetWebState); err != nil {
		return "", err
	}
	success = true
	return backup, nil
}
func removeHistory(database, root string) error {
	targets, err := historyMembers(database)
	if err != nil {
		return err
	}
	logs, dirs, err := historyLogMembers(root)
	if err != nil {
		return err
	}
	checkpoint := "/var/lib/ips-event-bridge/offsets.json"
	if info, e := os.Lstat(checkpoint); e == nil && !info.Mode().IsRegular() {
		return errors.New("采集位置文件异常")
	}
	for _, p := range append(append(logs, targets...), checkpoint) {
		if err = os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	for _, p := range dirs {
		if err = os.Remove(p); err != nil {
			return err
		}
	}
	return nil
}
func historyLogMembers(root string) ([]string, []string, error) {
	logs, dirs := []string{}, []string{}
	for _, spec := range []struct {
		root    string
		pattern *regexp.Regexp
	}{{filepath.Join(root, "snort"), historyNames}, {filepath.Join(root, "events"), streamNames}} {
		resolved, err := filepath.EvalSymlinks(spec.root)
		if err != nil || resolved != spec.root {
			return nil, nil, errors.New("日志目录被替换")
		}
		entries, err := os.ReadDir(spec.root)
		if err != nil {
			return nil, nil, err
		}
		for _, entry := range entries {
			p := filepath.Join(spec.root, entry.Name())
			if spec.pattern.MatchString(entry.Name()) {
				info, e := os.Lstat(p)
				if e != nil || !info.Mode().IsRegular() {
					return nil, nil, errors.New("日志清理成员异常")
				}
				logs = append(logs, p)
			} else if spec.root == filepath.Join(root, "snort") && historyArchive.MatchString(entry.Name()) {
				info, e := os.Lstat(p)
				if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
					return nil, nil, errors.New("日志归档目录异常")
				}
				members, e := os.ReadDir(p)
				if e != nil {
					return nil, nil, e
				}
				for _, member := range members {
					q := filepath.Join(p, member.Name())
					info, e := os.Lstat(q)
					if e != nil || !info.Mode().IsRegular() || !historyNames.MatchString(member.Name()) {
						return nil, nil, errors.New("日志归档成员异常")
					}
					logs = append(logs, q)
				}
				dirs = append(dirs, p)
			}
		}
	}
	return logs, dirs, nil
}
func historyWebReady(ctx context.Context) bool {
	cfg, err := LoadConfig(resetConfig)
	if err != nil {
		return false
	}
	host := cfg.Bind
	if host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	request, err := http.NewRequestWithContext(ctx, "GET", "http://"+net.JoinHostPort(host, strconv.Itoa(cfg.Port))+"/healthz", nil)
	if err != nil {
		return false
	}
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	res, err := client.Do(request)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	var value Object
	return res.StatusCode == 200 && json.NewDecoder(res.Body).Decode(&value) == nil && value["ok"] == true && value["event_db_ready"] == true
}
func RunHistoryReset(ctx context.Context, state, id string) (failure error) {
	if os.Geteuid() != 0 || state != resetState || !jobIDPattern.MatchString(id) {
		return errors.New("历史维护参数无效")
	}
	var value Object
	if err := readJSON(filepath.Join(state, "history-reset.json"), &value); err != nil || value["id"] != id || value["state"] != "queued" {
		return errors.New("历史任务无效或已执行")
	}
	socket := "/run/ips-rule-manager/control.sock"
	if _, err := managerRequest(ctx, socket, "history-reset-begin", Object{"job": id}); err != nil {
		return err
	}
	root := "/var/lib/ips-snort-logs"
	stream := filepath.Join(root, "events/events.json")
	timers, recoverUnits := []string{}, []string{}
	command := func(args ...string) error { _, err := commandOutput(ctx, 150*time.Second, args...); return err }
	active := func(unit string) bool { return command("systemctl", "is-active", "--quiet", unit) == nil }
	phase := func(s string) error {
		value["state"], value["phase"] = "running", s
		return writeJSON(filepath.Join(state, "history-reset.json"), value)
	}
	stop := func(unit string) error {
		if err := command("systemctl", "stop", unit); err != nil {
			return err
		}
		out, err := commandOutput(ctx, 5*time.Second, "systemctl", "show", unit, "-p", "MainPID", "--value")
		if err != nil || strings.TrimSpace(out) != "0" {
			return errors.New("服务未完全停止")
		}
		return nil
	}
	defer func() {
		if failure != nil {
			value["state"], value["phase"], value["finished"], value["error"] = "failed", "清空或重启失败", now(), failure.Error()
			writeJSON(filepath.Join(state, "history-reset.json"), value)
			for _, unit := range recoverUnits {
				command("systemctl", "start", unit)
			}
		}
		for _, unit := range timers {
			command("systemctl", "start", unit)
		}
		managerRequest(ctx, socket, "history-reset-finish", Object{"job": id})
	}()
	for _, unit := range []string{"ips-log-maintenance.timer", "snort-home-net.timer"} {
		if active(unit) {
			timers = append(timers, unit)
			if err := command("systemctl", "stop", unit); err != nil {
				return err
			}
		}
	}
	if err := command("systemctl", "stop", "ips-log-maintenance.service", "snort-home-net.service"); err != nil {
		return err
	}
	if value["scope"] == "database" {
		phase("停止控制台")
		recoverUnits = []string{"ips-web"}
		if err := stop("ips-web"); err != nil {
			return err
		}
		phase("切换空事件库")
		backup, err := resetHistoryDatabase(filepath.Join(resetWebState, "snort-ndr.db"), stream)
		if err != nil {
			return err
		}
		value["backup"] = backup
		phase("恢复控制台")
		if err = command("systemctl", "start", "ips-web"); err != nil {
			return err
		}
	} else if value["scope"] == "all" {
		observer := active("ips-quic-observer")
		recoverUnits = []string{"ips", "ips-event-bridge", "ips-web"}
		if observer {
			recoverUnits = append(recoverUnits, "ips-quic-observer")
			if err := stop("ips-quic-observer"); err != nil {
				return err
			}
		}
		phase("停止检测和采集")
		for _, unit := range []string{"ips", "ips-event-bridge", "ips-web"} {
			if err := stop(unit); err != nil {
				return err
			}
		}
		phase("清空事件和未入库日志")
		old, _ := os.Stat(stream)
		if err := removeHistory(filepath.Join(resetWebState, "snort-ndr.db"), root); err != nil {
			return err
		}
		if err := atomicWrite(stream, nil, 0644); err != nil {
			return err
		}
		if old != nil {
			os.Chmod(stream, old.Mode().Perm())
			copyOwnership(old, stream)
		}
		phase("重新启动检测和采集")
		for _, unit := range recoverUnits {
			if err := command("systemctl", "start", unit); err != nil {
				return err
			}
		}
	} else {
		return errors.New("历史任务范围无效")
	}
	deadline := time.Now().Add(150 * time.Second)
	for {
		ready := active("ips-web") && historyWebReady(ctx)
		if value["scope"] == "all" {
			_, err := engineCommand(ctx, "show_config_generation()", 2*time.Second)
			ready = ready && err == nil && active("ips-event-bridge")
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			return errors.New("服务重启后未就绪，备份和故障状态已保留")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	value["state"], value["phase"], value["finished"], value["error"] = "done", "已清空并恢复采集", now(), ""
	return writeJSON(filepath.Join(state, "history-reset.json"), value)
}
