package console

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type historyRuntime struct {
	root, web, checkpoint string
	command               func(context.Context, time.Duration, ...string) (string, error)
	engine                func(context.Context, string, time.Duration) (string, error)
	manager               func(context.Context, string, Object) (any, error)
	ready                 func(context.Context) bool
	identity              func() (string, int, error)
	validate              func() error
}

func validateHistoryStorage() error {
	native, stream, err := logPaths("", "/etc/ips-log-storage.json")
	if err != nil {
		return err
	}
	for source, target := range map[string]string{native: filepath.Join(managedLogRoot, "snort"), filepath.Dir(stream): filepath.Join(managedLogRoot, "events")} {
		a, err := os.Stat(source)
		if err != nil {
			return errors.New("当前日志目录不可用")
		}
		b, err := os.Stat(target)
		if err != nil || !a.IsDir() || !b.IsDir() || !os.SameFile(a, b) {
			return errors.New("日志存储与清理目录不一致，请先完成日志迁移")
		}
	}
	return nil
}

func historyProcessIdentity() (string, int, error) {
	pid, err := strconv.Atoi(strings.TrimSpace(readText("/run/snort/snort.pid")))
	if err != nil || pid <= 0 {
		return "", 0, errors.New("检测进程标识不可用")
	}
	stat := readText(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	end := strings.LastIndexByte(stat, ')')
	if end < 0 {
		return "", 0, errors.New("检测进程状态不可用")
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) < 20 {
		return "", 0, errors.New("检测进程状态无效")
	}
	return strconv.Itoa(pid) + ":" + fields[19], pid, nil
}

func RunHistoryReset(ctx context.Context, state, id string) error {
	if os.Geteuid() != 0 || state != resetState || !jobIDPattern.MatchString(id) {
		return errors.New("历史维护参数无效")
	}
	runtime := historyRuntime{
		root: managedLogRoot, web: resetWebState, checkpoint: "/var/lib/ips-event-bridge/offsets.json",
		command: commandOutput, engine: engineCommand, ready: historyWebReady, identity: historyProcessIdentity,
		validate: validateHistoryStorage,
		manager: func(ctx context.Context, operation string, params Object) (any, error) {
			return managerRequest(ctx, "/run/ips-rule-manager/control.sock", operation, params)
		},
	}
	return runHistoryReset(ctx, state, id, runtime)
}

func runHistoryReset(ctx context.Context, state, id string, r historyRuntime) (failure error) {
	var value Object
	if err := readJSON(filepath.Join(state, "history-reset.json"), &value); err != nil || value["id"] != id || value["state"] != "queued" {
		return errors.New("历史任务无效或已执行")
	}
	if _, err := r.manager(ctx, "history-reset-begin", Object{"job": id}); err != nil {
		return err
	}
	timers, recoverUnits := []string{}, []string{}
	var handoff *historyHandoff
	command := func(args ...string) error { _, err := r.command(ctx, 150*time.Second, args...); return err }
	active := func(unit string) bool { return command("systemctl", "is-active", "--quiet", unit) == nil }
	phase := func(s string) error {
		value["state"], value["phase"] = "running", s
		return writeJSON(filepath.Join(state, "history-reset.json"), value)
	}
	defer func() {
		// Recovery must work even when the original command was cancelled.
		recovery, cancel := context.WithTimeout(context.Background(), 180*time.Second)
		defer cancel()
		ctx = recovery
		if failure != nil {
			if handoff != nil {
				reply, err := r.engine(ctx, "reopen_logs()", 30*time.Second)
				if err != nil || engineFailure.MatchString(reply) || !strings.Contains(reply, "NDR_LOGS_REOPENED threads=") {
					failure = errors.Join(failure, errors.New("检测日志重开未恢复，隔离日志已保留"))
				}
			}
			for _, unit := range recoverUnits {
				failure = errors.Join(failure, command("systemctl", "start", unit))
			}
		}
		for _, unit := range timers {
			failure = errors.Join(failure, command("systemctl", "start", unit))
		}
		if failure != nil {
			value["state"], value["phase"], value["finished"], value["error"] = "failed", "清空或恢复采集失败", now(), failure.Error()
			failure = errors.Join(failure, writeJSON(filepath.Join(state, "history-reset.json"), value))
		}
		_, err := r.manager(ctx, "history-reset-finish", Object{"job": id})
		if err != nil {
			failure = errors.Join(failure, errors.New("无法结束历史维护状态"), err)
			value["state"], value["phase"], value["finished"], value["error"] = "failed", "结束维护失败", now(), failure.Error()
			failure = errors.Join(failure, writeJSON(filepath.Join(state, "history-reset.json"), value))
			_, retry := r.manager(ctx, "history-reset-finish", Object{"job": id})
			failure = errors.Join(failure, retry)
		}
	}()
	if value["scope"] != "database" && value["scope"] != "all" {
		return errors.New("历史任务范围无效")
	}
	database, stream := filepath.Join(r.web, "snort-ndr.db"), filepath.Join(r.root, "events/events.json")
	if _, err := historyMembersAt(database, r.web); err != nil {
		return err
	}
	var engineIdentity string
	var enginePID int
	if value["scope"] == "all" {
		if r.validate != nil {
			if err := r.validate(); err != nil {
				return err
			}
		}
		if _, _, err := historyLogMembers(r.root); err != nil {
			return err
		}
		info, err := os.Lstat(r.checkpoint)
		if err != nil && !errors.Is(err, os.ErrNotExist) || info != nil && !info.Mode().IsRegular() {
			return errors.New("采集位置文件异常")
		}
		help, err := r.engine(ctx, "help()", 5*time.Second)
		if err != nil || !strings.Contains(help, "reopen_logs") {
			return errors.New("当前引擎不支持无中断清空，请先更新引擎")
		}
		engineIdentity, enginePID, err = r.identity()
		if err != nil {
			return err
		}
	}
	stop := func(unit string) error {
		if err := command("systemctl", "stop", unit); err != nil {
			return err
		}
		out, err := r.command(ctx, 5*time.Second, "systemctl", "show", unit, "-p", "MainPID", "--value")
		if err != nil || strings.TrimSpace(out) != "0" {
			return errors.New("日志或控制台服务未完全停止")
		}
		return nil
	}
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
	units := []string{"ips-web"}
	if value["scope"] == "all" {
		units = []string{"ips-event-bridge", "ips-web"}
		if active("ips-quic-observer") {
			units = append([]string{"ips-quic-observer"}, units...)
		}
	}
	if err := phase("暂停日志采集和控制台"); err != nil {
		return err
	}
	for _, unit := range units {
		if active(unit) {
			recoverUnits = append(recoverUnits, unit)
			if err := stop(unit); err != nil {
				return err
			}
		}
	}
	if value["scope"] == "all" {
		if err := phase("切换原始事件日志"); err != nil {
			return err
		}
		var err error
		handoff, err = stageHistoryLogs(r.root, id)
		if handoff != nil {
			value["log_backup"] = handoff.backup
		}
		if err != nil {
			return err
		}
		if err = phase("等待检测日志句柄切换"); err != nil {
			return err
		}
		reply, err := r.engine(ctx, "reopen_logs()", 30*time.Second)
		if err != nil || engineFailure.MatchString(reply) || !strings.Contains(reply, "NDR_LOGS_REOPENED threads=") {
			return errors.New("引擎未确认日志切换，历史日志已保留")
		}
		current, _, err := r.identity()
		if err != nil || current != engineIdentity {
			return errors.New("检测进程发生变化，历史日志已保留")
		}
		if err = handoff.verifyClosed(enginePID); err != nil {
			return err
		}
	}
	if err := phase("切换空事件库"); err != nil {
		return err
	}
	backup, err := resetHistoryDatabaseAt(database, stream, r.web)
	if err != nil {
		return err
	}
	value["backup"] = backup
	if handoff != nil {
		if info, err := os.Lstat(r.checkpoint); err == nil {
			if !info.Mode().IsRegular() {
				return errors.New("采集位置文件发生变化")
			}
			checkpointBackup := filepath.Join(filepath.Dir(r.checkpoint), ".history-reset-"+id+".json")
			if err = os.Rename(r.checkpoint, checkpointBackup); err != nil {
				return err
			}
			handoff.files = append(handoff.files, retiredHistoryFile{checkpointBackup, info})
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err = phase("恢复日志采集和控制台"); err != nil {
		return err
	}
	for i := len(recoverUnits) - 1; i >= 0; i-- {
		if err = command("systemctl", "start", recoverUnits[i]); err != nil {
			return err
		}
	}
	deadline := time.Now().Add(150 * time.Second)
	for {
		ready := active("ips-web") && r.ready(ctx)
		if handoff != nil {
			current, _, err := r.identity()
			if err != nil || current != engineIdentity {
				return errors.New("检测进程发生变化，历史备份已保留")
			}
			_, err = r.engine(ctx, "show_config_generation()", 2*time.Second)
			ready = ready && err == nil
			for _, unit := range recoverUnits {
				ready = ready && active(unit)
			}
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			return errors.New("采集恢复后未就绪，历史备份已保留")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	if handoff != nil {
		if err = phase("删除已隔离的历史"); err != nil {
			return err
		}
		if err = handoff.remove(); err != nil {
			return err
		}
		if err = removeHistoryDatabaseBackup(backup, r.web); err != nil {
			return err
		}
		delete(value, "backup")
		delete(value, "log_backup")
		value["engine_preserved"] = true
	}
	value["state"], value["phase"], value["finished"], value["error"] = "done", "已清空并恢复采集", now(), ""
	return writeJSON(filepath.Join(state, "history-reset.json"), value)
}
