package console

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func (m *RuleManager) ensureSessionLoaded(ctx context.Context) error {
	var receipt Object
	if err := readJSON("/etc/ips-session-logger.json", &receipt); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return errors.New("会话扩展校验记录无效")
	}
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(text(receipt["engine_sha256"])) {
		return errors.New("会话扩展引擎摘要无效")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(readText("/run/snort/snort.pid")))
	if err != nil || pid <= 0 {
		return errors.New("检测进程尚未就绪")
	}
	stat := readText("/proc/" + strconv.Itoa(pid) + "/stat")
	end := strings.LastIndexByte(stat, ')')
	if end < 0 {
		return errors.New("检测进程状态不可读")
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) <= 19 {
		return errors.New("检测进程状态无效")
	}
	key := Object{"process": []any{pid, fields[19], strings.TrimSpace(readText("/proc/sys/kernel/random/boot_id"))}, "sha256": receipt["sha256"]}
	marker := filepath.Join(filepath.Dir(m.socket), "session-logger-loaded.json")
	var loaded Object
	if readJSON(marker, &loaded) == nil {
		a, _ := json.Marshal(key)
		b, _ := json.Marshal(loaded)
		if string(a) == string(b) {
			return nil
		}
	}
	if !m.mu.TryLock() {
		return nil
	}
	defer m.mu.Unlock()
	if m.paused || m.jobs.Busy() {
		return nil
	}
	guard, err := lockConfiguration(ctx, m.live.Config)
	if err != nil {
		return err
	}
	defer guard.Close()
	m.engineGate.Lock()
	defer m.engineGate.Unlock()
	actual, err := digestFile(filepath.Join(enginePrefix(), "bin/snort"))
	if err != nil || actual != receipt["engine_sha256"] {
		return errors.New("会话扩展引擎 ABI 校验失败")
	}
	arguments, err := pluginArguments()
	if err != nil {
		return err
	}
	if len(arguments) == 0 {
		return nil
	}
	before, err := engineCommand(ctx, "show_config_generation()", 5*time.Second)
	if err != nil {
		return err
	}
	config, _ := json.Marshal(m.live.Config)
	library, _ := json.Marshal(arguments[1])
	reply, err := engineCommand(ctx, "snort.reload_config("+string(config)+","+string(library)+")", 300*time.Second)
	if err != nil || engineFailure.MatchString(reply) {
		return errors.New("会话扩展配置重载失败")
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		after, err := engineCommand(ctx, "show_config_generation()", 5*time.Second)
		if err != nil {
			return err
		}
		if after != before {
			return writeJSON(marker, key)
		}
		if time.Now().After(deadline) {
			return errors.New("会话扩展重载代次未推进")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
