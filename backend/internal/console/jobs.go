package console

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

var clockPattern = regexp.MustCompile(`^(?:[01][0-9]|2[0-3]):[0-5][0-9]$`)
var suppressionExpression = regexp.MustCompile(`^suppress\s+gen_id\s+([0-9]+)\s*,\s*sig_id\s+([0-9]+)`)
var jobIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func suppressionText(line string) string {
	line = strings.TrimSpace(line)
	prefix := "# ips-web-pending-suppress "
	if strings.HasPrefix(line, prefix) {
		if data, err := base64.URLEncoding.DecodeString(strings.TrimPrefix(line, prefix)); err == nil {
			return string(data)
		}
	}
	return line
}
func validateSuggestion(line string) error {
	if len(line) > 4096 {
		return errors.New("规则建议超过长度限制")
	}
	header := regexp.MustCompile(`^(alert|block) (tcp|udp) any any -> any ([0-9]{1,5}) \(msg:"[^"\\;:\x00-\x1f\x7f]{1,80}"; (.*)rev:1;\)$`)
	m := header.FindStringSubmatch(line)
	if len(m) != 5 {
		return errors.New("规则不符合事件建议格式")
	}
	port, _ := strconv.Atoi(m[3])
	if port < 1 || port > 65535 {
		return errors.New("规则端口无效")
	}
	domain := `[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]`
	hex := `\|[0-9A-F]{2}(?: [0-9A-F]{2})*\|`
	body := m[4]
	for _, content := range regexp.MustCompile(hex).FindAllString(body, -1) {
		if len(strings.Fields(strings.Trim(content, "|"))) > 512 {
			return errors.New("规则内容字节超过限制")
		}
	}
	patterns := []string{}
	if m[2] == "tcp" {
		patterns = append(patterns, `flow:to_server,established; http_header:field host; content:"`+domain+`",nocase; (?:http_method; content:"[A-Z]{2,12}"; )?(?:http_uri:path; content:"`+hex+`"; )?`, `flow:to_server,established; ssl_state:client_hello; content:"`+domain+`",nocase; `, `flags:[FSRPAUEC0]{1,8}; (?:(?:ttl|tos|window|dsize):[0-9]{1,5}; ){0,4}`)
	}
	if port == 53 {
		patterns = append(patterns, `flow:to_server(?:,established)?; content:"`+hex+`",nocase; `)
	}
	patterns = append(patterns, `flow:to_server(?:,established)?; appids:"[A-Za-z0-9 _./:-]{1,80}"; `)
	for _, pattern := range patterns {
		if regexp.MustCompile("^(?:" + pattern + ")$").MatchString(body) {
			for _, match := range regexp.MustCompile(`(ttl|tos|window|dsize):([0-9]+);`).FindAllStringSubmatch(body, -1) {
				n, _ := strconv.Atoi(match[2])
				if n > 65535 || ((match[1] == "ttl" || match[1] == "tos") && n > 255) {
					return errors.New("报文条件超出范围")
				}
			}
			return nil
		}
	}
	return errors.New("规则必须包含经过校验的协议和内容特征")
}

type ruleBackup struct {
	Directory string
	Paths     map[string]*string `json:"paths"`
	GoBackend bool               `json:"go_backend"`
	AppID     Object             `json:"openappid"`
	RulesDir  string             `json:"rules_dir"`
}

func newRuleBackup(m *RuleManager, id string) (*ruleBackup, error) {
	dir := filepath.Join(m.state, "transaction-"+id)
	if err := os.Mkdir(dir, 0700); err != nil {
		return nil, err
	}
	backup := &ruleBackup{Directory: dir, Paths: map[string]*string{}, GoBackend: true, RulesDir: filepath.Join(m.live.Data, "rules")}
	ready := false
	defer func() {
		if !ready {
			backup.Close(m.state)
		}
	}()
	paths := []string{}
	for _, path := range m.live.controls {
		paths = append(paths, path)
	}
	paths = append(paths, m.live.groupsFile())
	for _, root := range []string{filepath.Join(m.live.Data, "rules"), m.live.Sources} {
		files, err := privateTree(root)
		if err != nil {
			return nil, err
		}
		for name := range files {
			paths = append(paths, filepath.Join(root, name))
		}
	}
	seen := map[string]bool{}
	sort.Strings(paths)
	for _, path := range paths {
		if seen[path] {
			continue
		}
		seen[path] = true
		data, err := regularRead(path, 512<<20)
		if errors.Is(err, os.ErrNotExist) {
			backup.Paths[path] = nil
			continue
		}
		if err != nil {
			return nil, err
		}
		name := strconv.Itoa(len(backup.Paths))
		if err = atomicWrite(filepath.Join(dir, name), data, 0600); err != nil {
			return nil, err
		}
		backup.Paths[path] = &name
	}
	appid, err := appIDSnapshot(filepath.Join(m.live.Data, "appid"))
	if err != nil {
		return nil, err
	}
	backup.AppID = appid
	if err = writeJSON(filepath.Join(dir, "manifest.json"), backup); err != nil {
		return nil, err
	}
	ready = true
	return backup, nil
}
func (b *ruleBackup) Restore(m *RuleManager) error {
	allowed := func(path string) bool {
		for _, p := range m.live.controls {
			if path == p {
				return true
			}
		}
		if path == m.live.groupsFile() {
			return true
		}
		for _, root := range []string{filepath.Join(m.live.Data, "rules"), m.live.Sources} {
			relative, err := filepath.Rel(root, path)
			if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				return true
			}
		}
		return false
	}
	for path, saved := range b.Paths {
		if !allowed(path) {
			return errors.New("回滚清单包含越界路径")
		}
		if saved == nil {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		} else {
			if !safeName(*saved) {
				return errors.New("回滚清单文件无效")
			}
			if err := copyFile(filepath.Join(b.Directory, *saved), path); err != nil {
				return err
			}
		}
	}
	for _, root := range []string{filepath.Join(m.live.Data, "rules"), m.live.Sources} {
		current, err := privateTree(root)
		if err != nil {
			return err
		}
		for name := range current {
			path := filepath.Join(root, name)
			if _, ok := b.Paths[path]; !ok {
				if err = os.Remove(path); err != nil {
					return err
				}
			}
		}
	}
	return restoreAppID(filepath.Join(m.live.Data, "appid"), b.AppID)
}
func (b *ruleBackup) Close(state string) error {
	absolute, err := filepath.Abs(b.Directory)
	if err != nil {
		return err
	}
	parent, err := filepath.Abs(state)
	if err != nil || filepath.Dir(absolute) != parent || !strings.HasPrefix(filepath.Base(absolute), "transaction-") {
		return errors.New("回滚目录超出任务范围")
	}
	info, err := os.Lstat(absolute)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("回滚目录被替换")
	}
	return os.RemoveAll(absolute)
}

type RuleJobs struct {
	manager                    *RuleManager
	mu                         sync.Mutex
	running                    bool
	current, manual, scheduled string
	records                    []Object
	reload                     Object
	wg                         sync.WaitGroup
	logError                   string
}

func NewRuleJobs(m *RuleManager) (*RuleJobs, error) {
	j := &RuleJobs{manager: m, reload: Object{"state": "idle"}, records: []Object{}}
	root := filepath.Join(m.state, "operation-logs")
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	var value Object
	if err := readJSON(filepath.Join(root, "index.json"), &value); err == nil {
		if integer(value["schema"]) != 1 || len(array(value["records"])) > 20 {
			return nil, errors.New("规则操作日志索引无效")
		}
		for _, raw := range array(value["records"]) {
			r := object(raw)
			if !jobIDPattern.MatchString(text(r["id"])) {
				return nil, errors.New("规则操作日志标识无效")
			}
			if r["state"] == "running" {
				r["state"] = "interrupted"
			}
			j.records = append(j.records, r)
		}
		j.current, j.manual, j.scheduled = text(value["current"]), text(value["manual"]), text(value["scheduled"])
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("规则操作日志索引读取失败")
	}
	return j, nil
}
func (j *RuleJobs) Wait()               { j.wg.Wait() }
func (j *RuleJobs) Busy() bool          { j.mu.Lock(); defer j.mu.Unlock(); return j.running }
func (j *RuleJobs) ReloadState() Object { j.mu.Lock(); defer j.mu.Unlock(); return clone(j.reload) }
func (j *RuleJobs) Status() Object {
	pending := j.manager.drafts.pending.Load()
	j.mu.Lock()
	defer j.mu.Unlock()
	result := Object{"state": "idle", "kind": "", "lines": []string{}, "pending": pending}
	for _, r := range j.records {
		if text(r["id"]) == j.current {
			result = j.recordStatus(r)
		}
	}
	for key, id := range map[string]string{"recent_manual": j.manual, "recent_scheduled": j.scheduled} {
		for _, r := range j.records {
			if text(r["id"]) == id {
				result[key] = j.recordStatus(r)
			}
		}
	}
	result["pending"] = pending
	if j.logError != "" {
		result["log_error"] = j.logError
	}
	return result
}
func (j *RuleJobs) recordStatus(record Object) Object {
	result := clone(record)
	if path, err := j.logPath(text(record["id"])); err == nil {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			result["log_bytes"] = info.Size()
		}
	}
	return result
}
func (j *RuleJobs) persistLocked() error {
	return writeJSON(filepath.Join(j.manager.state, "operation-logs/index.json"), Object{"schema": 1, "records": j.records, "current": nilIfEmpty(j.current), "manual": nilIfEmpty(j.manual), "scheduled": nilIfEmpty(j.scheduled)})
}
func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func (j *RuleJobs) logPath(id string) (string, error) {
	if !jobIDPattern.MatchString(id) {
		return "", errors.New("操作日志标识无效")
	}
	return filepath.Join(j.manager.state, "operation-logs", id+".log"), nil
}
func (j *RuleJobs) append(id, message string) {
	path, err := j.logPath(id)
	if err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err == nil {
		_, err = f.WriteString(strings.TrimRight(message, "\n") + "\n")
		if err == nil {
			err = f.Sync()
		}
		f.Close()
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err != nil {
		j.logError = "操作日志写入失败"
	}
	for _, r := range j.records {
		if text(r["id"]) == id {
			lines := array(r["lines"])
			for _, line := range strings.Split(strings.TrimRight(message, "\n"), "\n") {
				lines = append(lines, line)
			}
			if len(lines) > 300 {
				lines = lines[len(lines)-300:]
			}
			r["lines"] = lines
			break
		}
	}
	if err = j.persistLocked(); err != nil {
		j.logError = "操作日志状态保存失败"
	}
}
func (j *RuleJobs) Log(id string, offset int64) (Object, error) {
	if id == "" {
		j.mu.Lock()
		id = j.current
		j.mu.Unlock()
	}
	path, err := j.logPath(id)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("操作日志不存在")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if offset < 0 || offset > info.Size() {
		return nil, errors.New("日志偏移无效")
	}
	if _, err = f.Seek(offset, 0); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return nil, err
	}
	// A live writer may have published only the beginning of its final rune.
	end := len(data)
	for end > 0 && !utf8.Valid(data[:end]) && len(data)-end < 4 {
		end--
	}
	if utf8.Valid(data[:end]) {
		data = data[:end]
	}
	return Object{"id": id, "offset": offset, "next_offset": offset + int64(len(data)), "bytes": info.Size(), "text": strings.ToValidUTF8(string(data), "�"), "eof": offset+int64(len(data)) >= info.Size()}, nil
}
func (j *RuleJobs) Start(kind, trigger, rule string) (Object, error) {
	j.mu.Lock()
	if j.running {
		j.mu.Unlock()
		return nil, errors.New("规则任务正在执行")
	}
	j.running = true
	j.mu.Unlock()
	lockCtx, cancel := context.WithTimeout(j.manager.ctx, 5*time.Second)
	guard, err := lockConfiguration(lockCtx, j.manager.live.Config)
	cancel()
	if err != nil {
		j.mu.Lock()
		j.running = false
		j.mu.Unlock()
		return nil, errors.New("检测配置正在维护，请稍后重试")
	}
	launched := false
	defer func() {
		if !launched {
			guard.Close()
		}
	}()
	id := token()[:32]
	backup, err := newRuleBackup(j.manager, id)
	if err != nil {
		j.mu.Lock()
		j.running = false
		j.mu.Unlock()
		return nil, err
	}
	// Publish a job only after its empty log is readable. Draft promotion can
	// take time before the worker writes the first line.
	logPath, _ := j.logPath(id)
	if err := atomicWrite(logPath, nil, 0600); err != nil {
		backup.Close(j.manager.state)
		j.mu.Lock()
		j.running = false
		j.mu.Unlock()
		return nil, errors.New("操作日志初始化失败")
	}
	record := Object{"state": "running", "kind": kind, "trigger": trigger, "started": now(), "finished": 0, "rc": nil, "lines": []string{}, "id": id, "log_ref": id}
	if rule != "" {
		record["manual_rule"] = rule
	}
	j.mu.Lock()
	previousRecords := append([]Object(nil), j.records...)
	previousCurrent, previousManual, previousScheduled, previousReload := j.current, j.manual, j.scheduled, j.reload
	retiredLogs := []string{}
	j.current = id
	if trigger == "scheduled" {
		j.scheduled = id
	} else {
		j.manual = id
	}
	j.records = append(j.records, record)
	for len(j.records) > 20 {
		old := j.records[0]
		if text(old["id"]) == j.manual || text(old["id"]) == j.scheduled {
			j.records = append(j.records[1:], old)
			continue
		}
		if path, e := j.logPath(text(old["id"])); e == nil {
			retiredLogs = append(retiredLogs, path)
		}
		j.records = j.records[1:]
	}
	j.reload = Object{"state": "running", "since": time.Now().Format("2006-01-02 15:04:05")}
	err = j.persistLocked()
	if err != nil {
		j.records = previousRecords
		j.current, j.manual, j.scheduled, j.reload = previousCurrent, previousManual, previousScheduled, previousReload
		j.running = false
		j.mu.Unlock()
		os.Remove(logPath)
		backup.Close(j.manager.state)
		return nil, err
	}
	j.mu.Unlock()
	for _, path := range retiredLogs {
		os.Remove(path)
	}
	j.wg.Add(1)
	go func() { defer j.wg.Done(); defer guard.Close(); j.worker(record, backup) }()
	launched = true
	return Object{"ok": true, "job_id": id}, nil
}
func (j *RuleJobs) worker(record Object, backup *ruleBackup) {
	m := j.manager
	id, kind, trigger := text(record["id"]), text(record["kind"]), text(record["trigger"])
	reloadAttempted, appIDChanged, detectorsChanged, committed := false, false, false, false
	var failure error
	var err error
	defer func() {
		if panicValue := recover(); panicValue != nil {
			failure = errors.New("规则任务异常")
		}
		if failure != nil {
			j.append(id, failure.Error())
			if !committed {
				recovery := backup.Restore(m)
				if recovery == nil && reloadAttempted && detectorsChanged {
					_, recovery = m.engineCall(m.ctx, "appid-reload-detectors", 300*time.Second)
				}
				if recovery == nil && reloadAttempted {
					_, recovery = m.engineCall(m.ctx, "ruleset-reload-rules", 300*time.Second)
				}
				if recovery != nil {
					j.append(id, "恢复尚未完成，回滚材料已保留；规则写入已暂停")
					m.pauseRecovery()
				} else {
					if err := backup.Close(m.state); err != nil {
						j.append(id, "恢复完成，回滚目录清理待重试")
					}
					j.append(id, "已恢复任务开始前的规则文件；待应用更改仍保留")
				}
			} else {
				j.append(id, "规则已提交，待应用状态同步失败；重启后台将恢复")
				m.pauseRecovery()
			}
		}
		j.mu.Lock()
		record["state"] = "done"
		record["finished"] = now()
		rc := 0
		if failure != nil {
			rc = 1
		}
		record["rc"] = rc
		j.reload = Object{"state": "idle", "last": time.Now().Format("2006-01-02 15:04:05"), "ok": failure == nil, "error": ""}
		if failure != nil {
			j.reload["error"] = failure.Error()
		}
		j.persistLocked()
		j.mu.Unlock()
		m.catalog.Invalidate()
		m.mu.Lock()
		if trigger == "scheduled" {
			m.schedule["last_run"] = Object{"state": "done", "started": record["started"], "finished": record["finished"], "rc": record["rc"], "id": id}
			writeJSON(filepath.Join(m.state, "schedule.json"), m.schedule)
		}
		m.mu.Unlock()
		j.mu.Lock()
		j.running = false
		j.mu.Unlock()
	}()
	beforeDetector := readText(m.live.controls["BAN_DETECTOR"])
	applyPending := kind == "apply" || kind == "update" && trigger == "manual"
	m.mu.Lock()
	if kind == "manual-add" {
		failure = appendPrivateLine(m.live.controls["HUNT_RULES"], text(record["manual_rule"]))
	}
	if failure == nil && applyPending && m.drafts.Dirty {
		failure = m.drafts.Promote()
	}
	m.mu.Unlock()
	if failure != nil {
		return
	}
	if kind == "update" || kind == "apply" {
		j.append(id, "开始处理规则来源")
		failure = UpdateRules(m.ctx, m.live, kind == "apply", "", false, m.pool, func(message string) { j.append(id, message) })
		if failure != nil {
			return
		}
	}
	if kind == "update" {
		if err := writeJSON(filepath.Join(backup.Directory, "openappid-pending.json"), backup.AppID); err != nil {
			failure = err
			return
		}
		appIDChanged, failure = updateAppID(m.ctx, filepath.Join(m.live.Data, "appid"), func(message string) { j.append(id, message) })
		if failure != nil {
			return
		}
	}
	detectorsChanged = appIDChanged || beforeDetector != readText(m.live.controls["BAN_DETECTOR"])
	j.append(id, "开始 Snort 配置校验")
	if failure = m.prepareThresholds(m.ctx); failure != nil {
		return
	}
	plugin, err := pluginArguments()
	if err != nil {
		failure = err
		return
	}
	arguments := append([]string{filepath.Join(enginePrefix(), "bin/snort")}, plugin...)
	arguments = append(arguments, "-T", "-c", m.live.Config)
	if failure = j.runCommand(m.ctx, id, arguments, 300*time.Second, nil); failure != nil {
		return
	}
	reloadAttempted = true
	if detectorsChanged {
		if err = atomicWrite(filepath.Join(backup.Directory, "reload-detectors"), []byte("pending\n"), 0600); err != nil {
			failure = err
			return
		}
		if _, failure = m.engineCall(m.ctx, "appid-reload-detectors", 300*time.Second); failure != nil {
			return
		}
	}
	j.append(id, "开始 Snort 热重载")
	if _, failure = m.engineCall(m.ctx, "ruleset-reload-rules", 300*time.Second); failure != nil {
		return
	}
	commit := Object{"clear_pending": applyPending}
	if kind == "manual-add" {
		commit["applied_manual"] = record["manual_rule"]
	}
	if err = writeJSON(filepath.Join(backup.Directory, "committed.json"), commit); err != nil {
		failure = err
		return
	}
	committed = true
	m.mu.Lock()
	if kind == "manual-add" {
		failure = appendPrivateLine(m.drafts.paths.controls["HUNT_RULES"], text(record["manual_rule"]))
	} else if applyPending || !m.drafts.Dirty {
		failure = m.drafts.Reset()
	}
	m.mu.Unlock()
	if failure != nil {
		return
	}
	if err := m.recordPolicyFingerprint(); err != nil {
		j.append(id, "规则已生效，但自动同步状态记录失败")
	}
	if err := m.refreshRuleFileStats(m.ctx); err != nil {
		j.append(id, "规则已生效，但启用签名数更新失败")
	}
	backup.Close(m.state)
	if appIDChanged {
		j.append(id, "OpenAppID 检测器已热重载")
	}
	j.append(id, "规则已校验并完成热重载")
}
func (m *RuleManager) pauseRecovery() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.paused = true
	atomicWrite(filepath.Join(m.state, "maintenance"), []byte("recovery-required\n"), 0600)
}
func (j *RuleJobs) runCommand(ctx context.Context, id string, arguments []string, timeout time.Duration, environment []string) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(ctx, arguments[0], arguments[1:]...)
	if environment != nil {
		command.Env = environment
	}
	writer := &boundedLogWriter{max: rpcResponseLimit, write: func(data []byte) { j.append(id, string(data)) }}
	command.Stdout = writer
	command.Stderr = writer
	configureCommand(command)
	err := command.Run()
	if writer.exceeded {
		return errors.New("规则任务输出超过上限")
	}
	if ctx.Err() != nil {
		return errors.New("规则命令超时或取消")
	}
	if err != nil {
		return errors.New("规则命令执行失败，活动规则已保留")
	}
	return nil
}

type boundedLogWriter struct {
	mu         sync.Mutex
	count, max int
	exceeded   bool
	write      func([]byte)
}

func (w *boundedLogWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.count+len(data) > w.max {
		w.exceeded = true
		return 0, errors.New("命令输出超过限制")
	}
	w.count += len(data)
	w.write(data)
	return len(data), nil
}
func (j *RuleJobs) Recover() error {
	paths, err := filepath.Glob(filepath.Join(j.manager.state, "transaction-*"))
	if err != nil {
		return err
	}
	sort.Strings(paths)
	for _, path := range paths {
		var backup ruleBackup
		if err = readJSON(filepath.Join(path, "manifest.json"), &backup); err != nil {
			return errors.New("规则回滚清单损坏，材料已保留")
		}
		backup.Directory = path
		if !backup.GoBackend {
			return errors.New("存在未完成的旧版规则事务，需由原管理器恢复后升级")
		}
		var committed Object
		if readJSON(filepath.Join(path, "committed.json"), &committed) == nil {
			if committed["clear_pending"] == true {
				if err = j.manager.drafts.Reset(); err != nil {
					return err
				}
			}
			if line := text(committed["applied_manual"]); line != "" && !strings.Contains(readText(j.manager.drafts.paths.controls["HUNT_RULES"]), line) {
				if err = appendPrivateLine(j.manager.drafts.paths.controls["HUNT_RULES"], line); err != nil {
					return err
				}
			}
		} else {
			if err = backup.Restore(j.manager); err != nil {
				return err
			}
			if fileExists(filepath.Join(path, "reload-detectors")) {
				if _, err = j.manager.engineCall(j.manager.ctx, "appid-reload-detectors", 300*time.Second); err != nil {
					return err
				}
			}
			if _, err = j.manager.engineCall(j.manager.ctx, "ruleset-reload-rules", 300*time.Second); err != nil {
				return err
			}
		}
		if err = backup.Close(j.manager.state); err != nil {
			return err
		}
	}
	if strings.TrimSpace(readText(filepath.Join(j.manager.state, "maintenance"))) == "recovery-required" {
		if err = os.Remove(filepath.Join(j.manager.state, "maintenance")); err != nil {
			return err
		}
		j.manager.paused = false
	}
	return nil
}
func pluginArguments() ([]string, error) {
	var receipt Object
	if err := readJSON("/etc/ips-session-logger.json", &receipt); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, errors.New("会话扩展校验记录无效")
	}
	hash := text(receipt["sha256"])
	if len(hash) != 64 {
		return nil, errors.New("会话扩展摘要无效")
	}
	path := filepath.Join(enginePrefix(), "lib/ndr", hash, "ndr_session.so")
	data, err := regularRead(path, 64<<20)
	if err != nil {
		return nil, err
	}
	actual := sha256.Sum256(data)
	if hex.EncodeToString(actual[:]) != hash {
		return nil, errors.New("会话扩展校验失败")
	}
	return []string{"--plugin-path", path}, nil
}
func (m *RuleManager) prepareThresholds(ctx context.Context) error {
	catalog := newRuleCatalog(m.pool, m.live, m.live)
	if m.catalog != nil {
		catalog.ActiveRules = m.catalog.ActiveRules
	}
	rows, _, err := catalog.Load(ctx)
	if err != nil {
		return err
	}
	ids := map[RuleID]bool{}
	for _, r := range rows {
		if r.Enabled {
			ids[r.ID] = true
		}
	}
	var groupPolicies []string
	if err = readJSON(m.live.groupsFile(), &groupPolicies); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	groupIDs := map[RuleID]bool{}
	for _, selector := range groupPolicies {
		for _, r := range rows {
			if selectorMatches(selector, r) {
				groupIDs[r.ID] = true
			}
		}
	}
	lines, lua := []string{}, []string{}
	for _, raw := range readLines(m.live.controls["THRESHOLD_CONF"]) {
		line := suppressionText(raw)
		match := suppressionExpression.FindStringSubmatch(line)
		if len(match) != 3 {
			lines = append(lines, raw)
			continue
		}
		gid, _ := strconv.ParseInt(match[1], 10, 64)
		sid, _ := strconv.ParseInt(match[2], 10, 64)
		id := RuleID{gid, sid}
		if !ids[id] && gid != 0 && sid != 0 {
			lines = append(lines, "# ips-web-pending-suppress "+base64.URLEncoding.EncodeToString([]byte(line)))
			continue
		}
		lines = append(lines, line)
		if groupIDs[id] {
			continue
		}
		fields := []string{fmt.Sprintf("gid = %d", gid), fmt.Sprintf("sid = %d", sid)}
		if track := regexp.MustCompile(`\btrack\s+(by_src|by_dst)`).FindStringSubmatch(line); len(track) == 2 {
			fields = append(fields, "track = "+strconv.Quote(track[1]))
		}
		if ip := regexp.MustCompile(`\bip\s+([^,\s]+)`).FindStringSubmatch(line); len(ip) == 2 {
			if _, err := parseAddressOrPrefix(ip[1]); err != nil {
				return err
			}
			fields = append(fields, "ip = "+strconv.Quote(ip[1]))
		}
		lua = append(lua, "    { "+strings.Join(fields, ", ")+" }")
	}
	ordered := []RuleID{}
	for id := range groupIDs {
		if ids[id] {
			ordered = append(ordered, id)
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].GID == ordered[j].GID {
			return ordered[i].SID < ordered[j].SID
		}
		return ordered[i].GID < ordered[j].GID
	})
	for _, id := range ordered {
		lua = append(lua, fmt.Sprintf("    { gid = %d, sid = %d }", id.GID, id.SID))
	}
	states := []string{}
	disabled := configured(m.live.controls["DISABLE_CONF"])
	for _, r := range rows {
		if !r.Builtin {
			continue
		}
		for _, selector := range disabled {
			if selectorMatches(selector, r) {
				states = append(states, fmt.Sprintf("alert (gid:%d; sid:%d; enable:no;)", r.ID.GID, r.ID.SID))
				break
			}
		}
	}
	if err = atomicWrite(m.live.controls["THRESHOLD_CONF"], []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		return err
	}
	return atomicWrite(m.live.controls["SUPPRESS_LUA"], []byte("suppress = {\n"+strings.Join(lua, ",\n")+"\n}\nips.states = [[\n"+strings.Join(states, "\n")+"\n]]\n"), 0600)
}

var _ = json.Valid
