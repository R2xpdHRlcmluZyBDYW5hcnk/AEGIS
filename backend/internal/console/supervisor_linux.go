//go:build linux

package console

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const detectorRun = "/run/snort"

func SupervisorNftRules(workers int) string {
	queues := "0"
	if workers > 1 {
		queues += "-" + strconv.Itoa(workers-1)
	}
	return fmt.Sprintf("add table inet ips\ndelete table inet ips\ntable inet ips {\n    chain prerouting {\n        type filter hook prerouting priority -90; policy accept;\n        iifname \"lo\" return\n        fib daddr type { local, broadcast, multicast } return\n        ip daddr { 224.0.0.0/4, 255.255.255.255 } return\n        counter queue flags bypass to %s\n    }\n}\n", queues)
}

func detectorQueueCount() int {
	var instance Object
	if readJSON(filepath.Join(detectorRun, "instance.json"), &instance) == nil {
		if n := int(integer(instance["workers"])); n > 0 && n <= 65536 {
			return n
		}
	}
	pid := strings.TrimSpace(readText(filepath.Join(detectorRun, "snort.pid")))
	args := strings.Split(readText("/proc/"+pid+"/cmdline"), "\x00")
	for i, arg := range args {
		if arg == "-z" && i+1 < len(args) {
			if n, err := strconv.Atoi(args[i+1]); err == nil && n > 0 && n <= 65536 {
				return n
			}
		}
	}
	return 4 // Legacy instance receipts predate the recorded queue count.
}

func boundQueues(path string, count int) (map[int]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	bound := map[int]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, errors.New("NFQUEUE 状态无效")
		}
		id, e1 := strconv.Atoi(fields[0])
		peer, e2 := strconv.ParseUint(fields[1], 10, 64)
		if e1 != nil || e2 != nil || id < 0 || id > 65535 {
			return nil, errors.New("NFQUEUE 状态无效")
		}
		if id < count && peer > 0 {
			bound[id] = true
		}
	}
	return bound, nil
}

type queueHealth struct {
	started time.Time
	ready   bool
	missing map[int]time.Time
	count   int
}

func (h *queueHealth) overdue(bound map[int]bool, at time.Time) []int {
	if bound == nil {
		h.missing = nil
		return nil
	}
	if len(bound) == h.count {
		h.ready = true
	}
	if !h.ready && at.Sub(h.started) < 120*time.Second {
		return nil
	}
	if h.missing == nil {
		h.missing = map[int]time.Time{}
	}
	out := []int{}
	for id := 0; id < h.count; id++ {
		if bound[id] {
			delete(h.missing, id)
			continue
		}
		since, ok := h.missing[id]
		if !ok {
			since = at
			h.missing[id] = since
		}
		if at.Sub(since) >= 15*time.Second {
			out = append(out, id)
		}
	}
	return out
}

type detectorChild struct {
	command *exec.Cmd
	exit    chan error
	alive   bool
	result  error
}

func (c *detectorChild) Alive() bool {
	if c.alive {
		select {
		case c.result = <-c.exit:
			c.alive = false
		default:
		}
	}
	return c.alive
}
func (c *detectorChild) Start(argv []string, run string, count int) error {
	if c.Alive() {
		return errors.New("检测进程已经运行")
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	c.command, c.exit, c.alive, c.result = cmd, make(chan error, 1), true, nil
	exit := c.exit
	go func() { exit <- cmd.Wait() }()
	if err := atomicWrite(filepath.Join(run, "snort.pid"), []byte(strconv.Itoa(cmd.Process.Pid)+"\n"), 0644); err != nil {
		c.Stop(time.Second)
		return err
	}
	if err := writeJSON(filepath.Join(run, "instance.json"), Object{"epoch": token()[:32], "started": now(), "workers": count, "queues": count}); err != nil {
		c.Stop(time.Second)
		return err
	}
	return nil
}
func (c *detectorChild) Stop(timeout time.Duration) error {
	if !c.Alive() {
		return nil
	}
	c.command.Process.Signal(syscall.SIGTERM)
	select {
	case c.result = <-c.exit:
		c.alive = false
		return nil
	case <-time.After(timeout):
	}
	c.command.Process.Kill()
	select {
	case c.result = <-c.exit:
		c.alive = false
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("检测进程未完全退出")
	}
}

func detectorArguments(count int, logs string) ([]string, error) {
	if count < 1 || count > 65536 {
		return nil, errors.New("检测线程数超出 NFQUEUE 范围")
	}
	plugin, err := pluginArguments()
	if err != nil {
		return nil, err
	}
	prefix := enginePrefix()
	args := append([]string{filepath.Join(prefix, "bin/snort")}, plugin...)
	args = append(args, "--daq-dir", filepath.Join(prefix, "lib/daq"), "--daq", "nfq", "-Q", "-s", "65535", "-z", strconv.Itoa(count))
	for id := 0; id < count; id++ {
		args = append(args, "-i", strconv.Itoa(id))
	}
	return append(args, "-c", "/etc/snort/snort.lua", "-l", logs, "--control-socket", engineSocket, "--script-path", filepath.Join(prefix, "etc/snort")), nil
}

func nftSupervisor(ctx context.Context, input string, args ...string) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	command := input
	jsonOutput := len(args) > 0 && args[0] == "-j"
	if command == "" {
		parts := args
		if jsonOutput {
			parts = parts[1:]
		}
		command = strings.Join(parts, " ")
	}
	if output, err, handled := nftLibraryCommand(command, jsonOutput); handled {
		return output, err
	}
	run, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(run, "/usr/sbin/nft", args...)
	cmd.Stdin = strings.NewReader(input)
	configureCommand(cmd)
	var output strings.Builder
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	return output.String(), err
}
func supervisorHasQueue(ctx context.Context, count int) bool {
	out, err := nftSupervisor(ctx, "", "-j", "list", "table", "inet", "ips")
	if err != nil {
		return false
	}
	var table Object
	if decode([]byte(out), &table) != nil {
		return false
	}
	for _, entry := range array(table["nftables"]) {
		for _, expr := range array(object(object(entry)["rule"])["expr"]) {
			q := object(object(expr)["queue"])
			if q == nil {
				continue
			}
			value := q["num"]
			if r := array(object(value)["range"]); len(r) == 2 {
				return integer(r[0]) == 0 && integer(r[1]) == int64(count-1)
			}
			if count == 1 && value != nil {
				return integer(value) == 0
			}
		}
	}
	return false
}

func validateLogStorage() error {
	var config Object
	if info, err := os.Lstat("/etc/ips-log-storage.json"); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("日志存储标记不能是符号链接")
	}
	err := readJSON("/etc/ips-log-storage.json", &config)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if errors.Is(err, os.ErrPermission) && os.Getenv("IPS_LOG_STORAGE_ROOT") == managedLogRoot {
		config = Object{"root": managedLogRoot, "direct_paths": true}
		err = nil
	}
	if err != nil {
		return err
	}
	if text(config["root"]) != managedLogRoot {
		return errors.New("持久日志目录与已安装布局不一致")
	}
	for _, pair := range [][2]string{{"/var/log/snort", managedLogRoot + "/snort"}, {"/var/log/ips", managedLogRoot + "/events"}} {
		target, e := os.Lstat(pair[1])
		if e != nil || !target.IsDir() || target.Mode()&os.ModeSymlink != 0 {
			return errors.New("持久日志目录不可用")
		}
		if config["direct_paths"] != true {
			alias, e := os.Lstat(pair[0])
			if e != nil || !alias.IsDir() || !os.SameFile(alias, target) {
				return errors.New("持久日志挂载被遮盖或未生效")
			}
		}
	}
	return nil
}

var detectorLogName = regexp.MustCompile(`^(?:[0-9]+_)?(?:file_connector_ndr_transmit|alert_json\.txt|ndr_session\.json)$`)

func archiveDetectorLogs(ctx context.Context, logs, run, checkpoint string) error {
	entries, err := os.ReadDir(logs)
	if err != nil {
		return err
	}
	files := map[string]os.FileInfo{}
	for _, entry := range entries {
		if !detectorLogName.MatchString(entry.Name()) {
			continue
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() {
			return errors.New("原始日志成员类型无效")
		}
		if info.Size() > 0 {
			files[entry.Name()] = info
		}
	}
	if len(files) == 0 {
		return nil
	}
	var instance Object
	if readJSON(filepath.Join(run, "instance.json"), &instance) == nil && text(instance["epoch"]) != "" {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			var state Object
			ready := readJSON(checkpoint, &state) == nil && state["epoch"] == instance["epoch"]
			for name, info := range files {
				_, ino := fileIdentity(info)
				cursor := object(object(state["files"])[name])
				ready = ready && integer(cursor["inode"]) == int64(ino) && integer(cursor["offset"]) >= info.Size()
			}
			if ready {
				break
			}
			if !supervisorWait(ctx, 250*time.Millisecond) {
				return ctx.Err()
			}
		}
	}
	archive := filepath.Join(logs, ".response-"+time.Now().UTC().Format("20060102T150405")+"-"+strconv.FormatInt(time.Now().UnixNano(), 10))
	if err = os.Mkdir(archive, 0700); err != nil {
		return err
	}
	for name, info := range files {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		path, destination := filepath.Join(logs, name), filepath.Join(archive, name)
		current, e := os.Lstat(path)
		if e != nil || !os.SameFile(current, info) || !current.Mode().IsRegular() {
			return errors.New("原始日志在归档前发生变化")
		}
		f, e := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
		if e != nil {
			return e
		}
		f.Close()
		if e = copyOwnership(info, destination); e != nil {
			return e
		}
		if e = exchangeFiles(path, destination); e != nil {
			os.Remove(destination)
			return e
		}
	}
	return syncDirectory(logs)
}
func supervisorWait(ctx context.Context, duration time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(duration):
		return true
	}
}

func RunSupervisor(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("ips-supervisor", flag.ContinueOnError)
	status := flags.Bool("status", false, "只读检测状态")
	ensure := flags.Bool("ensure-nft", false, "补建检测队列表")
	rules := flags.Bool("nft-rules", false, "输出检测队列规则")
	queues := flags.Int("queues", 0, "只读规则输出的队列数")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *queues < 0 || *queues > 65536 {
		return errors.New("守护参数无效")
	}
	count := detectorQueueCount()
	if *queues > 0 {
		count = *queues
	}
	if *rules {
		_, err := io.WriteString(os.Stdout, SupervisorNftRules(count))
		return err
	}
	if *status {
		bound, err := boundQueues("/proc/net/netfilter/nfnetlink_queue", count)
		ok := err == nil && len(bound) == count && supervisorHasQueue(ctx, count)
		json.NewEncoder(os.Stdout).Encode(Object{"ok": ok, "backend": "go", "workers": count, "listeners": len(bound)})
		if !ok {
			return errors.New("检测队列未全部就绪")
		}
		return nil
	}
	if os.Geteuid() != 0 {
		return errors.New("检测守护需要 root 权限")
	}
	if *ensure {
		if supervisorHasQueue(ctx, count) {
			return nil
		}
		out, err := nftSupervisor(ctx, SupervisorNftRules(count), "-f", "-")
		if err != nil {
			return fmt.Errorf("队列表恢复失败: %s", out)
		}
		return nil
	}
	if *queues != 0 {
		return errors.New("运行队列数由检测服务 CPU 分配决定")
	}
	if err := os.MkdirAll(detectorRun, 0755); err != nil {
		return err
	}
	lease, err := os.OpenFile(filepath.Join(detectorRun, ".supervisor.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer lease.Close()
	if err = syscall.Flock(int(lease.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("检测守护已经运行")
	}
	if err = validateLogStorage(); err != nil {
		return err
	}
	logs, _, err := LogPaths()
	if err != nil {
		return err
	}
	child := &detectorChild{}
	defer func() {
		child.Stop(20 * time.Second)
		cleanup, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		nftSupervisor(cleanup, "delete table inet ips\n", "-f", "-")
	}()
	maintenance := "/var/lib/ips-rule-manager/maintenance"
	if os.Getenv("IPS_PROGRAM_DIRECTORY") == "/opt/ips-console/bin" {
		maintenance = "/var/lib/ips-snort-rule-manager/maintenance"
	}
	start := func() error {
		pid, _ := strconv.Atoi(strings.TrimSpace(readText(filepath.Join(detectorRun, "snort.pid"))))
		if pid > 0 && syscall.Kill(pid, 0) == nil {
			return errors.New("已有检测进程持有 PID 文件")
		}
		count = ServiceWorkers()
		if count > 65536 {
			return errors.New("检测线程数超出队列编号范围")
		}
		deadline := time.Now().Add(20 * time.Second)
		for {
			bound, e := boundQueues("/proc/net/netfilter/nfnetlink_queue", count)
			if e != nil {
				return e
			}
			if len(bound) == 0 {
				break
			}
			if time.Now().After(deadline) {
				return errors.New("检测队列仍被占用")
			}
			if !supervisorWait(ctx, 500*time.Millisecond) {
				return ctx.Err()
			}
		}
		if err := archiveDetectorLogs(ctx, logs, detectorRun, "/var/lib/ips-event-bridge/offsets.json"); err != nil {
			return err
		}
		argv, err := detectorArguments(count, logs)
		if err != nil {
			return err
		}
		out, err := nftSupervisor(ctx, SupervisorNftRules(count), "-f", "-")
		if err != nil {
			return fmt.Errorf("应用队列规则失败: %s", out)
		}
		os.Remove(engineSocket)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		fmt.Printf("[ips] 启动 Snort 检测线程=%d 队列=%d\n", count, count)
		return child.Start(argv, detectorRun, count)
	}
	started := time.Now()
	health := queueHealth{started: started, count: count}
	armed := true
	next := time.Time{}
	for ctx.Err() == nil {
		if !child.Alive() {
			if err = start(); err != nil {
				fmt.Printf("[ips] 检测启动暂缓: %v\n", err)
				if !supervisorWait(ctx, 3*time.Second) {
					break
				}
				continue
			}
			health = queueHealth{started: time.Now(), count: count}
		}
		if !supervisorHasQueue(ctx, count) {
			if out, e := nftSupervisor(ctx, SupervisorNftRules(count), "-f", "-"); e != nil {
				fmt.Printf("[ips] 队列表恢复失败: %s\n", out)
			}
		}
		bound, _ := boundQueues("/proc/net/netfilter/nfnetlink_queue", count)
		ready := fileExists(engineSocket)
		if len(bound) == count && ready {
			armed = true
		}
		at := time.Now()
		overdue := health.overdue(bound, at)
		missingSocket := !ready && at.Sub(health.started) >= 120*time.Second
		if armed && !at.Before(next) && (len(overdue) > 0 || missingSocket) {
			next = at.Add(5 * time.Second)
			guard, e := tryConfiguration("/etc/snort/snort.lua")
			if e == nil {
				bound, e = boundQueues("/proc/net/netfilter/nfnetlink_queue", count)
				missing := false
				for _, id := range overdue {
					missing = missing || e == nil && !bound[id]
				}
				if !fileExists(maintenance) && ctx.Err() == nil && (missing || missingSocket && !fileExists(engineSocket)) {
					fmt.Println("[ips] 检测监听持续异常，恢复 Snort")
					if child.Stop(20*time.Second) == nil {
						if e = start(); e != nil {
							fmt.Printf("[ips] 检测恢复暂缓: %v\n", e)
						}
					}
					health = queueHealth{started: time.Now(), count: count}
					next = time.Now().Add(180 * time.Second)
					armed = false
				}
				guard.Close()
			}
		}
		if !supervisorWait(ctx, time.Second) {
			break
		}
	}
	return nil
}

func tryConfiguration(config string) (*configurationGuard, error) {
	f, err := os.OpenFile(filepath.Join(filepath.Dir(config), ".configuration.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, err
	}
	return &configurationGuard{f}, nil
}
