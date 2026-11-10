package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"aegis.local/backend/internal/console"
)

func run(ctx context.Context, args []string) error {
	if len(args) == 1 && args[0] == "--version" {
		return json.NewEncoder(os.Stdout).Encode(console.BuildInfo())
	}
	name := filepath.Base(os.Args[0])
	mode := map[string]string{"ips-web": "web", "ips-rule-manager": "manager", "ips-event-bridge": "bridge", "ips-snort-rules": "rules", "ips-supervisor": "supervisor", "snort-home-net": "home-net", "ips-quic-observer": "quic-observer", "recover-event-db": "recover-event-db"}[name]
	if len(args) > 0 && strings.Contains("|web|manager|bridge|rules|history-reset|postgresql-reset|supervisor|home-net|quic-observer|recover-event-db|resources|", "|"+args[0]+"|") {
		mode, args = args[0], args[1:]
	}
	if mode == "" {
		if len(args) == 0 {
			return errors.New("用法: aegis web|manager|bridge|rules|history-reset")
		}
		mode, args = args[0], args[1:]
	}
	flags := flag.NewFlagSet(mode, flag.ContinueOnError)
	switch mode {
	case "postgresql-reset":
		return console.RunPostgresMaintenance(ctx, args)
	case "resources":
		return console.RunResourceBudget(ctx, args)
	case "recover-event-db":
		return console.RunRecovery(ctx, args)
	case "quic-observer":
		return console.RunQuicObserver(ctx, args)
	case "home-net":
		if len(args) > 0 {
			return errors.New("HOME_NET 不接受命令参数")
		}
		return console.RunHomeNet(ctx)
	case "supervisor":
		return console.RunSupervisor(ctx, args)
	case "web":
		config := flags.String("config", "/etc/ips-web.conf", "控制台配置")
		gen := flags.Bool("gen-password", false, "生成登录密码和哈希")
		bind := flags.String("bind", "", "监听地址覆盖")
		port := flags.Int("port", 0, "监听端口覆盖")
		prepare := flags.Bool("prepare-thresholds", false, "准备抑制配置")
		testRules := flags.Bool("test-rules", false, "准备抑制配置并验证签名")
		if err := flags.Parse(args); err != nil {
			return err
		}
		if *gen {
			password, hash, err := console.GeneratePassword()
			if err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(map[string]string{"password": password, "password_pbkdf2": hash})
		}
		if *prepare || *testRules {
			return console.PrepareRuleCLI(ctx, *testRules, os.Getenv("OUTPUT_FILENAME"))
		}
		if directory := os.Getenv("CREDENTIALS_DIRECTORY"); directory != "" {
			*config = filepath.Join(directory, "ips-web.conf")
		}
		cfg, err := console.LoadConfig(*config)
		if err != nil {
			return err
		}
		if *bind != "" {
			cfg.Bind = *bind
		}
		if *port != 0 {
			if *port < 1 || *port > 65535 {
				return errors.New("监听端口无效")
			}
			cfg.Port = *port
		}
		return console.ServeHTTP(ctx, cfg)
	case "manager":
		state := flags.String("state-dir", os.Getenv("STATE_DIRECTORY"), "签名管理状态目录")
		socket := flags.String("socket", "/run/ips-rule-manager/control.sock", "控制接口")
		if err := flags.Parse(args); err != nil {
			return err
		}
		if *state == "" {
			*state = "/var/lib/ips-rule-manager"
		}
		if os.Geteuid() != 0 {
			return errors.New("签名管理器需要 root 权限")
		}
		return console.ServeManager(ctx, *state, *socket, "")
	case "bridge":
		logsDefault, outputDefault, err := console.LogPaths()
		if err != nil {
			return err
		}
		logs := flags.String("logs", logsDefault, "原始日志目录")
		output := flags.String("output", outputDefault, "事件流")
		checkpoint := flags.String("checkpoint", "/var/lib/ips-event-bridge/offsets.json", "持久读取位置")
		instance := flags.String("instance", "/run/snort/instance.json", "引擎实例")
		drain := flags.Bool("drain", false, "排空已停止的事件源")
		if err := flags.Parse(args); err != nil {
			return err
		}
		pool := console.NewPool(console.WorkerCount())
		defer pool.Close()
		bridge, err := console.NewBridge(*logs, *output, *checkpoint, *instance, pool)
		if err != nil {
			return err
		}
		return bridge.Run(ctx, *drain)
	case "rules":
		return console.RunRuleCLI(ctx, args)
	case "history-reset":
		run := flags.Bool("run", false, "执行已排队的历史任务")
		job := flags.String("job", "", "历史任务标识")
		state := flags.String("state-dir", "/var/lib/ips-snort-rule-manager", "状态目录")
		if err := flags.Parse(args); err != nil {
			return err
		}
		if !*run {
			return errors.New("仅支持执行已排队的历史任务")
		}
		return console.RunHistoryReset(ctx, *state, *job)
	}
	return fmt.Errorf("未知服务 %q", mode)
}
func main() {
	console.ConfigureResources()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, strings.TrimSpace(err.Error()))
		os.Exit(1)
	}
}
