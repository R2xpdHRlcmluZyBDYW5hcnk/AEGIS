package console

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func PrepareRuleCLI(ctx context.Context, test bool, candidate string) error {
	if os.Geteuid() != 0 {
		return errors.New("签名维护需要 root 权限")
	}
	pool := NewPool(WorkerCount())
	defer pool.Close()
	p := liveRulePaths("")
	guard, err := lockConfiguration(ctx, p.Config)
	if err != nil {
		return err
	}
	defer guard.Close()
	m := &RuleManager{ctx: ctx, live: p, pool: pool}
	m.catalog = newRuleCatalog(pool, p, p)
	if test && candidate != "" {
		m.catalog.ActiveRules = candidate
	}
	if err = m.prepareThresholds(ctx); err != nil {
		return err
	}
	fmt.Println("[suppress] 配置已准备")
	if test {
		plugin, err := pluginArguments()
		if err != nil {
			return err
		}
		arguments := append([]string{filepath.Join(enginePrefix(), "bin/snort")}, plugin...)
		arguments = append(arguments, "-T", "-c", p.Config)
		output, err := commandOutput(ctx, 300*time.Second, arguments...)
		fmt.Print(output)
		return err
	}
	return nil
}

func RunRuleCLI(ctx context.Context, args []string) error {
	command, source := "update", ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command, args = args[0], args[1:]
		if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
			source, args = args[0], args[1:]
		}
	}
	flags := flag.NewFlagSet("rules", flag.ContinueOnError)
	data := flags.String("data-dir", "/var/lib/snort", "签名目录")
	config := flags.String("config", "/etc/snort/rule-update.conf", "更新配置")
	offline := flags.Bool("offline", false, "使用已校验缓存")
	sources := flags.String("sources-dir", "", "签名来源目录")
	downloadOnly := flags.Bool("download-only", false, "仅下载签名来源")
	flags.Bool("no-reload", false, "兼容参数，由签名管理器执行校验与重载")
	if err := flags.Parse(args); err != nil {
		return err
	}
	p := liveRulePaths("")
	p.Data, p.Sources, p.Cache = *data, filepath.Join(*data, "update/sources"), filepath.Join(*data, "update/cache")
	p.Config = filepath.Join(filepath.Dir(*config), "snort.lua")
	for key, path := range p.controls {
		if filepath.Dir(path) == "/etc/snort" {
			p.controls[key] = filepath.Join(filepath.Dir(*config), filepath.Base(path))
		}
	}
	for _, key := range []string{"LOCAL_RULES", "HUNT_RULES", "BAN_RULES", "BAN_STORE", "BAN_DETECTOR"} {
		p.controls[key] = filepath.Join(*data, "rules", filepath.Base(p.controls[key]))
	}
	switch command {
	case "list-sources":
		names := []string{}
		for name := range officialSources {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			s := officialSources[name]
			fmt.Printf("Name: %s\nVendor: %s\nSummary: %s\nLicense: %s\n", name, s[0], s[1], s[2])
		}
		return nil
	case "list-enabled-sources":
		custom, err := sourceDefinitions(p.Sources)
		if err != nil {
			return err
		}
		names := []string{}
		for name := range officialSources {
			if sourceEnabled(p.Sources, name, custom) {
				names = append(names, name)
			}
		}
		for name, s := range custom {
			if s["enabled"] == true {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Println("- " + name)
		}
		return nil
	case "enable-source", "disable-source":
		return setSourceEnabled(p.Sources, source, command == "enable-source", readSettings(*config))
	case "update":
		if os.Geteuid() != 0 {
			return errors.New("签名更新需要 root 权限")
		}
		guard, err := lockConfiguration(ctx, p.Config)
		if err != nil {
			return err
		}
		defer guard.Close()
		pool := NewPool(WorkerCount())
		defer pool.Close()
		return UpdateRules(ctx, p, *offline, *sources, *downloadOnly, pool, func(s string) { fmt.Println(s) })
	default:
		return errors.New("不支持的签名更新命令")
	}
}
