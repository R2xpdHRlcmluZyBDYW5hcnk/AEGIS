package console

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var homeNetAssignment = regexp.MustCompile(`HOME_NET\s*=\s*["']([^"']*)["']`)

type homeNetRuntime struct {
	home, state, config, validation string
	addresses                       func(context.Context, string) ([]byte, error)
	validate                        func(context.Context, string) error
	reload                          func(context.Context) error
}

func homeNetCandidate(source string, previous []string, addresses []byte) (string, []string, error) {
	span := homeNetAssignment.FindStringSubmatchIndex(source)
	if len(span) != 4 {
		return "", nil, errors.New("HOME_NET 配置项缺失")
	}
	var rows []Object
	if decode(addresses, &rows) != nil {
		return "", nil, errors.New("接口地址响应无效")
	}
	set := map[string]bool{}
	for _, row := range rows {
		for _, item := range array(row["addr_info"]) {
			entry := object(item)
			if entry["scope"] != "global" {
				continue
			}
			ip, err := netip.ParseAddr(text(entry["local"]))
			bits := int(integer(entry["prefixlen"]))
			if err != nil || !ip.Is6() || bits < 0 || bits > 128 {
				return "", nil, errors.New("接口 IPv6 前缀无效")
			}
			set[netip.PrefixFrom(ip, bits).Masked().String()] = true
		}
	}
	prefixes := []string{}
	for prefix := range set {
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(prefixes)
	old := map[string]bool{}
	for _, prefix := range previous {
		old[prefix] = true
	}
	networks := []string{}
	seen := map[string]bool{}
	for _, value := range strings.Split(strings.Trim(source[span[2]:span[3]], "[]"), ",") {
		value = strings.TrimSpace(value)
		if value != "" && !old[value] && !seen[value] {
			networks = append(networks, value)
			seen[value] = true
		}
	}
	for _, prefix := range prefixes {
		if !seen[prefix] {
			networks = append(networks, prefix)
			seen[prefix] = true
		}
	}
	return source[:span[2]] + "[" + strings.Join(networks, ",") + "]" + source[span[3]:], prefixes, nil
}

func (r homeNetRuntime) refresh(ctx context.Context, iface string) (bool, error) {
	if !regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`).MatchString(iface) {
		return false, errors.New("请配置有效的 IPS_HOME_NET_INTERFACE")
	}
	guard, err := lockConfiguration(ctx, r.config)
	if err != nil {
		return false, err
	}
	defer guard.Close()
	source, err := regularRead(r.home, 1<<20)
	if err != nil {
		return false, err
	}
	info, err := os.Stat(r.home)
	if err != nil {
		return false, err
	}
	var previous []string
	if err = readJSON(r.state, &previous); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	addresses, err := r.addresses(ctx, iface)
	if err != nil {
		return false, err
	}
	candidate, prefixes, err := homeNetCandidate(string(source), previous, addresses)
	if err != nil {
		return false, err
	}
	if candidate == string(source) {
		return false, nil
	}
	if err = os.MkdirAll(r.validation, 0700); err != nil {
		return false, err
	}
	stage, err := os.MkdirTemp(r.validation, "home-net-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(stage)
	stagedHome := filepath.Join(stage, "home-net.lua")
	if err = atomicWrite(stagedHome, []byte(candidate), 0600); err != nil {
		return false, err
	}
	config, err := regularRead(r.config, 4<<20)
	if err != nil {
		return false, err
	}
	include := regexp.MustCompile(`include\s+["']` + regexp.QuoteMeta(r.home) + `["']`)
	if len(include.FindAll(config, -1)) != 1 {
		return false, errors.New("HOME_NET 配置引用不明确")
	}
	stagedConfig := filepath.Join(stage, "snort.lua")
	data := include.ReplaceAllString(string(config), "include "+fmt.Sprintf("%q", stagedHome))
	if err = atomicWrite(stagedConfig, []byte(data), 0600); err != nil {
		return false, err
	}
	if err = r.validate(ctx, stagedConfig); err != nil {
		return false, err
	}
	if readText(r.home) != string(source) {
		return false, errors.New("HOME_NET 在校验期间发生变化")
	}
	if err = atomicWrite(r.home, []byte(candidate), info.Mode().Perm()); err != nil {
		return false, err
	}
	if err = r.reload(ctx); err != nil {
		recovery, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		restore := atomicWrite(r.home, source, info.Mode().Perm())
		if restore == nil {
			restore = r.reload(recovery)
		}
		return false, errors.Join(err, restore)
	}
	if err = writeJSON(r.state, prefixes); err != nil {
		return true, err
	}
	return true, nil
}

func RunHomeNet(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("HOME_NET 维护需要 root 权限")
	}
	r := homeNetRuntime{home: "/etc/snort/home-net.lua", state: "/var/lib/snort/home-net-state.json", config: "/etc/snort/snort.lua", validation: "/var/lib/snort/validation"}
	r.addresses = func(ctx context.Context, iface string) ([]byte, error) {
		out, err := commandOutput(ctx, 10*time.Second, "ip", "-j", "-6", "address", "show", "dev", iface)
		return []byte(out), err
	}
	r.validate = func(ctx context.Context, config string) error {
		plugin, err := pluginArguments()
		if err != nil {
			return err
		}
		prefix := enginePrefix()
		args := append([]string{filepath.Join(prefix, "bin/snort")}, plugin...)
		args = append(args, "--daq-dir", filepath.Join(prefix, "lib/daq"), "--script-path", filepath.Join(prefix, "etc/snort"), "-T", "-c", config)
		_, err = commandOutput(ctx, 5*time.Minute, args...)
		return err
	}
	r.reload = func(ctx context.Context) error {
		m := &RuleManager{}
		_, err := m.engineOperation(ctx, "ruleset-reload-rules", 5*time.Minute)
		return err
	}
	_, err := r.refresh(ctx, os.Getenv("IPS_HOME_NET_INTERFACE"))
	return err
}
