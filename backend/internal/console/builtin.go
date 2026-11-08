package console

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var builtinCache struct {
	sync.Mutex
	signature string
	rows      []*Rule
}

func builtinRules(ctx context.Context, config string) ([]*Rule, error) {
	if !regexp.MustCompile(`(?m)^\s*ips\.enable_builtin_rules\s*=\s*true\b`).MatchString(readText(config)) {
		return nil, nil
	}
	binary := filepath.Join(enginePrefix(), "bin/snort")
	info, err := os.Stat(binary)
	if err != nil {
		return nil, err
	}
	_, ino := fileIdentity(info)
	signature := fmt.Sprintf("%s:%d:%d:%d", binary, ino, info.Size(), info.ModTime().UnixNano())
	builtinCache.Lock()
	defer builtinCache.Unlock()
	if builtinCache.signature != signature {
		output, err := commandOutput(ctx, 20*time.Second, binary, "--list-builtin")
		if err != nil {
			return nil, errors.New("无法读取引擎内置签名目录")
		}
		expression := regexp.MustCompile(`^([0-9]+):([0-9]+) \(([^)]+)\) (.+)$`)
		rows := []*Rule{}
		for _, line := range strings.Split(output, "\n") {
			match := expression.FindStringSubmatch(strings.TrimSpace(line))
			if len(match) != 5 {
				continue
			}
			id, err := identity(match[1] + ":" + match[2])
			if err != nil {
				return nil, err
			}
			group := "snort-builtin-" + strconv.FormatInt(id.GID, 10) + "-" + match[3]
			rows = append(rows, &Rule{ID: id, Message: "(" + match[3] + ") " + match[4], Module: match[3], Group: group, Source: "Snort 内置", Action: "alert", Builtin: true, Enabled: true, PolicyManaged: false, SourceEnabled: true, Origins: []Object{{"group": group, "source": "Snort 内置"}}})
		}
		if len(rows) == 0 {
			return nil, errors.New("引擎内置签名目录为空")
		}
		builtinCache.signature, builtinCache.rows = signature, rows
	}
	out := []*Rule{}
	for _, row := range builtinCache.rows {
		copy := *row
		out = append(out, &copy)
	}
	return out, nil
}
