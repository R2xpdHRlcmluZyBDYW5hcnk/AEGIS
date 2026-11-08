package console

import (
	"errors"
	"os"
	"path/filepath"
)

const managedLogRoot = "/var/lib/ips-snort-logs"

// LogPaths follows the persistent layout shared with the detection supervisor.
func LogPaths() (string, string, error) {
	return logPaths(os.Getenv("IPS_LOG_STORAGE_ROOT"), "/etc/ips-log-storage.json")
}

func logPaths(configured, marker string) (string, string, error) {
	if configured != "" {
		if configured != managedLogRoot {
			return "", "", errors.New("服务日志目录与已安装布局不一致")
		}
		return filepath.Join(managedLogRoot, "snort"), filepath.Join(managedLogRoot, "events/events.json"), nil
	}
	var config Object
	if info, err := os.Lstat(marker); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", "", errors.New("日志存储标记不能是符号链接")
	}
	err := readJSON(marker, &config)
	if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, os.ErrPermission) {
		return "", "", errors.New("日志存储标记无效")
	}
	if err == nil {
		if text(config["root"]) != managedLogRoot {
			return "", "", errors.New("持久日志目录与已安装布局不一致")
		}
		if config["direct_paths"] == true {
			return filepath.Join(managedLogRoot, "snort"), filepath.Join(managedLogRoot, "events/events.json"), nil
		}
	}
	return "/var/log/snort", "/var/log/ips/events.json", nil
}
