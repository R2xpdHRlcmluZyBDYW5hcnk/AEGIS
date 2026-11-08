package console

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type retiredHistoryFile struct {
	path string
	info os.FileInfo
}

// Keep the old inodes until every writer has reopened and the new event store
// is healthy. Renaming a live log is safe; unlinking its open inode is not.
type historyHandoff struct {
	root, backup string
	files        []retiredHistoryFile
	directories  map[string]bool
	oldDirs      []string
}

func stageHistoryLogs(root, id string) (*historyHandoff, error) {
	if !jobIDPattern.MatchString(id) {
		return nil, errors.New("历史任务标识无效")
	}
	logs, dirs, err := historyLogMembers(root)
	if err != nil {
		return nil, err
	}
	h := &historyHandoff{root: root, backup: filepath.Join(root, ".history-reset-"+id), directories: map[string]bool{}, oldDirs: dirs}
	if err = os.Mkdir(h.backup, 0700); err != nil {
		return nil, err
	}
	for _, path := range logs {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return h, errors.New("日志在切换前发生变化")
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return h, errors.New("日志切换路径无效")
		}
		target := filepath.Join(h.backup, rel)
		for parent := filepath.Dir(target); parent != h.backup; parent = filepath.Dir(parent) {
			h.directories[parent] = true
		}
		if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return h, err
		}
		if err = os.Rename(path, target); err != nil {
			return h, err
		}
		h.files = append(h.files, retiredHistoryFile{target, info})
		// Only active top-level logs need a replacement. Preserve their access
		// rights, without recreating historical rotations or archive members.
		if filepath.Dir(path) == filepath.Join(root, "events") && filepath.Base(path) == "events.json" ||
			filepath.Dir(path) == filepath.Join(root, "snort") &&
				(strings.HasSuffix(path, "file_connector_ndr_transmit") || strings.HasSuffix(path, "alert_json.txt") ||
					strings.HasSuffix(path, "ndr_session.json") || strings.HasSuffix(path, "quic_observer.json")) {
			file, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
			if errors.Is(e, os.ErrExist) {
				now, e := os.Lstat(path)
				if e != nil || !now.Mode().IsRegular() {
					return h, errors.New("新日志成员类型异常")
				}
				continue
			}
			if e != nil {
				return h, e
			}
			if e = file.Close(); e != nil {
				return h, e
			}
			if e = os.Chmod(path, info.Mode().Perm()); e == nil {
				e = copyOwnership(info, path)
			}
			if e != nil {
				return h, e
			}
		}
	}
	if err = syncDirectory(h.backup); err == nil {
		err = syncDirectory(root)
	}
	return h, err
}

func (h *historyHandoff) verifyClosed(pid int) error {
	entries, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(pid), "fd"))
	if err != nil {
		return errors.New("无法核对检测日志句柄")
	}
	identities := map[[2]uint64]bool{}
	for _, old := range h.files {
		dev, ino := fileIdentity(old.info)
		identities[[2]uint64{dev, ino}] = true
	}
	for _, entry := range entries {
		info, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid), "fd", entry.Name()))
		if errors.Is(err, os.ErrNotExist) { // A descriptor can close during inspection.
			continue
		}
		if err != nil {
			return errors.New("检测日志句柄核对失败")
		}
		dev, ino := fileIdentity(info)
		if identities[[2]uint64{dev, ino}] {
			return errors.New("检测引擎仍持有旧日志，历史已保留")
		}
	}
	return nil
}

func (h *historyHandoff) remove() error {
	for _, old := range h.files {
		info, err := os.Lstat(old.path)
		if err != nil || !info.Mode().IsRegular() || !os.SameFile(info, old.info) {
			return errors.New("隔离日志发生变化，保留待检查文件")
		}
	}
	for _, old := range h.files {
		if err := os.Remove(old.path); err != nil {
			return err
		}
	}
	dirs := make([]string, 0, len(h.directories))
	for path := range h.directories {
		dirs = append(dirs, path)
	}
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	for _, path := range append(append(dirs, h.backup), h.oldDirs...) {
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	return syncDirectory(h.root)
}

func removeHistoryDatabaseBackup(backup, webState string) error {
	if webState == resetWebState && strings.HasPrefix(backup, "postgresql:") {
		address, err := configuredPostgresMaintenance()
		if err != nil {
			return err
		}
		if address == "" {
			return errors.New("PostgreSQL 维护配置不可用")
		}
		return removePostgresHistory(context.Background(), address, strings.TrimPrefix(backup, "postgresql:"))
	}
	if filepath.Dir(backup) != webState || !strings.HasPrefix(filepath.Base(backup), "history-backup-") {
		return errors.New("事件库备份清理路径无效")
	}
	canonical, err := historyStateDirectory(webState)
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(backup); err != nil || resolved != filepath.Join(canonical, filepath.Base(backup)) {
		return errors.New("事件库备份目录发生变化")
	}
	allowed := map[string]bool{}
	for _, suffix := range []string{"", "-wal", "-shm", ".summary.db", ".summary.db-wal", ".summary.db-shm"} {
		allowed["snort-ndr.db"+suffix] = true
	}
	entries, err := os.ReadDir(backup)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		info, err := os.Lstat(filepath.Join(backup, entry.Name()))
		if err != nil || !info.Mode().IsRegular() || !allowed[entry.Name()] {
			return errors.New("事件库备份成员异常，保留原文件")
		}
	}
	for _, entry := range entries {
		if err := os.Remove(filepath.Join(backup, entry.Name())); err != nil {
			return err
		}
	}
	return os.Remove(backup)
}
