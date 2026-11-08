//go:build linux

package console

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func peerCredential(conn *net.UnixConn) *syscall.Ucred {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil
	}
	var credential *syscall.Ucred
	var controlErr error
	err = raw.Control(func(fd uintptr) {
		credential, controlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil || controlErr != nil {
		return nil
	}
	return credential
}
func peerRoot(conn *net.UnixConn) bool { c := peerCredential(conn); return c != nil && c.Uid == 0 }
func peerAllowed(conn *net.UnixConn, gid uint32) bool {
	c := peerCredential(conn)
	if c == nil {
		return false
	}
	if c.Uid == 0 || c.Gid == gid {
		return true
	}
	// SO_PEERCRED contains only the effective group. DynamicUser receives the
	// console group through SupplementaryGroups; verify that exact live peer.
	data, err := os.ReadFile("/proc/" + strconv.Itoa(int(c.Pid)) + "/status")
	if err != nil {
		return false
	}
	uidOK, groupOK := false, false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] == "Uid:" && len(fields) == 5 {
			uidOK = fields[2] == strconv.FormatUint(uint64(c.Uid), 10)
		}
		if fields[0] == "Groups:" {
			for _, v := range fields[1:] {
				if v == strconv.FormatUint(uint64(gid), 10) {
					groupOK = true
				}
			}
		}
	}
	return uidOK && groupOK
}
func configureCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 2 * time.Second
}

type configurationGuard struct{ file *os.File }

func (g *configurationGuard) Close() error {
	syscall.Flock(int(g.file.Fd()), syscall.LOCK_UN)
	return g.file.Close()
}
func lockConfiguration(ctx context.Context, config string) (*configurationGuard, error) {
	f, err := os.OpenFile(filepath.Join(filepath.Dir(config), ".configuration.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return &configurationGuard{f}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func fileIdentity(info os.FileInfo) (uint64, uint64) {
	s := info.Sys().(*syscall.Stat_t)
	return uint64(s.Dev), s.Ino
}
func copyOwnership(info os.FileInfo, path string) error {
	s := info.Sys().(*syscall.Stat_t)
	return os.Chown(path, int(s.Uid), int(s.Gid))
}
