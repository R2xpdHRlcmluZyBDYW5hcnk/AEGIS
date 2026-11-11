package console

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

var builtinsEnabled = regexp.MustCompile(`(?m)^\s*ips\.enable_builtin_rules\s*=\s*true\b`)

func (m *RuleManager) policyFingerprint() (string, error) {
	hash := sha256.New()
	binary := filepath.Join(enginePrefix(), "bin/snort")
	info, err := os.Stat(binary)
	if err != nil {
		return "", err
	}
	dev, ino := fileIdentity(info)
	fmt.Fprintf(hash, "%s:%d:%d:%d:%d\n", binary, dev, ino, info.Size(), info.ModTime().UnixNano())
	for _, path := range []string{m.live.Config, m.live.groupsFile(), m.live.controls["THRESHOLD_CONF"], m.live.controls["DISABLE_CONF"]} {
		data, err := regularRead(path, 4<<20)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		fmt.Fprintf(hash, "%s:%d:", path, len(data))
		hash.Write(data)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (m *RuleManager) recordPolicyFingerprint() error {
	signature, err := m.policyFingerprint()
	if err != nil {
		return err
	}
	if err = writeJSON(filepath.Join(m.state, "policy-engine.json"), Object{"signature": signature, "at": now()}); err != nil {
		return err
	}
	m.mu.Lock()
	m.policyStamp = signature
	m.policyAfter = time.Time{}
	m.mu.Unlock()
	return nil
}

// Reconcile applied policy only. Pending edits stay outside this transaction.
func (m *RuleManager) maybeRefreshPolicies() error {
	if !m.mu.TryLock() {
		return nil
	}
	defer m.mu.Unlock()
	if m.paused || m.jobs.Busy() || time.Now().Before(m.policyAfter) || !builtinsEnabled.MatchString(readText(m.live.Config)) {
		return nil
	}
	signature, err := m.policyFingerprint()
	if err != nil {
		m.policyAfter = time.Now().Add(5 * time.Minute)
		return errors.New("无法核对内置特征策略")
	}
	if signature == m.policyStamp {
		return nil
	}
	m.policyAfter = time.Now().Add(5 * time.Minute)
	_, err = m.jobs.Start("policy-refresh", "maintenance", "")
	return err
}
