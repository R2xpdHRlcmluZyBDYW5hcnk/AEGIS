package console

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLogPathsMatchPersistentAndLegacyLayouts(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "storage.json")
	check := func(configured, wantLogs, wantStream string) {
		t.Helper()
		logs, stream, err := logPaths(configured, marker)
		if err != nil || logs != wantLogs || stream != wantStream {
			t.Fatal(logs, stream, err)
		}
	}
	check("", "/var/log/snort", "/var/log/ips/events.json")
	check(managedLogRoot, managedLogRoot+"/snort", managedLogRoot+"/events/events.json")
	if _, _, err := logPaths("/unexpected", marker); err == nil {
		t.Fatal("accepted an inconsistent storage root")
	}
	if err := writeJSON(marker, Object{"root": managedLogRoot, "direct_paths": true}); err != nil {
		t.Fatal(err)
	}
	check("", managedLogRoot+"/snort", managedLogRoot+"/events/events.json")
	if err := writeJSON(marker, Object{"root": managedLogRoot, "direct_paths": false}); err != nil {
		t.Fatal(err)
	}
	check("", "/var/log/snort", "/var/log/ips/events.json")
}

func TestBridgeRejectsMissingOrNonDirectorySource(t *testing.T) {
	root := t.TempDir()
	pool := NewPool(1)
	defer pool.Close()
	for _, name := range []string{"missing", "file"} {
		logs := filepath.Join(root, name)
		if name == "file" {
			if err := os.WriteFile(logs, nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := NewBridge(logs, filepath.Join(root, "events.json"), filepath.Join(root, "offsets.json"), filepath.Join(root, "instance.json"), pool); err == nil {
			t.Fatal("invalid source directory silently accepted")
		}
	}
}

func TestHistoryLogInventoryUsesTheManagedSnortDirectory(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"snort", "events"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"snort/0_file_connector_ndr_transmit", "snort/0_ndr_session.json.1", "events/events.json"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("fixture\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	unknown := filepath.Join(root, "snort/keep.json")
	if err := os.WriteFile(unknown, nil, 0600); err != nil {
		t.Fatal(err)
	}
	logs, dirs, err := historyLogMembers(root)
	if err != nil || len(logs) != 3 || len(dirs) != 0 {
		t.Fatal("managed history inventory unavailable", len(logs), len(dirs), err)
	}
	for _, name := range logs {
		if name == unknown {
			t.Fatal("unrelated file selected")
		}
		if _, err = os.Stat(name); err != nil {
			t.Fatal("read-only inventory changed source files")
		}
	}
}
