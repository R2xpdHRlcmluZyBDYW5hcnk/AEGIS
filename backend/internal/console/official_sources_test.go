package console

import (
	"crypto/md5"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func copyOfficialSources(t *testing.T, paths rulePaths) {
	t.Helper()
	if err := copyFile(filepath.Join("..", "..", "..", officialSourceFile), paths.officialSourcePath()); err != nil {
		t.Fatal(err)
	}
}

func testOfficialSources(t *testing.T, paths rulePaths) officialCatalog {
	t.Helper()
	catalog, err := paths.officialSources()
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func TestOfficialSourceConfigIsReadOnDemand(t *testing.T) {
	paths := liveRulePaths(t.TempDir())
	copyOfficialSources(t, paths)
	data := readText(paths.officialSourcePath())
	data = strings.ReplaceAll(data, "snort/community", "snort/fixture")
	data = strings.ReplaceAll(data, "snort3-community-rules.tar.gz", "fixture-signatures.tar.gz")
	if err := atomicWrite(paths.officialSourcePath(), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.Sources, 0700); err != nil {
		t.Fatal(err)
	}
	if err := setSourceEnabled(paths, "snort/fixture", true, nil); err != nil {
		t.Fatal(err)
	}
	public, err := publicSources(paths, nil)
	if err != nil || !slices.ContainsFunc(public["sources"].([]Object), func(row Object) bool {
		return row["name"] == "snort/fixture" && row["enabled"] == true
	}) {
		t.Fatal("configuration change did not reach the source list", err)
	}
	line := "alert tcp any any -> any any (msg:\"External catalog fixture\"; sid:1;)\n"
	archive, err := rulesArchive(map[string][]byte{"fixture.rules": []byte(line)})
	if err != nil {
		t.Fatal(err)
	}
	fixtureRuleDownloads(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/downloads/community/fixture-signatures.tar.gz":
			w.Write(archive)
		case "/downloads/community/fixture-signatures.tar.gz.md5":
			fmt.Fprintf(w, "%x", md5.Sum(archive))
		default:
			http.NotFound(w, r)
		}
	}))
	pool := NewPool(1)
	defer pool.Close()
	if err := UpdateRules(t.Context(), paths, false, "", false, pool, func(string) {}); err != nil {
		t.Fatal("updater did not select the configured enabled source", err)
	}
	if !strings.Contains(readText(filepath.Join(paths.Data, "rules/snort.rules")), line) {
		t.Fatal("downloaded signature did not reach the compiled rules")
	}
}

func TestInvalidOfficialSourceConfigRejectsUpdates(t *testing.T) {
	paths := liveRulePaths(t.TempDir())
	copyOfficialSources(t, paths)
	data := strings.ReplaceAll(readText(paths.officialSourcePath()), "https://snort.org/", "https://example.test/")
	if err := atomicWrite(paths.officialSourcePath(), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	pool := NewPool(1)
	defer pool.Close()
	if err := UpdateRules(t.Context(), paths, false, "", false, pool, func(string) {}); err == nil || !strings.Contains(err.Error(), "配置无效") {
		t.Fatal("update accepted an untrusted official source", err)
	}
	if _, err := os.Stat(paths.Cache); !os.IsNotExist(err) {
		t.Fatal("invalid configuration allowed cache writes", err)
	}
}
