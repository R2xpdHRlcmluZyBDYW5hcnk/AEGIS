package console

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func seedCatalogCandidate(t *testing.T, m *RuleManager, source string, raw []byte, groups map[string][]string, archiveSize int64) {
	t.Helper()
	key := sourceKey(source)
	file := filepath.Join(m.live.Cache, key+"-rules.tar.gz")
	if err := os.MkdirAll(m.live.Cache, 0700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	err = f.Truncate(archiveSize)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	if err := writeJSON(filepath.Join(m.live.Cache, key+"-receipt.json"), Object{"source": source, "sha256": digest}); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(m.live.Cache, "derived", key)
	if err := atomicWrite(base+".rules", raw, 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	if err := writeJSON(base+".json", Object{"recipe": Object{"source": source, "format": string(testOfficialSources(t, m.live).archiveFormat(source)), "parser": nativeRuleParserVersion}, "archive": digest, "candidate": hex.EncodeToString(hash[:]), "groups": groups}); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(m.live.Cache, "sources.json"), Object{key: Object{"source": source, "enabled": true}}); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogLargeArchiveUsesDerivedGroupsAndDisabledNames(t *testing.T) {
	m := testManager(t)
	source := "snort/lightspd"
	raw := []byte("# alert tcp any any -> any any (msg:\"Disabled browser detection\"; sid:1001;)\nalert tcp any any -> any any (msg:\"Active browser detection\"; sid:1002;)\nalert tcp any any -> any any (msg:\"Shared detection\"; sid:1003;)\n")
	groups := map[string][]string{"1001": {"snort3-browser"}, "1002": {"snort3-browser"}, "1003": {"snort3-browser", "snort3-malware"}}
	// A sparse local file crosses the old compressed-size cutoff without a
	// large fixture. The valid compiled candidate avoids archive decompression.
	seedCatalogCandidate(t, m, source, raw, groups, 129<<20)
	if err := atomicWrite(filepath.Join(m.live.Sources, "snort-lightspd.yaml"), []byte("source: snort/lightspd\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(m.live.Data, "rules/snort.rules"), []byte("alert tcp any any -> any any (msg:\"Active browser detection\"; sid:1002;)\nalert tcp any any -> any any (msg:\"Shared detection\"; sid:1003;)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.drafts.Reset(); err != nil {
		t.Fatal(err)
	}
	rows, catalog, err := m.catalog.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || len(catalog) != 2 {
		t.Fatal("compiled source inventory or groups missing", len(rows), len(catalog))
	}
	for _, g := range catalog {
		if g["source"] != source || g["source_enabled"] != true || g["policy_managed"] != true {
			t.Fatal("source identity or group capabilities lost")
		}
		if g["name"] == "snort3-browser" && (integer(g["total"]) != 3 || integer(g["compiled"]) != 2) {
			t.Fatal("disabled members missing from the source group")
		}
	}
	for _, row := range rows {
		if row.ID.SID == 1001 && (row.Enabled || row.Message != "Disabled browser detection") {
			t.Fatal("disabled signature lost its metadata")
		}
		if row.ID.SID == 1003 && len(row.Origins) != 2 {
			t.Fatal("multi-group identity collapsed")
		}
	}
	editManager(t, m, "/api/rules/disable", Object{"value": "sid:1001"})
	editManager(t, m, "/api/rules/disable", Object{"value": "sid:9999"})
	editManager(t, m, "/api/rules/action", Object{"selector": "sid:1002", "action": "reject"})
	editManager(t, m, "/api/rules/suppress", Object{"sids": []any{"1003"}})
	gov, err := m.governance(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	disabled := gov["disable"].([]Object)
	names := map[string]string{}
	for _, row := range disabled {
		names[text(row["value"])] = text(row["name"])
	}
	if names["sid:1001"] != "Disabled browser detection" || names["sid:9999"] != "sid:9999" || gov["action"].([]Object)[0]["name"] != "Active browser detection" || gov["suppress"].([]Object)[0]["name"] != "Shared detection" {
		t.Fatal("governance names or unknown-SID fallback incorrect")
	}

	updated := []byte(strings.ReplaceAll(string(raw), "Disabled browser detection", "Updated disabled description"))
	seedCatalogCandidate(t, m, source, updated, groups, 129<<20)
	gov, err = m.governance(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range gov["disable"].([]Object) {
		found = found || row["name"] == "Updated disabled description"
	}
	if !found {
		t.Fatal("derived cache changes did not invalidate catalog metadata")
	}
	editManager(t, m, "/api/rules/source", Object{"name": source, "enable": false})
	_, catalog, err = m.catalog.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range catalog {
		if row["source_enabled"] != false {
			t.Fatal("disabled source became visible")
		}
	}
}

func TestCatalogInvalidDerivedCacheFallsBackToArchive(t *testing.T) {
	for _, broken := range []string{"candidate", "recipe", "groups", "receipt"} {
		t.Run(broken, func(t *testing.T) {
			m := testManager(t)
			source := "snort/community"
			key := sourceKey(source)
			seedCatalogCandidate(t, m, source, []byte("alert tcp any any -> any any (msg:\"stale\"; sid:1;)\n"), map[string][]string{"1": {"stale"}}, 1)
			archive, err := rulesArchive(map[string][]byte{"snort3-community-rules/snort3-community.rules": []byte("# alert tcp any any -> any any (msg:\"Recovered original metadata\"; sid:1;)\n")})
			if err != nil {
				t.Fatal(err)
			}
			if err := atomicWrite(filepath.Join(m.live.Cache, key+"-rules.tar.gz"), archive, 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(m.live.Cache, "derived", key+".json")
			var meta Object
			if err := readJSON(path, &meta); err != nil {
				t.Fatal(err)
			}
			switch broken {
			case "candidate":
				meta["candidate"] = strings.Repeat("0", 64)
			case "recipe":
				object(meta["recipe"])["parser"] = "native-go-2"
			case "groups":
				meta["groups"] = Object{"1": []any{"../invalid"}}
			case "receipt":
				meta["archive"] = strings.Repeat("0", 64)
			}
			if err := writeJSON(path, meta); err != nil {
				t.Fatal(err)
			}
			rows, groups, err := m.catalog.Load(t.Context())
			if err != nil || len(rows) != 1 || len(groups) != 1 || rows[0].Message != "Recovered original metadata" || groups[0]["name"] != "snort3-community" {
				t.Fatal("invalid derived cache prevented bounded archive fallback", err)
			}
		})
	}
}

func TestCatalogArchiveBeyondBudgetReturnsError(t *testing.T) {
	m := testManager(t)
	seedCatalogCandidate(t, m, "snort/lightspd", []byte("alert tcp any any -> any any (msg:\"fixture\"; sid:1;)\n"), map[string][]string{"1": {"fixture"}}, 257<<20)
	if _, _, err := m.catalog.Load(t.Context()); err == nil {
		t.Fatal("oversized archive was silently omitted or accepted")
	}
}

func TestCatalogCopiedLightSPDReplay(t *testing.T) {
	root := os.Getenv("AEGIS_CATALOG_REPLAY")
	if root == "" {
		t.Skip("local copied rule source not provided")
	}
	m := testManager(t)
	source := "snort/lightspd"
	key := sourceKey(source)
	for name, target := range map[string]string{"lightspd.tar.gz": filepath.Join(m.live.Cache, key+"-rules.tar.gz"), "lightspd.rules": filepath.Join(m.live.Cache, "derived", key+".rules"), "lightspd.json": filepath.Join(m.live.Cache, "derived", key+".json"), "receipt.json": filepath.Join(m.live.Cache, key+"-receipt.json")} {
		if err := copyFile(filepath.Join(root, name), target); err != nil {
			t.Fatal(err)
		}
	}
	writeJSON(filepath.Join(m.live.Cache, "sources.json"), Object{key: Object{"source": source, "enabled": true}})
	atomicWrite(filepath.Join(m.live.Sources, "snort-lightspd.yaml"), []byte("source: snort/lightspd\n"), 0600)
	if err := m.drafts.Reset(); err != nil {
		t.Fatal(err)
	}
	rows, groups, err := m.catalog.Load(t.Context())
	if err != nil || len(rows) == 0 || len(groups) == 0 {
		t.Fatal("copied LightSPD metadata did not restore groups", err)
	}
	var saved Object
	if err := readJSON(filepath.Join(root, "lightspd.json"), &saved); err != nil {
		t.Fatal(err)
	}
	expectedGroups := map[string]bool{}
	for _, values := range object(saved["groups"]) {
		for _, value := range array(values) {
			expectedGroups[text(value)] = true
		}
	}
	if len(rows) != len(object(saved["groups"])) || len(groups) != len(expectedGroups) {
		t.Fatal("copied source lost signatures or groups")
	}
	for _, rule := range rows {
		if rule.Source != source || len(rule.Origins) == 0 {
			t.Fatal("source identity lost")
		}
	}
	editManager(t, m, "/api/rules/disable", Object{"value": rows[0].selector()})
	gov, err := m.governance(t.Context())
	if err != nil || gov["disable"].([]Object)[0]["name"] != rows[0].Message {
		t.Fatal("copied disabled signature name missing", err)
	}
	t.Logf("Copied LightSPD source: signatures=%d groups=%d; disabled signature names resolved", len(rows), len(groups))
	// Legacy or damaged derived metadata must still show compatible groups from
	// the original large archive, including every version delta.
	saved["candidate"] = strings.Repeat("0", 64)
	if err := writeJSON(filepath.Join(m.live.Cache, "derived", key+".json"), saved); err != nil {
		t.Fatal(err)
	}
	fallbackRows, fallbackGroups, err := m.catalog.Load(t.Context())
	if err != nil || len(fallbackRows) != len(rows) || len(fallbackGroups) != len(groups) {
		t.Fatal("copied large-archive fallback lost source groups", err)
	}
	t.Log("Copied LightSPD archive fallback preserved the full compatible group inventory")
}
