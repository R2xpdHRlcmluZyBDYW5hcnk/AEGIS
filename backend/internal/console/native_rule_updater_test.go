package console

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNativeOfficialDownloadVerifiesDigestRetriesAndHidesCredentials(t *testing.T) {
	paths := liveRulePaths(t.TempDir())
	copyOfficialSources(t, paths)
	catalog := testOfficialSources(t, paths)
	var calls atomic.Int32
	fetch := func(ctx context.Context, address string, limit int64) ([]byte, error) {
		if strings.Contains(address, ".md5") {
			hash := md5.Sum([]byte("good"))
			return []byte(hex.EncodeToString(hash[:])), nil
		}
		if calls.Add(1) == 1 {
			return []byte("publishing race"), nil
		}
		return []byte("good"), nil
	}
	data, err := downloadOfficialRules(t.Context(), catalog.sources["snort/registered"], catalog.snapshot("auto"), strings.Repeat("a", 40), fetch)
	if err != nil || string(data) != "good" || calls.Load() != 2 {
		t.Fatal(string(data), err, calls.Load())
	}
	_, err = downloadOfficialRules(t.Context(), catalog.sources["snort/lightspd"], "", "bad", fetch)
	if err == nil || strings.Contains(err.Error(), "bad") {
		t.Fatal("credential validation or sanitization failed", err)
	}
	address, err := catalog.sources["snort/registered"].downloadURL(catalog.snapshot("auto"), strings.Repeat("a", 40))
	if err != nil || !strings.Contains(address, "snapshot-31300.tar.gz?") {
		t.Fatal(address, err)
	}
}

func TestNativeLightSPDSelectsCompatibleTextPolicyAndFlowbitDependencies(t *testing.T) {
	pool := NewPool(2)
	defer pool.Close()
	files := map[string][]byte{
		"lightspd/rules/3.0.0.0/base.rules": []byte(`alert tcp any any -> any any (msg:"base"; sid:1; rev:1;)
# block tcp any any -> any any (msg:"setter"; flowbits:set,fixture; sid:10; rev:1;)
alert tcp any any -> any any (msg:"disabled"; sid:12; rev:1;)
alert tcp any any -> any any (msg:"higher revision"; sid:13; rev:2;)
alert tcp any any -> any any (msg:"old equal revision"; sid:14; rev:1;)
alert tcp any any -> any any (msg:"numeric version policy"; sid:15; rev:1;)
alert tcp any any -> any any (msg:"explicitly disabled"; sid:16; rev:1;)
`),
		"lightspd/rules/3.1.7.0/selected.rules": []byte(`alert tcp any any -> any any (msg:"check"; flowbits:isset,fixture; sid:11; rev:1;)
alert tcp any any -> any any (msg:"lower revision"; sid:13; rev:1;)
alert tcp any any -> any any (msg:"new equal revision"; sid:14; rev:1;)
`),
		"lightspd/rules/3.0.0.0/rulestates-balanced-ips.states":      []byte("\uFEFF# policy\r\nalert (gid:1; sid:1; enable;)\nblock (gid:1; sid:10; enable:no;)\nalert (gid:1; sid:13; enable;)\nalert (gid:1; sid:14; enable;)\nalert (gid:1; sid:16; enable;)\n"),
		"lightspd/rules/3.1.7.0/rulestates-balanced-ips.states":      []byte("block (gid:1; sid:11; enable;)\nalert (gid:1; sid:15; enable;)\n"),
		"lightspd/rules/3.1.24.0/rulestates-balanced-ips.states":     []byte("block (gid:1; sid:15; enable;)\nalert (gid:1; sid:16; enable:no;)\n"),
		"lightspd/builtins/3.0.0.0-0/builtins.rules":                 []byte(`alert (gid:119; sid:272; msg:"builtin fixture";)`),
		"lightspd/builtins/3.0.0.0-0/rulestates-balanced-ips.states": []byte("block (gid:119; sid:272; enable;)\n"),
		"lightspd/rules/3.14.0.0/new.rules":                          []byte(`alert tcp any any -> any any (msg:"future"; sid:99; rev:1;)`),
		"lightspd/manifest.json":                                     []byte(`{"snort versions":{"3.13.0.0-0":{"policies_path":"policies/3.1.0.0-0/"}}}`),
	}
	raw, groups, err := compileRuleBundle(t.Context(), files, lightSPDArchive, "3.13.2.0", "balanced", pool)
	if err != nil {
		t.Fatal(err)
	}
	rows := map[int64]*Rule{}
	for _, line := range strings.Split(string(raw), "\n") {
		if r := parseRule(line, "", "", true); r != nil {
			rows[r.ID.SID] = r
		}
	}
	for _, id := range []int64{1, 10, 11, 12, 13, 14, 15, 16} {
		if rows[id] == nil {
			t.Fatalf("base or delta rule %d missing", id)
		}
	}
	if rows[99] != nil || !rows[1].Enabled || rows[12].Enabled || rows[16].Enabled || rows[11].Action != "block" || rows[15].Action != "block" || !strings.Contains(rows[13].Line, "higher revision") || !strings.Contains(rows[14].Line, "new equal revision") {
		t.Fatal("cumulative rule revisions, policy actions or version precedence lost")
	}
	if !rows[10].Enabled || rows[10].Action != "alert" || !strings.Contains(rows[10].Line, "flowbits:noalert;") {
		t.Fatal("dependency setter must be active without blocking or alerting")
	}
	if builtin := rows[272]; builtin == nil || builtin.ID.GID != 119 || builtin.Action != "block" || !strings.HasSuffix(builtin.Line, " enable;)") {
		t.Fatal("builtin policy must use a native state override")
	}
	if len(groups["11"]) != 1 || groups["11"][0] != "selected" {
		t.Fatal(groups)
	}
	m := testManager(t)
	os.WriteFile(m.live.controls["DISABLE_CONF"], []byte("sid:10\n"), 0600)
	os.WriteFile(m.live.controls["ACTION_CONF"], []byte("reject sid:11\n"), 0600)
	controlled, err := applyRulePolicy(t.Context(), string(raw), m.live, groups, "snort/lightspd", pool)
	if err != nil || !strings.Contains(controlled, "# alert tcp any any -> any any (msg:\"setter\"") || !strings.Contains(controlled, "reject tcp any any -> any any (msg:\"check\"") {
		t.Fatal("user disable and action policies lost priority", err)
	}
	delete(files, "lightspd/rules/3.1.7.0/rulestates-balanced-ips.states")
	if _, _, err = compileRuleBundle(t.Context(), files, lightSPDArchive, "3.13.2.0", "balanced", pool); err == nil {
		t.Fatal("missing policy accepted")
	}
}

func TestNativePolicyStateSyntaxAndBounds(t *testing.T) {
	for _, test := range []struct {
		line    string
		enabled bool
	}{
		{"block (gid:1; sid:4294967295; enable;)", true},
		{"\uFEFF ALERT ( gid : 1 ; sid : 4294967295 ; enable : YES ; )\r", true},
		{"alert (gid:1; sid:4294967295; enable:no;)", false},
		{"alert (gid:1; sid:4294967295; disable;)", false},
		{"alert (gid:1; sid:4294967295; disable:no;)", true},
		{"alert (gid:1; sid:4294967295; enable) # legacy", true},
	} {
		id, state, ok := parseRulePolicyState(test.line)
		if !ok || id != (RuleID{1, 4294967295}) || state.enabled != test.enabled || state.action != strings.ToLower(strings.Fields(strings.TrimPrefix(test.line, "\uFEFF"))[0]) {
			t.Fatal("policy state syntax or enable state lost", test.line)
		}
	}
	for _, line := range []string{
		"alert (gid:0; sid:1; enable;)", "alert (gid:8130; sid:1; enable;)",
		"alert (gid:1; sid:0; enable;)", "alert (gid:1; sid:4294967296; enable;)",
		"alert (gid:1; sid:99999999999999999999999; enable;)",
		"alert (gid:1; sid:1; enable:invalid;)", "alert (gid:1; sid:1; enable;) injected",
	} {
		if _, _, ok := parseRulePolicyState(line); ok {
			t.Fatal("invalid policy accepted", line)
		}
	}
}

func TestNativePolicyErrorIdentifiesLocationWithoutPayload(t *testing.T) {
	pool := NewPool(1)
	defer pool.Close()
	_, _, err := compileRuleBundle(t.Context(), map[string][]byte{
		"rules/fixture.rules":                  []byte(`alert tcp any any -> any any (sid:1;)`),
		"rules/rulestates-balanced-ips.states": []byte("# policy\nprivate invalid payload\n"),
	}, registeredArchive, "3.13.2.0", "balanced", pool)
	if err == nil || !strings.Contains(err.Error(), "rules/rulestates-balanced-ips.states:2") || strings.Contains(err.Error(), "private") {
		t.Fatal("missing sanitized file and line diagnostic", err)
	}
}

func TestNativeBundleVersionOrder(t *testing.T) {
	names := []string{"lightspd/rules/3.1.24.0/a.rules", "lightspd/builtins/3.0.0.0-10/a.rules", "lightspd/builtins/3.0.0.0-2/a.rules", "lightspd/rules/3.1.7.0/a.rules", "rules/a.rules"}
	sortBundleNames(names)
	if !slices.Equal(names, []string{"lightspd/builtins/3.0.0.0-2/a.rules", "lightspd/builtins/3.0.0.0-10/a.rules", "lightspd/rules/3.1.7.0/a.rules", "lightspd/rules/3.1.24.0/a.rules", "rules/a.rules"}) {
		t.Fatal(names)
	}
}

func TestNativeLightSPDRebuildsLegacyDerivedCacheOffline(t *testing.T) {
	m := testManager(t)
	source := "snort/lightspd"
	key := sourceKey(source)
	archive, err := rulesArchive(map[string][]byte{
		"lightspd/rules/3.0.0.0/base.rules":                     []byte(`alert tcp any any -> any any (msg:"base"; sid:1;)`),
		"lightspd/rules/3.0.0.0/rulestates-balanced-ips.states": []byte("block (gid:1; sid:1; enable;)\n"),
		"lightspd/rules/3.7.0.0/delta.rules":                    []byte(`alert tcp any any -> any any (msg:"delta"; sid:2;)`),
		"lightspd/rules/3.7.0.0/rulestates-balanced-ips.states": []byte("alert (gid:1; sid:2; enable;)\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(m.live.Cache, key+"-rules.tar.gz")
	if err := atomicWrite(file, archive, 0600); err != nil {
		t.Fatal(err)
	}
	hash, _ := digestFile(file)
	if err := writeJSON(filepath.Join(m.live.Cache, key+"-receipt.json"), Object{"source": source, "sha256": hash}); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(m.live.Cache, "derived", key+".rules")
	if err := atomicWrite(base, []byte("alert tcp any any -> any any (msg:\"legacy truncated\"; sid:2;)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	candidateHash, _ := digestFile(base)
	if err := writeJSON(strings.TrimSuffix(base, ".rules")+".json", Object{
		"recipe":  Object{"source": source, "policy": "balanced", "snapshot": "", "definition": "", "parser": "native-go-2"},
		"archive": hash, "candidate": candidateHash, "groups": Object{},
	}); err != nil {
		t.Fatal(err)
	}
	built := 0
	for range 2 {
		output, err := testOfficialSources(t, m.live).updateRuleSource(t.Context(), m.live, source, Object{}, true, nil, m.pool, func(line string) {
			if strings.HasPrefix(line, "候选特征已生成") {
				built++
			}
		})
		if err != nil || !strings.Contains(output, "block tcp any any -> any any (msg:\"base\"") || !strings.Contains(output, "msg:\"delta\"") || strings.Contains(output, "legacy truncated") {
			t.Fatal("legacy cache was not safely rebuilt", err)
		}
	}
	if built != 1 {
		t.Fatal("new validated derived cache was not reused", built)
	}
}

func TestNativeRuleBundleRejectsUnsafeMembersAndDuplicateFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "parent", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			var data bytes.Buffer
			gz := gzip.NewWriter(&data)
			archive := tar.NewWriter(gz)
			name := "rules/fixture.rules"
			header := &tar.Header{Name: name, Mode: 0600, Typeflag: tar.TypeReg, Size: 0}
			if kind == "symlink" {
				header.Typeflag = tar.TypeSymlink
				header.Linkname = "/etc/passwd"
			}
			if kind == "parent" {
				header.Name = "../escape.rules"
			}
			archive.WriteHeader(header)
			if kind == "duplicate" {
				archive.WriteHeader(header)
			}
			archive.Close()
			gz.Close()
			file := filepath.Join(t.TempDir(), "source.tar.gz")
			os.WriteFile(file, data.Bytes(), 0600)
			if _, err := readRuleBundle(file); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
}

func TestNativeCommunityArchiveReplay(t *testing.T) {
	archive := os.Getenv("AEGIS_RULE_ARCHIVE")
	if archive == "" {
		t.Skip("local copied rule archive not provided")
	}
	files, err := readRuleBundle(archive)
	if err != nil {
		t.Fatal(err)
	}
	pool := NewPool(WorkerCount())
	defer pool.Close()
	raw, groups, err := compileRuleBundle(t.Context(), files, textArchive, "3.13.2.0", "balanced", pool)
	if err != nil {
		t.Fatal(err)
	}
	var active int
	for _, line := range strings.Split(string(raw), "\n") {
		if r := parseRule(line, "", "", true); r != nil && r.Enabled {
			active++
		}
	}
	if active < 1 || len(groups) < 1 {
		t.Fatal("copied official archive generated no active rules")
	}
	t.Log("Copied official archive parsed and rendered with native source groups")
}

// Opt in with an archive copied to a local temporary directory. Licensed rule
// text stays outside the repository and diagnostics contain counts only.
func TestNativeLightSPDArchiveReplay(t *testing.T) {
	archive := os.Getenv("AEGIS_LIGHTSPD_ARCHIVE")
	if archive == "" {
		t.Skip("local copied LightSPD archive not provided")
	}
	files, err := readRuleBundle(archive)
	if err != nil {
		t.Fatal(err)
	}
	pool := NewPool(WorkerCount())
	defer pool.Close()
	for _, policy := range []string{"balanced", "connectivity", "security", "max-detect"} {
		t.Run(policy, func(t *testing.T) {
			selected, states, err := ruleBundleSelection(files, lightSPDArchive, "3.13.2.0", policy)
			if err != nil {
				t.Fatal(err)
			}
			raw, groups, err := compileRuleBundle(t.Context(), files, lightSPDArchive, "3.13.2.0", policy, pool)
			if err != nil {
				t.Fatal(err)
			}
			rows := map[RuleID]*Rule{}
			active, blocked := 0, 0
			for _, line := range strings.Split(string(raw), "\n") {
				r := parseRule(line, "", "", true)
				if r == nil {
					continue
				}
				if rows[r.ID] != nil {
					t.Fatal("duplicate rendered signature")
				}
				rows[r.ID] = r
				if r.Enabled {
					active++
					if r.Action == "block" {
						blocked++
					}
				}
			}
			baseCount, deltaCount := 0, 0
			for name, data := range selected {
				if strings.HasPrefix(name, "lightspd/rules/3.0.0.0/") {
					baseCount++
				} else if strings.HasPrefix(name, "lightspd/rules/") {
					deltaCount++
				}
				normalized := strings.ReplaceAll(strings.ReplaceAll(string(data), "\\\r\n", ""), "\\\n", "")
				for _, line := range strings.Split(normalized, "\n") {
					if r := parseRule(line, "", "", true); r != nil && rows[r.ID] == nil {
						t.Fatal("base or compatible delta signature missing")
					}
				}
			}
			if baseCount == 0 || deltaCount == 0 || active == 0 || blocked == 0 || len(groups) == 0 {
				t.Fatal("base, version delta, active rules or block actions missing")
			}
			names := make([]string, 0, len(states))
			for name := range states {
				names = append(names, name)
			}
			sortBundleNames(names)
			final := map[RuleID]rulePolicyState{}
			for _, name := range names {
				for _, line := range strings.Split(string(states[name]), "\n") {
					if id, state, ok := parseRulePolicyState(line); ok {
						final[id] = state
					}
				}
			}
			for id, state := range final {
				if r := rows[id]; r != nil && state.enabled && (!r.Enabled || r.Action != state.action) {
					t.Fatal("selected IPS policy lost enable state or action")
				}
			}
			if directory := os.Getenv("AEGIS_LIGHTSPD_REPLAY_OUTPUT"); directory != "" {
				if err := os.WriteFile(filepath.Join(directory, policy+".rules"), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			t.Logf("base files=%d delta files=%d policies=%d signatures=%d active=%d block=%d", baseCount, deltaCount, len(states), len(rows), active, blocked)
		})
	}
}

func TestNativeUpdaterOfflineNeedsNoPythonAndKeepsFailedCandidateIsolated(t *testing.T) {
	m := testManager(t)
	source := "custom/fixture"
	item := Object{"name": source, "format": "rules", "url": "https://example.test/rules", "enabled": true, "token": ""}
	raw := []byte("alert tcp any any -> any 443 (msg:\"first\"; sid:101; rev:1;)\nalert tcp any any -> any 443 (msg:\"newer\"; sid:101; rev:2;)\n")
	archive, err := rulesArchive(map[string][]byte{"fixture.rules": raw})
	if err != nil {
		t.Fatal(err)
	}
	key := sourceKey(source)
	file := filepath.Join(m.live.Cache, key+"-rules.tar.gz")
	if err = atomicWrite(file, archive, 0600); err != nil {
		t.Fatal(err)
	}
	hash, _ := digestFile(file)
	writeJSON(filepath.Join(m.live.Cache, key+"-receipt.json"), Object{"source": source, "sha256": hash, "definition": definitionDigest(item)})
	output, err := testOfficialSources(t, m.live).updateRuleSource(t.Context(), m.live, source, Object{}, true, item, m.pool, func(string) {})
	if err != nil || strings.Contains(output, "first") || !strings.Contains(output, "newer") {
		t.Fatal(output, err)
	}
	os.WriteFile(file, []byte("corrupt"), 0600)
	if _, err = testOfficialSources(t, m.live).updateRuleSource(t.Context(), m.live, source, Object{}, true, item, m.pool, func(string) {}); err == nil {
		t.Fatal("corrupt cache accepted")
	}
}
