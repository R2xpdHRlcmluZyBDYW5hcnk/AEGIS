package console

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureBuiltinEngine(t *testing.T, prefix string, extra bool) {
	t.Helper()
	text := "119:301 (http_inspect) fixture old HTTP event\n116:1 (arp) fixture ARP event\n"
	if extra {
		text += "119:305 (http_inspect) fixture new HTTP event\n"
	}
	script := "#!/bin/sh\nif [ \"$1\" = \"--list-builtin\" ]; then\ncat <<'CATALOG'\n" + text + "CATALOG\nelse\nprintf 'configuration valid\\n'\nfi\n"
	if err := atomicWrite(filepath.Join(prefix, "bin/snort"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
}

func TestRuleCatalogReloadsBuiltinMembershipAfterEngineChange(t *testing.T) {
	m := testManager(t)
	prefix := t.TempDir()
	t.Setenv("SNORT_ENGINE_PREFIX", prefix)
	fixtureBuiltinEngine(t, prefix, false)
	if err := atomicWrite(m.live.Config, []byte("ips = {}\nips.enable_builtin_rules = true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	first, _, err := m.catalog.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 {
		t.Fatal(len(first))
	}
	fixtureBuiltinEngine(t, prefix, true)
	second, _, err := m.catalog.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 3 {
		t.Fatal("engine change did not refresh category membership", len(second))
	}
}

func TestPolicyRefreshValidationFailureRestoresAppliedConfiguration(t *testing.T) {
	m := testManager(t)
	prefix := t.TempDir()
	t.Setenv("SNORT_ENGINE_PREFIX", prefix)
	fixtureBuiltinEngine(t, prefix, true)
	binary := filepath.Join(prefix, "bin/snort")
	script := strings.Replace(readText(binary), "printf 'configuration valid\\n'", "printf 'validation refused\\n'\nexit 1", 1)
	if err := atomicWrite(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	atomicWrite(m.live.Config, []byte("ips = {}\nips.enable_builtin_rules = true\n"), 0600)
	writeJSON(m.live.groupsFile(), []string{groupSelector("snort-builtin-119-http_inspect", "Snort 内置")})
	original := "suppress = { { gid = 119, sid = 301 } }\n"
	atomicWrite(m.live.controls["SUPPRESS_LUA"], []byte(original), 0600)
	if err := m.drafts.Reset(); err != nil {
		t.Fatal(err)
	}
	editManager(t, m, "/api/rules/drop", Object{"value": "sid:1002"})
	calls := 0
	m.engineOverride = func(context.Context, string, time.Duration) (any, error) { calls++; return nil, nil }
	if _, err := m.Dispatch(t.Context(), Object{"operation": "refresh-policies"}, true); err != nil {
		t.Fatal(err)
	}
	m.jobs.Wait()
	if integer(m.jobs.Status()["rc"]) != 1 || calls != 0 || readText(m.live.controls["SUPPRESS_LUA"]) != original || !m.drafts.Dirty {
		t.Fatal("failed policy refresh changed live or pending state")
	}
	if fileExists(filepath.Join(m.state, "policy-engine.json")) {
		t.Fatal("failed policy refresh was recorded as applied")
	}
}

func TestAppliedSuppressionUsesNewBuiltinMembersAndKeepsDrafts(t *testing.T) {
	m := testManager(t)
	prefix := t.TempDir()
	t.Setenv("SNORT_ENGINE_PREFIX", prefix)
	fixtureBuiltinEngine(t, prefix, true)
	atomicWrite(m.live.Config, []byte("ips = {}\nips.enable_builtin_rules = true\n"), 0600)
	selector := groupSelector("snort-builtin-119-http_inspect", "Snort 内置")
	writeJSON(m.live.groupsFile(), []string{selector})
	if err := m.drafts.Reset(); err != nil {
		t.Fatal(err)
	}
	editManager(t, m, "/api/rules/disable", Object{"value": "sid:116:1"})
	// Pending removal must not silently change the currently applied group policy.
	editManager(t, m, "/api/rules/suppress-groups/remove", Object{"groups": []any{selector}})
	if err := m.prepareThresholds(t.Context()); err != nil {
		t.Fatal(err)
	}
	lua := readText(m.live.controls["SUPPRESS_LUA"])
	if !strings.Contains(lua, "gid = 119, sid = 305") || strings.Contains(lua, "gid:116; sid:1; enable:no") {
		t.Fatal("live policy mixed pending edits or lost new group members")
	}
	if !m.drafts.Dirty || !strings.Contains(readText(m.drafts.paths.controls["DISABLE_CONF"]), "116:1") {
		t.Fatal("policy refresh consumed pending edits")
	}
	if _, err := m.Dispatch(t.Context(), Object{"operation": "refresh-policies"}, false); err == nil {
		t.Fatal("unprivileged caller could refresh engine policy")
	}
	calls := 0
	m.engineOverride = func(context.Context, string, time.Duration) (any, error) {
		calls++
		return Object{"confirmed": true}, nil
	}
	if _, err := m.Dispatch(t.Context(), Object{"operation": "refresh-policies"}, true); err != nil {
		t.Fatal(err)
	}
	m.jobs.Wait()
	if integer(m.jobs.Status()["rc"]) != 0 || calls != 1 || !m.drafts.Dirty {
		t.Fatal("live policy transaction failed or applied pending changes", m.jobs.Status())
	}
	if !fileExists(filepath.Join(m.state, "policy-engine.json")) {
		t.Fatal("successful policy refresh was not recorded")
	}
}

func TestPolicyFingerprintSchedulesBoundedRefresh(t *testing.T) {
	m := testManager(t)
	prefix := t.TempDir()
	t.Setenv("SNORT_ENGINE_PREFIX", prefix)
	fixtureBuiltinEngine(t, prefix, false)
	atomicWrite(m.live.Config, []byte("ips = {}\nips.enable_builtin_rules = true\n"), 0600)
	if err := m.recordPolicyFingerprint(); err != nil {
		t.Fatal(err)
	}
	m.policyAfter = time.Time{}
	if err := m.maybeRefreshPolicies(); err != nil || m.jobs.Busy() {
		t.Fatal("unchanged applied policy triggered work", err)
	}
	fixtureBuiltinEngine(t, prefix, true)
	m.engineOverride = func(context.Context, string, time.Duration) (any, error) { return Object{"confirmed": true}, nil }
	if err := m.maybeRefreshPolicies(); err != nil {
		t.Fatal(err)
	}
	m.jobs.Wait()
	if integer(m.jobs.Status()["rc"]) != 0 || m.jobs.Status()["kind"] != "policy-refresh" {
		t.Fatal("engine update did not reconcile policy", m.jobs.Status())
	}
	current, err := m.policyFingerprint()
	if err != nil || current != m.policyStamp {
		t.Fatal("applied policy fingerprint did not converge", err)
	}
	if err = m.maybeRefreshPolicies(); err != nil || m.jobs.Busy() {
		t.Fatal("successful refresh kept rescheduling", err)
	}
}

func TestRuleCategoriesGenerateAppliedPolicies(t *testing.T) {
	m := testManager(t)
	prefix := t.TempDir()
	t.Setenv("SNORT_ENGINE_PREFIX", prefix)
	fixtureBuiltinEngine(t, prefix, true)
	atomicWrite(m.live.Config, []byte("ips = {}\nips.enable_builtin_rules = true\n"), 0600)
	for _, entry := range []struct {
		path string
		body Object
	}{
		{"/api/rules/disable", Object{"value": "sid:1001"}},
		{"/api/rules/disable", Object{"value": "sid:116:1"}},
		{"/api/rules/drop", Object{"value": "sid:1002"}},
		{"/api/rules/reject", Object{"value": "sid:1003"}},
		{"/api/rules/action", Object{"selector": "sid:1004", "action": "drop"}},
		{"/api/rules/suppress", Object{"sids": []any{"119:305"}}},
		{"/api/hunt/rules", Object{"rule": `alert tcp any any -> any 443 (msg:"fixture manual"; sid:9900101; rev:1;)`}},
		{"/api/bans", Object{"target": "192.0.2.99"}},
	} {
		editManager(t, m, entry.path, entry.body)
	}
	if err := m.drafts.Promote(); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, id := range []string{"1001", "1002", "1003", "1004", "1005"} {
		lines = append(lines, `alert tcp any any -> any 443 (msg:"fixture `+id+`"; sid:`+id+`; rev:1;)`)
	}
	rendered, err := applyRulePolicy(t.Context(), strings.Join(lines, "\n"), m.live, nil, "snort/community", m.pool)
	if err != nil {
		t.Fatal(err)
	}
	actual := map[int64]*Rule{}
	for _, line := range strings.Split(rendered, "\n") {
		if rule := parseRule(line, "", "", true); rule != nil {
			actual[rule.ID.SID] = rule
		}
	}
	for id, want := range map[int64]string{1001: "alert", 1002: "block", 1003: "reject", 1004: "block", 1005: "alert"} {
		if actual[id] == nil || actual[id].Action != want || actual[id].Enabled != (id != 1001) {
			t.Fatal("rule action category produced the wrong result", id, want)
		}
	}
	if err = m.prepareThresholds(t.Context()); err != nil {
		t.Fatal(err)
	}
	lua := readText(m.live.controls["SUPPRESS_LUA"])
	if !strings.Contains(lua, "gid = 119, sid = 305") || !strings.Contains(lua, "gid:116; sid:1; enable:no") {
		t.Fatal("builtin suppression or disable policy missing")
	}
	if len(manualRules(m.live)) != 1 || len(loadBans(m.live)) != 1 || !strings.Contains(readText(m.live.controls["BAN_RULES"]), "192.0.2.99") {
		t.Fatal("manual rule or ban category lost its configuration")
	}
	if _, err = os.Stat(m.live.controls["BAN_DETECTOR"]); err != nil {
		t.Fatal(err)
	}
}

func TestSourceSelectionAndOfflinePolicyApplication(t *testing.T) {
	m := testManager(t)
	editManager(t, m, "/api/rules/source", Object{"name": "snort/community", "enable": true})
	editManager(t, m, "/api/rules/drop", Object{"value": "sid:2001"})
	if err := m.drafts.Promote(); err != nil {
		t.Fatal(err)
	}
	raw := []byte("alert tcp any any -> any 443 (msg:\"fixture cached source\"; sid:2001; rev:1;)\n")
	archive, err := rulesArchive(map[string][]byte{"rules/fixture.rules": raw})
	if err != nil {
		t.Fatal(err)
	}
	key := sourceKey("snort/community")
	archiveHash := sha256.Sum256(archive)
	rawHash := sha256.Sum256(raw)
	if err = atomicWrite(filepath.Join(m.live.Cache, key+"-rules.tar.gz"), archive, 0600); err != nil {
		t.Fatal(err)
	}
	if err = writeJSON(filepath.Join(m.live.Cache, key+"-receipt.json"), Object{"source": "snort/community", "sha256": hex.EncodeToString(archiveHash[:])}); err != nil {
		t.Fatal(err)
	}
	if err = atomicWrite(filepath.Join(m.live.Cache, "derived", key+".rules"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = writeJSON(filepath.Join(m.live.Cache, "derived", key+".json"), Object{"recipe": Object{"source": "snort/community", "policy": "balanced", "snapshot": "", "definition": "", "parser": "console-1"}, "archive": hex.EncodeToString(archiveHash[:]), "candidate": hex.EncodeToString(rawHash[:]), "groups": Object{"2001": []string{"fixture"}}}); err != nil {
		t.Fatal(err)
	}
	if err = UpdateRules(t.Context(), m.live, true, "", false, m.pool, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readText(filepath.Join(m.live.Data, "rules/snort.rules")), "block tcp") {
		t.Fatal("cached source did not apply action policy")
	}
	editManager(t, m, "/api/rules/source", Object{"name": "snort/community", "enable": false})
	if err = m.drafts.Promote(); err != nil {
		t.Fatal(err)
	}
	if err = UpdateRules(t.Context(), m.live, true, "", false, m.pool, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(readText(filepath.Join(m.live.Data, "rules/snort.rules")), "sid:2001") {
		t.Fatal("disabled source remained in the active merged ruleset")
	}
}

func TestOfficialIPSPolicyConfigurationIsSharedValidatedAndStaged(t *testing.T) {
	m := testManager(t)
	for _, policy := range []string{"balanced", "connectivity", "security", "max-detect"} {
		editManager(t, m, "/api/rules/source/config", Object{"name": "snort/lightspd", "ips_policy": policy})
		public, err := publicSources(m.drafts.paths, Object{})
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range array(public["sources"]) {
			if item := object(raw); item["requires_code"] == true && item["ips_policy"] != policy {
				t.Fatal("Registered and LightSPD must share one staged policy")
			}
		}
		if !m.drafts.Dirty || readText(filepath.Join(m.live.Sources, "credentials.json")) != "" {
			t.Fatal("saving a policy must leave the active configuration unchanged")
		}
	}
	before := readText(filepath.Join(m.drafts.paths.Sources, "credentials.json"))
	for _, policy := range []any{"invalid", "../security", true, []any{"security"}} {
		_, err := m.Dispatch(t.Context(), Object{"operation": "mutate", "method": "POST", "path": "/api/rules/source/config", "body": Object{"name": "snort/registered", "ips_policy": policy}}, false)
		if err == nil || readText(filepath.Join(m.drafts.paths.Sources, "credentials.json")) != before {
			t.Fatal("invalid policy modified staged configuration")
		}
	}
	editManager(t, m, "/api/rules/pending/discard", Object{})
	public, err := publicSources(m.drafts.paths, Object{"ips_policy": "connectivity"})
	if err != nil || m.drafts.Dirty {
		t.Fatal("discarding policy edit failed", err)
	}
	for _, raw := range array(public["sources"]) {
		if item := object(raw); item["ips_policy"] != "connectivity" {
			t.Fatal("existing file-based policy fallback was lost")
		}
	}
}
