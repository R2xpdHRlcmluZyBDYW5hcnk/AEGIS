package console

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type RuleManager struct {
	mu             sync.Mutex
	state, socket  string
	live           rulePaths
	drafts         *Drafts
	catalog        *RuleCatalog
	pool           *Pool
	jobs           *RuleJobs
	ctx            context.Context
	paused         bool
	schedule       Object
	scheduleError  string
	policyStamp    string
	policyAfter    time.Time
	engineGate     sync.Mutex
	runtimeMu      sync.RWMutex
	runtime        Object
	metadata       *RuleMetadata
	engineOverride func(context.Context, string, time.Duration) (any, error)
}

func NewRuleManager(ctx context.Context, state, socket, root string) (*RuleManager, error) {
	if err := os.MkdirAll(state, 0700); err != nil {
		return nil, err
	}
	live := liveRulePaths(root)
	drafts, err := newDrafts(live, state)
	if err != nil {
		return nil, err
	}
	pool := NewPool(WorkerCount())
	m := &RuleManager{ctx: ctx, state: state, socket: socket, live: live, drafts: drafts, pool: pool, runtime: Object{}, schedule: Object{"enabled": false, "frequency": "daily", "time": "04:00", "weekday": 0, "next_run": float64(0), "last_run": nil}}
	m.catalog = newRuleCatalog(pool, live, drafts.paths)
	m.policyAfter = time.Now().Add(time.Minute)
	var policyReceipt Object
	if readJSON(filepath.Join(state, "policy-engine.json"), &policyReceipt) == nil {
		m.policyStamp = text(policyReceipt["signature"])
	}
	m.metadata = newMetadata(pool, live.Data)
	m.paused = fileExists(filepath.Join(state, "maintenance"))
	var saved Object
	if readJSON(filepath.Join(state, "schedule.json"), &saved) == nil {
		if validateSchedule(saved) == nil {
			m.schedule = saved
			if object(saved["last_run"])["state"] == "running" {
				object(saved["last_run"])["state"] = "interrupted"
			}
		} else {
			m.scheduleError = "定时设置无效，已停用"
		}
	}
	m.jobs, err = NewRuleJobs(m)
	if err != nil {
		pool.Close()
		return nil, err
	}
	if err = m.jobs.Recover(); err != nil {
		pool.Close()
		return nil, err
	}
	return m, nil
}
func fileExists(path string) bool { _, err := os.Stat(path); return err == nil }
func (m *RuleManager) Close()     { m.jobs.Wait(); m.pool.Close() }
func (m *RuleManager) Read(ctx context.Context, name string, args []any, params Object) (any, error) {
	if strings.HasPrefix(name, "sys.") {
		switch name {
		case "sys.update_status":
			return m.jobs.Status(), nil
		case "sys.reload_state":
			return m.jobs.ReloadState(), nil
		case "sys.service":
			return object(m.Runtime()["service"]), nil
		case "sys.rule_log":
			id := text(present(params["id"], params["identity"]))
			offset := integer(params["offset"])
			if len(args) > 0 {
				id = text(args[0])
			}
			if len(args) > 1 {
				offset = integer(args[1])
			}
			return m.jobs.Log(id, offset)
		}
	}
	if name == "system_payload" {
		return m.SystemPayload(ctx), nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.drafts.paths
	switch name {
	case "governance_state":
		return m.governance(ctx)
	case "hunt_rules_list":
		return manualRules(p), nil
	case "app.sources_catalog":
		return publicSources(p, readSettings(filepath.Join(filepath.Dir(m.live.Config), "rule-update.conf")))
	case "app.rules_payload":
		return m.rulesPayload(ctx)
	case "rule_group_catalog", "suppression_group_catalog", "rule_groups_search":
		_, groups, err := m.catalog.Load(ctx)
		if err != nil {
			return nil, err
		}
		q := strings.ToLower(text(present(params["q"], params["query"])))
		if len(args) > 0 {
			q = strings.ToLower(text(args[0]))
		}
		out := []Object{}
		scope := text(present(params["scope"], params["exclude"]))
		if len(args) > 1 {
			scope = text(args[1])
		}
		configuredValues := []string{}
		switch scope {
		case "disable":
			configuredValues = configured(p.controls["DISABLE_CONF"])
		case "action":
			configuredValues = append(configured(p.controls["DROP_CONF"]), actionSelectors(p)...)
		}
		var suppressGroups []string
		readJSON(p.groupsFile(), &suppressGroups)
		for _, group := range groups {
			if group["source_enabled"] == false && scope != "suppress-remove" {
				continue
			}
			if scope == "action" && (group["builtin"] == true || group["policy_managed"] == false) {
				continue
			}
			if scope == "disable" && group["policy_managed"] == false && group["builtin"] != true {
				continue
			}
			if selectorConfigured(text(group["selector"]), configuredValues) {
				continue
			}
			if scope == "suppress" {
				found := false
				for _, s := range suppressGroups {
					found = found || s == text(group["selector"])
				}
				if found {
					continue
				}
			}
			if q == "" || strings.Contains(strings.ToLower(text(group["name"])+" "+text(group["source"])+" "+text(group["label"])), q) {
				out = append(out, clone(group))
			}
		}
		return out, nil
	case "rule_group_detail":
		group := text(present(params["name"], params["group"]))
		source := text(params["source"])
		if len(args) > 0 {
			group = text(args[0])
		}
		if len(args) > 1 {
			source = text(args[1])
		}
		value, err := m.catalog.Search(ctx, params, groupSelector(group, source))
		if err != nil {
			return nil, err
		}
		return Object{"name": group, "source": source, "selector": groupSelector(group, source), "rules": value["rules"], "total": value["total"], "offset": value["offset"], "limit": value["limit"]}, nil
	case "app.rule_selection":
		selector := text(params["selector"])
		if len(args) > 0 {
			selector = text(args[0])
		}
		return m.catalog.Search(ctx, params, selector)
	case "app.rules_search":
		if len(args) > 0 {
			params = clone(params)
			params["q"] = args[0]
		}
		return m.catalog.Search(ctx, params, "")
	case "app.rules_page":
		if len(args) > 0 {
			params = object(args[0])
		}
		tab := text(get(params, "tab", "catalog"))
		summary := Object{"ruleset": object(object(m.Runtime()["engine"])["ruleset-stats"]), "reload": m.jobs.ReloadState(), "rule_manager": true, "pending": m.drafts.Dirty, "sources_pending": m.drafts.SourcesChanged()}
		gov := Object{}
		var data any
		var schedule any
		var err error
		switch tab {
		case "catalog":
			data, err = m.catalog.Search(ctx, params, "")
		case "groups":
			var groups []Object
			_, groups, err = m.catalog.Load(ctx)
			data = Object{"groups": groups}
			if q := strings.ToLower(text(params["q"])); q != "" {
				matches := []string{}
				for _, g := range groups {
					if strings.Contains(strings.ToLower(text(g["name"])+" "+text(g["source"])), q) {
						matches = append(matches, text(g["selector"]))
					}
				}
				object(data)["matching"] = matches
			}
		case "manual":
			data = Object{"rules": manualRules(p)}
			summary["local_rules"] = readLines(p.controls["LOCAL_RULES"])
		case "sources":
			data, err = publicSources(p, readSettings(filepath.Join(filepath.Dir(m.live.Config), "rule-update.conf")))
			schedule = m.scheduleStatus()
		case "bans":
			data = Object{"bans": loadBans(p)}
		case "disable", "action", "suppress":
			gov, err = m.governance(ctx)
			data = gov
		default:
			return nil, errors.New("无效特征标签页")
		}
		if err != nil {
			return nil, err
		}
		return Object{"summary": summary, "governance": gov, "data": data, "schedule": schedule}, nil
	}
	return nil, errors.New("不支持的特征管理查询")
}
func (m *RuleManager) governance(ctx context.Context) (Object, error) {
	result := governance(m.drafts.paths)
	policies := result["suppress_groups"].([]Object)
	needNames := len(policies) > 0
	for _, category := range []string{"disable", "drop", "action", "suppress"} {
		needNames = needNames || len(result[category].([]Object)) > 0
	}
	if !needNames {
		return result, nil
	}
	rows, _, err := m.catalog.Load(ctx)
	if err != nil {
		return nil, err
	}
	byID := map[RuleID]*Rule{}
	for _, rule := range rows {
		byID[rule.ID] = rule
	}
	for _, category := range []string{"disable", "drop", "action"} {
		for _, entry := range result[category].([]Object) {
			selector := text(present(entry["selector"], entry["value"]))
			if id, err := identity(selector); err == nil {
				if rule := byID[id]; rule != nil {
					entry["name"] = rule.Message
				}
			} else if strings.HasPrefix(selector, "group:") || strings.HasPrefix(selector, "group-source:") {
				if _, name, err := parseGroup(selector); err == nil {
					entry["name"] = name
				}
			}
		}
	}
	for _, entry := range result["suppress"].([]Object) {
		if rule := byID[RuleID{integer(entry["gid"]), integer(entry["sid"])}]; rule != nil {
			entry["name"] = rule.Message
		}
	}
	for _, policy := range policies {
		count := 0
		for _, r := range rows {
			if selectorMatches(text(policy["selector"]), r) {
				count++
			}
		}
		policy["total"] = count
	}
	return result, nil
}
func (m *RuleManager) rulesPayload(ctx context.Context) (Object, error) {
	_, groups, err := m.catalog.Load(ctx)
	if err != nil {
		return nil, err
	}
	public, err := publicSources(m.drafts.paths, readSettings(filepath.Join(filepath.Dir(m.live.Config), "rule-update.conf")))
	if err != nil {
		return nil, err
	}
	enabled := []string{}
	for _, value := range public["sources"].([]Object) {
		if value["enabled"] == true {
			enabled = append(enabled, text(value["name"]))
		}
	}
	mtime := int64(0)
	if info, err := os.Stat(filepath.Join(m.live.Data, "rules/snort.rules")); err == nil {
		mtime = info.ModTime().Unix()
	}
	return Object{"ruleset": object(object(m.Runtime()["engine"])["ruleset-stats"]), "categories": groups, "sources": enabled, "local_rules": readLines(m.drafts.paths.controls["LOCAL_RULES"]), "bans": loadBans(m.drafts.paths), "rules_mtime": mtime, "rule_manager": true, "pending": m.drafts.Dirty, "sources_pending": m.drafts.SourcesChanged(), "reload": m.jobs.ReloadState()}, nil
}
func (m *RuleManager) Dispatch(ctx context.Context, request Object, rootPeer bool) (any, error) {
	op := text(request["operation"])
	allowed := map[string]string{"ping": "operation", "read": "operation name args kwargs", "schedule": "operation", "history-status": "operation", "maintenance": "operation enabled", "refresh-policies": "operation", "history-reset": "operation scope", "history-reset-begin": "operation job", "history-reset-finish": "operation job", "mutate": "operation method path body"}[op]
	if allowed == "" {
		return nil, errors.New("不支持的特征管理操作")
	}
	keys := map[string]bool{}
	for _, key := range strings.Fields(allowed) {
		keys[key] = true
	}
	for key := range request {
		if !keys[key] {
			return nil, errors.New("请求包含不支持的参数")
		}
	}
	switch op {
	case "ping":
		if len(request) != 1 {
			return nil, errors.New("无效请求")
		}
		return Object{"ready": true}, nil
	case "read":
		if request["args"] != nil {
			if _, ok := request["args"].([]any); !ok {
				return nil, errors.New("查询参数必须为数组")
			}
		}
		args := array(request["args"])
		params := object(request["kwargs"])
		if len(args) > 6 {
			return nil, errors.New("查询参数过多")
		}
		names := map[string]string{"governance_state": "details", "rule_group_catalog": "", "suppression_group_catalog": "removable", "rule_groups_search": "query q scope exclude", "rule_group_detail": "name group source query q offset limit", "hunt_rules_list": "", "app.rules_payload": "", "app.sources_catalog": "", "app.rules_page": "tab query q offset limit source exclude include", "app.rule_selection": "selector q query source exclude include offset limit scope", "app.rules_search": "q query source exclude include offset limit scope browse include_groups", "sys.update_status": "", "sys.reload_state": "", "sys.service": "", "sys.rule_log": "id identity offset", "system_payload": ""}
		allowed, known := names[text(request["name"])]
		if !known {
			return nil, errors.New("不支持的特征管理查询")
		}
		for key := range params {
			found := false
			for _, v := range strings.Fields(allowed) {
				found = found || key == v
			}
			if !found {
				return nil, errors.New("查询包含不支持的参数")
			}
		}
		return m.Read(ctx, text(request["name"]), args, params)
	case "schedule":
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.scheduleStatus(), nil
	case "history-status":
		var value Object
		if readJSON(filepath.Join(m.state, "history-reset.json"), &value) != nil {
			return Object{"state": "idle"}, nil
		}
		return value, nil
	case "refresh-policies":
		if !rootPeer {
			return nil, errors.New("策略同步需要 root 对端")
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.paused || m.jobs.Busy() {
			return nil, errors.New("特征或维护任务正在执行")
		}
		m.policyAfter = time.Now().Add(5 * time.Minute)
		return m.jobs.Start("policy-refresh", "maintenance", "")
	case "maintenance":
		if !rootPeer {
			return nil, errors.New("维护操作需要 root 对端")
		}
		enabled, ok := request["enabled"].(bool)
		if !ok {
			return nil, errors.New("维护状态无效")
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.jobs.Busy() {
			return Object{"ok": false, "error": "特征任务正在执行"}, nil
		}
		path := filepath.Join(m.state, "maintenance")
		if strings.TrimSpace(readText(path)) == "history-reset" {
			return Object{"ok": false, "error": "历史清理正在执行"}, nil
		}
		if enabled {
			if err := atomicWrite(path, []byte("paused\n"), 0600); err != nil {
				return nil, err
			}
		} else {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
		}
		m.paused = enabled
		if !enabled {
			m.policyAfter = time.Now().Add(time.Minute)
		}
		return Object{"ok": true}, nil
	case "history-reset":
		scope := text(get(request, "scope", "all"))
		if scope != "all" && scope != "database" {
			return nil, errors.New("历史清理范围无效")
		}
		return m.StartHistoryReset(scope)
	case "history-reset-begin", "history-reset-finish":
		if !rootPeer {
			return nil, errors.New("历史维护需要 root 对端")
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		var value Object
		if err := readJSON(filepath.Join(m.state, "history-reset.json"), &value); err != nil {
			return nil, err
		}
		if value["id"] != request["job"] || !m.paused {
			return nil, errors.New("未知历史维护任务")
		}
		if op == "history-reset-begin" {
			if value["state"] != "queued" {
				return nil, errors.New("历史维护任务已经开始")
			}
			value["state"], value["phase"] = "running", "准备清空历史"
			if err := writeJSON(filepath.Join(m.state, "history-reset.json"), value); err != nil {
				return nil, err
			}
		}
		if op == "history-reset-finish" {
			if value["state"] != "done" && value["state"] != "failed" {
				return nil, errors.New("历史维护尚未完成")
			}
			if err := os.Remove(filepath.Join(m.state, "maintenance")); err != nil {
				return nil, err
			}
			m.paused = false
			m.policyAfter = time.Now().Add(time.Minute)
		}
		return Object{"ok": true}, nil
	case "mutate":
		if request["body"] != nil {
			switch request["body"].(type) {
			case Object, map[string]any:
			default:
				return nil, errors.New("操作正文必须为对象")
			}
		}
		method, path := text(request["method"]), text(request["path"])
		if !validMutation(method, path) {
			return nil, errors.New("不支持的特征操作")
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.paused || m.jobs.Busy() {
			return Object{"ok": false, "error": "特征或维护任务正在执行，请稍后重试"}, nil
		}
		body := object(request["body"])
		if path == "/api/actions/update" {
			return m.jobs.Start("update", "manual", "")
		}
		if path == "/api/actions/apply" {
			return m.jobs.Start("apply", "manual", "")
		}
		if path == "/api/actions/reload" {
			return Object{"ok": false, "error": "请点击“应用更改”提交更改"}, nil
		}
		if path == "/api/rules/action-apply" {
			return Object{"ok": true, "pending": m.drafts.Dirty, "message": "已保存，点击“应用更改”生效"}, nil
		}
		if path == "/api/rules/pending/discard" {
			if err := m.drafts.Reset(); err != nil {
				return nil, err
			}
			m.catalog.Invalidate()
			return Object{"ok": true, "pending": false}, nil
		}
		if path == "/api/rules/schedule" {
			if err := validateSchedule(body); err != nil {
				return nil, err
			}
			for _, key := range []string{"enabled", "frequency", "time", "weekday"} {
				m.schedule[key] = body[key]
			}
			m.schedule["next_run"] = float64(0)
			if body["enabled"] == true {
				m.schedule["next_run"] = nextSchedule(m.schedule, time.Now())
			}
			if err := writeJSON(filepath.Join(m.state, "schedule.json"), m.schedule); err != nil {
				return nil, err
			}
			result := m.scheduleStatus()
			result["ok"] = true
			return result, nil
		}
		if path == "/api/hunt/rules/add-apply" {
			line := text(body["rule"])
			if err := validateManualRule(line); err != nil {
				return nil, err
			}
			if sidExpression.MatchString(line) || validateSuggestion(line) != nil {
				return nil, errors.New("特征建议不符合受限格式")
			}
			used := map[int64]bool{}
			for _, path := range []string{filepath.Join(m.live.Data, "rules/snort.rules"), m.live.controls["LOCAL_RULES"], m.live.controls["HUNT_RULES"], m.live.controls["BAN_RULES"], m.drafts.paths.controls["HUNT_RULES"]} {
				for _, match := range sidExpression.FindAllStringSubmatch(readText(path), -1) {
					n, _ := strconv.ParseInt(match[1], 10, 64)
					used[n] = true
				}
			}
			sid := int64(9200001)
			for used[sid] {
				sid++
			}
			line = strings.TrimSuffix(line, ")") + fmt.Sprintf(" sid:%d;)", sid)
			result, err := m.jobs.Start("manual-add", "manual", line)
			if err != nil {
				return nil, err
			}
			result["sid"] = sid
			return result, nil
		}
		before, err := privateTree(m.drafts.root)
		if err != nil {
			return nil, err
		}
		dirty := m.drafts.Dirty
		result, err := m.edit(ctx, method, path, body)
		if err != nil {
			if recovery := replaceTree(m.drafts.root, before); recovery != nil {
				m.paused = true
				return nil, errors.New("待应用配置恢复失败，请检查维护状态")
			}
			m.drafts.Dirty = dirty
			return nil, err
		}
		m.drafts.Dirty = true
		if err = m.drafts.Persist(); err != nil {
			replaceTree(m.drafts.root, before)
			m.drafts.Dirty = dirty
			return nil, err
		}
		m.catalog.Invalidate()
		result["pending"] = true
		if result["ok"] == true {
			result["message"] = "已保存，点击“应用更改”生效"
		}
		return result, nil
	}
	return nil, errors.New("不支持的特征管理操作")
}
func valuesFrom(body Object, plural, single string) ([]string, error) {
	var values []any
	if v, ok := body[plural]; ok {
		values = array(v)
	} else {
		values = []any{body[single]}
	}
	if len(values) == 0 || len(values) > 1000 {
		return nil, errors.New("特征操作数量无效")
	}
	out := []string{}
	for _, v := range values {
		value, ok := v.(string)
		if !ok {
			if n, ok := v.(json.Number); ok {
				value = string(n)
			} else {
				return nil, errors.New("特征范围格式无效")
			}
		}
		if value == "" {
			return nil, errors.New("特征范围不能为空")
		}
		out = append(out, value)
	}
	return out, nil
}
func (m *RuleManager) edit(ctx context.Context, method, path string, body Object) (Object, error) {
	p := m.drafts.paths
	ok := func() Object { return Object{"ok": true} }
	if path == "/api/rules/batch-delete" {
		paths, err := valuesFrom(body, "paths", "path")
		if err != nil {
			return nil, err
		}
		for _, item := range paths {
			if !validMutation("DELETE", item) {
				return nil, errors.New("批量删除路径无效")
			}
			if _, err = m.edit(ctx, "DELETE", item, Object{}); err != nil {
				return nil, err
			}
		}
		return ok(), nil
	}
	if path == "/api/rules/source/config" {
		return ok(), configureSource(p, body, readSettings(filepath.Join(filepath.Dir(m.live.Config), "rule-update.conf")))
	}
	if path == "/api/rules/source" {
		enabled, valid := body["enable"].(bool)
		if !valid {
			return nil, errors.New("启用状态无效")
		}
		return ok(), setSourceEnabled(p, text(body["name"]), enabled, readSettings(filepath.Join(filepath.Dir(m.live.Config), "rule-update.conf")))
	}
	if path == "/api/hunt/rules" && method == "POST" {
		line := text(body["rule"])
		if err := validateManualRule(line); err != nil {
			return nil, err
		}
		if sidExpression.FindString(line) == "" {
			used := map[int64]bool{}
			for _, r := range manualRules(p) {
				used[integer(r["sid"])] = true
			}
			sid := int64(9200001)
			for used[sid] {
				sid++
			}
			line = strings.TrimSuffix(strings.TrimSpace(line), ")") + fmt.Sprintf(" sid:%d;)", sid)
		}
		rule := parseRule(line, "", "", true)
		if rule == nil {
			return nil, errors.New("特征缺少有效的 GID:SID")
		}
		for _, existing := range manualRules(p) {
			if integer(existing["gid"]) == rule.ID.GID && integer(existing["sid"]) == rule.ID.SID {
				return nil, errors.New("特征已存在")
			}
		}
		if err := appendPrivateLine(p.controls["HUNT_RULES"], line); err != nil {
			return nil, err
		}
		return Object{"ok": true, "sid": rule.ID.SID}, nil
	}
	if method == "DELETE" && strings.HasPrefix(path, "/api/hunt/rules/") {
		value, _ := url.PathUnescape(strings.TrimPrefix(path, "/api/hunt/rules/"))
		id, err := identity(value)
		if err != nil {
			return nil, err
		}
		kept := []string{}
		found := false
		for _, line := range readLines(p.controls["HUNT_RULES"]) {
			r := parseRule(line, "", "", true)
			if r != nil && r.ID == id {
				found = true
				continue
			}
			kept = append(kept, line)
		}
		if !found {
			return nil, errors.New("手动特征不存在")
		}
		return ok(), atomicWrite(p.controls["HUNT_RULES"], []byte(strings.Join(kept, "\n")+"\n"), 0600)
	}
	if path == "/api/bans" || strings.HasPrefix(path, "/api/bans/") {
		entries := loadBans(p)
		if method == "DELETE" || path == "/api/bans/batch-delete" {
			targets := []string{}
			if path == "/api/bans/batch-delete" {
				var err error
				targets, err = valuesFrom(body, "values", "value")
				if err != nil {
					return nil, err
				}
			} else {
				value, err := url.PathUnescape(strings.TrimPrefix(path, "/api/bans/"))
				if err != nil {
					return nil, err
				}
				targets = []string{value}
			}
			remove := map[string]bool{}
			for _, v := range targets {
				remove[v] = true
			}
			kept := []Object{}
			for _, entry := range entries {
				if !remove[text(entry["value"])] {
					kept = append(kept, entry)
				}
			}
			if len(kept) == len(entries) {
				return nil, errors.New("封禁条目不存在")
			}
			return ok(), saveBans(p, kept)
		}
		entry, err := parseBan(text(present(body["target"], body["ip"])))
		if err != nil {
			return nil, err
		}
		for _, existing := range entries {
			if existing["value"] == entry["value"] {
				return nil, errors.New("目标已封禁")
			}
		}
		entry["created"] = time.Now().Format("2006-01-02 15:04")
		if entry["type"] == "domain" {
			entry["ips"] = resolveDomain(ctx, text(entry["value"]))
		}
		return ok(), saveBans(p, append(entries, entry))
	}
	if strings.HasPrefix(path, "/api/rules/suppress-groups") {
		values, err := valuesFrom(body, "groups", "group")
		if err != nil {
			return nil, err
		}
		var groups []string
		readJSON(p.groupsFile(), &groups)
		set := map[string]bool{}
		for _, g := range groups {
			set[g] = true
		}
		for _, value := range values {
			source, name, err := parseGroup(value)
			if err != nil {
				return nil, err
			}
			selector := groupSelector(name, source)
			if strings.HasSuffix(path, "/remove") {
				delete(set, selector)
			} else {
				set[selector] = true
			}
		}
		groups = nil
		for value := range set {
			groups = append(groups, value)
		}
		sort.Strings(groups)
		if err = writeJSON(p.groupsFile(), groups); err != nil {
			return nil, err
		}
		if values := array(body["sids"]); len(values) > 0 {
			return m.edit(ctx, "POST", "/api/rules/suppress", Object{"sids": values})
		}
		return ok(), nil
	}
	if method == "DELETE" && strings.HasPrefix(path, "/api/rules/suppress-group/") {
		value, err := url.PathUnescape(strings.TrimPrefix(path, "/api/rules/suppress-group/"))
		if err != nil {
			return nil, err
		}
		return m.edit(ctx, "POST", "/api/rules/suppress-groups/remove", Object{"groups": []any{value}})
	}
	if path == "/api/rules/suppress" || strings.HasPrefix(path, "/api/rules/suppress/") {
		values := []string{}
		var err error
		if method == "DELETE" {
			value, e := url.PathUnescape(strings.TrimPrefix(path, "/api/rules/suppress/"))
			if e != nil {
				return nil, e
			}
			values = []string{value}
		} else {
			values, err = valuesFrom(body, "sids", "sid")
			if err != nil {
				return nil, err
			}
		}
		ids := map[RuleID]bool{}
		for _, value := range values {
			id, err := identity(value)
			if err != nil {
				return nil, err
			}
			ids[id] = true
		}
		kept := []string{}
		existing := map[RuleID]bool{}
		for _, line := range readLines(p.controls["THRESHOLD_CONF"]) {
			decoded := suppressionText(line)
			match := suppressionExpression.FindStringSubmatch(decoded)
			if len(match) == 3 {
				gid, _ := strconv.ParseInt(match[1], 10, 64)
				sid, _ := strconv.ParseInt(match[2], 10, 64)
				id := RuleID{gid, sid}
				if ids[id] && method == "DELETE" {
					continue
				}
				existing[id] = true
			}
			kept = append(kept, line)
		}
		if method != "DELETE" {
			for id := range ids {
				if !existing[id] {
					kept = append(kept, fmt.Sprintf("suppress gen_id %d, sig_id %d", id.GID, id.SID))
				}
			}
		}
		return ok(), atomicWrite(p.controls["THRESHOLD_CONF"], []byte(strings.Join(kept, "\n")+"\n"), 0600)
	}
	kind := ""
	for _, candidate := range []string{"disable", "drop", "reject", "action"} {
		if path == "/api/rules/"+candidate || strings.HasPrefix(path, "/api/rules/"+candidate+"/") {
			kind = candidate
			break
		}
	}
	if kind == "" {
		return nil, errors.New("不支持的特征编辑")
	}
	values := []string{}
	var err error
	if method == "DELETE" {
		v, e := url.PathUnescape(strings.TrimPrefix(path, "/api/rules/"+kind+"/"))
		if e != nil {
			return nil, e
		}
		values = []string{v}
	} else if kind == "action" {
		values, err = valuesFrom(body, "selectors", "selector")
	} else {
		values, err = valuesFrom(body, "values", "value")
	}
	if err != nil {
		return nil, err
	}
	canonical := []string{}
	for _, value := range values {
		selector, err := canonicalSelector(value)
		if err != nil {
			return nil, err
		}
		if kind == "action" && !strings.HasPrefix(selector, "sid:") && !strings.HasPrefix(selector, "msg:") {
			return nil, errors.New("动作覆盖范围应为 SID 或消息前缀")
		}
		canonical = append(canonical, selector)
	}
	if kind == "action" {
		action := text(body["action"])
		if method != "DELETE" && action != "drop" && action != "reject" {
			return nil, errors.New("动作只能是 drop 或 reject")
		}
		kept := []string{}
		for _, line := range readLines(p.controls["ACTION_CONF"]) {
			parts := strings.SplitN(strings.TrimSpace(line), " ", 2)
			matched := false
			if len(parts) == 2 {
				for _, selector := range canonical {
					if parts[1] == selector {
						matched = true
					}
				}
			}
			if !matched {
				kept = append(kept, line)
			}
		}
		if method != "DELETE" {
			for _, selector := range canonical {
				kept = append(kept, action+" "+selector)
			}
		}
		return ok(), atomicWrite(p.controls["ACTION_CONF"], []byte(strings.Join(kept, "\n")+"\n"), 0600)
	}
	keys := []string{"DISABLE_CONF"}
	if kind == "drop" {
		keys = []string{"DROP_CONF"}
		if method == "DELETE" {
			keys = append(keys, "MODIFY_CONF")
		}
	}
	if kind == "reject" {
		keys = []string{"DROP_CONF", "MODIFY_CONF"}
		if method == "DELETE" {
			keys = []string{"MODIFY_CONF"}
		}
	}
	for _, key := range keys {
		existing := configured(p.controls[key])
		set := map[string]bool{}
		for _, value := range existing {
			set[value] = true
		}
		for _, selector := range canonical {
			if method == "DELETE" || (kind == "reject" && body["enable"] == false && key == "MODIFY_CONF") {
				delete(set, selector)
			} else {
				set[selector] = true
			}
		}
		updated := []string{}
		for value := range set {
			updated = append(updated, value)
		}
		sort.Strings(updated)
		if err = saveSelectors(p.controls[key], updated, key == "MODIFY_CONF"); err != nil {
			return nil, err
		}
	}
	return ok(), nil
}
func validateSchedule(value Object) error {
	_, ok := value["enabled"].(bool)
	if !ok || (value["frequency"] != "daily" && value["frequency"] != "weekly") || !clockPattern.MatchString(text(value["time"])) || integer(value["weekday"]) < 0 || integer(value["weekday"]) > 6 {
		return errors.New("请选择每天或每周、有效时间和星期")
	}
	return nil
}
func nextSchedule(value Object, stamp time.Time) float64 {
	parts := strings.Split(text(value["time"]), ":")
	hour, _ := strconv.Atoi(parts[0])
	minute, _ := strconv.Atoi(parts[1])
	next := time.Date(stamp.Year(), stamp.Month(), stamp.Day(), hour, minute, 0, 0, stamp.Location())
	days := 1
	if value["frequency"] == "weekly" {
		weekday := (int(next.Weekday()) + 6) % 7
		next = next.AddDate(0, 0, (int(integer(value["weekday"]))-weekday+7)%7)
		days = 7
	}
	if !next.After(stamp) {
		next = next.AddDate(0, 0, days)
	}
	return float64(next.Unix())
}
func (m *RuleManager) scheduleStatus() Object {
	value := clone(m.schedule)
	zone, offset := time.Now().Zone()
	value["timezone"] = fmt.Sprintf("%s (UTC%+03d%02d)", zone, offset/3600, (offset%3600)/60)
	value["error"] = m.scheduleError
	value["next_run_local"] = ""
	value["last_started_local"] = ""
	if stamp := number(value["next_run"]); stamp > 0 {
		value["next_run_local"] = utc(stamp)
	}
	if stamp := number(object(value["last_run"])["started"]); stamp > 0 {
		value["last_started_local"] = utc(stamp)
	}
	return value
}
func (m *RuleManager) ScheduleLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			if !m.paused && !m.jobs.Busy() && m.schedule["enabled"] == true {
				next := number(m.schedule["next_run"])
				if next <= 0 {
					m.schedule["next_run"] = nextSchedule(m.schedule, time.Now())
				} else if now() >= next {
					result, err := m.jobs.Start("update", "scheduled", "")
					if err != nil {
						m.scheduleError = "定时更新启动失败"
					} else {
						m.schedule["last_run"] = Object{"state": "running", "id": result["job_id"], "started": now()}
						m.schedule["next_run"] = nextSchedule(m.schedule, time.Now())
					}
					writeJSON(filepath.Join(m.state, "schedule.json"), m.schedule)
				}
			}
			m.mu.Unlock()
		}
	}
}
func ServeManager(ctx context.Context, state, socket, root string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	m, err := NewRuleManager(ctx, state, socket, root)
	if err != nil {
		return err
	}
	defer m.Close()
	if err = os.MkdirAll(filepath.Dir(socket), 0755); err != nil {
		return err
	}
	if info, err := os.Lstat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("控制接口路径不是套接字")
		}
		probe, e := net.DialTimeout("unix", socket, time.Second)
		if e == nil {
			probe.Close()
			return errors.New("特征管理器已运行")
		}
		if err = os.Remove(socket); err != nil {
			return err
		}
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(socket)
	group, err := user.LookupGroup("ips-console")
	if err != nil && root == "" {
		return err
	}
	gid := uint32(os.Getgid())
	if group != nil {
		n, e := strconv.Atoi(group.Gid)
		if e != nil {
			return e
		}
		gid = uint32(n)
	}
	if err = os.Chown(socket, 0, int(gid)); err != nil && root == "" {
		return err
	}
	if err = os.Chmod(socket, 0660); err != nil {
		return err
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			listener.Close()
		case <-done:
		}
	}()
	var background sync.WaitGroup
	for _, run := range []func(context.Context){m.RuntimeLoop, m.ScheduleLoop} {
		background.Add(1)
		go func(run func(context.Context)) { defer background.Done(); run(ctx) }(run)
	}
	defer func() { cancel(); background.Wait() }()
	connections := make(chan *net.UnixConn, 2*WorkerCount())
	var workers sync.WaitGroup
	for range WorkerCount() {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for connection := range connections {
				m.handleRPC(ctx, connection, gid)
			}
		}()
	}
	defer func() { close(connections); workers.Wait() }()
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case connections <- conn:
		default:
			conn.SetDeadline(time.Now().Add(250 * time.Millisecond))
			bufio.NewReader(io.LimitReader(conn, rpcRequestLimit+1)).ReadBytes('\n')
			conn.Write([]byte("{\"ok\":false,\"error\":\"特征管理服务繁忙，请稍后重试\"}\n"))
			conn.Close()
		}
	}
}
func (m *RuleManager) handleRPC(ctx context.Context, conn *net.UnixConn, gid uint32) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	conn.SetDeadline(time.Now().Add(65 * time.Second))
	if !peerAllowed(conn, gid) {
		conn.Write([]byte("{\"ok\":false,\"error\":\"权限不足\"}\n"))
		return
	}
	line, err := bufio.NewReader(io.LimitReader(conn, rpcRequestLimit+1)).ReadBytes('\n')
	var request Object
	if err != nil || len(line) > rpcRequestLimit || decode(line, &request) != nil {
		conn.Write([]byte("{\"ok\":false,\"error\":\"请求无效或过大\"}\n"))
		return
	}
	rootPeer := peerRoot(conn)
	result, err := m.Dispatch(ctx, request, rootPeer)
	response := Object{"ok": err == nil, "result": result}
	if err != nil {
		response = Object{"ok": false, "error": err.Error()}
	}
	data, err := json.Marshal(response)
	if err != nil || len(data) > rpcResponseLimit {
		data = []byte("{\"ok\":false,\"error\":\"响应超过上限\"}")
	}
	conn.Write(append(data, '\n'))
}
