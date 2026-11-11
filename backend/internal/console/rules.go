package console

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type RuleID struct{ GID, SID int64 }
type Rule struct {
	ID                                             RuleID
	Message, Line, Action, Group, Source, Module   string
	Enabled, Builtin, PolicyManaged, SourceEnabled bool
	Origins                                        []Object
}
type rulePaths struct {
	controls                           map[string]string
	Sources, Cache, Data, Config, Dist string
}

func liveRulePaths(root string) rulePaths {
	path := func(p string) string {
		if root == "" {
			return p
		}
		return filepath.Join(root, strings.TrimPrefix(p, "/"))
	}
	return rulePaths{controls: map[string]string{"LOCAL_RULES": path("/var/lib/snort/rules/local.rules"), "HUNT_RULES": path("/var/lib/snort/rules/ips-web-hunting.rules"), "BAN_RULES": path("/var/lib/snort/rules/ips-web-bans.rules"), "BAN_STORE": path("/var/lib/snort/rules/ips-web-bans.json"), "BAN_DETECTOR": path("/var/lib/snort/rules/ips-web-bans.lua"), "THRESHOLD_CONF": path("/etc/snort/threshold.config"), "SUPPRESS_LUA": path("/etc/snort/suppress.lua"), "DISABLE_CONF": path("/etc/snort/disable.conf"), "DROP_CONF": path("/etc/snort/drop.conf"), "MODIFY_CONF": path("/etc/snort/modify.conf"), "ACTION_CONF": path("/etc/snort/action-override.conf")}, Sources: path("/var/lib/snort/update/sources"), Cache: path("/var/lib/snort/update/cache"), Data: path("/var/lib/snort"), Config: path("/etc/snort/snort.lua"), Dist: filepath.Join(enginePrefix(), "etc/snort/rules")}
}
func (p rulePaths) groupsFile() string {
	return filepath.Join(filepath.Dir(p.controls["THRESHOLD_CONF"]), "group-suppressions.json")
}
func enginePrefix() string {
	if value := os.Getenv("SNORT_ENGINE_PREFIX"); value != "" {
		return value
	}
	return "/opt/ips-snort3/3.12.4.0"
}
func regularRead(path string, maxBytes int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxBytes {
		return nil, errors.New("文件类型或大小不符合限制")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(info, actual) {
		return nil, errors.New("文件在读取时被替换")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if int64(len(data)) > maxBytes {
		return nil, errors.New("文件超过读取上限")
	}
	return data, err
}
func readText(path string) string {
	data, err := regularRead(path, 128<<20)
	if err != nil {
		return ""
	}
	return string(data)
}
func readLines(path string) []string {
	result := []string{}
	for _, line := range strings.Split(readText(path), "\n") {
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}
func copyFile(source, target string) error {
	data, err := regularRead(source, 512<<20)
	if err != nil {
		return err
	}
	return atomicWrite(target, data, 0600)
}
func privateTree(root string) (map[string][]byte, error) {
	out := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if errors.Is(err, os.ErrNotExist) && path == root {
			return nil
		}
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("受管目录不能包含符号链接")
		}
		if entry.IsDir() {
			return nil
		}
		if len(out) >= 10000 {
			return errors.New("受管文件数量超过限制")
		}
		data, err := regularRead(path, 128<<20)
		if err != nil {
			return err
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		out[name] = data
		return nil
	})
	return out, err
}
func replaceTree(root string, files map[string][]byte) error {
	existing, err := privateTree(root)
	if err != nil {
		return err
	}
	for name := range existing {
		if _, ok := files[name]; !ok {
			if err = os.Remove(filepath.Join(root, name)); err != nil {
				return err
			}
		}
	}
	for name, data := range files {
		target := filepath.Join(root, name)
		relative, err := filepath.Rel(root, target)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("受管路径越界")
		}
		if err = atomicWrite(target, data, 0600); err != nil {
			return err
		}
	}
	return nil
}

type Drafts struct {
	live, paths rulePaths
	root, state string
	Dirty       bool
	pending     atomic.Bool
}

func newDrafts(live rulePaths, state string) (*Drafts, error) {
	d := &Drafts{live: live, state: state, root: filepath.Join(state, "pending")}
	d.paths = live
	d.paths.controls = map[string]string{}
	for key, path := range live.controls {
		d.paths.controls[key] = filepath.Join(d.root, key, filepath.Base(path))
	}
	d.paths.Data = filepath.Join(d.root, "data")
	d.paths.Sources = filepath.Join(d.paths.Data, "update/sources")
	var saved Object
	if err := readJSON(filepath.Join(d.root, "state.json"), &saved); err == nil {
		dirty, ok := saved["dirty"].(bool)
		if !ok {
			return nil, errors.New("待应用特征状态损坏")
		}
		d.Dirty = dirty
		d.pending.Store(dirty)
		if dirty {
			return d, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := d.Reset(); err != nil {
		return nil, err
	}
	return d, nil
}
func (d *Drafts) Persist() error {
	err := writeJSON(filepath.Join(d.root, "state.json"), Object{"dirty": d.Dirty})
	if err == nil {
		d.pending.Store(d.Dirty)
	}
	return err
}
func (d *Drafts) Reset() error {
	for key, target := range d.paths.controls {
		data, err := regularRead(d.live.controls[key], 128<<20)
		if errors.Is(err, os.ErrNotExist) {
			data = []byte{}
			if key == "BAN_STORE" {
				data = []byte("[]\n")
			}
		} else if err != nil {
			return err
		}
		if err = atomicWrite(target, data, 0600); err != nil {
			return err
		}
	}
	groups, err := regularRead(d.live.groupsFile(), 4<<20)
	if errors.Is(err, os.ErrNotExist) {
		groups = []byte("[]\n")
	} else if err != nil {
		return err
	}
	if err = atomicWrite(d.paths.groupsFile(), groups, 0600); err != nil {
		return err
	}
	sources, err := privateTree(d.live.Sources)
	if err != nil {
		return err
	}
	if err = replaceTree(d.paths.Sources, sources); err != nil {
		return err
	}
	d.Dirty = false
	return d.Persist()
}
func (d *Drafts) Promote() error {
	for key, path := range d.paths.controls {
		if err := copyFile(path, d.live.controls[key]); err != nil {
			return err
		}
	}
	if err := copyFile(d.paths.groupsFile(), d.live.groupsFile()); err != nil {
		return err
	}
	files, err := privateTree(d.paths.Sources)
	if err != nil {
		return err
	}
	return replaceTree(d.live.Sources, files)
}
func (d *Drafts) SourcesChanged() bool {
	left, e := privateTree(d.paths.Sources)
	right, f := privateTree(d.live.Sources)
	if e != nil || f != nil || len(left) != len(right) {
		return true
	}
	for k, v := range left {
		if string(v) != string(right[k]) {
			return true
		}
	}
	return false
}

var sidExpression = regexp.MustCompile(`\bsid\s*:\s*([0-9]+)\s*;`)
var gidExpression = regexp.MustCompile(`\bgid\s*:\s*([0-9]+)\s*;`)
var messageExpression = regexp.MustCompile(`\bmsg\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"`)
var ruleAction = regexp.MustCompile(`^(alert|block|drop|reject[a-z]*|pass|react|rewrite|log)\s`)

func parseRule(line, group, source string, sourceEnabled bool) *Rule {
	enabled := !strings.HasPrefix(line, "#")
	line = strings.TrimSpace(strings.TrimLeft(line, "# "))
	action := ruleAction.FindStringSubmatch(line)
	sid := sidExpression.FindStringSubmatch(line)
	if len(action) != 2 || len(sid) != 2 {
		return nil
	}
	signature, _ := strconv.ParseInt(sid[1], 10, 64)
	generator := int64(1)
	if gid := gidExpression.FindStringSubmatch(line); len(gid) == 2 {
		generator, _ = strconv.ParseInt(gid[1], 10, 64)
	}
	if generator < 1 || generator > 8129 || signature < 1 || signature > 4294967295 {
		return nil
	}
	message := "SID " + sid[1]
	if match := messageExpression.FindStringSubmatch(line); len(match) == 2 {
		message = match[1]
	}
	return &Rule{ID: RuleID{generator, signature}, Message: message, Line: line, Action: action[1], Group: group, Source: source, Enabled: enabled, SourceEnabled: sourceEnabled, PolicyManaged: true, Origins: []Object{{"group": group, "source": source}}}
}
func (r *Rule) selector() string {
	if r.ID.GID == 1 {
		return "sid:" + strconv.FormatInt(r.ID.SID, 10)
	}
	return fmt.Sprintf("sid:%d:%d", r.ID.GID, r.ID.SID)
}
func (r *Rule) JSON() Object {
	result := Object{"gid": r.ID.GID, "sid": r.ID.SID, "msg": r.Message, "line": r.Line, "action": r.Action, "enabled": r.Enabled, "builtin": r.Builtin, "policy_managed": r.PolicyManaged, "group": r.Group, "source": r.Source, "source_enabled": r.SourceEnabled, "origins": r.Origins, "selector": r.selector(), "signature": fmt.Sprintf("%d:%d", r.ID.GID, r.ID.SID)}
	if r.Module != "" {
		result["module"] = r.Module
	}
	return result
}
func identity(value string) (RuleID, error) {
	value = strings.TrimPrefix(value, "sid:")
	parts := strings.Split(value, ":")
	if len(parts) == 1 {
		parts = append([]string{"1"}, parts...)
	}
	if len(parts) != 2 {
		return RuleID{}, errors.New("无效 GID:SID")
	}
	gid, e := strconv.ParseInt(parts[0], 10, 64)
	sid, f := strconv.ParseInt(parts[1], 10, 64)
	if e != nil || f != nil || gid < 1 || gid > 8129 || sid < 1 || sid > 4294967295 {
		return RuleID{}, errors.New("无效 GID:SID")
	}
	return RuleID{gid, sid}, nil
}
func groupSelector(group, source string) string {
	quote := func(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }
	if source == "" {
		return "group:" + strings.TrimSuffix(group, ".rules")
	}
	return "group-source:" + quote(source) + ":" + quote(strings.TrimSuffix(group, ".rules"))
}
func parseGroup(value string) (string, string, error) {
	kind, code, ok := strings.Cut(value, ":")
	if !ok {
		return "", strings.TrimSuffix(value, ".rules"), nil
	}
	if kind == "group" && code != "" {
		return "", strings.TrimSuffix(code, ".rules"), nil
	}
	if kind == "group-source" {
		source, name, ok := strings.Cut(code, ":")
		if !ok {
			return "", "", errors.New("特征分组缺少来源")
		}
		source, e := url.PathUnescape(source)
		name, f := url.PathUnescape(name)
		if e != nil || f != nil || source == "" || name == "" {
			return "", "", errors.New("无效特征分组")
		}
		return source, strings.TrimSuffix(name, ".rules"), nil
	}
	return "", "", errors.New("无效特征分组")
}
func canonicalSelector(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) == 0 || len(value) > 2000 || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("无效特征范围")
	}
	if regexp.MustCompile(`^[0-9]+(?::[0-9]+)?$`).MatchString(value) || strings.HasPrefix(value, "sid:") {
		id, err := identity(value)
		if err != nil {
			return "", err
		}
		r := Rule{ID: id}
		return r.selector(), nil
	}
	kind, code, ok := strings.Cut(value, ":")
	if !ok {
		return groupSelector(value, ""), nil
	}
	if code == "" {
		return "", errors.New("特征范围为空")
	}
	switch kind {
	case "group", "group-source":
		source, name, err := parseGroup(value)
		if err != nil {
			return "", err
		}
		return groupSelector(name, source), nil
	case "source", "msg", "ban":
		return value, nil
	case "re":
		if _, err := regexp.Compile(code); err != nil {
			return "", errors.New("正则表达式无效或不受支持")
		}
		return value, nil
	}
	return "", errors.New("特征范围类型无效")
}
func selectorMatches(selector string, r *Rule) bool {
	kind, code, _ := strings.Cut(selector, ":")
	switch kind {
	case "sid":
		id, err := identity(code)
		return err == nil && id == r.ID
	case "group", "group-source":
		source, name, err := parseGroup(selector)
		if err != nil {
			return false
		}
		for _, origin := range r.Origins {
			if (source == "" || source == origin["source"]) && (glob(name, text(origin["group"])) || glob(name, text(origin["group"])+".rules")) {
				return true
			}
		}
		return false
	case "source":
		for _, origin := range r.Origins {
			if origin["source"] == code {
				return true
			}
		}
		return false
	case "msg":
		return strings.HasPrefix(r.Message, strings.TrimSuffix(code, "*"))
	case "re":
		if r.Builtin {
			return false
		}
		expression, err := regexp.Compile(code)
		return err == nil && expression.MatchString(r.Line)
	}
	return false
}
func selectorConfigured(value string, selectors []string) bool {
	canonical, err := canonicalSelector(value)
	if err != nil {
		return false
	}
	for _, s := range selectors {
		if canonical == s {
			return true
		}
	}
	if !strings.HasPrefix(canonical, "group:") && !strings.HasPrefix(canonical, "group-source:") {
		return false
	}
	source, name, err := parseGroup(canonical)
	if err != nil {
		return false
	}
	r := &Rule{Group: name, Source: source, Origins: []Object{{"group": name, "source": source}}}
	for _, s := range selectors {
		if strings.HasPrefix(s, "group:") || strings.HasPrefix(s, "group-source:") {
			if source == "" && strings.HasPrefix(s, "group-source:") {
				continue
			}
			if selectorMatches(s, r) {
				return true
			}
		}
	}
	return false
}
func selectorFromLine(line string) string {
	marker := " # ips-web-selector-b64="
	if at := strings.LastIndex(line, marker); at >= 0 {
		encoded := strings.TrimSpace(line[at+len(marker):])
		if value, err := base64.URLEncoding.DecodeString(encoded); err == nil {
			return string(value)
		}
	}
	value := strings.TrimSpace(strings.SplitN(line, " #", 2)[0])
	if strings.HasPrefix(value, "metadata-add ") {
		return ""
	}
	if strings.HasSuffix(value, " ^drop reject") || strings.HasSuffix(value, " ^drop rejectboth") {
		parts := strings.Split(value, " ^drop ")
		value = strings.Trim(parts[0], "'\"")
	}
	if strings.HasPrefix(value, "re:msg:\"") {
		value = "msg:" + strings.TrimPrefix(value, "re:msg:\"")
	}
	if strings.HasPrefix(value, "re:") {
		return value
	}
	result, _ := canonicalSelector(value)
	return result
}
func selectorMarker(value string) string {
	return " # ips-web-selector-b64=" + base64.URLEncoding.EncodeToString([]byte(value))
}
func selectorConfig(value string) string {
	kind, code, _ := strings.Cut(value, ":")
	if kind == "sid" {
		if id, err := identity(code); err == nil && id.GID == 1 {
			return strconv.FormatInt(id.SID, 10)
		}
	}
	if kind == "msg" {
		var pattern strings.Builder
		for _, c := range code {
			switch c {
			case '*':
				pattern.WriteString(".*")
			case '?':
				pattern.WriteByte('.')
			default:
				pattern.WriteString(regexp.QuoteMeta(string(c)))
			}
		}
		return "re:msg:\"" + pattern.String()
	}
	return value
}
func configured(path string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, line := range readLines(path) {
		if strings.HasPrefix(strings.TrimSpace(line), "#") || strings.TrimSpace(line) == "" {
			continue
		}
		value := selectorFromLine(line)
		if value != "" && !seen[value] {
			out = append(out, value)
			seen[value] = true
		}
	}
	return out
}

type RuleCatalog struct {
	mu          sync.Mutex
	pool        *Pool
	live, draft rulePaths
	signature   string
	rules       []*Rule
	groups      []Object
	byID        map[RuleID]*Rule
	ActiveRules string
}

func newRuleCatalog(pool *Pool, live, draft rulePaths) *RuleCatalog {
	return &RuleCatalog{pool: pool, live: live, draft: draft}
}
func (c *RuleCatalog) Invalidate() { c.mu.Lock(); c.signature = ""; c.mu.Unlock() }
func (c *RuleCatalog) Load(ctx context.Context) ([]*Rule, []Object, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	paths := []string{}
	for _, key := range []string{"LOCAL_RULES", "HUNT_RULES", "BAN_RULES"} {
		if p := c.draft.controls[key]; p != "" {
			paths = append(paths, p)
		}
	}
	active := map[string]bool{}
	primary := c.ActiveRules
	if primary == "" {
		primary = filepath.Join(c.live.Data, "rules/snort.rules")
	}
	for _, name := range []string{primary, c.live.controls["LOCAL_RULES"], c.live.controls["HUNT_RULES"], c.live.controls["BAN_RULES"]} {
		active[name] = true
		paths = append(paths, name)
	}
	for _, root := range []string{filepath.Join(c.live.Data, "rules"), c.live.Dist, c.live.Cache, c.draft.Sources} {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if errors.Is(err, os.ErrNotExist) && path == root {
				return nil
			}
			if err != nil {
				return err
			}
			if entry.Type()&os.ModeSymlink != 0 {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			if len(paths) > 10000 {
				return errors.New("特征目录文件过多")
			}
			if strings.HasSuffix(path, ".rules") || strings.HasSuffix(path, "-rules.tar.gz") || strings.HasSuffix(path, "sources.json") || strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".json") {
				paths = append(paths, path)
			}
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	}
	sort.Strings(paths)
	hash := sha256.New()
	for _, path := range []string{c.live.Config, c.live.officialSourcePath(), c.live.controls["DISABLE_CONF"], filepath.Join(enginePrefix(), "bin/snort")} {
		if info, err := os.Stat(path); err == nil {
			dev, ino := fileIdentity(info)
			fmt.Fprintf(hash, "policy:%s:%d:%d:%d:%d\n", path, dev, ino, info.Size(), info.ModTime().UnixNano())
		}
	}
	unique := []string{}
	last := ""
	for _, path := range paths {
		if path == last {
			continue
		}
		last = path
		unique = append(unique, path)
		if info, err := os.Stat(path); err == nil {
			fmt.Fprintf(hash, "%s:%d:%d\n", path, info.Size(), info.ModTime().UnixNano())
		}
	}
	signature := hex.EncodeToString(hash.Sum(nil))
	if signature == c.signature {
		return c.rules, c.groups, nil
	}
	type batch struct {
		lines            []string
		group, source    string
		enabled, managed bool
		active           bool
		members          map[RuleID][]string
	}
	jobs := []batch{}
	var official officialCatalog
	var identities map[string]Object
	readJSON(filepath.Join(c.live.Cache, "sources.json"), &identities)
	sources, _ := sourceDefinitions(c.draft.Sources)
	for _, path := range unique {
		if strings.HasSuffix(path, ".json") || strings.HasSuffix(path, ".yaml") {
			continue
		}
		if filepath.Dir(path) == filepath.Join(c.live.Cache, "derived") {
			continue // Included in the signature; loaded through its source archive.
		}
		archive := strings.HasSuffix(path, "-rules.tar.gz")
		limit := int64(128 << 20)
		if archive {
			limit = 256 << 20
		}
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
			continue
		} else if info.Size() > limit {
			return nil, nil, errors.New("特征目录输入超过容量限制")
		}
		source, enabled := "本地目录", true
		managed := false
		group := "local/" + strings.TrimSuffix(filepath.Base(path), ".rules")
		if strings.HasPrefix(path, c.live.Dist+string(filepath.Separator)) {
			source = "Snort"
			relative, _ := filepath.Rel(c.live.Dist, path)
			group = strings.TrimSuffix(filepath.ToSlash(relative), ".rules")
		} else if strings.HasPrefix(path, c.live.Cache+string(filepath.Separator)) {
			key := strings.SplitN(filepath.Base(path), "-", 2)[0]
			if i, ok := identities[key]; ok {
				source = text(i["source"])
				enabled = sourceEnabled(c.draft.Sources, source, sources)
			} else {
				source = "未知来源"
			}
			managed = true
		}
		files := map[string][]byte{}
		var members map[RuleID][]string
		if archive {
			if official.sources == nil {
				var err error
				official, err = c.live.officialSources()
				if err != nil {
					return nil, nil, err
				}
			}
			format := official.archiveFormat(source)
			key := strings.TrimSuffix(filepath.Base(path), "-rules.tar.gz")
			if raw, groups, ok := cachedCatalogRules(c.live.Cache, key, source, format); ok {
				files[filepath.Base(path)] = raw
				members = groups
			} else {
				paths := c.draft
				paths.Config = c.live.Config
				var err error
				files, err = catalogArchiveRules(path, format, paths)
				if err != nil {
					return nil, nil, err
				}
			}
		} else {
			data, err := regularRead(path, 128<<20)
			if err != nil {
				return nil, nil, err
			}
			files[filepath.Base(path)] = data
		}
		names := []string{}
		for name := range files {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			g := group
			if managed {
				g = strings.TrimSuffix(filepath.Base(name), ".rules")
			}
			text := strings.ReplaceAll(strings.ReplaceAll(string(files[name]), "\\\r\n", ""), "\\\n", "")
			lines := strings.Split(text, "\n")
			for i := 0; i < len(lines); i += 512 {
				jobs = append(jobs, batch{lines[i:min(i+512, len(lines))], g, source, enabled, managed, active[path], members})
			}
		}
	}
	type parsedBatch struct {
		records []*Rule
		active  bool
	}
	parsed, err := parallelMap(ctx, c.pool, jobs, func(b batch) (parsedBatch, error) {
		rows := []*Rule{}
		for _, line := range b.lines {
			if r := parseRule(line, b.group, b.source, b.enabled); r != nil {
				r.PolicyManaged = b.managed
				if b.members != nil {
					groups := b.members[r.ID]
					if len(groups) == 0 {
						return parsedBatch{}, errors.New("特征分组缓存缺少特征，请重新应用特征")
					}
					r.Group, r.Origins = groups[0], nil
					for _, group := range groups {
						r.Origins = append(r.Origins, Object{"group": group, "source": b.source})
					}
				}
				rows = append(rows, r)
			}
		}
		return parsedBatch{rows, b.active}, nil
	})
	if err != nil {
		return nil, nil, err
	}
	compiled := map[RuleID]*Rule{}
	for _, batch := range parsed {
		if batch.active {
			for _, row := range batch.records {
				if row.Enabled {
					compiled[row.ID] = row
				}
			}
		}
	}
	byID := map[RuleID]*Rule{}
	groupMembers := map[string]map[RuleID]*Rule{}
	for _, batch := range parsed {
		for _, row := range batch.records {
			if batch.active && row.Group == "local/snort" {
				continue
			}
			for _, origin := range row.Origins {
				key := text(origin["source"]) + "\x00" + text(origin["group"])
				if groupMembers[key] == nil {
					groupMembers[key] = map[RuleID]*Rule{}
				}
				groupMembers[key][row.ID] = row
			}
			old := byID[row.ID]
			if old == nil || (!old.SourceEnabled && row.SourceEnabled) {
				byID[row.ID] = row
			} else if old.SourceEnabled == row.SourceEnabled {
				for _, candidate := range row.Origins {
					known := false
					for _, origin := range old.Origins {
						known = known || origin["group"] == candidate["group"] && origin["source"] == candidate["source"]
					}
					if !known {
						old.Origins = append(old.Origins, candidate)
					}
				}
			}
		}
	}
	builtins, err := builtinRules(ctx, c.live.Config)
	if err != nil {
		return nil, nil, err
	}
	for _, row := range builtins {
		if selected := compiled[row.ID]; selected != nil {
			row.Action = selected.Action
		}
		byID[row.ID] = row
		disabled := false
		for _, s := range configured(c.live.controls["DISABLE_CONF"]) {
			if selectorMatches(s, row) {
				disabled = true
				break
			}
		}
		if !disabled {
			compiled[row.ID] = row
		}
		key := row.Source + "\x00" + row.Group
		if groupMembers[key] == nil {
			groupMembers[key] = map[RuleID]*Rule{}
		}
		groupMembers[key][row.ID] = row
	}
	for id, row := range compiled {
		if byID[id] == nil {
			byID[id] = row
		}
	}
	rows := []*Rule{}
	for id, row := range byID {
		active, ok := compiled[id]
		row.Enabled = ok
		if ok {
			row.Action = active.Action
			row.Message = active.Message
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].ID.GID != rows[j].ID.GID {
			return rows[i].ID.GID < rows[j].ID.GID
		}
		return rows[i].ID.SID < rows[j].ID.SID
	})
	groups := []Object{}
	for key, members := range groupMembers {
		source, name, _ := strings.Cut(key, "\x00")
		count, blockable := 0, 0
		managed, enabled := false, true
		for id, row := range members {
			managed = row.PolicyManaged
			enabled = row.SourceEnabled
			if _, ok := compiled[id]; ok {
				count++
				if enabled && !row.Builtin && !strings.Contains(row.Line, "; noalert;") {
					blockable++
				}
			}
		}
		groups = append(groups, Object{"name": name, "label": strings.TrimPrefix(name, "local/"), "source": source, "selector": groupSelector(name, source), "source_enabled": enabled, "total": len(members), "compiled": count, "blockable": blockable, "policy_managed": managed, "builtin": source == "Snort 内置"})
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i]["name"] == groups[j]["name"] {
			return text(groups[i]["source"]) < text(groups[j]["source"])
		}
		return text(groups[i]["name"]) < text(groups[j]["name"])
	})
	c.signature, c.rules, c.groups, c.byID = signature, rows, groups, byID
	return rows, groups, nil
}
func (c *RuleCatalog) Search(ctx context.Context, params Object, selector string) (Object, error) {
	rows, groups, err := c.Load(ctx)
	if err != nil {
		return nil, err
	}
	q := strings.TrimSpace(text(present(params["q"], params["query"])))
	limit := bounded(int(integer(get(params, "limit", 50))), 1, 200)
	offset := max(0, int(integer(params["offset"])))
	exclude := text(params["exclude"])
	if exclude != "" && exclude != "disable" && exclude != "action" && exclude != "suppress" {
		return nil, errors.New("无效操作类型")
	}
	configuredValues := []string{}
	switch exclude {
	case "disable":
		configuredValues = configured(c.draft.controls["DISABLE_CONF"])
	case "action":
		configuredValues = configured(c.draft.controls["DROP_CONF"])
		configuredValues = append(configuredValues, actionSelectors(c.draft)...)
	case "suppress":
		for _, row := range suppressions(c.draft) {
			r := Rule{ID: RuleID{integer(row["gid"]), integer(row["sid"])}}
			configuredValues = append(configuredValues, r.selector())
		}
	}
	if selector != "" {
		selector, err = canonicalSelector(selector)
		if err != nil {
			return nil, err
		}
	}
	out := []Object{}
	total := 0
	for i := len(rows) - 1; i >= 0; i-- {
		r := rows[i]
		if !r.SourceEnabled {
			continue
		}
		if selector != "" && !selectorMatches(selector, r) {
			continue
		}
		if source := text(params["source"]); source != "" {
			found := false
			for _, origin := range r.Origins {
				if origin["source"] == source {
					found = true
				}
			}
			if !found {
				continue
			}
		}
		needle := strings.ToLower(strings.TrimPrefix(q, "sid:"))
		if needle != "" {
			if id, e := identity(needle); e == nil {
				if id != r.ID {
					continue
				}
			} else if !strings.Contains(strings.ToLower(fmt.Sprintf("%d:%d %s %s %s %s", r.ID.GID, r.ID.SID, r.Message, r.Line, r.Source, r.Group)), needle) {
				continue
			}
		}
		if exclude == "action" && (r.Builtin || !r.PolicyManaged || strings.Contains(r.Line, "; noalert;")) {
			continue
		}
		hidden := false
		for _, value := range configuredValues {
			if selectorMatches(value, r) && value != text(params["include"]) {
				hidden = true
				break
			}
		}
		if hidden {
			continue
		}
		if total >= offset && len(out) < limit {
			out = append(out, r.JSON())
		}
		total++
	}
	result := Object{"total": total, "rules": out, "offset": offset, "limit": limit}
	if selector != "" {
		result["selector"] = selector
	}
	if q == "" {
		names := []string{}
		labels, search := Object{}, Object{}
		for _, g := range groups {
			if g["source_enabled"] == false {
				continue
			}
			name := text(g["name"])
			names = append(names, name)
			labels[name] = g["label"]
			search[name] = name + " " + text(g["label"]) + " " + text(g["source"])
		}
		result["groups"] = names
		result["group_rows"] = groups
		result["group_labels"] = labels
		result["group_search"] = search
	}
	return result, nil
}
func suppressions(p rulePaths) []Object {
	out := []Object{}
	expression := regexp.MustCompile(`^suppress\s+gen_id\s+(\d+)\s*,\s*sig_id\s+(\d+)`)
	for _, line := range readLines(p.controls["THRESHOLD_CONF"]) {
		pending := strings.HasPrefix(line, "# ips-web-pending-suppress ")
		line = suppressionText(line)
		if m := expression.FindStringSubmatch(strings.TrimSpace(line)); len(m) == 3 {
			gid, _ := strconv.ParseInt(m[1], 10, 64)
			sid, _ := strconv.ParseInt(m[2], 10, 64)
			row := Object{"gid": gid, "sid": sid, "line": line, "name": fmt.Sprintf("%d:%d", gid, sid)}
			if pending {
				row["pending"] = true
			}
			out = append(out, row)
		}
	}
	return out
}
func actionSelectors(p rulePaths) []string {
	out := []string{}
	for _, line := range readLines(p.controls["ACTION_CONF"]) {
		parts := strings.SplitN(strings.TrimSpace(line), " ", 2)
		if len(parts) == 2 && !strings.HasPrefix(parts[0], "#") {
			if selector, err := canonicalSelector(parts[1]); err == nil {
				out = append(out, selector)
			}
		}
	}
	return out
}
func governance(p rulePaths) Object {
	disabled, dropped, actions, groupRows := []Object{}, []Object{}, []Object{}, []Object{}
	rejected := configured(p.controls["MODIFY_CONF"])
	rejectSet := map[string]bool{}
	for _, value := range rejected {
		rejectSet[value] = true
	}
	for _, value := range configured(p.controls["DISABLE_CONF"]) {
		disabled = append(disabled, Object{"value": value, "name": value})
	}
	for _, value := range configured(p.controls["DROP_CONF"]) {
		dropped = append(dropped, Object{"value": value, "name": value, "reject": rejectSet[value]})
	}
	for _, line := range readLines(p.controls["ACTION_CONF"]) {
		parts := strings.SplitN(strings.TrimSpace(line), " ", 2)
		if len(parts) != 2 || strings.HasPrefix(parts[0], "#") {
			continue
		}
		if selector, err := canonicalSelector(parts[1]); err == nil {
			actions = append(actions, Object{"action": parts[0], "selector": selector, "name": selector})
		}
	}
	var groups []string
	readJSON(p.groupsFile(), &groups)
	for _, selector := range groups {
		source, name, err := parseGroup(selector)
		if err != nil {
			continue
		}
		if source == "" {
			source = "全部来源"
		}
		groupRows = append(groupRows, Object{"selector": selector, "name": name, "source": source, "total": 0})
	}
	return Object{"suppress": suppressions(p), "suppress_groups": groupRows, "disable": disabled, "drop": dropped, "reject": rejected, "action": actions}
}
func manualRules(p rulePaths) []Object {
	out := []Object{}
	for _, line := range readLines(p.controls["HUNT_RULES"]) {
		if r := parseRule(line, "local/ips-web-hunting", "本地目录", true); r != nil {
			row := r.JSON()
			row["rule"] = r.Line
			out = append(out, row)
		}
	}
	return out
}
func loadBans(p rulePaths) []Object {
	var rows []Object
	if readJSON(p.controls["BAN_STORE"], &rows) != nil {
		return []Object{}
	}
	return rows
}
func validateManualRule(line string) error {
	if len(line) == 0 || len(line) > 4096 || strings.ContainsAny(line, "\r\n\x00") {
		return errors.New("特征必须为单行且不超过 4096 字节")
	}
	trimmed := strings.TrimSpace(line)
	if !ruleAction.MatchString(trimmed) || !strings.HasSuffix(trimmed, ")") || !strings.Contains(trimmed, "(") {
		return errors.New("特征结构无效")
	}
	quoted, escaped := false, false
	depth := 0
	for _, c := range trimmed {
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == '"' {
			quoted = !quoted
		}
		if !quoted {
			if c == '(' {
				depth++
			}
			if c == ')' {
				depth--
				if depth < 0 {
					return errors.New("特征括号无效")
				}
			}
		}
	}
	if quoted || depth != 0 {
		return errors.New("特征引号或括号未闭合")
	}
	return nil
}
func appendPrivateLine(path, line string) error {
	existing := readText(path)
	return atomicWrite(path, []byte(strings.TrimRight(existing, "\r\n")+"\n"+line+"\n"), 0600)
}
func saveSelectors(path string, values []string, modify bool) error {
	lines := []string{}
	seen := map[string]bool{}
	for _, selector := range values {
		if seen[selector] {
			continue
		}
		seen[selector] = true
		line := selectorConfig(selector)
		if modify {
			line = strconv.Quote(line) + " ^drop reject"
		}
		lines = append(lines, line+selectorMarker(selector))
	}
	return atomicWrite(path, []byte(strings.Join(lines, "\n")+"\n"), 0600)
}
func parseBan(value string) (Object, error) {
	value = strings.TrimRight(strings.ToLower(strings.Trim(strings.TrimSpace(value), "[]")), ".")
	if ip, err := netip.ParseAddr(value); err == nil {
		return Object{"type": "ip", "value": ip.String()}, nil
	}
	if len(value) > 253 || !strings.Contains(value, ".") || !regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$`).MatchString(value) {
		return nil, errors.New("IP 地址或域名无效")
	}
	return Object{"type": "domain", "value": value}, nil
}
func domainApp(domain string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(domain)))
	return "ipsweb-domain-" + hex.EncodeToString(digest[:])[:24]
}
func renderBans(entries []Object) (string, string, error) {
	lines := []string{"# 由 ips-web 生成的封禁规则"}
	detector := []string{"DetectorPackageInfo = {name='ips-web-bans', proto=6, client={init='DetectorInit', clean='DetectorClean', minimum_matches=1}}", "function DetectorInit(detector)"}
	sid := 9100000
	for _, entry := range entries {
		value := text(entry["value"])
		valid, err := parseBan(value)
		if err != nil {
			return "", "", err
		}
		if valid["type"] == "ip" {
			lines = append(lines, "# ip "+value, fmt.Sprintf("block ip any any <> %s any (msg:\"ips-web ban %s\"; sid:%d; rev:1;)", value, value, sid))
			sid++
			continue
		}
		if !domainPattern.MatchString(value) {
			return "", "", errors.New("域名无法生成内容检测器")
		}
		lines = append(lines, "# domain "+value, fmt.Sprintf("block ip any any -> any any (msg:\"ips-web ban domain %s\"; appids:\"%s\"; sid:%d; rev:1;)", value, domainApp(value), sid))
		sid += 2
		pattern := strings.ReplaceAll(regexp.QuoteMeta(value), "/", `\/`)
		lines = append(lines, fmt.Sprintf("block http any any -> any any (msg:\"ips-web ban HTTP domain %s\"; http_header:field host; pcre:\"/(?:^|\\.)%s(?::[0-9]+)?$/i\"; sid:%d; rev:1;)", value, pattern, sid))
		sid += 2
		wire := ""
		for _, label := range strings.Split(value, ".") {
			if len(label) > 63 {
				return "", "", errors.New("域名标签过长")
			}
			wire += fmt.Sprintf("|%02x|%s", len(label), label)
		}
		wire += "|00|"
		lines = append(lines, fmt.Sprintf("block dns any any -> any any (msg:\"ips-web ban DNS domain %s\"; flow:to_server; content:\"%s\",nocase; sid:%d; rev:1;)", value, wire, sid))
		sid += 2
		for _, raw := range array(entry["ips"]) {
			ip, err := netip.ParseAddr(text(raw))
			if err != nil {
				return "", "", err
			}
			lines = append(lines, fmt.Sprintf("block ip any any <> %s any (msg:\"ips-web ban %s (%s)\"; sid:%d; rev:1;)", ip.String(), value, ip.String(), sid))
			sid++
		}
		detector = append(detector, " local app = detector:open_createApp("+strconv.Quote(domainApp(value))+")", " detector:addSSLCertPattern(0, app, "+strconv.Quote(value)+")", " detector:addDNSHostPattern(0, app, "+strconv.Quote(value)+")")
	}
	detector = append(detector, " return detector", "end", "function DetectorClean() end")
	return strings.Join(lines, "\n") + "\n", strings.Join(detector, "\n") + "\n", nil
}
func saveBans(p rulePaths, entries []Object) error {
	rules, detector, err := renderBans(entries)
	if err != nil {
		return err
	}
	if err = writeJSON(p.controls["BAN_STORE"], entries); err != nil {
		return err
	}
	if err = atomicWrite(p.controls["BAN_RULES"], []byte(rules), 0600); err != nil {
		return err
	}
	return atomicWrite(p.controls["BAN_DETECTOR"], []byte(detector), 0600)
}
func resolveDomain(ctx context.Context, domain string) []string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", domain)
	if err != nil {
		return []string{}
	}
	out := []string{}
	seen := map[string]bool{}
	for _, ip := range addresses {
		if !seen[ip.String()] {
			seen[ip.String()] = true
			out = append(out, ip.String())
		}
	}
	sort.Strings(out)
	return out
}

var _ = bufio.ErrInvalidUnreadByte
