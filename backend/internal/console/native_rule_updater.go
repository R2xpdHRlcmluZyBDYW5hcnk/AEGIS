package console

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const nativeRuleParserVersion = "native-go-4"

// The native updater belongs to AEGIS. It reads published Snort archive formats
// directly and never installs, executes or changes an external PulledPork tree.
func (s officialSource) downloadURL(snapshot, oinkcode string) (string, error) {
	address := s.ArchiveURL
	if s.Format == registeredArchive {
		if !sourceVersion.MatchString(snapshot) || snapshot == "auto" {
			return "", errors.New("Registered 特征快照无效")
		}
		address = strings.Replace(address, "{snapshot}", strings.ReplaceAll(snapshot, ".", ""), 1)
	}
	if s.RequiresOinkcode {
		if !oinkPattern.MatchString(oinkcode) {
			return "", errors.New("此特征来源需要有效 Oinkcode")
		}
		u, _ := url.Parse(address)
		q := u.Query()
		q.Set("oinkcode", oinkcode)
		u.RawQuery = q.Encode()
		address = u.String()
	}
	return address, nil
}

type ruleFetcher func(context.Context, string, int64) ([]byte, error)

func downloadOfficialRules(ctx context.Context, source officialSource, snapshot, oinkcode string, fetch ruleFetcher) ([]byte, error) {
	address, err := source.downloadURL(snapshot, oinkcode)
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(address)
	u.Path += ".md5"
	checksumURL := u.String()
	for attempt := 0; attempt < 3; attempt++ {
		var archive, digest []byte
		var e1, e2 error
		if WorkerCount() > 1 {
			done := make(chan struct{})
			go func() { digest, e2 = fetch(ctx, checksumURL, 4096); close(done) }()
			archive, e1 = fetch(ctx, address, 256<<20)
			<-done
		} else {
			digest, e2 = fetch(ctx, checksumURL, 4096)
			if e2 == nil {
				archive, e1 = fetch(ctx, address, 256<<20)
			}
		}
		if e1 != nil || e2 != nil {
			return nil, errors.New("官方特征下载失败，请检查网络和授权")
		}
		expected := regexp.MustCompile(`\b[0-9a-fA-F]{32}\b`).Find(digest)
		if len(expected) != 32 {
			return nil, errors.New("官方特征摘要响应无效")
		}
		hash := md5.Sum(archive)
		if strings.EqualFold(hex.EncodeToString(hash[:]), string(expected)) {
			return archive, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, errors.New("官方特征摘要与归档不一致，活动特征已保留")
}

func readRuleBundle(filename string) (map[string][]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	files := map[string][]byte{}
	seen := map[string]bool{}
	var total, retained int64
	count := 0
	for {
		entry, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		count++
		total += entry.Size
		name := path.Clean(entry.Name)
		if entry.Size < 0 || entry.Size > 256<<20 || total > 512<<20 || count > 100000 || strings.HasPrefix(name, "/") || name == ".." || strings.HasPrefix(name, "../") || strings.Contains(entry.Name, "\\") || (entry.Typeflag != tar.TypeDir && entry.Typeflag != tar.TypeReg) {
			return nil, errors.New("特征归档包含不安全成员或超过限制")
		}
		if seen[name] {
			return nil, errors.New("特征归档包含重复成员")
		}
		seen[name] = true
		if entry.Typeflag != tar.TypeReg || !(strings.HasSuffix(name, ".rules") || strings.HasSuffix(name, ".states") || path.Base(name) == "manifest.json") {
			continue
		}
		if retained+entry.Size > 256<<20 {
			return nil, errors.New("特征文本超过内存预算")
		}
		data, err := io.ReadAll(io.LimitReader(reader, entry.Size+1))
		if err != nil || int64(len(data)) != entry.Size {
			return nil, errors.New("特征归档不完整")
		}
		files[name] = data
		retained += entry.Size
	}
	return files, nil
}

func normalizedVersion(value string) []int {
	value = strings.SplitN(value, "-", 2)[0]
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return nil
	}
	out := []int{}
	for _, part := range parts {
		v, err := strconv.Atoi(part)
		if err != nil || v < 0 {
			return nil
		}
		out = append(out, v)
	}
	return out
}
func versionCompare(a, b string) int {
	x, y := normalizedVersion(a), normalizedVersion(b)
	if len(x) != 4 || len(y) != 4 {
		return -1
	}
	for i := range x {
		if x[i] < y[i] {
			return -1
		}
		if x[i] > y[i] {
			return 1
		}
	}
	return 0
}
func compatibleBundleVersions(files map[string][]byte, root, engine string) []string {
	versions := map[string]bool{}
	for name := range files {
		relative, ok := strings.CutPrefix(name, root+"/")
		if !ok {
			continue
		}
		candidate := strings.SplitN(relative, "/", 2)[0]
		if len(normalizedVersion(candidate)) == 4 && versionCompare(candidate, engine) <= 0 {
			versions[candidate] = true
		}
	}
	out := make([]string, 0, len(versions))
	for version := range versions {
		out = append(out, version)
	}
	sort.Slice(out, func(i, j int) bool { return bundleVersionLess(out[i], out[j]) })
	return out
}

func bundleVersionLess(a, b string) bool {
	if order := versionCompare(a, b); order != 0 {
		return order < 0
	}
	_, buildA, _ := strings.Cut(a, "-")
	_, buildB, _ := strings.Cut(b, "-")
	x, errA := strconv.ParseUint(buildA, 10, 64)
	y, errB := strconv.ParseUint(buildB, 10, 64)
	class := func(build string, err error) int {
		if build == "" {
			return 0
		}
		if err == nil {
			return 1
		}
		return 2
	}
	if classA, classB := class(buildA, errA), class(buildB, errB); classA != classB {
		return classA < classB
	}
	if errA == nil && errB == nil && x != y {
		return x < y
	}
	return a < b
}

// LightSPD directories are a base plus cumulative minimum-version deltas.
// In particular, 3.1.24 must override 3.1.7, regardless of lexical path order.
func sortBundleNames(names []string) {
	version := func(name string) string {
		parts := strings.Split(name, "/")
		if len(parts) >= 4 && parts[0] == "lightspd" && (parts[1] == "rules" || parts[1] == "builtins") && len(normalizedVersion(parts[2])) == 4 {
			return parts[2]
		}
		return ""
	}
	sort.Slice(names, func(i, j int) bool {
		a, b := version(names[i]), version(names[j])
		if (a == "") != (b == "") {
			return a != ""
		}
		if a != "" && a != b {
			return bundleVersionLess(a, b)
		}
		return names[i] < names[j]
	})
}

func ruleBundleSelection(files map[string][]byte, format ruleArchiveFormat, engine, policy string) (map[string][]byte, map[string][]byte, error) {
	rules, states := map[string][]byte{}, map[string][]byte{}
	if !validIPSPolicy(policy) {
		return nil, nil, errors.New("IPS 策略无效")
	}
	roots := []string{}
	switch format {
	case registeredArchive:
		roots = []string{"rules/", "builtins/"}
	case lightSPDArchive:
		for _, kind := range []string{"rules", "builtins"} {
			root := "lightspd/" + kind
			for _, v := range compatibleBundleVersions(files, root, engine) {
				if _, ok := files[root+"/"+v+"/rulestates-"+policy+"-ips.states"]; !ok {
					return nil, nil, fmt.Errorf("特征归档缺少所选 IPS 策略 (%s/%s)", root, v)
				}
				roots = append(roots, root+"/"+v+"/")
			}
		}
		if len(roots) == 0 {
			return nil, nil, errors.New("LightSPD 没有兼容当前引擎的文本特征")
		}
		if data, ok := files["lightspd/manifest.json"]; ok {
			var manifest Object
			if decode(data, &manifest) != nil {
				return nil, nil, errors.New("LightSPD manifest 无效")
			}
			versions := object(manifest["snort versions"])
			best := ""
			for version := range versions {
				if len(normalizedVersion(version)) == 4 && versionCompare(version, engine) <= 0 && (best == "" || versionCompare(version, best) > 0) {
					best = version
				}
			}
			if best != "" {
				p := text(object(versions[best])["policies_path"])
				if p != "" {
					p = path.Clean(p)
					if p == ".." || strings.HasPrefix(p, "../") || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") {
						return nil, nil, errors.New("LightSPD 策略路径无效")
					}
					if !strings.HasPrefix(p, "lightspd/") {
						p = "lightspd/" + p
					}
					roots = append(roots, p+"/")
				}
			}
		}
	default: // Community and administrator-defined text sources.
		for name, data := range files {
			if strings.HasSuffix(name, ".rules") && path.Base(name) != "includes.rules" && path.Base(name) != "snort3-deleted.rules" {
				rules[name] = data
			}
		}
		return rules, states, nil
	}
	for name, data := range files {
		selected := false
		for _, root := range roots {
			selected = selected || strings.HasPrefix(name, root)
		}
		if !selected {
			continue
		}
		base := path.Base(name)
		if strings.HasSuffix(name, ".rules") && base != "includes.rules" && base != "snort3-deleted.rules" {
			rules[name] = data
		}
		if base == "rulestates-"+policy+"-ips.states" {
			states[name] = data
		}
	}
	if len(states) == 0 {
		return nil, nil, errors.New("特征归档缺少所选 IPS 策略")
	}
	return rules, states, nil
}

var policyState = regexp.MustCompile(`(?i)^\s*(alert|block|drop|reject[a-z]*|pass|react|rewrite|log)\s*\(\s*gid\s*:\s*([0-9]+)\s*;\s*sid\s*:\s*([0-9]+)\s*;\s*(enable|disable)(?:\s*:\s*(yes|no))?\s*;?\s*\)\s*(?:#.*)?$`)

type rulePolicyState struct {
	action  string
	enabled bool
}

func parseRulePolicyState(line string) (RuleID, rulePolicyState, bool) {
	m := policyState.FindStringSubmatch(strings.TrimPrefix(line, "\uFEFF"))
	if len(m) == 0 {
		return RuleID{}, rulePolicyState{}, false
	}
	gid, errGID := strconv.ParseInt(m[2], 10, 64)
	sid, errSID := strconv.ParseInt(m[3], 10, 64)
	if errGID != nil || errSID != nil || gid < 1 || gid > 8129 || sid < 1 || sid > 4294967295 {
		return RuleID{}, rulePolicyState{}, false
	}
	return RuleID{gid, sid}, rulePolicyState{
		action: strings.ToLower(m[1]), enabled: strings.EqualFold(m[4], "enable") != strings.EqualFold(m[5], "no"),
	}, true
}

var ruleRevision = regexp.MustCompile(`\brev\s*:\s*([0-9]+)`)
var flowbitOption = regexp.MustCompile(`\bflowbits\s*:\s*(set|setx|toggle|isset|isnotset)\s*,\s*([^;]+);`)

func compileRuleBundle(ctx context.Context, files map[string][]byte, format ruleArchiveFormat, engine, policy string, pool *Pool) ([]byte, map[string][]string, error) {
	selected, states, err := ruleBundleSelection(files, format, engine, policy)
	if err != nil {
		return nil, nil, err
	}
	policyIDs := map[RuleID]rulePolicyState{}
	stateNames := []string{}
	for name := range states {
		stateNames = append(stateNames, name)
	}
	sortBundleNames(stateNames)
	for _, name := range stateNames {
		for lineNumber, line := range strings.Split(string(states[name]), "\n") {
			s := strings.TrimSpace(strings.TrimPrefix(line, "\uFEFF"))
			if s == "" || strings.HasPrefix(s, "#") {
				continue
			}
			id, state, ok := parseRulePolicyState(s)
			if !ok {
				return nil, nil, fmt.Errorf("特征策略行无法解析 (%s:%d)", name, lineNumber+1)
			}
			policyIDs[id] = state
		}
	}
	type chunk struct{ name, text string }
	chunks := []chunk{}
	names := []string{}
	for name := range selected {
		names = append(names, name)
	}
	sortBundleNames(names)
	for _, name := range names {
		raw := strings.ReplaceAll(strings.ReplaceAll(string(selected[name]), "\\\r\n", ""), "\\\n", "")
		lines := strings.Split(raw, "\n")
		for i := 0; i < len(lines); i += 512 {
			chunks = append(chunks, chunk{name, strings.Join(lines[i:min(i+512, len(lines))], "\n")})
		}
	}
	parsed, err := parallelMap(ctx, pool, chunks, func(item chunk) ([]*Rule, error) {
		out := []*Rule{}
		for _, line := range strings.Split(item.text, "\n") {
			line = strings.TrimSpace(line)
			r := parseRule(line, strings.TrimSuffix(path.Base(item.name), ".rules"), "", true)
			if r != nil {
				out = append(out, r)
			}
		}
		return out, nil
	})
	if err != nil {
		return nil, nil, err
	}
	rows := map[RuleID]*Rule{}
	revision := func(r *Rule) int64 {
		m := ruleRevision.FindStringSubmatch(r.Line)
		if len(m) != 2 {
			return 0
		}
		return integer(m[1])
	}
	for _, batch := range parsed {
		for _, r := range batch {
			if old := rows[r.ID]; old == nil || revision(r) >= revision(old) {
				if len(states) > 0 {
					state, found := policyIDs[r.ID]
					r.Enabled = state.enabled
					if found {
						r.Line = state.action + strings.TrimPrefix(r.Line, r.Action)
						r.Action = state.action
					}
				}
				rows[r.ID] = r
			}
		}
	}
	// Flowbit state setters required by selected rules must remain loadable.
	// User disable/action policies run afterwards and keep their existing priority.
	setters := map[string][]*Rule{}
	checks := map[RuleID][]string{}
	for _, r := range rows {
		for _, m := range flowbitOption.FindAllStringSubmatch(r.Line, -1) {
			bits := strings.FieldsFunc(strings.SplitN(m[2], ",", 2)[0], func(c rune) bool { return c == '&' || c == '|' || c == ' ' })
			if m[1] == "isset" || m[1] == "isnotset" {
				checks[r.ID] = append(checks[r.ID], bits...)
			} else {
				for _, bit := range bits {
					setters[bit] = append(setters[bit], r)
				}
			}
		}
	}
	pending := []*Rule{}
	for _, r := range rows {
		if r.Enabled {
			pending = append(pending, r)
		}
	}
	for i := 0; i < len(pending); i++ {
		for _, bit := range checks[pending[i].ID] {
			for _, setter := range setters[bit] {
				if !setter.Enabled {
					setter.Enabled = true
					setter.Line = "alert" + strings.TrimPrefix(setter.Line, setter.Action)
					setter.Action = "alert"
					if !strings.Contains(setter.Line, "flowbits:noalert;") {
						setter.Line = strings.TrimSuffix(strings.TrimSpace(setter.Line), ")") + " flowbits:noalert;)"
					}
					pending = append(pending, setter)
				}
			}
		}
	}
	ids := []RuleID{}
	for id := range rows {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if ids[i].GID == ids[j].GID {
			return ids[i].SID < ids[j].SID
		}
		return ids[i].GID < ids[j].GID
	})
	var output strings.Builder
	for _, id := range ids {
		r := rows[id]
		// Snort has already loaded these builtins when enable_builtin_rules is
		// set. An enable option makes the stub a state override rather than a
		// duplicate rule declaration with a conflicting action.
		if r.Group == "builtins" && strings.HasPrefix(strings.TrimSpace(strings.TrimPrefix(r.Line, r.Action)), "(") {
			r.Line = strings.TrimSuffix(strings.TrimSpace(r.Line), ")") + " enable;)"
		}
		if !r.Enabled {
			output.WriteString("# ")
		}
		output.WriteString(r.Line)
		output.WriteByte('\n')
	}
	if len(rows) == 0 {
		return nil, nil, errors.New("候选集中没有可用的文本特征")
	}
	return []byte(output.String()), groupTokens(selected), nil
}
