package console

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

func digestFile(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func rulesArchive(files map[string][]byte) ([]byte, error) {
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	names := []string{}
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		data := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
func validCustomText(data []byte) ([]byte, error) {
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	if !utf8.Valid(data) {
		return nil, errors.New("签名文本必须是 UTF-8")
	}
	s := strings.ReplaceAll(strings.ReplaceAll(string(data), "\\\r\n", ""), "\\\n", "")
	for _, line := range strings.Split(s, "\n") {
		v := strings.TrimSpace(line)
		if v != "" && !strings.HasPrefix(v, "#") && !ruleAction.MatchString(v) {
			return nil, errors.New("自定义源只接受 Snort 文本签名，不支持配置指令")
		}
	}
	return data, nil
}
func customRuleFiles(filename string) (map[string][]byte, error) {
	f, e := os.Open(filename)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	gz, e := gzip.NewReader(f)
	if e != nil {
		return nil, e
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	total, count := int64(0), 0
	files := map[string][]byte{}
	for {
		entry, e := reader.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		count++
		parts := strings.Split(entry.Name, "/")
		unsafe := strings.Contains(entry.Name, "\\") || strings.HasPrefix(entry.Name, "/")
		for _, p := range parts {
			unsafe = unsafe || p == ".."
		}
		if unsafe || (entry.Typeflag != tar.TypeReg && entry.Typeflag != tar.TypeDir) || entry.Size < 0 {
			return nil, errors.New("自定义签名归档包含不安全成员")
		}
		total += entry.Size
		if count > 10000 || total > 64<<20 {
			return nil, errors.New("自定义签名归档超过限制")
		}
		if entry.Typeflag == tar.TypeReg && strings.HasSuffix(entry.Name, ".rules") {
			name := path.Clean(entry.Name)
			if _, ok := files[name]; ok {
				return nil, errors.New("归档包含重复签名文件")
			}
			data, e := io.ReadAll(io.LimitReader(reader, entry.Size+1))
			if e != nil {
				return nil, e
			}
			data, e = validCustomText(data)
			if e != nil {
				return nil, e
			}
			files[name] = data
		}
	}
	if len(files) == 0 {
		return nil, errors.New("自定义归档中没有签名文件")
	}
	return files, nil
}
func downloadCustom(ctx context.Context, item Object, archive, receipt string) error {
	data, err := fetchDownload(ctx, text(item["url"]), 64<<20, text(item["token"]), false)
	if err != nil {
		return err
	}
	if item["format"] == "rules" {
		data, err = validCustomText(data)
		if err == nil {
			data, err = rulesArchive(map[string][]byte{strings.ReplaceAll(text(item["name"]), "/", "-") + ".rules": data})
		}
		if err != nil {
			return err
		}
	}
	pending, err := os.CreateTemp(filepath.Dir(archive), ".custom-")
	if err != nil {
		return err
	}
	name := pending.Name()
	defer os.Remove(name)
	if err = pending.Chmod(0600); err == nil {
		_, err = pending.Write(data)
	}
	if err == nil {
		err = pending.Sync()
	}
	closeErr := pending.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if _, err = customRuleFiles(name); err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	if err = os.Rename(name, archive); err != nil {
		return err
	}
	return writeJSON(receipt, Object{"source": item["name"], "sha256": hex.EncodeToString(digest[:]), "updater": "AEGIS Go", "definition": definitionDigest(item)})
}
func groupTokens(files map[string][]byte) map[string][]string {
	members := map[string]map[string]bool{}
	for name, data := range files {
		group := strings.TrimSuffix(path.Base(name), ".rules")
		s := strings.ReplaceAll(strings.ReplaceAll(string(data), "\\\r\n", ""), "\\\n", "")
		for _, line := range strings.Split(s, "\n") {
			r := parseRule(line, "", "", true)
			if r == nil {
				continue
			}
			key := strconv.FormatInt(r.ID.SID, 10)
			if r.ID.GID != 1 {
				key = fmt.Sprintf("%d:%d", r.ID.GID, r.ID.SID)
			}
			if members[key] == nil {
				members[key] = map[string]bool{}
			}
			members[key][group] = true
		}
	}
	out := map[string][]string{}
	for key, items := range members {
		groups := []string{}
		for group := range items {
			groups = append(groups, group)
		}
		sort.Strings(groups)
		out[key] = groups
	}
	return out
}
func applyRulePolicy(ctx context.Context, raw string, p rulePaths, groups map[string][]string, source string, pool *Pool) (string, error) {
	disabled, dropped, rejected := configured(p.controls["DISABLE_CONF"]), configured(p.controls["DROP_CONF"]), configured(p.controls["MODIFY_CONF"])
	for _, selectors := range [][]string{disabled, dropped, rejected} {
		for _, selector := range selectors {
			if _, err := canonicalSelector(selector); err != nil {
				return "", err
			}
		}
	}
	overrides := []Object{}
	for _, line := range readLines(p.controls["ACTION_CONF"]) {
		action, selector, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok || strings.HasPrefix(action, "#") {
			continue
		}
		if action != "drop" && action != "block" && action != "reject" {
			return "", errors.New("签名动作配置无效")
		}
		overrides = append(overrides, Object{"action": action, "selector": selector})
	}
	lines := strings.Split(raw, "\n")
	chunks := [][]string{}
	for i := 0; i < len(lines); i += 512 {
		chunks = append(chunks, lines[i:min(i+512, len(lines))])
	}
	out, err := parallelMap(ctx, pool, chunks, func(lines []string) (string, error) {
		result := []string{}
		for _, line := range lines {
			r := parseRule(line, "", source, true)
			if r == nil || !r.Enabled {
				result = append(result, line)
				continue
			}
			key := strconv.FormatInt(r.ID.SID, 10)
			if r.ID.GID != 1 {
				key = fmt.Sprintf("%d:%d", r.ID.GID, r.ID.SID)
			}
			r.Origins = nil
			for _, group := range groups[key] {
				r.Origins = append(r.Origins, Object{"group": group, "source": source})
			}
			matches := func(selectors []string) bool {
				for _, selector := range selectors {
					if selectorMatches(selector, r) {
						return true
					}
				}
				return false
			}
			if matches(disabled) {
				result = append(result, "# "+line)
				continue
			}
			action := r.Action
			if !strings.Contains(line, "noalert;") {
				if matches(dropped) {
					action = "block"
				}
				if matches(rejected) {
					action = "reject"
				}
				for _, override := range overrides {
					if selectorMatches(text(override["selector"]), r) {
						action = text(override["action"])
						if action == "drop" {
							action = "block"
						}
						break
					}
				}
			}
			if action != r.Action {
				line = action + strings.TrimPrefix(line, r.Action)
			}
			result = append(result, line)
		}
		return strings.Join(result, "\n"), nil
	})
	if err != nil {
		return "", err
	}
	return strings.Join(out, "\n"), nil
}
func updateRuleSource(ctx context.Context, p rulePaths, source string, settings Object, offline bool, custom Object, pool *Pool, log func(string)) (string, error) {
	log("处理签名来源 " + source)
	key := sourceKey(source)
	archive, receipt := filepath.Join(p.Cache, key+"-rules.tar.gz"), filepath.Join(p.Cache, key+"-receipt.json")
	base := filepath.Join(p.Cache, "derived", key+".rules")
	metadata := strings.TrimSuffix(base, ".rules") + ".json"
	snapshot, definition := "", ""
	if source == "snort/registered" {
		snapshot = registeredSnapshot(text(settings["registered_version"]))
	}
	if custom != nil {
		definition = definitionDigest(custom)
		if !offline {
			if err := downloadCustom(ctx, custom, archive, receipt); err != nil {
				return "", err
			}
		}
	}
	recipe := Object{"source": source, "policy": get(settings, "ips_policy", "balanced"), "snapshot": snapshot, "definition": definition, "parser": nativeRuleParserVersion}
	var archiveDigest string
	if offline || custom != nil {
		var saved Object
		if err := readJSON(receipt, &saved); err != nil {
			return "", errors.New("签名来源没有本地签名，请先更新签名集")
		}
		var err error
		archiveDigest, err = digestFile(archive)
		if err != nil || archiveDigest != saved["sha256"] {
			return "", errors.New("缓存签名摘要不匹配")
		}
		if custom != nil && saved["definition"] != definition {
			return "", errors.New("自定义源配置已变化，请在线更新签名")
		}
		if offline {
			var derived Object
			if readJSON(metadata, &derived) == nil {
				raw, err := regularRead(base, 256<<20)
				if err == nil {
					hash := sha256.Sum256(raw)
					a, _ := json.Marshal(recipe)
					b, _ := json.Marshal(derived["recipe"])
					if string(a) == string(b) && derived["archive"] == archiveDigest && derived["candidate"] == hex.EncodeToString(hash[:]) {
						groups := map[string][]string{}
						for token, items := range object(derived["groups"]) {
							for _, v := range array(items) {
								groups[token] = append(groups[token], text(v))
							}
						}
						return applyRulePolicy(ctx, string(raw), p, groups, source, pool)
					}
				}
			}
		}
	}
	work, err := os.MkdirTemp(p.Cache, "native-rules-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(work)
	original := archive
	if !offline && custom == nil {
		log("下载并校验官方签名 " + source)
		data, err := downloadOfficialRules(ctx, source, settings, func(ctx context.Context, address string, limit int64) ([]byte, error) {
			return fetchDownload(ctx, address, limit, "", true)
		})
		if err != nil {
			return "", err
		}
		original = filepath.Join(work, "source.tar.gz")
		if err = atomicWrite(original, data, 0600); err != nil {
			return "", err
		}
	}
	files, err := readRuleBundle(original)
	if err != nil {
		return "", err
	}
	version := "3.13.2.0"
	var engine Object
	if readJSON(filepath.Join(enginePrefix(), "engine-manifest.json"), &engine) == nil {
		if value := text(object(object(engine["sources"])["snort"])["version"]); value != "" {
			version = value
		}
	}
	raw, groups, err := compileRuleBundle(ctx, files, source, version, text(get(settings, "ips_policy", "balanced")), pool)
	if err != nil {
		return "", err
	}
	active := false
	for _, line := range strings.Split(string(raw), "\n") {
		active = active || ruleAction.MatchString(line)
	}
	if !active {
		return "", errors.New("候选集中没有可用的文本签名")
	}
	rendered, err := applyRulePolicy(ctx, string(raw), p, groups, source, pool)
	if err != nil {
		return "", err
	}
	if !offline && custom == nil {
		if err = copyFile(original, archive); err != nil {
			return "", err
		}
		archiveDigest, err = digestFile(archive)
		if err != nil {
			return "", err
		}
		if err = writeJSON(receipt, Object{"source": source, "sha256": archiveDigest, "updater": "AEGIS Go"}); err != nil {
			return "", err
		}
	}
	if archiveDigest == "" {
		archiveDigest, err = digestFile(archive)
		if err != nil {
			return "", err
		}
	}
	if err = atomicWrite(base, raw, 0600); err != nil {
		return "", err
	}
	hash := sha256.Sum256(raw)
	if err = writeJSON(metadata, Object{"recipe": recipe, "archive": archiveDigest, "candidate": hex.EncodeToString(hash[:]), "groups": groups}); err != nil {
		return "", err
	}
	log("候选签名已生成 " + source)
	return rendered, nil
}
func UpdateRules(ctx context.Context, p rulePaths, offline bool, sources string, downloadOnly bool, pool *Pool, log func(string)) error {
	if offline && downloadOnly {
		return errors.New("离线应用不能仅下载")
	}
	if sources == "" {
		sources = p.Sources
	}
	custom, err := sourceDefinitions(sources)
	if err != nil {
		return err
	}
	settings := readSettings(filepath.Join(filepath.Dir(p.Config), "rule-update.conf"))
	credentials, err := sourceCredentials(sources, settings)
	if err != nil {
		return err
	}
	delete(settings, "oinkcode")
	for key, value := range credentials {
		settings[key] = value
	}
	selected := []string{}
	for name := range officialSources {
		if sourceEnabled(sources, name, custom) {
			selected = append(selected, name)
		}
	}
	for name, item := range custom {
		if item["enabled"] == true {
			selected = append(selected, name)
		}
	}
	sort.Strings(selected)
	if err = os.MkdirAll(p.Cache, 0700); err != nil {
		return err
	}
	// Source downloads have their own small queue. They never occupy the CPU pool
	// while waiting for policy jobs submitted to that same pool.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type candidate struct {
		text string
		err  error
	}
	results := make([]candidate, len(selected))
	queue := make(chan int)
	var wg sync.WaitGroup
	count := min(len(selected), WorkerCount())
	for range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range queue {
				source := selected[index]
				results[index].text, results[index].err = updateRuleSource(ctx, p, source, settings, offline, custom[source], pool, log)
				if results[index].err != nil {
					cancel()
				}
			}
		}()
	}
	for i := range selected {
		queue <- i
	}
	close(queue)
	wg.Wait()
	for _, r := range results {
		if r.err != nil {
			return r.err
		}
	}
	lines := map[RuleID]string{}
	owners := map[RuleID]string{}
	order := []RuleID{}
	comments := []string{}
	priority := map[string]int{"snort/community": 1, "snort/registered": 2, "snort/lightspd": 3}
	revision := regexp.MustCompile(`\brev\s*:\s*([0-9]+)`)
	rev := func(s string) int64 {
		m := revision.FindStringSubmatch(s)
		if len(m) == 2 {
			return integer(m[1])
		}
		return 0
	}
	for i, result := range results {
		source := selected[i]
		for _, line := range strings.Split(result.text, "\n") {
			if !ruleAction.MatchString(line) {
				comments = append(comments, line)
				continue
			}
			r := parseRule(line, "", source, true)
			if r == nil {
				return errors.New("签名缺少有效的 GID:SID")
			}
			old, exists := lines[r.ID]
			if exists && old != line {
				previous := owners[r.ID]
				if priority[source] == 0 || priority[previous] == 0 {
					return fmt.Errorf("签名来源包含冲突签名 %d:%d", r.ID.GID, r.ID.SID)
				}
				if rev(line) < rev(old) || (rev(line) == rev(old) && priority[source] <= priority[previous]) {
					continue
				}
			}
			if !exists {
				order = append(order, r.ID)
			}
			lines[r.ID], owners[r.ID] = line, source
		}
	}
	identities := map[string]Object{}
	readJSON(filepath.Join(p.Cache, "sources.json"), &identities)
	enabled := map[string]bool{}
	for _, s := range selected {
		enabled[s] = true
	}
	for _, item := range identities {
		item["enabled"] = enabled[text(item["source"])]
	}
	for _, source := range selected {
		identities[sourceKey(source)] = Object{"source": source, "enabled": true}
	}
	if err = writeJSON(filepath.Join(p.Cache, "sources.json"), identities); err != nil {
		return err
	}
	if downloadOnly {
		return nil
	}
	for _, id := range order {
		comments = append(comments, lines[id])
	}
	if len(selected) == 0 {
		comments = []string{"# No upstream ruleset enabled"}
	}
	return atomicWrite(filepath.Join(p.Data, "rules/snort.rules"), []byte(strings.Join(comments, "\n")+"\n"), 0600)
}
