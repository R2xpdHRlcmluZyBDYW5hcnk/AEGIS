package console

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"
)

var officialSources = map[string][3]string{"snort/community": {"Community", "Snort Community text rules", "GPLv2"}, "snort/registered": {"Registered 免费注册", "免费注册规则集，需 Snort Oinkcode", "Snort rules license"}, "snort/lightspd": {"LightSPD", "Talos LightSPD text rules", "Snort rules license"}}
var customNamePattern = regexp.MustCompile(`^custom/[a-z0-9][a-z0-9_-]{0,63}$`)
var oinkPattern = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
var sourceVersion = regexp.MustCompile(`^(?:auto|3\.[0-9]+\.[0-9]+\.[0-9]+)$`)

func registeredSnapshot(version string) string {
	switch version {
	case "auto", "", "3.13.2.0":
		return "3.13.0.0"
	case "3.12.4.0":
		return "3.12.0.0"
	}
	return version
}
func customPath(directory, name string) (string, error) {
	if !customNamePattern.MatchString(name) {
		return "", errors.New("自定义源标识只能包含小写字母、数字、下划线和短横线")
	}
	return filepath.Join(directory, strings.ReplaceAll(name, "/", "-")+".json"), nil
}
func sourceDefinitions(directory string) (map[string]Object, error) {
	out := map[string]Object{}
	paths, err := filepath.Glob(filepath.Join(directory, "custom-*.json"))
	if err != nil {
		return nil, err
	}
	if len(paths) > 128 {
		return nil, errors.New("自定义源数量超过限制")
	}
	for _, path := range paths {
		data, err := regularRead(path, 64<<10)
		if err != nil {
			return nil, err
		}
		var value Object
		if err = decode(data, &value); err != nil {
			return nil, errors.New("自定义源配置无效")
		}
		expected, err := customPath(directory, text(value["name"]))
		if err != nil || expected != path {
			return nil, errors.New("无效自定义源文件")
		}
		if _, ok := value["enabled"].(bool); !ok {
			return nil, errors.New("自定义源启用状态无效")
		}
		out[text(value["name"])] = value
	}
	return out, nil
}
func sourceEnabled(directory, name string, custom map[string]Object) bool {
	if value, ok := custom[name]; ok {
		return value["enabled"] == true
	}
	_, err := os.Stat(filepath.Join(directory, strings.ReplaceAll(name, "/", "-")+".yaml"))
	return err == nil
}
func readSettings(path string) Object {
	out := Object{}
	for _, line := range readLines(path) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok {
			out[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
		}
	}
	return out
}
func sourceCredentials(directory string, fallback Object) (Object, error) {
	var value Object
	err := readJSON(filepath.Join(directory, "credentials.json"), &value)
	if errors.Is(err, os.ErrNotExist) {
		value = clone(fallback)
		err = nil
	}
	if err != nil {
		return nil, errors.New("规则源凭据配置无效")
	}
	return value, nil
}
func publicSources(directory string, fallback Object) (Object, error) {
	credentials, err := sourceCredentials(directory, fallback)
	if err != nil {
		return nil, err
	}
	custom, err := sourceDefinitions(directory)
	if err != nil {
		return nil, err
	}
	names := []string{}
	for name := range officialSources {
		names = append(names, name)
	}
	sort.Strings(names)
	rows := []Object{}
	for _, name := range names {
		spec := officialSources[name]
		version := text(get(credentials, "registered_version", "auto"))
		if version == "3.12.4.0" {
			version = "auto"
		}
		rows = append(rows, Object{"name": name, "vendor": spec[0], "summary": spec[1], "license": spec[2], "enabled": sourceEnabled(directory, name, custom), "custom": false, "requires_code": name != "snort/community", "credential_configured": text(credentials["oinkcode"]) != "", "registered_version": version, "effective_version": registeredSnapshot(version)})
	}
	names = nil
	for name := range custom {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		item := custom[name]
		parsed, err := url.Parse(text(item["url"]))
		if err != nil {
			return nil, errors.New("自定义源地址无效")
		}
		rows = append(rows, Object{"name": name, "vendor": item["label"], "summary": "自定义 Snort 3 文本规则", "license": "由规则提供方授权", "custom": true, "enabled": item["enabled"], "format": item["format"], "download_host": parsed.Host, "credential_configured": text(item["token"]) != "", "requires_code": false})
	}
	return Object{"sources": rows, "error": ""}, nil
}
func configureSource(directory string, value, fallback Object) error {
	name := strings.ToLower(strings.TrimSpace(text(value["name"])))
	if _, ok := officialSources[name]; ok {
		if name == "snort/community" {
			return errors.New("Community 不需要注册码")
		}
		current, err := sourceCredentials(directory, fallback)
		if err != nil {
			return err
		}
		if code, ok := value["oinkcode"]; ok {
			str, ok := code.(string)
			if !ok {
				return errors.New("无效 Oinkcode")
			}
			if str != "" {
				str = strings.TrimSpace(str)
				if !oinkPattern.MatchString(str) {
					return errors.New("Oinkcode 必须是 40 位十六进制字符")
				}
				current["oinkcode"] = str
			}
		}
		if value["clear_credential"] == true {
			delete(current, "oinkcode")
		}
		version := text(get(value, "registered_version", get(current, "registered_version", "auto")))
		if !sourceVersion.MatchString(version) {
			return errors.New("Registered 规则快照版本无效")
		}
		current["registered_version"] = version
		return writeJSON(filepath.Join(directory, "credentials.json"), current)
	}
	path, err := customPath(directory, name)
	if err != nil {
		return err
	}
	current := Object{"name": name, "enabled": false}
	if err = readJSON(path, &current); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("自定义源配置无效")
	}
	if value["delete"] == true {
		if err = os.Remove(path); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	label := strings.TrimSpace(text(get(value, "label", get(current, "label", name))))
	if len([]rune(label)) < 1 || len([]rune(label)) > 100 {
		return errors.New("规则源名称需要 1 至 100 字")
	}
	address := text(present(value["url"], current["url"]))
	parsed, err := url.Parse(address)
	if err != nil || len(address) > 4096 || strings.ContainsAny(address, "\r\n") || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("下载地址必须是 HTTPS，不支持内嵌用户名、密码或片段")
	}
	format := text(get(value, "format", get(current, "format", "rules")))
	if format != "rules" && format != "tar.gz" {
		return errors.New("请选择 .rules 或 .tar.gz 格式")
	}
	token, ok := get(value, "token", "").(string)
	if !ok || len(token) > 2048 || strings.ContainsAny(token, "\r\n") {
		return errors.New("下载令牌无效")
	}
	current["label"], current["url"], current["format"] = label, address, format
	if token != "" {
		current["token"] = token
	}
	if value["clear_credential"] == true {
		delete(current, "token")
	}
	return writeJSON(path, current)
}
func setSourceEnabled(directory, name string, enabled bool, fallback Object) error {
	if _, ok := officialSources[name]; ok {
		path := filepath.Join(directory, strings.ReplaceAll(name, "/", "-")+".yaml")
		if enabled {
			credentials, err := sourceCredentials(directory, fallback)
			if err != nil {
				return err
			}
			if name != "snort/community" && text(credentials["oinkcode"]) == "" {
				return errors.New("请先配置 Oinkcode")
			}
			if err = atomicWrite(path, []byte("source: "+name+"\n"), 0600); err != nil {
				return err
			}
			os.Remove(path + ".disabled")
			return nil
		}
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return os.Rename(path, path+".disabled")
	}
	path, err := customPath(directory, name)
	if err != nil {
		return err
	}
	var item Object
	if err = readJSON(path, &item); err != nil {
		return errors.New("自定义源不存在或配置无效")
	}
	item["enabled"] = enabled
	return writeJSON(path, item)
}
func sourceKey(source string) string {
	digest := sha256.Sum256([]byte(source))
	return hex.EncodeToString(digest[:])[:24]
}
func pythonJSONString(value any) string {
	if value == nil {
		return "null"
	}
	data, _ := json.Marshal(value)
	s := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(string(data), `\u003c`, "<"), `\u003e`, ">"), `\u0026`, "&")
	var out strings.Builder
	for _, r := range s {
		if r >= 127 {
			for _, unit := range utf16.Encode([]rune{r}) {
				fmt.Fprintf(&out, `\u%04x`, unit)
			}
		} else {
			out.WriteRune(r)
		}
	}
	return out.String()
}
func definitionDigest(item Object) string {
	input := fmt.Sprintf(`{"format": %s, "token": %s, "url": %s}`, pythonJSONString(item["format"]), pythonJSONString(item["token"]), pythonJSONString(item["url"]))
	digest := sha256.Sum256([]byte(input))
	return hex.EncodeToString(digest[:])
}
func (a *RuleCatalog) sourceRead(ctx context.Context, params Object) (Object, error) {
	return publicSources(a.draft.Sources, readSettings(filepath.Join(filepath.Dir(a.live.Config), "rule-update.conf")))
}
