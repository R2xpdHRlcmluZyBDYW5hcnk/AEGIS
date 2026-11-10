package console

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
)

// The compiler has already selected compatible text rules and recorded every
// source group, including groups of disabled signatures. Reuse that bounded
// candidate instead of decompressing LightSPD's unrelated modules for browsing.
func cachedCatalogRules(cache, key, source string, format ruleArchiveFormat) ([]byte, map[RuleID][]string, bool) {
	if sourceKey(source) != key {
		return nil, nil, false
	}
	base := filepath.Join(cache, "derived", key)
	metadata, err := regularRead(base+".json", 32<<20)
	if err != nil {
		return nil, nil, false
	}
	var saved, receipt Object
	if decode(metadata, &saved) != nil || readJSON(filepath.Join(cache, key+"-receipt.json"), &receipt) != nil {
		return nil, nil, false
	}
	recipe := object(saved["recipe"])
	if recipe["source"] != source || recipe["format"] != string(format) || recipe["parser"] != nativeRuleParserVersion || receipt["source"] != source || saved["archive"] != receipt["sha256"] || len(text(saved["archive"])) != 64 {
		return nil, nil, false
	}
	raw, err := regularRead(base+".rules", 256<<20)
	if err != nil {
		return nil, nil, false
	}
	hash := sha256.Sum256(raw)
	if saved["candidate"] != hex.EncodeToString(hash[:]) {
		return nil, nil, false
	}
	groups := map[RuleID][]string{}
	for token, values := range object(saved["groups"]) {
		id, err := identity(token)
		if err != nil {
			return nil, nil, false
		}
		for _, value := range array(values) {
			name, ok := value.(string)
			if !ok || name == "" || len(name) > 255 || strings.ContainsAny(name, "/\\\r\n\x00") {
				return nil, nil, false
			}
			groups[id] = append(groups[id], name)
		}
		if len(groups[id]) == 0 {
			return nil, nil, false
		}
	}
	return raw, groups, len(groups) > 0
}

func catalogArchiveRules(filename string, format ruleArchiveFormat, paths rulePaths) (map[string][]byte, error) {
	files, err := readRuleBundle(filename)
	if err != nil {
		return nil, err
	}
	settings := readSettings(filepath.Join(filepath.Dir(paths.Config), "rule-update.conf"))
	credentials, err := sourceCredentials(paths.Sources, settings)
	if err != nil {
		return nil, err
	}
	version := "3.13.2.0"
	var manifest Object
	if readJSON(filepath.Join(enginePrefix(), "engine-manifest.json"), &manifest) == nil {
		if value := text(object(object(manifest["sources"])["snort"])["version"]); value != "" {
			version = value
		}
	}
	rules, _, err := ruleBundleSelection(files, format, version, text(get(credentials, "ips_policy", get(settings, "ips_policy", "balanced"))))
	return rules, err
}
