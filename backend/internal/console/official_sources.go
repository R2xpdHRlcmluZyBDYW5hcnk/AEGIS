package console

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

const officialSourceFile = "signature-sources.json"

type ruleArchiveFormat string

const (
	textArchive       ruleArchiveFormat = "text"
	registeredArchive ruleArchiveFormat = "registered"
	lightSPDArchive   ruleArchiveFormat = "lightspd"
)

type officialSource struct {
	Name             string            `json:"name"`
	Vendor           string            `json:"vendor"`
	Summary          string            `json:"summary"`
	License          string            `json:"license"`
	ArchiveURL       string            `json:"archive_url"`
	Format           ruleArchiveFormat `json:"format"`
	RequiresOinkcode bool              `json:"requires_oinkcode"`
	Priority         int               `json:"priority"`
}

type officialCatalog struct {
	sources map[string]officialSource
	aliases map[string]string
}

var officialSourceName = regexp.MustCompile(`^snort/[a-z0-9][a-z0-9_-]{0,63}$`)

func (p rulePaths) officialSourcePath() string {
	return filepath.Join(filepath.Dir(p.Config), officialSourceFile)
}

func (p rulePaths) officialSources() (officialCatalog, error) {
	data, err := regularRead(p.officialSourcePath(), 64<<10)
	if err != nil {
		return officialCatalog{}, errors.New("无法读取官方特征来源配置 " + officialSourceFile)
	}
	var config struct {
		Sources []officialSource  `json:"sources"`
		Aliases map[string]string `json:"snapshot_aliases"`
	}
	invalid := errors.New("官方特征来源配置无效 " + officialSourceFile)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || decoder.Decode(new(any)) != io.EOF || len(config.Sources) == 0 || len(config.Sources) > 128 {
		return officialCatalog{}, invalid
	}
	if config.Aliases["auto"] == "" {
		return officialCatalog{}, invalid
	}
	for alias, version := range config.Aliases {
		if !sourceVersion.MatchString(alias) || !sourceVersion.MatchString(version) || version == "auto" {
			return officialCatalog{}, invalid
		}
	}
	catalog := officialCatalog{sources: make(map[string]officialSource, len(config.Sources)), aliases: config.Aliases}
	priorities := map[int]bool{}
	for _, source := range config.Sources {
		if !officialSourceName.MatchString(source.Name) || catalog.sources[source.Name].Name != "" ||
			source.Priority < 1 || priorities[source.Priority] || strings.TrimSpace(source.Vendor) == "" ||
			strings.TrimSpace(source.Summary) == "" || strings.TrimSpace(source.License) == "" || !source.validArchive() {
			return officialCatalog{}, invalid
		}
		// Update only the old default display strings, leaving the source file intact.
		switch source.Summary {
		case "Snort Community 文本签名":
			source.Summary = "Snort Community 文本特征"
		case "免费注册签名集，需 Snort Oinkcode":
			source.Summary = "免费注册特征集，需 Snort Oinkcode"
		case "Talos LightSPD 文本签名":
			source.Summary = "Talos LightSPD 文本特征"
		}
		if source.License == "Snort 签名许可" {
			source.License = "Snort 特征许可"
		}
		catalog.sources[source.Name] = source
		priorities[source.Priority] = true
	}
	return catalog, nil
}

func (s officialSource) validArchive() bool {
	address := s.ArchiveURL
	switch s.Format {
	case registeredArchive:
		if strings.Count(address, "{snapshot}") != 1 {
			return false
		}
		address = strings.Replace(address, "{snapshot}", "1", 1)
	case textArchive, lightSPDArchive:
	default:
		return false
	}
	u, err := url.Parse(address)
	return err == nil && u.Scheme == "https" && u.User == nil &&
		(u.Hostname() == "snort.org" || u.Hostname() == "www.snort.org") && (u.Port() == "" || u.Port() == "443") &&
		u.RawQuery == "" && !u.ForceQuery && !strings.ContainsAny(address, "{}#") && strings.HasSuffix(u.Path, ".tar.gz")
}

func (c officialCatalog) snapshot(version string) string {
	if version == "" {
		version = "auto"
	}
	if target, ok := c.aliases[version]; ok {
		return target
	}
	return version
}

func (c officialCatalog) archiveFormat(name string) ruleArchiveFormat {
	if source, ok := c.sources[name]; ok {
		return source.Format
	}
	return textArchive
}
