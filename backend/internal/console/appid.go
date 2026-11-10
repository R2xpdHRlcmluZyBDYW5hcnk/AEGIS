package console

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func trustedAppIDURL(address string) bool {
	u, e := url.Parse(address)
	if e != nil || u.Scheme != "https" || u.User != nil || (u.Port() != "" && u.Port() != "443") {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == "snort.org" || host == "www.snort.org" || strings.HasSuffix(host, ".amazonaws.com") || strings.HasSuffix(host, ".cloudfront.net")
}
func fetchDownload(ctx context.Context, address string, maximum int64, token string, trusted bool) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.User != nil || (trusted && !trustedAppIDURL(address)) {
		return nil, errors.New("下载地址不受信任")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 45 * time.Second
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 8 || req.URL.Scheme != "https" || req.URL.User != nil || (trusted && !trustedAppIDURL(req.URL.String())) {
			return errors.New("重定向不受信任")
		}
		if len(via) > 0 && !strings.EqualFold(via[0].URL.Host, req.URL.Host) {
			req.Header.Del("Authorization")
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(ctx, "GET", address, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Snort-NDR-rule-updater")
	req.Header.Set("Cache-Control", "no-cache")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("下载失败，请检查网络和授权")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.ContentLength > maximum {
		return nil, errors.New("下载失败或响应超过限制")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, errors.New("下载失败或响应超过限制")
	}
	return data, nil
}
func appIDTarget(root, target string) (string, error) {
	resolved := target
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(root, resolved)
	}
	resolved, err := filepath.EvalSymlinks(resolved)
	if err != nil {
		return "", errors.New("OpenAppID 检测器目标缺失")
	}
	releases, err := filepath.Abs(filepath.Join(root, "releases"))
	if err != nil {
		return "", err
	}
	bundled := filepath.Join(enginePrefix(), "share/appid/odp")
	allowed := resolved == bundled || (filepath.Dir(resolved) == releases && regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(filepath.Base(resolved)))
	if !allowed {
		return "", errors.New("OpenAppID 检测器目标越界")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", errors.New("OpenAppID 检测器目录无效")
	}
	return resolved, nil
}
func appIDSnapshot(root string) (Object, error) {
	target, err := os.Readlink(filepath.Join(root, "odp"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("OpenAppID odp 必须是受管理的符号链接")
	}
	if _, err = appIDTarget(root, target); err != nil {
		return nil, err
	}
	var receipt Object
	if err = readJSON(filepath.Join(root, "update.json"), &receipt); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return Object{"target": target, "receipt": receipt}, nil
}
func switchAppID(root, target string) error {
	if _, err := appIDTarget(root, target); err != nil {
		return err
	}
	staged := filepath.Join(root, "odp.new")
	if info, err := os.Lstat(staged); err == nil {
		if info.IsDir() {
			return errors.New("OpenAppID 暂存指针异常")
		}
		if err = os.Remove(staged); err != nil {
			return err
		}
	}
	if err := os.Symlink(target, staged); err != nil {
		return err
	}
	if err := os.Rename(staged, filepath.Join(root, "odp")); err != nil {
		os.Remove(staged)
		return err
	}
	return syncDirectory(root)
}
func restoreAppID(root string, value Object) error {
	if value == nil {
		return nil
	}
	if err := switchAppID(root, text(value["target"])); err != nil {
		return err
	}
	if value["receipt"] == nil {
		if err := os.Remove(filepath.Join(root, "update.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDirectory(root)
	}
	return writeJSON(filepath.Join(root, "update.json"), value["receipt"])
}
func extractAppID(data []byte, destination string) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	total, count := int64(0), 0
	seen := map[string]bool{}
	lua, mapping := false, false
	for {
		entry, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		count++
		name := path.Clean(entry.Name)
		parts := strings.Split(entry.Name, "/")
		bad := false
		for _, p := range parts {
			if p == ".." || p == ".git" {
				bad = true
			}
		}
		if count > 20000 || strings.Contains(entry.Name, "\\") || strings.HasPrefix(name, "/") || bad || !(name == "odp" || strings.HasPrefix(name, "odp/")) || seen[name] || !(entry.Typeflag == tar.TypeReg || entry.Typeflag == tar.TypeDir) || entry.Size < 0 || entry.Size > 16<<20 {
			return errors.New("OpenAppID 压缩包包含不安全成员")
		}
		seen[name] = true
		total += entry.Size
		if total > 256<<20 {
			return errors.New("OpenAppID 解压大小超过限制")
		}
		target := filepath.Join(destination, filepath.FromSlash(name))
		if entry.Typeflag == tar.TypeDir {
			if err = os.MkdirAll(target, 0755); err != nil {
				return err
			}
			continue
		}
		if err = os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		_, copyErr := io.CopyN(f, reader, entry.Size)
		syncErr := f.Sync()
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		if syncErr != nil {
			return syncErr
		}
		if closeErr != nil {
			return closeErr
		}
		lua = lua || strings.HasSuffix(name, ".lua")
		mapping = mapping || name == "odp/appMapping.data"
	}
	if !lua || !mapping {
		return errors.New("OpenAppID 检测器目录不完整")
	}
	return nil
}
func updateAppID(ctx context.Context, root string, log func(string)) (bool, error) {
	previous, err := appIDSnapshot(root)
	if err != nil {
		return false, err
	}
	if previous == nil {
		log("未安装 OpenAppID 检测器，跳过更新")
		return false, nil
	}
	log("检查 OpenAppID 官方检测器更新")
	page, err := fetchDownload(ctx, "https://www.snort.org/downloads", 2<<20, "", true)
	if err != nil {
		return false, err
	}
	link := regexp.MustCompile(`href=["'](/downloads/openappid/[0-9]+)["']`).FindSubmatch(page)
	if len(link) != 2 {
		return false, errors.New("OpenAppID 官方页面未提供检测器包")
	}
	checksum, err := fetchDownload(ctx, "https://www.snort.org/downloads/openappid/md5s", 65536, "", true)
	if err != nil {
		return false, err
	}
	matches := regexp.MustCompile(`(?m)^[ \t]*([a-fA-F0-9]{32})[ \t]+\*?snort-openappid\.tar\.gz[ \t]*\r?$`).FindAllSubmatch(checksum, -1)
	if len(matches) != 1 {
		return false, errors.New("OpenAppID 官方校验格式无效")
	}
	expected := strings.ToLower(string(matches[0][1]))
	old := object(previous["receipt"])
	if old["md5"] == expected {
		old["checked"] = time.Now().Unix()
		if err := writeJSON(filepath.Join(root, "update.json"), old); err != nil {
			return false, err
		}
		log("OpenAppID 检测器已是最新，跳过下载")
		return false, nil
	}
	log("发现新版 OpenAppID 检测器，开始下载")
	data, err := fetchDownload(ctx, "https://www.snort.org"+string(link[1]), 64<<20, "", true)
	if err != nil {
		return false, err
	}
	legacy := md5.Sum(data)
	if hex.EncodeToString(legacy[:]) != expected {
		return false, errors.New("OpenAppID 官方校验值不匹配")
	}
	digest := sha256.Sum256(data)
	id := hex.EncodeToString(digest[:])
	releases := filepath.Join(root, "releases")
	if err = os.MkdirAll(releases, 0755); err != nil {
		return false, err
	}
	stage, err := os.MkdirTemp(releases, ".download-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(stage)
	if err = extractAppID(data, stage); err != nil {
		return false, err
	}
	version := filepath.Join(releases, id)
	if fileExists(version) {
		if strings.TrimSpace(readText(filepath.Join(version, ".ndr-sha256"))) != id {
			return false, errors.New("OpenAppID 版本校验记录不一致")
		}
	} else {
		if err = atomicWrite(filepath.Join(stage, "odp/.ndr-sha256"), []byte(id+"\n"), 0644); err != nil {
			return false, err
		}
		if err = os.Rename(filepath.Join(stage, "odp"), version); err != nil {
			return false, err
		}
		if err = syncDirectory(releases); err != nil {
			return false, err
		}
	}
	if err = switchAppID(root, version); err != nil {
		return false, err
	}
	if err = writeJSON(filepath.Join(root, "update.json"), Object{"sha256": id, "md5": expected, "checked": time.Now().Unix(), "source": "snort.org"}); err != nil {
		return false, err
	}
	log("OpenAppID 检测器已下载并校验，等待引擎热重载")
	return true, nil
}
