package console

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Raw                                       Object
	Bind                                      string
	Port                                      int
	User, PasswordSHA, PasswordPBKDF          string
	SecureCookie                              bool
	StaticDir, EventDB, Stream, ManagerSocket string
	DatabaseURL                               string
	ReadWorkers                               int
	PreloadBytes                              int64
	SessionTTL                                time.Duration
	snapshotDir                               string
}

func LoadConfig(path string) (Config, error) {
	var raw Object
	if err := readJSON(path, &raw); err != nil {
		return Config{}, err
	}
	if raw == nil {
		return Config{}, errors.New("配置必须为 JSON 对象")
	}
	c := Config{Raw: raw, Bind: text(get(raw, "bind", "127.0.0.1")), Port: int(integer(get(raw, "port", 9000))), User: text(get(raw, "user", "admin")), PasswordSHA: strings.TrimSpace(text(raw["password_sha256"])), PasswordPBKDF: strings.TrimSpace(text(raw["password_pbkdf2"])), SecureCookie: raw["secure_cookie"] == true, StaticDir: text(get(raw, "static_dir", "/usr/local/share/ips-web")), EventDB: text(get(raw, "event_db", "/var/lib/ips-web/snort-ndr.db")), Stream: text(get(raw, "eve", "/var/log/ips/events.json")), ManagerSocket: text(get(raw, "rule_manager_socket", "")), ReadWorkers: WorkerCount(), PreloadBytes: integer(get(raw, "preload_memory_mib", 128)) << 20, SessionTTL: time.Duration(integer(get(raw, "session_ttl", 43200))) * time.Second}
	if os.Getenv("IPS_WEB_ISOLATED") == "1" {
		c.ManagerSocket = "/run/ips-rule-manager/control.sock"
		dir := os.Getenv("STATE_DIRECTORY")
		if dir == "" {
			dir = "/var/lib/ips-web"
		}
		c.EventDB = filepath.Join(dir, "snort-ndr.db")
		c.snapshotDir = overviewRuntimeDirectory()
		if c.snapshotDir == "" {
			return Config{}, errors.New("概览内存快照目录不可用")
		}
	}
	c.DatabaseURL = strings.TrimSpace(text(raw["database_url"]))
	if root := os.Getenv("IPS_LOG_STORAGE_ROOT"); root != "" {
		if root != "/var/lib/ips-snort-logs" {
			return Config{}, errors.New("服务日志目录与安装布局不一致")
		}
		c.Stream = filepath.Join(root, "events/events.json")
	}
	if c.Port < 1 || c.Port > 65535 || c.PreloadBytes < 1<<20 || c.PreloadBytes > 1024<<20 || c.SessionTTL < time.Minute || c.SessionTTL > 7*24*time.Hour {
		return Config{}, errors.New("控制台资源或监听配置无效")
	}
	return c, nil
}
func (c Config) PasswordConfigured() bool { return c.PasswordSHA != "" || c.PasswordPBKDF != "" }
func (c Config) VerifyPassword(password string) bool {
	if c.PasswordPBKDF != "" {
		parts := strings.Split(c.PasswordPBKDF, "$")
		if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
			return false
		}
		rounds, err := strconv.Atoi(parts[1])
		if err != nil || rounds < 10000 || rounds > 10000000 {
			return false
		}
		salt, err := base64.StdEncoding.Strict().DecodeString(parts[2])
		if err != nil || len(salt) < 8 || len(salt) > 1024 {
			return false
		}
		expected, err := base64.StdEncoding.Strict().DecodeString(parts[3])
		if err != nil || len(expected) != 32 {
			return false
		}
		actual, err := pbkdf2.Key(sha256.New, password, salt, rounds, 32)
		return err == nil && subtle.ConstantTimeCompare(actual, expected) == 1
	}
	if c.PasswordSHA == "" {
		return false
	}
	actual := sha256.Sum256([]byte(password))
	return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(actual[:])), []byte(strings.ToLower(c.PasswordSHA))) == 1
}
func PasswordHash(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	digest, err := pbkdf2.Key(sha256.New, password, salt, 310000, 32)
	if err != nil {
		return "", err
	}
	return "pbkdf2-sha256$310000$" + base64.StdEncoding.EncodeToString(salt) + "$" + base64.StdEncoding.EncodeToString(digest), nil
}
func GeneratePassword() (string, string, error) {
	password := token()[:24]
	hash, err := PasswordHash(password)
	return password, hash, err
}

type session struct {
	user, ip string
	expires  time.Time
}
type loginFailure struct {
	count int
	first time.Time
}
type Sessions struct {
	mu       sync.Mutex
	entries  map[string]session
	failures map[string]loginFailure
	TTL      time.Duration
}

func NewSessions(ttl time.Duration) *Sessions {
	return &Sessions{entries: map[string]session{}, failures: map[string]loginFailure{}, TTL: ttl}
}
func (s *Sessions) Create(user, ip string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, v := range s.entries {
		if time.Now().After(v.expires) {
			delete(s.entries, key)
		}
	}
	if len(s.entries) >= 1024 {
		var oldest string
		var stamp time.Time
		for k, v := range s.entries {
			if oldest == "" || v.expires.Before(stamp) {
				oldest, stamp = k, v.expires
			}
		}
		delete(s.entries, oldest)
	}
	key := token()
	s.entries[key] = session{user, ip, time.Now().Add(s.TTL)}
	return key
}
func (s *Sessions) Valid(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.entries[key]
	if !ok || time.Now().After(value.expires) {
		delete(s.entries, key)
		return false
	}
	return true
}
func (s *Sessions) Drop(key string) { s.mu.Lock(); defer s.mu.Unlock(); delete(s.entries, key) }
func (s *Sessions) Throttled(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	failure := s.failures[ip]
	if time.Since(failure.first) > 5*time.Minute {
		delete(s.failures, ip)
		return false
	}
	return failure.count >= 5
}
func (s *Sessions) Failure(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.failures) > 4096 {
		for key, v := range s.failures {
			if time.Since(v.first) > 5*time.Minute {
				delete(s.failures, key)
			}
		}
		if len(s.failures) > 4096 {
			return
		}
	}
	f := s.failures[ip]
	if time.Since(f.first) > 5*time.Minute {
		f = loginFailure{first: time.Now()}
	}
	f.count++
	s.failures[ip] = f
}
func (s *Sessions) Success(ip string) { s.mu.Lock(); defer s.mu.Unlock(); delete(s.failures, ip) }
