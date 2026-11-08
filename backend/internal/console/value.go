package console

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Object map[string]any

func decode(data []byte, into any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := d.Decode(into); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("JSON 后存在多余内容")
	}
	return nil
}
func object(v any) Object {
	if x, ok := v.(map[string]any); ok {
		return x
	}
	if x, ok := v.(Object); ok {
		return x
	}
	return Object{}
}
func text(v any) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return string(x)
	case []byte:
		return string(x)
	default:
		return fmt.Sprint(v)
	}
}
func number(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case json.Number:
		n, _ := x.Float64()
		return n
	case string:
		n, _ := strconv.ParseFloat(x, 64)
		return n
	}
	return 0
}
func integer(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case json.Number:
		n, e := x.Int64()
		if e == nil {
			return n
		}
		f, e := x.Float64()
		if e != nil {
			return 0
		}
		return integer(f)
	case string:
		n, _ := strconv.ParseInt(x, 10, 64)
		return n
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) || x >= math.Exp2(63) || x < -math.Exp2(63) {
			return 0
		}
		return int64(x)
	}
	return 0
}
func boolean(v any) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return v != nil && v != "" && v != false && v != 0
}
func get(m Object, k string, fallback any) any {
	if v, ok := m[k]; ok && v != nil {
		return v
	}
	return fallback
}
func clone(m Object) Object {
	n := make(Object, len(m))
	for k, v := range m {
		n[k] = v
	}
	return n
}
func token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func timestamp(v any) float64 {
	if s, ok := v.(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return float64(t.UnixNano()) / 1e9
		}
	}
	return number(v)
}
func utc(v float64) string {
	sec, frac := math.Modf(v)
	return time.Unix(int64(sec), int64(frac*1e9)).UTC().Format(time.RFC3339Nano)
}
func now() float64                     { return float64(time.Now().UnixNano()) / 1e9 }
func bounded(v int, low, high int) int { return min(high, max(low, v)) }
func parseAddressOrPrefix(value string) (netip.Prefix, error) {
	if p, e := netip.ParsePrefix(value); e == nil {
		return p, nil
	}
	a, e := netip.ParseAddr(value)
	if e != nil {
		return netip.Prefix{}, e
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Sync both the new file and its containing directory before publishing progress.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("拒绝符号链接")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".aegis-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}
func readJSON(path string, into any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return decode(data, into)
}
func writeJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return atomicWrite(path, append(data, '\n'), 0600)
}
func safeName(value string) bool {
	return value != "" && len(value) <= 128 && value != "." && value != ".." && !strings.ContainsAny(value, "/\\\x00\r\n")
}
