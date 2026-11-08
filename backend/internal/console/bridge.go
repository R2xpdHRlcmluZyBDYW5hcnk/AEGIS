package console

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type RuleMetadata struct {
	mu        sync.Mutex
	signature string
	records   map[RuleID]Object
	pool      *Pool
	data      string
}

func newMetadata(pool *Pool, data string) *RuleMetadata { return &RuleMetadata{pool: pool, data: data} }

var metadataSeverity = regexp.MustCompile(`\bpriority\s*:\s*(\d+)`)
var metadataCategory = regexp.MustCompile(`\bclasstype\s*:\s*([^;\s]+)`)

func (m *RuleMetadata) Load(ctx context.Context) (map[RuleID]Object, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	paths := []string{filepath.Join(enginePrefix(), "etc/snort/snort_defaults.lua")}
	for _, name := range []string{"snort.rules", "local.rules", "ips-web-hunting.rules", "ips-web-bans.rules"} {
		paths = append(paths, filepath.Join(m.data, "rules", name))
	}
	var signature strings.Builder
	for _, p := range paths {
		if info, e := os.Stat(p); e == nil {
			dev, ino := fileIdentity(info)
			fmt.Fprintf(&signature, "%s:%d:%d:%d:%d\n", p, dev, ino, info.Size(), info.ModTime().UnixNano())
		}
	}
	if signature.String() == m.signature && m.records != nil {
		return m.records, nil
	}
	classifications := map[string]int64{}
	defaults := readText(paths[0])
	for _, item := range regexp.MustCompile(`\{([^{}]*name\s*=\s*[^{}]*)\}`).FindAllStringSubmatch(defaults, -1) {
		name := regexp.MustCompile(`name\s*=\s*['"]([^'"]+)`).FindStringSubmatch(item[1])
		priority := regexp.MustCompile(`priority\s*=\s*(\d+)`).FindStringSubmatch(item[1])
		if len(name) == 2 && len(priority) == 2 {
			classifications[name[1]] = integer(priority[1])
		}
	}
	records := map[RuleID]Object{}
	for _, p := range paths[1:] {
		f, e := os.Open(p)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return nil, e
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 65536), 1<<20)
		batches := [][]string{}
		batch := []string{}
		process := func() error {
			results, err := parallelMap(ctx, m.pool, batches, func(lines []string) (map[RuleID]Object, error) {
				out := map[RuleID]Object{}
				for _, line := range lines {
					r := parseRule(line, "", "", true)
					if r == nil || !r.Enabled {
						continue
					}
					category := ""
					if match := metadataCategory.FindStringSubmatch(line); len(match) == 2 {
						category = match[1]
					}
					severity := classifications[category]
					if match := metadataSeverity.FindStringSubmatch(line); len(match) == 2 {
						severity = integer(match[1])
					}
					metadata := Object{}
					for _, field := range strings.Fields("mitre_tactic_id mitre_technique_id mitre_tactic_name mitre_technique_name") {
						values := []string{}
						for _, match := range regexp.MustCompile(`\b`+field+`\s+([^,;]+)`).FindAllStringSubmatch(line, -1) {
							values = append(values, match[1])
						}
						if len(values) > 0 {
							metadata[field] = values
						}
					}
					out[r.ID] = Object{"category": category, "severity": severity, "metadata": metadata}
				}
				return out, nil
			})
			if err != nil {
				return err
			}
			for _, rows := range results {
				for id, r := range rows {
					records[id] = r
				}
			}
			batches = nil
			return nil
		}
		for scanner.Scan() {
			batch = append(batch, scanner.Text())
			if len(batch) >= 256 {
				batches = append(batches, batch)
				batch = nil
				if len(batches) >= m.pool.Workers {
					if e = process(); e != nil {
						break
					}
				}
			}
		}
		if e == nil {
			e = scanner.Err()
		}
		if len(batch) > 0 {
			batches = append(batches, batch)
		}
		if e == nil {
			e = process()
		}
		f.Close()
		if e != nil {
			return nil, e
		}
	}
	m.records, m.signature = records, signature.String()
	return records, nil
}

type bridgeFile struct {
	Inode      uint64 `json:"inode"`
	Offset     int64  `json:"offset"`
	Tail       string `json:"tail_hash"`
	Discarding bool   `json:"discarding"`
}
type bridgeState struct {
	Epoch    string                `json:"epoch"`
	Files    map[string]bridgeFile `json:"files"`
	Rejected int64                 `json:"rejected"`
	Sparse   int64                 `json:"sparse_bytes"`
}
type Bridge struct {
	logs, output, checkpoint, instance string
	state                              bridgeState
	cursor                             int
	pool                               *Pool
	metadata                           *RuleMetadata
}

func NewBridge(logs, output, checkpoint, instance string, pool *Pool) (*Bridge, error) {
	if info, err := os.Stat(logs); err != nil || !info.IsDir() {
		return nil, errors.New("原始日志目录不可用")
	}
	b := &Bridge{logs: logs, output: output, checkpoint: checkpoint, instance: instance, pool: pool, state: bridgeState{Files: map[string]bridgeFile{}}, metadata: newMetadata(pool, "/var/lib/snort")}
	if err := readJSON(checkpoint, &b.state); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if b.state.Files == nil {
		return nil, errors.New("采集位置记录无效")
	}
	if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(checkpoint), 0700); err != nil {
		return nil, err
	}
	if err := b.repairTail(); err != nil {
		return nil, err
	}
	return b, nil
}
func (b *Bridge) repairTail() error {
	if info, e := os.Lstat(b.output); e == nil && !info.Mode().IsRegular() {
		return errors.New("事件流不是普通文件")
	}
	f, e := os.OpenFile(b.output, os.O_CREATE|os.O_RDWR, 0644)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	size := info.Size()
	if size == 0 {
		return nil
	}
	last := []byte{0}
	if _, e = f.ReadAt(last, size-1); e != nil {
		return e
	}
	if last[0] == '\n' {
		return nil
	}
	start := max(int64(0), size-(8<<20))
	tail := make([]byte, size-start)
	if _, e = f.ReadAt(tail, start); e != nil {
		return e
	}
	boundary := bytes.LastIndexByte(tail, '\n')
	if boundary < 0 && start > 0 {
		return errors.New("事件流尾部损坏超出恢复上限，原日志已保留")
	}
	if e = f.Truncate(start + int64(boundary) + 1); e != nil {
		return e
	}
	return f.Sync()
}

type bridgeBatch struct {
	lines   [][]byte
	epoch   string
	decoder bool
}
type bridgeResult struct {
	segments          [][]byte
	metadata          []Object
	rejected, written int64
}

func decodeBridge(batch bridgeBatch) (bridgeResult, error) {
	result := bridgeResult{}
	for _, line := range batch.lines {
		var data Object
		if decode(line, &data) != nil || data == nil {
			result.rejected++
			continue
		}
		if !batch.decoder && (data["engine"] == "snort_session" || data["engine"] == "quic_observer") {
			var err error
			if data["engine"] == "snort_session" {
				_, err = sessionEvent(data)
			} else {
				_, err = observerEvent(data)
			}
			if err != nil {
				result.rejected++
				continue
			}
			encoded, err := json.Marshal(data)
			if err != nil {
				return result, err
			}
			result.segments = append(result.segments, append(encoded, '\n'))
			result.written++
			continue
		}
		kind := NativeKind(data)
		if batch.decoder {
			if integer(data["gid"]) != 116 {
				continue
			}
			kind = "decoder"
		}
		if kind == "" {
			result.rejected++
			continue
		}
		envelope := Object{"engine": "snort3", "epoch": batch.epoch, "kind": kind, "data": data}
		if kind == "notice" {
			result.metadata = append(result.metadata, envelope)
			result.segments = append(result.segments, nil)
		} else {
			encoded, err := json.Marshal(envelope)
			if err != nil {
				return result, err
			}
			result.segments = append(result.segments, append(encoded, '\n'))
		}
		result.written++
	}
	return result, nil
}
func tailHash(f *os.File, offset int64) (string, error) {
	tail := make([]byte, min(offset, 256))
	if len(tail) > 0 {
		if _, err := f.ReadAt(tail, offset-int64(len(tail))); err != nil {
			return "", err
		}
	}
	digest := sha256.Sum256(tail)
	return hex.EncodeToString(digest[:]), nil
}
func sparsePosition(f *os.File, offset int64) (int64, error) {
	fd, err := syscall.Open(f.Name(), syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0, nil
	}
	defer syscall.Close(fd)
	var info syscall.Stat_t
	if err = syscall.Fstat(fd, &info); err != nil {
		return 0, err
	}
	original, e := f.Stat()
	if e != nil {
		return 0, e
	}
	dev, ino := fileIdentity(original)
	if dev != uint64(info.Dev) || ino != info.Ino {
		return 0, nil
	}
	position, err := syscall.Seek(fd, offset, 3)
	if errors.Is(err, syscall.ENXIO) {
		return info.Size, nil
	}
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if position > offset {
		return position, nil
	}
	return 0, nil
}
func (b *Bridge) Poll(ctx context.Context) (int64, error) {
	var instance Object
	if e := readJSON(b.instance, &instance); errors.Is(e, os.ErrNotExist) {
		return 0, nil
	} else if e != nil {
		return 0, e
	}
	epoch := text(instance["epoch"])
	started := number(instance["started"])
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(epoch) || started <= 0 {
		return 0, errors.New("引擎实例记录无效")
	}
	state := b.state
	state.Files = map[string]bridgeFile{}
	// Native logs survive an engine restart. Their inode, length and tail hash
	// still fence the cursor; a new engine epoch alone must not replay them.
	for k, v := range b.state.Files {
		state.Files[k] = v
	}
	state.Epoch = epoch
	paths := []string{}
	for _, pattern := range []string{"*file_connector_ndr_transmit", "*alert_json.txt", "*quic_observer.json", "*ndr_session.json"} {
		matches, err := filepath.Glob(filepath.Join(b.logs, pattern))
		if err != nil {
			return 0, err
		}
		sort.Strings(matches)
		paths = append(paths, matches...)
	}
	if len(paths) > 128 {
		return 0, errors.New("原始日志文件过多")
	}
	if len(paths) > 0 {
		b.cursor %= len(paths)
		paths = append(paths[b.cursor:], paths[:b.cursor]...)
	}
	pending := append([]string{}, paths...)
	total := 0
	batches := []bridgeBatch{}
	for len(pending) > 0 && total < 4<<20 {
		p := pending[0]
		pending = pending[1:]
		b.cursor++
		info, err := os.Lstat(p)
		if err != nil {
			return 0, err
		}
		_, ino := fileIdentity(info)
		previous := state.Files[filepath.Base(p)]
		if !info.Mode().IsRegular() || float64(info.ModTime().UnixNano())/1e9 < started && previous.Inode != ino {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			return 0, err
		}
		actual, err := f.Stat()
		if err != nil || !os.SameFile(info, actual) {
			f.Close()
			return 0, errors.New("原始日志读取时被替换")
		}
		offset, discard := int64(0), false
		if previous.Inode == ino && previous.Offset <= info.Size() {
			offset, discard = previous.Offset, previous.Discarding
		}
		if offset > 0 && previous.Tail != "" {
			hash, e := tailHash(f, offset)
			if e != nil {
				f.Close()
				return 0, e
			}
			if hash != previous.Tail {
				offset, discard = 0, false
			}
		}
		if _, err = f.Seek(offset, 0); err != nil {
			f.Close()
			return 0, err
		}
		reader := bufio.NewReaderSize(f, (1<<20)+2)
		consumed, weight := 0, 0
		batch := bridgeBatch{epoch: epoch, decoder: strings.HasSuffix(p, "alert_json.txt")}
		for consumed < 1<<20 && total < 4<<20 {
			position := offset
			line, err := reader.ReadSlice('\n')
			if err == io.EOF && len(line) == 0 {
				break
			}
			if err != nil && err != io.EOF && err != bufio.ErrBufferFull {
				f.Close()
				return 0, err
			}
			padding := len(line) - len(bytes.TrimLeft(line, "\x00"))
			if padding > 0 {
				discard = false
				if padding == len(line) {
					target, e := sparsePosition(f, position)
					if e != nil {
						f.Close()
						return 0, e
					}
					if target <= position {
						target = position + int64(len(line))
					}
					state.Sparse += target - position
					offset = target
					consumed += len(line)
					total += len(line)
					f.Seek(offset, 0)
					reader.Reset(f)
					continue
				}
				state.Sparse += int64(padding)
				if line[len(line)-1] != '\n' {
					offset = position + int64(padding)
					f.Seek(offset, 0)
					reader.Reset(f)
					consumed += padding
					total += padding
					continue
				}
				line = line[padding:]
			}
			complete := len(line) > 0 && line[len(line)-1] == '\n'
			if discard {
				offset = position + int64(len(line)+padding)
				consumed += len(line) + padding
				total += len(line) + padding
				if complete {
					discard = false
				}
				continue
			}
			if !complete && len(line) <= 1<<20 {
				break
			}
			offset = position + int64(len(line)+padding)
			consumed += len(line) + padding
			total += len(line) + padding
			if len(line) > 1<<20 {
				state.Rejected++
				discard = !complete
				continue
			}
			batch.lines = append(batch.lines, append([]byte(nil), line...))
			weight += len(line)
			if weight >= 256<<10 {
				batches = append(batches, batch)
				batch = bridgeBatch{epoch: epoch, decoder: batch.decoder}
				weight = 0
			}
		}
		if len(batch.lines) > 0 {
			batches = append(batches, batch)
		}
		hash, err := tailHash(f, offset)
		f.Close()
		if err != nil {
			return 0, err
		}
		state.Files[filepath.Base(p)] = bridgeFile{ino, offset, hash, discard}
		if offset > previous.Offset && offset < info.Size() {
			pending = append(pending, p)
		}
	}
	results, err := parallelMap(ctx, b.pool, batches, decodeBridge)
	if err != nil {
		return 0, err
	}
	destination, err := os.OpenFile(b.output, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return 0, err
	}
	written := int64(0)
	var metadata map[RuleID]Object
	for _, result := range results {
		state.Rejected += result.rejected
		index := 0
		for _, segment := range result.segments {
			if segment == nil {
				if metadata == nil {
					metadata, err = b.metadata.Load(ctx)
					if err != nil {
						destination.Close()
						return 0, err
					}
				}
				envelope := result.metadata[index]
				index++
				d := object(envelope["data"])
				envelope["rule_metadata"] = getMetadata(metadata, RuleID{integer(d["gid"]), integer(d["sid"])})
				segment, err = json.Marshal(envelope)
				if err != nil {
					destination.Close()
					return 0, err
				}
				segment = append(segment, '\n')
			}
			if _, err = destination.Write(segment); err != nil {
				destination.Close()
				return 0, err
			}
		}
		written += result.written
	}
	if written > 0 {
		err = destination.Sync()
	}
	closeErr := destination.Close()
	if err != nil {
		return 0, err
	}
	if closeErr != nil {
		return 0, closeErr
	}
	if written > 0 {
		if err = syncDirectory(filepath.Dir(b.output)); err != nil {
			return 0, err
		}
	}
	before, _ := json.Marshal(b.state)
	after, _ := json.Marshal(state)
	if !bytes.Equal(before, after) {
		if err = atomicWrite(b.checkpoint, append(after, '\n'), 0600); err != nil {
			return 0, err
		}
	}
	b.state = state
	return written, nil
}
func getMetadata(rows map[RuleID]Object, id RuleID) Object {
	if r, ok := rows[id]; ok {
		return r
	}
	return Object{}
}
func (b *Bridge) Run(ctx context.Context, drain bool) error {
	for {
		before, _ := json.Marshal(b.state)
		if _, err := b.Poll(ctx); err != nil {
			return err
		}
		if drain {
			after, _ := json.Marshal(b.state)
			if bytes.Equal(before, after) {
				return nil
			}
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(250 * time.Millisecond):
		}
	}
}

var _ = strconv.Itoa
