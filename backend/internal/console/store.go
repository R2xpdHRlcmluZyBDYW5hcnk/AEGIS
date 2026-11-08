package console

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sqlite "github.com/mattn/go-sqlite3"
)

//go:embed network.sql
var networkSQL string

//go:embed network_logs.sql
var networkLogsSQL string

type Querier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}
type Store struct {
	Path, Stream    string
	Writer, Readers *sql.DB
	Gate            sync.Mutex
	stateMu         sync.RWMutex
	writeError      string
	blocked         bool
	cursor          Cursor
	recentCursor    Cursor
	cutoff          Cursor
	started         bool
	Pool            *Pool
	Revision        atomic.Uint64
	Generation      atomic.Uint64
	Cap             int64
	changed         chan struct{}
}
type Cursor struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
	Digest string `json:"digest"`
}

func init() {
	hook := func(c *sqlite.SQLiteConn) error {
		for name, fn := range map[string]any{"hunt_fold": func(v any) string { return strings.ToLower(text(v)) }, "hunt_glob": func(v, p any) bool { return glob(text(p), text(v)) }, "hunt_network": func(v, p any) bool {
			a, e := netip.ParseAddr(text(v))
			n, f := netip.ParsePrefix(text(p))
			return e == nil && f == nil && n.Contains(a)
		}, "hunt_metadata": func(raw any, field, value string, icase bool) bool { return matchMetadata(raw, field, value, icase) }, "tuple_hash": func(src, sport, dst, dport, proto any) any { return tupleHash(src, sport, dst, dport, proto) }, "flow_summary": func(app, proto, state, reason, old any) string {
			return flowSummary(text(app), text(proto), text(state), text(reason), text(old))
		}} {
			if err := c.RegisterFunc(name, fn, true); err != nil {
				return err
			}
		}
		return nil
	}
	sql.Register("aegis-sqlite", &sqlite.SQLiteDriver{ConnectHook: hook})
	sql.Register("aegis-recent-sqlite", &sqlite.SQLiteDriver{ConnectHook: func(c *sqlite.SQLiteConn) error {
		if err := hook(c); err != nil {
			return err
		}
		_, err := c.Exec("PRAGMA temp_store=MEMORY", nil)
		return err
	}})
}
func tupleHash(src, sport, dst, dport, proto any) any {
	a, e := netip.ParseAddr(text(src))
	b, f := netip.ParseAddr(text(dst))
	if e != nil || f != nil || a.BitLen() != b.BitLen() || sport == nil || dport == nil || sport == "" || dport == "" || integer(sport) < 0 || integer(sport) > 65535 || integer(dport) < 0 || integer(dport) > 65535 {
		return nil
	}
	p := strings.ToUpper(strings.TrimSpace(text(proto)))
	if code, ok := map[string]string{"TCP": "6", "UDP": "17", "SCTP": "132", "ICMP": "1", "IPV6-ICMP": "58"}[p]; ok {
		p = code
	}
	if n, err := strconv.ParseUint(p, 10, 8); err == nil {
		p = strconv.FormatUint(n, 10)
	} else if len(p) > 0 && strings.IndexFunc(p, func(c rune) bool { return c < '0' || c > '9' }) < 0 {
		return nil
	}
	if p == "" {
		return nil
	}
	ends := []struct {
		address string
		port    int64
	}{{hex.EncodeToString(a.AsSlice()), integer(sport)}, {hex.EncodeToString(b.AsSlice()), integer(dport)}}
	sort.Slice(ends, func(i, j int) bool {
		if ends[i].address == ends[j].address {
			return ends[i].port < ends[j].port
		}
		return ends[i].address < ends[j].address
	})
	data, _ := json.Marshal([]any{p, []any{[]any{ends[0].address, ends[0].port}, []any{ends[1].address, ends[1].port}}})
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
func columnNames() []string {
	out := []string{}
	for _, pair := range schema.Columns {
		out = append(out, *pair[0])
	}
	return out
}
func eventSchema() string {
	cols := []string{"id INTEGER PRIMARY KEY"}
	for _, name := range columnNames() {
		kind := "TEXT"
		if numericColumns[name] {
			kind = "INTEGER"
		}
		if name == "raw" {
			kind = "BLOB"
		}
		cols = append(cols, name+" "+kind)
	}
	return "CREATE TABLE IF NOT EXISTS events (" + strings.Join(cols, ",") + ")"
}
func NewStore(path, stream string, pool *Pool) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	if stat, err := os.Lstat(path); err == nil && stat.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("事件库不能是符号链接")
	}
	address := "file:" + filepath.ToSlash(path) + "?_busy_timeout=8000&_journal_mode=WAL&_synchronous=FULL&_cache_size=-65536&_auto_vacuum=incremental"
	w, err := sql.Open("aegis-sqlite", address)
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	s := &Store{Path: path, Stream: stream, Writer: w, Pool: pool, Cap: 8 << 30, changed: make(chan struct{}, 1)}
	ok := false
	defer func() {
		if !ok {
			w.Close()
		}
	}()
	for _, statement := range []string{eventSchema(), "CREATE TABLE IF NOT EXISTS event_state(key TEXT PRIMARY KEY,value TEXT NOT NULL)", "PRAGMA wal_autocheckpoint=4096", "PRAGMA journal_size_limit=67108864"} {
		if _, err = w.Exec(statement); err != nil {
			return nil, err
		}
	}
	rows, err := w.Query("PRAGMA table_info(events)")
	if err != nil {
		return nil, err
	}
	existing := map[string]bool{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var fallback any
		if err = rows.Scan(&cid, &name, &typ, &notnull, &fallback, &pk); err != nil {
			rows.Close()
			return nil, err
		}
		existing[name] = true
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	for _, name := range columnNames() {
		if !existing[name] {
			kind := "TEXT"
			if numericColumns[name] {
				kind = "INTEGER"
			}
			if _, err = w.Exec("ALTER TABLE events ADD COLUMN " + name + " " + kind); err != nil {
				return nil, err
			}
		}
	}
	for _, statement := range []string{"CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)", "CREATE INDEX IF NOT EXISTS idx_events_tier_ts ON events(tier,ts)", "CREATE INDEX IF NOT EXISTS idx_events_type_ts ON events(type,ts)", "CREATE INDEX IF NOT EXISTS idx_events_flow_ts ON events(flow_id,ts)", "CREATE INDEX IF NOT EXISTS idx_events_session_ts ON events(session_id,ts) WHERE session_id IS NOT NULL", "CREATE INDEX IF NOT EXISTS idx_events_community_ts ON events(community,ts)", "CREATE UNIQUE INDEX IF NOT EXISTS idx_events_key ON events(event_key) WHERE event_key IS NOT NULL"} {
		if _, err = w.Exec(statement); err != nil {
			return nil, err
		}
	}
	var saved string
	if w.QueryRow("SELECT value FROM event_state WHERE key='stream_cursor'").Scan(&saved) == nil {
		if err = decode([]byte(saved), &s.cursor); err != nil {
			return nil, errors.New("事件读取位置损坏")
		}
	}
	if w.QueryRow("SELECT value FROM event_state WHERE key='stream_cutoff'").Scan(&saved) == nil && saved != "null" {
		if err = decode([]byte(saved), &s.cutoff); err != nil || s.cutoff.Offset < 0 {
			return nil, errors.New("历史清理起点记录损坏")
		}
	}
	var settings Object
	if readJSON(path+".settings.json", &settings) == nil {
		if cap := integer(settings["cap_mib"]); cap >= 64 && cap <= 1048576 {
			s.Cap = cap << 20
		}
	}
	r, err := sql.Open("aegis-sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro&_query_only=1&_busy_timeout=1000&_cache_size=-2048")
	if err != nil {
		return nil, err
	}
	r.SetMaxOpenConns(2*WorkerCount() + 1)
	r.SetMaxIdleConns(9)
	s.Readers = r
	if err = r.Ping(); err != nil {
		r.Close()
		return nil, err
	}
	ok = true
	return s, nil
}
func (s *Store) Close() error {
	r := s.Readers.Close()
	if err := s.Writer.Close(); r == nil {
		r = err
	}
	return r
}
func (s *Store) Error() string { s.stateMu.RLock(); defer s.stateMu.RUnlock(); return s.writeError }
func (s *Store) fail(err error) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.writeError = err.Error()
	var e sqlite.Error
	if errors.As(err, &e) && (e.Code == sqlite.ErrCorrupt || e.Code == sqlite.ErrNotADB) {
		s.blocked = true
	}
}
func (s *Store) Lag() int64 {
	info, err := os.Stat(s.Stream)
	if err != nil {
		return -1
	}
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return max(0, info.Size()-s.cursor.Offset)
}
func (s *Store) RecentLag() int64 {
	info, err := os.Stat(s.Stream)
	if err != nil {
		return -1
	}
	dev, ino := fileIdentity(info)
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	offset := int64(0)
	for _, cursor := range []Cursor{s.cursor, s.recentCursor} {
		if cursor.Device == dev && cursor.Inode == ino && cursor.Offset <= info.Size() {
			offset = max(offset, cursor.Offset)
		}
	}
	return max(0, info.Size()-offset)
}
func cursorAt(file *os.File, info os.FileInfo, offset int64) (Cursor, error) {
	device, inode := fileIdentity(info)
	tail := make([]byte, min(int64(128), offset))
	if len(tail) > 0 {
		if _, err := file.ReadAt(tail, offset-int64(len(tail))); err != nil {
			return Cursor{}, err
		}
	}
	hash := sha256.Sum256(tail)
	return Cursor{device, inode, offset, hex.EncodeToString(hash[:])}, nil
}
func (s *Store) Ingest(ctx context.Context) (bool, error) {
	s.stateMu.RLock()
	blocked, cursor, started := s.blocked, s.cursor, s.started
	s.stateMu.RUnlock()
	if blocked {
		return false, errors.New("事件库结构故障，等待离线修复")
	}
	f, err := os.Open(s.Stream)
	if err != nil {
		return false, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	dev, ino := fileIdentity(info)
	if !started || cursor.Device != dev || cursor.Inode != ino || cursor.Offset > info.Size() {
		valid := false
		if cursor.Device == dev && cursor.Inode == ino && cursor.Offset <= info.Size() {
			expected, e := cursorAt(f, info, cursor.Offset)
			valid = e == nil && expected == cursor
		}
		if !valid {
			cursor.Offset = 0
			if s.cutoff.Device == dev && s.cutoff.Inode == ino && info.Size() >= s.cutoff.Offset {
				cursor.Offset = max(cursor.Offset, s.cutoff.Offset)
			}
		}
	}
	if cursor.Offset == info.Size() {
		s.stateMu.Lock()
		s.cursor = cursor
		s.started = true
		s.writeError = ""
		s.stateMu.Unlock()
		return false, nil
	}
	data := make([]byte, min(int64(4<<20), info.Size()-cursor.Offset))
	n, err := f.ReadAt(data, cursor.Offset)
	if err != nil && err != io.EOF {
		return false, err
	}
	data = data[:n]
	edge := bytesLastNewline(data)
	if edge < 0 {
		if len(data) >= 4<<20 {
			return false, errors.New("单条事件超过读取边界")
		}
		return false, nil
	}
	data = boundedEventBlock(data[:edge+1], 1000)
	flat, err := s.prepareBlock(ctx, data)
	if err != nil {
		return false, err
	}
	// The committed cursor advances only with its complete input batch, including rejected lines.
	next, err := cursorAt(f, info, cursor.Offset+int64(len(data)))
	if err != nil {
		return false, err
	}
	s.Gate.Lock()
	err = s.insert(ctx, flat, next)
	s.Gate.Unlock()
	if err != nil {
		s.fail(err)
		return false, err
	}
	s.stateMu.Lock()
	s.cursor = next
	s.started = true
	s.writeError = ""
	s.stateMu.Unlock()
	s.publish()
	return next.Offset < info.Size(), nil
}
func (s *Store) prepareBlock(ctx context.Context, data []byte) ([]*Prepared, error) {
	lines := strings.Split(string(data), "\n")
	lines = lines[:len(lines)-1]
	chunks := [][]string{}
	for i := 0; i < len(lines); i += 128 {
		chunks = append(chunks, lines[i:min(i+128, len(lines))])
	}
	batches, err := parallelMap(ctx, s.Pool, chunks, func(batch []string) ([]*Prepared, error) {
		out := []*Prepared{}
		for _, line := range batch {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if strings.TrimSpace(line) == "" {
				continue
			}
			item, e := ParseEvent([]byte(line))
			if e != nil {
				var syntax *json.SyntaxError
				if errors.As(e, &syntax) {
					continue
				}
				return nil, e
			}
			if item != nil {
				out = append(out, item)
			}
		}
		return out, nil
	})
	if err != nil {
		return nil, err
	}
	flat := []*Prepared{}
	for _, batch := range batches {
		flat = append(flat, batch...)
	}
	return flat, nil
}
func (s *Store) publish() {
	s.Revision.Add(1)
	select {
	case s.changed <- struct{}{}:
	default:
	}
}
func boundedEventBlock(data []byte, limit int) []byte {
	rows := 0
	for i, value := range data {
		if value == '\n' {
			rows++
			if rows == limit {
				return data[:i+1]
			}
		}
	}
	return data
}

// Recent rows are durable but never advance the ordered history checkpoint.
// Restarting or skipping ahead here is safe because history still replays every
// retained complete line and event_key deduplicates the overlapping inserts.
func (s *Store) IngestRecent(ctx context.Context) error {
	s.stateMu.RLock()
	cursor, recent, cutoff, blocked := s.cursor, s.recentCursor, s.cutoff, s.blocked
	s.stateMu.RUnlock()
	if blocked {
		return errors.New("事件库结构故障，等待离线修复")
	}
	f, err := os.Open(s.Stream)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	dev, ino := fileIdentity(info)
	floor := int64(0)
	if cursor.Device == dev && cursor.Inode == ino && cursor.Offset <= info.Size() {
		floor = cursor.Offset
	}
	if cutoff.Device == dev && cutoff.Inode == ino && cutoff.Offset <= info.Size() {
		floor = max(floor, cutoff.Offset)
	}
	if info.Size()-floor <= 8<<20 {
		return nil
	}
	start := max(floor, info.Size()-(256<<10))
	if recent.Device == dev && recent.Inode == ino && recent.Offset <= info.Size() {
		if expected, e := cursorAt(f, info, recent.Offset); e == nil && expected == recent {
			start = max(start, recent.Offset)
		}
	}
	if start >= info.Size() {
		return nil
	}
	data := make([]byte, info.Size()-start)
	if _, err = f.ReadAt(data, start); err != nil {
		return err
	}
	if start > 0 {
		previous := []byte{0}
		if _, err = f.ReadAt(previous, start-1); err != nil {
			return err
		}
		if previous[0] != '\n' {
			first := bytesFirstNewline(data)
			if first < 0 {
				return nil
			}
			start += int64(first + 1)
			data = data[first+1:]
		}
	}
	edge := bytesLastNewline(data)
	if edge < 0 {
		return nil
	}
	data = boundedEventBlock(data[:edge+1], 1000)
	records, err := s.prepareBlock(ctx, data)
	if err != nil {
		return err
	}
	next, err := cursorAt(f, info, start+int64(len(data)))
	if err != nil {
		return err
	}
	s.Gate.Lock()
	err = s.insertBatch(ctx, records, nil)
	s.Gate.Unlock()
	if err != nil {
		return err
	}
	s.stateMu.Lock()
	s.recentCursor = next
	s.stateMu.Unlock()
	s.publish()
	return nil
}
func bytesFirstNewline(data []byte) int {
	for i, value := range data {
		if value == '\n' {
			return i
		}
	}
	return -1
}
func bytesLastNewline(b []byte) int {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == '\n' {
			return i
		}
	}
	return -1
}
func (s *Store) insert(ctx context.Context, records []*Prepared, cursor Cursor) error {
	return s.insertBatch(ctx, records, &cursor)
}
func (s *Store) insertBatch(ctx context.Context, records []*Prepared, cursor *Cursor) error {
	tx, err := s.Writer.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	names := columnNames()
	statement, err := tx.PrepareContext(ctx, "INSERT INTO events ("+strings.Join(names, ",")+") VALUES ("+strings.TrimSuffix(strings.Repeat("?,", len(names)), ",")+") ON CONFLICT(event_key) WHERE event_key IS NOT NULL DO NOTHING")
	if err != nil {
		return err
	}
	defer statement.Close()
	for _, record := range records {
		if _, err = statement.ExecContext(ctx, record.Values...); err != nil {
			return err
		}
	}
	if cursor != nil {
		encoded, err := json.Marshal(cursor)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO event_state VALUES('stream_cursor',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", string(encoded)); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) Run(ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	maintenance := time.Now()
	for {
		if err := s.IngestRecent(ctx); err != nil {
			s.fail(err)
		}
		more, err := s.Ingest(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			s.fail(err)
		}
		if err == nil && time.Since(maintenance) > 5*time.Minute {
			s.maintain(ctx)
			maintenance = time.Now()
		}
		if more && err == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (s *Store) maintain(ctx context.Context) {
	s.Gate.Lock()
	defer s.Gate.Unlock()
	if s.Error() != "" {
		return
	}
	low := now() - 30*24*3600
	_, err := s.Writer.ExecContext(ctx, "DELETE FROM events WHERE id IN (SELECT id FROM events WHERE ts<? ORDER BY ts LIMIT 5000)", low*1000)
	if err != nil {
		s.fail(err)
		return
	}
	var pages, free, size int64
	if s.Writer.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages) != nil {
		return
	}
	s.Writer.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&free)
	s.Writer.QueryRowContext(ctx, "PRAGMA page_size").Scan(&size)
	s.stateMu.RLock()
	capacity := s.Cap
	s.stateMu.RUnlock()
	if (pages-free)*size > capacity {
		s.Writer.ExecContext(ctx, "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY tier DESC,ts LIMIT 5000)")
	}
}
func (s *Store) Stats(ctx context.Context) (Object, error) {
	var count int64
	var low, high sql.NullFloat64
	err := s.Readers.QueryRowContext(ctx, "SELECT COUNT(*),MIN(ts),MAX(ts) FROM events").Scan(&count, &low, &high)
	if err != nil {
		return nil, err
	}
	size := int64(0)
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if info, e := os.Stat(s.Path + suffix); e == nil {
			size += info.Size()
		}
	}
	s.stateMu.RLock()
	capacity := s.Cap
	s.stateMu.RUnlock()
	return Object{"path": s.Path, "size": size, "rows": count, "oldest": low.Float64 / 1000, "newest": high.Float64 / 1000, "cap": capacity, "error": s.Error(), "min_cap_mib": 64, "max_cap_mib": 1048576}, nil
}

func queryRows(ctx context.Context, q Querier, statement string, args ...any) ([]Object, error) {
	rows, err := q.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	names, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	out := []Object{}
	for rows.Next() {
		values := make([]any, len(names))
		pointers := make([]any, len(names))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err = rows.Scan(pointers...); err != nil {
			return nil, err
		}
		row := Object{}
		for i, name := range names {
			row[name] = values[i]
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
func readRecordRow(row Object, list bool, network bool) (Object, error) {
	r := Object{}
	for _, pair := range schema.Columns {
		column := *pair[0]
		if pair[1] != nil && column != "raw" {
			r[*pair[1]] = get(row, column, "")
		}
	}
	r["ts"] = number(row["ts"]) / 1000
	r["sig_id"] = row["sid"]
	r["dns"] = get(row, "dnsname", "")
	r["file"] = get(row, "fname", "")
	r["size"] = get(row, "fsize", "")
	r["community_id"] = get(row, "community", "")
	setLevel(r)
	if r["type"] == "flow" {
		r["sig"] = flowSummary(text(r["app"]), text(r["proto"]), text(r["state"]), text(r["reason"]), text(r["sig"]))
		if text(r["native_uid"]) != "" {
			delete(r, "flow_start")
			delete(r, "flow_end")
		}
	}
	r["tuple_hash"] = nil
	if text(r["session_id"]) == "" && text(r["community"]) == "" {
		hashed := tupleHash(r["src"], r["sport"], r["dst"], r["dport"], r["proto"])
		if integer(r["flow_id"]) <= 0 {
			r["tuple_hash"] = hashed
		} else if hashed != nil {
			r["association_flow_id"] = text(r["flow_id"])
		}
	}
	key := text(row["id"]) + ":" + text(present(row["event_key"], "t"+text(row["ts"])))
	r["record_id"] = key
	if list {
		fields := strings.Fields("ts type sev sig_id sig src sport dst dport proto app action reason state session_id native_uid level record_id")
		if network {
			fields = append(fields, "sni", "dns")
		}
		compact := Object{}
		for _, field := range fields {
			if v, ok := r[field]; ok {
				compact[field] = v
			}
		}
		return compact, nil
	}
	if data, ok := row["raw"].([]byte); ok && len(data) > 0 {
		raw, err := decompress(data)
		if err != nil {
			return nil, err
		}
		r["_raw"] = string(raw)
	}
	return r, nil
}
func (s *Store) Record(ctx context.Context, key string) (Object, error) {
	id, expected, ok := strings.Cut(key, ":")
	if !ok || len(id) > 19 {
		return nil, errors.New("事件标识无效")
	}
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n < 1 {
		return nil, errors.New("事件标识无效")
	}
	rows, err := queryRows(ctx, s.Readers, "SELECT * FROM events WHERE id=?", n)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errors.New("事件已不存在或已超过保留范围")
	}
	actual := text(present(rows[0]["event_key"], "t"+text(rows[0]["ts"])))
	if subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) != 1 {
		return nil, errors.New("事件已不存在或已超过保留范围")
	}
	record, err := readRecordRow(rows[0], false, false)
	if err != nil {
		return nil, err
	}
	rawText := text(record["_raw"])
	delete(record, "_raw")
	var raw any = clone(record)
	if rawText != "" {
		if err = decode([]byte(rawText), &raw); err != nil {
			return nil, err
		}
	}
	return Object{"record": record, "raw": raw, "raw_text": rawText}, nil
}
func (s *Store) SetCapacity(ctx context.Context, mib int64) (Object, error) {
	if mib < 64 || mib > 1048576 {
		return nil, errors.New("容量必须为 64 至 1048576 MiB 的整数")
	}
	if err := writeJSON(s.Path+".settings.json", Object{"cap_mib": mib}); err != nil {
		return nil, err
	}
	s.stateMu.Lock()
	s.Cap = mib << 20
	s.stateMu.Unlock()
	return s.Stats(ctx)
}
func sqliteVersion(ctx context.Context, db *sql.DB) string {
	var version string
	db.QueryRowContext(ctx, "SELECT sqlite_version()").Scan(&version)
	return version
}

var _ = fmt.Sprint
var _ = url.Values{}
