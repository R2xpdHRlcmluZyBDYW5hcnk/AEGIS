package console

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"

	sqlite "github.com/mattn/go-sqlite3"
)

func recoveryDSN(path string, readonly bool) string {
	u := url.URL{Scheme: "file", Path: path}
	q := u.Query()
	if readonly {
		q.Set("mode", "ro")
	}
	q.Set("_busy_timeout", "5000")
	u.RawQuery = q.Encode()
	return u.String()
}
func quoteIdentifier(name string) string { return `"` + strings.ReplaceAll(name, `"`, `""`) + `"` }
func withinPath(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel)
}

func verifyRecoverySnapshot(snapshot string) (Object, string, error) {
	var manifest Object
	if err := readJSON(filepath.Join(snapshot, "snapshot.json"), &manifest); err != nil {
		return nil, "", err
	}
	name := filepath.Base(text(manifest["database_path"]))
	if name == "." || name == "" || strings.ContainsAny(name, "/\\") {
		return nil, "", errors.New("快照数据库名称无效")
	}
	root := filepath.Join(snapshot, "original")
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, "", errors.New("快照原件目录无效")
	}
	files := object(manifest["files"])
	if files[name] == nil {
		return nil, "", errors.New("快照缺少主数据库")
	}
	for item, value := range files {
		if item != name && item != name+"-wal" && item != name+"-shm" {
			return nil, "", errors.New("快照只能包含数据库及其 WAL/SHM")
		}
		path := filepath.Join(root, item)
		info, err := os.Lstat(path)
		entry := object(value)
		if err != nil || !info.Mode().IsRegular() || info.Size() != integer(entry["bytes"]) {
			return nil, "", errors.New("快照文件类型或长度校验失败")
		}
		digest, err := digestFile(path)
		if err != nil || digest != entry["sha256"] {
			return nil, "", errors.New("快照摘要校验失败")
		}
	}
	return manifest, name, nil
}

func recoveryDatabase(path string, readonly bool) (*sql.DB, error) {
	db, err := sql.Open("aegis-sqlite", recoveryDSN(path, readonly))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec("PRAGMA cache_size=-65536; PRAGMA temp_store=FILE; PRAGMA synchronous=FULL;"); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func recoveryFingerprints(ctx context.Context, db *sql.DB) (Object, error) {
	rows, err := db.QueryContext(ctx, "SELECT name,sql FROM sqlite_schema WHERE type='table' ORDER BY name")
	if err != nil {
		return nil, err
	}
	definitions := [][2]string{}
	for rows.Next() {
		var name string
		var definition sql.NullString
		if err = rows.Scan(&name, &definition); err != nil {
			rows.Close()
			return nil, err
		}
		definitions = append(definitions, [2]string{name, definition.String})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	result := Object{}
	for _, definition := range definitions {
		name := definition[0]
		order := " ORDER BY rowid"
		if strings.Contains(strings.ToUpper(definition[1]), "WITHOUT ROWID") {
			order = ""
		}
		rows, err := db.QueryContext(ctx, "SELECT * FROM "+quoteIdentifier(name)+" NOT INDEXED"+order)
		if err != nil {
			return nil, err
		}
		columns, err := rows.Columns()
		if err != nil {
			rows.Close()
			return nil, err
		}
		hash := sha256.New()
		count := int64(0)
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range values {
				pointers[i] = &values[i]
			}
			if err = rows.Scan(pointers...); err != nil {
				rows.Close()
				return nil, err
			}
			for _, value := range values {
				var data []byte
				var kind byte
				switch v := value.(type) {
				case nil:
					kind = 'n'
				case int64:
					kind = 'i'
					data = make([]byte, 8)
					binary.BigEndian.PutUint64(data, uint64(v))
				case float64:
					kind = 'f'
					data = make([]byte, 8)
					binary.BigEndian.PutUint64(data, math.Float64bits(v))
				case []byte:
					kind = 'b'
					data = v
				case string:
					kind = 's'
					data = []byte(v)
				default:
					rows.Close()
					return nil, errors.New("不支持的 SQLite 值类型")
				}
				header := make([]byte, 9)
				header[0] = kind
				binary.BigEndian.PutUint64(header[1:], uint64(len(data)))
				hash.Write(header)
				hash.Write(data)
			}
			hash.Write([]byte{0xff})
			count++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		result[name] = Object{"rows": count, "sha256": hex.EncodeToString(hash.Sum(nil))}
	}
	return result, nil
}

func rebuildRecoveryIndexes(ctx context.Context, source, candidate string) (Object, error) {
	old, err := recoveryDatabase(source, true)
	if err != nil {
		return nil, err
	}
	defer old.Close()
	before, err := recoveryFingerprints(ctx, old)
	if err != nil {
		return nil, err
	}
	newDB, err := recoveryDatabase(candidate, false)
	if err != nil {
		return nil, err
	}
	defer newDB.Close()
	if _, err = newDB.ExecContext(ctx, "ATTACH DATABASE ? AS original", recoveryDSN(source, true)); err != nil {
		return nil, err
	}
	type schemaEntry struct{ kind, name, sql string }
	schema := []schemaEntry{}
	rows, err := old.QueryContext(ctx, "SELECT type,name,sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY rowid")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var e schemaEntry
		if err = rows.Scan(&e.kind, &e.name, &e.sql); err != nil {
			rows.Close()
			return nil, err
		}
		schema = append(schema, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	tx, err := newDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	for _, entry := range schema {
		if entry.kind != "table" || entry.name == "sqlite_sequence" {
			continue
		}
		if _, err = tx.ExecContext(ctx, entry.sql); err != nil {
			return nil, err
		}
		cols, err := old.QueryContext(ctx, "PRAGMA table_info("+quoteIdentifier(entry.name)+")")
		if err != nil {
			return nil, err
		}
		names := []string{}
		for cols.Next() {
			var cid, notnull, pk int
			var name, typ string
			var defaultValue any
			if err = cols.Scan(&cid, &name, &typ, &notnull, &defaultValue, &pk); err != nil {
				cols.Close()
				return nil, err
			}
			names = append(names, quoteIdentifier(name))
		}
		err = cols.Err()
		cols.Close()
		if err != nil {
			return nil, err
		}
		order := " ORDER BY rowid"
		if !strings.Contains(strings.ToUpper(entry.sql), "WITHOUT ROWID") {
			names = append([]string{"rowid"}, names...)
		} else {
			order = ""
		}
		selected := strings.Join(names, ",")
		if _, err = tx.ExecContext(ctx, "INSERT INTO main."+quoteIdentifier(entry.name)+"("+selected+") SELECT "+selected+" FROM original."+quoteIdentifier(entry.name)+" NOT INDEXED"+order); err != nil {
			return nil, err
		}
	}
	if before["sqlite_sequence"] != nil {
		if _, err = tx.ExecContext(ctx, `CREATE TABLE "_recovery_sequence_probe"(id INTEGER PRIMARY KEY AUTOINCREMENT); DROP TABLE "_recovery_sequence_probe"; DELETE FROM sqlite_sequence; INSERT INTO main.sqlite_sequence SELECT * FROM original.sqlite_sequence;`); err != nil {
			return nil, err
		}
	}
	for _, entry := range schema {
		if entry.kind != "table" {
			if _, err = tx.ExecContext(ctx, entry.sql); err != nil {
				return nil, err
			}
		}
	}
	for _, setting := range []string{"application_id", "user_version"} {
		var value int64
		if err = old.QueryRowContext(ctx, "PRAGMA "+setting).Scan(&value); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, fmt.Sprintf("PRAGMA %s=%d", setting, value)); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	after, err := recoveryFingerprints(ctx, newDB)
	if err != nil {
		return nil, err
	}
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	if !bytes.Equal(a, b) {
		return nil, errors.New("恢复后表值与源文件不一致")
	}
	return Object{"source_table_fingerprints": before, "all_table_values_preserved": true}, nil
}

var recoveryInsert = regexp.MustCompile(`(?is)^\s*INSERT\b`)
var recoveryValues = regexp.MustCompile(`(?i)\bVALUES\s*\(`)

func normalizeRecoveredSQL(statement []byte) ([]byte, error) {
	if !recoveryInsert.Match(statement) {
		return statement, nil
	}
	span := recoveryValues.FindIndex(statement)
	if span == nil {
		return statement, nil
	}
	var result bytes.Buffer
	result.Write(statement[:span[1]])
	for pos := span[1]; pos < len(statement); {
		if statement[pos] != '\'' {
			result.WriteByte(statement[pos])
			pos++
			continue
		}
		start := pos
		pos++
		value := []byte{}
		closed := false
		for pos < len(statement) {
			v := statement[pos]
			pos++
			if v == '\'' {
				if pos < len(statement) && statement[pos] == '\'' {
					value = append(value, '\'')
					pos++
					continue
				}
				closed = true
				break
			}
			value = append(value, v)
		}
		if !closed {
			return nil, errors.New("恢复 SQL 字符串未结束")
		}
		unsafe := !utf8.Valid(value)
		for _, v := range value {
			unsafe = unsafe || v < 32
		}
		blob := start > 0 && (statement[start-1] == 'x' || statement[start-1] == 'X')
		if unsafe && !blob {
			result.WriteString("CAST(X'")
			result.WriteString(hex.EncodeToString(value))
			result.WriteString("' AS TEXT)")
		} else {
			result.Write(statement[start:pos])
		}
	}
	return result.Bytes(), nil
}

func relayRecoveredSQL(source io.Reader, execute func([]byte) error) error {
	reader := bufio.NewReaderSize(source, 32768)
	statement := []byte{}
	for {
		line, err := reader.ReadSlice('\n')
		if len(statement)+len(line) > 64<<20 {
			return errors.New("恢复 SQL 超过缓冲限制")
		}
		statement = append(statement, line...)
		if err != bufio.ErrBufferFull && len(statement) > 0 {
			if statement[0] == '.' {
				if strings.TrimSpace(string(statement)) != ".dbconfig defensive off" {
					return errors.New("恢复 SQL 包含不支持的 shell 指令")
				}
				statement = nil
			} else if sqliteStatementComplete(bytes.ReplaceAll(statement, []byte{0}, []byte{' '})) {
				normalized, e := normalizeRecoveredSQL(statement)
				if e != nil {
					return e
				}
				if e = execute(normalized); e != nil {
					return e
				}
				statement = nil
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil && err != bufio.ErrBufferFull {
			return err
		}
	}
	if len(bytes.TrimSpace(statement)) > 0 {
		return errors.New("恢复输出在 SQL 语句中途结束")
	}
	return nil
}

var recoveryDriver sync.Once

func importRecoveredDatabase(ctx context.Context, cli, source, target, logs string) error {
	recoveryDriver.Do(func() {
		sql.Register("aegis-recovery-sqlite", &sqlite.SQLiteDriver{ConnectHook: func(conn *sqlite.SQLiteConn) error {
			conn.RegisterAuthorizer(func(action int, a, b, c string) int {
				if action == sqlite.SQLITE_ATTACH || action == sqlite.SQLITE_DETACH || action == sqlite.SQLITE_FUNCTION && strings.EqualFold(b, "load_extension") {
					return sqlite.SQLITE_DENY
				}
				return sqlite.SQLITE_OK
			})
			return nil
		}})
	})
	db, err := sql.Open("aegis-recovery-sqlite", recoveryDSN(target, false))
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err = db.ExecContext(ctx, "PRAGMA cache_size=-65536; PRAGMA temp_store=FILE; PRAGMA synchronous=FULL;"); err != nil {
		return err
	}
	log, err := os.OpenFile(filepath.Join(logs, "recover.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer log.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	producer := exec.CommandContext(ctx, cli, "-readonly", source, ".recover --ignore-freelist")
	configureCommand(producer)
	producer.Stderr = log
	pipe, err := producer.StdoutPipe()
	if err != nil {
		return err
	}
	if err = producer.Start(); err != nil {
		pipe.Close()
		return err
	}
	err = relayRecoveredSQL(pipe, func(sqlBytes []byte) error { _, e := db.ExecContext(ctx, string(sqlBytes)); return e })
	pipe.Close()
	if err != nil {
		cancel()
	}
	code := producer.Wait()
	if err != nil || code != nil {
		os.WriteFile(filepath.Join(logs, "import.log"), []byte(fmt.Sprint(errors.Join(err, code))), 0600)
		return errors.New("恢复导入失败，请检查私有日志")
	}
	return nil
}

func validateRecoveredDatabase(ctx context.Context, candidate, reference string) (Object, error) {
	db, err := recoveryDatabase(candidate, true)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, "PRAGMA integrity_check")
	if err != nil {
		return nil, err
	}
	checks := []string{}
	for rows.Next() {
		var value string
		if err = rows.Scan(&value); err != nil {
			rows.Close()
			return nil, err
		}
		checks = append(checks, value)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(checks) != 1 || checks[0] != "ok" {
		return nil, errors.New("恢复库完整性检查失败")
	}
	counts := Object{}
	tables, err := queryRows(ctx, db, "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'")
	if err != nil {
		return nil, err
	}
	for _, table := range tables {
		var count int64
		name := text(table["name"])
		if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+quoteIdentifier(name)).Scan(&count); err != nil {
			return nil, err
		}
		counts[name] = count
	}
	foreign, err := queryRows(ctx, db, "PRAGMA foreign_key_check")
	if err != nil {
		return nil, err
	}
	report := Object{"integrity_check": checks, "table_counts": counts, "foreign_key_violations": len(foreign), "activation_performed": false, "completeness_proven": false}
	if reference != "" {
		if _, err = db.ExecContext(ctx, "ATTACH DATABASE ? AS reference", recoveryDSN(reference, true)); err != nil {
			return nil, err
		}
		comparison := Object{}
		for key, query := range map[string]string{"expected": "SELECT COUNT(*) FROM reference.expected", "missing": "SELECT COUNT(*) FROM reference.expected r LEFT JOIN events e ON e.id=r.id WHERE e.id IS NULL", "unexpected": "SELECT COUNT(*) FROM events e LEFT JOIN reference.expected r ON r.id=e.id WHERE r.id IS NULL", "timestamp_mismatches": "SELECT COUNT(*) FROM events e JOIN reference.expected r ON r.id=e.id WHERE e.ts IS NOT r.ts"} {
			var count int64
			if err = db.QueryRowContext(ctx, query).Scan(&count); err != nil {
				return nil, err
			}
			comparison[key] = count
		}
		report["identity_comparison"] = comparison
	}
	return report, nil
}

func RecoverEventDatabase(ctx context.Context, snapshot, output, cli, reference string, indexes bool) (Object, error) {
	snapshot, err := filepath.EvalSymlinks(snapshot)
	if err != nil {
		return nil, err
	}
	snapshot, err = filepath.Abs(snapshot)
	if err != nil {
		return nil, err
	}
	manifest, name, err := verifyRecoverySnapshot(snapshot)
	if err != nil {
		return nil, err
	}
	output, err = filepath.Abs(output)
	if err != nil {
		return nil, err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(output))
	if err != nil {
		return nil, err
	}
	output = filepath.Join(parent, filepath.Base(output))
	if withinPath(snapshot, output) || withinPath(output, snapshot) {
		return nil, errors.New("恢复输出必须与快照原件分离")
	}
	if err = os.Mkdir(output, 0700); err != nil {
		return nil, err
	}
	work := filepath.Join(output, "input")
	if err = os.Mkdir(work, 0700); err != nil {
		return nil, err
	}
	for _, item := range []string{name, name + "-wal"} {
		if value := object(manifest["files"])[item]; value != nil {
			target := filepath.Join(work, item)
			if err = copyRecoveryFile(filepath.Join(snapshot, "original", item), target); err != nil {
				return nil, err
			}
			hash, e := digestFile(target)
			if e != nil || hash != object(value)["sha256"] {
				return nil, errors.New("恢复工作副本摘要不匹配")
			}
		}
	}
	candidate := filepath.Join(output, "candidate.db")
	var extra Object
	if indexes {
		extra, err = rebuildRecoveryIndexes(ctx, filepath.Join(work, name), candidate)
	} else {
		if cli == "" {
			return nil, errors.New("页级恢复需要指定可信 SQLite CLI")
		}
		cli, err = filepath.Abs(cli)
		if err != nil {
			return nil, err
		}
		probe, e := os.MkdirTemp(output, "cli-probe-")
		if e != nil {
			return nil, e
		}
		defer os.RemoveAll(probe)
		input := filepath.Join(probe, "input.db")
		db, e := recoveryDatabase(input, false)
		if e != nil {
			return nil, e
		}
		_, e = db.ExecContext(ctx, "CREATE TABLE probe(id INTEGER PRIMARY KEY AUTOINCREMENT,value TEXT); INSERT INTO probe(value) VALUES('verified');")
		db.Close()
		if e != nil {
			return nil, e
		}
		if err = importRecoveredDatabase(ctx, cli, input, filepath.Join(probe, "output.db"), probe); err != nil {
			return nil, err
		}
		verified, e := recoveryDatabase(filepath.Join(probe, "output.db"), true)
		if e != nil {
			return nil, e
		}
		var id int
		var value string
		e = verified.QueryRowContext(ctx, "SELECT id,value FROM probe").Scan(&id, &value)
		verified.Close()
		if e != nil || id != 1 || value != "verified" {
			return nil, errors.New("恢复工具自检失败")
		}
		err = importRecoveredDatabase(ctx, cli, filepath.Join(work, name), candidate, output)
	}
	if err != nil {
		return nil, err
	}
	report, err := validateRecoveredDatabase(ctx, candidate, reference)
	if err != nil {
		return nil, err
	}
	for key, value := range extra {
		report[key] = value
	}
	if err = writeJSON(filepath.Join(output, "validation.json"), report); err != nil {
		return nil, err
	}
	return report, nil
}

func RunRecovery(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("recover-event-db", flag.ContinueOnError)
	snapshot := flags.String("snapshot", "", "封存快照")
	output := flags.String("output", "", "全新恢复目录")
	cli := flags.String("sqlite-cli", "", "可信 SQLite CLI")
	reference := flags.String("reference", "", "事件身份对照库")
	indexes := flags.Bool("rebuild-indexes", false, "仅重建损坏索引")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *snapshot == "" || *output == "" || !*indexes && *cli == "" {
		return errors.New("请指定封存快照、全新输出目录及恢复方式")
	}
	if *reference != "" {
		var err error
		*reference, err = filepath.Abs(*reference)
		if err != nil {
			return err
		}
	}
	report, err := RecoverEventDatabase(ctx, *snapshot, *output, *cli, *reference, *indexes)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(report)
}

func copyRecoveryFile(source, target string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer output.Close()
	if _, err = io.Copy(output, input); err != nil {
		return err
	}
	return output.Sync()
}
