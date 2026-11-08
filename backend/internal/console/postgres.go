package console

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

//go:embed postgres_functions.sql
var postgresFunctions string

var postgresFloat = map[string]bool{"ts": true, "flow_age": true, "flow_start": true, "flow_end": true, "observed_first": true, "observed_last": true, "packet_ts": true}

func postgresText(value any) string {
	if b, ok := value.(bool); ok {
		if b {
			return "1"
		}
		return "0"
	}
	// PostgreSQL text cannot represent NUL. The evidence BLOB remains exact;
	// only searchable display fields replace unsupported text code points.
	return strings.ReplaceAll(strings.ToValidUTF8(text(value), "\uFFFD"), "\x00", "\uFFFD")
}

func postgresEventValue(name string, value any) any {
	if value == nil || name == "raw" {
		return value
	}
	if !numericColumns[name] {
		return postgresText(value)
	}
	if b, ok := value.(bool); ok {
		if b {
			value = int64(1)
		} else {
			value = int64(0)
		}
	}
	if postgresFloat[name] {
		return number(value)
	}
	return integer(value)
}

func postgresConfig(address string, readonly bool) (*pgx.ConnConfig, error) {
	cfg, err := pgx.ParseConfig(address)
	if err != nil {
		return nil, errors.New("PostgreSQL 连接配置无效")
	}
	if cfg.RuntimeParams == nil {
		cfg.RuntimeParams = map[string]string{}
	}
	cfg.RuntimeParams["search_path"] = "aegis,public"
	cfg.RuntimeParams["timezone"] = "UTC"
	cfg.RuntimeParams["statement_timeout"] = "30000"
	cfg.RuntimeParams["idle_in_transaction_session_timeout"] = "60000"
	cfg.RuntimeParams["application_name"] = "aegis-console"
	if readonly {
		cfg.RuntimeParams["default_transaction_read_only"] = "on"
		// Background queries retain their task lifetime and cancellation rules.
		// Parallel snapshot connections can stay idle while another helper runs.
		cfg.RuntimeParams["statement_timeout"] = "0"
		cfg.RuntimeParams["idle_in_transaction_session_timeout"] = "0"
	}
	cfg.ConnectTimeout = 8 * time.Second
	return cfg, nil
}

func postgresSchema() string {
	cols := []string{"id BIGSERIAL", "event_time TIMESTAMPTZ NOT NULL", "attack_metadata JSONB NOT NULL DEFAULT '{}'", "tuple_key TEXT", "flow_label TEXT NOT NULL DEFAULT ''"}
	for _, name := range columnNames() {
		kind := "TEXT"
		if numericColumns[name] {
			kind = "BIGINT"
		}
		if postgresFloat[name] {
			kind = "DOUBLE PRECISION"
		}
		if name == "raw" {
			kind = "BYTEA"
		}
		cols = append(cols, pgx.Identifier{name}.Sanitize()+" "+kind)
	}
	return "CREATE TABLE IF NOT EXISTS events (" + strings.Join(cols, ",") + ")"
}

func NewPostgresStore(path, stream, address string, pool *Pool) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	cfg, err := postgresConfig(address, false)
	if err != nil {
		return nil, err
	}
	w := stdlib.OpenDB(*cfg)
	w.SetMaxOpenConns(1)
	w.SetMaxIdleConns(1)
	s := &Store{Path: path, Stream: stream, Writer: w, Pool: pool, Postgres: true, DatabaseURL: address, Cap: 8 << 30, changed: make(chan struct{}, 1)}
	ok := false
	defer func() {
		if !ok {
			w.Close()
			if s.Readers != nil {
				s.Readers.Close()
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err = w.PingContext(ctx); err != nil {
		return nil, errors.New("PostgreSQL 事件库连接失败")
	}
	var extension string
	if err = w.QueryRowContext(ctx, "SELECT extversion FROM pg_extension WHERE extname='timescaledb'").Scan(&extension); err != nil {
		return nil, errors.New("TimescaleDB 扩展尚未安装")
	}
	for _, q := range []string{
		"CREATE SCHEMA IF NOT EXISTS aegis",
		postgresSchema(),
		"SELECT create_hypertable('aegis.events',by_range('event_time',INTERVAL '1 hour'),if_not_exists=>TRUE,create_default_indexes=>FALSE)",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_events_key ON events(event_key,event_time)",
		"CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC,id DESC)",
		"CREATE INDEX IF NOT EXISTS idx_events_id ON events(id)",
		"CREATE INDEX IF NOT EXISTS idx_events_session_ts ON events(session_id,ts DESC) WHERE session_id<>''",
		"CREATE TABLE IF NOT EXISTS event_state(key TEXT PRIMARY KEY,value TEXT NOT NULL)",
		postgresFunctions,
		"ALTER TABLE events SET (timescaledb.enable_columnstore=true,timescaledb.segmentby='type',timescaledb.orderby='event_time DESC,id DESC')",
		"CALL add_columnstore_policy('events',after=>INTERVAL '1 hour',if_not_exists=>TRUE,schedule_interval=>INTERVAL '10 minutes')",
		"SELECT add_retention_policy('events',drop_after=>INTERVAL '30 days',if_not_exists=>TRUE,schedule_interval=>INTERVAL '1 hour')",
	} {
		if _, err = w.ExecContext(ctx, q); err != nil {
			return nil, fmt.Errorf("初始化 PostgreSQL 事件结构失败: %w", err)
		}
	}
	for key, target := range map[string]*Cursor{"stream_cursor": &s.cursor, "stream_cutoff": &s.cutoff} {
		var saved string
		err = w.QueryRowContext(ctx, "SELECT value FROM event_state WHERE key=$1", key).Scan(&saved)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		if err == nil && saved != "null" {
			if err = decode([]byte(saved), target); err != nil {
				return nil, errors.New("事件读取位置损坏")
			}
		}
	}
	var settings Object
	if readJSON(path+".settings.json", &settings) == nil {
		if cap := integer(settings["cap_mib"]); cap >= 64 && cap <= 1048576 {
			s.Cap = cap << 20
		}
	}
	readerConfig, _ := postgresConfig(address, true)
	r := stdlib.OpenDB(*readerConfig)
	r.SetMaxOpenConns(2*pool.Workers + 1)
	r.SetMaxIdleConns(pool.Workers + 1)
	s.Readers = &eventDatabase{DB: r, postgres: true}
	if err = r.PingContext(ctx); err != nil {
		return nil, errors.New("PostgreSQL 只读连接失败")
	}
	var version, compression string
	if err = w.QueryRowContext(ctx, "SELECT current_setting('server_version'),current_setting('wal_compression')").Scan(&version, &compression); err != nil {
		return nil, err
	}
	s.StorageInfo = Object{"event_database": "postgresql", "postgresql_version": version, "timescaledb_version": extension, "wal_compression": compression, "ingest_batch_rows": 1000, "event_indexes": 4, "columnstore_after_seconds": 3600}
	ok = true
	return s, nil
}

// COPY only fills a connection-local staging table. The deduplicated insert and
// ordered stream cursor commit atomically; retrying a failed commit is safe.
func (s *Store) insertPostgres(ctx context.Context, records []*Prepared, cursor *Cursor) error {
	conn, err := s.Writer.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.Raw(func(raw any) error {
		c := raw.(*stdlib.Conn).Conn()
		tx, err := c.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			tx.Rollback(cleanup)
		}()
		if len(records) > 0 {
			if _, err = tx.Exec(ctx, "CREATE TEMP TABLE IF NOT EXISTS ingest_batch (LIKE aegis.events INCLUDING DEFAULTS) ON COMMIT DELETE ROWS"); err != nil {
				return err
			}
			columns := append(columnNames(), "event_time", "attack_metadata", "tuple_key", "flow_label")
			rows := make([][]any, len(records))
			for i, r := range records {
				v := append([]any{}, r.Values...)
				for j, name := range columnNames() {
					v[j] = postgresEventValue(name, v[j])
				}
				metadata := Object{}
				for _, field := range strings.Fields("mitre_tactic_id mitre_tactic_name mitre_technique_id mitre_technique_name") {
					if r.Record[field] != nil {
						values := []string{}
						for _, value := range array(r.Record[field]) {
							values = append(values, postgresText(value))
						}
						metadata[field] = values
					}
				}
				data, _ := json.Marshal(metadata)
				v = append(v, time.UnixMicro(int64(math.Round(number(r.Record["ts"])*1e6))), string(data), tupleHash(r.Record["src"], r.Record["sport"], r.Record["dst"], r.Record["dport"], r.Record["proto"]), postgresText(flowSummary(text(r.Record["app"]), text(r.Record["proto"]), text(r.Record["state"]), text(r.Record["reason"]), text(r.Record["sig"]))))
				rows[i] = v
			}
			if _, err = tx.CopyFrom(ctx, pgx.Identifier{"pg_temp", "ingest_batch"}, columns, pgx.CopyFromRows(rows)); err != nil {
				return err
			}
			all := append([]string{"id"}, columns...)
			quoted := make([]string, len(all))
			for i, name := range all {
				quoted[i] = pgx.Identifier{name}.Sanitize()
			}
			q := strings.Join(quoted, ",")
			if _, err = tx.Exec(ctx, "INSERT INTO aegis.events ("+q+") SELECT "+q+" FROM pg_temp.ingest_batch ON CONFLICT(event_key,event_time) DO NOTHING"); err != nil {
				return err
			}
		}
		if cursor != nil {
			data, _ := json.Marshal(cursor)
			if _, err = tx.Exec(ctx, "INSERT INTO aegis.event_state VALUES('stream_cursor',$1) ON CONFLICT(key) DO UPDATE SET value=excluded.value", string(data)); err != nil {
				return err
			}
		}
		return tx.Commit(ctx)
	})
}

func (s *Store) maintainPostgres(ctx context.Context) {
	// Retention and compression are bounded Timescale jobs. Capacity removal
	// drops whole oldest chunks, avoiding per-row DELETE and vacuum churn.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	s.stateMu.RLock()
	capacity := s.Cap
	s.stateMu.RUnlock()
	var size int64
	if err := s.Writer.QueryRowContext(ctx, "SELECT hypertable_size('aegis.events')").Scan(&size); err != nil {
		s.fail(err)
		return
	}
	if size <= capacity {
		return
	}
	var oldest time.Time
	if err := s.Writer.QueryRowContext(ctx, "SELECT range_end FROM timescaledb_information.chunks WHERE hypertable_schema='aegis' AND hypertable_name='events' AND range_end<now()-INTERVAL '1 hour' ORDER BY range_end LIMIT 1").Scan(&oldest); err == sql.ErrNoRows {
		return
	} else if err != nil {
		s.fail(err)
		return
	}
	if _, err := s.Writer.ExecContext(ctx, "SELECT drop_chunks('aegis.events',older_than=>$1::timestamptz)", oldest); err != nil {
		s.fail(err)
	}
}

func (s *Store) postgresStats(ctx context.Context) (Object, error) {
	var count, size int64
	var low, high sql.NullFloat64
	if err := s.Readers.QueryRowContext(ctx, "SELECT COUNT(*),MIN(ts),MAX(ts) FROM events").Scan(&count, &low, &high); err != nil {
		return nil, err
	}
	if err := s.Readers.QueryRowContext(ctx, "SELECT hypertable_size('aegis.events')").Scan(&size); err != nil {
		return nil, err
	}
	s.stateMu.RLock()
	capacity := s.Cap
	s.stateMu.RUnlock()
	return Object{"path": "PostgreSQL aegis", "size": size, "rows": count, "oldest": low.Float64 / 1000, "newest": high.Float64 / 1000, "cap": capacity, "error": s.Error(), "min_cap_mib": 64, "max_cap_mib": 1048576, "storage": "postgresql", "timescaledb": true}, nil
}

var postgresArchive = regexp.MustCompile(`^aegis_history_[a-f0-9]{16}$`)

func postgresMaintenanceURL(address string) (string, error) {
	cfg, err := postgresConfig(address, false)
	if err != nil || cfg.Host != "/var/run/postgresql" && cfg.Host != "/run/postgresql" || cfg.Port != 55432 || cfg.Database != "aegis" || cfg.Password != "" {
		return "", errors.New("PostgreSQL 维护只支持专用本机事件库")
	}
	return "postgresql://aegis_admin@/aegis?host=/var/run/postgresql&port=55432&sslmode=disable", nil
}

func configuredPostgresMaintenance() (string, error) {
	var config Object
	if err := readJSON(resetConfig, &config); err != nil {
		return "", err
	}
	if text(config["database_url"]) == "" {
		return "", nil
	}
	return postgresMaintenanceURL(text(config["database_url"]))
}

// Renaming the application schema seals its tables, sequences and hypertables
// atomically. No database dump or temporary copy is created on the appliance.
func resetPostgresHistory(ctx context.Context, address, stream string) (string, error) {
	cfg, err := postgresConfig(address, false)
	if err != nil {
		return "", err
	}
	db := stdlib.OpenDB(*cfg)
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var owner string
	if err = tx.QueryRowContext(ctx, "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()").Scan(&owner); err != nil {
		return "", err
	}
	var exists bool
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT FROM pg_namespace WHERE nspname='aegis')").Scan(&exists); err != nil {
		return "", err
	}
	archive := "aegis_history_" + token()[:16]
	if exists {
		jobs, err := queryRows(ctx, tx, "SELECT job_id FROM timescaledb_information.jobs WHERE hypertable_schema='aegis' AND hypertable_name='events'")
		if err != nil {
			return "", err
		}
		for _, job := range jobs {
			if _, err = tx.ExecContext(ctx, "SELECT alter_job($1,scheduled=>false)", integer(job["job_id"])); err != nil {
				return "", err
			}
		}
		if _, err = tx.ExecContext(ctx, "ALTER SCHEMA aegis RENAME TO "+pgx.Identifier{archive}.Sanitize()); err != nil {
			return "", err
		}
	} else {
		archive = ""
	}
	if _, err = tx.ExecContext(ctx, "CREATE SCHEMA aegis AUTHORIZATION "+pgx.Identifier{owner}.Sanitize()); err != nil {
		return "", err
	}
	if _, err = tx.ExecContext(ctx, "SET LOCAL ROLE "+pgx.Identifier{owner}.Sanitize()); err != nil {
		return "", err
	}
	if _, err = tx.ExecContext(ctx, "CREATE TABLE aegis.event_state(key TEXT PRIMARY KEY,value TEXT NOT NULL)"); err != nil {
		return "", err
	}
	var cutoff any
	f, err := os.Open(stream)
	if err == nil {
		defer f.Close()
		info, e := f.Stat()
		if e != nil {
			return "", e
		}
		if !info.Mode().IsRegular() {
			return "", errors.New("事件流类型异常")
		}
		c, e := cursorAt(f, info, info.Size())
		if e != nil {
			return "", e
		}
		cutoff = c
	} else if !os.IsNotExist(err) {
		return "", err
	}
	data, _ := json.Marshal(cutoff)
	if _, err = tx.ExecContext(ctx, "INSERT INTO aegis.event_state VALUES('stream_cutoff',$1),('stream_cursor',$1),('clear_epoch',$2)", string(data), token()[:32]); err != nil {
		return "", err
	}
	return archive, tx.Commit()
}

func restorePostgresHistory(ctx context.Context, address, archive string) error {
	if !postgresArchive.MatchString(archive) {
		return errors.New("PostgreSQL 备份标识无效")
	}
	cfg, err := postgresConfig(address, false)
	if err != nil {
		return err
	}
	db := stdlib.OpenDB(*cfg)
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	failed := "aegis_history_" + token()[:16]
	if _, err = tx.ExecContext(ctx, "ALTER SCHEMA aegis RENAME TO "+pgx.Identifier{failed}.Sanitize()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "ALTER SCHEMA "+pgx.Identifier{archive}.Sanitize()+" RENAME TO aegis"); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "SELECT alter_job(job_id,scheduled=>true) FROM timescaledb_information.jobs WHERE hypertable_schema='aegis' AND hypertable_name='events'"); err != nil {
		return err
	}
	return tx.Commit()
}

func removePostgresHistory(ctx context.Context, address, archive string) error {
	if !postgresArchive.MatchString(archive) {
		return errors.New("PostgreSQL 备份标识无效")
	}
	cfg, err := postgresConfig(address, false)
	if err != nil {
		return err
	}
	db := stdlib.OpenDB(*cfg)
	defer db.Close()
	_, err = db.ExecContext(ctx, "DROP SCHEMA "+pgx.Identifier{archive}.Sanitize()+" CASCADE")
	return err
}

func RunPostgresMaintenance(ctx context.Context, args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("PostgreSQL 维护需要 root 权限")
	}
	flags := flag.NewFlagSet("postgresql-reset", flag.ContinueOnError)
	address := flags.String("database-url", "", "专用本机事件库")
	stream := flags.String("stream", "/var/lib/ips-snort-logs/events/events.json", "事件流")
	restore := flags.String("restore", "", "恢复封存 schema")
	remove := flags.String("remove", "", "删除封存 schema")
	if err := flags.Parse(args); err != nil {
		return err
	}
	admin, err := postgresMaintenanceURL(*address)
	if err != nil {
		return err
	}
	if *restore != "" && *remove != "" {
		return errors.New("维护操作互斥")
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if *restore != "" {
		return restorePostgresHistory(ctx, admin, *restore)
	}
	if *remove != "" {
		return removePostgresHistory(ctx, admin, *remove)
	}
	archive, err := resetPostgresHistory(ctx, admin, *stream)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(Object{"archive": archive})
}
