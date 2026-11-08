package console

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const detectionSQL = "((type='alert' OR (type='drop' AND sid>0)) AND COALESCE(alert_suppressed,0)=0)"
const blockedSQL = "(type='drop' OR action='blocked')"
const incidentKeySQL = "CASE WHEN COALESCE(session_id,'')!='' THEN 'session:'||session_id ELSE COALESCE('event:'||event_key,'record:'||id||':'||ts) END"

type statement struct {
	SQL  string
	Args []any
}
type Snapshot struct {
	recent      bool
	main        *sql.Tx
	helpers     []*sql.Tx
	connections []*sql.Conn
	release     func()
	ctx         context.Context
}

var sqlHelpers = make(chan struct{}, 3)

func (s *Store) Snapshot(ctx context.Context, parallel bool) (*Snapshot, error) {
	group := &Snapshot{ctx: ctx}
	ok := false
	defer func() {
		if !ok {
			group.Close()
		}
	}()
	if parallel && s.Gate.TryLock() {
		defer s.Gate.Unlock()
		for range 3 {
			select {
			case sqlHelpers <- struct{}{}:
				group.helpers = append(group.helpers, nil)
			default:
			}
		}
	}
	reserved := len(group.helpers)
	group.helpers = nil
	group.release = func() {
		for range reserved {
			<-sqlHelpers
		}
	}
	for i := 0; i <= reserved; i++ {
		conn, err := s.Readers.Conn(ctx)
		if err != nil {
			return nil, err
		}
		group.connections = append(group.connections, conn)
		tx, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			return nil, err
		}
		if i == 0 {
			group.main = tx
		} else {
			group.helpers = append(group.helpers, tx)
		}
		var name string
		err = tx.QueryRowContext(ctx, "SELECT name FROM sqlite_master LIMIT 1").Scan(&name)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
	}
	ok = true
	return group, nil
}
func (g *Snapshot) Close() {
	if g.main != nil {
		g.main.Rollback()
	}
	for _, tx := range g.helpers {
		tx.Rollback()
	}
	for _, c := range g.connections {
		c.Close()
	}
	if g.release != nil {
		g.release()
		g.release = nil
	}
}
func (g *Snapshot) Many(statements []statement) ([][]Object, error) {
	out := make([][]Object, len(statements))
	for offset := 0; offset < len(statements); {
		var wg sync.WaitGroup
		errs := make([]error, len(g.helpers)+1)
		count := min(len(g.helpers)+1, len(statements)-offset)
		for i := 1; i < count; i++ {
			i := i
			query := statements[offset+i]
			index := offset + i
			wg.Add(1)
			go func() {
				defer wg.Done()
				out[index], errs[i] = queryRows(g.ctx, g.helpers[i-1], query.SQL, query.Args...)
			}()
		}
		query := statements[offset]
		out[offset], errs[0] = queryRows(g.ctx, g.main, query.SQL, query.Args...)
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				return nil, err
			}
		}
		offset += count
	}
	return out, nil
}
func rangeParams(params url.Values, defaultMinutes int, stamp float64) (float64, float64, error) {
	minutes, err := intParam(params, "window", defaultMinutes, 1, 43200)
	if err != nil {
		return 0, 0, err
	}
	low, high := stamp-float64(minutes*60), stamp
	for key, target := range map[string]*float64{"from": &low, "to": &high} {
		if value := params.Get(key); value != "" {
			n, e := strconv.ParseFloat(value, 64)
			if e != nil {
				return 0, 0, errors.New("时间参数无效")
			}
			*target = n
		}
	}
	if math.IsNaN(low+high) || math.IsInf(low+high, 0) || low < 0 || high < low {
		return 0, 0, errors.New("时间区间无效")
	}
	return low, high, nil
}
func intParam(params url.Values, key string, fallback, low, high int) (int, error) {
	if params.Get(key) == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(params.Get(key))
	if err != nil || v < low {
		return 0, fmt.Errorf("%s 参数无效", key)
	}
	return min(v, high), nil
}
func markArgs(values []string) string {
	return strings.TrimSuffix(strings.Repeat("?,", len(values)), ",")
}
func eventFilter(params url.Values, hunt bool) ([]string, []any, error) {
	parts, args := []string{}, []any{}
	if t := params.Get("type"); t != "" && t != "all" {
		if !eventKinds[t] {
			return nil, nil, errors.New("事件类型无效")
		}
		parts = append(parts, "type=?")
		args = append(args, t)
	}
	for _, key := range []string{"proto", "action"} {
		if value := params.Get(key); value != "" {
			parts = append(parts, "LOWER("+key+")=?")
			args = append(args, strings.ToLower(value))
		}
	}
	if levels := params.Get("sev"); levels != "" {
		values := strings.Split(levels, ",")
		if len(values) > 4 {
			return nil, nil, errors.New("级别筛选无效")
		}
		for _, v := range values {
			n, e := strconv.Atoi(v)
			if e != nil || n < 1 || n > 4 {
				return nil, nil, errors.New("级别筛选无效")
			}
			args = append(args, n)
		}
		parts = append(parts, "sev IN ("+markArgs(values)+")")
	}
	if detection := params.Get("detection"); detection != "" {
		if detection != "alerts" {
			return nil, nil, errors.New("检测筛选无效")
		}
		parts = append(parts, detectionSQL)
	}
	if q := strings.TrimSpace(params.Get("q")); q != "" {
		if hunt {
			node, err := ParseHunt(q)
			if err != nil {
				return nil, nil, err
			}
			part, values, err := compileHunt(node, params.Get("icase") == "1" || params.Get("icase") == "true")
			if err != nil {
				return nil, nil, err
			}
			parts = append(parts, "("+part+")")
			args = append(args, values...)
		} else {
			columns := strings.Fields("sig src dst app reason cat proto sport dport")
			checks := []string{}
			for _, column := range columns {
				if column == "sig" {
					column = "CASE WHEN type='flow' THEN flow_summary(app,proto,state,reason,sig) ELSE sig END"
				}
				checks = append(checks, "INSTR(LOWER(COALESCE("+column+",'')),?)>0")
				args = append(args, strings.ToLower(q))
			}
			parts = append(parts, "("+strings.Join(checks, " OR ")+")")
		}
	}
	return parts, args, nil
}
func securitySource(where string, dedup bool) string {
	if !dedup {
		return " FROM events" + where
	}
	same := []string{}
	for _, key := range strings.Fields("ts gid sid rev sig src sport dst dport proto tx") {
		same = append(same, "a."+key+" IS e."+key)
	}
	return " FROM (SELECT e.* FROM events e" + where + " AND (e.type='alert' OR COALESCE(e.session_id,'')='' OR NOT EXISTS (SELECT 1 FROM events a WHERE a.type='alert' AND " + strings.Join(same, " AND ") + " AND a.session_id=e.session_id)))"
}
func search(ctx context.Context, g *Snapshot, low, high float64, parts []string, args []any, limit, offset int, list, network, dedup bool) (int64, []Object, error) {
	where := " WHERE ts>=? AND ts<=?"
	bound := append([]any{low * 1000, high * 1000}, args...)
	if len(parts) > 0 {
		where += " AND " + strings.Join(parts, " AND ")
	}
	source := securitySource(where, dedup)
	columns := []string{"id"}
	for _, name := range columnNames() {
		if name != "raw" || !list {
			columns = append(columns, name)
		}
	}
	results, err := g.Many([]statement{{"SELECT COUNT(*) n" + source, bound}, {"SELECT " + strings.Join(columns, ",") + source + " ORDER BY ts DESC,id DESC LIMIT ? OFFSET ?", append(append([]any{}, bound...), limit, offset)}})
	if err != nil {
		return 0, nil, err
	}
	out := []Object{}
	for _, row := range results[1] {
		record, err := readRecordRow(row, list, network)
		if err != nil {
			return 0, nil, err
		}
		out = append(out, record)
	}
	return integer(results[0][0]["n"]), out, nil
}
func networkSummary(ctx context.Context, g *Snapshot, low, high float64, parts []string, args []any) (Object, error) {
	filter := ""
	if len(parts) > 0 {
		filter = "AND " + strings.Join(parts, " AND ")
	}
	bound := append([]any{low * 1000, high * 1000}, args...)
	results, err := g.Many([]statement{{strings.ReplaceAll(networkSQL, "{{FILTER}}", filter), bound}, {strings.ReplaceAll(networkLogsSQL, "{{FILTER}}", filter), bound}})
	if err != nil {
		return nil, err
	}
	r := Object{"range": []float64{low, high}, "as_of": now(), "records": int64(0), "flows": int64(0), "dns": int64(0), "tls": int64(0), "newest": float64(0), "bytes": int64(0), "bidirectional": int64(0), "one_way": int64(0), "addresses": int64(0), "source_count": int64(0), "destination_count": int64(0)}
	for _, key := range strings.Fields("applications protocols dns_names tls_names sources event_types log_sources log_destinations") {
		r[key] = []Object{}
	}
	// SQL compound-select column names derive from its first branch.
	for _, row := range results[1] {
		values := orderedValues(row, []string{"kind", "name", "n", "extra"})
		if len(values) != 4 {
			return nil, errors.New("网络日志投影无效")
		}
		kind, name, count, extra := text(values[0]), text(values[1]), integer(values[2]), values[3]
		switch kind {
		case "type":
			r["records"] = integer(r["records"]) + count
			r["newest"] = max(number(r["newest"]), number(extra)/1000)
			appendObject(r, "event_types", Object{"name": name, "count": count})
			if name == "dns" || name == "tls" {
				r[name] = count
			}
		case "address_counts":
			r["source_count"] = count
			r["destination_count"] = integer(extra)
		case "source", "destination":
			key := "log_sources"
			if kind == "destination" {
				key = "log_destinations"
			}
			appendObject(r, key, Object{"ip": name, "count": count})
		case "dns", "tls":
			key := "dns_names"
			if kind == "tls" {
				key = "tls_names"
			}
			appendObject(r, key, Object{"name": name, "count": count})
		}
	}
	for _, row := range results[0] {
		values := orderedValues(row, []string{"kind", "name", "n", "volume", "bidirectional", "one_way", "latest", "addresses"})
		if len(values) != 8 {
			return nil, errors.New("网络会话投影无效")
		}
		kind, name, count := text(values[0]), text(values[1]), integer(values[2])
		switch kind {
		case "metrics":
			r["flows"] = count
			r["bytes"] = integer(values[3])
			r["bidirectional"] = integer(values[4])
			r["one_way"] = integer(values[5])
			r["addresses"] = integer(values[7])
		case "connection_source":
			appendObject(r, "sources", Object{"ip": name, "count": count, "bytes": integer(values[3]), "latest": number(values[6]) / 1000})
		default:
			key := "applications"
			if kind == "protocol" {
				key = "protocols"
			}
			if name == "" {
				name = "未识别"
			}
			appendObject(r, key, Object{"name": name, "count": count})
		}
	}
	sort.Slice(r["event_types"].([]Object), func(i, j int) bool {
		return text(r["event_types"].([]Object)[i]["name"]) < text(r["event_types"].([]Object)[j]["name"])
	})
	r["available"] = true
	r["status"] = "ready"
	r["computed_at"] = now()
	return r, nil
}
func orderedValues(row Object, keys []string) []any {
	values := make([]any, len(keys))
	for i, k := range keys {
		v, ok := row[k]
		if !ok {
			return nil
		}
		values[i] = v
	}
	return values
}
func appendObject(m Object, key string, value Object) { m[key] = append(m[key].([]Object), value) }
func securitySummary(ctx context.Context, g *Snapshot, low, high float64, parts []string, args []any, dedup bool, kind string, top int) (Object, error) {
	where := " WHERE ts>=? AND ts<=? AND type IN ('alert','drop')"
	bound := append([]any{low * 1000, high * 1000}, args...)
	if len(parts) > 0 {
		where += " AND " + strings.Join(parts, " AND ")
	}
	if kind == "alert" || kind == "drop" {
		where += " AND type=?"
		bound = append(bound, kind)
	}
	source := securitySource(where, dedup)
	extra := " AND "
	if dedup {
		extra = " WHERE "
	}
	detections := securitySource(where+" AND "+detectionSQL, dedup)
	queries := []statement{{"SELECT COUNT(*) total,SUM(" + detectionSQL + ") alerts,SUM(" + blockedSQL + ") drops,SUM(" + detectionSQL + " AND sev=1) high,COUNT(DISTINCT NULLIF(src,'')) sources_count,COUNT(DISTINCT NULLIF(dst,'')) destinations_count,MAX(ts) newest" + source, bound}, {"SELECT sig,sev,sid,COUNT(*) count" + detections + " GROUP BY sig,sev,sid ORDER BY count DESC,sig LIMIT ?", append(append([]any{}, bound...), top)}}
	for _, column := range []string{"src", "dst", "reason", "proto"} {
		queries = append(queries, statement{"SELECT " + column + " value,COUNT(*) count" + source + extra + column + "!='' GROUP BY " + column + " ORDER BY count DESC," + column + " LIMIT ?", append(append([]any{}, bound...), top)})
	}
	queries = append(queries, statement{"SELECT dport,proto,COUNT(*) count" + source + extra + "dport IS NOT NULL GROUP BY dport,proto ORDER BY count DESC LIMIT ?", append(append([]any{}, bound...), top)}, statement{"SELECT MIN(ts) oldest FROM events", nil})
	values, err := g.Many(queries)
	if err != nil {
		return nil, err
	}
	r := values[0][0]
	for _, key := range strings.Fields("total alerts drops high sources_count destinations_count") {
		r[key] = integer(r[key])
	}
	r["newest"] = number(r["newest"]) / 1000
	r["oldest"] = number(values[7][0]["oldest"]) / 1000
	r["signatures"] = values[1]
	r["source"] = "db"
	for i, key := range []string{"sources", "destinations", "reasons", "protocols"} {
		label := []string{"ip", "ip", "reason", "proto"}[i]
		out := []Object{}
		for _, v := range values[i+2] {
			out = append(out, Object{label: v["value"], "count": v["count"]})
		}
		r[key] = out
	}
	ports := []Object{}
	for _, row := range values[6] {
		ports = append(ports, Object{"port": text(row["dport"]) + "/" + strings.ToLower(text(row["proto"])), "count": row["count"]})
	}
	r["ports"] = ports
	return r, nil
}
func securitySeries(ctx context.Context, g *Snapshot, low, high float64, bucket int, parts []string, args []any) ([]Object, error) {
	span := float64(bucket * 60)
	where := " WHERE ts>=? AND ts<=? AND type IN ('alert','drop')"
	if len(parts) > 0 {
		where += " AND " + strings.Join(parts, " AND ")
	}
	bound := append([]any{span * 1000, low * 1000, high * 1000}, args...)
	rows, err := queryRows(ctx, g.main, "SELECT CAST(ts/? AS INTEGER) slot,SUM("+detectionSQL+") alerts,SUM("+blockedSQL+") drops"+securitySource(where, true)+" GROUP BY slot", bound...)
	if err != nil {
		return nil, err
	}
	counts := map[int64]Object{}
	for _, row := range rows {
		counts[integer(row["slot"])] = row
	}
	out := []Object{}
	for slot := int64(math.Floor(low / span)); slot <= int64(math.Floor(high/span)); slot++ {
		row := counts[slot]
		out = append(out, Object{"t": float64(slot) * span, "alerts": integer(row["alerts"]), "drops": integer(row["drops"])})
	}
	return out, nil
}
