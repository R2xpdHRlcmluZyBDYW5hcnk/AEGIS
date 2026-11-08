package console

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func (a *App) DNSContext(ctx context.Context, contextData Object) (Object, error) {
	rows := []Object{}
	if v, ok := contextData["records"].([]Object); ok {
		rows = v
	} else {
		for _, v := range array(contextData["records"]) {
			rows = append(rows, object(v))
		}
	}
	var anchor Object
	first := number(contextData["first_ts"])
	for _, row := range rows {
		if anchor == nil && row["type"] != "dns" && text(row["src"]) != "" && text(row["dst"]) != "" {
			anchor = row
		}
		if t := number(row["observed_first"]); t > 0 {
			first = min(first, t)
		}
	}
	empty := func(status string) Object { return Object{"status": status, "records": []Object{}} }
	if anchor == nil {
		return empty("not_applicable"), nil
	}
	client, e := netip.ParseAddr(text(anchor["src"]))
	target, f := netip.ParseAddr(text(anchor["dst"]))
	if e != nil || f != nil || first <= 0 {
		return empty("not_applicable"), nil
	}
	queryCtx, cancel := context.WithTimeout(ctx, 3e9)
	defer cancel()
	raw, err := queryRows(queryCtx, a.Store.Readers, "SELECT * FROM events WHERE type='dns' AND src=? AND ts>=? AND ts<=? ORDER BY ts DESC,id DESC LIMIT 128", client.String(), (first-300)*1000, (first+2)*1000)
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, row := range rows {
		for _, field := range []string{"sni", "host"} {
			if name := text(row[field]); name != "" {
				names[strings.ToLower(strings.TrimRight(name, "."))] = true
			}
		}
	}
	matches := []Object{}
	seen := map[string]bool{}
	for _, rawRow := range raw {
		row, err := readRecordRow(rawRow, false, false)
		if err != nil {
			return nil, err
		}
		if contextData["session_id"] != "" && row["session_id"] == contextData["session_id"] {
			continue
		}
		name := strings.TrimRight(text(row["dns"]), ".")
		if !regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}$`).MatchString(name) {
			continue
		}
		found := false
		for _, word := range strings.FieldsFunc(text(row["answers"]), func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t' }) {
			if address, err := netip.ParseAddr(word); err == nil && address == target {
				found = true
			}
		}
		if !found {
			continue
		}
		age := first - number(row["ts"])
		ttl := number(row["dns_ttl"])
		known := row["dns_ttl"] != nil && row["dns_ttl"] != "" && ttl >= 0
		allow := float64(120)
		var ttlValue any
		if known {
			allow = ttl
			ttlValue = ttl
		}
		if age > max(2, allow) || seen[strings.ToLower(name)] {
			continue
		}
		seen[strings.ToLower(name)] = true
		matches = append(matches, Object{"name": name, "answer": target.String(), "client": client.String(), "ts": row["ts"], "age_seconds": math.Round(age*1000) / 1000, "ttl_seconds": ttlValue, "name_matches": names[strings.ToLower(name)], "session_id": get(row, "session_id", ""), "record_id": row["record_id"], "relation": "candidate"})
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i]["name_matches"] != matches[j]["name_matches"] {
			return matches[i]["name_matches"] == true
		}
		return math.Abs(number(matches[i]["age_seconds"])) < math.Abs(number(matches[j]["age_seconds"]))
	})
	status := "not_found"
	if len(matches) > 0 {
		status = "matched"
	}
	if len(raw) == 128 {
		status = "partial"
	}
	return Object{"status": status, "records": matches[:min(2, len(matches))]}, nil
}
func (a *App) Related(ctx context.Context, path string, params url.Values) (Object, error) {
	if id := text(present(params.Get("incident_id"), params.Get("incident"))); id != "" {
		if !strings.HasPrefix(id, "session:") {
			return nil, errors.New("此事件没有引擎会话 ID，不能合并调查")
		}
		session := strings.TrimPrefix(id, "session:")
		if !sessionValid(session) {
			return nil, errors.New("会话 ID 无效")
		}
		return a.rangeFor(ctx, "session_id=?", []any{session}, "session_id:"+strconv.Quote(session), 0, 1)
	}
	if path == "/api/hunt/flow-range" {
		id := params.Get("flow")
		n, err := strconv.ParseInt(id, 10, 64)
		if err != nil || n < 1 {
			return nil, errors.New("流标识无效")
		}
		return a.rangeFor(ctx, "flow_id=?", []any{n}, "flow:"+id, 0, 1)
	}
	if path == "/api/hunt/community-range" {
		community := params.Get("community")
		if community == "" {
			return nil, errors.New("Community ID 无效")
		}
		return a.rangeFor(ctx, "community=?", []any{community}, "community_id:"+strconv.Quote(community), 0, 0)
	}
	if path == "/api/hunt/tuple-range" {
		hash := strings.ToLower(text(present(params.Get("hash"), params.Get("tuple_hash"))))
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(hash) {
			return nil, errors.New("五元组摘要无效")
		}
		return a.rangeFor(ctx, "COALESCE(community,'')='' AND COALESCE(flow_id,0)<=0 AND tuple_hash(src,sport,dst,dport,proto)=?", []any{hash}, "tuple_hash:"+hash, 1, 0)
	}
	community := params.Get("community")
	var tuples []Object
	var err error
	if community != "" {
		tuples, err = queryRows(ctx, a.Store.Readers, "SELECT DISTINCT src,sport,dst,dport,proto,flow_id FROM events WHERE community=?", community)
		if err != nil {
			return nil, err
		}
	} else {
		sport, e := strconv.ParseInt(params.Get("sport"), 10, 64)
		dport, f := strconv.ParseInt(params.Get("dport"), 10, 64)
		src, g := netip.ParseAddr(params.Get("src"))
		dst, h := netip.ParseAddr(params.Get("dst"))
		if e != nil || f != nil || g != nil || h != nil || src.BitLen() != dst.BitLen() || sport < 0 || sport > 65535 || dport < 0 || dport > 65535 || params.Get("proto") == "" {
			return nil, errors.New("需要有效的完整五元组")
		}
		tuples = []Object{{"src": src.String(), "dst": dst.String(), "sport": sport, "dport": dport, "proto": params.Get("proto"), "flow_id": params.Get("flow")}}
	}
	type tuple struct {
		row   Object
		flows map[int64]bool
	}
	unique := map[string]*tuple{}
	flowsCount := 0
	for _, row := range tuples {
		hash := text(tupleHash(row["src"], row["sport"], row["dst"], row["dport"], row["proto"]))
		if hash == "" {
			continue
		}
		item := unique[hash]
		if item == nil {
			item = &tuple{row: row, flows: map[int64]bool{}}
			unique[hash] = item
		}
		if flow := integer(row["flow_id"]); flow > 0 && !item.flows[flow] {
			item.flows[flow] = true
			flowsCount++
		}
		if len(unique) > 32 || flowsCount > 128 {
			return nil, errors.New("关联五元组或 Flow ID 过多，请缩小范围")
		}
	}
	keys := []string{}
	for key := range unique {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	predicates := []string{}
	for _, key := range keys {
		item := unique[key]
		r := item.row
		forward := "src:" + strconv.Quote(text(r["src"])) + " AND sport:" + text(r["sport"]) + " AND dst:" + strconv.Quote(text(r["dst"])) + " AND dport:" + text(r["dport"])
		reverse := "src:" + strconv.Quote(text(r["dst"])) + " AND sport:" + text(r["dport"]) + " AND dst:" + strconv.Quote(text(r["src"])) + " AND dport:" + text(r["sport"])
		ids := []int64{}
		for id := range item.flows {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		flows := []string{"NOT flow:>0"}
		for _, id := range ids {
			flows = append(flows, "flow:"+strconv.FormatInt(id, 10))
		}
		predicates = append(predicates, "(proto:"+strconv.Quote(strings.ToUpper(text(r["proto"])))+" AND (("+forward+") OR ("+reverse+")) AND ("+strings.Join(flows, " OR ")+"))")
	}
	conditions := []string{}
	if community != "" {
		conditions = append(conditions, "community_id:"+strconv.Quote(community))
	}
	if len(predicates) > 0 {
		conditions = append(conditions, "(NOT community_id:* AND ("+strings.Join(predicates, " OR ")+"))")
	}
	query := strings.Join(conditions, " OR ")
	if query == "" || len(url.QueryEscape(query)) > 48000 {
		return nil, errors.New("关联条件缺失或过长")
	}
	node, err := ParseHunt(query)
	if err != nil {
		return nil, err
	}
	where, args, err := compileHunt(node, true)
	if err != nil {
		return nil, err
	}
	if len(args) > 900 {
		return nil, errors.New("关联条件过多")
	}
	return a.rangeFor(ctx, where, args, query, len(unique), flowsCount)
}
func (a *App) rangeFor(ctx context.Context, where string, args []any, query string, tuples, flows int) (Object, error) {
	var lo, hi sql.NullFloat64
	if err := a.Store.Readers.QueryRowContext(ctx, "SELECT MIN(ts),MAX(ts) FROM events WHERE "+where, args...).Scan(&lo, &hi); err != nil {
		return nil, err
	}
	if !lo.Valid {
		return nil, errors.New("未找到可调查的关联记录")
	}
	return Object{"from": math.Floor(lo.Float64/60000) * 60, "to": math.Ceil(hi.Float64/60000) * 60, "query": query, "tuple_count": tuples, "flow_count": flows}, nil
}
