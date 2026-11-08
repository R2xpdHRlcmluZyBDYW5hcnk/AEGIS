package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

var modelFields = strings.Fields("type src dst sport dport proto app action level sni host dns url method status rcode rrtype state bytes_toserver bytes_toclient pkts_toserver pkts_toclient wire_bytes_toserver wire_bytes_toclient flow_age ip_version ip_proto ip_ttl ip_tos tcp_flags tcp_window data_len icmp_type icmp_code session_event appid_service appid_client appid_payload tlsver validation_status alpn ja3 ja3s ja4 sha256 file size magic ssh_client ssh_server ssh_kex ssh_cipher command reply_code sig sid gid reason")
var modelNumbers = strings.Fields("sport dport status bytes_toserver bytes_toclient pkts_toserver pkts_toclient wire_bytes_toserver wire_bytes_toclient flow_age ip_version ip_proto ip_ttl ip_tos tcp_flags tcp_window data_len icmp_type icmp_code size sid gid")

func containsString(values []string, s string) bool {
	for _, v := range values {
		if v == s {
			return true
		}
	}
	return false
}
func compileModelTerms(raw any) (string, error) {
	terms, ok := raw.([]any)
	if !ok || len(terms) < 1 || len(terms) > 5 {
		return "", errors.New("检索条件数量无效")
	}
	clauses := []string{}
	for _, v := range terms {
		term, ok := v.([]any)
		if !ok || len(term) != 3 {
			return "", errors.New("检索条件格式无效")
		}
		field, op := text(term[0]), text(term[1])
		if !containsString(modelFields, field) || !containsString([]string{"=", ">", ">=", "<", "<="}, op) {
			return "", errors.New("检索字段或运算符无效")
		}
		literal := ""
		if containsString(modelNumbers, field) {
			switch term[2].(type) {
			case json.Number, float64, int, int64:
			default:
				return "", errors.New("数值字段需要数字")
			}
			n := number(term[2])
			if math.IsNaN(n) || math.IsInf(n, 0) {
				return "", errors.New("数值字段无效")
			}
			literal = text(term[2])
		} else {
			s, ok := term[2].(string)
			if !ok || op != "=" || strings.TrimSpace(s) == "" || strings.IndexFunc(s, func(r rune) bool { return r < 32 }) >= 0 {
				return "", errors.New("文字字段仅支持精确匹配")
			}
			literal = "\"" + strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(s) + "\""
		}
		if op == "=" {
			op = ""
		}
		clause := field + ":" + op + literal
		if !containsString(clauses, clause) {
			clauses = append(clauses, clause)
		}
	}
	query := strings.Join(clauses, " AND ")
	if len(query) > 240 {
		return "", errors.New("检索条件过长")
	}
	return query, nil
}
func simpleEvidence(v any) bool {
	switch v.(type) {
	case string, json.Number, float64, int, int64:
		return true
	}
	return false
}
func pickEvidence(row Object, fields []string) Object {
	out := Object{}
	for _, key := range fields {
		v := row[key]
		if v == nil || v == "" || !simpleEvidence(v) {
			continue
		}
		if s, ok := v.(string); ok {
			if key == "sig" && len([]rune(s)) > 100 {
				continue
			}
			if len([]rune(s)) > 100 {
				v = trim(s, 99) + "…"
			}
		}
		out[key] = v
	}
	return out
}
func promptMessages(system string, data Object) ([]Object, error) {
	encoded, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	if len(system)+len(encoded) > 1500 {
		return nil, errors.New("关键证据超过本地模型上下文上限，请选择更具体的事件")
	}
	return []Object{{"role": "system", "content": system}, {"role": "user", "content": string(encoded)}}, nil
}
func planMessages(context Object) ([]Object, error) {
	rows := []Object{}
	seen := map[string]bool{}
	all := append([]any{context["anchor"]}, array(context["records"])...)
	for _, raw := range all {
		record := object(raw)
		kind := text(record["type"])
		if seen[kind] {
			continue
		}
		row := Object{}
		for key, v := range record {
			field := key
			if field == "sig_id" {
				field = "sid"
			}
			if field == "sev" {
				field = "level"
				if record["level"] != nil {
					v = record["level"]
				}
			}
			if !containsString(modelFields, field) || v == nil || v == "" || !simpleEvidence(v) {
				continue
			}
			if containsString([]string{"sig", "sid", "gid", "action", "level"}, field) && kind != "alert" && kind != "drop" && kind != "anomaly" {
				continue
			}
			if field == "url" {
				if u, err := url.Parse(text(v)); err == nil {
					v = u.Path
				} else {
					continue
				}
			}
			if s, ok := v.(string); ok {
				if containsString([]string{"sni", "host", "dns", "sha256", "ja3", "ja3s", "ja4"}, field) {
					if len([]rune(s)) > 253 {
						continue
					}
				} else {
					v = trim(s, 100)
				}
			}
			row[field] = v
		}
		if len(row) > 0 {
			seen[kind] = true
			rows = append(rows, row)
		}
		if len(rows) >= 6 {
			break
		}
	}
	connection := Object{}
	if len(rows) > 0 {
		connection = pickEvidence(rows[0], strings.Fields("src sport dst dport proto app"))
	}
	facts := []Object{}
	for _, row := range rows {
		fact := clone(row)
		for key, v := range connection {
			if fmt.Sprint(fact[key]) == fmt.Sprint(v) {
				delete(fact, key)
			}
		}
		facts = append(facts, fact)
	}
	data := Object{"events": context["event_counts"], "actions": context["action_counts"], "connection": connection, "facts": facts}
	for {
		present := map[string]bool{}
		for _, f := range facts {
			for key := range f {
				present[key] = true
			}
		}
		fields := strings.Fields("type src dst sport dport proto app sni host dns state bytes_toserver bytes_toclient pkts_toserver pkts_toclient")
		for _, field := range modelFields {
			if present[field] && !containsString(fields, field) {
				fields = append(fields, field)
			}
		}
		for i, field := range fields {
			if containsString(modelNumbers, field) {
				fields[i] += "#"
			}
		}
		data["fields"] = strings.Join(fields, ",")
		messages, err := promptMessages(text(assistantPrompts["HUNT_PROMPT"]), data)
		if err == nil {
			return messages, nil
		}
		if len(facts) > 1 {
			facts = facts[:len(facts)-1]
			data["facts"] = facts
			continue
		}
		if len(facts) == 1 && len(facts[0]) > 4 {
			removed := false
			for _, key := range strings.Fields("sig reason url sni host dns file") {
				if _, ok := facts[0][key]; ok {
					delete(facts[0], key)
					removed = true
					break
				}
			}
			if !removed {
				keys := []string{}
				for key := range facts[0] {
					keys = append(keys, key)
				}
				sort.Strings(keys)
				delete(facts[0], keys[len(keys)-1])
			}
			continue
		}
		return nil, err
	}
}
func summaryMessages(context Object, hunts []Object) ([]Object, Object, error) {
	anchor := object(context["anchor"])
	detection := strings.Fields("sig gid sig_id sev action ips_action reason ids_reason")
	families := map[string][]string{"alert": detection, "drop": detection, "anomaly": strings.Fields("sig anom reason"), "dns": strings.Fields("dns rcode answers"), "tls": strings.Fields("sni tlsver validation_status"), "http": strings.Fields("host method status"), "http2": strings.Fields("host method status"), "flow": strings.Fields("state bytes_toserver bytes_toclient pkts_toserver pkts_toclient flow_age"), "quic": strings.Fields("sni alpn observer coverage"), "session": strings.Fields("session_event state appid_service appid_client appid_payload"), "ssh": strings.Fields("ssh_client ssh_server ssh_kex ssh_cipher"), "ftp": strings.Fields("command reply_code"), "fileinfo": strings.Fields("file size sha256 state")}
	data := Object{"scope": context["scope"], "events": context["event_counts"], "actions": context["action_counts"], "connection": pickEvidence(anchor, strings.Fields("src sport dst dport proto app")), "partial": true}
	anchorType := text(anchor["type"])
	if anchorType == "alert" || anchorType == "drop" || anchorType == "anomaly" {
		focus := pickEvidence(anchor, families[anchorType])
		focus["type"] = anchorType
		data["focus"] = focus
	}
	period := []string{}
	for _, key := range []string{"first_ts", "last_ts"} {
		if context[key] != nil {
			period = append(period, time.Unix(int64(number(context[key])), 0).UTC().Format(time.RFC3339))
		}
	}
	data["period_utc"] = period
	local := []Object{}
	var flow Object
	for _, v := range array(context["records"]) {
		r := object(v)
		if flow == nil && (r["type"] == "flow" || (r["type"] == "quic" && number(r["flow_start"]) > 0)) {
			flow = r
		}
		if text(r["record_id"]) != text(anchor["record_id"]) || text(r["record_id"]) == "" {
			local = append(local, r)
		}
	}
	if flow == nil {
		for _, v := range array(context["records"]) {
			if object(v)["type"] == "session" {
				flow = object(v)
				break
			}
		}
	}
	if flow != nil {
		data["flow"] = pickEvidence(flow, strings.Fields("state reason bytes_toserver bytes_toclient pkts_toserver pkts_toclient history wire_bytes_toserver wire_bytes_toclient session_origin session_limited"))
	}
	if data["focus"] == nil {
		local = append([]Object{anchor}, local...)
	}
	related := []Object{}
	for index := 0; index < 4; index++ {
		for number, hunt := range hunts {
			records := array(hunt["records"])
			if len(records) > index {
				r := clone(object(records[index]))
				r["_evidence_scope"] = "related"
				r["_evidence_query"] = number + 1
				related = append(related, r)
			}
		}
	}
	rows := append([]Object{}, local[:min(2, len(local))]...)
	rows = append(rows, related[:min(1, len(related))]...)
	rows = append(rows, local[min(2, len(local)):]...)
	rows = append(rows, related[min(1, len(related)):]...)
	records := []Object{}
	seen := map[string]bool{}
	for _, r := range rows {
		kind := text(r["type"])
		if kind == "flow" && r["_evidence_scope"] != "related" {
			continue
		}
		fields := families[kind]
		if fields == nil {
			fields = strings.Fields("sig reason state")
		}
		item := pickEvidence(r, fields)
		item["type"] = kind
		if r["_evidence_scope"] == "related" {
			for key, v := range pickEvidence(r, strings.Fields("src dst dport proto app")) {
				item[key] = v
			}
			item["relation"] = "candidate_related"
			item["hunt"] = r["_evidence_query"]
			if r["_retained_detections"] != nil {
				item["retained_detections"] = r["_retained_detections"]
			}
			if number(r["ts"]) > 0 {
				item["at_utc"] = time.Unix(int64(number(r["ts"])), 0).UTC().Format(time.RFC3339)
			}
		}
		if (kind == "http" || kind == "http2") && r["url"] != "" {
			if u, err := url.Parse(text(r["url"])); err == nil {
				item["url_path"] = trim(u.Path, 100)
			}
		}
		encoded, _ := json.Marshal(item)
		if !seen[string(encoded)] {
			seen[string(encoded)] = true
			records = append(records, item)
		}
	}
	data["records"] = records
	checks := []Object{}
	for _, h := range hunts {
		check := Object{"q": present(h["predicate"], h["query"]), "hits": h["total"], "scope": h["scope"]}
		if h["error"] != nil {
			check["error"] = h["error"]
		}
		checks = append(checks, check)
	}
	if len(checks) > 0 {
		data["hunt"] = checks
	}
	clues := array(object(context["dns_clues"])["records"])
	if len(clues) > 0 {
		c := object(clues[0])
		data["dns_hint"] = Object{"name": c["name"], "age_s": c["age_seconds"], "ttl_s": c["ttl_seconds"], "name_match": c["name_matches"]}
	}
	if containsString([]string{"invalid", "partial", "not_needed"}, text(context["hunt_status"])) {
		data["hunt_status"] = context["hunt_status"]
	}
	system := text(assistantPrompts["SUMMARY_PROMPT"])
	fits := func() bool { encoded, _ := json.Marshal(data); return len(system)+len(encoded) <= 1500 }
	for _, field := range strings.Fields("answers url_path ids_reason sha256 file") {
		if fits() {
			break
		}
		for _, r := range records {
			delete(r, field)
		}
	}
	if !fits() {
		for _, c := range checks {
			delete(c, "q")
		}
	}
	for !fits() && len(records) > 1 {
		records = records[:len(records)-1]
		data["records"] = records
	}
	if !fits() {
		delete(data, "period_utc")
	}
	messages, err := promptMessages(system, data)
	if err != nil {
		return nil, nil, err
	}
	included, relatedCount := 0, 0
	for _, r := range records {
		if r["relation"] == "candidate_related" {
			relatedCount++
		} else {
			included++
		}
	}
	if flow != nil {
		included++
	}
	if data["focus"] != nil {
		included++
	}
	meta := Object{"scope": context["scope"], "session_id": context["session_id"], "total_records": context["total_records"], "evidence_records": included, "related_evidence_records": relatedCount, "first_ts": context["first_ts"], "last_ts": context["last_ts"], "sampled": true, "from": math.Floor(number(context["first_ts"])/60) * 60, "to": math.Ceil(number(context["last_ts"])/60) * 60}
	return messages, meta, nil
}
func (a *Assistant) relatedHunt(ctx context.Context, evidence Object, query string) (Object, error) {
	node, err := ParseHunt(query)
	if err != nil {
		return nil, err
	}
	where, args, err := compileHunt(node, true)
	if err != nil {
		return nil, err
	}
	low, high := max(number(evidence["first_ts"])-900, number(evidence["last_ts"])-1800), number(evidence["last_ts"])+900
	where = "ts>=? AND ts<=? AND (" + where + ")"
	args = append([]any{low * 1000, high * 1000}, args...)
	id := text(evidence["session_id"])
	display := "(" + query + ") AND time:[" + strconv.FormatFloat(low, 'f', -1, 64) + " TO " + strconv.FormatFloat(high, 'f', -1, 64) + "]"
	if id != "" {
		where += " AND COALESCE(session_id,'')<>?"
		args = append(args, id)
		display += " AND NOT session_id:" + strconv.Quote(id)
	} else {
		where += " AND NOT (type=? AND ts/1000.0=?)"
		args = append(args, object(evidence["anchor"])["type"], number(evidence["first_ts"]))
	}
	g, err := a.app.Store.Snapshot(ctx, false)
	if err != nil {
		return nil, err
	}
	defer g.Close()
	var total int64
	if err = g.main.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE "+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	rows, err := queryRows(ctx, g.main, `WITH matched AS (SELECT id,ts,type,session_id FROM events WHERE `+where+`),ranked AS (SELECT id,ts,ROW_NUMBER() OVER(PARTITION BY CASE WHEN COALESCE(session_id,'')!='' THEN session_id ELSE 'row:'||id END ORDER BY (type NOT IN ('session','flow')) DESC,ts DESC,id DESC) position FROM matched) SELECT e.* FROM events e JOIN ranked r ON r.id=e.id WHERE r.position=1 ORDER BY r.ts DESC,r.id DESC LIMIT 4`, args...)
	if err != nil {
		return nil, err
	}
	records := []Object{}
	for _, row := range rows {
		r, err := readRecordRow(row, false, false)
		if err != nil {
			return nil, err
		}
		delete(r, "_raw")
		if session := text(r["session_id"]); session != "" {
			var count int64
			if err = g.main.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE session_id=? AND "+detectionSQL, session).Scan(&count); err != nil {
				return nil, err
			}
			r["_retained_detections"] = count
		}
		records = append(records, r)
	}
	return Object{"query": display, "predicate": query, "total": total, "records": records, "scope": "related", "range": []float64{low, high}, "excluded_current_session": id != "", "sampled": total > int64(len(records))}, nil
}
