package console

import (
	"context"
	"errors"
	"math"
	"net/url"
	"strconv"
	"strings"
)

func incidentFilter(identity string) ([]string, []any, error) {
	if strings.HasPrefix(identity, "session:") {
		id := strings.TrimPrefix(identity, "session:")
		if !sessionValid(id) {
			return nil, nil, errors.New("安全事件会话标识无效")
		}
		return []string{"session_id=?"}, []any{id}, nil
	}
	if strings.HasPrefix(identity, "event:") {
		id := strings.TrimPrefix(identity, "event:")
		if len(id) != 64 {
			return nil, nil, errors.New("安全事件标识无效")
		}
		return []string{"event_key=?"}, []any{id}, nil
	}
	if strings.HasPrefix(identity, "record:") {
		parts := strings.SplitN(strings.TrimPrefix(identity, "record:"), ":", 2)
		if len(parts) != 2 {
			return nil, nil, errors.New("安全事件标识无效")
		}
		id, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil || id <= 0 {
			return nil, nil, errors.New("安全事件标识无效")
		}
		ts, err := strconv.ParseFloat(parts[1], 64)
		if err != nil || math.IsNaN(ts) || math.IsInf(ts, 0) {
			return nil, nil, errors.New("安全事件时间无效")
		}
		return []string{"id=?", "ts=?"}, []any{id, ts}, nil
	}
	return nil, nil, errors.New("安全事件标识无效")
}
func incidents(ctx context.Context, g *Snapshot, params url.Values, low, high float64, identity string, signatureLimit int) (Object, error) {
	limit, err := intParam(params, "limit", 50, 1, 500)
	if err != nil {
		return nil, err
	}
	offset, err := intParam(params, "offset", 0, 0, math.MaxInt32)
	if err != nil {
		return nil, err
	}
	parts, args, err := eventFilter(params, false)
	if err != nil {
		return nil, err
	}
	where := " WHERE ts>=? AND ts<=? AND type IN ('alert','drop') AND " + detectionSQL
	bound := []any{low * 1000, high * 1000}
	if len(parts) > 0 {
		where += " AND " + strings.Join(parts, " AND ")
		bound = append(bound, args...)
	}
	if identity != "" {
		more, values, err := incidentFilter(identity)
		if err != nil {
			return nil, err
		}
		where += " AND " + strings.Join(more, " AND ")
		bound = append(bound, values...)
		limit = 1
		offset = 0
	}
	source := "WITH incident_events AS MATERIALIZED (SELECT id,type,session_id,community,flow_id,event_key,ts,sev,sid,sig,src,dst,sport,dport,proto,app,action,cat,gid," + incidentKeySQL + " incident_id" + securitySource(where, true) + ") "
	grouped := `,grouped AS (SELECT incident_id,MAX(session_id) session_id,MIN(ts) first_ts,MAX(ts) last_ts,COALESCE(MIN(NULLIF(sev,0)),0) sev,COUNT(*) alert_count,COUNT(DISTINCT COALESCE(gid,1)||':'||COALESCE(CAST(sid AS TEXT),'')||':'||sig) signature_count,MAX(CASE WHEN action IN ('blocked','drop','reject') THEN 1 ELSE 0 END) blocked FROM incident_events GROUP BY incident_id),ranked AS (SELECT *,ROW_NUMBER() OVER(PARTITION BY incident_id ORDER BY ts DESC,id DESC) rn FROM incident_events) SELECT g.*,r.src,r.dst,r.sport,r.dport,r.proto,r.sig,r.sid,r.cat FROM grouped g JOIN ranked r ON r.incident_id=g.incident_id AND r.rn=1 ORDER BY g.last_ts DESC,g.incident_id LIMIT ? OFFSET ?`
	results, err := g.Many([]statement{{"SELECT COUNT(DISTINCT " + incidentKeySQL + ") n" + securitySource(where, true), bound}, {strings.TrimSpace(source) + grouped, append(append([]any{}, bound...), limit, offset)}})
	if err != nil {
		return nil, err
	}
	out := []Object{}
	signatures := map[string][]Object{}
	blockedIDs := map[string]bool{}
	if len(results[1]) > 0 {
		// Enrich the entire page in two queries, rather than querying every
		// incident again. Keep signature limits per incident, including details.
		clauses, values, sessions := []string{}, []any{}, []any{}
		for _, row := range results[1] {
			id := text(row["incident_id"])
			if strings.HasPrefix(id, "session:") {
				sessions = append(sessions, strings.TrimPrefix(id, "session:"))
				continue
			}
			filter, args, err := incidentFilter(id)
			if err != nil {
				return nil, err
			}
			clauses = append(clauses, "("+strings.Join(filter, " AND ")+")")
			values = append(values, args...)
		}
		if len(sessions) > 0 {
			clauses = append(clauses, "(session_id<>'' AND session_id IN ("+strings.TrimSuffix(strings.Repeat("?,", len(sessions)), ",")+"))")
			values = append(values, sessions...)
		}
		pageFilter := "(" + strings.Join(clauses, " OR ") + ")"
		pageArgs := append([]any{low * 1000, high * 1000}, values...)
		hits := "WITH signature_counts AS (SELECT " + incidentKeySQL + " incident_id,sig,sid,COALESCE(gid,1) gid,sev,cat,COUNT(*) count,MIN(ts)/1000.0 first_ts,MAX(ts)/1000.0 last_ts" + securitySource(" WHERE ts>=? AND ts<=? AND type IN ('alert','drop') AND "+detectionSQL+" AND "+pageFilter, true) + " GROUP BY incident_id,sig,sid,sev,cat,gid) SELECT * FROM (SELECT *,ROW_NUMBER() OVER(PARTITION BY incident_id ORDER BY count DESC,CASE WHEN sev>0 THEN sev ELSE 99 END,sig,sid) signature_rank FROM signature_counts) ranked_signatures WHERE signature_rank<=? ORDER BY incident_id,signature_rank"
		enriched, err := g.Many([]statement{
			{hits, append(append([]any{}, pageArgs...), signatureLimit)},
			{"SELECT DISTINCT " + incidentKeySQL + " incident_id FROM events WHERE ts>=? AND ts<=? AND type='drop' AND action IN ('blocked','drop','reject') AND " + pageFilter, pageArgs},
		})
		if err != nil {
			return nil, err
		}
		for _, hit := range enriched[0] {
			id := text(hit["incident_id"])
			delete(hit, "incident_id")
			delete(hit, "signature_rank")
			signatures[id] = append(signatures[id], hit)
		}
		for _, row := range enriched[1] {
			blockedIDs[text(row["incident_id"])] = true
		}
	}
	for _, row := range results[1] {
		id := text(row["incident_id"])
		hits := signatures[id]
		if hits == nil {
			hits = []Object{}
		}
		blocked := integer(row["blocked"]) > 0 || blockedIDs[id]
		action := "allowed"
		if blocked {
			action = "blocked"
		}
		item := Object{"id": id, "session_id": get(row, "session_id", ""), "community_id": "", "tuple_hash": "", "association_flow_id": "", "first_ts": number(row["first_ts"]) / 1000, "last_ts": number(row["last_ts"]) / 1000, "ts": number(row["last_ts"]) / 1000, "sev": row["sev"], "alert_count": row["alert_count"], "signature_count": row["signature_count"], "src": get(row, "src", ""), "dst": get(row, "dst", ""), "sport": row["sport"], "dport": row["dport"], "proto": get(row, "proto", ""), "action": action, "sig": get(row, "sig", ""), "cat": get(row, "cat", ""), "signatures": hits}
		if len(hits) > 0 {
			item["sig"] = hits[0]["sig"]
			item["cat"] = hits[0]["cat"]
		}
		out = append(out, item)
	}
	return Object{"total": integer(results[0][0]["n"]), "incidents": out, "source": "db", "range": []float64{low, high}, "error": nil}, nil
}
func incidentDetail(ctx context.Context, g *Snapshot, params url.Values, low, high float64) (Object, error) {
	id := params.Get("id")
	filter, args, err := incidentFilter(id)
	if err != nil {
		return nil, err
	}
	summary, err := incidents(ctx, g, url.Values{}, low, high, id, 500)
	if err != nil {
		return nil, err
	}
	items := summary["incidents"].([]Object)
	if len(items) == 0 {
		return nil, errors.New("安全事件不存在或不在所选时间范围内")
	}
	if text(items[0]["session_id"]) != "" {
		var lo, hi float64
		if err = g.main.QueryRowContext(ctx, "SELECT COALESCE(MIN(ts),0)/1000.0,COALESCE(MAX(ts),0)/1000.0 FROM events").Scan(&lo, &hi); err != nil {
			return nil, err
		}
		low, high = lo, hi
		summary, err = incidents(ctx, g, url.Values{}, low, high, id, 500)
		if err != nil {
			return nil, err
		}
		items = summary["incidents"].([]Object)
	}
	list := params.Get("view") == "list"
	alertParts := append(append([]string{}, filter...), "type IN ('alert','drop')", detectionSQL)
	alertTotal, alerts, err := search(ctx, g, low, high, alertParts, args, 500, 0, list, false, true)
	if err != nil {
		return nil, err
	}
	offset, err := intParam(params, "network_offset", 0, 0, math.MaxInt32)
	if err != nil {
		return nil, err
	}
	limit, err := intParam(params, "network_limit", 50, 1, 500)
	if err != nil {
		return nil, err
	}
	total, network, err := search(ctx, g, low, high, filter, args, limit, offset, list, true, false)
	if err != nil {
		return nil, err
	}
	items[0]["network_count"] = total
	relation := "event"
	if text(items[0]["session_id"]) != "" {
		relation = "session"
	}
	attack := Object{}
	rows, err := queryRows(ctx, g.main, "SELECT raw"+securitySource(" WHERE ts>=? AND ts<=? AND "+strings.Join(alertParts, " AND "), true), append([]any{low * 1000, high * 1000}, args...)...)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if blob, ok := row["raw"].([]byte); ok && len(blob) > 0 {
			raw, e := decompress(blob)
			if e != nil {
				return nil, e
			}
			event, e := ParseEvent(raw)
			if e != nil || event == nil {
				continue
			}
			for _, key := range strings.Fields("mitre_tactic_id mitre_tactic_name mitre_technique_id mitre_technique_name") {
				values := array(event.Record[key])
				current := array(attack[key])
				for _, rawValue := range values {
					v := text(rawValue)
					if v == "" {
						continue
					}
					found := false
					for _, existing := range current {
						if existing == v {
							found = true
							break
						}
					}
					if !found {
						current = append(current, v)
					}
				}
				attack[key] = current
			}
		}
	}
	return Object{"incident": items[0], "alerts": alerts, "network": network, "attack": attack, "relation": relation, "context_range": []float64{low, high}, "range": []float64{low, high}, "network_offset": offset, "network_limit": limit, "truncated": alertTotal > int64(len(alerts))}, nil
}
