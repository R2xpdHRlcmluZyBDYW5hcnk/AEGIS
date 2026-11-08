package console

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed assistant_prompts.json
var assistantPromptData []byte
var assistantPrompts Object

func init() {
	if err := decode(assistantPromptData, &assistantPrompts); err != nil {
		panic(err)
	}
}

type proposal struct {
	owner, rule string
	created     time.Time
	accepted    Object
}
type Assistant struct {
	app       *App
	gate      chan struct{}
	mu        sync.Mutex
	proposals map[string]*proposal
	client    *http.Client
}

func NewAssistant(app *App) *Assistant {
	return &Assistant{app: app, gate: make(chan struct{}, 1), proposals: map[string]*proposal{}, client: &http.Client{Transport: &http.Transport{DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, ResponseHeaderTimeout: 0, DisableKeepAlives: true, Proxy: nil}}}
}
func (a *Assistant) Add(ctx context.Context, owner, key string) (Object, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p := a.proposals[key]
	if p == nil || p.owner != owner || time.Since(p.created) > 10*time.Minute {
		return nil, errors.New("规则建议已过期，请重新生成")
	}
	if p.accepted != nil {
		return clone(p.accepted), nil
	}
	value, err := a.app.Manager(ctx, "mutate", Object{"method": "POST", "path": "/api/hunt/rules/add-apply", "body": Object{"rule": p.rule}})
	if err != nil {
		return nil, err
	}
	result := object(value)
	if result["ok"] == true {
		p.accepted = result
	}
	return result, nil
}
func (a *App) SummaryContext(ctx context.Context, target Object) (Object, error) {
	var anchor Object
	switch text(target["kind"]) {
	case "record":
		detail, err := a.Store.Record(ctx, text(target["key"]))
		if err != nil {
			return nil, err
		}
		anchor = object(detail["record"])
	case "event":
		id := integer(target["id"])
		rows, err := queryRows(ctx, a.Store.Readers, "SELECT * FROM events WHERE id=?", id)
		if err != nil || len(rows) == 0 {
			return nil, errors.New("事件明细已超过保留范围")
		}
		anchor, err = readRecordRow(rows[0], false, false)
		if err != nil {
			return nil, err
		}
	case "incident":
		params := object(target["params"])
		clauses, args, err := incidentFilter(text(params["id"]))
		if err != nil {
			return nil, err
		}
		rows, err := queryRows(ctx, a.Store.Readers, "SELECT * FROM events WHERE "+strings.Join(clauses, " AND ")+" ORDER BY ts DESC,id DESC LIMIT 1", args...)
		if err != nil || len(rows) == 0 {
			return nil, errors.New("事件已不存在")
		}
		anchor, err = readRecordRow(rows[0], false, false)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("需要有效事件标识")
	}
	delete(anchor, "_raw")
	id := text(anchor["session_id"])
	records := []Object{anchor}
	total := int64(1)
	first, last := number(anchor["ts"]), number(anchor["ts"])
	counts := Object{text(anchor["type"]): 1}
	actions := Object{}
	scope := "event"
	if sessionValid(id) {
		g, err := a.Store.Snapshot(ctx, true)
		if err != nil {
			return nil, err
		}
		defer g.Close()
		rows, err := queryRows(ctx, g.main, "SELECT COUNT(*) n,MIN(ts)/1000.0 first,MAX(ts)/1000.0 last FROM events WHERE session_id=?", id)
		if err != nil {
			return nil, err
		}
		total = integer(rows[0]["n"])
		first, last = number(rows[0]["first"]), number(rows[0]["last"])
		records = []Object{}
		used := map[string]bool{}
		collect := func(predicate string, args []any, limit int, oldest bool) error {
			where := "session_id=?"
			bound := []any{id}
			if predicate != "" {
				where += " AND (" + predicate + ")"
				bound = append(bound, args...)
			}
			direction := "DESC"
			if oldest {
				direction = "ASC"
			}
			rows, err := queryRows(ctx, g.main, "SELECT * FROM events WHERE "+where+" ORDER BY ts "+direction+",id "+direction+" LIMIT ?", append(bound, limit)...)
			if err != nil {
				return err
			}
			for _, row := range rows {
				key := text(row["id"])
				if used[key] {
					continue
				}
				r, err := readRecordRow(row, false, false)
				if err != nil {
					return err
				}
				used[key] = true
				records = append(records, r)
			}
			return nil
		}
		for _, choice := range []struct {
			predicate string
			limit     int
			oldest    bool
		}{{"type IN ('alert','drop')", 2, false}, {"type IN ('alert','drop') AND action IN ('blocked','drop','reject','reset')", 1, false}, {"type='flow' OR (type='quic' AND flow_start IS NOT NULL)", 1, false}, {"type='session'", 1, false}, {"type='dns'", 1, false}, {"type='tls'", 1, false}, {"type='http'", 1, false}, {"type='anomaly'", 1, false}, {"type='fileinfo'", 1, false}, {"", 1, true}, {"", 1, false}} {
			if err = collect(choice.predicate, nil, choice.limit, choice.oldest); err != nil {
				return nil, err
			}
		}
		kinds, err := queryRows(ctx, g.main, "SELECT type,action,COUNT(*) n FROM events WHERE session_id=? GROUP BY type,action", id)
		if err != nil {
			return nil, err
		}
		counts = Object{}
		for _, r := range kinds {
			key := text(r["type"])
			counts[key] = integer(counts[key]) + integer(r["n"])
			key = text(r["action"])
			actions[key] = integer(actions[key]) + integer(r["n"])
		}
		scope = "session"
	}
	for _, r := range records {
		delete(r, "_raw")
	}
	return Object{"scope": scope, "session_id": id, "total_records": total, "first_ts": first, "last_ts": last, "event_counts": counts, "action_counts": actions, "records": records, "anchor": anchor}, nil
}
func compactEvidence(record Object) Object {
	out := Object{}
	for _, key := range array(assistantPrompts["FIELDS"]) {
		name := text(key)
		if v, ok := record[name]; ok && v != nil && text(v) != "" {
			if s, ok := v.(string); ok {
				v = trim(s, 100)
			}
			out[name] = v
		}
	}
	return out
}
func boundedPrompt(system string, evidence Object, candidates []Object) ([]Object, []Object, error) {
	data := clone(evidence)
	delete(data, "anchor")
	rows := []Object{}
	for _, v := range array(data["records"]) {
		rows = append(rows, compactEvidence(object(v)))
	}
	if v, ok := data["records"].([]Object); ok {
		rows = []Object{}
		for _, r := range v {
			rows = append(rows, compactEvidence(r))
		}
	}
	data["records"] = rows
	if candidates != nil {
		data["candidates"] = candidates
	}
	for {
		encoded, err := json.Marshal(data)
		if err != nil {
			return nil, nil, err
		}
		if len(system)+len(encoded) <= 1500 {
			return []Object{{"role": "system", "content": system}, {"role": "user", "content": string(encoded)}}, candidates, nil
		}
		if len(rows) > 1 {
			rows = rows[:len(rows)-1]
			data["records"] = rows
			continue
		}
		if candidates != nil && len(candidates) > 1 {
			candidates = candidates[:len(candidates)-1]
			data["candidates"] = candidates
			continue
		}
		if _, ok := data["hunts"]; ok {
			delete(data, "hunts")
			continue
		}
		if _, ok := data["dns_clues"]; ok {
			delete(data, "dns_clues")
			continue
		}
		if len(rows) > 0 {
			rows = nil
			data["records"] = rows
			continue
		}
		return nil, nil, errors.New("研判证据超过模型上下文预算")
	}
}

type streamResult struct {
	text, finish string
	err          error
}
type visibleText struct{ pending, hidden string }

func (f *visibleText) Feed(chunk string, final bool) (string, string) {
	f.pending += chunk
	visible, reasoning := "", ""
	for {
		tags := []string{"<think>", "<thinking>", "<analysis>"}
		if f.hidden != "" {
			tags = []string{f.hidden}
		}
		lower := strings.ToLower(f.pending)
		tag, at := "", -1
		for _, candidate := range tags {
			if index := strings.Index(lower, candidate); index >= 0 && (at < 0 || index < at) {
				tag, at = candidate, index
			}
		}
		if at >= 0 {
			piece := f.pending[:at]
			if f.hidden != "" {
				reasoning += piece
			} else {
				visible += piece
			}
			f.pending = f.pending[at+len(tag):]
			if f.hidden == "" {
				f.hidden = "</" + strings.TrimPrefix(tag, "<")
			} else {
				f.hidden = ""
			}
			continue
		}
		keep := 0
		if !final {
			for _, candidate := range tags {
				for i := 1; i < len(candidate) && i <= len(lower); i++ {
					if strings.HasSuffix(lower, candidate[:i]) {
						keep = max(keep, i)
					}
				}
			}
		}
		piece := f.pending[:len(f.pending)-keep]
		f.pending = f.pending[len(f.pending)-keep:]
		if f.hidden != "" {
			reasoning += piece
		} else {
			visible += piece
		}
		break
	}
	return visible, reasoning
}

type publicAnalysis struct {
	section, pending string
	remaining        int
}

func (p *publicAnalysis) Feed(text string, final bool) (string, string) {
	if p.section == "" {
		p.remaining = 120
		p.section = "prefix"
	}
	if p.section == "prefix" {
		text = strings.TrimLeft(p.pending+text, " \t\r\n")
		prefix := ""
		for _, v := range []string{"分析说明：", "分析说明:"} {
			if strings.HasPrefix(text, v) {
				prefix = v
				break
			}
		}
		if prefix != "" {
			p.section = "note"
			text = strings.TrimPrefix(text, prefix)
		} else if !final && (strings.HasPrefix("分析说明：", text) || strings.HasPrefix("分析说明:", text)) {
			p.pending = text
			return "", ""
		} else {
			p.section = "body"
		}
		p.pending = ""
	}
	if p.section == "note" {
		note, body, ok := strings.Cut(text, "\n")
		note = trim(note, p.remaining)
		p.remaining -= len([]rune(note))
		if ok {
			p.section = "body"
		}
		return note, body
	}
	return "", text
}
func (a *Assistant) infer(ctx context.Context, messages []Object, options Object, tokens int, stream bool, replace bool, send func(Object) bool) (string, string, error) {
	payload := clone(options)
	payload["model"] = "Qwen3.5-2B"
	payload["stream"] = true
	payload["max_tokens"] = tokens
	payload["messages"] = messages
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}
	request, err := http.NewRequestWithContext(ctx, "POST", "http://127.0.0.1:18080/v1/chat/completions", bytes.NewReader(encoded))
	if err != nil {
		return "", "", err
	}
	request.Header.Set("Content-Type", "application/json")
	updates := make(chan Object, 16)
	done := make(chan streamResult, 1)
	workerCtx, cancel := context.WithCancel(ctx)
	workerFinished := make(chan struct{})
	defer func() { cancel(); <-workerFinished }()
	request = request.WithContext(workerCtx)
	go func() {
		defer close(workerFinished)
		response, err := a.client.Do(request)
		if err != nil {
			done <- streamResult{err: errors.New("本地模型连接失败")}
			return
		}
		defer response.Body.Close()
		if response.StatusCode != 200 || !strings.Contains(response.Header.Get("Content-Type"), "text/event-stream") {
			done <- streamResult{err: errors.New("本地模型未提供流式响应")}
			return
		}
		scanner := bufio.NewScanner(response.Body)
		scanner.Buffer(make([]byte, 4096), 32769)
		filter := visibleText{}
		analysis := publicAnalysis{}
		var output strings.Builder
		finish := ""
		received := 0
		complete := false
		first := true
		publish := func(v Object) bool {
			select {
			case updates <- v:
				return true
			case <-workerCtx.Done():
				return false
			}
		}
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			raw := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if raw == "[DONE]" {
				complete = true
				break
			}
			var chunk Object
			if decode([]byte(raw), &chunk) != nil || chunk["error"] != nil {
				done <- streamResult{err: errors.New("本地模型响应格式无效")}
				return
			}
			for _, v := range array(chunk["choices"]) {
				choice := object(v)
				delta := object(choice["delta"])
				content, reason := "", ""
				if delta["content"] != nil {
					var valid bool
					content, valid = delta["content"].(string)
					if !valid {
						done <- streamResult{err: errors.New("本地模型响应格式无效")}
						return
					}
				}
				if delta["reasoning_content"] != nil {
					var valid bool
					reason, valid = delta["reasoning_content"].(string)
					if !valid {
						done <- streamResult{err: errors.New("本地模型响应格式无效")}
						return
					}
				}
				received += len(content) + len(reason)
				if received > 32768 {
					done <- streamResult{err: errors.New("本地模型响应超过上限")}
					return
				}
				visible, _ := filter.Feed(content, false)
				note, visible := analysis.Feed(visible, false)
				if note != "" && !publish(Object{"analysis_delta": note}) {
					return
				}
				if reason != "" && !publish(Object{"reasoning_delta": reason}) {
					return
				}
				if visible != "" {
					if first {
						visible = strings.TrimLeft(visible, " \t\r\n")
					}
					output.WriteString(visible)
					if stream && visible != "" {
						item := Object{"delta": visible}
						if first && replace {
							item["replace_draft"] = true
						}
						if !publish(item) {
							return
						}
					}
					first = false
				}
				if f := text(choice["finish_reason"]); f != "" {
					finish = f
				}
			}
		}
		visible, _ := filter.Feed("", true)
		note, visible := analysis.Feed(visible, true)
		if note != "" {
			publish(Object{"analysis_delta": note})
		}
		output.WriteString(visible)
		if stream && visible != "" {
			publish(Object{"delta": visible})
		}
		if err := scanner.Err(); err != nil || !complete || (finish != "stop" && finish != "length") {
			done <- streamResult{err: errors.New("本地模型响应中断，请重新生成")}
			return
		}
		done <- streamResult{text: strings.TrimSpace(output.String()), finish: finish}
	}()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	started := false
	deliver := func(item Object) bool {
		if item["delta"] != nil && !started {
			if !send(Object{"analysis_done": true}) {
				return false
			}
			started = true
		}
		return send(item)
	}
	for {
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-ticker.C:
			if !send(Object{"status": "generating"}) {
				return "", "", context.Canceled
			}
		case item := <-updates:
			if !deliver(item) {
				return "", "", context.Canceled
			}
		case result := <-done:
			for {
				select {
				case item := <-updates:
					if !deliver(item) {
						return "", "", context.Canceled
					}
				default:
					return result.text, result.finish, result.err
				}
			}
		}
	}
}
func (a *Assistant) Generate(ctx context.Context, owner string, body Object, send func(Object) bool) error {
	kind := text(body["kind"])
	if (kind != "summary" && kind != "rule") || len(object(body["target"])) == 0 {
		return errors.New("不支持的生成功能")
	}
	action := text(get(body, "action", "alert"))
	if action != "alert" && action != "block" {
		return errors.New("规则动作无效")
	}
	if object(a.app.Config.Raw["local_llm"])["enabled"] == false {
		return errors.New("本地模型未启用")
	}
	select {
	case a.gate <- struct{}{}:
		defer func() { <-a.gate }()
	default:
		return errors.New("本地模型正在生成，请稍后重试")
	}
	progress := func(id, label, state string) bool {
		return send(Object{"progress": Object{"id": id, "label": label, "state": state, "detail": ""}})
	}
	if !progress("evidence", "读取事件证据", "running") {
		return context.Canceled
	}
	evidence, err := a.app.SummaryContext(ctx, object(body["target"]))
	if err != nil {
		return err
	}
	if !progress("evidence", "证据读取完成", "done") {
		return context.Canceled
	}
	if kind == "rule" {
		rows := []Object{}
		for _, v := range array(evidence["records"]) {
			rows = append(rows, object(v))
		}
		if v, ok := evidence["records"].([]Object); ok {
			rows = v
		}
		choices := ruleCandidates(rows)
		if len(choices) == 0 {
			send(Object{"result": Object{"unavailable": true, "reason": "缺少可用于检测的协议、应用或异常报头特征，未生成规则"}})
			return nil
		}
		messages, choices, err := boundedPrompt(text(assistantPrompts["RULE_PROMPT"]), evidence, choices)
		if err != nil {
			return err
		}
		progress("rule", "深度分析规则条件与误报限制", "running")
		output, finish, err := a.infer(ctx, messages, object(assistantPrompts["THINKING_OPTIONS"]), 1024, false, false, send)
		if err != nil {
			return err
		}
		if finish != "stop" {
			return errors.New("本地模型输出不完整，请重新生成")
		}
		choice, err := modelJSON(output)
		if err != nil {
			return err
		}
		result, err := ruleFromChoice(choice, choices, action)
		if err != nil {
			return err
		}
		if line := text(result["rule"]); line != "" {
			a.mu.Lock()
			for key, p := range a.proposals {
				if time.Since(p.created) > 10*time.Minute {
					delete(a.proposals, key)
				}
			}
			for len(a.proposals) >= 16 {
				var oldest string
				var stamp time.Time
				for k, p := range a.proposals {
					if oldest == "" || p.created.Before(stamp) {
						oldest, stamp = k, p.created
					}
				}
				delete(a.proposals, oldest)
			}
			key := token()
			a.proposals[key] = &proposal{owner: owner, rule: line, created: time.Now()}
			a.mu.Unlock()
			result["proposal"] = key
		}
		progress("rule", "规则建议整理完成", "done")
		send(Object{"analysis_done": true})
		send(Object{"result": result})
		return nil
	}
	progress("plan", "规划关联日志检索", "running")
	planning, err := planMessages(evidence)
	if err != nil {
		return err
	}
	plan, finish, err := a.infer(ctx, planning, object(assistantPrompts["DIRECT_OPTIONS"]), 224, false, false, send)
	if err != nil {
		return err
	}
	hunts := []Object{}
	huntStatus := "invalid"
	if finish == "stop" {
		if value, e := modelJSON(plan); e == nil {
			hunts, huntStatus = a.runHunts(ctx, evidence, value, progress)
		}
	}
	latest, err := a.app.SummaryContext(ctx, object(body["target"]))
	if err != nil {
		return err
	}
	latest["anchor"] = evidence["anchor"]
	evidence = latest
	evidence["hunts"] = hunts
	progress("plan", "关联日志核查完成", "done")
	dns, err := a.app.DNSContext(ctx, evidence)
	if err != nil {
		dns = Object{"status": "unavailable", "records": []Object{}}
	}
	evidence["dns_clues"] = dns
	evidence["hunt_status"] = huntStatus
	messages, meta, err := summaryMessages(evidence, hunts)
	if err != nil {
		return err
	}
	tokens := bounded(int(integer(get(a.app.Config.Raw, "llm_summary_max_tokens", 384))), 384, 1024)
	if tokens == 1024 {
		tokens = 3072
	}
	progress("compose", "深度分析并组织总结", "running")
	output, finish, err := a.infer(ctx, messages, object(assistantPrompts["SUMMARY_THINKING_OPTIONS"]), tokens, true, false, send)
	if err != nil {
		return err
	}
	if finish == "length" || output == "" {
		retry := append([]Object{}, messages...)
		retry[0] = Object{"role": "system", "content": assistantPrompts["COMPACT_SUMMARY_PROMPT"]}
		replacement, retryFinish, e := a.infer(ctx, retry, object(assistantPrompts["DIRECT_OPTIONS"]), 384, true, output != "", send)
		if e == nil && replacement != "" {
			output = replacement
			finish = retryFinish
		}
	}
	if output == "" {
		return errors.New("本地模型未生成总结正文，请重新生成")
	}
	send(Object{"analysis_done": true})
	publicHunts := []Object{}
	for _, h := range hunts {
		copy := clone(h)
		delete(copy, "records")
		publicHunts = append(publicHunts, copy)
	}
	send(Object{"result": Object{"text": output, "model": "Qwen3.5-2B", "context": meta, "hunt_status": huntStatus, "truncated": finish == "length", "dns_clues": dns, "hunts": publicHunts}})
	return nil
}
func modelJSON(value string) (Object, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "```") {
		value = strings.TrimSpace(strings.TrimPrefix(value, "```json"))
		value = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(value, "```"), "```"))
	}
	start, end := strings.IndexByte(value, '{'), strings.LastIndexByte(value, '}')
	if start < 0 || end < start {
		return nil, errors.New("模型没有返回有效 JSON")
	}
	var result Object
	if err := decode([]byte(value[start:end+1]), &result); err != nil {
		return nil, errors.New("模型返回格式无效")
	}
	return result, nil
}
func (a *Assistant) runHunts(ctx context.Context, evidence, plan Object, progress func(string, string, string) bool) ([]Object, string) {
	results := []Object{}
	checks, ok := plan["checks"].([]any)
	if !ok || len(checks) > 2 {
		return results, "invalid"
	}
	if len(checks) == 0 {
		return results, "not_needed"
	}
	status := "complete"
	seen := map[string]bool{}
	for i, raw := range checks {
		if i >= 2 {
			break
		}
		item := object(raw)
		query, err := compileModelTerms(item["terms"])
		if err != nil {
			status = "partial"
			continue
		}
		if seen[query] {
			continue
		}
		seen[query] = true
		if !progress(fmt.Sprintf("hunt-%d", i), "检索关联日志", "running") {
			break
		}
		result, err := a.relatedHunt(ctx, evidence, query)
		if err != nil {
			status = "partial"
			results = append(results, Object{"predicate": query, "total": nil, "label": trim(text(item["reason"]), 60), "source": "model", "scope": "related", "error": "关联检索未完成，请重试", "error_kind": "execution", "records": []Object{}})
			continue
		}
		result["label"], result["source"] = trim(text(item["reason"]), 60), "model"
		results = append(results, result)
	}
	if len(results) == 0 && status == "partial" {
		status = "invalid"
	}
	return results, status
}

var domainPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]$`)

func ruleCandidates(rows []Object) []Object {
	out := []Object{}
	seen := map[string]bool{}
	for _, r := range rows {
		proto := strings.ToLower(text(r["proto"]))
		if proto != "tcp" && proto != "udp" {
			continue
		}
		source, e := netip.ParseAddr(text(r["src"]))
		destination, f := netip.ParseAddr(text(r["dst"]))
		port := integer(r["dport"])
		if e != nil || f != nil || source.BitLen() != destination.BitLen() || port < 1 || port > 65535 {
			continue
		}
		domain := func(v any) string {
			s := strings.TrimRight(strings.ToLower(text(v)), ".")
			if domainPattern.MatchString(s) {
				return s
			}
			return ""
		}
		host, sni, dns := domain(r["host"]), domain(r["sni"]), domain(r["dns"])
		candidate := Object{"proto": proto, "dport": port}
		switch {
		case proto == "tcp" && host != "":
			candidate["kind"] = "http"
			candidate["host"] = host
			if u, err := url.Parse(text(r["url"])); err == nil && strings.HasPrefix(u.Path, "/") && len(u.Path) >= 4 && len(u.Path) <= 120 && !strings.ContainsAny(u.Path, "\x00\r\n") {
				candidate["path"] = u.Path
			}
			if method := text(r["method"]); regexp.MustCompile(`^[A-Z]{2,12}$`).MatchString(method) {
				candidate["method"] = method
			}
		case proto == "tcp" && sni != "":
			candidate["kind"] = "tls"
			candidate["sni"] = sni
		case port == 53 && dns != "":
			valid := true
			for _, label := range strings.Split(dns, ".") {
				if len(label) < 1 || len(label) > 63 {
					valid = false
				}
			}
			if !valid {
				continue
			}
			candidate["kind"] = "dns"
			candidate["dns"] = dns
		case proto == "tcp" && strictInt(r["tcp_flags"], 0, 255) && (integer(r["tcp_flags"]) == 0 || integer(r["tcp_flags"])&3 == 3 || integer(r["tcp_flags"])&6 == 6 || integer(r["tcp_flags"])&41 == 41):
			candidate["kind"] = "tcp_flags"
			candidate["flags"] = integer(r["tcp_flags"])
			extra := Object{}
			for k, field := range map[string]string{"ttl": "ip_ttl", "tos": "ip_tos", "window": "tcp_window", "dsize": "data_len"} {
				limit := int64(65535)
				if k == "ttl" || k == "tos" {
					limit = 255
				}
				if v := r[field]; strictInt(v, 0, limit) {
					extra[k] = integer(v)
				}
			}
			candidate["metadata"] = extra
		default:
			application := text(r["appid_payload"])
			if application == "" || strings.Contains("|unknown|failed|http|https|dns|ssl|tls|", "|"+strings.ToLower(application)+"|") || !regexp.MustCompile(`^[A-Za-z0-9 _./:-]{1,80}$`).MatchString(application) {
				continue
			}
			candidate["kind"] = "appid"
			candidate["application"] = application
		}
		data, _ := json.Marshal(candidate)
		if !seen[string(data)] {
			seen[string(data)] = true
			out = append(out, candidate)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		score := func(m Object) int {
			n := 0
			if m["kind"] == "http" {
				n += 4
			}
			if m["path"] != nil {
				n += 2
			}
			if m["kind"] == "tls" {
				n++
			}
			return n
		}
		return score(out[i]) > score(out[j])
	})
	return out[:min(4, len(out))]
}
func hexContent(data []byte) string {
	out := []string{}
	for _, b := range data {
		out = append(out, strings.ToUpper(hex.EncodeToString([]byte{b})))
	}
	return "|" + strings.Join(out, " ") + "|"
}
func ruleFromChoice(value Object, choices []Object, action string) (Object, error) {
	if value["candidate"] == nil {
		return Object{"unavailable": true, "reason": trim(text(get(value, "reason", "证据不足，未生成规则")), 500)}, nil
	}
	n := integer(value["candidate"])
	if !strictInt(value["candidate"], 0, int64(len(choices)-1)) {
		return nil, errors.New("模型返回了证据范围外的规则条件")
	}
	c := choices[n]
	message := regexp.MustCompile(`["\\;:\x00-\x1f\x7f]`).ReplaceAllString(text(get(value, "message", "NDR observed indicator")), " ")
	message = strings.TrimSpace(trim(message, 80))
	if message == "" {
		message = "NDR observed indicator"
	}
	options := "msg:\"" + message + "\"; "
	scope, caveat := "", ""
	flow := "flow:to_server; "
	if c["proto"] == "tcp" {
		flow = "flow:to_server,established; "
	}
	switch c["kind"] {
	case "http":
		options += flow + "http_header:field host; content:\"" + text(c["host"]) + "\",nocase; "
		if method := text(c["method"]); method != "" {
			options += "http_method; content:\"" + method + "\"; "
		}
		if path := text(c["path"]); path != "" {
			options += "http_uri:path; content:\"" + hexContent([]byte(path)) + "\"; "
		}
		scope = "HTTP Host、方法与路径内容检测"
		caveat = "正常访问同一特征也会告警"
	case "tls":
		options += flow + "ssl_state:client_hello; content:\"" + text(c["sni"]) + "\",nocase; "
		scope = "TLS ClientHello 域名文字检测"
		caveat = "不解析加密应用内容或 ECH，域名文字匹配不等于严格 SNI 字段定位"
	case "dns":
		wire := []byte{}
		for _, label := range strings.Split(text(c["dns"]), ".") {
			wire = append(wire, byte(len(label)))
			wire = append(wire, label...)
		}
		wire = append(wire, 0)
		options += flow + "content:\"" + hexContent(wire) + "\",nocase; "
		scope = "DNS 查询名称字节特征检测"
		caveat = "不匹配加密 DNS；名称压缩可能不命中"
	case "tcp_flags":
		flags := integer(c["flags"])
		letters := ""
		for i, name := range "FSRPAUEC" {
			if flags&(1<<i) != 0 {
				letters += string(name)
			}
		}
		if letters == "" {
			letters = "0"
		}
		options += "flags:" + letters + "; "
		extra := array(value["extra"])
		if len(extra) > 4 {
			return nil, errors.New("规则附加条件超出证据")
		}
		keys := []string{}
		metadata := object(c["metadata"])
		for _, v := range extra {
			k := text(v)
			if _, ok := metadata[k]; !ok {
				return nil, errors.New("规则附加条件超出证据")
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			options += k + ":" + text(metadata[k]) + "; "
		}
		scope = "已观察到的异常 TCP 标志组合"
		caveat = "包头采样不代表所有报文，正常诊断也可能命中"
	case "appid":
		options += flow + "appids:\"" + text(c["application"]) + "\"; "
		scope = "OpenAppID 应用特征检测"
		caveat = "应用识别不等于恶意行为"
	default:
		return nil, errors.New("无效候选规则")
	}
	line := action + " " + text(c["proto"]) + " any any -> any " + text(c["dport"]) + " (" + options + "rev:1;)"
	if len(line) > 4096 {
		return nil, errors.New("规则超过长度限制")
	}
	return Object{"rule": line, "reason": trim(text(value["reason"]), 500), "scope": scope, "limitations": strings.TrimSpace(trim(text(value["limitations"]), 300) + " " + caveat), "notice": action + " 将按这些内容特征检测；请核查误报后添加并应用"}, nil
}

var _ = io.EOF
