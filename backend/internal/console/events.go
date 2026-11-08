package console

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

//go:embed schema.json
var schemaData []byte
var schema struct {
	Columns          [][2]*string      `json:"columns"`
	Numeric          []string          `json:"numeric"`
	EventFields      map[string]string `json:"event_fields"`
	NativeFields     map[string]string `json:"native_fields"`
	HuntFields       map[string]string `json:"hunt_fields"`
	HuntNumeric      []string          `json:"hunt_numeric"`
	HuntSubstring    []string          `json:"hunt_substring"`
	HuntSchema       Object            `json:"hunt_schema"`
	HuntCI           []string          `json:"hunt_ci"`
	HuntLevelAliases map[string]string `json:"hunt_level_aliases"`
	EventKinds       []string          `json:"event_kinds"`
}
var numericColumns = map[string]bool{}
var sessionPattern = regexp.MustCompile(`^[0-9a-f]{32}:[0-9a-f]{16}$`)
var nativeUID = regexp.MustCompile(`^[0-9]{1,20}$`)
var eventKinds = map[string]bool{}

func init() {
	if err := json.Unmarshal(schemaData, &schema); err != nil {
		panic(err)
	}
	for _, s := range schema.Numeric {
		numericColumns[s] = true
	}
	for _, s := range schema.EventKinds {
		eventKinds[s] = true
	}
}
func present(values ...any) any {
	for _, v := range values {
		switch x := v.(type) {
		case nil:
			continue
		case string:
			if x == "" {
				continue
			}
		case bool:
			if !x {
				continue
			}
		case json.Number:
			if x == "0" {
				continue
			}
		}
		return v
	}
	return ""
}
func suppressedAlert(value any) bool { return value == true || number(value) == 1 }
func strictInt(v any, low, high int64) bool {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		return err == nil && i >= low && i <= high
	case int:
		return int64(n) >= low && int64(n) <= high
	case int64:
		return n >= low && n <= high
	}
	return false
}
func sessionValid(id string) bool {
	return sessionPattern.MatchString(id) && !strings.HasSuffix(id, ":0000000000000000")
}
func NativeKind(data Object) string {
	if _, ok := data["sid"]; ok {
		if _, rev := data["rev"]; rev {
			return "notice"
		}
		return "weird"
	}
	for _, pair := range [][2]string{{"orig_pkts", "conn"}, {"trans_depth", "http"}, {"trans_id", "dns"}, {"fuid", "file"}, {"client_initial_dcid", "quic"}, {"reply_code", "ftp"}, {"module_identifier", "ssl"}, {"direction", "ssh"}} {
		if _, ok := data[pair[0]]; ok {
			return pair[1]
		}
	}
	return ""
}

func sessionEvent(envelope Object) (Object, error) {
	d := object(envelope["data"])
	id, ev := text(d["session_id"]), text(d["event"])
	if !sessionValid(id) || !strings.Contains("|start|first_observed|state|application|update|end|", "|"+ev+"|") {
		return nil, errors.New("无效会话身份或生命周期")
	}
	src, e1 := netip.ParseAddr(text(d["src"]))
	dst, e2 := netip.ParseAddr(text(d["dst"]))
	if e1 != nil || e2 != nil || !strictInt(d["sport"], 0, 65535) || !strictInt(d["dport"], 0, 65535) {
		return nil, errors.New("无效会话端点")
	}
	proto := text(d["proto"])
	if proto != "TCP" && proto != "UDP" && proto != "ICMP" && proto != "IP" {
		return nil, errors.New("无效会话协议")
	}
	first, last, ts := number(d["first_observed"]), number(d["last_observed"]), number(d["ts"])
	if first <= 0 || last < first || ts <= 0 || math.IsInf(first+last+ts, 0) || math.IsNaN(first+last+ts) {
		return nil, errors.New("无效会话时间")
	}
	syn, synOK := d["initial_syn_observed"].(bool)
	limited, limitedOK := d["state_limit_reached"].(bool)
	if !synOK || !limitedOK {
		return nil, errors.New("无效会话标记")
	}
	native := Object{"session_id": id, "session_event": ev, "observed_first": first, "observed_last": last, "session_origin": "partial", "session_limited": ""}
	if syn {
		native["session_origin"] = "syn_observed"
	}
	if limited {
		native["session_limited"] = "state_limit_reached"
	}
	for _, field := range strings.Fields("service client payload misc referred") {
		key := "appid_" + field
		n := get(d, key+"_id", json.Number("0"))
		name := get(d, key, "")
		str, ok := name.(string)
		if !ok || len(str) > 1012 || !strictInt(n, -1, 2147483647) {
			return nil, errors.New("无效应用身份")
		}
		native[key] = str
		native[key+"_id"] = n
	}
	for _, key := range strings.Fields("orig_pkts resp_pkts orig_wire_bytes resp_wire_bytes") {
		if !strictInt(d[key], 0, math.MaxInt64) {
			return nil, errors.New("无效会话计数")
		}
	}
	native["wire_bytes_toserver"] = d["orig_wire_bytes"]
	native["wire_bytes_toclient"] = d["resp_wire_bytes"]
	limits := map[string]int64{"icmp_type": 255, "icmp_code": 255, "packet_len": 4294967295, "data_len": 65535, "ip_ttl": 255, "ip_tos": 65535, "ip_id": 4294967295, "ip_offset": 65535, "ip_flags": 7, "ip_proto": 255, "ip_header_len": 255, "tcp_flags": 255, "tcp_window": 65535, "tcp_seq": 4294967295, "tcp_ack": 4294967295, "tcp_options_len": 255}
	for key, limit := range limits {
		if v, ok := d[key]; ok {
			if !strictInt(v, 0, limit) {
				return nil, errors.New("无效报文计数")
			}
			native[key] = v
		}
	}
	if v, ok := d["packet_ts"]; ok {
		n := number(v)
		if n <= 0 || math.IsNaN(n) || math.IsInf(n, 0) {
			return nil, errors.New("无效报文时间")
		}
		native["packet_ts"] = n
	}
	if v, ok := d["packet_direction"]; ok {
		if v != "to_server" && v != "to_client" && v != "unknown" {
			return nil, errors.New("无效报文方向")
		}
		native["packet_direction"] = v
	}
	states := strings.Fields("LISTEN SYN_SENT SYN_RECV ESTABLISHED MID_STREAM_SENT MID_STREAM_RECV FIN_WAIT1 FIN_WAIT2 CLOSE_WAIT CLOSING LAST_ACK TIME_WAIT CLOSED STATE_NONE")
	state := []string{}
	if proto == "TCP" {
		for _, entry := range [][2]string{{"client_state", "CLT_TCP_"}, {"server_state", "SRV_TCP_"}} {
			v := get(d, entry[0], json.Number("-1"))
			if !strictInt(v, -1, int64(len(states)-1)) {
				return nil, errors.New("无效 TCP 状态")
			}
			if i := integer(v); i >= 0 {
				state = append(state, entry[1]+states[i])
			}
		}
	}
	return Object{"event_type": "session", "timestamp": utc(ts), "src_ip": src.String(), "dest_ip": dst.String(), "src_port": d["sport"], "dest_port": d["dport"], "proto": proto, "app_proto": native["appid_service"], "snort_native": native, "flow": Object{"age": last - first, "state": strings.Join(state, " "), "pkts_toserver": d["orig_pkts"], "pkts_toclient": d["resp_pkts"]}}, nil
}

func nativeEvent(envelope Object) (Object, error) {
	if envelope["engine"] == "snort_session" {
		return sessionEvent(envelope)
	}
	if envelope["engine"] == "quic_observer" {
		return observerEvent(envelope)
	}
	if envelope["engine"] != "snort3" {
		return envelope, nil
	}
	d := object(envelope["data"])
	kind := text(present(envelope["kind"], NativeKind(d)))
	if kind == "decoder" {
		d = clone(d)
		stamp := text(d["seconds"])
		if parts := strings.Split(text(d["timestamp"]), "."); len(parts) > 1 {
			stamp += "." + parts[len(parts)-1]
		}
		d["ts"] = stamp
		for to, from := range map[string]string{"id.orig_h": "src_addr", "id.orig_p": "src_port", "id.resp_h": "dst_addr", "id.resp_p": "dst_port"} {
			d[to] = d[from]
		}
		kind = "notice"
	}
	ts := timestamp(d["ts"])
	if ts <= 0 || kind == "" {
		return nil, errors.New("原生日志没有有效时间或类型")
	}
	typeName := map[string]string{"conn": "flow", "ssl": "tls", "file": "fileinfo", "weird": "anomaly", "notice": "alert"}[kind]
	if typeName == "" {
		typeName = kind
	}
	native := Object{}
	for key, value := range d {
		if field, ok := schema.NativeFields[key]; ok {
			if key == "uid" || key == "fuid" {
				value = text(value)
			}
			native[field] = value
		}
	}
	id := text(d["session_id"])
	if !sessionValid(id) {
		id = ""
	}
	uid := text(d["uid"])
	if !nativeUID.MatchString(uid) {
		uid = ""
	}
	native["session_id"] = id
	native["native_uid"] = uid
	app := text(d["service"])
	if app == "" && kind != "notice" && kind != "weird" && kind != "conn" {
		app = kind
	}
	o := Object{"event_type": typeName, "timestamp": utc(ts), "src_ip": get(d, "id.orig_h", ""), "dest_ip": get(d, "id.resp_h", ""), "src_port": d["id.orig_p"], "dest_port": d["id.resp_p"], "proto": strings.ToUpper(text(d["proto"])), "app_proto": app, "session_id": id, "snort_native": native}
	switch kind {
	case "notice":
		metadata := object(envelope["rule_metadata"])
		action := strings.ToLower(text(d["action"]))
		blocked := action == "drop" || action == "block" || action == "reject" || action == "reset" || action == "blacklist"
		suppressed := suppressedAlert(d["alert_suppressed"])
		if suppressed && !blocked {
			return nil, nil
		}
		a := "allowed"
		if blocked {
			a = "blocked"
			o["event_type"] = "drop"
			o["drop"] = Object{"reason": action, "alert_suppressed": suppressed}
		}
		o["alert"] = Object{"gid": integer(d["gid"]), "signature_id": integer(d["sid"]), "rev": d["rev"], "signature": get(d, "msg", ""), "severity": get(d, "priority", get(metadata, "severity", 0)), "category": get(d, "class", get(metadata, "category", "")), "action": a, "metadata": object(metadata["metadata"])}
	case "weird":
		o["anomaly"] = Object{"type": get(d, "source", ""), "event": get(d, "msg", "")}
		for _, k := range []string{"gid", "sid"} {
			if strictInt(d[k], 1, 4294967295) {
				native["anomaly_"+k] = d[k]
			}
		}
	case "conn":
		o["flow"] = Object{"age": number(d["duration"]), "state": get(d, "conn_state", ""), "pkts_toserver": d["orig_pkts"], "pkts_toclient": d["resp_pkts"], "bytes_toserver": d["orig_bytes"], "bytes_toclient": d["resp_bytes"]}
	case "http":
		o["http"] = Object{"http_method": d["method"], "hostname": d["host"], "url": d["uri"], "http_user_agent": d["user_agent"], "http_refer": d["referrer"], "protocol": "HTTP/" + text(d["version"]), "status": d["status_code"], "length": d["response_body_len"], "http_content_type": d["resp_mime_types"]}
		o["tx_id"] = d["trans_depth"]
	case "dns":
		answers := []any{}
		for _, v := range array(d["answers"]) {
			answers = append(answers, Object{"rdata": text(v)})
		}
		o["dns"] = Object{"type": "response", "rrname": d["query"], "rrtype": present(d["qtype_name"], d["qtype"]), "rcode": present(d["rcode_name"], d["rcode"]), "answers": answers}
		o["tx_id"] = d["trans_id"]
		ttls := array(d["TTLs"])
		if s, ok := d["TTLs"].(string); ok {
			ttls = []any{}
			for _, v := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
				ttls = append(ttls, json.Number(v))
			}
		}
		ttl := int64(math.MaxInt64)
		for _, v := range ttls[:min(128, len(ttls))] {
			if n, err := strconv.ParseInt(text(v), 10, 64); err == nil && n >= 0 && n <= 2147483647 {
				ttl = min(ttl, n)
			}
		}
		if ttl != math.MaxInt64 {
			native["dns_ttl"] = ttl
		}
	case "ssl":
		o["tls"] = Object{"sni": d["server_name"], "version": d["version"], "subject": d["subject"], "issuerdn": d["issuer"]}
	case "file":
		o["fileinfo"] = Object{"filename": d["filename"], "magic": d["mime_type"], "size": d["total_bytes"], "sha256": d["sha256"]}
	default:
		o[kind] = d
	}
	return o, nil
}
func array(v any) []any {
	if a, ok := v.([]Object); ok {
		out := make([]any, len(a))
		for i, x := range a {
			out[i] = x
		}
		return out
	}
	if a, ok := v.([]string); ok {
		out := make([]any, len(a))
		for i, x := range a {
			out[i] = x
		}
		return out
	}
	if a, ok := v.([]any); ok {
		return a
	}
	if v == nil {
		return nil
	}
	return []any{v}
}
func joined(v any, separator string) string {
	parts := []string{}
	for _, x := range array(v) {
		parts = append(parts, text(x))
	}
	return strings.Join(parts, separator)
}
func trim(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}
func flowSummary(app, proto, state, reason, old string) string {
	app, proto, state, reason = strings.TrimSpace(app), strings.TrimSpace(proto), strings.TrimSpace(state), strings.TrimSpace(reason)
	failed := strings.EqualFold(app, "failed")
	application := app
	if failed {
		application = proto
	}
	label := strings.TrimSpace("连接 " + text(present(application, proto)))
	details := ""
	legacy := regexp.MustCompile(`(?i)^连接\s+(new|established|closed|bypassed)(?:\s*\x{00b7}\s*(.*))?$`).FindStringSubmatch(old)
	if legacy == nil {
		legacy = regexp.MustCompile(`(?i)^连接\s+.*?\s*\x{00b7}\s*(new|established|closed|bypassed)(?:\s*\x{00b7}\s*(.*))?$`).FindStringSubmatch(old)
	}
	if legacy != nil {
		if state == "" {
			state = legacy[1]
		}
		details = strings.TrimSpace(regexp.MustCompile(`\s*\x{00b7}\s*`).ReplaceAllString(legacy[2], " "))
	} else if bracket := regexp.MustCompile(`^连接.*?\s+\[\s*([^\]]+?)\s*\](?:\s+(.*))?$`).FindStringSubmatch(old); bracket != nil {
		if state == "" {
			state = bracket[1]
		}
		details = bracket[2]
		if failed {
			details = strings.TrimSpace(strings.TrimPrefix(details, "应用协议识别失败"))
		}
	}
	if state != "" {
		label += " [ " + state + " ]"
	}
	if failed {
		label += " 应用协议识别失败"
	}
	if reason != "" && state == "" {
		label += " 结束原因：" + reason
	}
	if details != "" {
		label += " " + details
	}
	return strings.TrimSpace(label)
}

type Prepared struct {
	Record Object
	Raw    []byte
	Values []any
}

func ParseEvent(line []byte) (*Prepared, error) {
	var envelope Object
	if err := decode(line, &envelope); err != nil {
		return nil, nil
	}
	o, err := nativeEvent(envelope)
	if err != nil || o == nil {
		return nil, nil
	}
	kind := text(o["event_type"])
	ts := timestamp(o["timestamp"])
	if !eventKinds[kind] || ts <= 0 || math.IsNaN(ts) || math.IsInf(ts, 0) {
		return nil, nil
	}
	r := Object{"ts": ts, "type": kind, "sev": int64(0), "level": "", "sig": "", "action": "", "reason": "", "cat": "", "anom": ""}
	for _, pair := range [][2]string{{"src", "src_ip"}, {"dst", "dest_ip"}, {"sport", "src_port"}, {"dport", "dest_port"}, {"proto", "proto"}, {"app", "app_proto"}, {"dir", "direction"}, {"iif", "in_iface"}, {"flow_id", "flow_id"}, {"community", "community_id"}, {"vlan", "vlan"}, {"pkt_src", "pkt_src"}, {"icmp_type", "icmp_type"}, {"icmp_code", "icmp_code"}} {
		r[pair[0]] = get(o, pair[1], "")
	}
	r["ip_version"] = 4
	if strings.Contains(text(r["src"])+text(r["dst"]), ":") {
		r["ip_version"] = 6
	}
	if a, ok := r["vlan"].([]any); ok {
		r["vlan"] = ""
		if len(a) > 0 {
			r["vlan"] = a[0]
		}
	}
	a, drop, http, tls, dns, file, anomaly := object(o["alert"]), object(o["drop"]), object(o["http"]), object(o["tls"]), object(o["dns"]), object(o["fileinfo"]), object(o["anomaly"])
	query := dns
	if queries := array(dns["queries"]); len(queries) > 0 {
		query = object(queries[0])
	}
	for key, value := range (Object{"sni": tls["sni"], "ja3": object(tls["ja3"])["hash"], "ja3s": object(tls["ja3s"])["hash"], "ja4": tls["ja4"], "host": http["hostname"], "url": http["url"], "ua": http["http_user_agent"], "dns": query["rrname"], "file": file["filename"], "magic": file["magic"], "md5": file["md5"], "sha1": file["sha1"], "sha256": file["sha256"], "state": file["state"], "size": file["size"], "rrtype": query["rrtype"], "rcode": dns["rcode"], "method": http["http_method"], "httpver": http["protocol"], "status": http["status"], "clen": http["length"], "ct": http["http_content_type"], "referrer": present(http["http_refer"], http["http_referrer"]), "subject": tls["subject"], "issuer": tls["issuerdn"], "tlsver": tls["version"], "gid": a["gid"], "rev": a["rev"], "sig_id": a["signature_id"], "tx": present(o["tx_id"], file["tx_id"])}) {
		if value == nil {
			value = ""
		}
		r[key] = value
	}
	answers := []string{}
	r["sig_id"] = a["signature_id"]
	r["sport"] = o["src_port"]
	r["dport"] = o["dest_port"]
	r["tx"] = get(o, "tx_id", get(file, "tx_id", ""))
	r["sni"] = present(tls["sni"], object(o[kind])["sni"])
	if kind == "quic" {
		r["httpver"] = ""
	} else if r["httpver"] == "" && (kind == "http2" || (kind == "http" && (r["app"] == "http2" || text(http["version"]) == "2"))) {
		r["httpver"] = "HTTP/2"
	}
	for _, v := range array(dns["answers"]) {
		m := object(v)
		answers = append(answers, text(present(m["rrname"], m["rdata"])))
	}
	r["answers"] = trim(strings.Join(answers, ","), 4096)
	r["alpn"] = trim(joined(append(array(tls["client_alpns"]), array(tls["server_alpns"])...), ","), 200)
	switch kind {
	case "alert", "drop":
		fallback := "engine drop"
		if text(drop["reason"]) != "" {
			fallback += ": " + text(drop["reason"])
		}
		r["sig"] = present(a["signature"], fallback)
		r["sev"] = integer(a["severity"])
		r["cat"] = get(a, "category", "")
		r["action"] = present(a["action"], "allowed")
		r["reason"] = get(drop, "reason", "")
		if kind == "drop" {
			r["action"] = present(a["action"], "blocked")
		}
	case "dns":
		if dns["type"] == "response" {
			answer := ""
			if values := array(dns["answers"]); len(values) > 0 {
				answer = text(object(values[0])["rrname"])
			}
			r["sig"] = "DNS answer " + text(present(query["rrname"], "?")) + " " + text(present(answer, dns["rcode"]))
		} else {
			r["sig"] = "DNS " + text(present(query["rrname"], "?")) + " " + text(get(query, "rrtype", ""))
		}
	case "http":
		r["sig"] = "HTTP " + text(r["method"]) + " " + text(r["host"]) + text(r["url"])
		if http["status"] != nil {
			r["sig"] = text(r["sig"]) + " -> " + text(r["status"])
		}
	case "tls":
		r["sig"] = "TLS " + text(present(tls["sni"], tls["subject"], "?")) + " " + text(get(tls, "version", ""))
	case "session":
		labels := map[string]string{"start": "发起连接", "first_observed": "首次观察", "state": "连接状态变化", "application": "应用识别更新", "update": "流量更新", "end": "跟踪结束"}
		n := object(o["snort_native"])
		r["sig"] = labels[text(n["session_event"])]
		if app := text(present(n["appid_payload"], n["appid_service"])); app != "" {
			r["sig"] = text(r["sig"]) + " " + app
		}
	case "anomaly":
		r["anom"] = text(get(anomaly, "type", "")) + "/" + text(get(anomaly, "event", ""))
		r["sig"] = "anomaly " + text(r["anom"])
	case "fileinfo":
		r["sig"] = "file " + text(present(file["filename"], "?")) + " " + text(get(file, "magic", ""))
	default:
		r["sig"] = strings.ToUpper(kind) + " " + appSummary(object(o[kind]))
	}
	if r["app"] == "" && (kind == "dns" || kind == "http" || kind == "tls" || !strings.Contains("|alert|drop|anomaly|fileinfo|flow|session|", "|"+kind+"|")) {
		r["app"] = kind
	}
	if kind == "flow" || kind == "session" || kind == "quic" {
		flow := object(o["flow"])
		for _, key := range strings.Fields("bytes_toserver bytes_toclient pkts_toserver pkts_toclient") {
			r[key] = nil
			if v := flow[key]; v != nil {
				r[key] = max(int64(0), integer(v))
			}
		}
		r["state"] = get(flow, "state", "")
		r["reason"] = get(flow, "reason", "")
		r["flow_age"] = nil
		if flow["age"] != nil {
			r["flow_age"] = max(int64(0), integer(flow["age"]))
		}
		for _, k := range []string{"start", "end"} {
			r["flow_"+k] = nil
			if t := timestamp(flow[k]); t > 0 {
				r["flow_"+k] = t
			}
		}
		if kind == "flow" {
			r["sig"] = flowSummary(text(r["app"]), text(r["proto"]), text(r["state"]), text(r["reason"]), "")
		}
	}
	for k, v := range object(o["snort_native"]) {
		r[k] = v
	}
	for k, v := range object(o["observer_fields"]) {
		r[k] = v
	}
	if suppressedAlert(o["alert_suppressed"]) || suppressedAlert(a["alert_suppressed"]) || suppressedAlert(drop["alert_suppressed"]) || suppressedAlert(r["alert_suppressed"]) {
		r["alert_suppressed"] = 1
	} else {
		delete(r, "alert_suppressed")
	}
	if o["snort_native"] != nil {
		r["_native_snort"] = true
	}
	attackMetadata(r, object(a["metadata"]))
	r["sig"] = trim(strings.TrimSpace(text(r["sig"])), 300)
	setLevel(r)
	prepared := &Prepared{Record: r, Raw: append([]byte(nil), line...)}
	prepared.Values, err = eventValues(r, line)
	return prepared, err
}
func appSummary(data Object) string {
	parts := []string{}
	for _, key := range strings.Fields("sni hostname rrname filename url query cname server_name client_id community method assigned_ip version software_version proto_version username command") {
		switch v := data[key].(type) {
		case string:
			if v != "" {
				parts = append(parts, v)
			}
		case json.Number, float64, int, int64:
			parts = append(parts, text(v))
		}
		if len(parts) >= 2 {
			return strings.Join(parts, " ")
		}
	}
	for _, side := range []string{"client", "server"} {
		sub := object(data[side])
		for _, key := range []string{"software_version", "proto_version"} {
			if v := sub[key]; v != nil && text(v) != "" {
				parts = append(parts, side+"="+text(v))
				break
			}
		}
	}
	return strings.Join(parts, " ")
}
func setLevel(r Object) {
	sev := integer(r["sev"])
	switch {
	case sev == 1:
		r["level"] = "high"
	case sev == 2:
		r["level"] = "medium"
	case sev >= 3:
		r["level"] = "low"
	case (r["type"] == "alert" || r["type"] == "drop") && integer(r["sig_id"]) > 0:
		r["level"] = "unknown"
	default:
		r["level"] = ""
	}
}
func attackMetadata(r Object, m Object) {
	for _, key := range strings.Fields("mitre_tactic_id mitre_tactic_name mitre_technique_id mitre_technique_name") {
		values := []string{}
		seen := map[string]bool{}
		for _, raw := range array(m[key]) {
			s, ok := raw.(string)
			if !ok {
				continue
			}
			parts := []string{s}
			if strings.HasSuffix(key, "_id") {
				parts = regexp.MustCompile(`[\s,;|]+`).Split(s, -1)
			}
			for _, value := range parts {
				value = strings.TrimSpace(value)
				if strings.HasSuffix(key, "_id") {
					value = strings.ToUpper(value)
					pattern := `^T[0-9]{4}(?:\.[0-9]{3})?$`
					if key == "mitre_tactic_id" {
						pattern = `^TA[0-9]{4}$`
					}
					if !regexp.MustCompile(pattern).MatchString(value) {
						continue
					}
				}
				if value != "" && !seen[value] {
					seen[value] = true
					values = append(values, value)
				}
			}
		}
		if len(values) > 0 {
			r[key] = values
		}
	}
}
func pythonFloat(n float64) string {
	a := math.Abs(n)
	if a == 0 || (a >= 1e-4 && a < 1e16) {
		s := strconv.FormatFloat(n, 'f', -1, 64)
		if !strings.Contains(s, ".") {
			s += ".0"
		}
		return s
	}
	return strconv.FormatFloat(n, 'e', -1, 64)
}

var eventCompressors = sync.Pool{New: func() any { writer, _ := zlib.NewWriterLevel(io.Discard, 6); return writer }}

func eventValues(r Object, raw []byte) ([]any, error) {
	values := make([]any, 0, len(schema.Columns))
	var compressed []byte
	keep := boolean(r["_native_snort"]) || r["observer"] != nil || r["type"] == "alert" || (r["type"] == "drop" && integer(r["sig_id"]) > 0)
	if keep {
		var b bytes.Buffer
		writer := eventCompressors.Get().(*zlib.Writer)
		writer.Reset(&b)
		defer func() { writer.Reset(io.Discard); eventCompressors.Put(writer) }()
		if _, err := writer.Write(raw); err != nil {
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
		compressed = b.Bytes()
	}
	hash := sha256.Sum256(append([]byte(pythonFloat(number(r["ts"]))+"\n"), raw...))
	key := hex.EncodeToString(hash[:])
	r["_event_key"] = key
	for _, c := range schema.Columns {
		column := *c[0]
		var value any
		if c[1] != nil {
			value = r[*c[1]]
		}
		switch column {
		case "ts":
			value = number(r["ts"]) * 1000
		case "event_key":
			value = key
		case "raw":
			value = compressed
			if value == nil {
				value = []byte{}
			}
		case "tier":
			value = 2
			if r["type"] == "alert" || r["type"] == "anomaly" || r["type"] == "fileinfo" || (r["type"] == "drop" && integer(r["sig_id"]) > 0) {
				value = 1
			}
		case "dnsname":
			value = r["dns"]
		case "fname":
			value = r["file"]
		case "fsize":
			value = r["size"]
		}
		if value == nil || value == "" {
			if numericColumns[column] {
				value = nil
			} else if column != "raw" {
				value = ""
			}
		}
		if n, ok := value.(json.Number); ok {
			if i, err := n.Int64(); err == nil {
				value = i
			} else if f, err := n.Float64(); err == nil {
				if numericColumns[column] && column != "ts" && math.Trunc(f) == f {
					return nil, errors.New("整数超出 SQLite 范围")
				}
				value = f
			} else {
				return nil, err
			}
		}
		switch value.(type) {
		case Object, map[string]any, []any:
			data, err := json.Marshal(value)
			if err != nil {
				return nil, err
			}
			value = string(data)
		}
		values = append(values, value)
	}
	return values, nil
}
func decompress(data []byte) ([]byte, error) {
	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(io.LimitReader(reader, 4<<20))
}
