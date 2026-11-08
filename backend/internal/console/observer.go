package console

import (
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"regexp"
	"strings"
)

var cidPattern = regexp.MustCompile(`^(?:[0-9a-f]{2}){1,20}$`)

func observerEvent(envelope Object) (Object, error) {
	d := object(envelope["data"])
	id := text(d["session_id"])
	first, last := number(d["first"]), number(d["last"])
	if !sessionPattern.MatchString(id) || first <= 0 || last < first || math.IsNaN(first+last) || math.IsInf(first+last, 0) {
		return nil, errors.New("无效 QUIC 观察身份或时间")
	}
	origin, peer := array(d["origin"]), array(d["peer"])
	for _, endpoint := range [][]any{origin, peer} {
		if len(endpoint) != 2 {
			return nil, errors.New("无效 QUIC 端点")
		}
		if _, err := netip.ParseAddr(text(endpoint[0])); err != nil {
			return nil, err
		}
		if !strictInt(endpoint[1], 0, 65535) {
			return nil, errors.New("无效 QUIC 端口")
		}
	}
	offered := []any{}
	for i, v := range array(d["alpn"]) {
		if i == 8 {
			break
		}
		offered = append(offered, trim(text(v), 64))
	}
	cids := []string{}
	for i, v := range array(d["cids"]) {
		if i == 16 {
			break
		}
		if cidPattern.MatchString(text(v)) {
			cids = append(cids, text(v))
		}
	}
	paths := array(d["paths"])
	paths = paths[:min(8, len(paths))]
	encoded, _ := json.Marshal(paths)
	native := Object{"session_id": id, "observer": "Wireshark QUIC", "quic_cids": strings.Join(cids, ","), "quic_paths": string(encoded), "coverage": "passive_visible"}
	versions := array(d["version"])
	versions = versions[:min(2, len(versions))]
	quic := Object{"sni": trim(text(d["sni"]), 253), "version": joined(versions, ","), "alpn_offered": offered, "visible_paths": paths, "connection_ids": cids, "observation_end": get(d, "reason", "update"), "partial": true, "limits_reached": boolean(d["limited"]), "packets_a_to_b": d["a_packets"], "packets_b_to_a": d["b_packets"], "direction_unknown": get(d, "unknown_packets", 0)}
	o := Object{"timestamp": utc(last), "event_type": "quic", "src_ip": origin[0], "src_port": origin[1], "dest_ip": peer[0], "dest_port": peer[1], "proto": "UDP", "app_proto": "quic", "quic": quic, "tls": Object{"sni": quic["sni"], "client_alpns": offered}, "observer_fields": native}
	if client := array(d["client"]); len(client) == 2 && integer(d["unknown_packets"]) == 0 {
		a, b := "a", "b"
		if text(client[0]) != text(origin[0]) || integer(client[1]) != integer(origin[1]) {
			a, b = b, a
		}
		o["flow"] = Object{"start": utc(first), "end": utc(last), "age": last - first, "state": "observed", "bytes_toserver": d[a+"_bytes"], "bytes_toclient": d[b+"_bytes"], "pkts_toserver": d[a+"_packets"], "pkts_toclient": d[b+"_packets"]}
	}
	return o, nil
}
