package console

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestOverviewSuppressionKeepsEnforcementAndFiltersEveryDetectionView(t *testing.T) {
	store, ctx := testStore(t)
	stamp := float64(int64(now()) - 30)
	session := func(sid int) string { return strings.Repeat("b", 32) + fmt.Sprintf(":%016x", sid) }
	native := func(sid, severity int, action string, suppressed any) Object {
		return Object{"engine": "snort3", "kind": "notice", "data": Object{"ts": stamp, "session_id": session(sid), "gid": 1, "sid": sid, "rev": 1, "msg": fmt.Sprintf("Fixture %d", sid), "priority": severity, "proto": "TCP", "id.orig_h": "192.0.2.1", "id.orig_p": 51000, "id.resp_h": "198.51.100.1", "id.resp_p": 443, "action": action, "alert_suppressed": suppressed}}
	}
	legacy := func(kind string, sid, severity int, action string, suppressed any) Object {
		return Object{"event_type": kind, "timestamp": utc(stamp), "src_ip": "192.0.2.1", "src_port": 51000, "dest_ip": "198.51.100.1", "dest_port": 443, "proto": "TCP", "alert": Object{"gid": 1, "signature_id": sid, "rev": 1, "signature": fmt.Sprintf("Fixture %d", sid), "severity": severity, "action": action}, "snort_native": Object{"session_id": session(sid), "alert_suppressed": suppressed}}
	}
	rows := []Object{
		native(91001, 1, "block", 1),
		native(91002, 1, "reject", true),
		native(91003, 1, "block", 0),
		legacy("alert", 91003, 1, "blocked", nil), // Ordinary alert/drop mirror.
		native(91004, 2, "alert", false),
		legacy("alert", 91005, 1, "blocked", 1), // Already-indexed alert-form suppression.
		legacy("alert", 91006, 1, "allowed", nil),
		{"event_type": "drop", "timestamp": utc(stamp), "drop": Object{"reason": "policy"}},
	}
	var prepared []*Prepared
	for _, row := range rows {
		data, _ := json.Marshal(row)
		p, err := ParseEvent(data)
		if err != nil || p == nil {
			t.Fatal("fixture parse failed", err)
		}
		prepared = append(prepared, p)
	}
	if err := store.insert(ctx, prepared, Cursor{}); err != nil {
		t.Fatal(err)
	}
	// An explicit zero in existing databases also means not suppressed.
	if _, err := store.Writer.Exec("UPDATE events SET alert_suppressed=0 WHERE type='drop' AND sid=91003"); err != nil {
		t.Fatal(err)
	}
	var zeroFlag int
	if err := store.Readers.QueryRowContext(ctx, "SELECT "+detectionSQL+" FROM events WHERE type='drop' AND sid=91003").Scan(&zeroFlag); err != nil || zeroFlag != 1 {
		t.Fatal("explicit zero treated as suppressed", zeroFlag, err)
	}
	app := &App{Store: store, Config: Config{PreloadBytes: 8 << 20, ManagerSocket: t.TempDir() + "/control.sock"}}
	var err error
	app.Recent, err = NewRecentEvents(app)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Recent.Close()
	app.Network = NewNetworkSnapshots(app)
	for !app.Recent.Ready() || app.Recent.Count() != int64(len(rows)) {
		if err = app.Recent.refresh(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for _, backend := range []string{"disk", "memory"} {
		t.Run(backend, func(t *testing.T) {
			var snapshot *Snapshot
			var release func()
			if backend == "disk" {
				snapshot, err = store.Snapshot(ctx, true)
				release = func() { snapshot.Close() }
			} else {
				var ok bool
				snapshot, release, ok = app.Recent.Snapshot(ctx, 0, now()+5, true)
				if !ok {
					t.Fatal("resident snapshot unavailable")
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			summary, err := securitySummary(ctx, snapshot, 0, now()+5, nil, nil, true, "all", 5)
			if err != nil {
				t.Fatal(err)
			}
			if integer(summary["alerts"]) != 3 || integer(summary["high"]) != 2 || integer(summary["drops"]) != 5 {
				t.Fatal("incorrect detection/enforcement counts", summary)
			}
			want := map[int64]bool{91003: true, 91004: true, 91006: true}
			signatures := summary["signatures"].([]Object)
			if len(signatures) != len(want) {
				t.Fatal("quiet or unsigned records entered signature ranks", signatures)
			}
			for _, row := range signatures {
				if !want[integer(row["sid"])] || integer(row["count"]) != 1 {
					t.Fatal("signature rank differs from detection count", row)
				}
			}
			series, err := securitySeries(ctx, snapshot, stamp-60, stamp+60, 1, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			var alerts, drops int64
			for _, bucket := range series {
				alerts += integer(bucket["alerts"])
				drops += integer(bucket["drops"])
			}
			if alerts != 3 || drops != 5 {
				t.Fatal("trend differs from cards", alerts, drops)
			}
			network, err := networkSummary(ctx, snapshot, 0, now()+5, nil, nil)
			if err != nil || integer(network["records"]) != int64(len(rows)) {
				t.Fatal("raw network evidence was removed", err, network)
			}
			grouped, err := incidents(ctx, snapshot, url.Values{}, 0, now()+5, "", 3)
			if err != nil || integer(grouped["total"]) != 3 {
				t.Fatal("suppressed record created an incident", err, grouped)
			}
			parts, args, err := eventFilter(url.Values{"detection": {"alerts"}}, false)
			if err != nil {
				t.Fatal(err)
			}
			total, events, err := search(ctx, snapshot, 0, now()+5, parts, args, 100, 0, false, false, false)
			if err != nil || total != 4 {
				t.Fatal("raw detection export lost mirrors or included suppression", total, err)
			}
			for _, event := range events {
				if suppressedAlert(event["alert_suppressed"]) {
					t.Fatal("suppressed evidence exported as an alert")
				}
			}
		})
	}
	for _, filter := range []string{"", "alerts", "high", "drops"} {
		params := url.Values{"scope": {"cache"}, "view": {"panel"}}
		if filter != "" {
			params.Set("detection", filter)
		}
		result, err := app.execute(ctx, "overview", params)
		if err != nil {
			t.Fatal(filter, err)
		}
		security := object(result["security"])
		if filter == "" || filter == "alerts" {
			if integer(security["alerts"]) != 3 || integer(security["high"]) != 2 {
				t.Fatal("overview card filter changed alert eligibility", filter, security)
			}
		}
		if filter == "high" && integer(security["alerts"]) != 2 {
			t.Fatal("high filter included quiet alerts", security)
		}
		if filter == "drops" && integer(security["drops"]) != 5 {
			t.Fatal("blocking filter hid suppressed enforcement", security)
		}
	}
	// The raw drop list remains available independently of alert suppression.
	drops, err := app.execute(ctx, "events", url.Values{"type": {"drop"}, "all": {"1"}})
	if err != nil || integer(drops["total"]) != 4 {
		t.Fatal("raw block records were hidden", err, drops)
	}
}

func TestSuppressionFlagNormalization(t *testing.T) {
	for _, flag := range []any{true, 1, 1.0, json.Number("1"), "1"} {
		t.Run(fmt.Sprintf("%T-%v", flag, flag), func(t *testing.T) {
			for _, field := range []string{"drop", "alert", "snort_native", "top"} {
				row := Object{"event_type": "drop", "timestamp": utc(now()), "alert": Object{"signature_id": 123, "signature": "fixture"}, "drop": Object{}}
				if field == "top" {
					row["alert_suppressed"] = flag
				} else {
					objectField := object(row[field])
					objectField["alert_suppressed"] = flag
					row[field] = objectField
				}
				data, _ := json.Marshal(row)
				p, err := ParseEvent(data)
				if err != nil || p == nil || p.Record["alert_suppressed"] != 1 {
					t.Fatal("suppression flag lost", field, flag, err)
				}
			}
			row := Object{"engine": "snort3", "kind": "notice", "data": Object{"ts": now(), "gid": 1, "sid": 123, "msg": "fixture", "action": "alert", "alert_suppressed": flag}}
			data, _ := json.Marshal(row)
			p, err := ParseEvent(data)
			if err != nil || p != nil {
				t.Fatal("suppressed native alert entered ingestion", flag, err)
			}
		})
	}
	for _, flag := range []any{nil, false, 0, 0.0, json.Number("0"), "0"} {
		if suppressedAlert(flag) {
			t.Fatal("non-suppressed record marked quiet", flag)
		}
	}
}
