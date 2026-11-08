package console

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func localAssistantProvider(t *testing.T, handler http.HandlerFunc) *Assistant {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	a := NewAssistant(&App{})
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	a.client = &http.Client{Transport: transport}
	t.Cleanup(transport.CloseIdleConnections)
	return a
}
func TestAssistantSeparatesReasoningPublicNoteAndBody(t *testing.T) {
	a := localAssistantProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		chunks := []Object{{"reasoning_content": "核对证据。"}, {"content": "<Thi"}, {"content": "nking>hidden reasoning</THINK"}, {"content": "ING>分析"}, {"content": "说明：只描述可见事实\n正文"}, {"content": " 完成。"}}
		for _, delta := range chunks {
			data, _ := json.Marshal(Object{"choices": []Object{{"delta": delta}}})
			fmt.Fprintf(w, "data: %s\n\n", data)
		}
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
	})
	items := []Object{}
	body, finish, err := a.infer(t.Context(), []Object{{"role": "user", "content": "fixture"}}, Object{}, 384, true, false, func(v Object) bool { items = append(items, v); return true })
	if err != nil || finish != "stop" || body != "正文 完成。" {
		t.Fatal(body, finish, err)
	}
	notes, reason, deltas := "", "", ""
	started := false
	for _, item := range items {
		notes += text(item["analysis_delta"])
		reason += text(item["reasoning_delta"])
		if item["analysis_done"] == true {
			started = true
		}
		if item["delta"] != nil {
			if !started {
				t.Fatal("body arrived before analysis completion")
			}
			deltas += text(item["delta"])
		}
	}
	if notes != "只描述可见事实" || reason != "核对证据。" || deltas != body || strings.Contains(reason, "hidden") {
		t.Fatal("reasoning or public note leaked into output", items)
	}
}
func TestAssistantCancellationJoinsProviderWorker(t *testing.T) {
	started, closed := make(chan struct{}), make(chan struct{})
	a := localAssistantProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		close(closed)
	})
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, _, err := a.infer(ctx, []Object{}, Object{}, 384, true, false, func(Object) bool { return true })
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("provider did not start")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled inference succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled provider worker did not exit")
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("provider connection remained active")
	}
}
func TestRuleSuggestionsRequireRealPacketEvidence(t *testing.T) {
	base := Object{"src": "192.0.2.1", "dst": "198.51.100.2", "dport": 443, "proto": "TCP", "tcp_flags": "", "ip_ttl": ""}
	if rows := ruleCandidates([]Object{base}); len(rows) != 0 {
		t.Fatal("missing packet fields became a NULL-flags detector")
	}
	base["tcp_flags"] = int64(0)
	base["ip_ttl"] = int64(64)
	rows := ruleCandidates([]Object{base})
	if len(rows) != 1 {
		t.Fatal("observed anomalous flags not available")
	}
	result, err := ruleFromChoice(Object{"candidate": 0, "extra": []any{"ttl"}, "message": "Fixture"}, rows, "alert")
	if err != nil {
		t.Fatal(err)
	}
	if err = validateSuggestion(text(result["rule"])); err != nil {
		t.Fatal(err)
	}
	if _, err = ruleFromChoice(Object{"candidate": 0, "extra": []any{"window"}}, rows, "alert"); err == nil {
		t.Fatal("invented packet feature accepted")
	}
	if _, err = ruleFromChoice(Object{"candidate": 1}, rows, "alert"); err == nil {
		t.Fatal("out-of-evidence candidate accepted")
	}
}
func TestAllGeneratedRuleFamiliesPassRestrictedValidation(t *testing.T) {
	for _, features := range []Object{{"host": "example.test", "url": "/fixture", "method": "GET"}, {"sni": "example.test"}, {"dns": "example.test", "proto": "UDP", "dport": 53}, {"appid_payload": "FixtureApp"}} {
		r := Object{"src": "192.0.2.1", "dst": "198.51.100.2", "dport": 443, "proto": "TCP"}
		for k, v := range features {
			r[k] = v
		}
		choices := ruleCandidates([]Object{r})
		if len(choices) != 1 {
			t.Fatal("missing candidate", features)
		}
		result, err := ruleFromChoice(Object{"candidate": 0, "message": "Fixture"}, choices, "block")
		if err != nil {
			t.Fatal(err)
		}
		if err = validateSuggestion(text(result["rule"])); err != nil {
			t.Fatal(result, err)
		}
	}
}
func TestAssistantRejectsMalformedProviderContent(t *testing.T) {
	a := localAssistantProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":{\"unexpected\":true}},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
	})
	if _, _, err := a.infer(t.Context(), nil, Object{}, 384, true, false, func(Object) bool { return true }); err == nil {
		t.Fatal("non-text provider output accepted")
	}
}
func TestAssistantGenerateKeepsFrontendResultContract(t *testing.T) {
	store, ctx := testStore(t)
	record, err := ParseEvent(syntheticEvent("alert"))
	if err != nil {
		t.Fatal(err)
	}
	if err = store.insert(ctx, []*Prepared{record}, Cursor{}); err != nil {
		t.Fatal(err)
	}
	var key string
	if err = store.Readers.QueryRow("SELECT id||':'||event_key FROM events LIMIT 1").Scan(&key); err != nil {
		t.Fatal(err)
	}
	stage := 0
	a := localAssistantProvider(t, func(w http.ResponseWriter, r *http.Request) {
		var body Object
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("bad model request")
		}
		messages := array(body["messages"])
		if len(messages) != 2 {
			t.Error("missing model messages")
		}
		if len(text(object(messages[0])["content"]))+len(text(object(messages[1])["content"])) > 1500 {
			t.Error("model context budget exceeded")
		}
		stage++
		content := `{"checks":[]}`
		if stage == 2 {
			content = "分析说明：依据保留日志\n### 观察\nFixture summary"
		}
		w.Header().Set("Content-Type", "text/event-stream")
		data, _ := json.Marshal(Object{"choices": []Object{{"delta": Object{"content": content}, "finish_reason": "stop"}}})
		fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", data)
	})
	a.app = &App{Store: store, Config: Config{Raw: Object{}}}
	var result Object
	if err = a.Generate(ctx, "fixture-owner", Object{"kind": "summary", "target": Object{"kind": "record", "key": key}}, func(item Object) bool {
		if item["result"] != nil {
			result = object(item["result"])
		}
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if stage != 2 || result["text"] != "### 观察\nFixture summary" || result["hunt_status"] != "not_needed" || object(result["context"])["scope"] != "event" {
		t.Fatal("frontend summary result contract changed", result)
	}
}
func TestSessionEvidenceRetainsDetectionAndOutcome(t *testing.T) {
	store, ctx := testStore(t)
	id := strings.Repeat("e", 32) + ":0000000000000001"
	records := []*Prepared{}
	kinds := []string{"alert", "flow", "session"}
	for range 20 {
		kinds = append(kinds, "dns")
	}
	for i, kind := range kinds {
		var event Object
		decode(syntheticEvent(kind), &event)
		event["timestamp"] = utc(1794009600 + float64(i))
		event["snort_native"] = Object{"session_id": id}
		raw, _ := json.Marshal(event)
		r, err := ParseEvent(raw)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, r)
	}
	if err := store.insert(ctx, records, Cursor{}); err != nil {
		t.Fatal(err)
	}
	var key string
	store.Readers.QueryRow("SELECT id||':'||event_key FROM events ORDER BY id DESC LIMIT 1").Scan(&key)
	app := &App{Store: store}
	data, err := app.SummaryContext(ctx, Object{"kind": "record", "key": key})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, v := range array(data["records"]) {
		found[text(object(v)["type"])] = true
	}
	if !found["alert"] || !found["flow"] || integer(data["total_records"]) != 23 {
		t.Fatal("important session evidence dropped", data)
	}
	if _, _, err = summaryMessages(data, nil); err != nil {
		t.Fatal("real session could not fit model budget", err)
	}
}
