package console

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const rpcRequestLimit = 256 << 10
const rpcResponseLimit = 16 << 20

func (a *App) Manager(ctx context.Context, operation string, params Object) (any, error) {
	if a.Config.ManagerSocket == "" {
		return nil, errors.New("独立规则管理器未配置")
	}
	return managerRequest(ctx, a.Config.ManagerSocket, operation, params)
}
func managerRequest(ctx context.Context, path, operation string, params Object) (any, error) {
	request := clone(params)
	request["operation"] = operation
	data, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	if len(data)+1 > rpcRequestLimit {
		return nil, errors.New("规则管理请求过大")
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, errors.New("规则管理器暂不可用")
	}
	defer conn.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()
	conn.SetDeadline(time.Now().Add(70 * time.Second))
	if _, err = conn.Write(append(data, '\n')); err != nil {
		return nil, errors.New("规则管理连接中断")
	}
	reader := bufio.NewReader(io.LimitReader(conn, rpcResponseLimit+1))
	line, err := reader.ReadBytes('\n')
	if err != nil || len(line) > rpcResponseLimit {
		return nil, errors.New("规则管理响应无效")
	}
	var reply Object
	if err = decode(line, &reply); err != nil {
		return nil, errors.New("规则管理响应无效")
	}
	if reply["ok"] != true {
		return nil, errors.New(text(get(reply, "error", "规则操作失败")))
	}
	return reply["result"], nil
}
func (a *App) StatusSnapshot() Object {
	path := filepath.Join(filepath.Dir(a.Config.ManagerSocket), "status.json")
	file, err := os.Open(path)
	if err != nil {
		return Object{"telemetry": Object{"stale": true, "error": "运行状态快照暂不可用"}}
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, rpcResponseLimit+1))
	if err != nil || len(data) > rpcResponseLimit {
		return Object{"telemetry": Object{"stale": true, "error": "运行状态快照无效"}}
	}
	var value Object
	if decode(data, &value) != nil || integer(value["schema"]) != 1 {
		return Object{"telemetry": Object{"stale": true, "error": "运行状态快照无效"}}
	}
	metadata := object(value["telemetry"])
	metadata["stale"] = now()-number(value["published"]) > 5 || now()-number(metadata["as_of"]) > 10 || metadata["updating"] == true
	value["telemetry"] = metadata
	return value
}
func (a *App) Runtime(ctx context.Context) Object {
	snapshot := a.StatusSnapshot()
	engine := object(snapshot["engine"])
	counters := object(engine["dump-counters"])
	ips := object(counters["ips"])
	drops := object(ips["drop_reason"])
	ruleStats := object(engine["ruleset-stats"])
	engineDrops := int64(0)
	for name, v := range drops {
		if name != "rules" {
			engineDrops += integer(v)
		}
	}
	return Object{"telemetry": snapshot["telemetry"], "service": get(snapshot, "service", Object{"state": "unknown"}), "rates": get(snapshot, "rates", Object{}), "queue": get(snapshot, "queue_listeners", Object{"packets": nil, "queue_total": nil, "kernel_drops": nil, "user_drops": nil, "listeners_known": false}), "ips": Object{"accepted": ips["accepted"], "blocked": ips["blocked"], "rejected": ips["rejected"], "rule_drops": drops["rules"], "engine_drops": engineDrops, "drop_reasons": drops}, "rules": Object{"loaded": ruleStats["rules_loaded"], "failed": ruleStats["rules_failed"], "skipped": ruleStats["rules_skipped"], "reload": get(snapshot, "reload_state", Object{})}}
}
func (a *App) System(ctx context.Context) (Object, error) {
	snapshot := a.StatusSnapshot()
	value, err := a.Manager(ctx, "read", Object{"name": "system_payload", "args": []any{}, "kwargs": Object{}})
	if err != nil {
		return nil, err
	}
	result := object(value)
	result["uptime_web"] = int64(time.Since(a.Started).Seconds())
	result["telemetry"] = snapshot["telemetry"]
	components := array(result["components"])
	state, message := "ok", "事件库和入库正常"
	if e := a.Store.Error(); e != "" {
		state, message = "error", e
	}
	components = append(components, Object{"id": "event-db", "name": "事件库", "state": state, "message": message, "at": now()})
	state, message = a.Network.Health()
	if e := a.Recent.Error(); e != "" {
		state, message = "warning", e
	}
	components = append(components, Object{"id": "network", "name": "概览网络统计", "state": state, "message": message, "at": now()})
	result["components"] = components
	return result, nil
}
func rpcReadName(path string) string {
	return map[string]string{"/api/rules/governance": "governance_state", "/api/rules/page": "app.rules_page", "/api/rules/groups": "rule_groups_search", "/api/rules/group": "rule_group_detail", "/api/rules/selection": "app.rule_selection", "/api/rules/search": "app.rules_search", "/api/rules/sources": "app.sources_catalog", "/api/rules": "app.rules_payload", "/api/hunt/rules": "hunt_rules_list", "/api/actions/status": "sys.update_status", "/api/actions/log": "sys.rule_log"}[path]
}
func validMutation(method, path string) bool {
	if method == "POST" {
		for _, allowed := range strings.Fields("/api/actions/reload /api/actions/update /api/actions/apply /api/rules/schedule /api/hunt/rules /api/hunt/rules/add-apply /api/rules/suppress-groups /api/rules/suppress-groups/remove /api/rules/suppress /api/rules/action /api/rules/source /api/rules/source/config /api/rules/action-apply /api/rules/reject /api/rules/drop /api/rules/disable /api/rules/batch-delete /api/rules/pending/discard /api/bans/batch-delete /api/bans") {
			if path == allowed {
				return true
			}
		}
	}
	if method == "DELETE" {
		for _, prefix := range strings.Fields("/api/hunt/rules/ /api/rules/suppress/ /api/rules/action/ /api/rules/reject/ /api/rules/drop/ /api/rules/disable/ /api/rules/suppress-group/ /api/bans/") {
			if strings.HasPrefix(path, prefix) && safeName(strings.TrimPrefix(path, prefix)) {
				return true
			}
		}
	}
	return false
}
