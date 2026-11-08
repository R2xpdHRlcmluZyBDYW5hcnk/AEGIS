package console

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type HTTPHandler struct {
	App        *App
	loginSlots chan struct{}
	streams    chan struct{}
}

func NewHTTPHandler(app *App) *HTTPHandler {
	return &HTTPHandler{App: app, loginSlots: make(chan struct{}, max(1, WorkerCount()/2)), streams: make(chan struct{}, 8*WorkerCount())}
}
func jsonReply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}
func httpError(w http.ResponseWriter, status int, message string) {
	jsonReply(w, status, Object{"error": message})
}
func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	defer func() {
		if recover() != nil {
			httpError(w, 500, "请求处理失败")
			log.Print("request handler panic")
		}
	}()
	if r.URL.Path == "/healthz" && r.Method == "GET" {
		jsonReply(w, 200, h.App.Health())
		return
	}
	if r.URL.Path == "/login" {
		if r.Method == "POST" {
			h.login(w, r)
			return
		}
		if r.Method == "GET" {
			h.loginPage(w, r)
			return
		}
		httpError(w, 405, "method not allowed")
		return
	}
	if r.Method == "GET" && (strings.HasPrefix(r.URL.Path, "/fonts/") || r.URL.Path == "/favicon.svg" || r.URL.Path == "/favicon.ico") {
		if r.URL.Path == "/favicon.ico" {
			w.WriteHeader(204)
			return
		}
		h.static(w, r, strings.TrimPrefix(r.URL.Path, "/"))
		return
	}
	cookie, _ := r.Cookie("ipsweb_session")
	owner := ""
	if cookie != nil {
		owner = cookie.Value
	}
	if !h.App.Sessions.Valid(owner) {
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/metrics" {
			httpError(w, 401, "login required")
		} else {
			http.Redirect(w, r, "/login", http.StatusFound)
		}
		return
	}
	if r.Method == "POST" || r.Method == "DELETE" {
		if r.Header.Get("X-Requested-With") != "ips-web" {
			httpError(w, 400, "missing X-Requested-With header")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			parsed, err := url.Parse(origin)
			if err != nil || parsed.Host != r.Host {
				httpError(w, 403, "请求来源无效")
				return
			}
		}
		h.mutate(w, r, owner)
		return
	}
	if r.Method != "GET" {
		httpError(w, 405, "method not allowed")
		return
	}
	path := r.URL.Path
	params := r.URL.Query()
	if path == "/" || path == "/index.html" {
		h.static(w, r, "index.html")
		return
	}
	if path == "/app.js" || path == "/app.css" || path == "/ui.js" || regexp.MustCompile(`^/chunk-[A-Za-z0-9]+\.js$`).MatchString(path) {
		h.static(w, r, strings.TrimPrefix(path, "/"))
		return
	}
	queries := map[string]string{"/api/overview": "overview", "/api/hunt": "hunt", "/api/events": "events", "/api/incidents": "incidents", "/api/incident": "incident", "/api/aggregate": "aggregate", "/api/record": "record", "/api/session": "session_events"}
	if name, ok := queries[path]; ok {
		data, err := h.App.Read(r.Context(), name, params)
		if err != nil {
			h.fail(w, err)
			return
		}
		if path == "/api/events" && params.Get("format") == "csv" {
			h.csv(w, data)
			return
		}
		jsonReply(w, 200, data)
		return
	}
	if path == "/api/stream" || path == "/api/hunt/stream" {
		if path == "/api/hunt/stream" {
			params.Set("topic", "hunt")
		}
		h.stream(w, r, params)
		return
	}
	if name := rpcReadName(path); name != "" {
		kwargs := Object{}
		for key, values := range params {
			if len(values) > 0 {
				kwargs[key] = values[0]
			}
		}
		result, err := h.App.Manager(r.Context(), "read", Object{"name": name, "args": []any{}, "kwargs": kwargs})
		if err != nil {
			h.fail(w, err)
			return
		}
		if path == "/api/hunt/rules" {
			result = Object{"rules": result, "path": "/var/lib/snort/rules/ips-web-hunting.rules"}
		}
		if path == "/api/rules/groups" {
			result = Object{"groups": result}
		}
		jsonReply(w, 200, result)
		return
	}
	switch path {
	case "/api/hunt/schema":
		jsonReply(w, 200, schema.HuntSchema)
	case "/api/cache/stats":
		jsonReply(w, 200, h.App.CacheStats())
	case "/api/db/stats":
		result, err := h.App.Store.Stats(r.Context())
		if err != nil {
			h.fail(w, err)
			return
		}
		jsonReply(w, 200, result)
	case "/api/version":
		build := int64(0)
		if executable, err := os.Executable(); err == nil {
			if info, err := os.Stat(executable); err == nil {
				build = info.ModTime().Unix()
			}
		}
		for _, name := range []string{"index.html", "app.js", "ui.js", "app.css"} {
			if info, err := os.Stat(filepath.Join(h.App.Config.StaticDir, name)); err == nil {
				build = max(build, info.ModTime().Unix())
			}
		}
		jsonReply(w, 200, Object{"build": build, "backend": "go"})
	case "/api/system":
		result, err := h.App.System(r.Context())
		if err != nil {
			h.fail(w, err)
			return
		}
		jsonReply(w, 200, result)
	case "/api/actions/status":
		value, err := h.App.Manager(r.Context(), "read", Object{"name": "sys.update_status"})
		if err != nil {
			h.fail(w, err)
			return
		}
		jsonReply(w, 200, value)
	case "/api/rules/schedule":
		value, err := h.App.Manager(r.Context(), "schedule", Object{})
		if err != nil {
			h.fail(w, err)
			return
		}
		jsonReply(w, 200, value)
	case "/api/db/clear/status":
		value, err := h.App.Manager(r.Context(), "history-status", Object{})
		if err != nil {
			h.fail(w, err)
			return
		}
		jsonReply(w, 200, Object{"reset": value})
	case "/api/hunt/flow-range", "/api/hunt/community-range", "/api/hunt/tuple-range", "/api/hunt/related":
		result, err := h.App.Related(r.Context(), path, params)
		if err != nil {
			h.fail(w, err)
			return
		}
		jsonReply(w, 200, result)
	case "/metrics":
		h.metrics(w, r)
	default:
		if strings.HasPrefix(path, "/api/event/") {
			id, err := strconv.ParseInt(strings.TrimPrefix(path, "/api/event/"), 10, 64)
			if err != nil || id < 1 {
				httpError(w, 400, "invalid event id")
				return
			}
			rows, err := queryRows(r.Context(), h.App.Store.Readers, "SELECT raw FROM events WHERE id=?", id)
			if err != nil {
				h.fail(w, err)
				return
			}
			if len(rows) == 0 {
				httpError(w, 404, "事件明细已超过保留范围")
				return
			}
			blob, ok := rows[0]["raw"].([]byte)
			if !ok || len(blob) == 0 {
				httpError(w, 404, "事件原文未保留")
				return
			}
			raw, err := decompress(blob)
			if err != nil {
				h.fail(w, err)
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write(raw)
			return
		}
		httpError(w, 404, "not found")
	}
}
func (h *HTTPHandler) fail(w http.ResponseWriter, err error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		httpError(w, 503, "查询已中断，请重试")
		return
	}
	httpError(w, 400, err.Error())
}
func (h *HTTPHandler) loginPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	message := map[string]string{"bad": "用户名或密码错误", "unset": "尚未配置登录密码", "throttled": "登录尝试过于频繁，请稍后重试"}[r.URL.Query().Get("error")]
	if !h.App.Config.PasswordConfigured() {
		message = "尚未配置登录密码，登录已禁用"
	}
	next := r.URL.Query().Get("next")
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		next = "/"
	}
	loginTemplate.Execute(w, Object{"User": h.App.Config.User, "Message": message, "Next": next, "Disabled": !h.App.Config.PasswordConfigured()})
}

//go:embed login.html
var loginHTML string
var loginTemplate = template.Must(template.New("login").Parse(loginHTML))

func (h *HTTPHandler) login(w http.ResponseWriter, r *http.Request) {
	select {
	case h.loginSlots <- struct{}{}:
		defer func() { <-h.loginSlots }()
	default:
		httpError(w, 429, "登录请求过多，请稍后重试")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if err := r.ParseForm(); err != nil {
		httpError(w, 400, "登录表单无效")
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	cfg := h.App.Config
	if !cfg.PasswordConfigured() {
		http.Redirect(w, r, "/login?error=unset", 302)
		return
	}
	if h.App.Sessions.Throttled(ip) {
		http.Redirect(w, r, "/login?error=throttled", 302)
		return
	}
	user := strings.TrimSpace(r.Form.Get("username"))
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(cfg.User)) == 1
	passwordOK := cfg.VerifyPassword(r.Form.Get("password"))
	if !userOK || !passwordOK {
		h.App.Sessions.Failure(ip)
		http.Redirect(w, r, "/login?error=bad", 302)
		return
	}
	h.App.Sessions.Success(ip)
	key := h.App.Sessions.Create(user, ip)
	http.SetCookie(w, &http.Cookie{Name: "ipsweb_session", Value: key, Path: "/", HttpOnly: true, Secure: cfg.SecureCookie, SameSite: http.SameSiteStrictMode, MaxAge: int(cfg.SessionTTL.Seconds())})
	next := r.Form.Get("next")
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.ContainsAny(next, "\r\n\\") {
		next = "/"
	}
	http.Redirect(w, r, next, 302)
}
func (h *HTTPHandler) mutate(w http.ResponseWriter, r *http.Request, owner string) {
	if r.URL.Path == "/logout" && r.Method == "POST" {
		h.App.Sessions.Drop(owner)
		http.SetCookie(w, &http.Cookie{Name: "ipsweb_session", Value: "", Path: "/", HttpOnly: true, Secure: h.App.Config.SecureCookie, SameSite: http.SameSiteStrictMode, MaxAge: -1})
		http.Redirect(w, r, "/login", 302)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		httpError(w, 413, "request body too large")
		return
	}
	body := Object{}
	if len(raw) > 0 {
		if err = decode(raw, &body); err != nil || body == nil {
			httpError(w, 400, "json body must be an object")
			return
		}
	}
	if r.URL.Path == "/api/ai/generate" && r.Method == "POST" {
		h.generate(w, r, owner, body)
		return
	}
	if r.URL.Path == "/api/ai/rules/add" && r.Method == "POST" {
		value, err := h.App.Assistant.Add(r.Context(), owner, text(body["proposal"]))
		if err != nil {
			h.fail(w, err)
			return
		}
		h.App.Invalidate()
		jsonReply(w, 200, value)
		return
	}
	h.App.mutation.Lock()
	defer h.App.mutation.Unlock()
	if r.URL.Path == "/api/db/settings" && r.Method == "POST" {
		if !strictInt(body["cap_mib"], 64, 1048576) {
			httpError(w, 400, "容量必须为整数")
			return
		}
		value, err := h.App.Store.SetCapacity(r.Context(), integer(body["cap_mib"]))
		if err != nil {
			h.fail(w, err)
			return
		}
		jsonReply(w, 200, Object{"ok": true, "stats": value})
		return
	}
	if r.URL.Path == "/api/db/clear" && r.Method == "POST" {
		scope := text(get(body, "scope", "all"))
		if scope != "all" && scope != "database" {
			httpError(w, 400, "历史清理范围无效")
			return
		}
		result, err := h.App.Manager(r.Context(), "history-reset", Object{"scope": scope})
		if err != nil {
			h.fail(w, err)
			return
		}
		h.App.Invalidate()
		jsonReply(w, 200, result)
		return
	}
	if !validMutation(r.Method, r.URL.Path) {
		httpError(w, 404, "not found")
		return
	}
	result, err := h.App.Manager(r.Context(), "mutate", Object{"method": r.Method, "path": r.URL.Path, "body": body})
	if err != nil {
		h.fail(w, err)
		return
	}
	h.App.Invalidate()
	jsonReply(w, 200, result)
}
func (h *HTTPHandler) static(w http.ResponseWriter, r *http.Request, name string) {
	root, err := filepath.EvalSymlinks(h.App.Config.StaticDir)
	if err != nil {
		httpError(w, 404, "not found")
		return
	}
	target, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(name)))
	if err != nil {
		httpError(w, 404, "not found")
		return
	}
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		httpError(w, 404, "not found")
		return
	}
	info, err := os.Stat(target)
	if err != nil || !info.Mode().IsRegular() {
		httpError(w, 404, "not found")
		return
	}
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
	if typ := mime.TypeByExtension(filepath.Ext(target)); typ != "" {
		w.Header().Set("Content-Type", typ)
	}
	http.ServeFile(w, r, target)
}
func (h *HTTPHandler) stream(w http.ResponseWriter, r *http.Request, params url.Values) {
	select {
	case h.streams <- struct{}{}:
		defer func() { <-h.streams }()
	default:
		httpError(w, 503, "实时连接已满，请稍后重试")
		return
	}
	topic := params.Get("topic")
	if !strings.Contains("|overview|hunt|events|incidents|aggregate|alerts|drops|system|rules|manage|", "|"+topic+"|") || topic == "" {
		httpError(w, 400, "unsupported stream topic")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		httpError(w, 503, "streaming unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Connection", "close")
	w.WriteHeader(200)
	flusher.Flush()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	heartbeat := time.NewTicker(2 * time.Second)
	defer heartbeat.Stop()
	last := ""
	for {
		type result struct {
			value Object
			err   error
		}
		done := make(chan result, 1)
		go func() { v, e := h.streamPayload(ctx, topic, params); done <- result{v, e} }()
		waiting := true
		for waiting {
			select {
			case <-ctx.Done():
				return
			case <-heartbeat.C:
				if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
					return
				}
				flusher.Flush()
			case value := <-done:
				waiting = false
				if value.err != nil {
					data, _ := json.Marshal(Object{"error": value.err.Error()})
					fmt.Fprintf(w, "data: %s\n\n", data)
					flusher.Flush()
					return
				}
				data, err := json.Marshal(value.value)
				if err != nil {
					return
				}
				if string(data) != last {
					if _, err = fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
						return
					}
					flusher.Flush()
					last = string(data)
				}
			}
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func (h *HTTPHandler) streamPayload(ctx context.Context, topic string, params url.Values) (Object, error) {
	switch topic {
	case "system":
		return h.App.System(ctx)
	case "rules", "manage":
		value, err := h.App.Manager(ctx, "read", Object{"name": "app.rules_payload", "args": []any{}, "kwargs": Object{}})
		if err != nil {
			return nil, err
		}
		if topic == "rules" {
			return object(value), nil
		}
		gov, err := h.App.Manager(ctx, "read", Object{"name": "governance_state", "args": []any{}, "kwargs": Object{}})
		return Object{"governance": gov, "rules": value}, err
	case "alerts":
		return h.App.Read(ctx, "incidents", params)
	case "drops":
		copy := url.Values{}
		for k, v := range params {
			copy[k] = append([]string{}, v...)
		}
		copy.Set("type", "drop")
		return h.App.Read(ctx, "events", copy)
	default:
		return h.App.Read(ctx, topic, params)
	}
}
func (h *HTTPHandler) generate(w http.ResponseWriter, r *http.Request, owner string, body Object) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		httpError(w, 503, "streaming unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Connection", "close")
	w.WriteHeader(200)
	flusher.Flush()
	send := func(value Object) bool {
		if r.Context().Err() != nil {
			return false
		}
		if err := json.NewEncoder(w).Encode(value); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	if err := h.App.Assistant.Generate(r.Context(), owner, body, send); err != nil && !errors.Is(err, context.Canceled) {
		send(Object{"error": err.Error()})
	}
}
func (h *HTTPHandler) csv(w http.ResponseWriter, data Object) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"snort-alerts.csv\"")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	w.Write([]byte{0xef, 0xbb, 0xbf})
	writer := csv.NewWriter(w)
	fields := strings.Fields("ts type sev sig_id sig src sport dst dport proto app action reason")
	writer.Write(fields)
	rows, _ := data["events"].([]Object)
	for _, row := range rows {
		record := make([]string, len(fields))
		for i, key := range fields {
			value := text(row[key])
			if strings.HasPrefix(strings.TrimLeft(value, " \t\r\n"), "=") || strings.ContainsAny(value[:min(1, len(value))], "+-@") {
				value = "'" + value
			}
			record[i] = value
		}
		writer.Write(record)
	}
	writer.Flush()
}
func (h *HTTPHandler) metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintln(w, "# HELP ips_web_up ips-web exporter alive\n# TYPE ips_web_up gauge\nips_web_up 1")
	fmt.Fprintf(w, "ips_web_ingest_lag_bytes %d\nips_web_cpu_workers %d\n", h.App.Store.Lag(), h.App.Pool.Workers)
	snapshot := h.App.StatusSnapshot()
	engine := object(snapshot["engine"])
	ips := object(object(engine["dump-counters"])["ips"])
	active := 0
	if object(snapshot["service"])["state"] == "active" {
		active = 1
	}
	values := []struct {
		name, kind, help string
		value            any
	}{{"snort_up", "gauge", "Snort service active", active}, {"snort_rules_loaded", "gauge", "Loaded signatures", object(engine["ruleset-stats"])["rules_loaded"]}, {"snort_ips_accepted_total", "counter", "Packets accepted by Snort", ips["accepted"]}, {"snort_ips_blocked_total", "counter", "Packets blocked by Snort", ips["blocked"]}, {"snort_block_actions_total", "counter", "Rule block actions", object(ips["drop_reason"])["rules"]}, {"snort_queue_packets_total", "counter", "Packets sent to NFQUEUE", object(snapshot["queue_listeners"])["packets"]}, {"snort_throughput_pps", "gauge", "Current packet rate", object(snapshot["rates"])["pps"]}, {"snort_throughput_mbps", "gauge", "Current throughput", object(snapshot["rates"])["mbps"]}}
	for _, v := range values {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s %g\n", v.name, v.help, v.name, v.kind, v.name, number(v.value))
	}
}

type limitedListener struct {
	net.Listener
	slots chan struct{}
	stop  chan struct{}
	once  sync.Once
}
type limitedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *limitedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (l *limitedListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.stop:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitedConn{Conn: c, release: func() { <-l.slots }}, nil
}
func (l *limitedListener) Close() error {
	l.once.Do(func() { close(l.stop) })
	return l.Listener.Close()
}
func ServeHTTP(ctx context.Context, cfg Config) error {
	app, err := NewApp(ctx, cfg)
	if err != nil {
		return err
	}
	defer app.Close()
	listener, err := net.Listen("tcp", net.JoinHostPort(cfg.Bind, strconv.Itoa(cfg.Port)))
	if err != nil {
		return err
	}
	limited := &limitedListener{Listener: listener, slots: make(chan struct{}, 32*WorkerCount()), stop: make(chan struct{})}
	server := &http.Server{Handler: NewHTTPHandler(app), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			server.Close()
		case <-done:
		}
	}()
	err = server.Serve(limited)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
