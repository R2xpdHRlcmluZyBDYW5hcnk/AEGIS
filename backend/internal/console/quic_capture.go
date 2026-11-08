package console

import (
	"bufio"
	"container/list"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unicode/utf8"
)

var quicCaptureFields = []string{"frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "udp.srcport", "ip.dst", "ipv6.dst", "udp.dstport", "udp.length", "quic.connection.number", "quic.dcid", "quic.scid", "quic.version", "tls.handshake.type", "tls.handshake.extensions_server_name", "tls.handshake.extensions_alpn_str"}

const quicResetPackets = 100000

type quicEndpoint struct {
	ip   string
	port int
}

func (e quicEndpoint) JSON() []any { return []any{e.ip, e.port} }

type quicPacket struct {
	frame                             int64
	stamp                             float64
	connection                        string
	source, target                    quicEndpoint
	cids, dcids, scids, version, alpn []string
	hello                             bool
	sni                               string
	size                              int64
}

func quicValues(value string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, v := range strings.Split(value, ",") {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
func limitedStrings(values []string, count, width int) []string {
	out := []string{}
	for _, v := range values[:min(count, len(values))] {
		out = append(out, string([]rune(v)[:min(width, len([]rune(v)))]))
	}
	return out
}
func parseQuicPacket(line string) (quicPacket, error) {
	p := quicPacket{}
	if !utf8.ValidString(line) {
		return p, errors.New("QUIC 字段不是有效 UTF-8")
	}
	reader := csv.NewReader(strings.NewReader(line))
	reader.Comma = '\t'
	reader.FieldsPerRecord = len(quicCaptureFields)
	row, err := reader.Read()
	if err != nil {
		return p, err
	}
	p.frame, err = strconv.ParseInt(row[0], 10, 64)
	if err != nil || p.frame < 1 {
		return p, errors.New("QUIC 帧编号无效")
	}
	p.stamp, err = strconv.ParseFloat(row[1], 64)
	if err != nil || p.stamp <= 0 || math.IsNaN(p.stamp) || math.IsInf(p.stamp, 0) {
		return p, errors.New("QUIC 时间戳无效")
	}
	connections := quicValues(row[9])
	if len(connections) != 1 {
		return p, nil
	}
	if _, err = strconv.ParseUint(connections[0], 10, 64); err != nil {
		return p, nil
	}
	p.connection = connections[0]
	parseEndpoint := func(ip, v6, port string) (quicEndpoint, error) {
		if ip == "" {
			ip = v6
		}
		address, err := netip.ParseAddr(ip)
		n, e := strconv.Atoi(port)
		if err != nil || e != nil || n < 0 || n > 65535 {
			return quicEndpoint{}, errors.New("QUIC 端点无效")
		}
		return quicEndpoint{address.String(), n}, nil
	}
	p.source, err = parseEndpoint(row[2], row[3], row[4])
	if err != nil {
		return p, err
	}
	p.target, err = parseEndpoint(row[5], row[6], row[7])
	if err != nil {
		return p, err
	}
	parseCID := func(value string) ([]string, error) {
		out := []string{}
		for _, v := range quicValues(value) {
			v = strings.ToLower(strings.ReplaceAll(v, ":", ""))
			if !regexp.MustCompile(`^(?:[0-9a-f]{2}){1,20}$`).MatchString(v) {
				return nil, errors.New("QUIC CID 无效")
			}
			out = append(out, v)
		}
		return out, nil
	}
	p.dcids, err = parseCID(row[10])
	if err != nil {
		return p, err
	}
	p.scids, err = parseCID(row[11])
	if err != nil {
		return p, err
	}
	p.cids = append(append([]string{}, p.dcids...), p.scids...)
	p.cids = p.cids[:min(16, len(p.cids))]
	p.dcids = p.dcids[:min(8, len(p.dcids))]
	p.scids = p.scids[:min(8, len(p.scids))]
	p.version = limitedStrings(quicValues(row[12]), 2, 64)
	for _, v := range quicValues(row[13]) {
		p.hello = p.hello || v == "1"
	}
	p.sni = strings.Join(limitedStrings([]string{row[14]}, 1, 253), "")
	p.alpn = limitedStrings(quicValues(row[15]), 8, 64)
	size, err := strconv.ParseInt(strings.SplitN(row[8], ",", 2)[0], 10, 64)
	if err != nil {
		return p, err
	}
	p.size = max(0, min(int64(65535), size)-8)
	return p, nil
}

type quicState struct {
	key, id                                     string
	first, last, published                      float64
	origin, peer                                quicEndpoint
	client                                      *quicEndpoint
	sni                                         string
	alpn, version, cids                         []string
	paths                                       [][2]quicEndpoint
	aPackets, bPackets, aBytes, bBytes, unknown int64
	limited, dirty                              bool
	aCIDs, bCIDs                                map[string]bool
	node                                        *list.Element
}
type quicTracker struct {
	emit           func(Object) error
	states         map[string]*quicState
	order          *list.List
	prefix         string
	sequence       uint64
	lastFrame      int64
	capacity       int
	interval, idle float64
}

func newQuicTracker(emit func(Object) error) *quicTracker {
	return &quicTracker{emit: emit, states: map[string]*quicState{}, order: list.New(), prefix: token()[:32], capacity: 4096, interval: 30, idle: 120}
}
func (t *quicTracker) flush(s *quicState, reason string) error {
	if !s.dirty {
		return nil
	}
	paths := []any{}
	for _, p := range s.paths {
		paths = append(paths, []any{p[0].JSON(), p[1].JSON()})
	}
	var client any
	if s.client != nil {
		client = s.client.JSON()
	}
	data := Object{"session_id": s.id, "first": s.first, "last": s.last, "origin": s.origin.JSON(), "peer": s.peer.JSON(), "client": client, "sni": s.sni, "alpn": s.alpn, "version": s.version, "cids": s.cids, "paths": paths, "a_packets": s.aPackets, "b_packets": s.bPackets, "a_bytes": s.aBytes, "b_bytes": s.bBytes, "unknown_packets": s.unknown, "limited": s.limited, "reason": reason}
	if err := t.emit(Object{"engine": "quic_observer", "data": data}); err != nil {
		return err
	}
	s.dirty = false
	s.published = s.last
	return nil
}
func (t *quicTracker) close(reason string) error {
	for e := t.order.Front(); e != nil; e = e.Next() {
		if err := t.flush(e.Value.(*quicState), reason); err != nil {
			return err
		}
	}
	t.states = map[string]*quicState{}
	t.order.Init()
	return nil
}
func (t *quicTracker) observe(p quicPacket) error {
	if t.lastFrame > 0 && (p.frame <= t.lastFrame || (p.frame-1)/quicResetPackets != (t.lastFrame-1)/quicResetPackets) {
		if err := t.close("decoder_state_reset"); err != nil {
			return err
		}
	}
	t.lastFrame = p.frame
	if p.connection == "" {
		return nil
	}
	s := t.states[p.connection]
	if s == nil {
		if len(t.states) >= t.capacity {
			e := t.order.Front()
			old := e.Value.(*quicState)
			if err := t.flush(old, "state_capacity"); err != nil {
				return err
			}
			delete(t.states, old.key)
			t.order.Remove(e)
		}
		t.sequence++
		s = &quicState{key: p.connection, id: fmt.Sprintf("%s:%016x", t.prefix, t.sequence), first: p.stamp, last: p.stamp, origin: p.source, peer: p.target, aCIDs: map[string]bool{}, bCIDs: map[string]bool{}, alpn: []string{}, version: []string{}, cids: []string{}}
		s.node = t.order.PushBack(s)
		t.states[p.connection] = s
	}
	changed := s.published == 0
	if p.hello {
		if p.sni != "" && p.sni != s.sni {
			s.sni = p.sni
			changed = true
		}
		if len(p.alpn) > 0 && strings.Join(p.alpn, "\x00") != strings.Join(s.alpn, "\x00") {
			s.alpn = p.alpn
			changed = true
		}
		if len(p.version) > 0 && strings.Join(p.version, "\x00") != strings.Join(s.version, "\x00") {
			s.version = p.version
			changed = true
		}
	}
	toA, toB := false, false
	for _, cid := range p.dcids {
		toA = toA || s.aCIDs[cid]
		toB = toB || s.bCIDs[cid]
	}
	reverse := p.target == s.origin || p.source == s.peer
	if toA != toB {
		reverse = toA
	}
	known := toA != toB || p.source == s.origin || p.source == s.peer || p.target == s.origin || p.target == s.peer
	if known {
		own, other := s.aCIDs, s.bCIDs
		if reverse {
			s.bPackets++
			s.bBytes += p.size
			own, other = s.bCIDs, s.aCIDs
		} else {
			s.aPackets++
			s.aBytes += p.size
		}
		for _, cid := range p.scids[:min(len(p.scids), max(0, 16-len(own)))] {
			own[cid] = true
		}
		for _, cid := range p.dcids[:min(len(p.dcids), max(0, 16-len(other)))] {
			other[cid] = true
		}
		if p.hello {
			client := s.origin
			if reverse {
				client = s.peer
			}
			s.client = &client
		}
	} else {
		s.unknown++
	}
	visible := [2]quicEndpoint{p.source, p.target}
	if reverse {
		visible = [2]quicEndpoint{p.target, p.source}
	}
	found := false
	for _, path := range s.paths {
		found = found || path == visible
	}
	if !found {
		if len(s.paths) < 8 {
			s.paths = append(s.paths, visible)
			changed = true
		} else {
			s.limited = true
		}
	}
	for _, cid := range p.cids {
		found = false
		for _, existing := range s.cids {
			found = found || cid == existing
		}
		if !found {
			if len(s.cids) < 16 {
				s.cids = append(s.cids, cid)
				changed = true
			} else {
				s.limited = true
			}
		}
	}
	s.first = min(s.first, p.stamp)
	s.last = max(s.last, p.stamp)
	s.dirty = true
	t.order.MoveToBack(s.node)
	if changed || p.stamp-s.published >= t.interval {
		if err := t.flush(s, "update"); err != nil {
			return err
		}
	}
	for e := t.order.Front(); e != nil; {
		old := e.Value.(*quicState)
		if p.stamp-old.last <= t.idle {
			break
		}
		if err := t.flush(old, "observation_idle"); err != nil {
			return err
		}
		delete(t.states, old.key)
		next := e.Next()
		t.order.Remove(e)
		e = next
	}
	return nil
}

func quicDecodeArguments(input string) []string {
	args := []string{"-n", "-l", "-M", strconv.Itoa(quicResetPackets), "-r", input, "-Y", "quic || frame.number == 1", "-T", "fields", "-E", "separator=\t", "-E", "quote=d"}
	for _, field := range quicCaptureFields {
		args = append(args, "-e", field)
	}
	return args
}

// Parsing is parallel, but decoder sequence, tracker state and output stay in
// source order. Admission tokens bound both the work queue and reorder buffer.
func readQuicObservations(ctx context.Context, input io.Reader, tracker *quicTracker, workers int) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type job struct {
		id   int64
		line string
	}
	type answer struct {
		id     int64
		packet quicPacket
		err    error
	}
	readDone := make(chan struct{})
	defer close(readDone)
	if closer, ok := input.(io.ReadCloser); ok {
		go func() {
			select {
			case <-ctx.Done():
				closer.Close()
			case <-readDone:
			}
		}()
	}
	jobs := make(chan job, workers)
	answers := make(chan answer, workers)
	slots := make(chan struct{}, workers*2)
	readError := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(jobs)
		scanner := bufio.NewScanner(input)
		scanner.Buffer(make([]byte, 32768), 32769)
		var id int64
		for scanner.Scan() {
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				return
			}
			select {
			case jobs <- job{id, scanner.Text()}:
				id++
			case <-ctx.Done():
				return
			}
		}
		readError <- scanner.Err()
	}()
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				p, err := parseQuicPacket(item.line)
				select {
				case answers <- answer{item.id, p, err}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(answers); close(done) }()
	pending := map[int64]answer{}
	var next int64
	var failure error
	for item := range answers {
		pending[item.id] = item
		for {
			value, ok := pending[next]
			if !ok {
				break
			}
			delete(pending, next)
			next++
			<-slots
			if failure == nil && value.err == nil {
				failure = tracker.observe(value.packet)
				if failure != nil {
					cancel()
				}
			}
		}
	}
	<-done
	if failure != nil {
		return failure
	}
	select {
	case err := <-readError:
		return err
	default:
		return ctx.Err()
	}
}

func RunQuicObserver(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("ips-quic-observer", flag.ContinueOnError)
	iface := flags.String("interface", "", "监听接口")
	pcap := flags.String("pcap", "", "离线 PCAP")
	output := flags.String("output", "", "观察记录")
	binary := flags.String("tshark", "tshark", "Wireshark 解码器")
	config := flags.String("config", "", "观察配置")
	prepare := flags.Bool("prepare-output", false, "准备日志权限")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("QUIC 参数无效")
	}
	if err := validateLogStorage(); err != nil {
		return err
	}
	logs, _, err := LogPaths()
	if err != nil {
		return err
	}
	if *output == "" {
		*output = filepath.Join(logs, "0_quic_observer.json")
	}
	if *prepare {
		if os.Geteuid() != 0 {
			return errors.New("观察日志权限维护需要 root 权限")
		}
		account, err := user.Lookup("ips-quic")
		if err != nil {
			return err
		}
		uid, e1 := strconv.Atoi(account.Uid)
		gid, e2 := strconv.Atoi(account.Gid)
		if e1 != nil || e2 != nil {
			return errors.New("观察用户无效")
		}
		f, err := os.OpenFile(*output, os.O_CREATE|os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW, 0644)
		if err != nil {
			return err
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("观察日志不是常规文件")
		}
		return f.Chown(uid, gid)
	}
	if *config != "" {
		var value Object
		if err := readJSON(*config, &value); err != nil {
			return err
		}
		*iface = text(value["interface"])
	}
	if (*iface == "") == (*pcap == "") {
		return errors.New("请选择一个监听接口或离线 PCAP")
	}
	if *iface != "" && !regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`).MatchString(*iface) {
		return errors.New("监听接口无效")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	input := *pcap
	var capture *exec.Cmd
	var pipe io.ReadCloser
	if input == "" {
		input = "-"
		capture = exec.CommandContext(ctx, "dumpcap", "-i", *iface, "-f", "udp", "-B", "4", "-s", "65535", "-w", "-", "-q")
		configureCommand(capture)
		capture.Stderr = os.Stderr
		pipe, err = capture.StdoutPipe()
		if err != nil {
			return err
		}
		if err = capture.Start(); err != nil {
			pipe.Close()
			return err
		}
		defer func() { cancel(); pipe.Close(); capture.Wait() }()
	}
	decoder := exec.CommandContext(ctx, *binary, quicDecodeArguments(input)...)
	configureCommand(decoder)
	decoder.Stdin = pipe
	decoder.Stderr = os.Stderr
	stream, err := decoder.StdoutPipe()
	if err != nil {
		return err
	}
	if err = decoder.Start(); err != nil {
		stream.Close()
		return err
	}
	if pipe != nil {
		pipe.Close()
	}
	defer func() { cancel(); stream.Close(); decoder.Wait() }()
	tracker := newQuicTracker(func(value Object) error {
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(*output, os.O_CREATE|os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW, 0644)
		if err != nil {
			return err
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("观察日志不是常规文件")
		}
		if _, err = f.Write(append(data, '\n')); err != nil {
			return err
		}
		return f.Sync()
	})
	err = readQuicObservations(ctx, stream, tracker, WorkerCount())
	flush := tracker.close("observer_stopped")
	stream.Close()
	if ctx.Err() != nil {
		return flush
	}
	if err != nil {
		return errors.Join(err, flush)
	}
	if err = decoder.Wait(); err != nil {
		return errors.Join(errors.New("QUIC 解码器退出失败"), flush)
	}
	if capture != nil {
		return errors.Join(errors.New("QUIC 采集通道意外关闭"), flush)
	}
	return flush
}
