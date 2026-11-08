package console

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestServiceAllocationUsesOwnAffinityAndAncestorQuota(t *testing.T) {
	t.Setenv("GOMAXPROCS", "")
	t.Setenv("IPS_CPU_WORKERS", "")
	files := map[string]string{"/proc/self/status": "Cpus_allowed_list:\t4-7\n", "/proc/self/cgroup": "0::/performance.slice/ips.service\n", "/cg/performance.slice/ips.service/cpu.max": "max 100000", "/cg/performance.slice/ips.service/cpuset.cpus.effective": "4-7", "/cg/performance.slice/cpu.max": "250000 100000"}
	read := func(path string) ([]byte, error) {
		if value, ok := files[path]; ok {
			return []byte(value), nil
		}
		return nil, os.ErrNotExist
	}
	if got := serviceWorkers("/proc/self", "/cg", 16, read); got != 3 {
		t.Fatal("ancestor quota not respected", got)
	}
	files["/cg/performance.slice/ips.service/cpu.max"] = "50000 100000"
	if got := serviceWorkers("/proc/self", "/cg", 16, read); got != 1 {
		t.Fatal("sub-core service overallocated", got)
	}
	files["/cg/performance.slice/ips.service/cpu.max"] = "max 100000"
	files["/cg/performance.slice/cpu.max"] = "max 100000"
	if got := serviceWorkers("/proc/self", "/cg", 16, read); got != 4 {
		t.Fatal("detector affinity not respected", got)
	}
	files["/proc/self/status"] = "Cpus_allowed_list:\t0-7\n"
	files["/cg/performance.slice/ips.service/cpuset.cpus.effective"] = "0-7"
	if got := serviceWorkers("/proc/self", "/cg", 16, read); got != 8 {
		t.Fatal("legacy four-worker cap remains", got)
	}
	t.Setenv("IPS_CPU_WORKERS", "2")
	if got := serviceWorkers("/proc/self", "/cg", 16, read); got != 8 {
		t.Fatal("legacy worker setting replaced the service allocation", got)
	}
}

func TestServiceAllocationLegacyCgroupAndCpuLists(t *testing.T) {
	t.Setenv("GOMAXPROCS", "")
	t.Setenv("IPS_CPU_WORKERS", "")
	files := map[string]string{"/p/status": "Cpus_allowed_list: 0-1,4,6-7\n", "/p/cgroup": "2:cpu,cpuacct:/system.slice/worker.service\n", "/cg/cpu/system.slice/worker.service/cpu.cfs_quota_us": "100000", "/cg/cpu/system.slice/worker.service/cpu.cfs_period_us": "100000"}
	read := func(path string) ([]byte, error) {
		if value, ok := files[path]; ok {
			return []byte(value), nil
		}
		return nil, os.ErrNotExist
	}
	if got := serviceWorkers("/p", "/cg", 32, read); got != 1 {
		t.Fatal(got)
	}
	for value, want := range map[string]int{"0-3": 4, "0-1,4,6-7": 5, "2,2": 1, "": 0, "2-1": 0, "x": 0} {
		if got := cpuListCount(value); got != want {
			t.Fatal(value, got)
		}
	}
}

func TestDetectorQueuesFollowDetectionServiceBudget(t *testing.T) {
	for _, count := range []int{1, 2, 4, 8, 16} {
		rules := SupervisorNftRules(count)
		want := "0"
		if count > 1 {
			want += "-" + strconv.Itoa(count-1)
		}
		if !strings.Contains(rules, "queue flags bypass to "+want+"\n") || strings.Contains(rules, "fanout") {
			t.Fatal(rules)
		}
		args, err := detectorArguments(count, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		inputs := 0
		threads := ""
		for i, arg := range args {
			if arg == "-i" {
				if args[i+1] != strconv.Itoa(inputs) {
					t.Fatal(args)
				}
				inputs++
			}
			if arg == "-z" {
				threads = args[i+1]
			}
		}
		if inputs != count || threads != strconv.Itoa(count) {
			t.Fatal(args)
		}
	}
	path := filepath.Join(t.TempDir(), "queue")
	os.WriteFile(path, []byte("0 100\n7 101\n9 0\n"), 0600)
	bound, err := boundQueues(path, 8)
	if err != nil || !bound[7] || len(bound) != 2 {
		t.Fatal(bound, err)
	}
	os.WriteFile(path, []byte("0 100\n1 incomplete\n"), 0600)
	if bound, err = boundQueues(path, 8); err == nil || bound != nil {
		t.Fatal("uncertain state treated as missing")
	}
}

func TestDetectorWatchdogDoesNotAccumulateUnknownSamples(t *testing.T) {
	start := time.Now()
	h := queueHealth{started: start, count: 2}
	check := func(seconds int, bound map[int]bool, want int) {
		t.Helper()
		got := h.overdue(bound, start.Add(time.Duration(seconds)*time.Second))
		if len(got) != want {
			t.Fatal(seconds, got)
		}
	}
	check(119, map[int]bool{0: true}, 0)
	check(120, map[int]bool{0: true}, 0)
	check(134, map[int]bool{0: true}, 0)
	check(135, map[int]bool{0: true}, 1)
	check(136, nil, 0)
	check(137, map[int]bool{0: true}, 0)
	check(152, map[int]bool{0: true}, 1)
	check(153, map[int]bool{0: true, 1: true}, 0)
}

func TestDetectorChildHelper(t *testing.T) {
	mode := os.Getenv("AEGIS_DETECTOR_HELPER")
	if mode == "" {
		return
	}
	if mode == "ignore" {
		signal.Ignore(syscall.SIGTERM)
		os.WriteFile(os.Getenv("AEGIS_DETECTOR_READY"), nil, 0600)
		select {}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()
	os.WriteFile(os.Getenv("AEGIS_DETECTOR_READY"), nil, 0600)
	<-ctx.Done()
}

func TestDetectorChildLifecycleAndForcedStop(t *testing.T) {
	for _, mode := range []string{"graceful", "ignore"} {
		t.Run(mode, func(t *testing.T) {
			run := t.TempDir()
			ready := filepath.Join(run, "ready")
			t.Setenv("AEGIS_DETECTOR_HELPER", mode)
			t.Setenv("AEGIS_DETECTOR_READY", ready)
			c := &detectorChild{}
			defer c.Stop(time.Second)
			if err := c.Start([]string{os.Args[0], "-test.run=^TestDetectorChildHelper$"}, run, 8); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(5 * time.Second)
			for !fileExists(ready) && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if !fileExists(ready) || !c.Alive() {
				t.Fatal("child failed to start")
			}
			var instance Object
			if readJSON(filepath.Join(run, "instance.json"), &instance) != nil || integer(instance["workers"]) != 8 || len(text(instance["epoch"])) != 32 {
				t.Fatal(instance)
			}
			if err := c.Stop(100 * time.Millisecond); err != nil || c.Alive() {
				t.Fatal("child did not stop", err)
			}
		})
	}
}

func TestDetectorRestartPreservesEveryQueueLogAndQuic(t *testing.T) {
	logs, run := t.TempDir(), t.TempDir()
	names := []string{"0_file_connector_ndr_transmit", "7_file_connector_ndr_transmit", "7_alert_json.txt", "7_ndr_session.json"}
	for _, name := range append(names, "0_quic_observer.json") {
		if err := os.WriteFile(filepath.Join(logs, name), []byte("retained\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := os.Stat(filepath.Join(logs, names[0]))
	if err := archiveDetectorLogs(t.Context(), logs, run, filepath.Join(run, "offsets.json")); err != nil {
		t.Fatal(err)
	}
	archives, _ := filepath.Glob(filepath.Join(logs, ".response-*"))
	if len(archives) != 1 {
		t.Fatal(archives)
	}
	for _, name := range names {
		if readText(filepath.Join(logs, name)) != "" || readText(filepath.Join(archives[0], name)) != "retained\n" {
			t.Fatal("history lost", name)
		}
	}
	after, _ := os.Stat(filepath.Join(archives[0], names[0]))
	if !os.SameFile(before, after) {
		t.Fatal("archive copied rather than retaining inode")
	}
	if readText(filepath.Join(logs, "0_quic_observer.json")) != "retained\n" {
		t.Fatal("observer log changed")
	}
	os.Remove(filepath.Join(logs, names[0]))
	os.Symlink(filepath.Join(logs, "0_quic_observer.json"), filepath.Join(logs, names[0]))
	if err := archiveDetectorLogs(t.Context(), logs, run, ""); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestDetectorRecoverySharesRuleTransactionLock(t *testing.T) {
	config := filepath.Join(t.TempDir(), "snort.lua")
	guard, err := lockConfiguration(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	if g, err := tryConfiguration(config); err == nil {
		g.Close()
		t.Fatal("recovery bypassed active rule transaction")
	}
	guard.Close()
	g, err := tryConfiguration(config)
	if err != nil {
		t.Fatal(err)
	}
	g.Close()
}
