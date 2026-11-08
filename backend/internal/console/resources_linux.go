//go:build linux

package console

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// ServiceWorkers reads the current service's kernel-enforced allocation, never
// another service's settings or the host CPU count alone. Quotas round upward;
// a sub-core quota still needs one worker. Pool sizes are fixed until restart.
func ServiceWorkers() int {
	return serviceWorkers("/proc/self", "/sys/fs/cgroup", runtime.NumCPU(), os.ReadFile)
}

func cpuListCount(value string) int {
	cpus := map[int]bool{}
	for _, part := range strings.Split(strings.TrimSpace(value), ",") {
		ends := strings.Split(part, "-")
		first, err := strconv.Atoi(ends[0])
		if err != nil || first < 0 || len(ends) > 2 {
			return 0
		}
		last := first
		if len(ends) == 2 {
			last, err = strconv.Atoi(ends[1])
		}
		if err != nil || last < first || last > 1<<20 {
			return 0
		}
		for cpu := first; cpu <= last; cpu++ {
			cpus[cpu] = true
		}
	}
	return len(cpus)
}

func serviceWorkers(proc, root string, online int, read func(string) ([]byte, error)) int {
	n := max(1, online)
	limit := func(value int) {
		if value > 0 {
			n = min(n, value)
		}
	}
	status, _ := read(filepath.Join(proc, "status"))
	for _, line := range strings.Split(string(status), "\n") {
		if value, ok := strings.CutPrefix(line, "Cpus_allowed_list:"); ok {
			limit(cpuListCount(value))
		}
	}
	groups, _ := read(filepath.Join(proc, "cgroup"))
	for _, line := range strings.Split(string(groups), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 {
			continue
		}
		base := root
		unified := fields[0] == "0" && fields[1] == ""
		if !unified {
			controller := ""
			for _, name := range strings.Split(fields[1], ",") {
				if name == "cpu" || name == "cpuset" {
					controller = name
					break
				}
			}
			if controller == "" {
				continue
			}
			base = filepath.Join(root, fields[1])
			if _, err := read(filepath.Join(base, "cgroup.procs")); err != nil {
				base = filepath.Join(root, controller)
			}
		}
		path := filepath.Join(base, strings.TrimPrefix(filepath.Clean("/"+fields[2]), "/"))
		for {
			for _, file := range []string{"cpuset.cpus.effective", "cpuset.effective_cpus", "cpuset.cpus"} {
				if value, err := read(filepath.Join(path, file)); err == nil {
					limit(cpuListCount(string(value)))
				}
			}
			if value, err := read(filepath.Join(path, "cpu.max")); err == nil {
				var quota, period int64
				if _, err = fmt.Sscan(string(value), &quota, &period); err == nil && quota > 0 && period > 0 {
					limit(int((quota-1)/period + 1))
				}
			} else {
				q, _ := read(filepath.Join(path, "cpu.cfs_quota_us"))
				p, _ := read(filepath.Join(path, "cpu.cfs_period_us"))
				quota, e1 := strconv.ParseInt(strings.TrimSpace(string(q)), 10, 64)
				period, e2 := strconv.ParseInt(strings.TrimSpace(string(p)), 10, 64)
				if e1 == nil && e2 == nil && quota > 0 && period > 0 {
					limit(int((quota-1)/period + 1))
				}
			}
			if path == base {
				break
			}
			parent := filepath.Dir(path)
			if parent == path {
				break
			}
			path = parent
		}
	}
	return n
}

func ConfigureResources() { runtime.GOMAXPROCS(ServiceWorkers()) }

func RunResourceBudget(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("resources", flag.ContinueOnError)
	pid := flags.Int("pid", os.Getpid(), "服务进程")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *pid < 1 || flags.NArg() != 0 {
		return errors.New("服务进程参数无效")
	}
	proc := filepath.Join("/proc", strconv.Itoa(*pid))
	if _, err := os.Stat(filepath.Join(proc, "status")); err != nil {
		return err
	}
	n := serviceWorkers(proc, "/sys/fs/cgroup", runtime.NumCPU(), os.ReadFile)
	return json.NewEncoder(os.Stdout).Encode(Object{"workers": n, "pid": *pid, "source": "service-cgroup-affinity"})
}
