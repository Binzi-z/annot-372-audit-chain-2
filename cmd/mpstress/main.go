// mpstress 是多进程并发写入压测工具（需求③的取证数据来源）。
//
// 父进程模式：启动 -p 个独立 OS 进程，每个进程写 -n 条事件，
// 全部退出后输出总吞吐；配合 auditctl verify 可证明链不乱序。
//
//	go run ./cmd/mpstress -data data -p 8 -n 12500
//
// 子进程模式由父进程通过 -child 与环境变量驱动，不直接使用。
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"annot-audit/internal/audit"
)

const envChild = "AUDIT_MPSTRESS_CHILD"

func main() {
	dataDir := flag.String("data", "data", "audit data directory")
	procs := flag.Int("p", 4, "number of writer processes")
	perProc := flag.Int("n", 1000, "events per process")
	child := flag.Bool("child", false, "internal: child worker mode")
	flag.Parse()

	if *child || os.Getenv(envChild) == "1" {
		runChild(*dataDir)
		return
	}
	runParent(*dataDir, *procs, *perProc)
}

func runChild(dir string) {
	shard, _ := strconv.Atoi(os.Getenv("AUDIT_MPSTRESS_SHARD"))
	n, _ := strconv.Atoi(os.Getenv("AUDIT_MPSTRESS_EVENTS"))
	w, err := audit.NewWriter(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "child %d open: %v\n", shard, err)
		os.Exit(1)
	}
	for i := 0; i < n; i++ {
		if err := w.Write(audit.Event{
			ID:       fmt.Sprintf("p%d-e%d", shard, i),
			Actor:    fmt.Sprintf("proc-%d", shard),
			Action:   "write",
			Resource: "doc/mp",
		}); err != nil {
			fmt.Fprintf(os.Stderr, "child %d write: %v\n", shard, err)
			os.Exit(1)
		}
	}
	if err := w.WaitFlush(); err != nil {
		fmt.Fprintf(os.Stderr, "child %d flush: %v\n", shard, err)
		os.Exit(1)
	}
	if err := w.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "child %d close: %v\n", shard, err)
		os.Exit(1)
	}
}

func runParent(dir string, procs, perProc int) {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "locate executable: %v\n", err)
		os.Exit(2)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(2)
	}

	start := time.Now()
	var wg sync.WaitGroup
	errs := make(chan error, procs)
	for s := 0; s < procs; s++ {
		wg.Add(1)
		go func(shard int) {
			defer wg.Done()
			cmd := exec.Command(exe, "-data", dir, "-child")
			cmd.Env = append(os.Environ(),
				envChild+"=1",
				"AUDIT_MPSTRESS_SHARD="+strconv.Itoa(shard),
				"AUDIT_MPSTRESS_EVENTS="+strconv.Itoa(perProc),
			)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				errs <- fmt.Errorf("shard %d: %w", shard, err)
			}
		}(s)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
	elapsed := time.Since(start)
	total := procs * perProc

	rep, err := audit.Verify(dir, audit.VerifyOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("processes=%d per_proc=%d total=%d elapsed=%s throughput=%.0f events/s\n",
		procs, perProc, total, elapsed.Round(time.Millisecond),
		float64(total)/elapsed.Seconds())
	if !rep.OK {
		fmt.Fprintf(os.Stderr, "INTEGRITY FAILURE: %d anomalies\n", len(rep.Anomalies))
		os.Exit(1)
	}
	if rep.ScannedEvents != int64(total) {
		fmt.Fprintf(os.Stderr, "EVENT LOSS: wrote=%d verified=%d\n", total, rep.ScannedEvents)
		os.Exit(1)
	}
	fmt.Printf("integrity OK: %d events replayed, chain head=%s\n",
		rep.ScannedEvents, shortHash(rep.Segments[len(rep.Segments)-1].HeadHash))
}

func shortHash(h string) string {
	if len(h) > 16 {
		return h[:16] + "…"
	}
	return h
}
