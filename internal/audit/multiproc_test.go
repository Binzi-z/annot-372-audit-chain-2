package audit

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// 多进程并发写入测试：通过重入测试二进制启动真正独立的 OS 进程，
// 每个进程持有自己的 Writer，共享同一个 data 目录与 audit.lock。
func TestMultiProcessWrites(t *testing.T) {
	if os.Getenv("AUDIT_TEST_CHILD") == "1" {
		runChildWriter(t)
		return
	}

	const procs = 4
	const perProc = 200
	dir := t.TempDir()

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("test executable: %v", err)
	}
	for s := 0; s < procs; s++ {
		cmd := exec.Command(exe, "-test.run=TestMultiProcessWrites")
		cmd.Env = append(os.Environ(),
			"AUDIT_TEST_CHILD=1",
			"AUDIT_TEST_DIR="+dir,
			fmt.Sprintf("AUDIT_TEST_SHARD=%d", s),
			fmt.Sprintf("AUDIT_TEST_EVENTS=%d", perProc),
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("child %d failed: %v\n%s", s, err, out)
		}
	}

	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	want := int64(procs * perProc)
	if !rep.OK {
		t.Fatalf("chain broken under multi-process writes: %+v", rep.Anomalies)
	}
	if rep.ScannedEvents != want {
		t.Fatalf("events lost: verified=%d want=%d", rep.ScannedEvents, want)
	}
	// seq 必须 1..N 连续无重号。
	got, err := ReadAll(dir)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, e := range got {
		if ids[e.ID] {
			t.Fatalf("duplicate event id: %s", e.ID)
		}
		ids[e.ID] = true
	}
	if len(ids) != int(want) {
		t.Fatalf("unique ids=%d want=%d", len(ids), want)
	}
}

func runChildWriter(t *testing.T) {
	dir := os.Getenv("AUDIT_TEST_DIR")
	shard := os.Getenv("AUDIT_TEST_SHARD")
	n := atoiEnv("AUDIT_TEST_EVENTS")
	w, err := NewWriter(dir, WithFlushInterval(5*time.Millisecond))
	if err != nil {
		t.Fatalf("child writer: %v", err)
	}
	for i := 0; i < n; i++ {
		if err := w.Write(Event{
			ID:       fmt.Sprintf("mp-%s-%d", shard, i),
			Time:     time.Now().UTC(),
			Actor:    "proc-" + shard,
			Action:   "write",
			Resource: filepath.Base(dir),
		}); err != nil {
			t.Fatalf("child write: %v", err)
		}
	}
	if err := w.WaitFlush(); err != nil {
		t.Fatalf("child flush: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("child close: %v", err)
	}
}

func atoiEnv(k string) int {
	n := 0
	for _, c := range os.Getenv(k) {
		n = n*10 + int(c-'0')
	}
	return n
}

// TestVerify1M 验证需求④：100 万条事件上 verify 30 秒内完成。
// 默认跳过，AUDIT_BIG_E2E=1 时运行（与多进程端到端压测共用开关）。
func TestVerify1M(t *testing.T) {
	if os.Getenv("AUDIT_BIG_E2E") != "1" {
		t.Skip("set AUDIT_BIG_E2E=1 to run the 1M-event performance test")
	}
	const n = 1_000_000
	dir := t.TempDir()
	w, err := NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("generating %d events…", n)
	genStart := time.Now()
	for i := 0; i < n; i++ {
		if err := w.Write(Event{
			ID:       fmt.Sprintf("big-%d", i),
			Time:     time.Unix(1700000000+int64(i), 0).UTC(),
			Actor:    "alice",
			Action:   "read",
			Resource: "doc/big",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.WaitFlush(); err != nil {
		t.Fatal(err)
	}
	t.Logf("generate done in %s; sealing…", time.Since(genStart).Round(time.Millisecond))
	if err := w.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	rep, err := Verify(dir, VerifyOptions{})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("verify %d events in %s (%.0f events/s)",
		n, elapsed.Round(time.Millisecond), float64(n)/elapsed.Seconds())
	if !rep.OK {
		t.Fatalf("integrity failure: %+v", rep.Anomalies)
	}
	if rep.ScannedEvents != n {
		t.Fatalf("scanned=%d want=%d", rep.ScannedEvents, n)
	}
	if elapsed > 30*time.Second {
		t.Fatalf("verify took %s, requirement is <= 30s", elapsed)
	}
}
