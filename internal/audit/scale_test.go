package audit

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// TestVerifyMillionEvents 验证需求④：100 万事件的完整性验证在 30 秒内完成。
//
// 默认跳过（写入 100 万条耗时较长）；按需显式开启：
//
//	AUDIT_SCALE_TEST=1 go test ./internal/audit -run TestVerifyMillionEvents -timeout 10m -v
func TestVerifyMillionEvents(t *testing.T) {
	if os.Getenv("AUDIT_SCALE_TEST") == "" {
		t.Skip("set AUDIT_SCALE_TEST=1 to run the 1M-event scale test")
	}
	const n = 1_000_000
	dir := t.TempDir()

	w, err := NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	writeStart := time.Now()
	for i := 0; i < n; i++ {
		if err := w.Write(Event{
			ID:       fmt.Sprintf("scale-%d", i),
			Actor:    "scale",
			Action:   "write",
			Resource: "doc/scale",
			Extra:    map[string]interface{}{"i": i},
		}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := w.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d events in %s", n, time.Since(writeStart).Round(time.Millisecond))

	verifyStart := time.Now()
	rep, err := Verify(dir, VerifyOptions{})
	elapsed := time.Since(verifyStart)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	t.Logf("verify %d events: elapsed=%s segments=%d",
		rep.EventsChecked, elapsed.Round(time.Millisecond), rep.Segments)

	if !rep.OK {
		t.Fatalf("chain must verify, findings: %+v", rep.Findings)
	}
	if rep.EventsChecked != n {
		t.Fatalf("events checked = %d, want %d", rep.EventsChecked, n)
	}
	if elapsed > 30*time.Second {
		t.Fatalf("verify took %s, exceeds 30s budget", elapsed.Round(time.Millisecond))
	}
}
