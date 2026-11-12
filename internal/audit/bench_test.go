package audit

import (
	"fmt"
	"testing"
	"time"
)

// BenchmarkWrite 单进程写入吞吐。与改造前基线对比，要求下降不超过 10%：
//
//	go test ./internal/audit -bench=BenchmarkWrite -benchtime=3s -run=^$
func BenchmarkWrite(b *testing.B) {
	w, err := NewWriter(b.TempDir(),
		WithFlushInterval(20*time.Millisecond),
		WithLeaseIdle(2*time.Millisecond))
	if err != nil {
		b.Fatalf("new writer: %v", err)
	}
	defer w.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := w.Write(Event{
			ID:       fmt.Sprintf("bench-%d", i),
			Actor:    "bench",
			Action:   "write",
			Resource: "doc/bench",
		}); err != nil {
			b.Fatalf("write: %v", err)
		}
	}
	b.StopTimer()
	if err := w.WaitFlush(); err != nil {
		b.Fatalf("flush: %v", err)
	}
}
