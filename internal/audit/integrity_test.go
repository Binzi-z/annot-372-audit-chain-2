package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// writeN 写入 n 条事件并 Sync。
func writeN(t *testing.T, w *Writer, n int, prefix string) {
	t.Helper()
	for i := 0; i < n; i++ {
		err := w.Write(Event{
			ID:       fmt.Sprintf("%s-%d", prefix, i),
			Time:     time.Unix(1700000000+int64(i), 0).UTC(),
			Actor:    "alice",
			Action:   "read",
			Resource: fmt.Sprintf("doc/%d", i),
			Extra:    map[string]interface{}{"k": i, "tag": prefix},
		})
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := w.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}
}

func TestHashChainIntact(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	writeN(t, w, 50, "hc")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !rep.OK {
		t.Fatalf("expected intact chain, got findings: %+v", rep.Findings)
	}
	if rep.EventsChecked != 50 {
		t.Fatalf("events checked = %d, want 50", rep.EventsChecked)
	}
}

func TestContentModificationDetected(t *testing.T) {
	dir := t.TempDir()
	w, _ := NewWriter(dir)
	writeN(t, w, 20, "cm")
	w.Close()

	path := singleSegment(t, dir)
	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	// 篡改第 10 行（0-based）的 actor，保持 hash 字段不变。
	var env envelope
	if err := json.Unmarshal([]byte(lines[10]), &env); err != nil {
		t.Fatal(err)
	}
	env.Event.Actor = "attacker"
	env.Hash = mustEncode(env.Hash) // 哈希字段不动（重新序列化仅改 actor）
	patched, _ := json.Marshal(env)
	lines[10] = string(patched)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("expected verification failure for content tamper")
	}
	if rep.AffectedRange == nil || rep.AffectedRange.FirstLine != 11 {
		t.Fatalf("first tampered line = %+v, want line 11", rep.AffectedRange)
	}
	if !hasKind(rep.Findings, TamperContent) {
		t.Fatalf("expected content_modified finding, got %+v", rep.Findings)
	}
}

func TestDeletionDetected(t *testing.T) {
	dir := t.TempDir()
	w, _ := NewWriter(dir)
	writeN(t, w, 20, "dl")
	w.Close()

	path := singleSegment(t, dir)
	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	// 删除中间一行（第 8 行）。
	cut := append([]string{}, lines[:8]...)
	cut = append(cut, lines[9:]...)
	if err := os.WriteFile(path, []byte(strings.Join(cut, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("expected verification failure for deletion")
	}
	if !hasKind(rep.Findings, TamperDeleted) && !hasKind(rep.Findings, TamperReorder) {
		t.Fatalf("expected delete/reorder finding, got %+v", rep.Findings)
	}
	if rep.AffectedRange == nil || rep.AffectedRange.FirstLine != 9 {
		t.Fatalf("expected first break at line 9, got %+v", rep.AffectedRange)
	}
}

func TestReorderDetected(t *testing.T) {
	dir := t.TempDir()
	w, _ := NewWriter(dir)
	writeN(t, w, 20, "ro")
	w.Close()

	path := singleSegment(t, dir)
	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	// 交换相邻两行（保留各自完整信封，仅改变顺序）。
	lines[5], lines[6] = lines[6], lines[5]
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("expected verification failure for reorder")
	}
	if !hasKind(rep.Findings, TamperReorder) && !hasKind(rep.Findings, TamperContent) {
		t.Fatalf("expected reorder/content finding, got %+v", rep.Findings)
	}
}

func TestSealProducesWORMAndMerkle(t *testing.T) {
	dir := t.TempDir()
	w, _ := NewWriter(dir)
	w.now = func() time.Time { return time.Date(2026, 11, 12, 10, 30, 0, 0, time.UTC) }
	writeN(t, w, 30, "se")

	// 把时钟拨到下一个小时并触发封存。
	w.now = func() time.Time { return time.Date(2026, 11, 12, 11, 5, 0, 0, time.UTC) }
	if err := w.Seal(); err != nil {
		t.Fatalf("seal: %v", err)
	}
	writeN(t, w, 5, "se2")
	w.Close()

	sealed, err := listSegments(filepath.Join(dir, sealedDirName))
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) != 1 {
		t.Fatalf("sealed segments = %d, want 1", len(sealed))
	}
	info, err := os.Stat(sealed[0])
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != sealedFilePerm {
		t.Fatalf("sealed perm = %o, want %o (WORM read-only)", info.Mode().Perm(), sealedFilePerm)
	}

	// 全量验证：封存段 Merkle + 跨段链都应通过。
	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("sealed chain should verify, findings: %+v", rep.Findings)
	}
	if rep.Segments != 2 {
		t.Fatalf("segments = %d, want 2", rep.Segments)
	}

	// manifest 与 SQLite 双锚点存在。
	if _, err := readManifest(filepath.Join(dir, sealedDirName), "20261112T10"); err != nil {
		t.Fatalf("manifest missing: %v", err)
	}
}

func TestMultiProcessChainOrder(t *testing.T) {
	dir := t.TempDir()
	const procs = 4
	const perProc = 150

	var wg sync.WaitGroup
	errCh := make(chan error, procs)
	wg.Add(procs)
	for p := 0; p < procs; p++ {
		go func(p int) {
			defer wg.Done()
			// 每个 goroutine 独立 NewWriter，模拟独立进程（独立句柄/状态）。
			w, err := NewWriter(dir)
			if err != nil {
				errCh <- err
				return
			}
			defer w.Close()
			for i := 0; i < perProc; i++ {
				if err := w.Write(Event{
					ID: fmt.Sprintf("p%d-%d", p, i), Actor: "mp", Action: "w", Resource: "r",
				}); err != nil {
					errCh <- err
					return
				}
			}
			if err := w.Sync(); err != nil {
				errCh <- err
			}
		}(p)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("multiprocess write: %v", err)
		}
	}

	got, err := ReadAll(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != procs*perProc {
		t.Fatalf("events = %d, want %d (lost/corrupt under concurrency)", len(got), procs*perProc)
	}

	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("concurrent chain must verify, findings: %+v", rep.Findings)
	}
}

func TestTimeWindowVerify(t *testing.T) {
	dir := t.TempDir()
	w, _ := NewWriter(dir)
	w.now = func() time.Time { return time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC) }
	writeN(t, w, 10, "w1")
	w.now = func() time.Time { return time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC) }
	if err := w.Seal(); err != nil {
		t.Fatal(err)
	}
	writeN(t, w, 10, "w2")
	w.Close()

	// 仅验证 10 点段。
	rep, err := Verify(dir, VerifyOptions{
		From: time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 11, 12, 10, 59, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK || rep.EventsChecked != 10 {
		t.Fatalf("window verify = ok:%v events:%d, want ok true events 10", rep.OK, rep.EventsChecked)
	}
}

// --- helpers ---

func singleSegment(t *testing.T, dir string) string {
	t.Helper()
	active, err := listSegments(filepath.Join(dir, activeDirName))
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 {
		t.Fatalf("active segments = %d, want 1", len(active))
	}
	return active[0]
}

func hasKind(fs []Finding, k TamperKind) bool {
	for _, f := range fs {
		if f.Kind == k {
			return true
		}
	}
	return false
}

// mustEncode 保持字符串原样返回（测试里用于占位，强调不改 hash 字段）。
func mustEncode(s string) string { return s }
