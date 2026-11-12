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

func newTestWriter(t *testing.T, dir string) *Writer {
	t.Helper()
	// 测试用短节拍，WaitFlush 更快收敛。
	w, err := NewWriter(dir, WithFlushInterval(5*time.Millisecond), WithLeaseIdle(5*time.Millisecond))
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	// 显式 defer（LIFO 先于 t.TempDir 的清理执行），保证 Windows 下
	// 文件句柄在目录删除前关闭。
	t.Cleanup(func() {
		_ = w.WaitFlush()
		_ = w.Close()
	})
	return w
}

func writeN(t *testing.T, w *Writer, n int, prefix string) {
	t.Helper()
	for i := 0; i < n; i++ {
		err := w.Write(Event{
			ID:       fmt.Sprintf("%s-%d", prefix, i),
			Time:     time.Unix(1700000000+int64(i), 0).UTC(),
			Actor:    "alice",
			Action:   "read",
			Resource: fmt.Sprintf("doc/%d", i),
		})
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := w.WaitFlush(); err != nil {
		t.Fatalf("wait flush: %v", err)
	}
}

func TestWriteAndRead(t *testing.T) {
	dir := t.TempDir()
	w := newTestWriter(t, dir)
	writeN(t, w, 3, "evt")
	if w.Count() != 3 {
		t.Fatalf("count = %d, want 3", w.Count())
	}

	got, err := ReadAll(dir)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("events = %d, want 3", len(got))
	}
	if got[0].ID != "evt-0" || got[2].Resource != "doc/2" {
		t.Fatalf("unexpected content: %+v", got)
	}

	// 新鲜存储上验证必须通过。
	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !rep.OK {
		t.Fatalf("fresh store should verify OK, anomalies=%+v", rep.Anomalies)
	}
	if rep.ScannedEvents != 3 {
		t.Fatalf("scanned=%d want 3", rep.ScannedEvents)
	}
}

func TestWriteRequiresID(t *testing.T) {
	dir := t.TempDir()
	w := newTestWriter(t, dir)
	if err := w.Write(Event{Actor: "bob", Action: "write"}); err == nil {
		t.Fatal("expected error for empty id, got nil")
	}
}

func TestConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	w := newTestWriter(t, dir)

	const goroutines = 8
	const perG = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				_ = w.Write(Event{
					ID:       fmt.Sprintf("g%d-%d", g, i),
					Actor:    "carol",
					Action:   "update",
					Resource: "doc/x",
				})
			}
		}(g)
	}
	wg.Wait()
	if err := w.WaitFlush(); err != nil {
		t.Fatalf("wait flush: %v", err)
	}

	got, err := ReadAll(dir)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if len(got) != goroutines*perG {
		t.Fatalf("events = %d, want %d (corrupt or lost)", len(got), goroutines*perG)
	}
	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !rep.OK {
		t.Fatalf("concurrent writes should verify OK: %+v", rep.Anomalies)
	}
}

func TestHashChainLinks(t *testing.T) {
	dir := t.TempDir()
	w := newTestWriter(t, dir)
	writeN(t, w, 5, "hc")

	path := w.Path()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("lines=%d want 5", len(lines))
	}
	var prevHash string = GenesisHash
	for i, line := range lines {
		var rec Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if rec.Seq != int64(i+1) {
			t.Fatalf("line %d seq=%d want %d", i, rec.Seq, i+1)
		}
		if rec.Prev != prevHash {
			t.Fatalf("line %d prev not linked", i)
		}
		want := toHex(ChainHash(rec.Seq, rec.Prev, rec.Event))
		if want != rec.Hash {
			t.Fatalf("line %d hash mismatch", i)
		}
		prevHash = rec.Hash
	}
}

func TestMerkleIncrementalMatchesReference(t *testing.T) {
	for n := 0; n <= 200; n++ {
		var mb merkleBuilder
		lines := make([][]byte, n)
		for i := 0; i < n; i++ {
			line := []byte(fmt.Sprintf(`{"v":1,"seq":%d}`, i+1))
			lines[i] = line
			mb.add(line)
		}
		got := mb.root()
		want := merkleRootBruteForce(lines)
		if (got == nil) != (want == nil) || (got != nil && toHex(got) != toHex(want)) {
			t.Fatalf("n=%d merkle mismatch: %x vs %x", n, got, want)
		}
	}
}

func TestSealAndManifest(t *testing.T) {
	dir := t.TempDir()
	w := newTestWriter(t, dir)
	writeN(t, w, 10, "seal")
	if err := w.Seal(); err != nil {
		t.Fatalf("seal: %v", err)
	}

	entries, _ := os.ReadDir(sealedDir(dir))
	if len(entries) != 2 { // .jsonl + .manifest.json
		t.Fatalf("sealed entries=%d want 2: %v", len(entries), entries)
	}
	// 封存文件必须只读。
	var segFile string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".jsonl") {
			segFile = filepath.Join(sealedDir(dir), e.Name())
			if e.Type().Perm()&0o222 != 0 && !isWindowsRO(filepath.Join(sealedDir(dir), e.Name())) {
				t.Fatalf("sealed file not read-only: %v", e.Type().Perm())
			}
		}
	}
	// 尝试写只读段必须失败（WORM 强制）。
	f, err := os.OpenFile(segFile, os.O_WRONLY|os.O_APPEND, 0o644)
	if err == nil {
		if _, werr := f.WriteString("tamper\n"); werr == nil {
			_ = f.Close()
			t.Fatal("write to sealed segment succeeded, WORM not enforced")
		}
		_ = f.Close()
	}

	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !rep.OK {
		t.Fatalf("sealed store should verify OK: %+v", rep.Anomalies)
	}
	for _, sr := range rep.Segments {
		if sr.Kind != dirSealed || sr.MerkleRoot == "" {
			t.Fatalf("segment not sealed properly: %+v", sr)
		}
	}

	// 封存后继续写：新段必须与旧段链头接续。
	writeN(t, w, 4, "post")
	rep2, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatalf("verify after reseal: %v", err)
	}
	if !rep2.OK || rep2.ScannedEvents != 14 {
		t.Fatalf("post-seal chain broken: ok=%v n=%d anomalies=%+v",
			rep2.OK, rep2.ScannedEvents, rep2.Anomalies)
	}
}

func TestTamperContentModification(t *testing.T) {
	dir := t.TempDir()
	w := newTestWriter(t, dir)
	writeN(t, w, 6, "tam")
	if err := w.Seal(); err != nil {
		t.Fatalf("seal: %v", err)
	}

	// 封存文件是只读的；测试里先解除只读再篡改，再恢复只读，
	// 模拟“拿到磁盘权限的攻击者”。
	seg := onlySegment(t, dir, dirSealed)
	makeWritable(t, seg)
	raw, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	var rec Record
	if err := json.Unmarshal([]byte(lines[2]), &rec); err != nil {
		t.Fatal(err)
	}
	rec.Event = json.RawMessage(strings.Replace(string(rec.Event), "doc/2", "doc/EVIL", 1))
	bad, _ := json.Marshal(rec)
	lines[2] = string(bad)
	if err := os.WriteFile(seg, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = setReadOnly(seg)

	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rep.OK {
		t.Fatal("expected verification failure for modified content")
	}
	if rep.FirstBreach == nil || rep.FirstBreach.Seq != 3 {
		t.Fatalf("first breach should point at seq 3: %+v", rep.FirstBreach)
	}
	if rep.AffectedRange == nil || rep.AffectedRange.From != 3 || rep.AffectedRange.To != 6 {
		t.Fatalf("affected range wrong: %+v", rep.AffectedRange)
	}
	if !containsType(rep.Anomalies, AnomalyRecordHash) &&
		!containsType(rep.Anomalies, AnomalyFileHash) &&
		!containsType(rep.Anomalies, AnomalyMerkleRoot) {
		t.Fatalf("expected hash/merkle/file anomaly, got %+v", rep.Anomalies)
	}
}

func TestTamperReorder(t *testing.T) {
	dir := t.TempDir()
	w := newTestWriter(t, dir)
	writeN(t, w, 5, "ord")
	seg := w.Path()
	raw, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("not enough lines: %d", len(lines))
	}
	lines[1], lines[2] = lines[2], lines[1] // 重排第 2、3 行
	if err := os.WriteFile(seg, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("expected failure for reordered records")
	}
	// 重排首先表现为 seq 不连续（PREV_HASH_MISMATCH 通常紧随其后）。
	if !containsType(rep.Anomalies, AnomalySeqGap) &&
		!containsType(rep.Anomalies, AnomalyPrevHash) {
		t.Fatalf("expected seq-gap/prev-hash breach, got %+v", rep.Anomalies)
	}
	if rep.FirstBreach == nil || rep.FirstBreach.Line != 2 {
		t.Fatalf("first breach at wrong physical position: %+v", rep.FirstBreach)
	}
	if rep.AffectedRange == nil {
		t.Fatal("missing affected range")
	}
}

func TestTamperDelete(t *testing.T) {
	dir := t.TempDir()
	w := newTestWriter(t, dir)
	writeN(t, w, 6, "del")
	seg := w.Path()
	raw, _ := os.ReadFile(seg)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	// 删除第 4 行。
	kept := append(append([]string{}, lines[:3]...), lines[4:]...)
	if err := os.WriteFile(seg, []byte(strings.Join(kept, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("expected failure for deleted record")
	}
	// 删除第 4 行后，原第 5 行（seq=5）成为第一个对不上的位置。
	if rep.FirstBreach == nil || rep.FirstBreach.Seq != 5 {
		t.Fatalf("breach should point at seq 5 (first record after the hole): %+v", rep.FirstBreach)
	}
	if !containsType(rep.Anomalies, AnomalySeqGap) {
		t.Fatalf("expected seq gap after deletion: %+v", rep.Anomalies)
	}
}

func TestTamperWholeSegmentDelete(t *testing.T) {
	dir := t.TempDir()
	w := newTestWriter(t, dir)
	writeN(t, w, 4, "a")
	if err := w.Seal(); err != nil {
		t.Fatal(err)
	}
	writeN(t, w, 4, "b")
	if err := w.Seal(); err != nil {
		t.Fatal(err)
	}
	rep0, _ := Verify(dir, VerifyOptions{})
	if !rep0.OK || len(rep0.Segments) != 2 {
		t.Fatalf("setup wrong: %+v", rep0)
	}
	// 删掉第一段的封存文件。
	seg0 := rep0.Segments[0]
	makeWritable(t, seg0.Path)
	if err := os.Remove(seg0.Path); err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK || !containsType(rep.Anomalies, AnomalyMissingFile) {
		t.Fatalf("expected missing-file anomaly: %+v", rep.Anomalies)
	}
}

func TestWindowedVerify(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(time.Date(2026, 11, 12, 4, 30, 0, 0, time.UTC))
	w, err := NewWriter(dir, withClock(clock.now),
		WithFlushInterval(5*time.Millisecond), WithLeaseIdle(5*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	writeN(t, w, 3, "h4")
	clock.advance(time.Hour)
	if err := w.WaitFlush(); err != nil {
		t.Fatal(err)
	}
	writeN(t, w, 2, "h5")
	clock.advance(time.Hour)
	if err := w.WaitFlush(); err != nil {
		t.Fatal(err)
	}
	writeN(t, w, 1, "h6")
	_ = w.WaitFlush()

	rep, err := Verify(dir, VerifyOptions{
		Start: time.Date(2026, 11, 12, 5, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 11, 12, 6, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Segments) != 1 || rep.ScannedEvents != 2 {
		t.Fatalf("window verify should hit only the 05:00 segment: %+v", rep.Segments)
	}
}

func TestCrashRecoveryPartialTail(t *testing.T) {
	dir := t.TempDir()
	w := newTestWriter(t, dir)
	writeN(t, w, 5, "crash")
	seg := w.Path()
	// 模拟崩溃：追加半行且无换行。
	f, err := os.OpenFile(seg, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"v":1,"seq":6,"prev":"abcd`); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	_ = w.Close()

	// 新进程打开：应自动裁剪半行并恢复链。
	w2 := newTestWriter(t, dir)
	writeN(t, w2, 2, "recovered")
	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK || rep.ScannedEvents != 7 {
		t.Fatalf("recovery verify failed: ok=%v n=%d %+v", rep.OK, rep.ScannedEvents, rep.Anomalies)
	}
}

func TestReopenPreservesChain(t *testing.T) {
	dir := t.TempDir()
	w := newTestWriter(t, dir)
	writeN(t, w, 4, "ro")
	_ = w.Close()

	w2 := newTestWriter(t, dir)
	writeN(t, w2, 3, "ro2")
	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK || rep.ScannedEvents != 7 {
		t.Fatalf("reopen chain broken: %+v", rep.Anomalies)
	}
}

func TestHourRolloverSealsAndChains(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(time.Date(2026, 11, 12, 4, 59, 59, 0, time.UTC))
	w, err := NewWriter(dir, withClock(clock.now),
		WithFlushInterval(50*time.Millisecond), WithLeaseIdle(5*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = w.WaitFlush()
		_ = w.Close()
	})

	// 第一批写入旧小时并确保已落盘形成 T04 段。
	for i := 0; i < 100; i++ {
		if err := w.Write(Event{
			ID: fmt.Sprintf("old-%d", i), Time: clock.now(),
			Actor: "a", Action: "r", Resource: "d",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.WaitFlush(); err != nil {
		t.Fatal(err)
	}
	clock.advance(2 * time.Second) // 进入 05:00:01，下一条触发 T04 自动封存
	for i := 0; i < 100; i++ {
		if err := w.Write(Event{
			ID: fmt.Sprintf("new-%d", i), Time: clock.now(),
			Actor: "a", Action: "r", Resource: "d",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.WaitFlush(); err != nil {
		t.Fatal(err)
	}
	if err := w.Seal(); err != nil {
		t.Fatal(err)
	}

	// T04 自动封存 + T05 显式封存，共两个段文件。
	sealed, _ := os.ReadDir(sealedDir(dir))
	var jsonlCount int
	for _, e := range sealed {
		if strings.HasSuffix(e.Name(), ".jsonl") {
			jsonlCount++
		}
	}
	if jsonlCount != 2 {
		t.Fatalf("expected 2 sealed hour segments (T04+T05), got %d", jsonlCount)
	}
	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("cross-hour chain broken: %+v", rep.Anomalies)
	}
	if rep.ScannedEvents != 200 {
		t.Fatalf("events lost across hour rollover: got %d want 200", rep.ScannedEvents)
	}
	// seq 必须全局连续 1..200。
	if rep.Segments[0].StartSeq != 1 || rep.Segments[len(rep.Segments)-1].EndSeq != 200 {
		t.Fatalf("seq not globally contiguous: %+v", rep.Segments)
	}
}

func TestHourRolloverFlushesBufferBeforeSeal(t *testing.T) {
	dir := t.TempDir()
	// 确定性时钟：通过切换门控，让 flusher 在处理第 501 条事件的 appendOne
	// 路径（nowFunc 第二次读取）时观察到整点跳变。先把 1200 条事件全部
	// 入队，再释放 flusher，使排空集中在同一持锁过程中，跨小时必然发生
	// 在批次内部——旧段 buffer 里仍有未 flush 的记录，专门覆盖
	// seal() 必须先 flushBuffer 的不变量。
	base := time.Date(2026, 11, 12, 4, 0, 0, 0, time.UTC)
	gate := make(chan struct{})
	var appendReads int64
	clock := func() time.Time {
		// Write() 路径在入队前调用（gate 未关，返回旧小时用于 Time 字段）；
		// appendOne 在 flusher 内调用，此时 gate 已关闭。
		select {
		case <-gate:
			// flusher 排空阶段。
			n := appendReads
			appendReads++
			if n >= 500 { // 前 500 条落 T04，之后落 T05
				return base.Add(time.Hour)
			}
			return base
		default:
			return base // 入队阶段
		}
	}
	w, err := NewWriter(dir, withClock(clock),
		WithFlushInterval(10*time.Second), WithLeaseIdle(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = w.WaitFlush()
		_ = w.Close()
	})

	// 暂停 flusher：占用锁使其阻塞在 acquire，事件先全部进入缓冲 channel。
	if err := w.lock.Lock(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1200; i++ {
		if err := w.Write(Event{
			ID: fmt.Sprintf("x-%d", i), Actor: "a", Action: "r", Resource: "d",
		}); err != nil {
			t.Fatal(err)
		}
	}
	close(gate)
	if err := w.lock.Unlock(); err != nil { // 释放 flusher，一口气排空 1200 条
		t.Fatal(err)
	}
	if err := w.WaitFlush(); err != nil {
		t.Fatal(err)
	}
	if err := w.Seal(); err != nil {
		t.Fatal(err)
	}

	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("in-batch hour rollover lost/duplicated data: %+v", rep.Anomalies)
	}
	if rep.ScannedEvents != 1200 {
		t.Fatalf("events lost across in-batch rollover: got %d want 1200", rep.ScannedEvents)
	}
	// 必须产生两个非空小时段且 seq 全局连续。
	if len(rep.Segments) != 2 {
		t.Fatalf("expected 2 hour segments, got %d", len(rep.Segments))
	}
	for _, s := range rep.Segments {
		if s.Count == 0 {
			t.Fatalf("segment %s unexpectedly empty", s.Segment)
		}
	}
	if rep.Segments[0].StartSeq != 1 ||
		rep.Segments[1].EndSeq != 1200 ||
		rep.Segments[1].StartSeq != rep.Segments[0].EndSeq+1 {
		t.Fatalf("seq not globally contiguous: %+v", rep.Segments)
	}
}

func TestVerifyMissingMetadataFallback(t *testing.T) {
	dir := t.TempDir()
	w := newTestWriter(t, dir)
	writeN(t, w, 5, "meta")
	_ = w.WaitFlush()
	_ = w.Close()

	// 删掉 SQLite 三件套：验证应降级为纯磁盘模式并显式告警，
	// 链本身仍能基于文件重放通过（封存段还可对 manifest）。
	_ = os.Remove(filepath.Join(dir, dbFile))
	_ = os.Remove(filepath.Join(dir, dbFile+"-wal"))
	_ = os.Remove(filepath.Join(dir, dbFile+"-shm"))
	rep, err := Verify(dir, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !containsType(rep.Anomalies, AnomalyDBMissing) {
		t.Fatalf("expected metadata-unavailable anomaly: %+v", rep.Anomalies)
	}
	if rep.ScannedEvents != 5 {
		t.Fatalf("disk-only replay should still see 5 events, got %d", rep.ScannedEvents)
	}
}

// ---- helpers ----

func onlySegment(t *testing.T, dir, kind string) string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, kind))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".jsonl") {
			return filepath.Join(dir, kind, e.Name())
		}
	}
	t.Fatal("no segment found")
	return ""
}

func containsType(anoms []Anomaly, typ string) bool {
	for _, a := range anoms {
		if a.Type == typ {
			return true
		}
	}
	return false
}

type fakeClock struct{ t time.Time }

func newFakeClock(t time.Time) *fakeClock    { return &fakeClock{t: t} }
func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }
