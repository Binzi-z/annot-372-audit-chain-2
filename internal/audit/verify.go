package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// 异常类型：覆盖删除、重排、内容修改、截断、整文件丢失、元数据不一致。
const (
	AnomalyRecordHash  = "RECORD_HASH_MISMATCH" // 内容被修改（信封哈希对不上）
	AnomalyPrevHash    = "PREV_HASH_MISMATCH"   // 重排/删除导致 prev 断链
	AnomalySeqGap      = "SEQ_GAP"              // seq 不连续（删除/跳号）
	AnomalyMerkleRoot  = "MERKLE_ROOT_MISMATCH" // 段被整体改写后重算仍与封存值不符
	AnomalyFileHash    = "FILE_HASH_MISMATCH"   // 段文件字节被改动
	AnomalyManifest    = "MANIFEST_MISMATCH"    // manifest 与 SQLite 元数据不一致
	AnomalyMissingFile = "SEGMENT_FILE_MISSING" // 整段文件被删除
	AnomalyPartialTail = "PARTIAL_TAIL"         // 尾部不完整行（崩溃残留/截断）
	AnomalyChainGap    = "CROSS_SEGMENT_GAP"    // 段间链头不接续
	AnomalyDBMismatch  = "SQLITE_METADATA_MISMATCH"
	AnomalyDBMissing   = "SQLITE_METADATA_UNAVAILABLE" // 元数据库缺失/损坏，降级纯磁盘验证
)

// Anomaly 是验证中发现的一个取证点。
type Anomaly struct {
	Type     string `json:"type"`
	Segment  string `json:"segment"`
	Line     int    `json:"line,omitempty"`     // 段内行号（从 1 开始）
	Seq      int64  `json:"seq,omitempty"`      // 涉及的记录 seq
	EventID  string `json:"event_id,omitempty"` // 涉及的事件 ID（若可解析）
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// SegmentReport 是单个段的验证结果。
type SegmentReport struct {
	Segment    string    `json:"segment"`
	Path       string    `json:"path"`
	Kind       string    `json:"kind"`
	StartSeq   int64     `json:"start_seq"`
	EndSeq     int64     `json:"end_seq"`
	Count      int64     `json:"count"`
	HeadHash   string    `json:"head_hash"`
	MerkleRoot string    `json:"merkle_root,omitempty"`
	FileHash   string    `json:"file_hash,omitempty"`
	Anomalies  []Anomaly `json:"anomalies,omitempty"`
	OK         bool      `json:"ok"`
}

// Report 是一次时间窗口验证的总报告。
type Report struct {
	OK            bool            `json:"ok"`
	WindowStart   string          `json:"window_start,omitempty"`
	WindowEnd     string          `json:"window_end,omitempty"`
	Segments      []SegmentReport `json:"segments"`
	TotalEvents   int64           `json:"total_events"`
	ScannedEvents int64           `json:"scanned_events"`
	Anomalies     []Anomaly       `json:"anomalies"`
	// FirstBreach 是链上第一条不可信记录的位置；nil 表示链完整。
	FirstBreach *BreachPoint `json:"first_breach,omitempty"`
	// AffectedRange 是受影响的 seq 闭区间 [From, To]。
	AffectedRange *SeqRange `json:"affected_range,omitempty"`
	DurationMS    int64     `json:"duration_ms"`
}

// BreachPoint 指出第一条被篡改/断链记录的精确位置。
type BreachPoint struct {
	Segment string `json:"segment"`
	Line    int    `json:"line"`
	Seq     int64  `json:"seq"`
	EventID string `json:"event_id,omitempty"`
	Type    string `json:"type"`
}

// SeqRange 是受影响 seq 区间。
type SeqRange struct {
	From int64 `json:"from"`
	To   int64 `json:"to"`
}

// VerifyOptions 指定验证窗口（零值表示全量）。
type VerifyOptions struct {
	Start time.Time // 含，按小时桶对齐
	End   time.Time // 不含
}

// Verify 对时间窗口内的所有段做完整性验证。
// 验证是只读的：不依赖写入进程的内存状态，只信任封存文件 + manifest + SQLite
// 三方互相印证的证据链。
func Verify(base string, opts VerifyOptions) (*Report, error) {
	start := time.Now()
	rep := &Report{OK: true}
	if !opts.Start.IsZero() {
		rep.WindowStart = opts.Start.UTC().Format(time.RFC3339)
	}
	if !opts.End.IsZero() {
		rep.WindowEnd = opts.End.UTC().Format(time.RFC3339)
	}

	rows, dbDown, err := listSegmentsForVerify(base)
	if err != nil {
		return nil, err
	}
	// 也扫描磁盘上的封存/活跃文件，发现 SQLite 里被删掉的段。
	diskBuckets := scanDiskBuckets(base)
	if dbDown {
		rep.OK = false
		rep.Anomalies = append(rep.Anomalies, Anomaly{
			Type:   AnomalyDBMissing,
			Detail: "sqlite metadata unavailable (deleted/corrupted/locked); fell back to disk-only verification",
		})
	}

	wantBuckets := filterWindow(rows, diskBuckets, opts)
	// 按链顺序重放，并把上一段的链头传给下一段：这样即使某段在 SQLite
	// 里的行因 WAL 可见性暂时读不到，也能从磁盘记录 + 前一段链头自洽恢复，
	// 不会误判成从创世重新开始。
	var carryHead string
	var carrySeq int64
	for _, bucket := range wantBuckets {
		sr := verifySegment(base, bucket, rows[bucket], carryHead, carrySeq)
		rep.Segments = append(rep.Segments, sr)
		rep.TotalEvents += sr.Count
		rep.ScannedEvents += sr.Count
		if !sr.OK {
			rep.OK = false
			rep.Anomalies = append(rep.Anomalies, sr.Anomalies...)
		}
		carryHead = sr.HeadHash
		carrySeq = sr.EndSeq
	}

	// 段间连续性：prev/head 必须首尾相接（含被过滤窗口的边界段衔接）。
	checkCrossSegment(rep)

	buildForensics(rep)
	rep.DurationMS = time.Since(start).Milliseconds()
	return rep, nil
}

// listSegmentsForVerify 综合 SQLite 与磁盘清单得到段集合。
// 第二个返回值表示 SQLite 元数据库是否不可用（被删/损坏/锁定/为空库）——
// 这本身是安全事件，调用方应在报告中显式标注，只能降级为纯磁盘验证。
func listSegmentsForVerify(base string) (map[string]*SegmentRow, bool, error) {
	out := map[string]*SegmentRow{}
	// 库文件本身不存在：SQLite 打开时会自动建空库，先据此判定缺失。
	if _, err := os.Stat(dbPath(base)); err != nil {
		return out, true, nil
	}
	m, err := openMetaDB(base)
	if err != nil {
		return out, true, nil
	}
	defer m.close()
	m.checkpoint() // 合并 WAL，确保读到写入进程的最新已提交元数据
	rows, err := m.listSegments()
	if err != nil {
		return out, true, nil
	}
	for _, r := range rows {
		out[r.Bucket] = r
	}
	return out, false, nil
}

func scanDiskBuckets(base string) map[string]string {
	out := map[string]string{}
	for _, kind := range []string{dirSealed, dirActive} {
		entries, err := os.ReadDir(filepath.Join(base, kind))
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if len(name) > 6 && name[len(name)-6:] == ".jsonl" {
				bucket := name[:len(name)-6]
				out[bucket] = kind
			}
		}
	}
	return out
}

func filterWindow(rows map[string]*SegmentRow, disk map[string]string, opts VerifyOptions) []string {
	seen := map[string]bool{}
	var out []string
	add := func(b string) {
		if !seen[b] {
			seen[b] = true
			out = append(out, b)
		}
	}
	for b := range rows {
		add(b)
	}
	for b := range disk {
		add(b)
	}
	sort.Strings(out)
	if opts.Start.IsZero() && opts.End.IsZero() {
		return out
	}
	lo := opts.Start.UTC().Truncate(time.Hour).Format(hourLayout)
	var hi string
	if !opts.End.IsZero() {
		hi = opts.End.UTC().Truncate(time.Hour).Format(hourLayout)
	}
	var kept []string
	for _, b := range out {
		h := bucketHour(b)
		if h >= lo && (hi == "" || h < hi) {
			kept = append(kept, b)
		}
	}
	return kept
}

// verifySegment 重放单个段并做全部对账。
// carryHead/carrySeq 是上一已验证段的链头与末 seq（首段为创世值），
// 用于在 SQLite 行不可见时仍能正确接续链。
func verifySegment(base, bucket string, row *SegmentRow, carryHead string, carrySeq int64) SegmentReport {
	sr := SegmentReport{Segment: bucket, OK: true}
	path, kind := locateSegment(base, bucket)
	sr.Path = path
	sr.Kind = kind

	info, err := os.Stat(path)
	if err != nil {
		sr.OK = false
		sr.Anomalies = append(sr.Anomalies, Anomaly{
			Type: AnomalyMissingFile, Segment: bucket,
			Detail: fmt.Sprintf("segment file missing: %v", err),
		})
		return sr
	}
	_ = info

	// 封存段先对整文件哈希（任何字节级改动都跑不掉）。
	var manifest *Manifest
	if kind == dirSealed {
		if fh, ferr := hashFile(path); ferr == nil {
			sr.FileHash = fh
		}
		manifest, _ = readManifest(base, bucket)
		if manifest != nil && manifest.FileHash != sr.FileHash {
			sr.OK = false
			sr.Anomalies = append(sr.Anomalies, Anomaly{
				Type: AnomalyFileHash, Segment: bucket,
				Expected: manifest.FileHash, Actual: sr.FileHash,
				Detail: "sealed segment bytes differ from manifest",
			})
		}
	}

	// 流式重放：信封哈希、prev 链接、seq 连续性、增量 Merkle。
	// 段首状态优先级：SQLite 行 > manifest > 上一段链头（carry）> 创世。
	st := &activeState{bucket: bucket, headHash: GenesisHash, seq: 0, startSeq: 1}
	switch {
	case row != nil:
		st.headHash = row.PrevHash
		st.seq = row.StartSeq - 1
		st.startSeq = row.StartSeq
	case manifest != nil:
		st.headHash = manifest.PrevHash
		st.seq = manifest.StartSeq - 1
		st.startSeq = manifest.StartSeq
	case carryHead != "":
		// DB 行暂不可见且无 manifest（活跃段）：沿用上一段链头自洽接续。
		st.headHash = carryHead
		st.seq = carrySeq
		st.startSeq = carrySeq + 1
	}
	var (
		lineNo    int
		tailLen   int64
		complete  int64
		firstAnom *Anomaly
		firstLine int
	)
	f, err := os.Open(path)
	if err != nil {
		sr.OK = false
		sr.Anomalies = append(sr.Anomalies, Anomaly{Type: AnomalyMissingFile, Segment: bucket, Detail: err.Error()})
		return sr
	}
	readErr := scanLines(f, func(line []byte) error {
		lineNo++
		a := replayLine(line, st, lineNo)
		if a != nil {
			sr.OK = false
			sr.Anomalies = append(sr.Anomalies, *a)
			if firstAnom == nil {
				firstAnom = a
				firstLine = lineNo
			}
			// 断链后继续扫描以收集全部异常，但链状态不再可信：
			// 用记录自报值推进，尽量定位后续问题。
			st.seq, st.headHash = salvage(line, st)
		}
		complete++
		return nil
	})
	_ = f.Close()
	if readErr != nil {
		sr.OK = false
		sr.Anomalies = append(sr.Anomalies, Anomaly{Type: AnomalyPartialTail, Segment: bucket, Detail: readErr.Error()})
	}
	// 检测无换行的尾部残留。
	if fi, _ := os.Stat(path); fi != nil {
		if sz := fi.Size(); sz > 0 {
			// scanLines 吃掉的是完整行；用最后字节判断是否缺换行。
			if last, _ := readLastByte(path); last >= 0 && last != '\n' {
				tailLen = 1
			}
		}
	}
	if tailLen > 0 {
		sr.OK = false
		sr.Anomalies = append(sr.Anomalies, Anomaly{Type: AnomalyPartialTail, Segment: bucket, Detail: "unterminated tail line (crash remnant or truncation)"})
	}

	sr.StartSeq = st.startSeq
	sr.EndSeq = st.seq
	sr.Count = complete
	sr.HeadHash = st.headHash
	root := st.merkle.root()
	sr.MerkleRoot = toHex(root)

	// 与 manifest 对账。
	if manifest != nil {
		if manifest.MerkleRoot != sr.MerkleRoot && sr.OK {
			sr.OK = false
			sr.Anomalies = append(sr.Anomalies, Anomaly{
				Type: AnomalyMerkleRoot, Segment: bucket,
				Expected: manifest.MerkleRoot, Actual: sr.MerkleRoot,
			})
		}
		if manifest.HeadHash != sr.HeadHash && firstAnom == nil {
			sr.OK = false
			sr.Anomalies = append(sr.Anomalies, Anomaly{
				Type: AnomalyManifest, Segment: bucket,
				Expected: manifest.HeadHash, Actual: sr.HeadHash,
				Detail: "replayed head hash differs from manifest",
			})
		}
		if manifest.Count != sr.Count {
			sr.OK = false
			sr.Anomalies = append(sr.Anomalies, Anomaly{
				Type: AnomalyManifest, Segment: bucket,
				Expected: fmt.Sprintf("%d", manifest.Count),
				Actual:   fmt.Sprintf("%d", sr.Count),
				Detail:   "record count differs (records may have been deleted)",
			})
		}
	}
	// 与 SQLite 对账。
	if row != nil {
		if row.EndSeq != sr.EndSeq || row.HeadHash != sr.HeadHash {
			sr.OK = false
			sr.Anomalies = append(sr.Anomalies, Anomaly{
				Type: AnomalyDBMismatch, Segment: bucket,
				Detail: fmt.Sprintf("sqlite(end=%d,head=%s) vs replayed(end=%d,head=%s)",
					row.EndSeq, row.HeadHash, sr.EndSeq, sr.HeadHash),
			})
		}
		if row.MerkleRoot.Valid && row.MerkleRoot.String != sr.MerkleRoot && sr.OK {
			sr.OK = false
			sr.Anomalies = append(sr.Anomalies, Anomaly{
				Type: AnomalyMerkleRoot, Segment: bucket,
				Expected: row.MerkleRoot.String, Actual: sr.MerkleRoot,
			})
		}
	}
	_ = firstLine
	return sr
}

// replayLine 重放一行，返回第一个异常（nil 表示通过）。
func replayLine(line []byte, st *activeState, lineNo int) *Anomaly {
	var rec Record
	if err := json.Unmarshal(line, &rec); err != nil {
		return &Anomaly{Type: AnomalyRecordHash, Segment: st.bucket, Line: lineNo,
			Detail: "unparseable record: " + err.Error()}
	}
	eventID := extractEventID(rec.Event)
	mk := func(typ, detail, expected, actual string) *Anomaly {
		return &Anomaly{
			Type: typ, Segment: st.bucket, Line: lineNo, Seq: rec.Seq,
			EventID: eventID, Expected: expected, Actual: actual, Detail: detail,
		}
	}
	if rec.Seq != st.seq+1 {
		return mk(AnomalySeqGap,
			fmt.Sprintf("expected seq %d but found %d", st.seq+1, rec.Seq),
			fmt.Sprintf("%d", st.seq+1), fmt.Sprintf("%d", rec.Seq))
	}
	if rec.Prev != st.headHash {
		return mk(AnomalyPrevHash, "prev hash does not chain to previous record",
			st.headHash, rec.Prev)
	}
	want := toHex(ChainHash(rec.Seq, rec.Prev, rec.Event))
	if want != rec.Hash {
		return mk(AnomalyRecordHash, "record hash mismatch; event content was modified",
			want, rec.Hash)
	}
	// 全部通过才把叶子纳入 Merkle——被篡改的行没有资格进树，
	// 这样最终 root 必然与封存 root 不同。
	st.merkle.add(line)
	st.seq = rec.Seq
	st.headHash = rec.Hash
	return nil
}

// salvage 在异常后尽力推进链状态，使后续异常也能被定位。
func salvage(line []byte, st *activeState) (int64, string) {
	var rec Record
	if err := json.Unmarshal(line, &rec); err != nil {
		return st.seq, st.headHash
	}
	return rec.Seq, rec.Hash
}

func extractEventID(raw json.RawMessage) string {
	var e struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &e); err != nil {
		return ""
	}
	return e.ID
}

func locateSegment(base, bucket string) (path, kind string) {
	sealed := sealedPath(base, bucket)
	if _, err := os.Stat(sealed); err == nil {
		return sealed, dirSealed
	}
	return activePath(base, bucket), dirActive
}

func readManifest(base, bucket string) (*Manifest, error) {
	b, err := os.ReadFile(manifestPath(base, bucket))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func readLastByte(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return -1, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.Size() == 0 {
		return -1, err
	}
	buf := make([]byte, 1)
	if _, err := f.ReadAt(buf, fi.Size()-1); err != nil {
		return -1, err
	}
	return int(buf[0]), nil
}

// checkCrossSegment 校验段间链头接续，并发现整段缺失造成的链空洞。
// 判定完全基于实际重放出的段报告，不依赖可能因 WAL 可见性缺失的 SQLite 行。
func checkCrossSegment(rep *Report) {
	var prevSeq int64
	first := true
	for i := range rep.Segments {
		sr := &rep.Segments[i]
		if !first && sr.StartSeq != prevSeq+1 {
			rep.OK = false
			rep.Anomalies = append(rep.Anomalies, Anomaly{
				Type: AnomalyChainGap, Segment: sr.Segment,
				Expected: fmt.Sprintf("start_seq=%d", prevSeq+1),
				Actual:   fmt.Sprintf("start_seq=%d", sr.StartSeq),
				Detail:   "missing segment(s) create a chain hole",
			})
		}
		prevSeq = sr.EndSeq
		first = false
	}
}

// buildForensics 从异常集合推导第一条篡改点与受影响区间。
func buildForensics(rep *Report) {
	if len(rep.Anomalies) == 0 {
		return
	}
	// 第一条异常 = 链上最早不可信位置：按物理位置（段、行号）排序，
	// 重排场景下行号最小的异常才是“第一个被挪动的位置”。
	earliest := rep.Anomalies[0]
	for _, a := range rep.Anomalies[1:] {
		if (a.Segment < earliest.Segment) ||
			(a.Segment == earliest.Segment && a.Line > 0 &&
				(earliest.Line == 0 || a.Line < earliest.Line)) {
			earliest = a
		}
	}
	rep.FirstBreach = &BreachPoint{
		Segment: earliest.Segment, Line: earliest.Line,
		Seq: earliest.Seq, EventID: earliest.EventID, Type: earliest.Type,
	}
	// 受影响区间：从首条异常所在位置到窗口内最后一条记录。
	// 起点优先用异常 seq；seq 缺失（如整文件丢失）时回退为段起始 seq。
	from := earliest.Seq
	if from == 0 {
		for _, sr := range rep.Segments {
			if sr.Segment == earliest.Segment {
				from = sr.StartSeq
				break
			}
		}
	}
	if from == 0 {
		from = 1
	}
	var to int64
	for _, sr := range rep.Segments {
		if sr.EndSeq > to {
			to = sr.EndSeq
		}
	}
	if to < from {
		to = from
	}
	rep.AffectedRange = &SeqRange{From: from, To: to}
}
