package audit

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// TamperKind 标识完整性问题的类型。
type TamperKind string

const (
	TamperContent   TamperKind = "content_modified" // 记录正文被修改，重算哈希与链上哈希不符
	TamperReorder   TamperKind = "reordered"        // 记录顺序被改变（前驱不匹配）
	TamperDeleted   TamperKind = "deleted"          // 记录被删除（序号断号/前驱不匹配）
	TamperMerkle    TamperKind = "merkle_mismatch"  // 封存段重算 Merkle root 与锚点不符
	TamperManifest  TamperKind = "manifest_mismatch"
	TamperTruncated TamperKind = "truncated_tail" // 段尾部存在无法解析的半行
)

// Finding 是一次验证发现的具体问题（取证报告条目）。
type Finding struct {
	Kind       TamperKind `json:"kind"`
	Segment    string     `json:"segment"`
	LineNumber int        `json:"line_number"` // 从 1 开始，段内行号
	GlobalSeq  uint64     `json:"global_seq"`  // 问题记录自身序号（可知时）
	EventID    string     `json:"event_id,omitempty"`
	Detail     string     `json:"detail"`
}

// SegmentReport 是单个段的验证结果。
type SegmentReport struct {
	Segment    string   `json:"segment"`
	Sealed     bool     `json:"sealed"`
	Count      int      `json:"count"`
	StartSeq   uint64   `json:"start_seq"`
	EndSeq     uint64   `json:"end_seq"`
	MerkleOK   bool     `json:"merkle_ok"`
	ChainOK    bool     `json:"chain_ok"`
	FirstBreak *Finding `json:"first_break,omitempty"`
}

// Report 是时间窗口完整性验证的总报告。
type Report struct {
	OK             bool            `json:"ok"`
	From           string          `json:"from"`
	To             string          `json:"to"`
	Segments       int             `json:"segments_checked"`
	EventsChecked  int             `json:"events_checked"`
	ElapsedMS      int64           `json:"elapsed_ms"`
	Findings       []Finding       `json:"findings"`
	SegmentReports []SegmentReport `json:"segment_reports"`
	// AffectedRange 是从第一处断点起、链信任不再成立的区间（取证重点）。
	AffectedRange *AffectedRange `json:"affected_range,omitempty"`
}

// AffectedRange 指出第一处被篡改记录及之后所有不可信记录。
type AffectedRange struct {
	FirstSegment string `json:"first_segment"`
	FirstLine    int    `json:"first_line"`
	FirstSeq     uint64 `json:"first_seq"`
	LastSegment  string `json:"last_segment"`
	LastSeq      uint64 `json:"last_seq"`
	Reason       string `json:"reason"`
}

// VerifyOptions 控制验证窗口。零值表示验证全部数据。
type VerifyOptions struct {
	From time.Time
	To   time.Time
}

// Verify 对指定时间窗口做完整性验证。
//
// 验证依据（不需要任何在线服务）：
//  1. 每条记录重算 RecordHash，与信封内 hash 比较 -> 识别内容修改；
//  2. 逐条比对 prev 与上一条 hash、检查 seq 连续 -> 识别删除与重排；
//  3. 封存段重算 Merkle root，与 SQLite + 侧车 manifest 双锚点比对；
//  4. 跨段链接：本段首记录的 prev 必须等于上一段末记录 hash。
func Verify(dir string, opts VerifyOptions) (*Report, error) {
	start := time.Now()
	rep := &Report{OK: true, From: "begin", To: "end"}
	if !opts.From.IsZero() {
		rep.From = opts.From.UTC().Format(time.RFC3339)
	}
	if !opts.To.IsZero() {
		rep.To = opts.To.UTC().Format(time.RFC3339)
	}

	st, err := openStore(filepath.Join(dir, dbFileName))
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	defer st.close()

	sealedRows, err := st.allSegments()
	if err != nil {
		return nil, err
	}
	fromHour, toHour := windowHours(opts)
	if fromHour != "" {
		sealedRows, err = st.segmentsBetween(fromHour, toHour)
		if err != nil {
			return nil, err
		}
	}

	// 构建待扫描段列表：封存段 + 活动段（若落在窗口内）。
	type scanItem struct {
		path   string
		hour   string
		sealed bool
		row    *segmentRow
	}
	var items []scanItem
	for i := range sealedRows {
		items = append(items, scanItem{
			path:   filepath.Join(dir, sealedDirName, sealedRows[i].Path),
			hour:   sealedRows[i].Hour,
			sealed: true,
			row:    &sealedRows[i],
		})
	}
	head, _, activeHour, activeBase, err := st.loadChain()
	if err != nil {
		return nil, err
	}
	_ = head
	if activeBase != "" && (fromHour == "" || (activeHour >= fromHour && activeHour <= toHour)) {
		items = append(items, scanItem{
			path:   filepath.Join(dir, activeDirName, activeBase),
			hour:   activeHour,
			sealed: false,
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].hour < items[j].hour })

	// expectedPrev 跨段延续；创世段从全零开始。
	expectedPrev := append([]byte(nil), chainGenesis...)
	var firstBreak *Finding
	var lastItemHour string
	var lastSeq uint64

	for _, it := range items {
		sr, err := verifySegment(it, expectedPrev, rep)
		if err != nil {
			return nil, err
		}
		rep.SegmentReports = append(rep.SegmentReports, sr)
		rep.Segments++
		rep.EventsChecked += sr.Count
		if sr.FirstBreak != nil && firstBreak == nil {
			firstBreak = sr.FirstBreak
		}
		// 用本段末哈希接续下一段（即便断链，也继续扫描以圈定全部受影响区间）。
		if h, s, ok := segmentTail(it.path); ok {
			expectedPrev = h
			lastSeq = s
		}
		lastItemHour = it.hour
	}

	if firstBreak != nil {
		rep.OK = false
		rep.AffectedRange = &AffectedRange{
			FirstSegment: firstBreak.Segment,
			FirstLine:    firstBreak.LineNumber,
			FirstSeq:     firstBreak.GlobalSeq,
			LastSegment:  lastItemHour,
			LastSeq:      lastSeq,
			Reason: fmt.Sprintf("链信任自第 %d 行（seq=%d，%s）起失效，其后所有记录均不可独立信任",
				firstBreak.LineNumber, firstBreak.GlobalSeq, firstBreak.Kind),
		}
	}
	rep.ElapsedMS = time.Since(start).Milliseconds()
	return rep, nil
}

func windowHours(opts VerifyOptions) (from, to string) {
	if opts.From.IsZero() && opts.To.IsZero() {
		return "", ""
	}
	from = "00000000T00"
	to = "99999999T99"
	if !opts.From.IsZero() {
		from = hourKey(opts.From)
	}
	if !opts.To.IsZero() {
		to = hourKey(opts.To)
	}
	return from, to
}

// verifySegment 验证单个段并把发现追加进总报告，返回段报告。
func verifySegment(it struct {
	path   string
	hour   string
	sealed bool
	row    *segmentRow
}, expectedPrev []byte, rep *Report) (SegmentReport, error) {
	sr := SegmentReport{Segment: filepath.Base(it.path), Sealed: it.sealed, MerkleOK: true, ChainOK: true}
	f, err := os.Open(it.path)
	if err != nil {
		if os.IsNotExist(err) {
			sr.ChainOK = false
			fn := &Finding{Kind: TamperDeleted, Segment: sr.Segment, LineNumber: 0,
				Detail: "段文件缺失，整段记录疑似被删除"}
			sr.FirstBreak = fn
			rep.Findings = append(rep.Findings, *fn)
			return sr, nil
		}
		return sr, err
	}
	defer f.Close()

	var leaves [][]byte
	prev := expectedPrev
	var prevSeq uint64
	havePrev := false
	lineNo := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		lineNo++
		raw := sc.Bytes()
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		var env envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			fn := &Finding{Kind: TamperTruncated, Segment: sr.Segment, LineNumber: lineNo,
				Detail: "记录无法解析（半行/损坏）: " + err.Error()}
			addFirst(&sr, fn)
			rep.Findings = append(rep.Findings, *fn)
			break
		}
		if sr.Count == 0 {
			sr.StartSeq = env.Seq
		}
		sr.EndSeq = env.Seq
		sr.Count++

		storedHash := mustHex(env.Hash)
		storedPrev := mustHex(env.PrevHash)
		// selfConsistent：用记录自身声明的 prev 重算，是否等于其自身 hash。
		selfHash := RecordHash(storedPrev, env.Seq, env.Event, env.ExtraRaw)
		selfConsistent := equalBytes(selfHash, storedHash)
		prevMismatch := !equalBytes(storedPrev, prev)

		var fn *Finding
		switch {
		case prevMismatch && selfConsistent:
			// 记录本身未被改动，但它声明的前驱接不上当前链 => 删除或重排。
			// 序号大于"当前应有的下一个序号"说明中间缺记录，判删除；否则判重排。
			if (havePrev && env.Seq > prevSeq+1) || (!havePrev && env.Seq > 1) {
				fn = &Finding{Kind: TamperDeleted, Segment: sr.Segment, LineNumber: lineNo,
					GlobalSeq: env.Seq, EventID: env.Event.ID,
					Detail: fmt.Sprintf("序号断号/记录缺失：上一条 seq=%d，下一条应为 %d，实际为 seq=%d",
						prevSeq, prevSeq+1, env.Seq)}
			} else {
				fn = &Finding{Kind: TamperReorder, Segment: sr.Segment, LineNumber: lineNo,
					GlobalSeq: env.Seq, EventID: env.Event.ID,
					Detail: fmt.Sprintf("前驱哈希不匹配（顺序被改变）：期望 %s，记录声明 %s",
						hex.EncodeToString(prev), env.PrevHash)}
			}
		case !selfConsistent:
			// 用记录自身声明的 prev 都重算不出它的 hash => 正文/hash 被篡改。
			fn = &Finding{Kind: TamperContent, Segment: sr.Segment, LineNumber: lineNo,
				GlobalSeq: env.Seq, EventID: env.Event.ID,
				Detail: fmt.Sprintf("记录哈希不匹配（内容被修改）：按其自身前驱重算 %s，记录声明 %s",
					hex.EncodeToString(selfHash), env.Hash)}
		}
		if fn != nil {
			addFirst(&sr, fn)
			rep.Findings = append(rep.Findings, *fn)
		}
		leaves = append(leaves, storedHash)
		prev = storedHash
		prevSeq = env.Seq
		havePrev = true
	}
	if err := sc.Err(); err != nil {
		return sr, err
	}

	if it.sealed && it.row != nil {
		root := MerkleRoot(leaves)
		if !equalBytes(root, it.row.MerkleRoot) {
			sr.MerkleOK = false
			fn := &Finding{Kind: TamperMerkle, Segment: sr.Segment,
				Detail: fmt.Sprintf("Merkle root 不匹配：锚点 %s，重算 %s",
					hex.EncodeToString(it.row.MerkleRoot), hex.EncodeToString(root))}
			addFirst(&sr, fn)
			rep.Findings = append(rep.Findings, *fn)
		}
		if int64(sr.Count) != it.row.Count {
			fn := &Finding{Kind: TamperDeleted, Segment: sr.Segment,
				Detail: fmt.Sprintf("记录数与封存锚点不符：锚点 %d，实际 %d", it.row.Count, sr.Count)}
			addFirst(&sr, fn)
			rep.Findings = append(rep.Findings, *fn)
		}
		// 侧车 manifest 交叉校验。
		if m, err := readManifest(filepath.Dir(it.path), it.hour); err == nil {
			if m.MerkleRoot != hex.EncodeToString(it.row.MerkleRoot) ||
				m.HeadHash != hex.EncodeToString(it.row.HeadHash) || m.Count != int(it.row.Count) {
				fn := &Finding{Kind: TamperManifest, Segment: sr.Segment,
					Detail: "manifest 与 SQLite 锚点不一致"}
				addFirst(&sr, fn)
				rep.Findings = append(rep.Findings, *fn)
			}
		}
	}
	return sr, nil
}

func addFirst(sr *SegmentReport, fn *Finding) {
	sr.ChainOK = false
	if sr.FirstBreak == nil {
		sr.FirstBreak = fn
	}
}

// segmentTail 返回段内最后一条可解析记录的哈希与序号，用于跨段接续。
func segmentTail(path string) ([]byte, uint64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, false
	}
	defer f.Close()
	var head []byte
	var seq uint64
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		var env envelope
		if json.Unmarshal(sc.Bytes(), &env) != nil {
			continue
		}
		head = mustHex(env.Hash)
		seq = env.Seq
	}
	return head, seq, head != nil
}
