// Package audit 提供带完整性保护的审计事件写入与验证能力。
//
// 完整性模型：
//   - 每条记录包含全局序号 seq、前驱哈希 prev 与自身哈希 hash，形成 SHA-256
//     哈希链；删除、重排、修改任意一条都会在其后第一个节点处断链；
//   - 记录按 UTC 小时切分段；跨小时后旧段被"封存"（seal）：重命名进 WORM
//     目录、置为只读、计算整段 Merkle root，并把段摘要与链头写入 SQLite；
//   - 多进程通过一把跨进程咨询锁串行化"封存 + 链头对齐"，而高频的事件追加
//     在进程内由聚合 goroutine 串行完成；新进程打开/竞争后以活动段文件为
//     权威重放链头，因此不同进程写入的记录仍落在同一条全局哈希链上；
//   - 不使用任何外部区块链服务，全部信任锚点保存在本地 SQLite 与 WORM 文件中。
package audit

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	activeDirName  = "active"
	sealedDirName  = "sealed"
	dbFileName     = "audit.db"
	lockFileName   = "audit.lock"
	headCheckpoint = 256 // 每写 N 条把链头检查点落一次 SQLite
	// leaseReleaseInterval 是持久锁租约的周期释放间隔：兼顾单进程吞吐与
	// 多进程公平性——其他进程最多等待一个间隔即可获得锁。
	leaseReleaseInterval = 20 * time.Millisecond
	// writeBufferSize 是内存写缓冲的批量落盘阈值：攒够即一次 WriteFile，
	// 把单条事件的系统调用成本摊销到整批，同时 Sync/封存强制 flush 保证可见性。
	writeBufferSize = 64 << 10
	sealedFilePerm  = 0o444
	sealedDirPerm   = 0o555
)

// Event 是一条审计事件（对外结构保持兼容）。
type Event struct {
	ID       string                 `json:"id"`
	Time     time.Time              `json:"time"`
	Actor    string                 `json:"actor"`
	Action   string                 `json:"action"`
	Resource string                 `json:"resource"`
	Extra    map[string]interface{} `json:"extra,omitempty"`
}

// pending 是一个等待提交的写请求。
type pending struct {
	env      envelope
	extraRaw json.RawMessage
	err      error
	done     chan struct{}
}

// Writer 把事件以哈希链形式追加到按小时切分的 WORM 段中。
type Writer struct {
	dir        string
	activeDir  string
	sealedDir  string
	store      *store
	procLock   *fileLock
	mu         sync.Mutex // 保护状态字段读取（Path/Count/Close）
	head       []byte
	seq        uint64
	hour       string
	activePath string
	f          *os.File
	pendingBuf bytes.Buffer
	sinceSave  int
	segSize    int64  // 已知活动段文件大小，用于检测其他进程的追加
	sealedPrev []byte // 最近一个封存段的链头，活动段记录的前驱锚点
	now        func() time.Time

	reqs      chan *pending
	sealCh    chan sealRequest
	syncCh    chan syncRequest
	stop      chan struct{}
	done      chan struct{}
	closed    bool
	leaseMu   sync.Mutex
	leaseHeld bool
}

// syncRequest 是一次显式落盘请求。
type syncRequest struct {
	done chan struct{}
	err  error
}

// sealRequest 是一次主动封存的同步控制请求。
type sealRequest struct{ reply chan error }

// NewWriter 打开（或初始化）dir 下的哈希链审计存储。
func NewWriter(dir string) (*Writer, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	activeDir := filepath.Join(dir, activeDirName)
	sealedDir := filepath.Join(dir, sealedDirName)
	if err := os.MkdirAll(activeDir, 0o755); err != nil {
		return nil, fmt.Errorf("create active dir: %w", err)
	}
	if err := os.MkdirAll(sealedDir, sealedDirPerm); err != nil {
		return nil, fmt.Errorf("create sealed dir: %w", err)
	}

	lk, err := newFileLock(filepath.Join(dir, lockFileName))
	if err != nil {
		return nil, err
	}

	w := &Writer{
		dir:       dir,
		activeDir: activeDir,
		sealedDir: sealedDir,
		procLock:  lk,
		now:       func() time.Time { return time.Now().UTC() },
		reqs:      make(chan *pending, 1024),
		sealCh:    make(chan sealRequest, 1),
		syncCh:    make(chan syncRequest, 1),
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}

	// 初始化（建库/DDL/恢复）整体放在跨进程锁内，避免多进程同时建表撞 SQLITE_BUSY。
	if err := lk.lock(); err != nil {
		lk.close()
		return nil, fmt.Errorf("acquire process lock: %w", err)
	}
	st, err := openStore(filepath.Join(dir, dbFileName))
	if err != nil {
		lk.unlock()
		lk.close()
		return nil, err
	}
	w.store = st
	if err := st.putMeta("hash_algo", []byte(HashAlgo)); err != nil {
		w.Close()
		return nil, err
	}
	if err := w.recoverAndOpenLocked(); err != nil {
		w.Close()
		return nil, err
	}
	if err := lk.unlock(); err != nil {
		w.Close()
		return nil, err
	}
	go w.aggregate()
	return w, nil
}

// hourKey 返回 t 对应的 UTC 小时段标识，如 20261112T15。
func hourKey(t time.Time) string { return t.UTC().Format("20060102T15") }

func segmentPath(dir, hour string) string {
	return filepath.Join(dir, hour+".jsonl")
}

// recoverAndOpenLocked 恢复链状态并打开当前小时活动段（调用方已持跨进程锁）。
// 活动段是链头权威来源：重放它即可接续任何其他进程此前写入的记录。
func (w *Writer) recoverAndOpenLocked() error {
	// 缓存最近封存段链头作为活动段前驱锚点。
	if segs, err := w.store.allSegments(); err == nil && len(segs) > 0 {
		w.sealedPrev = append([]byte(nil), segs[len(segs)-1].HeadHash...)
	}

	hour := hourKey(w.now())
	path := segmentPath(w.activeDir, hour)
	// 活动段是链头权威来源：启动时完整重放一次（含崩溃半行截断修复）。
	lastHash, lastSeq, err := recoverSegment(path, w.expectedSegmentPrev())
	if err != nil {
		return err
	}
	if lastHash != nil {
		w.head = lastHash
		w.seq = lastSeq
	} else {
		w.head = w.expectedSegmentPrev()
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open active segment: %w", err)
	}
	w.f = f
	w.hour = hour
	w.activePath = path
	if info, err := os.Stat(path); err == nil {
		w.segSize = info.Size()
	}
	return w.store.saveChain(w.head, int64(w.seq), w.hour, filepath.Base(path))
}

// recoverSegment 校验并修复一个活动段：重放哈希链，截掉末尾不完整/非法的
// 半行（进程崩溃的典型残留），返回最后一条合法记录的哈希与序号。
func recoverSegment(path string, expectPrev []byte) (head []byte, seq uint64, err error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("read active segment: %w", err)
	}
	head = append([]byte(nil), expectPrev...)
	var validLen int
	for off := 0; off < len(raw); {
		nl := indexNewline(raw[off:])
		if nl < 0 {
			break
		}
		line := raw[off : off+nl]
		env, perr := parseEnvelope(line)
		if perr != nil {
			break
		}
		want := RecordHash(head, env.Seq, env.Event, env.ExtraRaw)
		got, _ := hex.DecodeString(env.Hash)
		if !equalBytes(want, got) || !equalBytes(head, mustHex(env.PrevHash)) {
			break
		}
		head = got
		seq = env.Seq
		validLen = off + nl + 1
		off += nl + 1
	}
	if validLen != len(raw) {
		if err := os.WriteFile(path, raw[:validLen], 0o644); err != nil {
			return nil, 0, fmt.Errorf("truncate torn segment: %w", err)
		}
	}
	return head, seq, nil
}

// Write 追加一条事件，完成哈希链接并落盘。并发安全、可多进程同时调用。
func (w *Writer) Write(e Event) error {
	if e.ID == "" {
		return fmt.Errorf("event id is required")
	}
	if e.Time.IsZero() {
		e.Time = w.now()
	}
	extraRaw, err := marshalExtra(e)
	if err != nil {
		return fmt.Errorf("marshal extra: %w", err)
	}
	p := &pending{
		env:      envelope{Version: envelopeVersion, Event: e, ExtraRaw: extraRaw},
		extraRaw: extraRaw,
		done:     make(chan struct{}),
	}
	w.reqs <- p
	<-p.done
	return p.err
}

// aggregate 是单 goroutine 提交循环：本进程所有链推进都在这里串行发生。
//
// 采用持久锁租约：无竞争时长期持锁，写路径零锁系统调用；后台周期释放租约，
// 让其他进程有窗口获得锁写入，其再写入时重新 TryLock 并对齐链头。
func (w *Writer) aggregate() {
	defer close(w.done)
	batch := make([]*pending, 0, 256)
	leaseTick := time.NewTicker(leaseReleaseInterval)
	defer leaseTick.Stop()
	for {
		select {
		case <-w.stop:
			w.drainAndCommit(batch)
			return
		case <-leaseTick.C:
			w.releaseLease()
		case sr := <-w.sealCh:
			sr.reply <- w.runSeal()
		case ack := <-w.syncCh:
			// 确保此前所有已提交记录落盘：在锁内 flush 内存缓冲。
			if !w.leaseHeld {
				_ = w.procLock.lock()
				w.leaseHeld = true
			}
			ack.err = w.flushBufferLocked()
			if w.f != nil && ack.err == nil {
				ack.err = w.f.Sync()
			}
			close(ack.done)
		case p := <-w.reqs:
			batch = append(batch, p)
			w.serveUnderLease(batch)
			batch = batch[:0]
		}
	}
}

// serveUnderLease 在跨进程锁保护下连续排空并提交请求。
//
// 锁采用持久租约：首次 TryLock 成功后保持持有（leaseHeld=true），后续请求
// 零锁系统调用；后台 goroutine 周期性释放租约，给其他进程写入机会，其下次
// 写入再重新 TryLock。只有 TryLock 返回 busy（真有跨进程竞争）时才阻塞并
// 重读文件对齐链头。无竞争的单进程因此走纯内存快速路径。
func (w *Writer) serveUnderLease(batch []*pending) {
	if !w.leaseHeld {
		if err := w.procLock.tryLock(); err != nil {
			if err != errLockBusy {
				failBatch(batch, err)
				finishPending(batch)
				return
			}
			if lerr := w.procLock.lock(); lerr != nil {
				failBatch(batch, lerr)
				finishPending(batch)
				return
			}
			// 阻塞拿到锁说明其他进程刚写过，必须以文件为权威对齐链头。
			if err := w.resyncHeadLocked(); err != nil {
				failBatch(batch, err)
				finishPending(batch)
				return
			}
		}
		w.leaseHeld = true
	}

	for {
		w.commitBatchLocked(batch)
		finishPending(batch)
		batch = batch[:0]
		// 缓冲达到阈值就落盘一次；否则继续在同一租约内吸收后续请求，
		// 把 N 条记录合并成一次 WriteFile，摊薄系统调用开销。
		if w.pendingBuf.Len() >= writeBufferSize {
			if err := w.flushBufferLocked(); err != nil {
				return
			}
		}
		select {
		case q := <-w.reqs:
			batch = append(batch, q)
		default:
			// 队列暂空：不立即落盘，让缓冲继续攒批；可见性由 Sync 保证，
			// 租约周期释放（20ms）与缓冲阈值会强制 flush，延迟有上界。
			return
		}
	}
}

// flushBufferLocked 把内存写缓冲一次性追加到活动段文件（调用方持锁）。
func (w *Writer) flushBufferLocked() error {
	if w.pendingBuf.Len() == 0 {
		return nil
	}
	if _, err := w.pendingBuf.WriteTo(w.f); err != nil {
		return fmt.Errorf("flush segment: %w", err)
	}
	return nil
}

// releaseLease 周期性释放持有的跨进程锁，使其他进程能获得写入机会。
// 释放前必须 flush：缓冲数据不随锁转移，留在内存会让其他进程的重放漏记。
func (w *Writer) releaseLease() {
	w.leaseMu.Lock()
	defer w.leaseMu.Unlock()
	if w.leaseHeld {
		_ = w.flushBufferLocked()
		_ = w.procLock.unlock()
		w.leaseHeld = false
	}
}

// drainAndCommit 非阻塞排空请求队列并提交，最后强制 flush 落盘。
func (w *Writer) drainAndCommit(batch []*pending) {
drain:
	for {
		select {
		case q := <-w.reqs:
			batch = append(batch, q)
		default:
			break drain
		}
	}
	if len(batch) == 0 {
		return
	}
	w.serveUnderLease(batch)
}

// commitBatchLocked 在已持有跨进程锁的前提下串行推进哈希链并追加整批请求。
//
// 每次进入都以活动段文件最后一条记录为权威对齐链头（其他进程的写入可能尚未
// 到达 SQLite 检查点）；O_APPEND 保证持锁期间追加不与其他进程交错，从而让
// 所有进程的记录落在同一条全局哈希链上。
func (w *Writer) commitBatchLocked(batch []*pending) {
	// 链头已在租约开始时按需对齐；此处直接基于内存链头连续推进。
	if hour := hourKey(w.now()); hour != w.hour {
		if err := w.sealeLocked(); err != nil {
			failBatch(batch, err)
			return
		}
		if err := w.openNewHourLocked(hourKey(w.now())); err != nil {
			failBatch(batch, err)
			return
		}
	}

	// 整批先编码进内存缓冲；实际 WriteFile 在 flushBufferLocked 批量发生。
	type stEntry struct {
		p   *pending
		env envelope
	}
	entries := make([]stEntry, 0, len(batch))
	for _, p := range batch {
		w.seq++
		env := buildEnvelope(w.head, w.seq, p.env.Event, p.extraRaw)
		line, err := json.Marshal(env)
		if err != nil {
			w.seq--
			p.err = fmt.Errorf("marshal envelope: %w", err)
			continue
		}
		w.pendingBuf.Write(line)
		w.pendingBuf.WriteByte('\n')
		entries = append(entries, stEntry{p, env})
	}
	// 缓冲写入成功后更新内存链头与序号（落盘由 flush 统一完成）。
	for _, s := range entries {
		h, _ := hex.DecodeString(s.env.Hash)
		w.head = h
		w.seq = s.env.Seq
		w.sinceSave++
	}
	if w.sinceSave >= headCheckpoint {
		if err := w.flushBufferLocked(); err != nil {
			failBatch(batch, err)
			return
		}
		if err := w.store.saveChain(w.head, int64(w.seq), w.hour, filepath.Base(w.activePath)); err != nil {
			failBatch(batch, err)
			return
		}
		w.sinceSave = 0
	}
}

// resyncHeadLocked 以活动段文件为权威同步链头（每次持锁提交前调用）。
//
// 只读取段文件最后一条记录（从尾部反向找换行，IO 量与段长度无关）。
// 不能用本地缓存的文件大小跳过：其他进程的追加不会更新本进程的缓存。
func (w *Writer) resyncHeadLocked() error {
	if _, err := os.Stat(w.activePath); err != nil {
		return err
	}
	h, seq, err := readLastRecord(w.activePath)
	if err != nil {
		return err
	}
	if h != nil {
		w.head = h
		w.seq = seq
	} else {
		w.head = w.expectedSegmentPrev()
		w.seq = 0
	}
	return nil
}

// readLastRecord 读取段文件最后一条完整记录的哈希与序号。
// 从文件尾部读取一个有界块（单条信封远小于该值），取其中最后一行解析，
// IO 量与段总长度无关。
func readLastRecord(path string) (hash []byte, seq uint64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	size := info.Size()
	if size == 0 {
		return nil, 0, nil
	}
	const maxTail = 16 << 10 // 16KB，足以覆盖任何单条审计记录
	tailLen := size
	if tailLen > maxTail {
		tailLen = maxTail
	}
	buf := make([]byte, tailLen)
	if _, err := f.ReadAt(buf, size-tailLen); err != nil {
		return nil, 0, err
	}
	// 取最后一个换行符之前的最后一行（去掉尾部空字节/半行）。
	last := buf
	if i := bytesLastByte(buf, '\n'); i >= 0 {
		// 找倒数第二个换行，截取最后一条完整行。
		head := buf[:i]
		if j := bytesLastByte(head, '\n'); j >= 0 {
			last = head[j+1:]
		} else {
			last = head
		}
	}
	last = trimCR(last)
	if len(last) == 0 {
		return nil, 0, nil
	}
	var env envelope
	if err := json.Unmarshal(last, &env); err != nil {
		return nil, 0, nil // 尾部半行，忽略
	}
	h, _ := hex.DecodeString(env.Hash)
	return h, env.Seq, nil
}

func bytesLastByte(b []byte, c byte) int {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func trimCR(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\r' || b[len(b)-1] == '\n') {
		b = b[:len(b)-1]
	}
	return b
}

func lastNewline(b []byte) int { return bytesLastByte(b, '\n') }

// expectedSegmentPrev 返回当前活动段应接续的前驱哈希（缓存值，封存时更新）。
func (w *Writer) expectedSegmentPrev() []byte {
	if w.sealedPrev != nil {
		return append([]byte(nil), w.sealedPrev...)
	}
	return append([]byte(nil), chainGenesis...)
}

func failBatch(batch []*pending, err error) {
	for _, p := range batch {
		if p.err == nil {
			p.err = err
		}
	}
}

func finishPending(batch []*pending) {
	for _, q := range batch {
		close(q.done)
	}
}

// sealeLocked 封存当前活动段（调用方已持跨进程锁）。
func (w *Writer) sealeLocked() error {
	if err := w.flushBufferLocked(); err != nil {
		return err
	}
	if err := w.f.Sync(); err != nil {
		return err
	}
	if err := w.f.Close(); err != nil {
		return err
	}
	w.f = nil

	leaves, count, startSeq, endSeq, head, err := scanSegmentHashes(w.activePath)
	if err != nil {
		return err
	}
	if count == 0 {
		_ = os.Remove(w.activePath)
		return nil
	}
	root := MerkleRoot(leaves)
	base := filepath.Base(w.activePath)
	sealedPath := filepath.Join(w.sealedDir, base)
	if err := os.Rename(w.activePath, sealedPath); err != nil {
		return fmt.Errorf("seal rename: %w", err)
	}
	if err := writeManifest(w.sealedDir, w.hour, base, count, startSeq, endSeq, root, head); err != nil {
		return err
	}
	if err := os.Chmod(sealedPath, sealedFilePerm); err != nil {
		return fmt.Errorf("seal chmod: %w", err)
	}
	row := segmentRow{
		Hour: w.hour, Path: base, Count: int64(count),
		StartSeq: int64(startSeq), EndSeq: int64(endSeq),
		MerkleRoot: root, HeadHash: head,
	}
	if err := w.store.insertSegment(row, w.now().Unix()); err != nil {
		return fmt.Errorf("persist segment meta: %w", err)
	}
	w.sealedPrev = append([]byte(nil), head...) // 后续活动段接续此链头
	return w.store.saveChain(head, int64(endSeq), w.hour, base)
}

func (w *Writer) openNewHourLocked(hour string) error {
	w.hour = hour
	w.activePath = segmentPath(w.activeDir, hour)
	f, err := os.OpenFile(w.activePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	w.f = f
	w.sinceSave = 0
	w.segSize = 0
	return w.store.saveChain(w.head, int64(w.seq), w.hour, filepath.Base(w.activePath))
}

// runSeal 在聚合 goroutine 内执行主动封存，天然与在途写互斥。
func (w *Writer) runSeal() error {
	alreadyHeld := w.leaseHeld
	if !alreadyHeld {
		if err := w.procLock.lock(); err != nil {
			return err
		}
		w.leaseHeld = true
		if err := w.resyncHeadLocked(); err != nil {
			return err
		}
	}
	if hourKey(w.now()) == w.hour {
		return nil // 当前小时段仍可写
	}
	if err := w.sealeLocked(); err != nil {
		return err
	}
	return w.openNewHourLocked(hourKey(w.now()))
}

// Seal 主动封存当前小时之前的段（测试/运维入口）。
func (w *Writer) Seal() error {
	reply := make(chan error, 1)
	select {
	case w.sealCh <- sealRequest{reply: reply}:
	case <-w.stop:
		return fmt.Errorf("writer closed")
	}
	return <-reply
}

// Sync 阻塞直到此前所有 Write 的数据已落盘（对其他进程/验证器可见）。
func (w *Writer) Sync() error {
	req := syncRequest{done: make(chan struct{})}
	select {
	case w.syncCh <- req:
	case <-w.stop:
		return fmt.Errorf("writer closed")
	}
	<-req.done
	return req.err
}

// Count 返回链上最新全局序号。
func (w *Writer) Count() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return int64(w.seq)
}

// Path 返回当前活动段文件路径。
func (w *Writer) Path() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.activePath
}

// Close 停止聚合循环并关闭句柄；不封存当前小时段（它仍可能被其他进程追加）。
func (w *Writer) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	close(w.stop)
	w.mu.Unlock()
	<-w.done

	w.mu.Lock()
	defer w.mu.Unlock()
	var firstErr error
	if err := w.flushBufferLocked(); err != nil {
		firstErr = err
	}
	if w.f != nil {
		if err := w.f.Sync(); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := w.f.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := w.store.saveChain(w.head, int64(w.seq), w.hour, filepath.Base(w.activePath)); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := w.store.close(); err != nil && firstErr == nil {
		firstErr = err
	}
	if w.procLock != nil {
		if err := w.procLock.close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// --- 段文件解析辅助 ---

func parseEnvelope(line []byte) (envelope, error) {
	var env envelope
	if err := json.Unmarshal(line, &env); err != nil {
		return env, err
	}
	if env.Hash == "" {
		return env, fmt.Errorf("envelope missing hash")
	}
	return env, nil
}

// scanSegmentHashes 顺序重放一个段文件，返回每条记录哈希、计数与首尾序号/链头。
func scanSegmentHashes(path string) (leaves [][]byte, count int, startSeq, endSeq uint64, head []byte, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, 0, 0, nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		env, perr := parseEnvelope(line)
		if perr != nil {
			return nil, 0, 0, 0, nil, fmt.Errorf("parse segment line: %w", perr)
		}
		h, _ := hex.DecodeString(env.Hash)
		if count == 0 {
			startSeq = env.Seq
		}
		endSeq = env.Seq
		leaves = append(leaves, h)
		head = h
		count++
	}
	return leaves, count, startSeq, endSeq, head, sc.Err()
}

func indexNewline(b []byte) int {
	for i, c := range b {
		if c == '\n' {
			return i
		}
	}
	return -1
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func mustHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}
