package audit

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/flock"
)

// 默认节拍，可在测试中覆盖。
const (
	defaultFlushInterval = 20 * time.Millisecond  // 后台排空周期
	defaultLeaseIdle     = 250 * time.Millisecond // 空闲多久后释放跨进程锁租约
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

// pending 是已通过校验、等待排空的一条记录。
type pending struct {
	eventJSON []byte // 规范序列化的事件原文（seq/prev/hash 在锁内确定）
}

// activeState 是当前活跃小时段的内存视图（仅在持有租约时有意义）。
type activeState struct {
	bucket   string
	file     *os.File
	seq      int64         // 最后一条记录的 seq（空段为 startSeq-1）
	startSeq int64         // 本段第一条 seq
	headHash string        // 最后一条记录的哈希（空段为段首 prev）
	prevHash string        // 段首 prev，即上一段 head
	merkle   merkleBuilder // 增量 Merkle 树
	buf      []byte        // 待合并落盘的记录行（含换行）
}

// Writer 把带哈希链的审计事件追加到按小时分段的 JSONL，
// 支持多进程并发写入且全局 seq 与链序不乱。
//
// 并发模型：
//   - 进程内 sync.Mutex 保护待确认计数；
//   - 跨进程 flock 保护文件与 SQLite；
//   - flusher goroutine 持有“锁租约”，有积压时批量排空，
//     仅在持续空闲 leaseIdle 后才释放锁——正常持续写入时
//     每条事件只承担一次有缓冲 channel 入队的成本，不产生额外系统调用。
type Writer struct {
	base string
	lock *flock.Flock
	meta *metaDB

	in        chan pending
	ctl       chan ctlReq
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error

	flushInterval time.Duration
	leaseIdle     time.Duration
	nowFunc       func() time.Time

	mu         sync.Mutex
	pending    int64  // 已入队但尚未确认落盘的事件数
	confirmed  int64  // 已成功落盘的事件数
	lastBucket string // 最近写入的段桶名（Path 兜底用）
	wake       chan struct{}
}

// ctlReq 是发给 flusher goroutine 的控制消息（目前用于显式封存）。
type ctlReq struct {
	seal bool
	resp chan error
}

// Option 配置 Writer。
type Option func(*Writer)

// WithFlushInterval 覆盖后台排空周期。
func WithFlushInterval(d time.Duration) Option {
	return func(w *Writer) { w.flushInterval = d }
}

// WithLeaseIdle 覆盖锁租约空闲释放时间。
func WithLeaseIdle(d time.Duration) Option {
	return func(w *Writer) { w.leaseIdle = d }
}

// withClock 注入时钟（测试用）。
func withClock(f func() time.Time) Option {
	return func(w *Writer) { w.nowFunc = f }
}

// NewWriter 打开（或恢复）data 目录下的审计存储。
func NewWriter(dir string, opts ...Option) (*Writer, error) {
	if err := ensureDataDirs(dir); err != nil {
		return nil, err
	}
	meta, err := openMetaDB(dir)
	if err != nil {
		return nil, err
	}
	w := &Writer{
		base:          dir,
		lock:          flock.New(lockPath(dir)),
		meta:          meta,
		in:            make(chan pending, 4096),
		ctl:           make(chan ctlReq, 4),
		done:          make(chan struct{}),
		wake:          make(chan struct{}, 1),
		flushInterval: defaultFlushInterval,
		leaseIdle:     defaultLeaseIdle,
		nowFunc:       func() time.Time { return time.Now().UTC() },
	}
	for _, o := range opts {
		o(w)
	}
	go w.flusher()
	return w, nil
}

// Write 校验、序列化事件并入队。返回时事件已进入持久化队列；
// 多进程下的全局链序由 flusher 持有的跨进程锁保证。
func (w *Writer) Write(e Event) error {
	if e.ID == "" {
		return fmt.Errorf("event id is required")
	}
	if e.Time.IsZero() {
		e.Time = w.nowFunc()
	}
	eventJSON, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	w.mu.Lock()
	w.pending++
	w.mu.Unlock()
	w.in <- pending{eventJSON: eventJSON}
	select {
	case w.wake <- struct{}{}:
	default:
	}
	return nil
}

// WaitFlush 阻塞直到所有已入队事件完成落盘（测试与优雅停机用）。
func (w *Writer) WaitFlush() error {
	for {
		w.mu.Lock()
		n := w.pending
		w.mu.Unlock()
		if n == 0 {
			return nil
		}
		select {
		case <-w.done:
			return w.closeErr
		case <-w.wake:
		}
	}
}

// Count 返回本进程已成功落盘的事件数。
func (w *Writer) Count() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.confirmed
}

// Path 返回当前活跃段文件路径（兼容旧接口；无活跃段时返回目录）。
func (w *Writer) Path() string {
	w.mu.Lock()
	cached := w.lastBucket
	w.mu.Unlock()
	if b, err := w.meta.activeBucket(); err == nil && b != "" {
		w.mu.Lock()
		w.lastBucket = b
		w.mu.Unlock()
		return activePath(w.base, b)
	}
	if cached != "" {
		return activePath(w.base, cached)
	}
	return activeDir(w.base)
}

// Close 排空队列、落盘并释放全部资源（当前活跃段保留在 active/，
// 跨小时或显式 Seal 时才进入 sealed/）。
func (w *Writer) Close() error {
	w.closeOnce.Do(func() {
		close(w.in)
		<-w.done
		w.closeErr = w.meta.close()
	})
	return w.closeErr
}

// Seal 显式封存当前活跃段（命令行/停机钩子用）。封存动作在 flusher
// goroutine 内执行，避免与写入并发触碰同一个文件句柄。
func (w *Writer) Seal() error {
	if err := w.WaitFlush(); err != nil {
		return err
	}
	req := ctlReq{seal: true, resp: make(chan error, 1)}
	select {
	case w.ctl <- req:
	case <-w.done:
		return w.closeErr
	}
	select {
	case err := <-req.resp:
		return err
	case <-w.done:
		return w.closeErr
	}
}

// flusher 是唯一触碰文件句柄与跨进程锁的 goroutine。
func (w *Writer) flusher() {
	defer close(w.done)

	var (
		held      bool
		st        *activeState
		idleTimer = time.NewTimer(w.leaseIdle)
	)
	if !idleTimer.Stop() {
		<-idleTimer.C
	}
	defer idleTimer.Stop()
	ticker := time.NewTicker(w.flushInterval)
	defer ticker.Stop()

	// release 落盘当前段、关闭句柄、释放锁并清空内存视图，
	// 同时撤防空闲计时器。句柄必须关闭：Windows 上打开的文件无法删除。
	release := func() {
		if st != nil {
			_ = w.flushBuffer(st)
			_ = w.persistActive(st)
			_ = fsyncFile(st.file)
			_ = st.file.Close()
			st = nil
		}
		if held {
			_ = w.lock.Unlock()
			held = false
		}
		if !idleTimer.Stop() {
			select {
			case <-idleTimer.C:
			default:
			}
		}
	}
	defer release()

	armIdle := func() {
		if !idleTimer.Stop() {
			select {
			case <-idleTimer.C:
			default:
			}
		}
		idleTimer.Reset(w.leaseIdle)
	}

	for {
		select {
		case p, ok := <-w.in:
			if !ok {
				// 通道关闭：排空剩余事件后返回，defer 负责落盘解锁。
				w.drainRemaining(&held, &st)
				return
			}
			if err := w.acquire(&held, &st); err != nil {
				w.confirm(true)
				continue
			}
			if err := w.appendOne(&st, p); err != nil {
				w.confirm(true)
				continue
			}
			w.confirm(false)
			w.drainQueue(&st, 1024)
			// 队列瞬时排空：立即合并落盘，缩短崩溃暴露窗口。
			_ = w.flushBuffer(st)
			armIdle()

		case req := <-w.ctl:
			if req.seal {
				req.resp <- w.doSeal(&held, &st, idleTimer)
			}

		case <-ticker.C:
			if held && st != nil {
				_ = w.flushBuffer(st)
				_ = w.persistActive(st)
				_ = fsyncFile(st.file)
			}

		case <-idleTimer.C:
			// 仅当确实没有积压时才释放租约。
			if held && w.queueEmpty() {
				release()
			}
		}
	}
}

// doSeal 在 flusher goroutine 内封存当前活跃段并清空视图。
func (w *Writer) doSeal(held *bool, stp **activeState, idleTimer *time.Timer) error {
	if err := w.acquire(held, stp); err != nil {
		return err
	}
	st := *stp
	if st == nil {
		return nil
	}
	// 封存路径会关闭文件句柄，先摘掉视图，避免后续误用。
	*stp = nil
	if err := w.seal(st); err != nil {
		// 失败：段仍在 active/，重新打开视图供后续写入重试。
		if s, oerr := w.openActive(); oerr == nil {
			*stp = s
		}
		return err
	}
	// 封存完成后 chain_meta 已无 active bucket，撤防空闲计时并立即释放锁，
	// 让其他进程可以接手新段。
	if !idleTimer.Stop() {
		select {
		case <-idleTimer.C:
		default:
		}
	}
	if err := w.lock.Unlock(); err != nil {
		return err
	}
	*held = false
	return nil
}

// drainRemaining 在 Close 时取出通道里剩余事件并全部落盘。
func (w *Writer) drainRemaining(held *bool, st **activeState) {
	for p := range w.in {
		if err := w.acquire(held, st); err != nil {
			w.confirm(true)
			continue
		}
		if err := w.appendOne(st, p); err != nil {
			w.confirm(true)
			continue
		}
		w.confirm(false)
		w.drainQueue(st, 1024)
	}
}

// drainQueue 非阻塞地排空当前就绪事件（上限 max）。
func (w *Writer) drainQueue(st **activeState, max int) {
	for i := 0; i < max; i++ {
		select {
		case p, ok := <-w.in:
			if !ok {
				return
			}
			if err := w.appendOne(st, p); err != nil {
				w.confirm(true)
				continue
			}
			w.confirm(false)
		default:
			return
		}
	}
}

func (w *Writer) queueEmpty() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.pending == 0
}

// confirm 记账：成功累加 confirmed；无论成败都减少待确认数并唤醒等待者。
func (w *Writer) confirm(failed bool) {
	w.mu.Lock()
	w.pending--
	if !failed {
		w.confirmed++
	}
	w.mu.Unlock()
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// acquire 取得跨进程锁并重建活跃段视图（含对账恢复）。
func (w *Writer) acquire(held *bool, st **activeState) error {
	if *held {
		return nil
	}
	if err := w.lock.Lock(); err != nil {
		return fmt.Errorf("acquire audit lock: %w", err)
	}
	*held = true
	s, err := w.openActive()
	if err != nil {
		_ = w.lock.Unlock()
		*held = false
		return err
	}
	*st = s
	return nil
}

// appendOne 在锁内向当前小时段追加一条记录，必要时滚动到新小时段。
func (w *Writer) appendOne(stp **activeState, p pending) error {
	st := *stp
	hour := hourBucket(w.nowFunc())
	// 跨小时（或当前无活跃段）时封存旧段、开新段。
	if st == nil || bucketHour(st.bucket) != hour {
		if st != nil {
			if err := w.seal(st); err != nil {
				return err
			}
		}
		s, err := w.startActive(hour)
		if err != nil {
			return err
		}
		st = s
		*stp = s
	}

	seq := st.seq + 1
	hash := ChainHash(seq, st.headHash, p.eventJSON)
	rec := Record{
		V:     RecordVersion,
		Seq:   seq,
		Prev:  st.headHash,
		Hash:  toHex(hash),
		Event: p.eventJSON,
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal record: %w", err)
	}
	// 缓冲到段 buffer，由 flushBuffer 合并为一次 Write 系统调用，
	// 显著降低 Windows 下逐行 WriteFile 的 cgocall 成本。
	st.buf = append(st.buf, line...)
	st.buf = append(st.buf, '\n')
	st.merkle.add(line)
	st.seq = seq
	st.headHash = rec.Hash
	w.mu.Lock()
	w.lastBucket = st.bucket
	w.mu.Unlock()
	return nil
}

// flushBuffer 把当前段缓冲区合并写入文件（一次 syscall）。
func (w *Writer) flushBuffer(st *activeState) error {
	if st == nil || len(st.buf) == 0 {
		return nil
	}
	if _, err := st.file.Write(st.buf); err != nil {
		return fmt.Errorf("append batch: %w", err)
	}
	st.buf = st.buf[:0]
	return nil
}

// persistActive 把活跃段链头写回 SQLite（轻量、幂等），并同步全局链头，
// 保证任何时刻崩溃后 chain_meta 都能定位到最新状态。
func (w *Writer) persistActive(st *activeState) error {
	if st == nil || st.seq < st.startSeq {
		return nil
	}
	if err := w.meta.upsertActive(&SegmentRow{
		Bucket:   st.bucket,
		Kind:     KindActive,
		StartSeq: st.startSeq,
		EndSeq:   st.seq,
		Count:    st.seq - st.startSeq + 1,
		PrevHash: st.prevHash,
		HeadHash: st.headHash,
	}); err != nil {
		return err
	}
	return w.meta.setChainMeta(st.headHash, st.seq, st.bucket, w.nowFunc().Unix())
}

// startActive 创建新的小时段；段首 prev 取自全局链头。
// 同一小时内若已封存过（显式 Seal），新段使用 "<hour>-<n>" 后缀桶名，
// 避免与封存文件冲突，也保证 SQLite 段表主键唯一。
func (w *Writer) startActive(hour string) (*activeState, error) {
	bucket := hour
	for n := 2; ; n++ {
		_, sealedErr := os.Stat(sealedPath(w.base, bucket))
		_, activeErr := os.Stat(activePath(w.base, bucket))
		if os.IsNotExist(sealedErr) && os.IsNotExist(activeErr) {
			break
		}
		bucket = fmt.Sprintf("%s-%d", hour, n)
	}
	path := activePath(w.base, bucket)
	headHash, headSeq, err := w.meta.chainHead()
	if err != nil {
		return nil, err
	}
	if headHash == "" {
		headHash = GenesisHash
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open active segment: %w", err)
	}
	return &activeState{
		bucket:   bucket,
		file:     f,
		seq:      headSeq, // 空段：最后 seq = 上一段 endSeq
		startSeq: headSeq + 1,
		headHash: headHash,
		prevHash: headHash,
	}, nil
}

// seal 把活跃段封存：算 Merkle root 与文件哈希、移动到 sealed、置只读，
// 并在 SQLite 中落封存元数据与新全局链头。
func (w *Writer) seal(st *activeState) error {
	if st.seq < st.startSeq {
		// 空段：仅关闭删除，不产生封存记录。
		_ = st.file.Close()
		_ = os.Remove(activePath(w.base, st.bucket))
		return nil
	}
	// 关键：封存前必须把段缓冲区合并落盘，否则跨小时滚动时
	// 已计入 seq/merkle 但还在内存里的记录会丢失，并使 Merkle root
	// 与实际文件内容不一致。
	if err := w.flushBuffer(st); err != nil {
		return err
	}
	if err := w.persistActive(st); err != nil {
		return err
	}
	if err := fsyncFile(st.file); err != nil {
		return err
	}
	if err := st.file.Close(); err != nil {
		return fmt.Errorf("close segment before seal: %w", err)
	}
	root := st.merkle.root()
	if _, err := sealWORM(w.base, st.bucket); err != nil {
		return err
	}
	fileHash, err := hashFile(sealedPath(w.base, st.bucket))
	if err != nil {
		return err
	}
	now := w.nowFunc()
	m := &Manifest{
		Version:    RecordVersion,
		Segment:    st.bucket,
		StartSeq:   st.startSeq,
		EndSeq:     st.seq,
		Count:      st.seq - st.startSeq + 1,
		PrevHash:   st.prevHash,
		HeadHash:   st.headHash,
		MerkleRoot: toHex(root),
		FileHash:   fileHash,
		SealedAt:   now.Format(time.RFC3339Nano),
	}
	if _, err := writeManifest(w.base, st.bucket, m); err != nil {
		return err
	}
	row := &SegmentRow{
		Bucket:     st.bucket,
		Kind:       KindSealed,
		StartSeq:   st.startSeq,
		EndSeq:     st.seq,
		Count:      m.Count,
		PrevHash:   st.prevHash,
		HeadHash:   st.headHash,
		MerkleRoot: sql.NullString{String: toHex(root), Valid: true},
		FileHash:   sql.NullString{String: fileHash, Valid: true},
		SealedAt:   sql.NullTime{Time: now, Valid: true},
	}
	if err := w.meta.markSealed(row); err != nil {
		return err
	}
	if err := w.meta.setChainMeta(st.headHash, st.seq, "", now.Unix()); err != nil {
		return err
	}
	return nil
}

// openActive 取得锁后恢复活跃段视图：
// 以 SQLite 为权威定位段，流式扫描文件对账，识别截断/损坏/外部写入，
// 崩溃残留的不完整尾行会被安全裁剪。
func (w *Writer) openActive() (*activeState, error) {
	bucket, err := w.meta.activeBucket()
	if err != nil {
		return nil, err
	}
	if bucket == "" {
		return w.recoverFromDir()
	}
	row, err := w.meta.segment(bucket)
	if err != nil {
		return nil, err
	}
	if row == nil || row.Kind != KindActive {
		return w.recoverFromDir()
	}
	path := activePath(w.base, bucket)
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("active segment %s missing on disk (run verify for forensic report)", bucket)
		}
		return nil, err
	}
	st := &activeState{
		bucket:   bucket,
		startSeq: row.StartSeq,
		seq:      row.StartSeq - 1,
		prevHash: row.PrevHash,
		headHash: row.PrevHash,
	}
	scanned, tailLen, err := scanActiveSegment(path, st)
	if err != nil {
		return nil, err
	}
	if tailLen > 0 {
		// 崩溃残留的半行：裁剪回最后完整记录之后。
		if err := os.Truncate(path, scanned); err != nil {
			return nil, fmt.Errorf("truncate partial tail: %w", err)
		}
	}
	if st.seq != row.EndSeq || (st.seq >= st.startSeq && st.headHash != row.HeadHash) {
		return nil, fmt.Errorf("active segment %s diverged from sqlite metadata (run verify)", bucket)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	st.file = f
	if err := w.meta.setChainMeta(st.headHash, st.seq, bucket, w.nowFunc().Unix()); err != nil {
		_ = f.Close()
		return nil, err
	}
	_ = info
	return st, nil
}

// scanActiveSegment 流式扫描段文件，校验链并重建 st 的 seq/head/merkle。
// 返回完整行字节数与尾部不完整行长度。
func scanActiveSegment(path string, st *activeState) (completeBytes int64, tailLen int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return 0, 0, err
	}
	r := bufio.NewReaderSize(f, 1<<20)
	var offset int64
	for {
		line, rerr := r.ReadBytes('\n')
		if len(line) > 0 {
			if rerr == nil {
				// 完整行：去掉换行符后校验。
				clean := bytes.TrimRight(line, "\n")
				offset += int64(len(line))
				if verr := verifyRecordLine(clean, st); verr != nil {
					return 0, 0, verr
				}
				continue
			}
			if errors.Is(rerr, io.EOF) {
				// 尾部残留（无换行）：不参与链，留给上层裁剪。
				tailLen = int64(len(line))
				break
			}
			return 0, 0, rerr
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			return 0, 0, rerr
		}
	}
	_ = info
	return offset, tailLen, nil
}

// verifyRecordLine 校验单行记录并把状态推进到 st。
func verifyRecordLine(line []byte, st *activeState) error {
	var rec Record
	if err := json.Unmarshal(line, &rec); err != nil {
		return fmt.Errorf("corrupt record in %s: %w", st.bucket, err)
	}
	if rec.V != RecordVersion {
		return fmt.Errorf("unsupported record version %d in %s", rec.V, st.bucket)
	}
	if rec.Seq != st.seq+1 {
		return fmt.Errorf("seq gap in %s: want %d got %d", st.bucket, st.seq+1, rec.Seq)
	}
	if rec.Prev != st.headHash {
		return fmt.Errorf("hash chain broken in %s at seq %d (prev mismatch)", st.bucket, rec.Seq)
	}
	want := ChainHash(rec.Seq, rec.Prev, rec.Event)
	if toHex(want) != rec.Hash {
		return fmt.Errorf("record hash mismatch in %s at seq %d", st.bucket, rec.Seq)
	}
	st.merkle.add(line)
	st.seq = rec.Seq
	st.headHash = rec.Hash
	return nil
}

// recoverFromDir 在 SQLite 无活跃段登记时扫描 active 目录兜底
// （处理“文件已写但元数据未及更新”的崩溃窗口）。
func (w *Writer) recoverFromDir() (*activeState, error) {
	entries, err := os.ReadDir(activeDir(w.base))
	if err != nil {
		return nil, err
	}
	var found string
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() && strings.HasSuffix(name, ".jsonl") &&
			len(bucketHour(name)) == len(hourLayout) {
			found = name
			break
		}
	}
	if found == "" {
		return nil, nil // 无活跃段，appendOne 时按需创建
	}
	bucket := segmentFromPath(found)
	row, err := w.meta.segment(bucket)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, fmt.Errorf("orphan active segment %s with no sqlite metadata (run verify)", bucket)
	}
	if err := w.meta.setChainMeta(row.HeadHash, row.EndSeq, bucket, w.nowFunc().Unix()); err != nil {
		return nil, err
	}
	return w.openActive()
}
