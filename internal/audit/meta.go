package audit

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // 纯 Go SQLite 驱动，CGO_ENABLED=0 也可编译
)

// SegmentKind 区分活跃段与封存段。
type SegmentKind string

const (
	KindActive SegmentKind = "active"
	KindSealed SegmentKind = "sealed"
)

// SegmentRow 是 segments 表的一行。
type SegmentRow struct {
	Bucket     string
	Kind       SegmentKind
	StartSeq   int64
	EndSeq     int64
	Count      int64
	PrevHash   string
	HeadHash   string
	MerkleRoot sql.NullString // 活跃段封存前为 NULL
	FileHash   sql.NullString
	SealedAt   sql.NullTime
}

// metaDB 封装 SQLite 元数据库。所有写入调用方都已持有跨进程文件锁，
// 因此这里不需要额外的库内并发控制。
type metaDB struct {
	db *sql.DB
}

func openMetaDB(base string) (*metaDB, error) {
	// _txlock=immediate 让写事务立即加锁，避免 SQLITE_BUSY 重试竞态；
	// WAL 允许验证（只读）与写入并发进行。
	dsn := "file:" + dbPath(base) + "?_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// 元数据量很小，单连接即可，顺带消除 modernc 多连接下的锁竞争。
	db.SetMaxOpenConns(1)
	m := &metaDB{db: db}
	if err := m.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return m, nil
}

func (m *metaDB) init() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS segments(
			bucket      TEXT PRIMARY KEY,
			kind        TEXT NOT NULL,
			start_seq   INTEGER NOT NULL,
			end_seq     INTEGER NOT NULL,
			count       INTEGER NOT NULL,
			prev_hash   TEXT NOT NULL,
			head_hash   TEXT NOT NULL,
			merkle_root TEXT,
			file_hash   TEXT,
			sealed_at   INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS chain_meta(
			id           INTEGER PRIMARY KEY CHECK (id = 1),
			head_hash    TEXT NOT NULL,
			head_seq     INTEGER NOT NULL,
			active_bucket TEXT NOT NULL,
			updated_at   INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_segments_seq ON segments(start_seq, end_seq)`,
	}
	// 多进程首次并发初始化时，另一进程可能正持有写锁，
	// busy_timeout 对部分 DDL 路径不重试，这里做显式退避。
	return withBusyRetry(func() error {
		for _, s := range stmts {
			if _, err := m.db.Exec(s); err != nil {
				return fmt.Errorf("init schema: %w", err)
			}
		}
		return nil
	})
}

// withBusyRetry 在 SQLITE_BUSY/LOCKED 时做有限次指数退避重试。
func withBusyRetry(fn func() error) error {
	const attempts = 6
	delay := 5 * time.Millisecond
	var err error
	for i := 0; i < attempts; i++ {
		if err = fn(); err == nil {
			return nil
		}
		if !isBusyErr(err) {
			return err
		}
		time.Sleep(delay)
		delay *= 2
	}
	return err
}

func isBusyErr(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "SQLITE_BUSY") || strings.Contains(msg, "database is locked") ||
		strings.Contains(msg, "SQLITE_LOCKED")
}

func (m *metaDB) close() error { return m.db.Close() }

// checkpoint 尝试把 WAL 合并回主库，确保随后打开的只读连接能看到
// 最新已提交事务。PASSIVE 模式不阻塞写入者，失败可安全忽略。
func (m *metaDB) checkpoint() {
	_, _ = m.db.Exec(`PRAGMA wal_checkpoint(PASSIVE)`)
}

// upsertActive 插入或更新活跃段的链头信息（每批排空调用一次）。
func (m *metaDB) upsertActive(r *SegmentRow) error {
	_, err := m.db.Exec(`
		INSERT INTO segments(bucket, kind, start_seq, end_seq, count, prev_hash, head_hash)
		VALUES(?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(bucket) DO UPDATE SET
			kind=excluded.kind, end_seq=excluded.end_seq,
			count=excluded.count, head_hash=excluded.head_hash`,
		r.Bucket, string(r.Kind), r.StartSeq, r.EndSeq, r.Count, r.PrevHash, r.HeadHash)
	return err
}

// markSealed 把段标记为封存并补齐 Merkle root 等封存字段。
func (m *metaDB) markSealed(r *SegmentRow) error {
	res, err := m.db.Exec(`
		UPDATE segments SET kind=?, end_seq=?, count=?, head_hash=?,
			merkle_root=?, file_hash=?, sealed_at=?
		WHERE bucket=?`,
		string(KindSealed), r.EndSeq, r.Count, r.HeadHash,
		r.MerkleRoot, r.FileHash, r.SealedAt.Time.Unix(), r.Bucket)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("segment %s missing in sqlite while sealing", r.Bucket)
	}
	return nil
}

// setChainMeta 维护全局链头（单例行）。
func (m *metaDB) setChainMeta(headHash string, headSeq int64, activeBucket string, unixNow int64) error {
	_, err := m.db.Exec(`
		INSERT INTO chain_meta(id, head_hash, head_seq, active_bucket, updated_at)
		VALUES(1, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			head_hash=excluded.head_hash, head_seq=excluded.head_seq,
			active_bucket=excluded.active_bucket, updated_at=excluded.updated_at`,
		headHash, headSeq, activeBucket, unixNow)
	return err
}

// activeBucket 返回当前活跃段桶名（chain_meta 单行）。
func (m *metaDB) activeBucket() (string, error) {
	var b string
	err := m.db.QueryRow(`SELECT active_bucket FROM chain_meta WHERE id = 1`).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return b, err
}

// segment 按桶名读取段元数据。
func (m *metaDB) segment(bucket string) (*SegmentRow, error) {
	row := &SegmentRow{}
	var kind string
	var merkle, fileHash sql.NullString
	var sealedAt sql.NullInt64
	err := m.db.QueryRow(`
		SELECT bucket, kind, start_seq, end_seq, count, prev_hash, head_hash,
		       merkle_root, file_hash, sealed_at
		FROM segments WHERE bucket = ?`, bucket).
		Scan(&row.Bucket, &kind, &row.StartSeq, &row.EndSeq, &row.Count,
			&row.PrevHash, &row.HeadHash, &merkle, &fileHash, &sealedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	row.Kind = SegmentKind(kind)
	row.MerkleRoot = merkle
	row.FileHash = fileHash
	if sealedAt.Valid {
		row.SealedAt = sql.NullTime{Time: unixTime(sealedAt.Int64), Valid: true}
	}
	return row, nil
}

// listSegments 按链顺序返回全部段。
func (m *metaDB) listSegments() ([]*SegmentRow, error) {
	rows, err := m.db.Query(`
		SELECT bucket, kind, start_seq, end_seq, count, prev_hash, head_hash,
		       merkle_root, file_hash, sealed_at
		FROM segments ORDER BY start_seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*SegmentRow
	for rows.Next() {
		r := &SegmentRow{}
		var kind string
		var merkle, fileHash sql.NullString
		var sealedAt sql.NullInt64
		if err := rows.Scan(&r.Bucket, &kind, &r.StartSeq, &r.EndSeq, &r.Count,
			&r.PrevHash, &r.HeadHash, &merkle, &fileHash, &sealedAt); err != nil {
			return nil, err
		}
		r.Kind = SegmentKind(kind)
		r.MerkleRoot = merkle
		r.FileHash = fileHash
		if sealedAt.Valid {
			r.SealedAt = sql.NullTime{Time: unixTime(sealedAt.Int64), Valid: true}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// chainHead 返回 (headHash, headSeq)；无记录时返回 ("", 0, nil)。
func (m *metaDB) chainHead() (string, int64, error) {
	var hash string
	var seq int64
	err := m.db.QueryRow(`SELECT head_hash, head_seq FROM chain_meta WHERE id = 1`).Scan(&hash, &seq)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, nil
	}
	return hash, seq, err
}
