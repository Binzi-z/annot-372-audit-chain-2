package audit

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// segmentRow 是封存段在 SQLite 中的元数据。
type segmentRow struct {
	Hour       string // 段归属小时，UTC，格式 20060102T15
	Path       string // WORM 目录内相对文件名
	Count      int64  // 段内记录数
	StartSeq   int64  // 首条记录全局序号
	EndSeq     int64  // 末条记录全局序号
	MerkleRoot []byte // 封存时计算的 Merkle root
	HeadHash   []byte // 末条记录哈希（封存时刻的链头）
}

// store 封装审计链的 SQLite 元数据库。
//
// 注意：SQLite 只保存"信任锚点"（链头与各封存段摘要），不保存事件正文；
// 事件正文在 WORM 段文件里。数据库自身应受文件系统权限保护。
type store struct {
	db *sql.DB
}

func openStore(path string) (*store, error) {
	// WAL 允许多进程并发：多读单写、写不阻塞读；busy_timeout 让抢锁方等待
	// 而非立即报 SQLITE_BUSY。modernc 驱动对 DSN 用 query 参数形式最可靠。
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// 单连接保证进程内事务串行；多进程并发由 WAL + busy_timeout 协调。
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &store{db: db}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *store) init() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS segments (
    hour         TEXT PRIMARY KEY,
    path         TEXT NOT NULL,
    count        INTEGER NOT NULL,
    start_seq    INTEGER NOT NULL,
    end_seq      INTEGER NOT NULL,
    merkle_root  BLOB NOT NULL,
    head_hash    BLOB NOT NULL,
    sealed_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS chain_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    head_hash   BLOB NOT NULL,   -- 最新一条记录的哈希
    head_seq    INTEGER NOT NULL,-- 最新一条记录的全局序号
    active_hour TEXT NOT NULL,   -- 当前活动段小时
    active_path TEXT NOT NULL    -- 当前活动段文件
);
`)
	return err
}

func (s *store) close() error { return s.db.Close() }

// meta 通用键值（例如算法版本）。
func (s *store) getMeta(key string) ([]byte, error) {
	var v []byte
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return v, err
}

func (s *store) putMeta(key string, val []byte) error {
	_, err := s.db.Exec(`INSERT INTO meta(key,value) VALUES(?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, val)
	return err
}

// loadChain 读取链状态；不存在返回 (nil, 0, "", "")。
func (s *store) loadChain() (head []byte, seq int64, hour, path string, err error) {
	row := s.db.QueryRow(`SELECT head_hash, head_seq, active_hour, active_path FROM chain_state WHERE id = 1`)
	err = row.Scan(&head, &seq, &hour, &path)
	if err == sql.ErrNoRows {
		return nil, 0, "", "", nil
	}
	return
}

func (s *store) saveChain(head []byte, seq int64, hour, path string) error {
	_, err := s.db.Exec(`INSERT INTO chain_state(id, head_hash, head_seq, active_hour, active_path)
		VALUES (1, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
		  head_hash=excluded.head_hash, head_seq=excluded.head_seq,
		  active_hour=excluded.active_hour, active_path=excluded.active_path`,
		head, seq, hour, path)
	return err
}

// insertSegment 写入封存段元数据。同一小时重复封存会报错（幂等由调用方保证）。
func (s *store) insertSegment(r segmentRow, sealedAtUnix int64) error {
	_, err := s.db.Exec(`INSERT INTO segments
		(hour, path, count, start_seq, end_seq, merkle_root, head_hash, sealed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Hour, r.Path, r.Count, r.StartSeq, r.EndSeq, r.MerkleRoot, r.HeadHash, sealedAtUnix)
	return err
}

// allSegments 按小时（即链顺序）返回全部封存段。
func (s *store) allSegments() ([]segmentRow, error) {
	rows, err := s.db.Query(`SELECT hour, path, count, start_seq, end_seq, merkle_root, head_hash
		FROM segments ORDER BY hour ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []segmentRow
	for rows.Next() {
		var r segmentRow
		if err := rows.Scan(&r.Hour, &r.Path, &r.Count, &r.StartSeq, &r.EndSeq, &r.MerkleRoot, &r.HeadHash); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// segmentsBetween 返回小时窗口 [fromHour, toHour] 内的封存段。
func (s *store) segmentsBetween(fromHour, toHour string) ([]segmentRow, error) {
	rows, err := s.db.Query(`SELECT hour, path, count, start_seq, end_seq, merkle_root, head_hash
		FROM segments WHERE hour >= ? AND hour <= ? ORDER BY hour ASC`, fromHour, toHour)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []segmentRow
	for rows.Next() {
		var r segmentRow
		if err := rows.Scan(&r.Hour, &r.Path, &r.Count, &r.StartSeq, &r.EndSeq, &r.MerkleRoot, &r.HeadHash); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
