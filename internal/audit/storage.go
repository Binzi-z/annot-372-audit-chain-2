package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 目录与文件命名。
const (
	dirActive  = "active"
	dirSealed  = "sealed"
	dbFile     = "audit.db"
	lockFile   = "audit.lock"
	hourLayout = "20060102T15" // UTC 小时段，例：20261112T04
)

// Manifest 是封存段的随附清单，与只读段文件一起放入 sealed/。
type Manifest struct {
	Version    int    `json:"version"`
	Segment    string `json:"segment"`
	StartSeq   int64  `json:"start_seq"`
	EndSeq     int64  `json:"end_seq"`
	Count      int64  `json:"count"`
	PrevHash   string `json:"prev_hash"`
	HeadHash   string `json:"head_hash"`
	MerkleRoot string `json:"merkle_root"`
	FileHash   string `json:"file_hash"`
	SealedAt   string `json:"sealed_at"`
}

func hourBucket(t time.Time) string { return t.UTC().Format(hourLayout) }

// bucketHour 返回桶名对应的小时部分（去掉同小时封存产生的 "-N" 后缀）。
func bucketHour(bucket string) string {
	if i := strings.IndexByte(bucket, '-'); i >= 0 {
		return bucket[:i]
	}
	return bucket
}

func activeDir(base string) string { return filepath.Join(base, dirActive) }
func sealedDir(base string) string { return filepath.Join(base, dirSealed) }
func lockPath(base string) string  { return filepath.Join(base, lockFile) }
func dbPath(base string) string    { return filepath.Join(base, dbFile) }

func activePath(base, bucket string) string {
	return filepath.Join(activeDir(base), bucket+".jsonl")
}

func sealedPath(base, bucket string) string {
	return filepath.Join(sealedDir(base), bucket+".jsonl")
}

func manifestPath(base, bucket string) string {
	return filepath.Join(sealedDir(base), bucket+".manifest.json")
}

func ensureDataDirs(base string) error {
	for _, d := range []string{base, activeDir(base), sealedDir(base)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("create dir %s: %w", d, err)
		}
	}
	return nil
}

// setReadOnly 把文件标记为只追加/只读（WORM 封存的文件系统层强制）。
// Unix 下 chmod 0444 是真正的权限位；Windows 下 Go 的 Chmod 会切换
// FILE_ATTRIBUTE_READONLY，写入将被系统拒绝。
func setReadOnly(path string) error {
	if err := os.Chmod(path, 0o444); err != nil {
		return fmt.Errorf("seal (chmod) %s: %w", path, err)
	}
	return nil
}

// sealWORM 把 active 段原子移入 sealed 目录并落只读位。目标已存在时拒绝覆盖。
func sealWORM(base, bucket string) (string, error) {
	src := activePath(base, bucket)
	dst := sealedPath(base, bucket)
	if _, err := os.Stat(dst); err == nil {
		return "", fmt.Errorf("sealed segment already exists: %s", dst)
	}
	if err := os.Rename(src, dst); err != nil {
		return "", fmt.Errorf("move segment to sealed: %w", err)
	}
	if err := setReadOnly(dst); err != nil {
		return "", err
	}
	return dst, nil
}

// writeManifest 先写临时文件再 rename，随后置只读。
func writeManifest(base, bucket string, m *Manifest) (string, error) {
	final := manifestPath(base, bucket)
	if _, err := os.Stat(final); err == nil {
		return "", fmt.Errorf("manifest already exists: %s", final)
	}
	tmp := final + ".tmp"
	buf, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	buf = append(buf, '\n')
	if err := os.WriteFile(tmp, buf, 0o644); err != nil {
		return "", fmt.Errorf("write manifest: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return "", fmt.Errorf("finalize manifest: %w", err)
	}
	if err := setReadOnly(final); err != nil {
		return "", err
	}
	return final, nil
}

// hashFile 计算整段文件内容的 SHA-256（封存与验证两侧共用，保证一致）。
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// segmentFromPath 从路径中解析小时桶名。
func segmentFromPath(p string) string {
	base := filepath.Base(p)
	return strings.TrimSuffix(base, ".jsonl")
}
