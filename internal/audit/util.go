package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"time"
)

// scanLines 逐行回调；单行上限 4MiB，足够容纳带 Extra 的审计事件。
// 行尾的 '\n' 不包含在回调参数里（与 bytes.Split 语义一致）。
func scanLines(r io.Reader, fn func(line []byte) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		if err := fn(sc.Bytes()); err != nil {
			return err
		}
	}
	return sc.Err()
}

// fsyncFile 刷盘并返回错误，屏蔽不同平台的细微差异。
func fsyncFile(f *os.File) error { return f.Sync() }

// hexHash 计算 data 的 SHA-256 并返回小写十六进制。
func hexHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// unixTime 把秒级 Unix 时间戳转成 UTC time.Time。
func unixTime(sec int64) time.Time {
	return time.Unix(sec, 0).UTC()
}
