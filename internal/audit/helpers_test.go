package audit

import (
	"os"
	"runtime"
	"testing"
)

// makeWritable 解除封存文件的只读位，供篡改测试模拟“有磁盘权限的攻击者”。
func makeWritable(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod writable %s: %v", path, err)
	}
}

// isWindowsRO 判断 Windows 只读属性是否生效（Unix 下 chmod 位已足够，恒真）。
func isWindowsRO(path string) bool {
	if runtime.GOOS != "windows" {
		return true
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode()&0o222 == 0
}
