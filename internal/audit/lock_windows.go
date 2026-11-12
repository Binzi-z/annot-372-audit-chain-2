//go:build windows

package audit

import (
	"errors"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/windows"
)

// errLockBusy 表示非阻塞抢锁时锁正被其他进程持有。
var errLockBusy = errors.New("file lock held by another process")

// fileLock 是跨进程字节范围咨询锁（第 0 字节，长度 1）。
//
//   - tryLock：LockFileEx + FAIL_IMMEDIATELY，无竞争时一次系统调用，给热路径；
//   - lock：阻塞式 LockFileEx，等待竞争结束，给初始化/封存等低频路径。
//
// 同一把锁承担：段文件追加协调 与 封存/恢复临界区互斥。
type fileLock struct {
	f    *os.File
	held bool
	ol   windows.Overlapped
}

func newFileLock(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	return &fileLock{f: f}, nil
}

func (l *fileLock) tryLock() error {
	if l.held {
		return nil
	}
	// LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY
	if err := windows.LockFileEx(windows.Handle(l.f.Fd()), 0x3, 0, 1, 0, &l.ol); err != nil {
		var errno syscall.Errno
		if errors.As(err, &errno) && errno == 33 { // ERROR_LOCK_VIOLATION
			return errLockBusy
		}
		return err
	}
	l.held = true
	runtime.KeepAlive(l.f)
	return nil
}

func (l *fileLock) lock() error {
	if l.held {
		return nil
	}
	// 仅 LOCKFILE_EXCLUSIVE_LOCK => 阻塞直到获得锁。
	if err := windows.LockFileEx(windows.Handle(l.f.Fd()), 0x2, 0, 1, 0, &l.ol); err != nil {
		return err
	}
	l.held = true
	runtime.KeepAlive(l.f)
	return nil
}

func (l *fileLock) unlock() error {
	if !l.held {
		return nil
	}
	if err := windows.UnlockFileEx(windows.Handle(l.f.Fd()), 0, 1, 0, &l.ol); err != nil {
		return err
	}
	l.held = false
	runtime.KeepAlive(l.f)
	return nil
}

func (l *fileLock) close() error {
	_ = l.unlock()
	return l.f.Close()
}
