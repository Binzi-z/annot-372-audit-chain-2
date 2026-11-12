//go:build !windows

package audit

import (
	"errors"
	"os"
	"syscall"
)

// errLockBusy 表示非阻塞抢锁时锁正被其他进程持有。
var errLockBusy = errors.New("file lock held by another process")

// fileLock 是跨进程咨询锁，底层为 POSIX flock(2)。
type fileLock struct {
	f    *os.File
	held bool
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
	if err := syscall.Flock(int(l.f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return errLockBusy
		}
		return err
	}
	l.held = true
	return nil
}

func (l *fileLock) lock() error {
	if l.held {
		return nil
	}
	if err := syscall.Flock(int(l.f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	l.held = true
	return nil
}

func (l *fileLock) unlock() error {
	if !l.held {
		return nil
	}
	if err := syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN); err != nil {
		return err
	}
	l.held = false
	return nil
}

func (l *fileLock) close() error {
	_ = l.unlock()
	return l.f.Close()
}
