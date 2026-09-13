//go:build aix || darwin || dragonfly || freebsd || hurd || illumos || ios || linux || netbsd || openbsd || solaris

package migrations

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// fileLock is deliberately backed by an OS advisory lock. The lock file is
// retained after release so a concurrent opener cannot race an inode replace.
type fileLock struct {
	file *os.File
}

func acquireFileLock(path string, create bool) (*fileLock, error) {
	flags := os.O_RDWR
	if create {
		flags |= os.O_CREATE
	}
	file, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, errLockBusy
		}
		return nil, err
	}
	return &fileLock{file: file}, nil
}

func (l *fileLock) release() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	closeErr := l.file.Close()
	l.file = nil
	if err != nil {
		return err
	}
	return closeErr
}
