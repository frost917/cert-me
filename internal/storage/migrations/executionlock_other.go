//go:build !(aix || darwin || dragonfly || freebsd || hurd || illumos || ios || linux || netbsd || openbsd || solaris)

package migrations

import "errors"

type fileLock struct{}

func acquireFileLock(string, bool) (*fileLock, error) {
	return nil, errors.New("OS file locking is unavailable")
}

func (*fileLock) release() error { return nil }
