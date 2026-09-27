//go:build !(linux || darwin || dragonfly || freebsd || netbsd || openbsd)

package executionlock

import "os"

func openLockFile(string) (*os.File, error) {
	return nil, ErrOperation
}

func tryExclusiveFileLock(*os.File) (bool, error) {
	return false, ErrOperation
}

func unlockFile(*os.File) error {
	return ErrOperation
}
