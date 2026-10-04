//go:build !windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func disableCoreDumps() error {
	return syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
}
func protectedPath(path string) error {
	for {
		info, e := os.Lstat(path)
		if e != nil {
			return errors.New("cannot inspect broker op path")
		}
		if info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("op and its parent directories must not be symlinks or group/world-writable; install a dedicated copy")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
			return errors.New("op and its parents must be owned by root or the broker user")
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}
