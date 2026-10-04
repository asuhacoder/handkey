package broker

import (
	"os"
	"syscall"
	"unsafe"
)

func lockFile(f *os.File) error {
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("LockFileEx")
	var overlapped syscall.Overlapped
	r, _, err := proc.Call(f.Fd(), 3, 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
	if r == 0 {
		return err
	}
	return nil
}
func syncDir(string) error { return nil }
