package audit

import (
	"os"
	"syscall"
	"unsafe"
)

var lockFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("LockFileEx")

// lockFile takes an exclusive lock on f, or fails at once if someone else holds it.
func lockFile(f *os.File) error {
	const exclusiveAndFailAtOnce = 0x2 | 0x1 // LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY
	var overlapped syscall.Overlapped
	ok, _, err := lockFileEx.Call(f.Fd(), exclusiveAndFailAtOnce, 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
	if ok == 0 {
		return err
	}
	return nil
}
