//go:build unix

package audit

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive lock on f, or fails at once if someone else holds it.
func lockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}
