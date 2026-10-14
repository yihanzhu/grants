//go:build darwin || linux

package cli

import (
	"syscall"
	"unsafe"
)

// fdIsTerminal asks the kernel whether fd is a terminal. A character-device check
// would also accept /dev/null.
func fdIsTerminal(fd uintptr) bool {
	var t [256]byte // large enough for struct termios on every supported system
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(ioctlGetTermios), uintptr(unsafe.Pointer(&t[0])))
	return e == 0
}
