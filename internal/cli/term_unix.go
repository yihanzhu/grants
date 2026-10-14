//go:build unix

package cli

import (
	"syscall"
	"unsafe"
)

// fdWidth asks the terminal for its width with TIOCGWINSZ. It returns 0 when fd is not
// a terminal.
func fdWidth(fd uintptr) int {
	var ws struct{ Row, Col, X, Y uint16 }
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws)))
	if e != 0 {
		return 0
	}
	return int(ws.Col)
}
