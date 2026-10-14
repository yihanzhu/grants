//go:build !darwin && !linux

package cli

// fdIsTerminal is false on systems grants does not build for. Output stays plain.
func fdIsTerminal(uintptr) bool { return false }
