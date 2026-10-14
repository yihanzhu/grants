//go:build !unix

package cli

func fdWidth(uintptr) int { return 0 }
