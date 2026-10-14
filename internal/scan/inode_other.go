//go:build !unix

package scan

import "io/fs"

func inodeOf(fs.FileInfo) uint64 { return 0 }
