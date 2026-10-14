// Package jsonl reads newline-delimited files whose lines can be very long.
package jsonl

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// ErrStop can be returned by a callback to end iteration early without an error.
var ErrStop = errors.New("jsonl: stop")

// Each calls fn for every line in r, without the trailing newline. The slice is only
// valid during the call. Lines of any length are supported.
func Each(r io.Reader, fn func(line []byte) error) error {
	br := bufio.NewReaderSize(r, 1<<20)
	var long []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			long = append(long, chunk...)
			continue
		}
		line := chunk
		if long != nil {
			long = append(long, chunk...)
			line = long
		}
		if n := len(line); n > 0 && line[n-1] == '\n' {
			line = line[:n-1]
		}
		if len(line) > 0 {
			if ferr := fn(line); ferr != nil {
				if ferr == ErrStop {
					return nil
				}
				return ferr
			}
		}
		long = nil
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// EachFile opens path and calls Each on it. A path ending in .zst is decompressed
// first; Codex compresses older session files this way.
func EachFile(path string, fn func(line []byte) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if !strings.HasSuffix(path, ".zst") {
		return Each(f, fn)
	}
	// One goroutine per decoder: scan already reads many files in parallel.
	d, err := zstd.NewReader(f, zstd.WithDecoderConcurrency(1))
	if err != nil {
		return err
	}
	defer d.Close()
	return Each(d, fn)
}
