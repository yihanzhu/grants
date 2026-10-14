// Package scan runs per-file history extractors in parallel and caches their results,
// so later runs only read files that changed.
package scan

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
)

// Options control a collection run.
type Options struct {
	NoCache  bool                                // ignore and do not write the cache
	Workers  int                                 // 0 means runtime.NumCPU()
	Progress func(stage string, done, total int) // optional; called from worker goroutines
}

// Stats summarizes one Run.
type Stats struct {
	Files   int
	Cached  int
	Scanned int
	Failed  int
	Bytes   int64    // size of the files fn read; cached files add nothing
	Errors  []string // first few errors, for notes
}

// Run calls fn for every file, in parallel, and returns the results by path. A file
// whose cached result is still valid is not read again. files must be the complete
// set for this cache: entries for other paths are dropped. A file whose fn returns an
// error is left out of the result and counted in Stats.Failed. stage names the work
// for opt.Progress.
func Run[T any](c *Cache, files []string, opt Options, stage string, fn func(path string) (T, error)) (map[string]T, Stats) {
	workers := opt.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if opt.NoCache {
		c = nil
	}
	stats := Stats{Files: len(files)}
	out := make(map[string]T, len(files))
	var mu sync.Mutex // guards stats, out and done
	done := 0
	finish := func() { // call with mu held
		done++
		if opt.Progress != nil && (done%100 == 0 || done == len(files)) {
			opt.Progress(stage, done, len(files))
		}
	}

	sorted := append([]string(nil), files...)
	sort.Strings(sorted)
	jobs := make(chan string)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				v, hit, size, err := one(c, p, fn)
				mu.Lock()
				switch {
				case err != nil:
					stats.Failed++
					if len(stats.Errors) < 5 {
						stats.Errors = append(stats.Errors, fmt.Sprintf("%s: %v", p, err))
					}
				case hit:
					stats.Cached++
					out[p] = v
				default:
					stats.Scanned++
					stats.Bytes += size
					out[p] = v
				}
				finish()
				mu.Unlock()
			}
		}()
	}
	for _, p := range sorted {
		jobs <- p
	}
	close(jobs)
	wg.Wait()
	if len(files) == 0 && opt.Progress != nil {
		opt.Progress(stage, 0, 0)
	}
	c.prune(files)
	return out, stats
}

// one returns the result for one file from the cache or from fn.
func one[T any](c *Cache, path string, fn func(string) (T, error)) (v T, hit bool, size int64, err error) {
	if c == nil {
		v, err = fn(path)
		if err == nil {
			size = statSize(path)
		}
		return v, false, size, err
	}
	sig, serr := fileSignature(path)
	if serr != nil {
		c.drop(path)
		return v, false, 0, serr
	}
	if data, ok := c.get(path, sig); ok {
		if gob.NewDecoder(bytes.NewReader(data)).Decode(&v) == nil {
			return v, true, 0, nil
		}
		var zero T
		v = zero // a failed decode may leave partial data
	}
	v, err = fn(path)
	if err != nil {
		c.drop(path)
		var zero T
		return zero, false, 0, err
	}
	var buf bytes.Buffer
	if eerr := gob.NewEncoder(&buf).Encode(v); eerr == nil {
		c.put(path, sig, buf.Bytes())
	} else {
		c.drop(path) // not cacheable; do not keep a stale entry
	}
	return v, false, sig.Size, nil
}

func statSize(path string) int64 {
	if fi, err := os.Stat(path); err == nil {
		return fi.Size()
	}
	return 0
}

// Walk lists regular files under root for which keep returns true. It does not follow
// symlinked folders, and it skips folders it cannot read; their count is returned as
// skipped. A missing root returns no files and no error.
func Walk(root string, keep func(path string) bool) (files []string, skipped int, err error) {
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == root && errors.Is(err, fs.ErrNotExist) {
				return fs.SkipAll
			}
			skipped++
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() && keep(p) {
			files = append(files, p)
		}
		return nil
	})
	return files, skipped, err
}
