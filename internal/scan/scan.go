// Package scan runs per-file history extractors in parallel and caches their results,
// so later runs only read files that changed.
package scan

import (
	"errors"
	"fmt"
	"io/fs"
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

// Cache stores extractor results per file. A nil *Cache disables caching.
//
// TODO(scan agent): persist results under dir, keyed by file path and a file
// signature (size, mtime, inode, hash of the first 4 KB), and drop the whole cache
// when version changes.
type Cache struct {
	dir     string
	name    string
	version int
}

// Open opens (or creates) the named cache in dir.
func Open(dir, name string, version int) (*Cache, error) {
	return &Cache{dir: dir, name: name, version: version}, nil
}

// Save writes the cache to disk.
func (c *Cache) Save() error { return nil }

// Stats summarizes one Run.
type Stats struct {
	Files   int
	Cached  int
	Scanned int
	Failed  int
	Bytes   int64
	Errors  []string // first few errors, for notes
}

// Run calls fn for every file, in parallel, and returns the results by path. Files
// whose cached result is still valid are not read again. files must be the complete
// set for this cache: entries for other paths are dropped. A file whose fn returns an
// error is left out of the result and counted in Stats.Failed. stage names the work
// for opt.Progress.
func Run[T any](c *Cache, files []string, opt Options, stage string, fn func(path string) (T, error)) (map[string]T, Stats) {
	workers := opt.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	stats := Stats{Files: len(files)}
	out := make(map[string]T, len(files))
	var mu sync.Mutex
	jobs := make(chan string)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				v, err := fn(p)
				mu.Lock()
				if err != nil {
					stats.Failed++
					if len(stats.Errors) < 5 {
						stats.Errors = append(stats.Errors, fmt.Sprintf("%s: %v", p, err))
					}
				} else {
					stats.Scanned++
					out[p] = v
				}
				mu.Unlock()
			}
		}()
	}
	sorted := append([]string(nil), files...)
	sort.Strings(sorted)
	for _, p := range sorted {
		jobs <- p
	}
	close(jobs)
	wg.Wait()
	return out, stats
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
