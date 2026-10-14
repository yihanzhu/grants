package scan

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// headBytes is how much of a file feeds the signature hash. Files can be rewritten in
// place with the same size and mtime, so the head and the inode join size and mtime.
const headBytes = 4096

// signature identifies one version of a file.
type signature struct {
	Size  int64
	MTime int64 // unix nanoseconds
	Inode uint64
	Head  [sha256.Size]byte
}

type entry struct {
	Sig  signature
	Data []byte // gob encoding of the extractor result
}

type cacheFile struct {
	Version int
	Entries map[string]entry
}

// Cache stores extractor results per file, keyed by path and a file signature. A nil
// *Cache disables caching. It is safe for concurrent use.
type Cache struct {
	dir     string
	name    string
	version int

	mu      sync.Mutex
	entries map[string]entry
	dirty   bool
}

func (c *Cache) path() string { return filepath.Join(c.dir, "cache-"+c.name+".gob") }

// Open opens the named cache in dir. A missing, corrupt or older-version file gives
// an empty cache, not an error.
func Open(dir, name string, version int) (*Cache, error) {
	c := &Cache{dir: dir, name: name, version: version, entries: map[string]entry{}}
	data, err := os.ReadFile(c.path())
	if err != nil {
		return c, nil
	}
	var f cacheFile
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&f); err != nil || f.Version != version || f.Entries == nil {
		c.dirty = len(data) > 0 // rewrite over the bad file on the next Save
		return c, nil
	}
	c.entries = f.Entries
	return c, nil
}

// Save writes the cache to disk if it changed since Open or the last Save. The write
// is atomic: a crash leaves the old file.
func (c *Cache) Save() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.dirty {
		return nil
	}
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return fmt.Errorf("scan: create cache folder: %w", err)
	}
	tmp, err := os.CreateTemp(c.dir, "cache-"+c.name+".*.tmp")
	if err != nil {
		return fmt.Errorf("scan: write cache: %w", err)
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("scan: write cache: %w", err)
	}
	if err := gob.NewEncoder(tmp).Encode(cacheFile{Version: c.version, Entries: c.entries}); err != nil {
		tmp.Close()
		return fmt.Errorf("scan: encode cache: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("scan: write cache: %w", err)
	}
	if err := os.Rename(tmp.Name(), c.path()); err != nil {
		return fmt.Errorf("scan: write cache: %w", err)
	}
	c.dirty = false
	return nil
}

func (c *Cache) get(path string, sig signature) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[path]
	if !ok || e.Sig != sig {
		return nil, false
	}
	return e.Data, true // entries are never modified in place, so sharing is safe
}

func (c *Cache) put(path string, sig signature, data []byte) {
	c.mu.Lock()
	c.entries[path] = entry{Sig: sig, Data: data}
	c.dirty = true
	c.mu.Unlock()
}

func (c *Cache) drop(path string) {
	c.mu.Lock()
	if _, ok := c.entries[path]; ok {
		delete(c.entries, path)
		c.dirty = true
	}
	c.mu.Unlock()
}

// prune removes entries for paths that are not in keep.
func (c *Cache) prune(keep []string) {
	if c == nil {
		return
	}
	set := make(map[string]struct{}, len(keep))
	for _, p := range keep {
		set[p] = struct{}{}
	}
	c.mu.Lock()
	for p := range c.entries {
		if _, ok := set[p]; !ok {
			delete(c.entries, p)
			c.dirty = true
		}
	}
	c.mu.Unlock()
}

// fileSignature stats path and hashes its first 4 KB.
func fileSignature(path string) (signature, error) {
	var s signature
	f, err := os.Open(path)
	if err != nil {
		return s, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return s, err
	}
	s.Size = fi.Size()
	s.MTime = fi.ModTime().UnixNano()
	s.Inode = inodeOf(fi)
	buf := make([]byte, headBytes)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return s, err
	}
	s.Head = sha256.Sum256(buf[:n])
	return s, nil
}
