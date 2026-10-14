package edit

// Stubs so other packages compile while the edit package is being written.
// TODO(edit agent): replace every function here with a real implementation in other
// files, then delete this file.

import (
	"errors"
	"time"
)

var errTODO = errors.New("edit: not implemented")

// RemoveArrayString removes every element equal to value from the JSON string array
// at path (object keys), keeping all other bytes as they were. It returns the new
// document and how many elements it removed.
func RemoveArrayString(doc []byte, path []string, value string) ([]byte, int, error) {
	return nil, 0, errTODO
}

// SetBool sets the existing boolean at path (object keys) to v, changing only the
// value bytes.
func SetBool(doc []byte, path []string, v bool) ([]byte, error) { return nil, errTODO }

// TOMLSetString sets key = "value" inside the table named by table (e.g.
// ["projects", "/a/b"] for [projects."/a/b"]), changing only the value bytes. The key
// must already exist in that table.
func TOMLSetString(doc []byte, table []string, key, value string) ([]byte, error) {
	return nil, errTODO
}

// TOMLDeleteTable removes the table header named by table and its body, up to the
// next table header.
func TOMLDeleteTable(doc []byte, table []string) ([]byte, error) { return nil, errTODO }

// WriteFileAtomic writes data to path through a temp file in the same folder, keeping
// the file's mode.
func WriteFileAtomic(path string, data []byte) error { return errTODO }

// Apply backs up every file, checks each still holds Change.Before, writes the new
// content atomically, and records the batch in the journal under stateDir.
func Apply(stateDir string, now time.Time, changes []Change) (Batch, error) {
	return Batch{}, errTODO
}

// Undo restores the latest batch that is not undone yet. It refuses when a file
// changed after grants wrote it, unless force is set.
func Undo(stateDir string, now time.Time, force bool) (Batch, error) { return Batch{}, errTODO }

// Batches returns journal batches, newest first.
func Batches(stateDir string) ([]Batch, error) { return nil, errTODO }
