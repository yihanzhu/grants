// Package edit changes agent config files safely: it edits only the bytes that hold
// the grant, verifies the result by parsing it again, keeps a backup of every file it
// touches, and can undo the last change.
package edit

import "time"

// Change replaces one file's content. Before must equal the file's content when the
// change is applied; otherwise Apply refuses, because the agent changed the file meanwhile.
type Change struct {
	File    string
	Before  []byte
	After   []byte
	GrantID string
	Summary string // one line for the journal, e.g. `remove "Bash(git push:*)" from permissions.allow`
}

// Batch is one Apply call as recorded in the journal.
type Batch struct {
	ID     string      `json:"id"`
	Time   time.Time   `json:"time"`
	Files  []BatchFile `json:"files"`
	Undone bool        `json:"undone,omitempty"`
}

type BatchFile struct {
	File      string `json:"file"`
	Backup    string `json:"backup"`     // copy of the file before the change
	AfterHash string `json:"after_hash"` // sha256 of the content grants wrote
	GrantID   string `json:"grant_id,omitempty"`
	Summary   string `json:"summary,omitempty"`
}
