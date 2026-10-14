package edit

import "errors"

var (
	// ErrNotFound means the path, table or key an edit targets does not exist.
	ErrNotFound = errors.New("edit: not found")
	// ErrChanged means a file no longer holds the content a change was planned
	// against (or, for Undo, the content grants wrote). Nothing was written.
	ErrChanged = errors.New("edit: file changed since it was read")
	// ErrUnsupportedLayout means the target exists but is written in a way the
	// editor does not rewrite safely (an inline table, dotted keys, an array of tables).
	ErrUnsupportedLayout = errors.New("edit: unsupported layout")
	// ErrNothingToUndo means the journal holds no applied batch that is still undoable.
	ErrNothingToUndo = errors.New("edit: nothing to undo")
)
