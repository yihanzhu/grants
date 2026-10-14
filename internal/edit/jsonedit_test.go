package edit

import (
	"errors"
	"strings"
	"testing"
)

func TestRemoveArrayString(t *testing.T) {
	allow := []string{"permissions", "allow"}
	tests := []struct {
		name    string
		doc     string
		path    []string
		value   string
		want    string
		wantN   int
		wantErr error
		anyErr  bool
	}{
		{
			name: "inline middle", path: allow, value: "b",
			doc:   `{"permissions":{"allow":["a","b","c"]}}`,
			want:  `{"permissions":{"allow":["a","c"]}}`,
			wantN: 1,
		},
		{
			name: "inline first", path: allow, value: "a",
			doc:   `{"permissions":{"allow":["a", "b", "c"]}}`,
			want:  `{"permissions":{"allow":["b", "c"]}}`,
			wantN: 1,
		},
		{
			name: "inline last", path: allow, value: "c",
			doc:   `{"permissions":{"allow":["a", "b", "c"]}}`,
			want:  `{"permissions":{"allow":["a", "b"]}}`,
			wantN: 1,
		},
		{
			name: "only element inline", path: allow, value: "a",
			doc:   `{"permissions":{"allow":[ "a" ]}}`,
			want:  `{"permissions":{"allow":[]}}`,
			wantN: 1,
		},
		{
			name: "only element multi-line", path: allow, value: "a",
			doc:   "{\n  \"permissions\": {\n    \"allow\": [\n      \"a\"\n    ]\n  }\n}\n",
			want:  "{\n  \"permissions\": {\n    \"allow\": []\n  }\n}\n",
			wantN: 1,
		},
		{
			name: "multi-line first", path: allow, value: "a",
			doc:   "{\n  \"permissions\": {\n    \"allow\": [\n      \"a\",\n      \"b\"\n    ]\n  }\n}\n",
			want:  "{\n  \"permissions\": {\n    \"allow\": [\n      \"b\"\n    ]\n  }\n}\n",
			wantN: 1,
		},
		{
			name: "multi-line middle", path: allow, value: "b",
			doc:   "{\n  \"permissions\": {\n    \"allow\": [\n      \"a\",\n      \"b\",\n      \"c\"\n    ]\n  }\n}\n",
			want:  "{\n  \"permissions\": {\n    \"allow\": [\n      \"a\",\n      \"c\"\n    ]\n  }\n}\n",
			wantN: 1,
		},
		{
			name: "multi-line last", path: allow, value: "c",
			doc:   "{\n  \"permissions\": {\n    \"allow\": [\n      \"a\",\n      \"c\"\n    ]\n  }\n}\n",
			want:  "{\n  \"permissions\": {\n    \"allow\": [\n      \"a\"\n    ]\n  }\n}\n",
			wantN: 1,
		},
		{
			name: "duplicates", path: allow, value: "a",
			doc:   `{"permissions":{"allow":["a","b","a","a","c"]}}`,
			want:  `{"permissions":{"allow":["b","c"]}}`,
			wantN: 3,
		},
		{
			name: "all duplicates", path: allow, value: "a",
			doc:   `{"permissions":{"allow":["a","a"]}}`,
			want:  `{"permissions":{"allow":[]}}`,
			wantN: 2,
		},
		{
			name: "value absent", path: allow, value: "z",
			doc:   `{"permissions":{"allow":["a"]}}`,
			want:  `{"permissions":{"allow":["a"]}}`,
			wantN: 0,
		},
		{
			name: "escaped string matches decoded value", path: allow, value: `Bash(echo "hi":*)`,
			doc:   `{"permissions":{"allow":["Bash(echo \"hi\":*)","x"]}}`,
			want:  `{"permissions":{"allow":["x"]}}`,
			wantN: 1,
		},
		{
			name: "unicode escape matches literal unicode", path: allow, value: "café",
			doc:   `{"permissions":{"allow":["café","x"]}}`,
			want:  `{"permissions":{"allow":["x"]}}`,
			wantN: 1,
		},
		{
			name: "literal unicode matches", path: allow, value: "日本語",
			doc:   `{"permissions":{"allow":["日本語","x"]}}`,
			want:  `{"permissions":{"allow":["x"]}}`,
			wantN: 1,
		},
		{
			name: "surrogate pair", path: allow, value: "😀",
			doc:   `{"permissions":{"allow":["😀","x"]}}`,
			want:  `{"permissions":{"allow":["x"]}}`,
			wantN: 1,
		},
		{
			name: "brackets and commas inside strings", path: allow, value: "b",
			doc:   `{"permissions":{"allow":["a,]\"","b","]"]}}`,
			want:  `{"permissions":{"allow":["a,]\"","]"]}}`,
			wantN: 1,
		},
		{
			name: "key with slash", path: []string{"projects", "/home/u/work/app", "allowedTools"}, value: "Bash(ls)",
			doc:   `{"projects":{"/home/u/work/app":{"allowedTools":["Bash(ls)","Read"]},"/other":{"allowedTools":["Bash(ls)"]}}}`,
			want:  `{"projects":{"/home/u/work/app":{"allowedTools":["Read"]},"/other":{"allowedTools":["Bash(ls)"]}}}`,
			wantN: 1,
		},
		{
			name: "key with quote and space", path: []string{"projects", `/home/u/my "app"`, "allowedTools"}, value: "x",
			doc:   `{"projects":{"/home/u/my \"app\"":{"allowedTools":["x","y"]}}}`,
			want:  `{"projects":{"/home/u/my \"app\"":{"allowedTools":["y"]}}}`,
			wantN: 1,
		},
		{
			name: "key with unicode escape", path: []string{"ké", "a"}, value: "x",
			doc:   `{"ké":{"a":["x","y"]}}`,
			want:  `{"ké":{"a":["y"]}}`,
			wantN: 1,
		},
		{
			name: "mixed element types stay", path: []string{"a"}, value: "x",
			doc:   `{"a":[1,"x",null,{"b":"x"},["x"],true]}`,
			want:  `{"a":[1,null,{"b":"x"},["x"],true]}`,
			wantN: 1,
		},
		{
			name: "other keys and numbers untouched", path: []string{"a"}, value: "x",
			doc:   "{\"n\": 1.50e+2,\n \"a\": [ \"x\" ,\"y\" ],\n \"z\": {\"a\": [\"x\"]}}",
			want:  "{\"n\": 1.50e+2,\n \"a\": [ \"y\" ],\n \"z\": {\"a\": [\"x\"]}}",
			wantN: 1,
		},
		{
			name: "tabs and CRLF", path: []string{"a"}, value: "x",
			doc:   "{\r\n\t\"a\": [\r\n\t\t\"x\",\r\n\t\t\"y\"\r\n\t]\r\n}\r\n",
			want:  "{\r\n\t\"a\": [\r\n\t\t\"y\"\r\n\t]\r\n}\r\n",
			wantN: 1,
		},
		{
			name: "duplicate key uses the last, like encoding/json", path: []string{"a"}, value: "x",
			doc:   `{"a":["x","y"],"a":["x","z"]}`,
			want:  `{"a":["x","y"],"a":["z"]}`,
			wantN: 1,
		},
		{
			name: "root array", path: nil, value: "x",
			doc:   `["x","y"]`,
			want:  `["y"]`,
			wantN: 1,
		},
		{name: "missing leaf", path: allow, value: "a", doc: `{"permissions":{}}`, wantErr: ErrNotFound},
		{name: "missing parent", path: allow, value: "a", doc: `{}`, wantErr: ErrNotFound},
		{name: "parent is not an object", path: allow, value: "a", doc: `{"permissions":"x"}`, wantErr: ErrNotFound},
		{name: "wrong type string", path: allow, value: "a", anyErr: true, doc: `{"permissions":{"allow":"a"}}`},
		{name: "wrong type object", path: allow, value: "a", anyErr: true, doc: `{"permissions":{"allow":{}}}`},
		{name: "invalid JSON", path: allow, value: "a", anyErr: true, doc: `{"permissions":{"allow":["a",]}}`},
		{name: "trailing data", path: allow, value: "a", anyErr: true, doc: `{"permissions":{"allow":["a"]}} x`},
		{name: "empty doc", path: allow, value: "a", anyErr: true, doc: ``},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, n, err := RemoveArrayString([]byte(tt.doc), tt.path, tt.value)
			if tt.wantErr != nil || tt.anyErr {
				if err == nil {
					t.Fatalf("want error, got %q", got)
				}
				if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				if got != nil {
					t.Fatalf("output on error: %q", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want || n != tt.wantN {
				t.Fatalf("got %q (n=%d)\nwant %q (n=%d)", got, n, tt.want, tt.wantN)
			}
		})
	}
}

func TestSetBool(t *testing.T) {
	path := []string{"projects", "/home/u/app", "hasTrustDialogAccepted"}
	tests := []struct {
		name    string
		doc     string
		path    []string
		v       bool
		want    string
		wantErr error
		anyErr  bool
	}{
		{
			name: "true to false", path: path, v: false,
			doc:  `{"projects":{"/home/u/app":{"hasTrustDialogAccepted":true,"x":1}}}`,
			want: `{"projects":{"/home/u/app":{"hasTrustDialogAccepted":false,"x":1}}}`,
		},
		{
			name: "false to true", path: path, v: true,
			doc:  `{"projects":{"/home/u/app":{"hasTrustDialogAccepted": false }}}`,
			want: `{"projects":{"/home/u/app":{"hasTrustDialogAccepted": true }}}`,
		},
		{
			name: "same value", path: path, v: true,
			doc:  `{"projects":{"/home/u/app":{"hasTrustDialogAccepted":true}}}`,
			want: `{"projects":{"/home/u/app":{"hasTrustDialogAccepted":true}}}`,
		},
		{
			name: "only the named project changes", path: path, v: false,
			doc:  "{\n  \"big\": 12345678901234567890,\n  \"projects\": {\n    \"/home/u/other\": {\"hasTrustDialogAccepted\": true},\n    \"/home/u/app\": {\n      \"hasTrustDialogAccepted\": true\n    }\n  }\n}\n",
			want: "{\n  \"big\": 12345678901234567890,\n  \"projects\": {\n    \"/home/u/other\": {\"hasTrustDialogAccepted\": true},\n    \"/home/u/app\": {\n      \"hasTrustDialogAccepted\": false\n    }\n  }\n}\n",
		},
		{name: "missing key", path: path, doc: `{"projects":{"/home/u/app":{}}}`, wantErr: ErrNotFound},
		{name: "missing project", path: path, doc: `{"projects":{}}`, wantErr: ErrNotFound},
		{name: "wrong type string", path: path, doc: `{"projects":{"/home/u/app":{"hasTrustDialogAccepted":"true"}}}`, anyErr: true},
		{name: "wrong type null", path: path, doc: `{"projects":{"/home/u/app":{"hasTrustDialogAccepted":null}}}`, anyErr: true},
		{name: "wrong type number", path: path, doc: `{"projects":{"/home/u/app":{"hasTrustDialogAccepted":1}}}`, anyErr: true},
		{name: "invalid JSON", path: path, doc: `{`, anyErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SetBool([]byte(tt.doc), tt.path, tt.v)
			if tt.wantErr != nil || tt.anyErr {
				if err == nil {
					t.Fatalf("want error, got %q", got)
				}
				if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Fatalf("got %q\nwant %q", got, tt.want)
			}
		})
	}
}

func TestJSONDeepNestingDoesNotPanic(t *testing.T) {
	doc := strings.Repeat("[", 3000) + strings.Repeat("]", 3000)
	if _, _, err := RemoveArrayString([]byte(doc), []string{"a"}, "x"); err == nil {
		t.Fatal("want error")
	}
}

func TestJSONVerifyCatchesBadEdit(t *testing.T) {
	// verifyJSON must reject an output that differs from the intended change.
	old := []byte(`{"a":["x","y"]}`)
	bad := []byte(`{"a":["y"],"b":1}`)
	err := verifyJSON(old, bad, []string{"a"}, func(v any) (any, error) { return []any{"y"}, nil })
	if err == nil {
		t.Fatal("verification accepted a wrong output")
	}
}
