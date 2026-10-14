package edit

import (
	"errors"
	"strings"
	"testing"
)

func TestTOMLSetString(t *testing.T) {
	trust := []string{"projects", "/home/u/app"}
	tests := []struct {
		name    string
		doc     string
		table   []string
		key     string
		value   string
		want    string
		wantErr error
	}{
		{
			name: "simple", table: trust, key: "trust_level", value: "untrusted",
			doc:  "[projects.\"/home/u/app\"]\ntrust_level = \"trusted\"\n",
			want: "[projects.\"/home/u/app\"]\ntrust_level = \"untrusted\"\n",
		},
		{
			name: "trailing comment kept", table: trust, key: "trust_level", value: "untrusted",
			doc:  "[projects.\"/home/u/app\"]\ntrust_level = \"trusted\"   # ask me, # not\n",
			want: "[projects.\"/home/u/app\"]\ntrust_level = \"untrusted\"   # ask me, # not\n",
		},
		{
			name: "comments around", table: trust, key: "trust_level", value: "untrusted",
			doc:  "# top\n[projects.\"/home/u/app\"] # hdr\n# before\ntrust_level=\"trusted\"\n# after\n",
			want: "# top\n[projects.\"/home/u/app\"] # hdr\n# before\ntrust_level=\"untrusted\"\n# after\n",
		},
		{
			name: "literal string value", table: trust, key: "trust_level", value: "untrusted",
			doc:  "[projects.\"/home/u/app\"]\ntrust_level = 'trusted'\n",
			want: "[projects.\"/home/u/app\"]\ntrust_level = \"untrusted\"\n",
		},
		{
			name: "multi-line string with fake header", table: []string{"a"}, key: "k", value: "v",
			doc:  "[x]\ntext = \"\"\"\n[a]\nk = \"no\"\n\"\"\"\n\n[a]\nk = \"old\"\n",
			want: "[x]\ntext = \"\"\"\n[a]\nk = \"no\"\n\"\"\"\n\n[a]\nk = \"v\"\n",
		},
		{
			name: "literal multi-line string with fake header", table: []string{"a"}, key: "k", value: "v",
			doc:  "[x]\ntext = '''\n[a]\nk = \"no\"\n'''\n[a]\nk = \"old\"\n",
			want: "[x]\ntext = '''\n[a]\nk = \"no\"\n'''\n[a]\nk = \"v\"\n",
		},
		{
			name: "array across lines with fake header", table: []string{"a"}, key: "k", value: "v",
			doc:  "[x]\nlist = [\n  \"[a]\", # [a]\n  'k = 1',\n]\n[a]\nk = \"old\"\n",
			want: "[x]\nlist = [\n  \"[a]\", # [a]\n  'k = 1',\n]\n[a]\nk = \"v\"\n",
		},
		{
			name: "string with closing quotes before delimiter", table: []string{"a"}, key: "k", value: "v",
			doc:  "[x]\ns = \"\"\"say \"hi\"\"\"\"\n[a]\nk = 1\n",
			want: "[x]\ns = \"\"\"say \"hi\"\"\"\"\n[a]\nk = \"v\"\n",
		},
		{
			name: "same key in other table untouched", table: []string{"b"}, key: "k", value: "v",
			doc:  "[a]\nk = \"1\"\n[b]\nk = \"2\"\n[c]\nk = \"3\"\n",
			want: "[a]\nk = \"1\"\n[b]\nk = \"v\"\n[c]\nk = \"3\"\n",
		},
		{
			name: "quoted key with escapes", table: []string{"projects", "/home/u/my \"app\"\\x"}, key: "trust_level", value: "untrusted",
			doc:  "[projects.\"/home/u/my \\\"app\\\"\\\\x\"]\ntrust_level = \"trusted\"\n",
			want: "[projects.\"/home/u/my \\\"app\\\"\\\\x\"]\ntrust_level = \"untrusted\"\n",
		},
		{
			name: "literal-quoted table key", table: []string{"projects", `/home/u/a "b"`}, key: "trust_level", value: "untrusted",
			doc:  "[projects.'/home/u/a \"b\"']\ntrust_level = \"trusted\"\n",
			want: "[projects.'/home/u/a \"b\"']\ntrust_level = \"untrusted\"\n",
		},
		{
			name: "dotted header with spaces", table: trust, key: "trust_level", value: "untrusted",
			doc:  "[ projects . \"/home/u/app\" ]\ntrust_level = \"trusted\"\n",
			want: "[ projects . \"/home/u/app\" ]\ntrust_level = \"untrusted\"\n",
		},
		{
			name: "quoted key name", table: []string{"t"}, key: "my key", value: "v",
			doc:  "[t]\n\"my key\" = \"old\"\n",
			want: "[t]\n\"my key\" = \"v\"\n",
		},
		{
			name: "literal key name", table: []string{"t"}, key: "a.b", value: "v",
			doc:  "[t]\n'a.b' = \"old\"\n",
			want: "[t]\n'a.b' = \"v\"\n",
		},
		{
			name: "value needs escaping", table: []string{"t"}, key: "k", value: "a\"b\\c\né",
			doc:  "[t]\nk = \"old\"\n",
			want: "[t]\nk = \"a\\\"b\\\\c\\né\"\n",
		},
		{
			name: "array of tables elsewhere", table: []string{"a"}, key: "k", value: "v",
			doc:  "[[servers]]\nk = \"1\"\n[[servers]]\nk = \"2\"\n[a]\nk = \"old\"\n",
			want: "[[servers]]\nk = \"1\"\n[[servers]]\nk = \"2\"\n[a]\nk = \"v\"\n",
		},
		{
			name: "last table without final newline", table: []string{"a"}, key: "k", value: "v",
			doc:  "[a]\nk = \"old\"",
			want: "[a]\nk = \"v\"",
		},
		{
			name: "CRLF", table: []string{"a"}, key: "k", value: "v",
			doc:  "[x]\r\nj = 1\r\n[a]\r\nk = \"old\" # c\r\nm = 2\r\n",
			want: "[x]\r\nj = 1\r\n[a]\r\nk = \"v\" # c\r\nm = 2\r\n",
		},
		{
			name: "BOM", table: []string{"a"}, key: "k", value: "v",
			doc:  "\xef\xbb\xbf[a]\nk = \"old\"\n",
			want: "\xef\xbb\xbf[a]\nk = \"v\"\n",
		},
		{
			name: "date value before key", table: []string{"a"}, key: "k", value: "v",
			doc:  "[a]\nwhen = 1979-05-27 07:32:00Z # c\nk = \"old\"\n",
			want: "[a]\nwhen = 1979-05-27 07:32:00Z # c\nk = \"v\"\n",
		},
		{
			name: "inline table value before key", table: []string{"a"}, key: "k", value: "v",
			doc:  "[a]\nopts = { x = \"}\", y = [1, 2] }\nk = \"old\"\n",
			want: "[a]\nopts = { x = \"}\", y = [1, 2] }\nk = \"v\"\n",
		},
		{name: "missing table", table: []string{"zz"}, key: "k", value: "v", doc: "[a]\nk = \"1\"\n", wantErr: ErrNotFound},
		{name: "missing key", table: []string{"a"}, key: "nope", value: "v", doc: "[a]\nk = \"1\"\n", wantErr: ErrNotFound},
		{name: "key only in a later table", table: []string{"a"}, key: "k", value: "v", doc: "[a]\nj = 1\n[b]\nk = \"1\"\n", wantErr: ErrNotFound},
		{
			name: "inline table layout", table: []string{"projects", "/p"}, key: "trust_level", value: "untrusted",
			doc:     "[projects]\n\"/p\" = { trust_level = \"trusted\" }\n",
			wantErr: ErrUnsupportedLayout,
		},
		{
			name: "dotted keys layout", table: []string{"projects", "/p"}, key: "trust_level", value: "untrusted",
			doc:     "[projects]\n\"/p\".trust_level = \"trusted\"\n",
			wantErr: ErrUnsupportedLayout,
		},
		{
			name: "top-level dotted keys layout", table: []string{"a"}, key: "k", value: "v",
			doc:     "a.k = \"1\"\n",
			wantErr: ErrUnsupportedLayout,
		},
		{
			name: "array of tables layout", table: []string{"a"}, key: "k", value: "v",
			doc:     "[[a]]\nk = \"1\"\n",
			wantErr: ErrUnsupportedLayout,
		},
		{name: "invalid TOML", table: []string{"a"}, key: "k", value: "v", doc: "[a\nk = 1\n", wantErr: errAny},
		{name: "invalid UTF-8 value", table: []string{"a"}, key: "k", value: "\xff", doc: "[a]\nk = \"1\"\n", wantErr: errAny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TOMLSetString([]byte(tt.doc), tt.table, tt.key, tt.value)
			if tt.wantErr != nil {
				checkErr(t, got, err, tt.wantErr)
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

var errAny = errors.New("any error")

func checkErr(t *testing.T, got []byte, err, want error) {
	t.Helper()
	if err == nil {
		t.Fatalf("want error, got %q", got)
	}
	if want != errAny && !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
	if got != nil {
		t.Fatalf("output on error: %q", got)
	}
}

func TestTOMLDeleteTable(t *testing.T) {
	p := func(name string) []string { return []string{"projects", name} }
	tests := []struct {
		name    string
		doc     string
		table   []string
		want    string
		wantErr error
	}{
		{
			name: "middle table", table: p("/b"),
			doc:  "[projects.\"/a\"]\ntrust_level = \"trusted\"\n\n[projects.\"/b\"]\ntrust_level = \"trusted\"\n\n[projects.\"/c\"]\ntrust_level = \"trusted\"\n",
			want: "[projects.\"/a\"]\ntrust_level = \"trusted\"\n\n[projects.\"/c\"]\ntrust_level = \"trusted\"\n",
		},
		{
			name: "first table", table: p("/a"),
			doc:  "[projects.\"/a\"]\ntrust_level = \"trusted\"\n\n[projects.\"/b\"]\ntrust_level = \"trusted\"\n",
			want: "[projects.\"/b\"]\ntrust_level = \"trusted\"\n",
		},
		{
			name: "first table after top-level keys", table: p("/a"),
			doc:  "model = \"m\"\n\n[projects.\"/a\"]\ntrust_level = \"trusted\"\n\n[projects.\"/b\"]\ntrust_level = \"trusted\"\n",
			want: "model = \"m\"\n\n[projects.\"/b\"]\ntrust_level = \"trusted\"\n",
		},
		{
			name: "last table", table: p("/b"),
			doc:  "[projects.\"/a\"]\ntrust_level = \"trusted\"\n\n[projects.\"/b\"]\ntrust_level = \"trusted\"\n",
			want: "[projects.\"/a\"]\ntrust_level = \"trusted\"\n",
		},
		{
			name: "last table without final newline", table: p("/b"),
			doc:  "[projects.\"/a\"]\ntrust_level = \"trusted\"\n\n[projects.\"/b\"]\ntrust_level = \"trusted\"",
			want: "[projects.\"/a\"]\ntrust_level = \"trusted\"\n",
		},
		{
			name: "last table keeps trailing comments", table: p("/a"),
			doc:  "[projects.\"/b\"]\nk = 1\n\n[projects.\"/a\"]\nk = 1\n\n# [mcp_servers.x]\n# command = \"npx\"\n",
			want: "[projects.\"/b\"]\nk = 1\n\n# [mcp_servers.x]\n# command = \"npx\"\n",
		},
		{
			name: "first table keeps the BOM", table: p("/a"),
			doc:  "\xEF\xBB\xBF[projects.\"/a\"]\nk = 1\n\n[projects.\"/b\"]\nk = 1\n",
			want: "\xEF\xBB\xBF[projects.\"/b\"]\nk = 1\n",
		},
		{
			name: "no blank line before: keep one", table: p("/b"),
			doc:  "[projects.\"/a\"]\ntrust_level = \"trusted\"\n[projects.\"/b\"]\ntrust_level = \"trusted\"\n\n[projects.\"/c\"]\ntrust_level = \"trusted\"\n",
			want: "[projects.\"/a\"]\ntrust_level = \"trusted\"\n\n[projects.\"/c\"]\ntrust_level = \"trusted\"\n",
		},
		{
			name: "no blank lines at all", table: p("/b"),
			doc:  "[projects.\"/a\"]\nk = 1\n[projects.\"/b\"]\nk = 1\n[projects.\"/c\"]\nk = 1\n",
			want: "[projects.\"/a\"]\nk = 1\n[projects.\"/c\"]\nk = 1\n",
		},
		{
			name: "comment above next header stays", table: p("/b"),
			doc:  "[projects.\"/a\"]\nk = 1\n\n[projects.\"/b\"]\nk = 1\n\n# about c\n[projects.\"/c\"]\nk = 1\n",
			want: "[projects.\"/a\"]\nk = 1\n\n# about c\n[projects.\"/c\"]\nk = 1\n",
		},
		{
			name: "comment block above next header stays", table: p("/b"),
			doc:  "[projects.\"/a\"]\nk = 1\n\n[projects.\"/b\"]\nk = 1\n# one\n# two\n[projects.\"/c\"]\nk = 1\n",
			want: "[projects.\"/a\"]\nk = 1\n\n# one\n# two\n[projects.\"/c\"]\nk = 1\n",
		},
		{
			name: "comment inside body goes", table: p("/b"),
			doc:  "[projects.\"/a\"]\nk = 1\n\n[projects.\"/b\"]\n# note\nk = 1\n# trailing\n\n[projects.\"/c\"]\nk = 1\n",
			want: "[projects.\"/a\"]\nk = 1\n\n[projects.\"/c\"]\nk = 1\n",
		},
		{
			name: "header comment goes", table: p("/b"),
			doc:  "[projects.\"/a\"]\nk = 1\n\n[projects.\"/b\"] # mine\nk = 1\n\n[projects.\"/c\"]\nk = 1\n",
			want: "[projects.\"/a\"]\nk = 1\n\n[projects.\"/c\"]\nk = 1\n",
		},
		{
			name: "multi-line string with fake header in body", table: p("/b"),
			doc:  "[projects.\"/a\"]\nk = 1\n\n[projects.\"/b\"]\ntext = \"\"\"\n[projects.\"/c\"]\n\"\"\"\n\n[projects.\"/c\"]\nk = 1\n",
			want: "[projects.\"/a\"]\nk = 1\n\n[projects.\"/c\"]\nk = 1\n",
		},
		{
			name: "multi-line array in body", table: p("/b"),
			doc:  "[projects.\"/a\"]\nk = 1\n\n[projects.\"/b\"]\nlist = [\n  \"x\",\n  # [projects.\"/c\"]\n  \"y\",\n]\n\n[projects.\"/c\"]\nk = 1\n",
			want: "[projects.\"/a\"]\nk = 1\n\n[projects.\"/c\"]\nk = 1\n",
		},
		{
			name: "fake header in string above does not match", table: p("/b"),
			doc:  "[x]\ntext = '''\n[projects.\"/b\"]\n'''\n\n[projects.\"/b\"]\nk = 1\n",
			want: "[x]\ntext = '''\n[projects.\"/b\"]\n'''\n",
		},
		{
			name: "array of tables follows", table: p("/b"),
			doc:  "[projects.\"/a\"]\nk = 1\n\n[projects.\"/b\"]\nk = 1\n\n[[servers]]\nname = \"s\"\n",
			want: "[projects.\"/a\"]\nk = 1\n\n[[servers]]\nname = \"s\"\n",
		},
		{
			name: "only table in file", table: []string{"a"},
			doc:  "[a]\nk = 1\n",
			want: "",
		},
		{
			name: "only project, parent implicit", table: p("/a"),
			doc:  "model = \"m\"\n\n[projects.\"/a\"]\nk = 1\n",
			want: "model = \"m\"\n",
		},
		{
			name: "parent has its own header", table: p("/a"),
			doc:  "[projects]\nx = 1\n\n[projects.\"/a\"]\nk = 1\n",
			want: "[projects]\nx = 1\n",
		},
		{
			name: "quoted key with escapes", table: p("/my \"app\""),
			doc:  "[projects.\"/my \\\"app\\\"\"]\nk = 1\n\n[projects.\"/b\"]\nk = 1\n",
			want: "[projects.\"/b\"]\nk = 1\n",
		},
		{
			name: "CRLF", table: p("/b"),
			doc:  "[projects.\"/a\"]\r\nk = 1\r\n\r\n[projects.\"/b\"]\r\nk = 1\r\n\r\n[projects.\"/c\"]\r\nk = 1\r\n",
			want: "[projects.\"/a\"]\r\nk = 1\r\n\r\n[projects.\"/c\"]\r\nk = 1\r\n",
		},
		{
			name: "similar name stays", table: p("/a"),
			doc:  "[projects.\"/a\"]\nk = 1\n\n[projects.\"/a2\"]\nk = 2\n",
			want: "[projects.\"/a2\"]\nk = 2\n",
		},
		{name: "missing", table: p("/zz"), doc: "[projects.\"/a\"]\nk = 1\n", wantErr: ErrNotFound},
		{
			name: "inline table layout", table: p("/a"),
			doc:     "[projects]\n\"/a\" = { k = 1 }\n",
			wantErr: ErrUnsupportedLayout,
		},
		{
			name: "dotted keys layout", table: p("/a"),
			doc:     "[projects]\n\"/a\".k = 1\n\"/b\".k = 1\n",
			wantErr: ErrUnsupportedLayout,
		},
		{
			name: "array of tables", table: []string{"a"},
			doc:     "[[a]]\nk = 1\n",
			wantErr: ErrUnsupportedLayout,
		},
		{
			name: "has sub-tables", table: []string{"a"},
			doc:     "[a]\nk = 1\n[a.b]\nk = 1\n",
			wantErr: ErrUnsupportedLayout,
		},
		{name: "invalid TOML", table: []string{"a"}, doc: "[a]\nk = \n", wantErr: errAny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TOMLDeleteTable([]byte(tt.doc), tt.table)
			if tt.wantErr != nil {
				checkErr(t, got, err, tt.wantErr)
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

func TestTOMLScannerStatements(t *testing.T) {
	doc := "# c\n[a.\"b c\".'d']\nk = [\n \"[x]\",\n]\n[[arr]]\ns = \"\"\"\n[no]\n\"\"\"\n"
	stmts, err := scanTOML([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	var kinds []tomlKind
	for _, s := range stmts {
		kinds = append(kinds, s.kind)
	}
	want := []tomlKind{tomlComment, tomlTable, tomlKV, tomlArrayTable, tomlKV}
	if len(kinds) != len(want) {
		t.Fatalf("kinds = %v, want %v", kinds, want)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Fatalf("kinds = %v, want %v", kinds, want)
		}
	}
	if got := strings.Join(stmts[1].key, "|"); got != "a|b c|d" {
		t.Fatalf("header key = %q", got)
	}
}

func TestTOMLNaNDoesNotFailVerification(t *testing.T) {
	got, err := TOMLSetString([]byte("x = nan\n[a]\nk = \"1\"\n"), []string{"a"}, "k", "v")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "x = nan\n[a]\nk = \"v\"\n" {
		t.Fatalf("got %q", got)
	}
}
