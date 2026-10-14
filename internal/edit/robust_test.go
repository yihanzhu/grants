package edit

import "testing"

// Truncated and corrupted input must come back as errors, never panics, and a
// successful edit must still parse.
func TestEditsSurviveDamagedInput(t *testing.T) {
	jsonDoc := "{\n \"permissions\": {\"allow\": [\"a\", \"b\\\"\\u00e9\"], \"n\": 1.5},\n \"projects\": {\"/p\": {\"t\": true}}\n}\n"
	tomlDoc := "# c\n[projects.\"/p\"]\ntrust_level = \"trusted\" # x\nl = [\"[a]\", '''\n[b]\n''']\n\n[[arr]]\ns = \"\"\"\n[no]\n\"\"\"\n[z]\nk = \"v\"\n"
	for cut := 0; cut <= len(jsonDoc); cut++ {
		for _, doc := range []string{jsonDoc[:cut], jsonDoc[:cut] + "}", "[" + jsonDoc[cut:]} {
			if out, _, err := RemoveArrayString([]byte(doc), []string{"permissions", "allow"}, "a"); err == nil {
				if _, derr := decodeJSON(out); derr != nil {
					t.Fatalf("invalid output for %q", doc)
				}
			}
			SetBool([]byte(doc), []string{"projects", "/p", "t"}, false)
		}
	}
	for cut := 0; cut <= len(tomlDoc); cut++ {
		for _, doc := range []string{tomlDoc[:cut], tomlDoc[:cut] + "\"", tomlDoc[cut:]} {
			if out, err := TOMLSetString([]byte(doc), []string{"projects", "/p"}, "trust_level", "u"); err == nil {
				if _, derr := decodeTOML(out); derr != nil {
					t.Fatalf("invalid output for %q", doc)
				}
			}
			TOMLDeleteTable([]byte(doc), []string{"projects", "/p"})
			TOMLDeleteTable([]byte(doc), []string{"z"})
		}
	}
}

func FuzzJSONEdits(f *testing.F) {
	f.Add(`{"a":["x","y"],"b":true}`)
	f.Add("{\n  \"a\": [\n    \"x\"\n  ]\n}")
	f.Fuzz(func(t *testing.T, doc string) {
		if out, _, err := RemoveArrayString([]byte(doc), []string{"a"}, "x"); err == nil {
			if _, derr := decodeJSON(out); derr != nil {
				t.Fatalf("invalid output %q", out)
			}
		}
		SetBool([]byte(doc), []string{"b"}, false)
	})
}

func FuzzTOMLEdits(f *testing.F) {
	f.Add("[a]\nk = \"x\"\n\n[b]\nk = 1\n")
	f.Add("# c\n[a] # d\nk = '''\n[b]\n''' # e\n[[c]]\n")
	f.Fuzz(func(t *testing.T, doc string) {
		if out, err := TOMLSetString([]byte(doc), []string{"a"}, "k", "v"); err == nil {
			if _, derr := decodeTOML(out); derr != nil {
				t.Fatalf("invalid output %q", out)
			}
		}
		TOMLDeleteTable([]byte(doc), []string{"a"})
	})
}
