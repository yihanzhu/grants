package risk

import (
	"fmt"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"empty", "", ""},
		{"plain", "git status", "git status"},
		{"bearer", "curl -H 'Authorization: Bearer abcdef123456' x", "curl -H 'Authorization: [redacted]' x"},
		{"bearer alone", "Bearer abcdef123456", "Bearer [redacted]"},
		{"bearer short word", "bearer of bad news", "bearer of bad news"},
		{"token equals", "deploy --token=abc123", "deploy --token=[redacted]"},
		{"token env name", "GITHUB_TOKEN=abc123 make", "GITHUB_TOKEN=[redacted] make"},
		{"token flag space", "deploy --token abc123", "deploy --token [redacted]"},
		{"password flag space", "login --password hunter", "login --password [redacted]"},
		{"api_key", "run api_key=k1 x", "run api_key=[redacted] x"},
		{"apikey", "apikey: k1", "apikey: [redacted]"},
		{"api-key", "--api-key=k1", "--api-key=[redacted]"},
		{"secret quoted", `secret="a b c"`, `secret=[redacted]`},
		{"password colon", "password: hunter2", "password: [redacted]"},
		{"passwd", "passwd=x1", "passwd=[redacted]"},
		{"auth equals", "auth=u:p", "auth=[redacted]"},
		{"json style", `{"password": "hunter2"}`, `{"password": [redacted]}`},
		{"upper case", "PASSWORD=Abc", "PASSWORD=[redacted]"},
		{"authorization basic", "Authorization: Basic dXNlcjpwYXNz", "Authorization: [redacted]"},
		{"auth subcommand kept", "gh auth login", "gh auth login"},
		{"auth status kept", "gh auth status", "gh auth status"},
		{"token word in prose kept", "refresh the token cache", "refresh the token cache"},
		{"author kept", "author=me", "author=me"},
		{"env var reference kept", "--token=$GH_TOKEN", "--token=$GH_TOKEN"},
		{"placeholder kept", "--token=<your token>", "--token=<your token>"},
		{"wildcard kept", "token=*", "token=*"},
		{"auth host kept", "http://auth:8080/x", "http://auth:8080/x"},
		{"openai shape", "key sk-abcdefghijklmnopqrstuvwxyz0123", "key [redacted]"},
		{"anthropic shape", "sk-ant-api03-abcdefghijklmnop_qrstuv-wxyz", "[redacted]"},
		{"sk too short", "sk-short", "sk-short"},
		{"task- is not sk-", "task-abcdefghijklmnopqrstuvwxyz", "task-abcdefghijklmnopqrstuvwxyz"},
		{"ghp", "ghp_0123456789abcdefghijABCDEFGHIJ0123456", "[redacted]"},
		{"gho", "gho_0123456789abcdefghij", "[redacted]"},
		{"ghs", "ghs_0123456789abcdefghij", "[redacted]"},
		{"ghu", "ghu_0123456789abcdefghij", "[redacted]"},
		{"github_pat", "github_pat_11ABCDEFG0123456789_abcdefghijklmnop", "[redacted]"},
		{"slack", "xoxb-1234567890-abcdefghij", "[redacted]"},
		{"slack p", "xoxp-1234567890-abcdefghij", "[redacted]"},
		{"aws", "AKIAABCDEFGHIJKLMNOP is the id", "[redacted] is the id"},
		{"aws too short", "AKIAABC", "AKIAABC"},
		{"google", "AIzaSyA-1234567890abcdefghijklmnopqrstu", "[redacted]"},
		{"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.c2ln", "[redacted]"},
		{"pem", "x -----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY----- y", "x [redacted] y"},
		{"pem unterminated", "-----BEGIN PRIVATE KEY-----\nMIIabc", "[redacted]"},
		{"url password", "git clone https://bob:s3cret@example.com/r.git", "git clone https://bob:[redacted]@example.com/r.git"},
		{"url user only", "https://bob@example.com/r", "https://bob@example.com/r"},
		{"query token", "https://example.com/x?token=abc&a=1", "https://example.com/x?token=[redacted]&a=1"},
		{"query key", "https://example.com/x?a=1&key=abc", "https://example.com/x?a=1&key=[redacted]"},
		{"query secret", "https://example.com/?secret=zz", "https://example.com/?secret=[redacted]"},
		{"query sig", "https://example.com/?sig=zz&signature=yy", "https://example.com/?sig=[redacted]&signature=[redacted]"},
		{"query password", "https://example.com/?password=zz", "https://example.com/?password=[redacted]"},
		{"query access_token", "https://example.com/?access_token=zz", "https://example.com/?access_token=[redacted]"},
		{"query other kept", "https://example.com/?page=2&q=go", "https://example.com/?page=2&q=go"},
		{"unicode kept", "echo héllo 世界", "echo héllo 世界"},
		{"already redacted", "token=[redacted]", "token=[redacted]"},
		{"already redacted bearer", "Authorization: Bearer [redacted]", "Authorization: Bearer [redacted]"},
	}
	for _, c := range cases {
		got := Redact(c.in)
		if got != c.want {
			t.Errorf("%s: Redact(%q)\n got %q\nwant %q", c.name, c.in, got, c.want)
		}
		if again := Redact(got); again != got {
			t.Errorf("%s: not idempotent: %q -> %q", c.name, got, again)
		}
	}
}

func TestRedactLeavesNoSecret(t *testing.T) {
	secrets := []string{"hunter2xyz", "abcdef123456", "ghp_0123456789abcdefghij", "s3cretPass"}
	for _, s := range secrets {
		for _, tmpl := range []string{"--token=%s", "password: %s", "Bearer %s", "https://u:%s@h/x", "?key=%s"} {
			in := fmt.Sprintf(tmpl, s)
			if got := Redact(in); strings.Contains(got, s) {
				t.Errorf("Redact(%q) = %q still holds the secret", in, got)
			}
		}
	}
}
