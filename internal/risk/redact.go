package risk

import (
	"regexp"
	"strings"
)

const redacted = "[redacted]"

var (
	pemRe = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\z)`)

	// shapeRes match tokens that are credentials by their format alone.
	shapeRes = []*regexp.Regexp{
		regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}`),
		regexp.MustCompile(`\b(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{10,}`),
		regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{10,}`),
		regexp.MustCompile(`\bxox[abpr]-[A-Za-z0-9-]{10,}`),
		regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{30,}`),
		regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`),
	}

	// userinfoRe finds scheme://user:password@host and keeps everything but the password.
	userinfoRe = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://[^/\s:@'"]*:)[^/\s@'"]+(@)`)

	queryRe = regexp.MustCompile(`(?i)([?&](?:[a-z0-9]+[_-])*(?:token|key|secret|sig|signature|password|passwd)=)[^&\s'"#]+`)

	// assignRe finds name=value and name: value where the name ends in a secret word.
	// Group 1 is the name and separator, group 2 the value.
	assignRe = regexp.MustCompile(`(?i)([a-z0-9_.-]*(?:bearer|token|api[_-]?key|secret|password|passwd|authorization|auth)["']?\s*[:=]\s*)` +
		`((?:(?:bearer|basic)\s+)?(?:"[^"]*"|'[^']*'|[^\s"'&,;]+))`)

	// spaceRe finds "--token value", "bearer value" and "password value" without a separator.
	// Group 1 is the text before the keyword, 2 the dashes, 3 the keyword, 4 the value.
	spaceRe = regexp.MustCompile(`(?i)(^|[^a-z0-9_])(-{0,2})(bearer|token|api[_-]?key|secret|password|passwd|auth)(\s+)([^\s"'&,;\[]+)`)
)

// Redact masks credential-like substrings with [redacted]. It is meant for text that
// grants stores or shows, such as justifications and command summaries. Running it on
// its own output changes nothing.
func Redact(s string) string {
	if s == "" {
		return s
	}
	s = pemRe.ReplaceAllString(s, redacted)
	for _, re := range shapeRes {
		s = re.ReplaceAllString(s, redacted)
	}
	s = userinfoRe.ReplaceAllString(s, "${1}"+redacted+"${2}")
	s = queryRe.ReplaceAllString(s, "${1}"+redacted)
	s = replaceIf(assignRe, s, func(sub []string, start int, full string) (string, bool) {
		if start >= 2 && full[start-2:start] == "//" { // http://auth:8080 is a host and port
			return "", false
		}
		return sub[1] + redacted, secretValue(sub[2])
	})
	s = replaceIf(spaceRe, s, func(sub []string, _ int, _ string) (string, bool) {
		dashes, word, value := sub[2], strings.ToLower(sub[3]), sub[5]
		if word != "bearer" && dashes == "" && !looksLikeSecret(value) {
			return "", false // "gh auth login" is not a credential
		}
		if word == "bearer" && len(value) < 8 {
			return "", false
		}
		if !secretValue(value) {
			return "", false
		}
		return sub[1] + dashes + sub[3] + sub[4] + redacted, true
	})
	return s
}

// replaceIf replaces each match of re when fn returns ok. fn gets the submatches, the
// byte offset of the match start and the whole string.
func replaceIf(re *regexp.Regexp, s string, fn func(sub []string, start int, full string) (string, bool)) string {
	var b strings.Builder
	last := 0
	for _, m := range re.FindAllStringSubmatchIndex(s, -1) {
		sub := make([]string, len(m)/2)
		for i := range sub {
			if m[2*i] >= 0 {
				sub[i] = s[m[2*i]:m[2*i+1]]
			}
		}
		if repl, ok := fn(sub, m[0], s); ok {
			b.WriteString(s[last:m[0]])
			b.WriteString(repl)
			last = m[1]
		}
	}
	b.WriteString(s[last:])
	return b.String()
}

// secretValue reports whether v may be a real secret. Empty values, wildcards,
// variable references and already-redacted text are not.
func secretValue(v string) bool {
	v = strings.Trim(v, `"'`)
	if v == "" || strings.HasPrefix(v, redacted) {
		return false
	}
	switch v[0] {
	case '$', '*', '<', '{', '%':
		return false
	}
	if i := strings.IndexAny(v, " \t"); i > 0 { // Bearer <value>: judge the value
		return secretValue(v[i+1:])
	}
	return true
}

// looksLikeSecret is the test for a value that follows a keyword after a plain space:
// long enough and mixing letters with digits or symbols.
func looksLikeSecret(v string) bool {
	if len(v) < 8 {
		return false
	}
	return strings.ContainsAny(v, "0123456789")
}
