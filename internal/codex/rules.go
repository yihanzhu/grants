package codex

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Rule is one top-level statement of a Codex .rules file, such as
// prefix_rule(pattern=["git", "status"], decision="allow").
//
// The parser understands the Starlark subset Codex writes and people write by hand:
// calls with keyword arguments, strings, nested lists, True/False/None, numbers and
// # comments. A statement it cannot read keeps its span and gets Err, so callers can
// leave it alone.
type Rule struct {
	Name          string     // function name, e.g. prefix_rule
	Pattern       [][]string // one entry per token position, listing its alternatives
	Decision      string     // "allow" when omitted on a prefix_rule
	Justification string
	Line          int    // 1-based line of the call
	Start, End    int    // byte span: from the start of the line holding the call to past the closing ")", trailing space or comment and the newline
	Raw           string // the statement's text, src[Start:End]
	Err           string // set when the statement could not be parsed
}

// kind of a parsed value.
type valKind int

const (
	vString valKind = iota
	vList
	vOther // True, False, None, numbers
)

type value struct {
	kind valKind
	str  string
	list []value
}

type parser struct {
	src []byte
	i   int
}

var errSyntax = errors.New("unsupported syntax")

// ParseRules parses a Codex .rules file into statements with byte spans. It never
// fails: statements it cannot read come back with Err set.
func ParseRules(src []byte) []Rule {
	var rules []Rule
	p := &parser{src: src}
	prevEnd := 0
	for {
		p.skipBlank()
		if p.i >= len(src) {
			break
		}
		start := max(lineStart(src, p.i), prevEnd)
		begin := p.i
		r, err := p.statement()
		if err != nil {
			p.i = recoverEnd(src, begin)
			r = Rule{Err: fmt.Sprintf("line %d: %v", lineOf(src, begin), err)}
		}
		end := p.endOfStatement(p.i)
		r.Line = lineOf(src, begin)
		r.Start, r.End = start, end
		r.Raw = string(src[start:end])
		rules = append(rules, r)
		p.i, prevEnd = end, end
	}
	return rules
}

// RemoveRule deletes every prefix_rule statement with this pattern and decision, and
// returns the new text and how many statements it removed. It parses the result again
// and fails when any other statement changed.
func RemoveRule(src []byte, pattern [][]string, decision string) ([]byte, int, error) {
	rules := ParseRules(src)
	var out []byte
	var kept []Rule
	pos, n := 0, 0
	for _, r := range rules {
		if r.Err == "" && r.Name == "prefix_rule" && r.Decision == decision && samePattern(r.Pattern, pattern) {
			out = append(out, src[pos:r.Start]...)
			pos = r.End
			n++
			continue
		}
		kept = append(kept, r)
	}
	if n == 0 {
		return src, 0, nil
	}
	out = append(out, src[pos:]...)

	after := ParseRules(out)
	if len(after) != len(kept) {
		return nil, 0, fmt.Errorf("rules check failed: expected %d statements after removal, found %d", len(kept), len(after))
	}
	for i := range kept {
		if after[i].Raw != kept[i].Raw || (after[i].Err == "") != (kept[i].Err == "") || after[i].Name != kept[i].Name {
			return nil, 0, fmt.Errorf("rules check failed: statement %d changed", i+1)
		}
		if after[i].Err == "" && after[i].Name == "prefix_rule" && after[i].Decision == decision && samePattern(after[i].Pattern, pattern) {
			return nil, 0, errors.New("rules check failed: the rule is still present")
		}
	}
	return out, n, nil
}

// statement parses one call. p.i starts at the first character of the name.
func (p *parser) statement() (Rule, error) {
	name := p.ident()
	if name == "" {
		return Rule{}, errSyntax
	}
	p.skipSpaces()
	if !p.eat('(') {
		return Rule{}, errSyntax
	}
	r := Rule{Name: name}
	args := map[string]value{}
	for {
		p.skipSpace()
		if p.eat(')') {
			break
		}
		key := p.ident()
		if key == "" {
			return Rule{}, errSyntax
		}
		p.skipSpace()
		if !p.eat('=') || p.peek() == '=' {
			return Rule{}, errSyntax
		}
		v, err := p.value(0)
		if err != nil {
			return Rule{}, err
		}
		args[key] = v
		p.skipSpace()
		if p.eat(',') {
			continue
		}
		p.skipSpace()
		if !p.eat(')') {
			return Rule{}, errSyntax
		}
		break
	}

	if v, ok := args["justification"]; ok && v.kind == vString {
		r.Justification = v.str
	}
	if name != "prefix_rule" {
		if v, ok := args["decision"]; ok && v.kind == vString {
			r.Decision = v.str
		}
		return r, nil
	}
	r.Decision = "allow"
	if v, ok := args["decision"]; ok {
		if v.kind != vString {
			return Rule{}, errors.New("decision is not a string")
		}
		r.Decision = v.str
	}
	pat, ok := args["pattern"]
	if !ok {
		return Rule{}, errors.New("prefix_rule has no pattern")
	}
	pattern, err := toPattern(pat)
	if err != nil {
		return Rule{}, err
	}
	r.Pattern = pattern
	return r, nil
}

// toPattern turns a parsed list into token positions. An element that is a string is
// one alternative; an element that is a list of strings is several.
func toPattern(v value) ([][]string, error) {
	if v.kind != vList || len(v.list) == 0 {
		return nil, errors.New("pattern is not a list of tokens")
	}
	out := make([][]string, 0, len(v.list))
	for _, e := range v.list {
		switch e.kind {
		case vString:
			out = append(out, []string{e.str})
		case vList:
			if len(e.list) == 0 {
				return nil, errors.New("pattern has an empty alternatives list")
			}
			alts := make([]string, 0, len(e.list))
			for _, a := range e.list {
				if a.kind != vString {
					return nil, errors.New("pattern alternatives must be strings")
				}
				alts = append(alts, a.str)
			}
			out = append(out, alts)
		default:
			return nil, errors.New("pattern element is not a string or list")
		}
	}
	return out, nil
}

const maxDepth = 16

func (p *parser) value(depth int) (value, error) {
	if depth > maxDepth {
		return value{}, errSyntax
	}
	p.skipSpace()
	c := p.peek()
	switch {
	case c == '"' || c == '\'':
		s, err := p.str(false)
		return value{kind: vString, str: s}, err
	case (c == 'r' || c == 'R') && (p.at(1) == '"' || p.at(1) == '\''):
		p.i++
		s, err := p.str(true)
		return value{kind: vString, str: s}, err
	case c == '[' || c == '(':
		closer := byte(']')
		if c == '(' {
			closer = ')'
		}
		p.i++
		v := value{kind: vList}
		for {
			p.skipSpace()
			if p.eat(closer) {
				return v, nil
			}
			e, err := p.value(depth + 1)
			if err != nil {
				return value{}, err
			}
			v.list = append(v.list, e)
			p.skipSpace()
			if p.eat(',') {
				continue
			}
			if !p.eat(closer) {
				return value{}, errSyntax
			}
			return v, nil
		}
	case c == '-' || c == '+' || (c >= '0' && c <= '9'):
		p.i++
		for p.i < len(p.src) && strings.IndexByte("0123456789.eExXabcdefABCDEF_+-", p.src[p.i]) >= 0 {
			p.i++
		}
		return value{kind: vOther}, nil
	default:
		switch id := p.ident(); id {
		case "True", "False", "None":
			return value{kind: vOther}, nil
		}
	}
	return value{}, errSyntax
}

// str parses a string literal; p.i is at the opening quote.
func (p *parser) str(raw bool) (string, error) {
	q := p.src[p.i]
	triple := p.at(1) == q && p.at(2) == q
	if triple {
		p.i += 3
	} else {
		p.i++
	}
	var sb strings.Builder
	for p.i < len(p.src) {
		c := p.src[p.i]
		switch {
		case c == q && !triple:
			p.i++
			return sb.String(), nil
		case c == q && triple && p.at(1) == q && p.at(2) == q:
			p.i += 3
			return sb.String(), nil
		case c == '\n' && !triple:
			return "", errors.New("unterminated string")
		case c == '\\' && !raw:
			p.i++
			if err := p.escape(&sb); err != nil {
				return "", err
			}
		case c == '\\' && raw:
			sb.WriteByte(c)
			p.i++
			if p.i < len(p.src) {
				sb.WriteByte(p.src[p.i])
				p.i++
			}
		default:
			sb.WriteByte(c)
			p.i++
		}
	}
	return "", errors.New("unterminated string")
}

// escape decodes the escape sequence after a backslash. p.i is at the character
// after the backslash.
func (p *parser) escape(sb *strings.Builder) error {
	if p.i >= len(p.src) {
		return errors.New("unterminated string")
	}
	c := p.src[p.i]
	p.i++
	switch c {
	case 'n':
		sb.WriteByte('\n')
	case 't':
		sb.WriteByte('\t')
	case 'r':
		sb.WriteByte('\r')
	case 'a':
		sb.WriteByte(7)
	case 'b':
		sb.WriteByte(8)
	case 'f':
		sb.WriteByte(12)
	case 'v':
		sb.WriteByte(11)
	case '\\', '"', '\'':
		sb.WriteByte(c)
	case '\n':
		// a backslash before a newline continues the string
	case '\r':
		if p.peek() == '\n' {
			p.i++
		}
	case 'x':
		return p.hexEscape(sb, 2, false)
	case 'u':
		return p.hexEscape(sb, 4, true)
	case 'U':
		return p.hexEscape(sb, 8, true)
	case '0', '1', '2', '3', '4', '5', '6', '7':
		n := int(c - '0')
		for k := 0; k < 2 && p.peek() >= '0' && p.peek() <= '7'; k++ {
			n = n*8 + int(p.peek()-'0')
			p.i++
		}
		if n > 255 {
			return errors.New("bad octal escape")
		}
		sb.WriteByte(byte(n))
	default:
		// Starlark rejects unknown escapes; Codex never writes them. Keep the text.
		return errors.New("unknown escape")
	}
	return nil
}

func (p *parser) hexEscape(sb *strings.Builder, n int, unicode bool) error {
	if p.i+n > len(p.src) {
		return errors.New("bad escape")
	}
	v, err := strconv.ParseUint(string(p.src[p.i:p.i+n]), 16, 32)
	if err != nil {
		return errors.New("bad escape")
	}
	p.i += n
	if !unicode {
		sb.WriteByte(byte(v))
		return nil
	}
	if !utf8.ValidRune(rune(v)) {
		return errors.New("bad unicode escape")
	}
	sb.WriteRune(rune(v))
	return nil
}

func (p *parser) ident() string {
	start := p.i
	for p.i < len(p.src) {
		c := p.src[p.i]
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (p.i > start && c >= '0' && c <= '9') {
			p.i++
			continue
		}
		break
	}
	return string(p.src[start:p.i])
}

func (p *parser) peek() byte { return p.at(0) }

func (p *parser) at(n int) byte {
	if p.i+n < len(p.src) {
		return p.src[p.i+n]
	}
	return 0
}

func (p *parser) eat(c byte) bool {
	if p.i < len(p.src) && p.src[p.i] == c {
		p.i++
		return true
	}
	return false
}

// skipSpaces skips spaces and tabs only.
func (p *parser) skipSpaces() {
	for p.i < len(p.src) && (p.src[p.i] == ' ' || p.src[p.i] == '\t') {
		p.i++
	}
}

// skipSpace skips whitespace, newlines and comments. It is used inside a call, where
// line breaks do not end the statement.
func (p *parser) skipSpace() {
	for p.i < len(p.src) {
		switch p.src[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		case '\\':
			if p.at(1) == '\n' || (p.at(1) == '\r' && p.at(2) == '\n') {
				p.i += 2
				continue
			}
			return
		case '#':
			p.skipComment()
		default:
			return
		}
	}
}

// skipBlank skips whitespace, comments and stray semicolons between statements.
func (p *parser) skipBlank() {
	for p.i < len(p.src) {
		switch p.src[p.i] {
		case ' ', '\t', '\n', '\r', ';':
			p.i++
		case '#':
			p.skipComment()
		default:
			return
		}
	}
}

func (p *parser) skipComment() {
	for p.i < len(p.src) && p.src[p.i] != '\n' {
		p.i++
	}
}

// endOfStatement returns the end offset of a statement that stopped at i: past the
// closing ")", then trailing spaces, an optional ";" and comment, and the newline. When
// another statement follows on the same line, the span stops before it.
func (p *parser) endOfStatement(i int) int {
	src := p.src
	j := i
	for j < len(src) && (src[j] == ' ' || src[j] == '\t') {
		j++
	}
	if j < len(src) && src[j] == ';' {
		j++
		for j < len(src) && (src[j] == ' ' || src[j] == '\t') {
			j++
		}
	}
	switch {
	case j >= len(src):
		return len(src)
	case src[j] == '#':
		for j < len(src) && src[j] != '\n' {
			j++
		}
	case src[j] == '\r' && j+1 < len(src) && src[j+1] == '\n':
	case src[j] == '\n':
	default:
		return j // another statement on this line
	}
	if j < len(src) && src[j] == '\r' {
		j++
	}
	if j < len(src) && src[j] == '\n' {
		j++
	}
	return j
}

func lineStart(src []byte, i int) int {
	for i > 0 && src[i-1] != '\n' {
		i--
	}
	return i
}

func lineOf(src []byte, i int) int {
	n := 1
	for _, c := range src[:min(i, len(src))] {
		if c == '\n' {
			n++
		}
	}
	return n
}

// recoverEnd finds where a statement that failed to parse ends, so that one bad
// statement does not hide the ones after it. It reads to the end of the logical line
// (brackets and strings balanced) and stops early at a line that starts like a new
// call in column 0.
func recoverEnd(src []byte, from int) int {
	depth := 0
	i := from
	for i < len(src) {
		c := src[i]
		switch c {
		case '"', '\'':
			i = skipStringLoose(src, i)
			continue
		case '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '\n':
			if depth <= 0 || startsCall(src, i+1) {
				return i
			}
		}
		i++
	}
	return len(src)
}

// skipStringLoose skips a string literal for error recovery. A plain string ends at
// the line break; a triple-quoted string ends at its closing quotes.
func skipStringLoose(src []byte, i int) int {
	q := src[i]
	if i+2 < len(src) && src[i+1] == q && src[i+2] == q {
		i += 3
		for i < len(src) {
			if src[i] == '\\' {
				i += 2
				continue
			}
			if src[i] == q && i+2 < len(src) && src[i+1] == q && src[i+2] == q {
				return i + 3
			}
			i++
		}
		return len(src)
	}
	i++
	for i < len(src) && src[i] != '\n' {
		if src[i] == '\\' {
			i += 2
			continue
		}
		if src[i] == q {
			return i + 1
		}
		i++
	}
	return min(i, len(src))
}

// startsCall reports whether src[i:] begins with name( in column 0.
func startsCall(src []byte, i int) bool {
	j := i
	for j < len(src) && (src[j] == '_' || (src[j] >= 'a' && src[j] <= 'z') || (src[j] >= 'A' && src[j] <= 'Z') || (j > i && src[j] >= '0' && src[j] <= '9')) {
		j++
	}
	return j > i && j < len(src) && src[j] == '('
}
