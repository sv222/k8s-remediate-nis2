package out

import (
	"strings"
	"testing"
)

func unescapedPipes(s string) int {
	return unescaped(s, '|')
}

func unescaped(s string, want rune) int {
	n := 0
	bs := 0
	for _, r := range s {
		if r == '\\' {
			bs++
			continue
		}
		if r == want && bs%2 == 0 {
			n++
		}
		bs = 0
	}
	return n
}

var markdownSeeds = []string{
	"", "plain", "a|b", "![x](https://attacker.example/p.png)", "[l](javascript:alert(1))", "`code`", "a\nb\r\nc", "<img src=x onerror=1>",
	"**b** _i_ ~~s~~", "back\\slash\\", "\\|", "||", "s3_bucket", "u x", "\x00", "[[x]]", "!![", strings.Repeat("`", 5),
}

func FuzzCell(f *testing.F) {
	for _, s := range markdownSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := cell(s)
		if strings.ContainsAny(got, "\n\r<>") {
			t.Fatalf("raw newline or angle bracket in %q", got)
		}
		if unescapedPipes(got) != 0 {
			t.Fatalf("unescaped pipe in %q", got)
		}
		for _, c := range []rune{'[', ']', '`', '*', '!'} {
			if unescaped(got, c) != 0 {
				t.Fatalf("unescaped %q in %q", c, got)
			}
		}
	})
}

func FuzzCode(f *testing.F) {
	for _, s := range markdownSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := code(s)
		if got == "" {
			return
		}
		if len(got) < 3 || got[0] != '`' || got[len(got)-1] != '`' {
			t.Fatalf("not a code span: %q", got)
		}
		for _, r := range got[1 : len(got)-1] {
			if r != '?' && !isTokenRune(r) {
				t.Fatalf("code(%q) = %q has %q", s, got, r)
			}
		}
		if strings.Count(got, "`") != 2 {
			t.Fatalf("stray backtick in %q", got)
		}
	})
}

func FuzzMappingTableKeepsItsShape(f *testing.F) {
	for _, s := range markdownSeeds {
		f.Add(s, s, s, s)
	}
	f.Fuzz(func(t *testing.T, check, resource, note, article string) {
		rep := Report{Rows: []SummaryRow{{
			Scanner: "prowler", CheckID: check, ResourceID: resource, Region: resource, Account: check, Severity: note,
			Articles: []string{article}, Files: []string{resource}, Status: StatusNoMapping, Note: note,
		}}, Manual: []Item{{Scanner: "x", CheckID: check, ResourceID: resource}}}
		for name, doc := range map[string]string{"mapping": mappingMD(rep), "evidence": evidenceMD(nil, rep, testTime)} {
			rows := 0
			for _, line := range strings.Split(doc, "\n") {
				isRow := strings.HasPrefix(line, "| `prowler` |")
				isItem := strings.HasPrefix(line, "| `x` |")
				if !isRow && !isItem {
					continue
				}
				want := 8
				if name == "evidence" {
					want = 11
				}
				if isItem {
					want = 7
				}
				if isRow {
					rows++
				}
				if got := unescapedPipes(line); got != want {
					t.Fatalf("%s: %d separators, want %d: %q", name, got, want, line)
				}
				if strings.Contains(line, "![") {
					t.Fatalf("%s: image syntax in %q", name, line)
				}
			}
			if rows != 1 {
				t.Fatalf("%s: %d rows for input %q %q", name, rows, check, resource)
			}
		}
	})
}
