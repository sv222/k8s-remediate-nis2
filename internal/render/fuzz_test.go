package render

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/sv222/k8s-remediate-nis2/internal/finding"
	"github.com/sv222/k8s-remediate-nis2/mapping"
)

func hclProblem(src string) string {
	depth := 0
	for n, line := range strings.Split(src, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		inStr := false
		for i := 0; i < len(line); i++ {
			c := line[i]
			if inStr {
				switch c {
				case '"':
					inStr = false
				case '\\':
					i++
				}
				continue
			}
			switch c {
			case '"':
				inStr = true
			case '{':
				depth++
			case '}':
				depth--
				if depth < 0 {
					return fmt.Sprintf("line %d: unbalanced }", n+1)
				}
			}
		}
		if inStr {
			return fmt.Sprintf("line %d: unterminated string", n+1)
		}
	}
	if depth != 0 {
		return "unbalanced braces"
	}
	return ""
}

func checkFiles(t *testing.T, files []RenderedFile, id string) {
	t.Helper()
	for _, f := range files {
		if !isLocal(f.RelPath) || strings.ContainsAny(f.RelPath, "\\\x00") {
			t.Fatalf("path %q is not local", f.RelPath)
		}
		if strings.HasSuffix(f.RelPath, ".tf") {
			for _, bad := range []string{"0.0.0.0/0", "::/0"} {
				if strings.Contains(f.Content, bad) {
					t.Fatalf("%s contains %s", f.RelPath, bad)
				}
			}
			if p := hclProblem(f.Content); p != "" {
				t.Fatalf("%s for id %q: %s\n%s", f.RelPath, id, p, f.Content)
			}
		}
		if strings.HasSuffix(f.RelPath, ".yaml") {
			var doc map[string]any
			if err := yaml.Unmarshal([]byte(f.Content), &doc); err != nil {
				t.Fatalf("%s: %v", f.RelPath, err)
			}
		}
	}
}

func FuzzRender(f *testing.F) {
	for _, s := range [][2]string{
		{"company-assets", "us-east-1"}, {"arn:aws:s3:::bucket/key", "eu-west-1"}, {"sg-0a1b2c3d4e5f60718", "us-gov-west-1"},
		{"arn:aws:ec2:eu-central-1:123456789012:security-group/sg-0a1", "eu-central-1"},
		{"", ""}, {"b\"\n}\nresource \"x\" \"y\" {", "us-east-1"}, {"a${var.x}", "x\"y"}, {"UPPER.case_Mix", "ap-southeast-2"},
		{"000000000000", "us-east-1"}, {"../../etc/passwd", "us-east-1"}, {"a b", "us-east-1"}, {strings.Repeat("a", 300), "us-east-1"},
	} {
		f.Add(s[0], s[1])
	}
	entries, err := mapping.Load()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, id, region string) {
		for _, e := range entries {
			files, err := Render(e, finding.Finding{ResourceID: id, Region: region})
			if err != nil {
				if !errors.Is(err, ErrInvalidResourceID) {
					t.Fatalf("%s: unexpected error %v", e.Title, err)
				}
				if files != nil {
					t.Fatal("files returned together with an error")
				}
				continue
			}
			checkFiles(t, files, id)
		}
	})
}

func FuzzSanitizeResourceID(f *testing.F) {
	for _, s := range []string{"", "a", "a.b", "a_b", "Bucket", "bucket", "BUCKET", "sg-0abc", strings.Repeat("x", 100), "ü", "a/b", "unknown_e3b0c442", "..", "-", "a\x00b"} {
		f.Add(s, s+"x")
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		sa := SanitizeResourceID(a)
		if sa == "" || len(sa) > maxNameLen+9 || sa != strings.ToLower(sa) {
			t.Fatalf("bad name %q for %q", sa, a)
		}
		for _, r := range sa {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
				t.Fatalf("name %q for %q has character %q", sa, a, r)
			}
		}
		if SanitizeResourceID(a) != sa {
			t.Fatal("not deterministic")
		}
		p := ResourcePath("terraform/x.tf", a)
		if !isLocal(p) || path.Dir(p) != "terraform" || strings.Count(p, "/") != 1 {
			t.Fatalf("path %q escapes its directory", p)
		}
		if a != b && a != "" && b != "" && strings.EqualFold(SanitizeResourceID(b), sa) {
			t.Fatalf("%q and %q map to the same name %q", a, b, sa)
		}
		n := NormalizeResourceID(a)
		if ValidateResourceID(a) == nil && ValidateResourceID(n) != nil && n != a {
			t.Fatalf("normalizing a valid id %q gave an invalid id %q", a, n)
		}
	})
}

func isLocal(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "." || seg == "" {
			return false
		}
	}
	return true
}
