package render

import (
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sv222/k8s-remediate-nis2/internal/finding"
	"github.com/sv222/k8s-remediate-nis2/mapping"
)

const (
	validAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/@+=,-"
	anyAlphabet   = validAlphabet + " \"\n\\${}%;<>|`'!*[]()\t\x00ü"
)

var regions = []string{"us-east-1", "eu-west-1", "eu-central-1", "ap-southeast-2", "us-gov-west-1", "Us-East-1", "x", ""}

func randomID(r *rand.Rand, alphabet string) string {
	n := r.Intn(40)
	if r.Intn(30) == 0 {
		n = 250 + r.Intn(20)
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	switch r.Intn(6) {
	case 0:
		return "arn:aws:s3:::" + string(b)
	case 1:
		return "arn:aws:ec2:us-east-1:123456789012:security-group/sg-" + string(b)
	}
	return string(b)
}

func renderAll(t *testing.T, ids []string, r *rand.Rand) *Set {
	t.Helper()
	entries, err := mapping.Load()
	if err != nil {
		t.Fatal(err)
	}
	set := NewSet()
	for _, id := range ids {
		region := regions[r.Intn(len(regions))]
		for _, e := range entries {
			files, err := Render(e, finding.Finding{ResourceID: id, Region: region})
			if err != nil {
				continue
			}
			checkFiles(t, files, id)
			set.Add(files)
		}
	}
	return set
}

func TestPropertyNoInternetWideCIDRForAnyInput(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	var ids []string
	for i := 0; i < 400; i++ {
		ids = append(ids, randomID(r, anyAlphabet), randomID(r, validAlphabet))
	}
	ids = append(ids, "0.0.0.0/0", "::/0", "sg-0.0.0.0/0", "arn:aws:s3:::0.0.0.0/0")
	files, err := renderAll(t, ids, r).Files()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f.RelPath, ".tf") && (strings.Contains(f.Content, "0.0.0.0/0") || strings.Contains(f.Content, "::/0")) {
			t.Errorf("%s contains an internet-wide CIDR", f.RelPath)
		}
	}
}

func TestPropertyFileNamesAreLocalAndCaseInsensitivelyUnique(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	var ids []string
	for i := 0; i < 600; i++ {
		ids = append(ids, randomID(r, validAlphabet))
	}
	ids = append(ids, "Bucket", "bucket", "BUCKET", "a.b", "a_b", "a:b", "A.B", "sg-ABC", "sg-abc")
	files, err := renderAll(t, ids, r).Files()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, f := range files {
		low := strings.ToLower(f.RelPath)
		if prev, ok := seen[low]; ok {
			t.Errorf("%s and %s collide on a case-insensitive file system", prev, f.RelPath)
		}
		seen[low] = f.RelPath
	}
	if len(files) < 100 {
		t.Errorf("only %d files rendered", len(files))
	}
}

func TestPropertyTerraformCheckCorpus(t *testing.T) {
	dir := os.Getenv("TFCHECK_DIR")
	if dir == "" {
		t.Skip("TFCHECK_DIR is not set")
	}
	r := rand.New(rand.NewSource(3))
	var ids []string
	for i := 0; i < 12; i++ {
		bucket := "b" + randomString(r, "abcdefghijklmnopqrstuvwxyz0123456789", 3+r.Intn(30)) + "." + randomString(r, "abcdefghijklmnopqrstuvwxyz0123456789-", 2+r.Intn(10)) + "x"
		ids = append(ids, bucket, "sg-"+randomString(r, "0123456789abcdef", 8+r.Intn(10)), "arn:aws:s3:::"+bucket+"/some/key")
	}
	ids = append(ids, "a.b-c", "a:b@c+d=e,f", "000000000000")
	files, err := renderAll(t, ids, r).Files()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if !strings.HasPrefix(f.RelPath, "terraform/") {
			continue
		}
		p := filepath.Join(dir, filepath.FromSlash(f.RelPath))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(f.Content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func randomString(r *rand.Rand, alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}
