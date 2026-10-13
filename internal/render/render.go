package render

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"text/template"

	"github.com/nis2rem/k8s-remediate-nis2/internal/finding"
	"github.com/nis2rem/k8s-remediate-nis2/mapping"
)

const (
	maxResourceIDLen = 256
	maxNameLen       = 64
	placeholderName  = "RESOURCE_IDENTIFIER"
)

var (
	ErrInvalidResourceID = errors.New("invalid resource id")

	resourceIDRe = regexp.MustCompile(`^[A-Za-z0-9._:/@+=,-]+$`)
	sanitizeRe   = regexp.MustCompile(`[^A-Za-z0-9_-]`)
)

type RenderedFile struct {
	RelPath string
	Content string
}

type resourceData struct {
	Title               string
	Articles            []string
	ResourceID          string
	SanitizedResourceID string
}

func ValidateResourceID(id string) error {
	if id == "" {
		return nil
	}
	if len(id) > maxResourceIDLen {
		return fmt.Errorf("%w: longer than %d characters", ErrInvalidResourceID, maxResourceIDLen)
	}
	if !resourceIDRe.MatchString(id) {
		return fmt.Errorf("%w: %q contains characters outside [A-Za-z0-9._:/@+=,-]", ErrInvalidResourceID, id)
	}
	return nil
}

func NormalizeResourceID(id string) string {
	if !strings.HasPrefix(id, "arn:") {
		return id
	}
	parts := strings.SplitN(id, ":", 6)
	if len(parts) != 6 {
		return id
	}
	switch parts[2] {
	case "s3":
		bucket, _, _ := strings.Cut(parts[5], "/")
		return bucket
	case "ec2":
		if sg, ok := strings.CutPrefix(parts[5], "security-group/"); ok {
			return sg
		}
	}
	return id
}

func SanitizeResourceID(id string) string {
	if id == "" {
		return placeholderName
	}
	s := sanitizeRe.ReplaceAllString(id, "_")
	if len(s) > maxNameLen {
		s = s[:maxNameLen]
	}
	if s != id {
		sum := sha256.Sum256([]byte(id))
		s += "_" + hex.EncodeToString(sum[:])[:6]
	}
	return s
}

func ResourcePath(tpl, resourceID string) string {
	dir, file := path.Split(tpl)
	ext := path.Ext(file)
	base := strings.TrimSuffix(file, ext)
	return dir + base + "__" + SanitizeResourceID(resourceID) + ext
}

func Render(e mapping.Entry, f finding.Finding) ([]RenderedFile, error) {
	var out []RenderedFile
	if len(e.Templates) > 0 {
		if err := ValidateResourceID(f.ResourceID); err != nil {
			return nil, err
		}
		id := NormalizeResourceID(f.ResourceID)
		data := resourceData{
			Title:               e.Title,
			Articles:            e.Articles,
			ResourceID:          orPlaceholder(id),
			SanitizedResourceID: SanitizeResourceID(id),
		}
		for _, rel := range e.Templates {
			content, err := execute(rel, data)
			if err != nil {
				return nil, err
			}
			out = append(out, RenderedFile{RelPath: ResourcePath(rel, id), Content: content})
		}
	}
	for _, rel := range e.SharedTemplates {
		content, err := execute(rel, struct{}{})
		if err != nil {
			return nil, err
		}
		out = append(out, RenderedFile{RelPath: rel, Content: content})
	}
	return out, nil
}

func execute(rel string, data any) (string, error) {
	raw, err := mapping.TemplatesFS.ReadFile("templates/" + rel)
	if err != nil {
		return "", err
	}
	tpl, err := template.New(path.Base(rel)).Option("missingkey=error").Parse(string(raw))
	if err != nil {
		return "", fmt.Errorf("template %s: %w", rel, err)
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("template %s: %w", rel, err)
	}
	return buf.String(), nil
}

func orPlaceholder(id string) string {
	if strings.TrimSpace(id) == "" {
		return "<" + placeholderName + ">"
	}
	return id
}

type Set struct {
	files map[string]RenderedFile
}

func NewSet() *Set {
	return &Set{files: map[string]RenderedFile{}}
}

func (s *Set) Add(files []RenderedFile) {
	for _, f := range files {
		if _, exists := s.files[f.RelPath]; !exists {
			s.files[f.RelPath] = f
		}
	}
}

func (s *Set) Files() []RenderedFile {
	out := make([]RenderedFile, 0, len(s.files))
	for _, f := range s.files {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RelPath < out[j].RelPath })
	return out
}
