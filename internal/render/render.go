package render

import (
	"bytes"
	"fmt"
	"path"
	"regexp"
	"strings"
	"text/template"

	"github.com/nis2rem/k8s-remediate-nis2/internal/finding"
	"github.com/nis2rem/k8s-remediate-nis2/mapping"
)

var sanitizeRe = regexp.MustCompile(`[^A-Za-z0-9_]`)

type RenderedFile struct {
	RelPath string
	Content string
}

type tplData struct {
	mapping.Entry
	Finding             finding.Finding
	Scanner             string
	CheckID             string
	Title               string
	Articles            []string
	ResourceID          string
	SanitizedResourceID string
}

// SanitizeResourceID makes an identifier safe for terraform resource names.
// Empty ID falls back to a placeholder the engineer fills in.
func SanitizeResourceID(id string) string {
	if id == "" {
		return "RESOURCE_IDENTIFIER"
	}
	s := sanitizeRe.ReplaceAllString(id, "_")
	s = strings.TrimLeft(s, "_0123456789") // must not start with digit for tf names
	if s == "" {
		return "RESOURCE_IDENTIFIER"
	}
	return s
}

// Render executes every template of entry e against finding f.
func Render(e mapping.Entry, f finding.Finding) ([]RenderedFile, error) {
	data := tplData{
		Entry: e, Finding: f,
		Scanner: f.Scanner, CheckID: f.CheckID, Title: e.Title,
		Articles: e.Articles, ResourceID: orPlaceholder(f.ResourceID),
		SanitizedResourceID: SanitizeResourceID(f.ResourceID),
	}
	var out []RenderedFile
	for _, rel := range e.Templates {
		raw, err := mapping.TemplatesFS.ReadFile("templates/" + rel)
		if err != nil {
			return nil, err
		}
		tpl, err := template.New(path.Base(rel)).Parse(string(raw))
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", rel, err)
		}
		var buf bytes.Buffer
		if err := tpl.Execute(&buf, data); err != nil {
			return nil, fmt.Errorf("template %s: %w", rel, err)
		}
		out = append(out, RenderedFile{RelPath: rel, Content: buf.String()})
	}
	return out, nil
}

func orPlaceholder(id string) string {
	if strings.TrimSpace(id) == "" {
		return "<RESOURCE_IDENTIFIER>"
	}
	return id
}
