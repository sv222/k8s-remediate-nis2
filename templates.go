// Package templates embeds the remediation template tree (templates/**).
//
// The embed directive lives at the repository root because Go's embed
// cannot reference parent directories; mapping re-exports it as
// mapping.TemplatesFS.
package templates

import "embed"

//go:embed templates
var FS embed.FS
