package out

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/sv222/k8s-remediate-nis2/internal/version"
)

const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	ShortDescription sarifText      `json:"shortDescription"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine int `json:"startLine"`
		} `json:"region"`
	} `json:"physicalLocation"`
}

func SARIF(rep Report, outDir string) ([]byte, error) {
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "k8s-remediate-nis2",
			Version:        version.Get(),
			InformationURI: "https://github.com/sv222/k8s-remediate-nis2",
			Rules:          []sarifRule{},
		}},
		Results: []sarifResult{},
	}
	index := map[string]int{}
	for _, r := range rep.Rows {
		id := r.Scanner + "/" + r.CheckID
		i, ok := index[id]
		if !ok {
			i = len(run.Tool.Driver.Rules)
			index[id] = i
			desc := r.Title
			if desc == "" {
				desc = r.Scanner + " check " + r.CheckID
			}
			rule := sarifRule{ID: id, ShortDescription: sarifText{desc}}
			if len(r.Articles) > 0 {
				rule.Properties = map[string]any{"articles": r.Articles}
			}
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
		}
		uri := r.Source
		if len(r.Files) > 0 {
			uri = filepath.Join(outDir, filepath.FromSlash(r.Files[0]))
		}
		var loc sarifLocation
		loc.PhysicalLocation.ArtifactLocation.URI = sarifURI(uri)
		loc.PhysicalLocation.Region.StartLine = 1
		msg := r.Status + ": " + r.CheckID + " on " + r.ResourceID
		if r.Note != "" {
			msg += ". " + r.Note
		}
		fp := sha256.Sum256([]byte(strings.Join([]string{r.Scanner, r.CheckID, r.Account, r.Region, r.ResourceID}, "\x00")))
		props := map[string]any{"status": r.Status, "resource": r.ResourceID, "severity": r.Severity}
		for k, v := range map[string]string{"region": r.Region, "account": r.Account} {
			if v != "" {
				props[k] = v
			}
		}
		if len(r.Files) > 0 {
			props["files"] = r.Files
		}
		run.Results = append(run.Results, sarifResult{
			RuleID:              id,
			RuleIndex:           i,
			Level:               sarifLevel(r.Severity),
			Message:             sarifText{msg},
			Locations:           []sarifLocation{loc},
			PartialFingerprints: map[string]string{"findingHash/v1": hex.EncodeToString(fp[:])},
			Properties:          props,
		})
	}
	data, err := json.MarshalIndent(sarifLog{Schema: sarifSchema, Version: "2.1.0", Runs: []sarifRun{run}}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func sarifURI(p string) string {
	s := filepath.ToSlash(p)
	if !filepath.IsAbs(p) {
		return (&url.URL{Path: strings.TrimPrefix(s, "./")}).String()
	}
	if !strings.HasPrefix(s, "/") {
		s = "/" + s
	}
	return (&url.URL{Scheme: "file", Path: s}).String()
}

func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	}
	return "note"
}
