package prowler

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/sv222/k8s-remediate-nis2/internal/finding"
)

type legacyRecord struct {
	FindingUniqueID string `json:"FindingUniqueId"`
	CheckID         string `json:"CheckID"`
	CheckTitle      string `json:"CheckTitle"`
	Status          string `json:"Status"`
	StatusExtended  string `json:"StatusExtended"`
	ServiceName     string `json:"ServiceName"`
	Severity        string `json:"Severity"`
	ResourceID      string `json:"ResourceId"`
	ResourceArn     string `json:"ResourceArn"`
	Region          string `json:"Region"`
	Description     string `json:"Description"`
}

type ocsfResource struct {
	UID    string `json:"uid"`
	Name   string `json:"name"`
	Region string `json:"region"`
	Group  struct {
		Name string `json:"name"`
	} `json:"group"`
}

type ocsfRecord struct {
	StatusCode   string `json:"status_code"`
	StatusDetail string `json:"status_detail"`
	Severity     string `json:"severity"`
	Message      string `json:"message"`
	Metadata     struct {
		EventCode string `json:"event_code"`
	} `json:"metadata"`
	FindingInfo struct {
		UID   string `json:"uid"`
		Title string `json:"title"`
		Desc  string `json:"desc"`
	} `json:"finding_info"`
	Resources []ocsfResource `json:"resources"`
	Cloud     struct {
		Region string `json:"region"`
	} `json:"cloud"`
}

func Parse(data []byte, sourceFile string) ([]finding.Finding, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("%s: empty file", sourceFile)
	}
	if trimmed[0] != '[' {
		return nil, fmt.Errorf("%s: unsupported Prowler layout: expected a JSON array of findings as written by `prowler -M json-ocsf` or legacy `prowler -M json`", sourceFile)
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(trimmed, &elems); err != nil {
		return nil, fmt.Errorf("%s: invalid JSON: %w", sourceFile, err)
	}
	if len(elems) == 0 {
		return nil, errors.New("no findings in prowler file: " + sourceFile)
	}
	out := make([]finding.Finding, 0, len(elems))
	for i, e := range elems {
		f, err := parseRecord(e)
		if err != nil {
			return nil, fmt.Errorf("%s: record %d: %w", sourceFile, i, err)
		}
		f.SourceFile = sourceFile
		out = append(out, f)
	}
	return out, nil
}

func parseRecord(raw json.RawMessage) (finding.Finding, error) {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil || keys == nil {
		return finding.Finding{}, errors.New("not a JSON object")
	}
	has := func(names ...string) bool {
		for _, n := range names {
			if _, ok := keys[n]; ok {
				return true
			}
		}
		return false
	}
	switch {
	case has("finding_info", "status_code"):
		return parseOCSF(raw)
	case has("FindingUniqueId", "CheckID"):
		return parseLegacy(raw)
	case has("SchemaVersion", "ProductArn"):
		return finding.Finding{}, errors.New("AWS Security Finding Format (json-asff) is not supported: re-run prowler with `-M json-ocsf`")
	}
	return finding.Finding{}, errors.New("unsupported Prowler record layout: expected legacy keys (CheckID, Status) or OCSF keys (finding_info, status_code)")
}

func parseLegacy(raw json.RawMessage) (finding.Finding, error) {
	var r legacyRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return finding.Finding{}, err
	}
	if r.CheckID == "" || r.Status == "" {
		return finding.Finding{}, errors.New("legacy record without CheckID or Status")
	}
	res := r.ResourceID
	if res == "" {
		res = r.ResourceArn
	}
	desc := r.Description
	if desc == "" {
		desc = r.StatusExtended
	}
	return finding.Finding{
		Scanner:     "prowler",
		CheckID:     r.CheckID,
		FindingUID:  r.FindingUniqueID,
		Title:       r.CheckTitle,
		Status:      normStatus(r.Status),
		ResourceID:  res,
		Region:      r.Region,
		Severity:    strings.ToLower(r.Severity),
		Service:     r.ServiceName,
		Description: desc,
	}, nil
}

func parseOCSF(raw json.RawMessage) (finding.Finding, error) {
	var r ocsfRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return finding.Finding{}, err
	}
	if r.Metadata.EventCode == "" || r.StatusCode == "" {
		return finding.Finding{}, errors.New("OCSF record without metadata.event_code or status_code")
	}
	var res, region, service string
	if len(r.Resources) > 0 {
		first := r.Resources[0]
		res = first.Name
		if res == "" {
			res = first.UID
		}
		region = first.Region
		service = first.Group.Name
	}
	if region == "" {
		region = r.Cloud.Region
	}
	desc := r.FindingInfo.Desc
	if desc == "" {
		desc = r.StatusDetail
	}
	return finding.Finding{
		Scanner:     "prowler",
		CheckID:     r.Metadata.EventCode,
		FindingUID:  r.FindingInfo.UID,
		Title:       r.FindingInfo.Title,
		Status:      normStatus(r.StatusCode),
		ResourceID:  res,
		Region:      region,
		Severity:    strings.ToLower(r.Severity),
		Service:     service,
		Description: desc,
	}, nil
}

func normStatus(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}
