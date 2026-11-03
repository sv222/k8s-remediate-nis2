package prowler

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/sv222/k8s-remediate-nis2/internal/finding"
)

const ocsfStatusSuppressed = 3

var Formats = []string{"auto", "ocsf", "json", "asff"}

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
	AccountID       string `json:"AccountId"`
	Muted           bool   `json:"Muted"`
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
	Status       string `json:"status"`
	StatusID     int    `json:"status_id"`
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
		Region  string `json:"region"`
		Account struct {
			UID string `json:"uid"`
		} `json:"account"`
	} `json:"cloud"`
}

type asffRecord struct {
	ID            string `json:"Id"`
	GeneratorID   string `json:"GeneratorId"`
	AwsAccountID  string `json:"AwsAccountId"`
	Title         string `json:"Title"`
	Description   string `json:"Description"`
	Region        string `json:"Region"`
	ProductFields struct {
		ProwlerResourceName string `json:"ProwlerResourceName"`
	} `json:"ProductFields"`
	Severity struct {
		Label string `json:"Label"`
	} `json:"Severity"`
	Resources []struct {
		ID     string `json:"Id"`
		Region string `json:"Region"`
	} `json:"Resources"`
	Compliance struct {
		Status string `json:"Status"`
	} `json:"Compliance"`
	Workflow struct {
		Status string `json:"Status"`
	} `json:"Workflow"`
}

func Parse(data []byte, sourceFile string) ([]finding.Finding, error) {
	return ParseFormat(data, sourceFile, "auto")
}

func ParseFormat(data []byte, sourceFile, format string) ([]finding.Finding, error) {
	if !slices.Contains(Formats, format) {
		return nil, fmt.Errorf("unknown Prowler input format %q: use one of %s", format, strings.Join(Formats, ", "))
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("%s: empty file", sourceFile)
	}
	if trimmed[0] != '[' {
		return nil, fmt.Errorf("%s: unsupported Prowler layout: expected a JSON array of findings as written by `prowler -M json-ocsf`, `prowler -M json-asff` or legacy `prowler -M json`", sourceFile)
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
		f, err := parseRecord(e, format)
		if err != nil {
			return nil, fmt.Errorf("%s: record %d: %w", sourceFile, i, err)
		}
		f.SourceFile = sourceFile
		out = append(out, f)
	}
	return out, nil
}

func parseRecord(raw json.RawMessage, format string) (finding.Finding, error) {
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
	detected := ""
	switch {
	case has("finding_info", "status_code"):
		detected = "ocsf"
	case has("FindingUniqueId", "CheckID"):
		detected = "json"
	case has("SchemaVersion", "ProductArn", "GeneratorId"):
		detected = "asff"
	default:
		return finding.Finding{}, errors.New("unsupported Prowler record layout: expected legacy keys (CheckID, Status), OCSF keys (finding_info, status_code) or ASFF keys (SchemaVersion, GeneratorId)")
	}
	if format != "auto" && format != detected {
		return finding.Finding{}, fmt.Errorf("record is %s, but --input-format is %s", detected, format)
	}
	switch detected {
	case "ocsf":
		return parseOCSF(raw)
	case "json":
		return parseLegacy(raw)
	}
	return parseASFF(raw)
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
		Suppressed:  r.Muted || isSuppressed(r.Status, 0),
		AccountID:   strings.TrimSpace(r.AccountID),
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
		Suppressed:  isSuppressed(r.Status, r.StatusID),
		AccountID:   strings.TrimSpace(r.Cloud.Account.UID),
		ResourceID:  res,
		Region:      region,
		Severity:    strings.ToLower(r.Severity),
		Service:     service,
		Description: desc,
	}, nil
}

func parseASFF(raw json.RawMessage) (finding.Finding, error) {
	var r asffRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return finding.Finding{}, err
	}
	check, ok := strings.CutPrefix(r.GeneratorID, "prowler-")
	if !ok || check == "" || r.Compliance.Status == "" {
		return finding.Finding{}, errors.New("ASFF record without a Prowler GeneratorId (prowler-<check>) or Compliance.Status")
	}
	uid := r.ProductFields.ProwlerResourceName
	region := r.Region
	if len(r.Resources) > 0 {
		if uid == "" {
			uid = r.Resources[0].ID
		}
		if r.Resources[0].Region != "" {
			region = r.Resources[0].Region
		}
	}
	account := strings.TrimSpace(r.AwsAccountID)
	status := normStatus(r.Compliance.Status)
	switch status {
	case "PASSED":
		status = "PASS"
	case "FAILED":
		status = "FAIL"
	case "NOT_AVAILABLE":
		status = "MANUAL"
	}
	service, _, _ := strings.Cut(check, "_")
	return finding.Finding{
		Scanner:     "prowler",
		CheckID:     check,
		FindingUID:  r.ID,
		Title:       r.Title,
		Status:      status,
		Suppressed:  status == "WARNING" || isSuppressed(r.Workflow.Status, 0),
		AccountID:   account,
		ResourceID:  arnName(uid, account),
		Region:      region,
		Severity:    strings.ToLower(r.Severity.Label),
		Service:     service,
		Description: r.Description,
	}, nil
}

func arnName(uid, account string) string {
	parts := strings.SplitN(uid, ":", 6)
	if len(parts) < 6 || parts[0] != "arn" {
		return uid
	}
	res := parts[5]
	if i := strings.LastIndexAny(res, "/:"); i >= 0 {
		return res[i+1:]
	}
	if parts[2] == "s3" || account == "" {
		return res
	}
	return account
}

func isSuppressed(status string, statusID int) bool {
	if statusID == ocsfStatusSuppressed {
		return true
	}
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "SUPPRESSED", "MUTED":
		return true
	}
	return false
}

func normStatus(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}
