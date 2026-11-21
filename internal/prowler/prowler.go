package prowler

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/sv222/k8s-remediate-nis2/internal/finding"
)

const ocsfStatusSuppressed = 3

var Formats = []string{"auto", "ocsf", "json", "asff"}

// SupportedProviders lists the Prowler providers whose findings the tool
// reads. Other providers are skipped and reported, so a mixed report of one
// supported provider still works.
var SupportedProviders = []string{"aws", "kubernetes"}

// UnsupportedProvider counts the records of one unsupported provider in a report.
type UnsupportedProvider struct {
	Provider string
	Records  int
}

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
	UID       string `json:"uid"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Namespace string `json:"namespace"`
	Region    string `json:"region"`
	Group     struct {
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
		Provider string `json:"provider"`
		Region   string `json:"region"`
		Account  struct {
			UID string `json:"uid"`
		} `json:"account"`
	} `json:"cloud"`
	Unmapped struct {
		Provider    string `json:"provider"`
		ProviderUID string `json:"provider_uid"`
	} `json:"unmapped"`
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
	fs, _, err := ParseFormatStats(data, sourceFile, "auto")
	return fs, err
}

func ParseFormat(data []byte, sourceFile, format string) ([]finding.Finding, error) {
	fs, _, err := ParseFormatStats(data, sourceFile, format)
	return fs, err
}

func ParseFormatStats(data []byte, sourceFile, format string) ([]finding.Finding, []UnsupportedProvider, error) {
	if !slices.Contains(Formats, format) {
		return nil, nil, fmt.Errorf("unknown Prowler input format %q: use one of %s", format, strings.Join(Formats, ", "))
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, nil, fmt.Errorf("%s: empty file", sourceFile)
	}
	if trimmed[0] != '[' {
		return nil, nil, fmt.Errorf("%s: unsupported Prowler layout: expected a JSON array of findings as written by `prowler -M json-ocsf`, `prowler -M json-asff` or legacy `prowler -M json`", sourceFile)
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(trimmed, &elems); err != nil {
		return nil, nil, fmt.Errorf("%s: invalid JSON: %w", sourceFile, err)
	}
	if len(elems) == 0 {
		return nil, nil, errors.New("no findings in prowler file: " + sourceFile)
	}
	out := make([]finding.Finding, 0, len(elems))
	skipped := map[string]int{}
	for i, e := range elems {
		f, err := parseRecord(e, format)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: record %d: %w", sourceFile, i, err)
		}
		f.SourceFile = sourceFile
		if !slices.Contains(SupportedProviders, f.Provider) {
			skipped[f.Provider]++
			continue
		}
		out = append(out, f)
	}
	stats := unsupportedStats(skipped)
	if len(out) == 0 && len(stats) > 0 {
		names := make([]string, 0, len(stats))
		records := 0
		for _, u := range stats {
			names = append(names, u.Provider)
			records += u.Records
		}
		return nil, stats, fmt.Errorf("%s: all %d records are of unsupported provider(s) %s: no findings to remediate", sourceFile, records, strings.Join(names, ", "))
	}
	return out, stats, nil
}

func unsupportedStats(skipped map[string]int) []UnsupportedProvider {
	if len(skipped) == 0 {
		return nil
	}
	stats := make([]UnsupportedProvider, 0, len(skipped))
	for _, p := range slices.Sorted(maps.Keys(skipped)) {
		stats = append(stats, UnsupportedProvider{Provider: p, Records: skipped[p]})
	}
	return stats
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
		Provider:    "aws",
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
	provider := ocsfProvider(&r)
	var res, region, service string
	if len(r.Resources) > 0 {
		first := r.Resources[0]
		res = first.Name
		if res == "" {
			res = first.UID
		}
		region = first.Region
		service = first.Group.Name
		if provider == "kubernetes" {
			res = kubernetesResourceID(first, strings.TrimSpace(r.Unmapped.ProviderUID))
		}
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
		Provider:    provider,
		Severity:    strings.ToLower(r.Severity),
		Service:     service,
		Description: desc,
	}, nil
}

// ocsfProvider reads the provider field Prowler writes into the OCSF record.
// Kubernetes records carry it in unmapped.provider, AWS records also in
// cloud.provider. Reports without the field are older AWS reports.
func ocsfProvider(r *ocsfRecord) string {
	p := strings.ToLower(strings.TrimSpace(r.Unmapped.Provider))
	if p == "" {
		p = strings.ToLower(strings.TrimSpace(r.Cloud.Provider))
	}
	if p == "" {
		return "aws"
	}
	return p
}

// kubernetesResourceID builds namespace/kind/name for namespaced objects.
// Cluster-scoped objects (namespace cluster-wide or empty) are reported under
// the cluster name, or cluster when the report has none.
func kubernetesResourceID(res ocsfResource, cluster string) string {
	name := res.Name
	if name == "" {
		name = res.UID
	}
	kind := strings.TrimSpace(res.Type)
	ns := strings.TrimSpace(res.Namespace)
	if ns == "" || ns == "cluster-wide" || kind == "" || name == "" {
		if cluster != "" {
			return cluster
		}
		return "cluster"
	}
	return ns + "/" + kind + "/" + name
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
		Provider:    "aws",
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
