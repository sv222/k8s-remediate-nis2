package finding

type Finding struct {
	Scanner     string `json:"scanner"`
	CheckID     string `json:"check_id"`
	Benchmark   string `json:"benchmark,omitempty"`
	FindingUID  string `json:"finding_uid,omitempty"`
	Title       string `json:"title,omitempty"`
	Status      string `json:"status"`
	Manual      bool   `json:"manual,omitempty"`
	ResourceID  string `json:"resource_id"`
	Region      string `json:"region"`
	Severity    string `json:"severity"`
	Service     string `json:"service"`
	Description string `json:"description"`
	SourceFile  string `json:"-"`
}

func (f Finding) IsManualWarn() bool {
	return f.Manual && f.Status == "WARN"
}
