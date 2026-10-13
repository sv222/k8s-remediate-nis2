package finding

type Finding struct {
	Scanner     string `json:"scanner"`
	CheckID     string `json:"check_id"`
	Status      string `json:"status"`
	ResourceID  string `json:"resource_id"`
	Region      string `json:"region"`
	Severity    string `json:"severity"`
	Service     string `json:"service"`
	Description string `json:"description"`
	SourceFile  string `json:"-"`
}
