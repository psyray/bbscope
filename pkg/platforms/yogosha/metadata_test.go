package yogosha

import (
	"testing"
)

func TestExtractYogoshaMetadata_BountyProgram(t *testing.T) {
	// Fixture derived from the real Yogosha /api/programs/<id>?embed=content,audiences
	// response (FDJ France program). Trimmed to the fields metadata extraction reads.
	const fdjBody = `{
		"id": "5Mv8fvNoNIpCJcnaaiPuh7",
		"name": "FDJ France",
		"organization": {"id": "abc", "name": "FDJ United", "country": "FR", "currency": "EUR"},
		"lowReward": {"amount": "10000", "currency": "EUR"},
		"mediumReward": {"amount": "50000", "currency": "EUR"},
		"highReward": {"amount": "160000", "currency": "EUR"},
		"criticalReward": {"amount": "400000", "currency": "EUR"},
		"state": "online",
		"tags": [],
		"rewardEnabled": true,
		"rewardMandatory": true,
		"vpnRequired": true,
		"type": "bugbounty",
		"archivedAt": null,
		"asset": {"id": "x", "title": "FDJ France", "type": "webapp"},
		"scope": ["https://www.fdj.fr", "https://www.groupefdj.com", "https://play.google.com/store/apps/details?id=fr.fdj.apps.fdj"],
		"outOfScopes": ["https://www.fdj.fr/resultats-et-rapports-officiels"],
		"monitoring": {"type": "vpn"},
		"vpnIpAdresses": ["171.33.114.168", "171.33.122.249"],
		"testAccountsEnabled": false,
		"testAccountsActivated": false,
		"audiences": [{"accessMode": "open", "group": {"name": "Yogosha's Community"}}],
		"content": {
			"mission": "###### Scope rules\n\nThe program's scope is limited to technical vulnerabilities.\n\n###### Qualifying vulnerabilities:\n\n**Each report received will be analyzed.**\n\n- Remote code execution (RCE)\n- Local files access and manipulation (LFI, RFI, XXE, SSRF, XSPA)\n- Code injections (JS, SQL, PHP, ...)\n- Cross-Site Scripting (XSS) with real security impact\n- Broken authentication & session management\n\n##### About CVSS and severity\n\nThe CVSS score is imposed by Yogosha.",
			"outOfScope": "**The following issues are outside the scope of our vulnerability rewards program:**\n\n* Attacks requiring physical access to a user's device or clipboard\n* Business logic errors without security impact\n* CSRF\n* Password and account recovery policies\n* Missing security headers which do not lead directly to a vulnerability\n* Missing cookie flags",
			"terms": "**Using VPN is mandatory on this program**\n\n* Always use the X-Bug-Bounty HTTP header (details available under \"Test accounts\")\n* Do not intentionally harm the user experience including degradation of services and denial of service attacks.\n* Limit the number of queries per second on automated tests. (max. 5 per sec)\n* Do not interact with other party."
		},
		"testAccounts": {"instructions": null, "parsedInstructions": null}
	}`

	m := extractYogoshaMetadata(fdjBody, true)

	// 1. Classification & Context
	if m.Title != "FDJ France" {
		t.Errorf("Title = %q, want %q", m.Title, "FDJ France")
	}
	if m.Tagline != "FDJ France" {
		t.Errorf("Tagline = %q, want %q", m.Tagline, "FDJ France")
	}
	if m.CompanyName != "FDJ United" {
		t.Errorf("CompanyName = %q, want %q", m.CompanyName, "FDJ United")
	}
	if m.ProgramType != "bugbounty" {
		t.Errorf("ProgramType = %q, want %q", m.ProgramType, "bugbounty")
	}
	if m.IsBounty == nil || !*m.IsBounty {
		t.Error("IsBounty should be true")
	}
	if m.IsVDP != nil && *m.IsVDP {
		t.Error("IsVDP should be false for a bounty program")
	}
	if m.IsPublic == nil || !*m.IsPublic {
		t.Error("IsPublic should be true (audiences has accessMode 'open')")
	}
	if m.IsDisabled != nil && *m.IsDisabled {
		t.Error("IsDisabled should be false for state=online")
	}

	// 2. Rewards
	if m.Currency != "EUR" {
		t.Errorf("Currency = %q, want %q", m.Currency, "EUR")
	}
	if m.BountyRewardMin == nil || *m.BountyRewardMin != 100 {
		t.Errorf("BountyRewardMin = %v, want 10000", m.BountyRewardMin)
	}
	if m.BountyRewardMax == nil || *m.BountyRewardMax != 4000 {
		t.Errorf("BountyRewardMax = %v, want 400000", m.BountyRewardMax)
	}
	if len(m.RewardGrids) != 1 {
		t.Fatalf("RewardGrids len = %d, want 1", len(m.RewardGrids))
	}
	rg := m.RewardGrids[0]
	if rg.Dimension != "default" {
		t.Errorf("RewardGrid Dimension = %q, want %q", rg.Dimension, "default")
	}
	if rg.BountyLowMin == nil || *rg.BountyLowMin != 100 {
		t.Errorf("BountyLowMin = %v, want 10000", rg.BountyLowMin)
	}
	if rg.BountyMediumMax == nil || *rg.BountyMediumMax != 500 {
		t.Errorf("BountyMediumMax = %v, want 50000", rg.BountyMediumMax)
	}
	if rg.BountyHighMin == nil || *rg.BountyHighMin != 1600 {
		t.Errorf("BountyHighMin = %v, want 160000", rg.BountyHighMin)
	}
	if rg.BountyCriticalMax == nil || *rg.BountyCriticalMax != 4000 {
		t.Errorf("BountyCriticalMax = %v, want 400000", rg.BountyCriticalMax)
	}

	// 3. Scope Rules
	if m.Rules == "" {
		t.Error("Rules should not be empty (content.mission present)")
	}
	if m.RulesFormat != "markdown" {
		t.Errorf("RulesFormat = %q, want %q", m.RulesFormat, "markdown")
	}

	// Qualifying vulnerabilities parsed from mission markdown
	if len(m.QualifyingVulnerabilities) == 0 {
		t.Fatal("QualifyingVulnerabilities should not be empty")
	}
	foundRCE := false
	for _, qv := range m.QualifyingVulnerabilities {
		if contains(qv, "Remote code execution") {
			foundRCE = true
			break
		}
	}
	if !foundRCE {
		t.Error("QualifyingVulnerabilities should contain 'Remote code execution (RCE)'")
	}

	// Non-qualifying vulnerabilities parsed from outOfScope markdown
	if len(m.NonQualifyingVulnerabilities) == 0 {
		t.Fatal("NonQualifyingVulnerabilities should not be empty")
	}
	foundCSRF := false
	for _, nqv := range m.NonQualifyingVulnerabilities {
		if nqv == "CSRF" {
			foundCSRF = true
			break
		}
	}
	if !foundCSRF {
		t.Error("NonQualifyingVulnerabilities should contain 'CSRF'")
	}

	// OutOfScopeSummary
	if len(m.OutOfScopeSummary) == 0 {
		t.Fatal("OutOfScopeSummary should not be empty")
	}

	// 4. Testing Instructions
	if m.VPNRequired == nil || !*m.VPNRequired {
		t.Error("VPNRequired should be true")
	}
	if len(m.VNPIPs) != 2 {
		t.Errorf("VNPIPs len = %d, want 2", len(m.VNPIPs))
	}
	if m.RequestHeader != "X-Bug-Bounty" {
		t.Errorf("RequestHeader = %q, want %q", m.RequestHeader, "X-Bug-Bounty")
	}
	if m.AutomatedToolingLimit == nil || *m.AutomatedToolingLimit != 5 {
		t.Errorf("AutomatedToolingLimit = %v, want 5", m.AutomatedToolingLimit)
	}

	// 5. Account Setup
	if m.CanCreateTestAccount != nil {
		t.Error("CanCreateTestAccount should be nil (testAccountsEnabled=false)")
	}

	// 6. Program Stats
	if m.ScopesCount == nil || *m.ScopesCount != 3 {
		t.Errorf("ScopesCount = %v, want 3", m.ScopesCount)
	}
}

func TestExtractYogoshaMetadata_VDP(t *testing.T) {
	// Unicef H4V program: all rewards zero, tag "hack_for_values"
	const vdpBody = `{
		"name": "Unicef bug bounty H4V",
		"organization": {"name": "Unicef", "country": "FR", "currency": "EUR"},
		"lowReward": {"amount": "0", "currency": "EUR"},
		"mediumReward": {"amount": "0", "currency": "EUR"},
		"highReward": {"amount": "0", "currency": "EUR"},
		"criticalReward": {"amount": "0", "currency": "EUR"},
		"state": "online",
		"tags": ["hack_for_values"],
		"rewardEnabled": true,
		"rewardMandatory": false,
		"vpnRequired": false,
		"type": "bugbounty",
		"archivedAt": null,
		"asset": {"title": "Unicef"},
		"scope": ["https://www.unicef.org"],
		"outOfScopes": [],
		"monitoring": {"type": "none"},
		"audiences": [{"accessMode": "open"}],
		"content": {"mission": "VDP rules", "outOfScope": "", "terms": ""}
	}`

	m := extractYogoshaMetadata(vdpBody, false)

	if m.IsVDP == nil || !*m.IsVDP {
		t.Error("IsVDP should be true (all rewards zero + hack_for_values tag)")
	}
	if m.IsBounty != nil && *m.IsBounty {
		t.Error("IsBounty should be false for VDP")
	}
	if m.BountyRewardMin != nil {
		t.Error("BountyRewardMin should be nil (all rewards zero)")
	}
	if len(m.RewardGrids) != 0 {
		t.Errorf("RewardGrids len = %d, want 0 (all rewards zero)", len(m.RewardGrids))
	}
	if m.VPNRequired != nil && *m.VPNRequired {
		t.Error("VPNRequired should be false")
	}
	if m.RequestHeader != "" {
		t.Errorf("RequestHeader = %q, want empty (no terms)", m.RequestHeader)
	}
	if len(m.Tags) != 1 || m.Tags[0] != "hack_for_values" {
		t.Errorf("Tags = %v, want [hack_for_values]", m.Tags)
	}
}

func TestExtractYogoshaMetadata_Disabled(t *testing.T) {
	const disabledBody = `{
		"name": "Test Program",
		"organization": {"name": "Test", "currency": "EUR"},
		"lowReward": {"amount": "5000", "currency": "EUR"},
		"mediumReward": {"amount": "10000", "currency": "EUR"},
		"highReward": {"amount": "20000", "currency": "EUR"},
		"criticalReward": {"amount": "50000", "currency": "EUR"},
		"state": "offline",
		"tags": [],
		"type": "bugbounty",
		"archivedAt": "2026-01-01T00:00:00+00:00",
		"asset": {"title": "Test"},
		"scope": [],
		"outOfScopes": [],
		"audiences": [{"accessMode": "invitation"}],
		"content": {}
	}`

	m := extractYogoshaMetadata(disabledBody, true)

	if m.IsDisabled == nil || !*m.IsDisabled {
		t.Error("IsDisabled should be true (state=offline + archivedAt set)")
	}
	if m.IsPublic != nil && *m.IsPublic {
		t.Error("IsPublic should be false (accessMode=invitation)")
	}
}

func TestExtractMarkdownList(t *testing.T) {
	text := `###### Some heading

Some intro text.

###### Qualifying vulnerabilities:

**Each report will be analyzed.**

- Remote code execution (RCE)
- SQL injection
- XSS

##### Next heading

This should not be captured.
`
	items := extractMarkdownList(text, "Qualifying vulnerabilities")
	if len(items) != 3 {
		t.Fatalf("expected 3 items, got %d: %v", len(items), items)
	}
	if items[0] != "Remote code execution (RCE)" {
		t.Errorf("item[0] = %q, want %q", items[0], "Remote code execution (RCE)")
	}
	if items[1] != "SQL injection" {
		t.Errorf("item[1] = %q, want %q", items[1], "SQL injection")
	}
	if items[2] != "XSS" {
		t.Errorf("item[2] = %q, want %q", items[2], "XSS")
	}
}

func TestExtractMarkdownList_StarBullets(t *testing.T) {
	text := `**The following issues are outside the scope of our program:**

* CSRF
* Click-jacking
* Open Redirect
* DoS
`
	items := extractMarkdownList(text, "outside the scope")
	if len(items) != 4 {
		t.Fatalf("expected 4 items, got %d: %v", len(items), items)
	}
	if items[0] != "CSRF" {
		t.Errorf("item[0] = %q, want %q", items[0], "CSRF")
	}
}

func TestExtractMarkdownList_NoHeading(t *testing.T) {
	text := "No relevant heading here.\n- item 1\n- item 2"
	items := extractMarkdownList(text, "Qualifying vulnerabilities")
	if items != nil {
		t.Errorf("expected nil, got %v", items)
	}
}

func TestExtractRateLimit(t *testing.T) {
	tests := []struct {
		terms string
		want  int
	}{
		{"Limit the number of queries per second on automated tests. (max. 5 per sec)", 5},
		{"max. 10 per sec", 10},
		{"max 3 per sec", 3},
		{"No rate limit mentioned", 0},
		{"", 0},
	}
	for _, tt := range tests {
		got := extractRateLimit(tt.terms)
		if got != tt.want {
			t.Errorf("extractRateLimit(%q) = %d, want %d", tt.terms, got, tt.want)
		}
	}
}

func TestHasTag(t *testing.T) {
	tests := []struct {
		body string
		tag  string
		want bool
	}{
		{`{"tags": ["hack_for_values", "other"]}`, "hack_for_values", true},
		{`{"tags": ["other"]}`, "hack_for_values", false},
		{`{"tags": []}`, "hack_for_values", false},
		{`{"tags": null}`, "hack_for_values", false},
	}
	for _, tt := range tests {
		got := hasTag(tt.body, tt.tag)
		if got != tt.want {
			t.Errorf("hasTag(%q, %q) = %v, want %v", tt.body, tt.tag, got, tt.want)
		}
	}
}

// contains is a helper for substring matching in tests.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
